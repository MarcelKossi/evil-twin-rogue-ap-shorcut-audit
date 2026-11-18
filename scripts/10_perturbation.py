"""Perturbation test (exploratory; design fixed in the journal on 2026-11-18, before any result).

Do the detectors still flag the rogue beacons once these carry the legitimate AP's values
in the fields the attacker controls? The models are those of the S4 blocked protocol
(same hyperparameters, same training rows, same F1 threshold from the validation block);
nothing is trained on modified data. For each held-out block, the rogue beacons of the
block are copied and changed in one of three ways:
  L     length and the airtime that follows from it (frame.len, wlan_radio.duration)
  P     received signal strength (radiotap.dbm_antsignal, wlan_radio.signal_dbm)
  L+P   both
Values come from real legitimate beacons of the attack window (one donor per rogue beacon,
drawn at random with seed = block number, then paired in time order); all fields changed
on one beacon come from the same donor. Only fields present in the feature set are changed.
Legitimate beacons are normal-labelled beacons whose length differs from every rogue beacon
length; this leaves out the rogue beacons labelled Normal (S1c), which are scored separately.

Usage (from the repository root):
    python scripts/10_perturbation.py --seeds 0      # first pass
    python scripts/10_perturbation.py                # seeds 0-4 (finished runs are skipped)
    python scripts/10_perturbation.py --summary-only
Output: results/S4p_perturbation_runs.csv, results/S4p_perturbation.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.modeling import DETERMINISTIC, GRIDS, WINDOWS, Capture, f1_threshold, fit, make_folds, pr_auc, predict  # noqa: E402
from src.utils import ROOT, load_paths, run_metadata, sha256_file, write_result  # noqa: E402

_spec = importlib.util.spec_from_file_location("s4x", ROOT / "scripts" / "09_s4x_field_detail.py")
s4x = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(s4x)

SETS = ["F-all", "F-noA", "F-chatz"]
FIELDS_L = ["frame.len", "wlan_radio.duration"]
FIELDS_P = ["radiotap.dbm_antsignal", "wlan_radio.signal_dbm"]
VARIANTS = {"none": [], "L": FIELDS_L, "P": FIELDS_P, "L+P": FIELDS_L + FIELDS_P}
S4_RUNS = ROOT / "results" / "S4_runs.csv"
RUNS = ROOT / "results" / "S4p_perturbation_runs.csv"


def beacon_sets(cap: Capture) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Rogue, legitimate and rogue-but-labelled-Normal beacons of the attack window."""
    lo, hi = WINDOWS[cap.name]
    b = s4x.beacon_rows(cap, np.flatnonzero((cap.fn >= lo) & (cap.fn <= hi)))
    flen = cap.rows(b, cap.col_index(["frame.len"]))[:, 0]
    rogue_len = np.unique(flen[cap.y[b] == 1])
    normal = cap.y[b] == 0
    return b[~normal], b[normal & ~np.isin(flen, rogue_len)], b[normal & np.isin(flen, rogue_len)]


def run_capture(cap: Capture, ref: pd.DataFrame, seeds: list[int]) -> None:
    folds, _, _ = make_folds(cap)
    fams = np.array([cap.families.get(c, "U") for c in cap.columns])
    rogue_all, legit_all, mislab_all = beacon_sets(cap)
    print(f"[S4p] {cap.name}: {len(rogue_all)} rogue, {len(legit_all)} legitimate, "
          f"{len(mislab_all)} rogue labelled Normal beacons in the attack window", flush=True)
    done = pd.read_csv(RUNS) if RUNS.exists() else pd.DataFrame(columns=["capture", "fold", "feature_set", "model", "seed"])
    for fold in folds:
        rogue, legit, mislab = (np.intersect1d(x, fold.test) for x in (rogue_all, legit_all, mislab_all))
        if not len(rogue):
            continue
        donors = np.sort(np.random.default_rng(fold.k).choice(legit_all, len(rogue), replace=True))
        for fs in SETS:
            cols = s4x.set_columns(cap, fs, fams)
            names = [cap.columns[c] for c in cols]
            Xr, Xd = cap.rows(rogue, cols), cap.rows(donors, cols)
            Xl, Xm = cap.rows(legit, cols), cap.rows(mislab, cols)
            for family in GRIDS:
                key = (done["capture"] == cap.name) & (done["fold"] == fold.k) & \
                      (done["feature_set"] == fs) & (done["model"] == family)
                todo = [s for s in ([0] if family in DETERMINISTIC else seeds) if s not in set(done.loc[key, "seed"])]
                if not todo:
                    continue
                r4 = ref[(ref["capture"] == cap.name) & (ref["protocol"] == "blocked") & (ref["fold"] == fold.k) &
                         (ref["feature_set"] == fs) & (ref["model"] == family)]
                params = json.loads(r4["params"].iloc[0])
                m0, _, _ = fit(cap, family, params, 0, fold.tune_train, cols, sample_seed=fold.k)   # as in tune()
                thr = f1_threshold(cap.y[fold.val], predict(m0, cap, fold.val, cols))
                for seed in todo:
                    model, _, _ = fit(cap, family, params, seed, fold.train, cols, sample_seed=fold.k)
                    check = pr_auc(cap.y[fold.test], predict(model, cap, fold.test, cols))
                    s_legit = model.predict_proba(Xl)[:, 1] if len(legit) else np.empty(0)
                    rows = []
                    for variant, fields in VARIANTS.items():
                        j = [names.index(f) for f in fields if f in names]
                        Xp = Xr.copy()
                        Xp[:, j] = Xd[:, j]
                        s = model.predict_proba(Xp)[:, 1]
                        y = np.r_[np.ones(len(s)), np.zeros(len(s_legit))]
                        rows.append({"capture": cap.name, "fold": fold.k, "feature_set": fs, "model": family,
                                     "seed": seed, "variant": variant, "fields_changed": "|".join(names[i] for i in j),
                                     "threshold": thr, "rogue": len(rogue), "detected": int((s >= thr).sum()),
                                     "mean_score": float(s.mean()), "legit": len(legit),
                                     "legit_flagged": int((s_legit >= thr).sum()),
                                     "pr_auc_beacons": pr_auc(y, np.r_[s, s_legit]),
                                     "pr_auc_test": check, "pr_auc_s4": float(r4.loc[r4["seed"] == seed, "pr_auc"].iloc[0])})
                    s_mis = model.predict_proba(Xm)[:, 1] if len(mislab) else np.empty(0)
                    for r in rows:
                        r.update({"mislabelled": len(mislab), "mislabelled_flagged": int((s_mis >= thr).sum())})
                    pd.DataFrame(rows).to_csv(RUNS, mode="a", header=not RUNS.exists(), index=False)
                    det = {r["variant"]: r["detected"] / r["rogue"] for r in rows}
                    print(f"[S4p] {cap.name} fold {fold.k} {fs:<7} {family:<3} seed {seed}  detected "
                          + "  ".join(f"{v} {d:.3f}" for v, d in det.items())
                          + f"  (PR-AUC test {check:.4f}, S4 {rows[0]['pr_auc_s4']:.4f})", flush=True)


def summarise(df: pd.DataFrame) -> dict:
    out = {}
    pooled = df.groupby(["capture", "feature_set", "model", "variant", "seed"])[
        ["rogue", "detected", "mislabelled", "mislabelled_flagged"]].sum()
    pooled["rate"] = pooled["detected"] / pooled["rogue"]
    for (cap, fs, family), d in df.groupby(["capture", "feature_set", "model"]):
        p = pooled.loc[(cap, fs, family)]
        res = {"max_abs_difference_pr_auc_vs_s4": round(float((d["pr_auc_test"] - d["pr_auc_s4"]).abs().max()), 4),
               "seeds": sorted(int(s) for s in d["seed"].unique())}
        for v in VARIANTS:
            rate = p.loc[v, "rate"]
            res[v] = {"detection_rate_mean": round(float(rate.mean()), 4),
                      "detection_rate_std": round(float(rate.std(ddof=1)), 4) if len(rate) > 1 else None,
                      "pr_auc_beacons_mean": round(float(d.loc[d["variant"] == v, "pr_auc_beacons"].mean()), 4),
                      "fields_changed": sorted(set("|".join(d.loc[d["variant"] == v, "fields_changed"].fillna("")).split("|")) - {""})}
        none = p.loc["none"]
        res["rogue_labelled_normal_flagged"] = (round(float((none["mislabelled_flagged"] / none["mislabelled"]).mean()), 4)
                                                if none["mislabelled"].max() > 0 else None)
        res["legit_beacons_flagged_rate"] = round(float(d.loc[d["variant"] == "none", "legit_flagged"].sum()
                                                        / max(d.loc[d["variant"] == "none", "legit"].sum(), 1)), 5)
        out.setdefault(cap, {}).setdefault(fs, {})[family] = res
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--captures", nargs="+", default=["rogue_ap", "evil_twin"])
    parser.add_argument("--seeds", nargs="+", type=int, default=[0, 1, 2, 3, 4])
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()
    paths = load_paths()
    ref = pd.read_csv(S4_RUNS)
    if not args.summary_only:
        for name in args.captures:
            run_capture(Capture.load(paths["interim_dir"], name), ref, args.seeds)
    inputs = {p.name: sha256_file(p) for p in [S4_RUNS] +
              [paths["interim_dir"] / f"awid3_{n}_features.json" for n in args.captures]}
    out = write_result("S4p_perturbation", {"exploratory": True, "results": summarise(pd.read_csv(RUNS))},
                       run_metadata("scripts/10_perturbation.py", inputs_sha256=inputs))
    print(f"[S4p] Done -> {out}")


if __name__ == "__main__":
    main()
