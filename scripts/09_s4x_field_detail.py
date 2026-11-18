"""Stage S4x (exploratory, added after S4) - which fields carry the decision?

S4 records attribution shares per family only. Here I refit DT and XGB (seed 0, the
hyperparameters S4 chose for each blocked fold) on F-all, F-noA and F-chatz, and keep the
attribution of every single field. The refit PR-AUC is compared with the S4 value as a check.
  default     attributions on the S4 evaluation sample (mostly normal frames);
              then, for the five fields that weigh most under F-noA, their values on beacon
              frames inside the attack window, attack against normal
  always      H2b artefact-share test re-run on F-all and F-chatz together (deviation 8:
              the S4 script tested F-all only; F-noA and F-sem hold no artefact field),
              and the median S4 PR-AUC per blocked fold
  --beacons   attributions on the beacon frames of each test block only (rogue and
              legitimate beacons), plus the PR-AUC on those beacons: what separates a rogue
              beacon from a real one, once frame type no longer sorts the traffic

Usage (from the repository root):
    python scripts/09_s4x_field_detail.py                # finished runs are skipped
    python scripts/09_s4x_field_detail.py --beacons
    python scripts/09_s4x_field_detail.py --summary-only
Output: results/S4x_field_runs.csv, results/S4x_beacon_runs.csv, results/S4x_field_detail.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import wilcoxon

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.attribution import mean_abs_attribution  # noqa: E402
from src.modeling import WINDOWS, Capture, fit, make_folds, pr_auc, predict  # noqa: E402
from src.utils import ROOT, load_paths, run_metadata, sha256_file, write_result  # noqa: E402

_spec = importlib.util.spec_from_file_location("s4", ROOT / "scripts" / "08_s4_reliance.py")
s4 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(s4)

SETS, MODELS, TOP = ["F-all", "F-noA", "F-chatz"], ["DT", "XGB"], 10
S4_RUNS = ROOT / "results" / "S4_runs.csv"
RUNS = {"eval": ROOT / "results" / "S4x_field_runs.csv", "beacons": ROOT / "results" / "S4x_beacon_runs.csv"}


def set_columns(cap: Capture, fs: str, fams: np.ndarray) -> np.ndarray:
    keep = s4.SETS[fs]
    return cap.col_index(s4.CHATZOGLOU_16) if keep is None else np.flatnonzero(np.isin(fams, keep))


def beacon_rows(cap: Capture, rows: np.ndarray) -> np.ndarray:
    """Beacon frames (type 0, subtype 8) among rows; both columns have a minimum of 0, so no offset."""
    t = cap.rows(rows, cap.col_index(["wlan.fc.type", "wlan.fc.subtype"]))
    return rows[(t[:, 0] == 0) & (t[:, 1] == 8)]


def run_capture(cap: Capture, ref: pd.DataFrame, sample: str) -> None:
    folds, _, _ = make_folds(cap)
    fams = np.array([cap.families.get(c, "U") for c in cap.columns])
    path = RUNS[sample]
    done = pd.read_csv(path) if path.exists() else pd.DataFrame(columns=["capture", "fold", "feature_set", "model"])
    for fold in folds:
        E = beacon_rows(cap, fold.test) if sample == "beacons" else s4.eval_sample(cap, fold.test, seed=fold.k)
        ye = cap.y[E]
        for fs in SETS:
            cols = set_columns(cap, fs, fams)
            Xe = cap.rows(E, cols)
            for family in MODELS:
                key = (done["capture"] == cap.name) & (done["fold"] == fold.k) & \
                      (done["feature_set"] == fs) & (done["model"] == family)
                if key.any():
                    continue
                r = ref[(ref["capture"] == cap.name) & (ref["protocol"] == "blocked") & (ref["fold"] == fold.k) &
                        (ref["feature_set"] == fs) & (ref["model"] == family) & (ref["seed"] == 0)].iloc[0]
                model, _, _ = fit(cap, family, json.loads(r["params"]), 0, fold.train, cols, sample_seed=fold.k)
                score = pr_auc(cap.y[fold.test], predict(model, cap, fold.test, cols))
                imp = mean_abs_attribution(model, family, Xe) if len(E) else np.zeros(len(cols))
                share = imp / imp.sum() if imp.sum() > 0 else imp
                rows = pd.DataFrame({"capture": cap.name, "fold": fold.k, "feature_set": fs, "model": family,
                                     "pr_auc": score, "pr_auc_s4": r["pr_auc"],
                                     "sample_attack": int(ye.sum()), "sample_normal": int((ye == 0).sum()),
                                     "pr_auc_sample": pr_auc(ye, model.predict_proba(Xe)[:, 1]) if len(E) else np.nan,
                                     "field": [cap.columns[c] for c in cols], "family": fams[cols], "share": share})
                rows.to_csv(path, mode="a", header=not path.exists(), index=False)
                print(f"[S4x {sample}] {cap.name} fold {fold.k} {fs:<7} {family:<3} PR-AUC {score:.4f} "
                      f"(S4 {r['pr_auc']:.4f}), on sample {rows['pr_auc_sample'].iloc[0]:.4f} "
                      f"({int(ye.sum())} attack / {int((ye == 0).sum())} normal)  "
                      f"top: {rows.nlargest(3, 'share')['field'].tolist()}", flush=True)


def beacon_table(cap: Capture, fields: list[str]) -> dict:
    """Most frequent values of each field on beacons in the attack window, attack vs normal
    (numeric fields are stored minus their column minimum, see S2b)."""
    lo, hi = WINDOWS[cap.name]
    beacons = beacon_rows(cap, np.flatnonzero((cap.fn >= lo) & (cap.fn <= hi)))
    vals = cap.rows(beacons, cap.col_index(fields))
    y = cap.y[beacons]
    out = {"beacons_attack": int(y.sum()), "beacons_normal": int((y == 0).sum())}
    for j, f in enumerate(fields):
        v = pd.Series(vals[:, j]).fillna(-1)
        a, n = v[y == 1].value_counts(normalize=True), v[y == 0].value_counts(normalize=True)
        top = a.index[:5].union(n.index[:5])
        out[f] = {str(float(k)): {"attack": round(float(a.get(k, 0)), 4), "normal": round(float(n.get(k, 0)), 4)}
                  for k in top}
    return out


def h2b_share_a(s4df: pd.DataFrame) -> dict:
    """Deviation 8: random vs blocked artefact share over model x feature set x seed, F-all and F-chatz."""
    d = s4df[s4df["share_A"].notna() & s4df["feature_set"].isin(["F-all", "F-chatz"])]
    out = {}
    for cap, x in d.groupby("capture"):
        g = x.groupby(["protocol", "feature_set", "model", "seed"])["share_A"].mean().unstack("protocol").dropna()
        diff = g["random"] - g["blocked"]
        out[cap] = {"pairs": int(len(diff)), "mean_random": round(float(g["random"].mean()), 4),
                    "mean_blocked": round(float(g["blocked"].mean()), 4),
                    "median_difference": round(float(diff.median()), 4),
                    "wilcoxon_p_one_sided": float(wilcoxon(diff, alternative="greater").pvalue)}
    return out


def s4_by_block(s4df: pd.DataFrame) -> dict:
    """Median S4 PR-AUC over models and seeds, per capture, blocked fold and feature set; S4 compute time."""
    b = s4df[s4df["protocol"] == "blocked"]
    med = b.groupby(["capture", "fold", "feature_set"])["pr_auc"].median().round(4)
    out = {cap: {int(k): v.droplevel([0, 1]).to_dict() for k, v in x.groupby(level="fold")}
           for cap, x in med.groupby(level="capture")}
    return {"median_pr_auc_by_block": out, "s4_compute_hours": round(float(s4df["seconds"].sum()) / 3600, 1)}


def summarise(df: pd.DataFrame) -> dict:
    out = {}
    for (cap, fs, family), d in df.groupby(["capture", "feature_set", "model"]):
        runs = d.drop_duplicates("fold")
        top = d.groupby(["field", "family"])["share"].mean().sort_values(ascending=False).head(TOP).round(4)
        fam = d.groupby(["fold", "family"])["share"].sum().groupby("family").mean().round(4)
        res = {"pr_auc_refit": round(float(runs["pr_auc"].mean()), 4),
               "pr_auc_s4": round(float(runs["pr_auc_s4"].mean()), 4),
               "max_abs_difference": round(float((runs["pr_auc"] - runs["pr_auc_s4"]).abs().max()), 4)}
        if "pr_auc_sample" in runs:          # columns added with --beacons (absent from the first eval run)
            res.update({"sample_attack": int(runs["sample_attack"].sum()), "sample_normal": int(runs["sample_normal"].sum()),
                        "pr_auc_on_sample_by_fold": {int(k): round(float(v), 4)
                                                     for k, v in zip(runs["fold"], runs["pr_auc_sample"])}})
        res.update({"family_shares": fam.to_dict(),
                    "top_fields": [{"field": f, "family": fm, "mean_share": s} for (f, fm), s in top.items()]})
        out.setdefault(cap, {}).setdefault(fs, {})[family] = res
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--captures", nargs="+", default=["rogue_ap", "evil_twin"])
    parser.add_argument("--beacons", action="store_true", help="attributions on the beacon frames of each test block")
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()
    paths = load_paths()
    ref = pd.read_csv(S4_RUNS)
    caps = {n: Capture.load(paths["interim_dir"], n) for n in args.captures}
    if not args.summary_only:
        for cap in caps.values():
            run_capture(cap, ref, "beacons" if args.beacons else "eval")
    payload = {"exploratory": True, "h2b_share_a_f_all_and_f_chatz": h2b_share_a(ref), "s4_blocked": s4_by_block(ref)}
    for sample, path in RUNS.items():
        if path.exists():
            payload[f"results_{sample}"] = summarise(pd.read_csv(path))
    if RUNS["eval"].exists():
        df = pd.read_csv(RUNS["eval"])
        payload["beacon_values_top_f_noa"] = {
            n: beacon_table(c, df[(df["capture"] == n) & (df["feature_set"] == "F-noA")]
                            .groupby("field")["share"].mean().nlargest(5).index.tolist()) for n, c in caps.items()}
    inputs = {p.name: sha256_file(p) for p in [S4_RUNS] +
              [paths["interim_dir"] / f"awid3_{n}_features.json" for n in args.captures]}
    out = write_result("S4x_field_detail", payload, run_metadata("scripts/09_s4x_field_detail.py", inputs_sha256=inputs))
    print(f"[S4x] Done -> {out}")


if __name__ == "__main__":
    main()
