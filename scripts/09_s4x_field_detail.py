"""Stage S4x (exploratory, added after S4) - which fields carry the decision?

S4 records attribution shares per family only. Here I refit DT and XGB (seed 0, the
hyperparameters S4 chose for each blocked fold) on F-all, F-noA and F-chatz, and keep the
attribution of every single field, on the same evaluation sample as S4. The refit PR-AUC
is compared with the S4 value as a check.
For the five fields that weigh most under F-noA, I also tabulate their values on beacon
frames inside the attack window, attack against normal, to see what separates the fake
beacons from the real ones.

Usage (from the repository root):
    python scripts/09_s4x_field_detail.py                # finished runs are skipped
    python scripts/09_s4x_field_detail.py --summary-only
Output: results/S4x_field_runs.csv, results/S4x_field_detail.json
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
from src.attribution import mean_abs_attribution  # noqa: E402
from src.modeling import WINDOWS, Capture, fit, make_folds, pr_auc, predict  # noqa: E402
from src.utils import ROOT, load_paths, run_metadata, sha256_file, write_result  # noqa: E402

_spec = importlib.util.spec_from_file_location("s4", ROOT / "scripts" / "08_s4_reliance.py")
s4 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(s4)

SETS, MODELS, TOP = ["F-all", "F-noA", "F-chatz"], ["DT", "XGB"], 10
S4_RUNS = ROOT / "results" / "S4_runs.csv"
RUNS = ROOT / "results" / "S4x_field_runs.csv"


def set_columns(cap: Capture, fs: str, fams: np.ndarray) -> np.ndarray:
    keep = s4.SETS[fs]
    return cap.col_index(s4.CHATZOGLOU_16) if keep is None else np.flatnonzero(np.isin(fams, keep))


def run_capture(cap: Capture, ref: pd.DataFrame) -> None:
    folds, _, _ = make_folds(cap)
    fams = np.array([cap.families.get(c, "U") for c in cap.columns])
    done = pd.read_csv(RUNS) if RUNS.exists() else pd.DataFrame(columns=["capture", "fold", "feature_set", "model"])
    for fold in folds:
        E = s4.eval_sample(cap, fold.test, seed=fold.k)
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
                imp = mean_abs_attribution(model, family, Xe)
                share = imp / imp.sum() if imp.sum() > 0 else imp
                rows = pd.DataFrame({"capture": cap.name, "fold": fold.k, "feature_set": fs, "model": family,
                                     "pr_auc": score, "pr_auc_s4": r["pr_auc"], "field": [cap.columns[c] for c in cols],
                                     "family": fams[cols], "share": share})
                rows.to_csv(RUNS, mode="a", header=not RUNS.exists(), index=False)
                print(f"[S4x] {cap.name} fold {fold.k} {fs:<7} {family:<3} PR-AUC {score:.4f} (S4 {r['pr_auc']:.4f})  "
                      f"top: {rows.nlargest(3, 'share')['field'].tolist()}", flush=True)


def beacon_table(cap: Capture, fields: list[str]) -> dict:
    """Most frequent values of each field on beacons in the attack window, attack vs normal."""
    lo, hi = WINDOWS[cap.name]
    window = np.flatnonzero((cap.fn >= lo) & (cap.fn <= hi))
    tcols = cap.col_index(["wlan.fc.type", "wlan.fc.subtype"])
    if len(tcols) < 2:
        return {"note": "wlan.fc.type / wlan.fc.subtype not in the matrix"}
    t = cap.rows(window, tcols)
    beacons = window[(t[:, 0] == 0) & (t[:, 1] == 8)]
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


def summarise(df: pd.DataFrame, caps: dict) -> dict:
    out = {}
    for (cap, fs, family), d in df.groupby(["capture", "feature_set", "model"]):
        runs = d.drop_duplicates("fold")
        top = (d.groupby(["field", "family"])["share"].mean().sort_values(ascending=False).head(TOP).round(4))
        out.setdefault(cap, {}).setdefault(fs, {})[family] = {
            "pr_auc_refit": round(float(runs["pr_auc"].mean()), 4),
            "pr_auc_s4": round(float(runs["pr_auc_s4"].mean()), 4),
            "max_abs_difference": round(float((runs["pr_auc"] - runs["pr_auc_s4"]).abs().max()), 4),
            "top_fields": [{"field": f, "family": fam, "mean_share": s} for (f, fam), s in top.items()]}
    for cap, c in caps.items():
        d = df[(df["capture"] == cap) & (df["feature_set"] == "F-noA")]
        fields = d.groupby("field")["share"].mean().nlargest(5).index.tolist()
        out[cap]["beacon_values_top_f_noa"] = beacon_table(c, fields)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--captures", nargs="+", default=["rogue_ap", "evil_twin"])
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()
    paths = load_paths()
    ref = pd.read_csv(S4_RUNS)
    caps = {n: Capture.load(paths["interim_dir"], n) for n in args.captures}
    if not args.summary_only:
        for cap in caps.values():
            run_capture(cap, ref)
    inputs = {p.name: sha256_file(p) for p in [S4_RUNS] +
              [paths["interim_dir"] / f"awid3_{n}_features.json" for n in args.captures]}
    out = write_result("S4x_field_detail", {"exploratory": True, "results": summarise(pd.read_csv(RUNS), caps)},
                       run_metadata("scripts/09_s4x_field_detail.py", inputs_sha256=inputs))
    print(f"[S4x] Done -> {out}")


if __name__ == "__main__":
    main()
