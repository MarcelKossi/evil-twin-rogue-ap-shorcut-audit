"""Stage S3 - do lightweight detectors learn the labelling rule? (H1b, H1c)

Blocked protocol (protocol 9.2): the attack window is cut into 5 contiguous
blocks; each block is held out in turn, with 10,000 frames purged on each side;
pre-attack normal frames are used for training, except the last 20% of them,
kept as a clean-period check. Hyperparameters are tuned with seed 0 on the
block next to the test block, then reused for every seed.

Feature sets:
  F-all     all kept columns (identifiers label-encoded, as in common practice)
  F-noFV    F-all without the filter variables (H1c)
  F-filter  the filter variables only, for a decision tree of depth <= 3 (H1b)

Each run is appended to results/S3_runs.csv as soon as it finishes; re-running
the script skips the runs already done. The summary (H1b, H1c) is written to
results/S3_label_rule.json.

Usage (from the repository root):
    python scripts/07_s3_label_rule.py                  # full run (all captures, seeds 0-4)
    python scripts/07_s3_label_rule.py --seeds 0        # one seed only
    python scripts/07_s3_label_rule.py --summary-only   # recompute the summary from S3_runs.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.modeling import (DETERMINISTIC, FILTER_VARIABLES, GRIDS, Capture, f1_threshold, fit,  # noqa: E402
                          make_folds, metrics, pr_auc, predict)
from src.utils import ROOT, load_paths, run_metadata, write_result  # noqa: E402

RUNS = ROOT / "results" / "S3_runs.csv"
FIELDS = ["capture", "fold", "feature_set", "model", "params", "seed", "n_train", "attack_train",
          "threshold", "pr_auc", "roc_auc", "recall_at_fpr_0.001", "recall_at_fpr_0.01", "mcc", "f1",
          "test_rows", "test_attack", "prevalence", "clean_fpr", "seconds"]
H1B_RATIO = 0.95
H1C_DROP = 0.20


def done_runs() -> set:
    if not RUNS.exists():
        return set()
    df = pd.read_csv(RUNS)
    return set(zip(df["capture"], df["fold"], df["feature_set"], df["model"], df["seed"]))


def append(row: dict) -> None:
    new = not RUNS.exists()
    with open(RUNS, "a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        if new:
            w.writeheader()
        w.writerow({k: row.get(k) for k in FIELDS})


def tune(cap, family, fold, cols) -> tuple[dict, float]:
    """Pick the grid configuration with the best PR-AUC on the validation block (seed 0)."""
    best, best_score, best_thr = None, -1.0, 0.5
    yv = cap.y[fold.val]
    for params in GRIDS[family]:
        model, _, _ = fit(cap, family, params, 0, fold.tune_train, cols, sample_seed=fold.k)
        s = predict(model, cap, fold.val, cols)
        score = pr_auc(yv, s)
        score = -0.0 if np.isnan(score) else score
        if score > best_score:
            best, best_score, best_thr = params, score, f1_threshold(yv, s)
    return best, best_thr


def run_capture(cap: Capture, seeds: list[int], done: set) -> dict:
    folds, clean, info = make_folds(cap)
    fv = [c for c in FILTER_VARIABLES if c in cap.columns]
    sets = {
        "F-all": cap.col_index(cap.columns),
        "F-noFV": cap.col_index([c for c in cap.columns if c not in fv]),
        "F-filter": cap.col_index(fv),
    }
    info["filter_variables_used"] = fv
    info["n_columns"] = {k: int(len(v)) for k, v in sets.items()}
    plan = [("F-filter", "DT3")] + [(fs, m) for fs in ("F-all", "F-noFV") for m in GRIDS]
    for fold in folds:
        for fs, family in plan:
            cols = sets[fs]
            todo = [s for s in (seeds[:1] if family in DETERMINISTIC else seeds)
                    if (cap.name, fold.k, fs, family, s) not in done]
            if not todo:
                continue
            if family == "DT3":
                params = {"max_depth": 3}
                m0, _, _ = fit(cap, "DT3", params, 0, fold.tune_train, cols, sample_seed=fold.k)
                thr = f1_threshold(cap.y[fold.val], predict(m0, cap, fold.val, cols))
            else:
                params, thr = tune(cap, family, fold, cols)
            for seed in todo:
                t0 = time.time()
                model, n_train, n_att = fit(cap, family, params, seed, fold.train, cols, sample_seed=fold.k)
                s = predict(model, cap, fold.test, cols)
                m = metrics(cap.y[fold.test], s, thr)
                fpr_clean = float((predict(model, cap, clean, cols) >= thr).mean()) if len(clean) else None
                row = {"capture": cap.name, "fold": fold.k, "feature_set": fs, "model": family,
                       "params": json.dumps(params), "seed": seed, "n_train": n_train, "attack_train": n_att,
                       "threshold": thr, "test_rows": m["n"], "test_attack": m["attack"],
                       "prevalence": m["prevalence"], "clean_fpr": fpr_clean,
                       "seconds": round(time.time() - t0, 1),
                       **{k: m.get(k) for k in ("pr_auc", "roc_auc", "recall_at_fpr_0.001", "recall_at_fpr_0.01", "mcc", "f1")}}
                append(row)
                print(f"[S3] {cap.name} fold {fold.k} {fs:<8} {family:<4} seed {seed}  "
                      f"PR-AUC {m['pr_auc']:.4f}  ({row['seconds']} s)", flush=True)
    return info


def fold_bootstrap(per_fold: np.ndarray, n_boot: int = 2000, seed: int = 0) -> list[float]:
    rng = np.random.default_rng(seed)
    means = [rng.choice(per_fold, len(per_fold), replace=True).mean() for _ in range(n_boot)]
    return [float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))]


def summarise(infos: dict) -> dict:
    df = pd.read_csv(RUNS)
    out = {}
    for cap, d in df.groupby("capture"):
        res = {"design": infos.get(cap)}
        mean_pr = d.groupby(["feature_set", "model"])["pr_auc"].mean()
        res["mean_pr_auc"] = {f"{fs} {m}": round(v, 4) for (fs, m), v in mean_pr.items()}
        res["mean_clean_fpr"] = {f"{fs} {m}": round(v, 6) for (fs, m), v in
                                 d.groupby(["feature_set", "model"])["clean_fpr"].mean().items()}

        all_models = mean_pr.loc["F-all"] if "F-all" in mean_pr.index.get_level_values(0) else pd.Series(dtype=float)
        if len(all_models) and ("F-filter", "DT3") in mean_pr.index:
            best = all_models.idxmax()
            ratio = mean_pr[("F-filter", "DT3")] / all_models.max()
            res["H1b"] = {"dt3_filter_pr_auc": round(mean_pr[("F-filter", "DT3")], 4),
                          "best_f_all_model": best, "best_f_all_pr_auc": round(all_models.max(), 4),
                          "ratio": round(float(ratio), 4), "threshold": H1B_RATIO,
                          "supported": bool(ratio >= H1B_RATIO)}

        h1c = {}
        for fam in sorted(set(d["model"]) - {"DT3"}):
            a = d[(d["model"] == fam) & (d["feature_set"] == "F-all")].set_index(["fold", "seed"])["pr_auc"]
            b = d[(d["model"] == fam) & (d["feature_set"] == "F-noFV")].set_index(["fold", "seed"])["pr_auc"]
            pair = pd.concat([a.rename("all"), b.rename("nofv")], axis=1).dropna()
            if pair.empty:
                continue
            pair["drop"] = (pair["all"] - pair["nofv"]) / pair["all"]
            per_fold = pair.groupby(level="fold")["drop"].mean().to_numpy()
            ci = fold_bootstrap(per_fold)
            mean_drop = float(pair["drop"].mean())
            h1c[fam] = {"mean_relative_drop": round(mean_drop, 4), "ci95_fold_bootstrap": [round(x, 4) for x in ci],
                        "runs": int(len(pair)), "meets": bool(mean_drop >= H1C_DROP and ci[0] > 0)}
        if h1c:
            n_meet = sum(v["meets"] for v in h1c.values())
            res["H1c"] = {"per_model": h1c, "models_meeting": n_meet, "threshold_drop": H1C_DROP,
                          "supported": bool(n_meet >= 3),
                          "note": "CI from a bootstrap over the 5 folds (seed-averaged); coarse with 5 folds"}
        out[cap] = res
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--captures", nargs="+", default=["rogue_ap", "evil_twin"])
    parser.add_argument("--seeds", nargs="+", type=int, default=[0, 1, 2, 3, 4])
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()

    paths = load_paths()
    infos = {}
    for name in args.captures:
        cap = Capture.load(paths["interim_dir"], name)
        if args.summary_only:
            infos[name] = make_folds(cap)[2]
            continue
        print(f"[S3] {name}: {len(cap.y):,} rows, {int(cap.y.sum()):,} attack, {len(cap.columns)} columns", flush=True)
        infos[name] = run_capture(cap, args.seeds, done_runs())
    summary = summarise(infos)
    out = write_result("S3_label_rule", {"results": summary},
                       run_metadata("scripts/07_s3_label_rule.py", seeds=args.seeds))
    print(f"[S3] Done -> {out}")
    for cap, r in summary.items():
        if "H1b" in r:
            print(f"  {cap} H1b: DT3 on filter variables {r['H1b']['dt3_filter_pr_auc']} vs best F-all "
                  f"{r['H1b']['best_f_all_model']} {r['H1b']['best_f_all_pr_auc']} -> ratio {r['H1b']['ratio']} "
                  f"supported={r['H1b']['supported']}")
        if "H1c" in r:
            print(f"  {cap} H1c: {r['H1c']['models_meeting']}/5 models drop >= 20% -> supported={r['H1c']['supported']}")


if __name__ == "__main__":
    main()
