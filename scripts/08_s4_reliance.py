"""Stage S4 - how much do detectors rely on artefacts? (H2a, H2b, H2c)

For each capture, model family (LR, DT, RF, XGB, MLP), seed and feature set
(F-all, F-noA = without artefacts, F-sem = semantic fields only, F-chatz = the
16 expert features of Chatzoglou et al. 2022 reused in later work), under two
splitting protocols:
  blocked  the 5-block protocol of S3 (hyperparameters tuned per fold, seed 0)
  random   one stratified random 80/20 split of the attack-window frames, as in most
           published work but on the same test population as the blocked protocol
           (hyperparameters of blocked fold 0)
Each run records PR-AUC and the share of attribution per family (S, A, C, U)
and for the filter variables, on an evaluation sample of the test rows
(all attack frames up to 10,000, normal frames up to 20,000 rows in total).
Grouped permutation importance (secondary method) is computed for seed 0.

Usage (from the repository root):
    python scripts/08_s4_reliance.py                 # all runs (finished runs are skipped)
    python scripts/08_s4_reliance.py --summary-only
Output: results/S4_runs.csv, results/S4_reliance.json
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import kendalltau, wilcoxon

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.attribution import mean_abs_attribution  # noqa: E402
from src.modeling import (DETERMINISTIC, FILTER_VARIABLES, GRIDS, Capture, fit, make_folds,  # noqa: E402
                          metrics, pr_auc, predict, random_window_fold, tune)
from src.utils import ROOT, load_paths, run_metadata, write_result  # noqa: E402

FAMILIES = ["S", "A", "C", "U"]
SETS = {"F-all": FAMILIES, "F-noA": ["S", "C", "U"], "F-sem": ["S"], "F-chatz": None}
# The 16 expert features of Chatzoglou et al. (2022), as listed by later studies that reuse them
# (Khalid et al. 2025, Ahmad et al. 2025, Solpan et al. 2026); constant ones are dropped in S2b.
CHATZOGLOU_16 = ["frame.len", "radiotap.length", "radiotap.dbm_antsignal", "wlan.duration", "radiotap.present.tsft",
                 "radiotap.channel.freq", "radiotap.channel.flags.cck", "radiotap.channel.flags.ofdm", "wlan.fc.type",
                 "wlan.fc.subtype", "wlan.fc.ds", "wlan.fc.frag", "wlan.fc.retry", "wlan.fc.pwrmgt",
                 "wlan.fc.moredata", "wlan.fc.protected"]
ATTRIBUTED = ["LR", "DT", "RF", "XGB"]
RUNS = ROOT / "results" / "S4_runs.csv"
E_ROWS, E_ATTACK, PERM_REPEATS = 20_000, 10_000, 10
FIELDS = (["capture", "protocol", "fold", "feature_set", "model", "params", "seed", "pr_auc", "roc_auc",
           "recall_at_fpr_0.001", "clean_fpr", "test_attack"] + [f"share_{f}" for f in FAMILIES]
          + ["share_FV"] + [f"perm_{f}" for f in FAMILIES] + ["seconds"])


def eval_sample(cap: Capture, rows: np.ndarray, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    pos, neg = rows[cap.y[rows] == 1], rows[cap.y[rows] == 0]
    pos = rng.choice(pos, min(len(pos), E_ATTACK), replace=False)
    neg = rng.choice(neg, min(len(neg), E_ROWS - len(pos)), replace=False)
    return np.sort(np.concatenate([pos, neg]))


def permutation_drops(model, X: np.ndarray, y: np.ndarray, fams: np.ndarray, seed: int) -> dict:
    rng = np.random.default_rng(seed)
    base = pr_auc(y, model.predict_proba(X)[:, 1])
    out = {}
    for f in FAMILIES:
        cols = np.flatnonzero(fams == f)
        if len(cols):
            drops = []
            for _ in range(PERM_REPEATS):
                Xp = X.copy()
                Xp[:, cols] = X[rng.permutation(len(X))][:, cols]
                drops.append(base - pr_auc(y, model.predict_proba(Xp)[:, 1]))
            out[f"perm_{f}"] = float(np.mean(drops))
    return out


def read_runs(path: Path) -> pd.DataFrame:
    return pd.read_csv(path) if path.exists() else pd.DataFrame(columns=FIELDS)


def run_capture(cap: Capture) -> None:
    folds, clean, _ = make_folds(cap)
    fams = np.array([cap.families.get(c, "U") for c in cap.columns])
    fv = np.isin(cap.columns, FILTER_VARIABLES)
    for protocol, fold_list in (("blocked", folds), ("random", [random_window_fold(cap)])):
        for fold in fold_list:
            for fs, keep in SETS.items():
                cols = cap.col_index(CHATZOGLOU_16) if keep is None else np.flatnonzero(np.isin(fams, keep))
                for family in GRIDS:
                    done = read_runs(RUNS)
                    done = done[(done["capture"] == cap.name) & (done["protocol"] == protocol) &
                                (done["fold"] == fold.k) & (done["feature_set"] == fs) & (done["model"] == family)]
                    seeds = [s for s in ([0] if family in DETERMINISTIC else range(5)) if s not in set(done["seed"])]
                    if not seeds:
                        continue
                    if protocol == "random":        # hyperparameters of blocked fold 0
                        ref = read_runs(RUNS)
                        ref = ref[(ref["capture"] == cap.name) & (ref["protocol"] == "blocked") & (ref["fold"] == 0) &
                                  (ref["feature_set"] == fs) & (ref["model"] == family)]
                        params, thr = json.loads(ref["params"].iloc[0]), 0.5
                    else:
                        params, thr = tune(cap, family, fold, cols)
                    E = eval_sample(cap, fold.test, seed=max(fold.k, 0))
                    Xe, ye = cap.rows(E, cols), cap.y[E]
                    for seed in seeds:
                        t0 = time.time()
                        model, _, _ = fit(cap, family, params, seed, fold.train, cols, sample_seed=max(fold.k, 0))
                        m = metrics(cap.y[fold.test], predict(model, cap, fold.test, cols), thr)
                        row = {"capture": cap.name, "protocol": protocol, "fold": fold.k, "feature_set": fs,
                               "model": family, "params": json.dumps(params), "seed": seed,
                               "test_attack": m["attack"], **{k: m.get(k) for k in ("pr_auc", "roc_auc", "recall_at_fpr_0.001")}}
                        if protocol == "blocked" and len(clean):
                            row["clean_fpr"] = float((predict(model, cap, clean, cols) >= thr).mean())
                        imp = mean_abs_attribution(model, family, Xe)
                        if imp is not None and imp.sum() > 0:
                            for f in FAMILIES:
                                row[f"share_{f}"] = float(imp[fams[cols] == f].sum() / imp.sum())
                            row["share_FV"] = float(imp[fv[cols]].sum() / imp.sum())
                        if seed == 0:
                            row.update(permutation_drops(model, Xe, ye, fams[cols], seed))
                        row["seconds"] = round(time.time() - t0, 1)
                        new = not RUNS.exists()
                        with open(RUNS, "a", newline="", encoding="utf-8") as fh:
                            w = csv.DictWriter(fh, fieldnames=FIELDS)
                            if new:
                                w.writeheader()
                            w.writerow(row)
                        print(f"[S4] {cap.name} {protocol:<7} fold {fold.k:>2} {fs:<5} {family:<3} seed {seed}  "
                              f"PR-AUC {m['pr_auc']:.4f}  A-share {row.get('share_A', float('nan')):.3f}  "
                              f"({row['seconds']} s)", flush=True)


def fold_ci(per_fold: np.ndarray, n_boot: int = 2000) -> list[float]:
    rng = np.random.default_rng(0)
    means = [rng.choice(per_fold, len(per_fold)).mean() for _ in range(n_boot)]
    return [round(float(np.percentile(means, q)), 4) for q in (2.5, 97.5)]


def summarise(df: pd.DataFrame) -> dict:
    out = {}
    for cap, d in df.groupby("capture"):
        b, r = d[d["protocol"] == "blocked"], d[d["protocol"] == "random"]
        res = {"pr_auc": {p: x.groupby(["feature_set", "model"])["pr_auc"].mean().round(4).unstack().to_dict()
                          for p, x in (("blocked", b), ("random", r))},
               "clean_fpr_blocked": b.groupby(["feature_set", "model"])["clean_fpr"].mean().round(5).unstack().to_dict()}
        ball = b[(b["feature_set"] == "F-all") & b["model"].isin(ATTRIBUTED)]
        shares = ball.groupby("model")[[f"share_{f}" for f in FAMILIES] + ["share_FV"]].mean()
        res["attribution_shares_blocked_f_all"] = shares.round(4).to_dict(orient="index")
        res["acrs_blocked_f_all"] = (shares["share_A"] + shares["share_C"]).round(4).to_dict()
        perm = b[(b["feature_set"] == "F-all") & (b["seed"] == 0)].groupby("model")[[f"perm_{f}" for f in FAMILIES]].mean()
        res["permutation_drop_blocked_f_all_seed0"] = perm.round(4).to_dict(orient="index")

        # H2a: median ARS >= 0.25 and removing A costs >= 10% PR-AUC for >= 3 of 5 models
        median_ars = float(shares["share_A"].median())
        abl = {}
        for fam in GRIDS:
            a = b[(b["model"] == fam) & (b["feature_set"] == "F-all")].set_index(["fold", "seed"])["pr_auc"]
            n = b[(b["model"] == fam) & (b["feature_set"] == "F-noA")].set_index(["fold", "seed"])["pr_auc"]
            pair = pd.concat([a.rename("a"), n.rename("n")], axis=1).dropna()
            if len(pair):
                drop = (pair["a"] - pair["n"]) / pair["a"]
                ci = fold_ci(drop.groupby(level="fold").mean().to_numpy())
                abl[fam] = {"mean_relative_drop": round(float(drop.mean()), 4), "ci95": ci,
                            "meets": bool(drop.mean() >= 0.10 and ci[0] > 0)}
        res["H2a"] = {"median_ars": round(median_ars, 4), "ars_threshold": 0.25, "ablation_without_A": abl,
                      "supported": bool(median_ars >= 0.25 and sum(v["meets"] for v in abl.values()) >= 3)}

        # H2b: random split vs blocked, paired over model x feature set x seed (blocked = mean over folds)
        bm = b.groupby(["model", "feature_set", "seed"])[["pr_auc", "share_A"]].mean()
        rm = r.set_index(["model", "feature_set", "seed"])[["pr_auc", "share_A"]]
        pair = bm.join(rm, lsuffix="_blocked", rsuffix="_random", how="inner")
        h2b = {}
        for metric, sub in (("pr_auc", pair), ("share_A", pair.xs("F-all", level="feature_set").dropna())):
            diff = (sub[f"{metric}_random"] - sub[f"{metric}_blocked"]).dropna()
            p = float(wilcoxon(diff, alternative="greater").pvalue) if (diff != 0).any() else 1.0
            h2b[metric] = {"pairs": int(len(diff)), "mean_random": round(float(sub[f"{metric}_random"].mean()), 4),
                           "mean_blocked": round(float(sub[f"{metric}_blocked"].mean()), 4),
                           "median_difference": round(float(diff.median()), 4), "wilcoxon_p_one_sided": p}
        res["H2b"] = {**h2b, "note": "raw p-values; Holm correction across the confirmatory family at the end"}

        # H2c: stability of the family ranking across seeds, within model and fold
        taus = {}
        for fam, x in ball.groupby("model"):
            vals = []
            for _, xf in x.groupby("fold"):
                ranks = xf[[f"share_{f}" for f in FAMILIES]].to_numpy()
                vals += [kendalltau(u, v)[0] for u, v in combinations(ranks, 2)]
            taus[fam] = round(float(np.nanmean(vals)), 4) if vals else None
        res["H2c"] = {"mean_kendall_tau_across_seeds": taus, "threshold": 0.6,
                      "supported": bool(all(t >= 0.6 for t in taus.values() if t is not None))}
        out[cap] = res
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--captures", nargs="+", default=["rogue_ap", "evil_twin"])
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()
    if not args.summary_only:
        paths = load_paths()
        for name in args.captures:
            run_capture(Capture.load(paths["interim_dir"], name))
    summary = summarise(read_runs(RUNS))
    out = write_result("S4_reliance", {"results": summary}, run_metadata("scripts/08_s4_reliance.py"))
    print(f"[S4] Done -> {out}")
    for cap, r in summary.items():
        print(f"  {cap}: median ARS {r['H2a']['median_ars']} -> H2a {r['H2a']['supported']}; "
              f"H2b PR-AUC random {r['H2b']['pr_auc']['mean_random']} vs blocked {r['H2b']['pr_auc']['mean_blocked']} "
              f"(p={r['H2b']['pr_auc']['wilcoxon_p_one_sided']:.3g}); H2c {r['H2c']['mean_kendall_tau_across_seeds']}")


if __name__ == "__main__":
    main()
