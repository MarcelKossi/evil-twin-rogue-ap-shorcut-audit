"""Stage S7 - imbalance probe (protocol RQ4, H4).

RF and XGB on F-all, three arms:
  none       no class weighting (class_weight=None, scale_pos_weight=1)
  weighting  class weighting, as in S4 and S5: these runs are taken from results/S4_runs.csv and
             results/S5_runs.csv (same code, data, hyperparameters and seeds), not refitted
  smote      no class weighting; SMOTE (imbalanced-learn, k = 5) on the training rows only, after the
             -1 fill used by the tree pipelines. Only the attack class is oversampled, up to the number
             of normal rows; when a training set already has at least as many attack rows as normal
             rows (Evil_Twin on AWID3, after the cap of deviation 4), no synthetic row is added
Hyperparameters: those chosen in S4 (in-domain) and S5 (transfer) for the same fold, set and model.
In-domain: AWID3 Rogue_AP and Evil_Twin, blocked protocol, 5 folds, seeds 0-4; PR-AUC on the test
block and ARS (artefact share of the attribution on the S4 evaluation sample).
Transfer: Evil_Twin only, AWID3 <-> AWID2 on the shared fields, as in S5 (the third dataset of
protocol 6.3 is not available, so Rogue_AP transfer and the real-frame arm are not performed).
H4, decided before running (journal, 2026-11-21), SMOTE against weighting:
  (i)   in-domain PR-AUC higher: one-sided Wilcoxon over model x capture x seed (fold means);
  (ii)  transfer gap not reduced: mean dG = G(smote) - G(weighting) over model x direction x seed,
        95% bootstrap CI; holds if mean dG >= 0 or the CI includes 0;
  (iii) ARS higher: one-sided Wilcoxon as in (i).
H4 is supported if all three hold; its p-value for Holm (S8) is the larger of (i) and (iii).

Usage (from the repository root):
    python scripts/15_s7_smote.py --seeds 0     # first pass
    python scripts/15_s7_smote.py               # seeds 0-4 (finished runs are skipped)
    python scripts/15_s7_smote.py --summary-only
Output: results/S7_runs.csv, results/S7_smote.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import wilcoxon

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.attribution import mean_abs_attribution  # noqa: E402
from src.modeling import Capture, make_folds, make_model, pr_auc, predict, sample_training  # noqa: E402
from src.utils import ROOT, load_paths, run_metadata, sha256_file, write_result  # noqa: E402


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


s4 = _load("s4", "08_s4_reliance.py")        # eval_sample
s5 = _load("s5", "13_s5_transfer.py")        # load, kept_fields, sets_for, awid2_fold
MODELS, ARMS = ["RF", "XGB"], ["none", "smote"]
RUNS = ROOT / "results" / "S7_runs.csv"
S4_RUNS, S5_RUNS = ROOT / "results" / "S4_runs.csv", ROOT / "results" / "S5_runs.csv"
KEY = ["part", "where", "kind", "model", "arm", "seed", "fold"]


def fit_arm(cap: Capture, family: str, params: dict, seed: int, rows: np.ndarray, cols: np.ndarray,
            sample_seed: int, arm: str):
    idx = sample_training(rows, cap.y, sample_seed)
    X, y = cap.rows(idx, cols), cap.y[idx]
    model = make_model(family, params, seed, pos_weight=1.0)
    if family == "RF":
        model[-1].set_params(class_weight=None)
    n_pos, n_neg, synthetic = int(y.sum()), int((y == 0).sum()), 0
    if arm == "smote" and n_pos < n_neg:      # only the attack class is ever oversampled
        from imblearn.over_sampling import SMOTE
        X = np.where(np.isnan(X), -1.0, X)    # the same -1 fill as the tree pipelines
        X, y = SMOTE(sampling_strategy={1: n_neg}, k_neighbors=5, random_state=seed).fit_resample(X, y)
        synthetic = int(len(y)) - n_pos - n_neg
    model.fit(X, y)
    return model, n_pos + n_neg, n_pos, synthetic


def ars(model, family: str, cap: Capture, E: np.ndarray, cols: np.ndarray) -> float:
    imp = mean_abs_attribution(model, family, cap.rows(E, cols))
    fam = np.array([cap.families.get(cap.columns[c], "U") for c in cols])
    return float(imp[fam == "A"].sum() / imp.sum()) if imp is not None and imp.sum() > 0 else float("nan")


def append(row: dict) -> None:
    pd.DataFrame([row]).to_csv(RUNS, mode="a", header=not RUNS.exists(), index=False)


def in_domain(interim: Path, seeds: list[int], finished: set) -> None:
    ref = pd.read_csv(S4_RUNS)
    for name in ("rogue_ap", "evil_twin"):
        cap = Capture.load(interim, name)
        cols = np.arange(len(cap.columns))
        for fold in make_folds(cap)[0]:
            E = s4.eval_sample(cap, fold.test, seed=fold.k)
            for family in MODELS:
                r4 = ref[(ref["capture"] == name) & (ref["protocol"] == "blocked") & (ref["feature_set"] == "F-all")
                         & (ref["model"] == family) & (ref["fold"] == fold.k)]
                params = json.loads(r4["params"].iloc[0])
                for arm in ARMS:
                    for seed in seeds:
                        if ("in", name, "blocked", family, arm, str(seed), str(fold.k)) in finished:
                            continue
                        t0 = time.time()
                        model, n, n_att, n_syn = fit_arm(cap, family, params, seed, fold.train, cols, fold.k, arm)
                        row = {"part": "in", "where": name, "kind": "blocked", "model": family, "arm": arm,
                               "seed": seed, "fold": fold.k, "n_train": n, "attack_train": n_att, "synthetic": n_syn,
                               "pr_auc": pr_auc(cap.y[fold.test], predict(model, cap, fold.test, cols)),
                               "ars": ars(model, family, cap, E, cols), "seconds": round(time.time() - t0, 1)}
                        append(row)
                        print(f"[S7] {name} fold {fold.k} {family} {arm:<5} seed {seed}  PR-AUC {row['pr_auc']:.4f}  "
                              f"ARS {row['ars']:.3f}  ({n_att} attack / {n} rows, {n_syn} synthetic)", flush=True)


def transfer(interim: Path, seeds: list[int], finished: set) -> None:
    caps, meta = s5.load(interim)
    ref = pd.read_csv(S5_RUNS)
    folds = {"awid3": make_folds(caps["awid3"])[0], "awid2": [s5.awid2_fold(caps["awid2"])]}
    for direction, (src, tgt) in s5.DIRECTIONS.items():
        S, T = caps[src], caps[tgt]
        cols = s5.sets_for(S, s5.kept_fields(S, meta, src))["F-all"]
        jobs = [("s2t", None, -1)] + [("t2t", f, f.k) for f in folds[tgt]]
        for family in MODELS:
            for kind, fold, k in jobs:
                r5 = ref[(ref["direction"] == direction) & (ref["kind"] == kind) & (ref["feature_set"] == "F-all")
                         & (ref["model"] == family) & (ref["fold"] == k)]
                params = json.loads(r5["params"].iloc[0])
                for arm in ARMS:
                    for seed in seeds:
                        if ("transfer", direction, kind, family, arm, str(seed), str(k)) in finished:
                            continue
                        cap, rows = (S, np.arange(len(S.y))) if kind == "s2t" else (T, fold.train)
                        test = np.arange(len(T.y)) if kind == "s2t" else fold.test
                        t0 = time.time()
                        model, n, n_att, n_syn = fit_arm(cap, family, params, seed, rows, cols, max(k, 0), arm)
                        row = {"part": "transfer", "where": direction, "kind": kind, "model": family, "arm": arm,
                               "seed": seed, "fold": k, "n_train": n, "attack_train": n_att, "synthetic": n_syn,
                               "pr_auc": pr_auc(T.y[test], predict(model, T, test, cols)), "ars": np.nan,
                               "seconds": round(time.time() - t0, 1)}
                        append(row)
                        print(f"[S7] {direction} {kind} {family} {arm:<5} seed {seed} fold {k:>2}  "
                              f"PR-AUC {row['pr_auc']:.4f}  ({n_syn} synthetic)", flush=True)


def weighting_rows() -> pd.DataFrame:
    """The weighting arm, from S4 (in-domain) and S5 (transfer)."""
    a = pd.read_csv(S4_RUNS)
    a = a[(a["protocol"] == "blocked") & (a["feature_set"] == "F-all") & a["model"].isin(MODELS)]
    a = pd.DataFrame({"part": "in", "where": a["capture"], "kind": "blocked", "model": a["model"], "arm": "weighting",
                      "seed": a["seed"], "fold": a["fold"], "pr_auc": a["pr_auc"], "ars": a["share_A"]})
    b = pd.read_csv(S5_RUNS)
    b = b[(b["feature_set"] == "F-all") & b["model"].isin(MODELS)]
    b = pd.DataFrame({"part": "transfer", "where": b["direction"], "kind": b["kind"], "model": b["model"],
                      "arm": "weighting", "seed": b["seed"], "fold": b["fold"], "pr_auc": b["pr_auc"], "ars": np.nan})
    return pd.concat([a, b], ignore_index=True)


def summarise(df: pd.DataFrame) -> dict:
    ind = df[df["part"] == "in"].groupby(["where", "model", "arm", "seed"])[["pr_auc", "ars"]].mean()
    tr = df[df["part"] == "transfer"]
    t2t = tr[tr["kind"] == "t2t"].groupby(["where", "model", "arm", "seed"])["pr_auc"].mean()
    s2t = tr[tr["kind"] == "s2t"].set_index(["where", "model", "arm", "seed"])["pr_auc"]
    g = (1 - s2t / t2t).dropna().rename("G")
    out = {"in_domain_means": {f"{w} | {m} | {a}": {k: round(float(v), 4) for k, v in x.mean().items()}
                               for (w, m, a), x in ind.groupby(level=["where", "model", "arm"])},
           "transfer_G_means": {f"{w} | {m} | {a}": round(float(x.mean()), 4)
                                for (w, m, a), x in g.groupby(level=["where", "model", "arm"])}}

    def paired(series: pd.Series, a: str, b: str) -> pd.DataFrame:
        u = series.unstack("arm")
        return u[[a, b]].dropna() if {a, b} <= set(u.columns) else pd.DataFrame(columns=[a, b])

    pi, pa, pg = paired(ind["pr_auc"], "smote", "weighting"), paired(ind["ars"], "smote", "weighting"), \
        paired(g, "smote", "weighting")
    def one_sided(p: pd.DataFrame) -> float:
        d = (p["smote"] - p["weighting"]).to_numpy()
        if len(d) < 2:
            return float("nan")
        if not np.any(d != 0):              # no difference at all: no evidence for an increase
            return 1.0
        return float(wilcoxon(d, alternative="greater").pvalue)

    p_i, p_iii = one_sided(pi), one_sided(pa)
    dg = (pg["smote"] - pg["weighting"]).to_numpy()
    rng = np.random.default_rng(0)
    boot = [rng.choice(dg, len(dg)).mean() for _ in range(2000)] if len(dg) else [np.nan]
    lo, hi = np.percentile(boot, [2.5, 97.5])
    ii = bool(len(dg) and (dg.mean() >= 0 or lo <= 0 <= hi))
    syn = df[(df["arm"] == "smote")].groupby(["part", "where"])["synthetic"]
    out["smote_runs_without_synthetic_rows"] = {f"{p} | {w}": f"{int((x == 0).sum())} of {len(x)}" for (p, w), x in syn}
    out["H4"] = {
        "i_in_domain_pr_auc": {"pairs": int(len(pi)), "mean_smote": float(pi["smote"].mean()),
                               "mean_weighting": float(pi["weighting"].mean()), "wilcoxon_p_one_sided": p_i},
        "ii_transfer_gap": {"pairs": int(len(dg)), "mean_dG": float(np.mean(dg)) if len(dg) else None,
                            "ci95": [float(lo), float(hi)], "holds": ii},
        "iii_ars": {"pairs": int(len(pa)), "mean_smote": float(pa["smote"].mean()),
                    "mean_weighting": float(pa["weighting"].mean()), "wilcoxon_p_one_sided": p_iii},
        "p_for_holm": float(max(p_i, p_iii)),
        "supported_before_holm": bool(p_i < 0.05 and ii and p_iii < 0.05)}
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seeds", nargs="+", type=int, default=[0, 1, 2, 3, 4])
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()
    interim = load_paths()["interim_dir"]
    if not args.summary_only:
        done = pd.read_csv(RUNS) if RUNS.exists() else pd.DataFrame(columns=KEY)
        finished = set(map(tuple, done[KEY].astype(str).to_numpy()))
        in_domain(interim, args.seeds, finished)
        transfer(interim, args.seeds, finished)
    df = pd.concat([pd.read_csv(RUNS), weighting_rows()], ignore_index=True)
    res = summarise(df)
    print(f"[S7] H4: {json.dumps(res['H4'])}")
    inputs = {p.name: sha256_file(p) for p in [S4_RUNS, S5_RUNS]}
    out = write_result("S7_smote", {"results": res}, run_metadata("scripts/15_s7_smote.py", inputs_sha256=inputs))
    print(f"[S7] Done -> {out}")


if __name__ == "__main__":
    main()
