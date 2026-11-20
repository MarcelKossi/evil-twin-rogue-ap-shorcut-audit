"""Stage S5, part 2 - transfer AWID3 Evil_Twin <-> AWID2 (protocol RQ3, H3a and the F-sem part of H3b).

Data: the matrices of scripts/12_s5_prepare.py (37 shared fields, same encoding in both datasets).
For each direction source -> target, the fields kept are those not more than 99% missing and not
constant in the source domain (protocol 9.3); feature sets F-all, F-noA, F-sem and F-chatz are
taken within them. For each set, model family (5) and seed (0-4; LR once):
  s->t  tuned on the source (AWID3: validation block of fold 0; AWID2: stratified 20% of Trn),
        trained on all source rows (all attack frames, at most 100,000 normal frames),
        tested on all target rows; ARS = artefact share of the attribution on a source sample;
  t->t  in-domain score of the same set and model on the target: AWID3 blocked protocol (5 folds),
        AWID2 official split (train Trn, test Tst).
G = 1 - PR-AUC(s->t) / PR-AUC(t->t), also per sub-task (ET-B: beacons and probe responses,
ET-D: data frames). H3a: Spearman rho between ARS and G over model x set x direction (seed means,
MLP has no ARS), 95% bootstrap CI clustered by model family (2,000 resamples). H3b (F-sem part):
G(F-sem) < G(F-all), one-sided Wilcoxon over model x direction; the rule baseline comes in S6.
Raw p-values; Holm in S8.

Usage (from the repository root):
    python scripts/13_s5_transfer.py --seeds 0     # first pass
    python scripts/13_s5_transfer.py               # seeds 0-4 (finished runs are skipped)
    python scripts/13_s5_transfer.py --summary-only
Output: results/S5_runs.csv, results/S5_transfer.json
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
from scipy.stats import spearmanr, wilcoxon

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.attribution import mean_abs_attribution  # noqa: E402
from src.modeling import DETERMINISTIC, GRIDS, Capture, Fold, fit, make_folds, pr_auc, predict, tune  # noqa: E402
from src.utils import ROOT, load_paths, run_metadata, sha256_file, write_result  # noqa: E402

_spec = importlib.util.spec_from_file_location("s4", ROOT / "scripts" / "08_s4_reliance.py")
s4 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(s4)

RUNS = ROOT / "results" / "S5_runs.csv"
DIRECTIONS = {"AWID3->AWID2": ("awid3", "awid2"), "AWID2->AWID3": ("awid2", "awid3")}
SUBTASKS = {"ET-B": lambda t, s: (t == 0) & np.isin(s, [5, 8]), "ET-D": lambda t, s: t == 2}
KEY = ["direction", "kind", "feature_set", "model", "seed", "fold"]


def load(interim: Path) -> tuple[dict, list[dict]]:
    meta = json.loads((interim / "s5_features.json").read_text(encoding="utf-8"))["columns"]
    names = [c["name"] for c in meta]
    fams = {c["name"]: c["family"] if c["family"] in ("S", "A", "C", "U") else "U" for c in meta}
    caps = {}
    for tag, cap_name in (("awid3", "evil_twin"), ("awid2", "awid2")):
        caps[tag] = Capture(cap_name, np.load(interim / f"s5_{tag}_X.npy", mmap_mode="r"),
                            np.load(interim / f"s5_{tag}_y.npy"), np.load(interim / f"s5_{tag}_fn.npy"), names, fams)
    return caps, meta


def kept_fields(cap: Capture, meta: list[dict], tag: str) -> list[str]:
    """Not more than 99% missing and not constant in this domain."""
    lo, hi = np.full(len(meta), np.inf), np.full(len(meta), -np.inf)
    for s in range(0, len(cap.y), 200_000):
        part = np.asarray(cap.X[s:s + 200_000])
        lo, hi = np.fmin(lo, np.nanmin(np.where(np.isnan(part), np.inf, part), axis=0)), \
            np.fmax(hi, np.nanmax(np.where(np.isnan(part), -np.inf, part), axis=0))
    return [c["name"] for j, c in enumerate(meta) if c[f"missing_{tag}"] <= 0.99 and lo[j] < hi[j]]


def sets_for(cap: Capture, fields: list[str]) -> dict[str, np.ndarray]:
    out = {}
    for fs, fams in s4.SETS.items():
        names = [f for f in fields if (f in s4.CHATZOGLOU_16 if fams is None else cap.families[f] in fams)]
        out[fs] = cap.col_index(names)
    return out


def subtask_masks(cap: Capture, meta: list[dict], rows: np.ndarray) -> dict[str, np.ndarray]:
    off = {c["name"]: c["offset"] for c in meta}
    ts = cap.rows(rows, cap.col_index(["wlan.fc.type", "wlan.fc.subtype"]))
    t, s = ts[:, 0] + off["wlan.fc.type"], ts[:, 1] + off["wlan.fc.subtype"]
    return {k: f(t, s) for k, f in SUBTASKS.items()}


def awid2_fold(cap: Capture) -> Fold:
    split = np.load(load_paths()["interim_dir"] / "s5_awid2_split.npy")
    trn, tst = np.flatnonzero(split == 0), np.flatnonzero(split == 1)
    rng = np.random.default_rng(0)
    val = np.sort(np.concatenate([rng.choice(r, len(r) // 5, replace=False)
                                  for r in (trn[cap.y[trn] == 1], trn[cap.y[trn] == 0])]))
    return Fold(0, tst, val, trn, np.setdiff1d(trn, val))


def scores(cap: Capture, meta: list[dict], model, rows: np.ndarray, cols: np.ndarray) -> dict:
    s, y = predict(model, cap, rows, cols), cap.y[rows]
    out = {"pr_auc": pr_auc(y, s), "prevalence": float(y.mean()), "n": int(len(rows)), "attack": int(y.sum())}
    for k, m in subtask_masks(cap, meta, rows).items():
        out[f"pr_auc_{k}"], out[f"attack_{k}"], out[f"n_{k}"] = pr_auc(y[m], s[m]), int(y[m].sum()), int(m.sum())
    return out


def run(caps: dict, meta: list[dict], seeds: list[int]) -> None:
    done = pd.read_csv(RUNS) if RUNS.exists() else pd.DataFrame(columns=KEY)
    finished = set(map(tuple, done[KEY].astype(str).to_numpy()))
    folds = {"awid3": make_folds(caps["awid3"])[0], "awid2": [awid2_fold(caps["awid2"])]}
    for direction, (src, tgt) in DIRECTIONS.items():
        S, T = caps[src], caps[tgt]
        fields = kept_fields(S, meta, src)
        print(f"[S5] {direction}: {len(fields)} fields kept in the source", flush=True)
        for fs, cols in sets_for(S, fields).items():
            if not len(cols):
                continue
            for family in GRIDS:
                todo_seeds = [0] if family in DETERMINISTIC else seeds
                jobs = [("s2t", folds[src][0], -1)] + [("t2t", f, f.k) for f in folds[tgt]]
                for kind, fold, k in jobs:
                    left = [sd for sd in todo_seeds if (direction, kind, fs, family, str(sd), str(k)) not in finished]
                    if not left:
                        continue
                    cap = S if kind == "s2t" else T
                    params, _ = tune(cap, family, fold, cols)
                    for seed in left:
                        t0 = time.time()
                        rows = np.arange(len(S.y)) if kind == "s2t" else fold.train
                        model, n_train, n_att = fit(cap, family, params, seed, rows, cols, sample_seed=max(k, 0))
                        test_cap, test_rows = (T, np.arange(len(T.y))) if kind == "s2t" else (T, fold.test)
                        r = {"direction": direction, "kind": kind, "feature_set": fs, "model": family, "seed": seed,
                             "fold": k, "params": json.dumps(params), "n_fields": len(cols),
                             "fields": "|".join(S.columns[c] for c in cols), "n_train": n_train, "attack_train": n_att}
                        r.update(scores(test_cap, meta, model, test_rows, cols))
                        if kind == "s2t":
                            E = s4.eval_sample(S, np.arange(len(S.y)), seed)
                            imp = mean_abs_attribution(model, family, S.rows(E, cols))
                            fam = np.array([S.families[S.columns[c]] for c in cols])
                            r["ars"] = float(imp[fam == "A"].sum() / imp.sum()) if imp is not None and imp.sum() > 0 else np.nan
                        r["seconds"] = round(time.time() - t0, 1)
                        pd.DataFrame([r]).to_csv(RUNS, mode="a", header=not RUNS.exists(), index=False)
                        print(f"[S5] {direction} {kind} {fs:<7} {family:<3} seed {seed} fold {k:>2}  "
                              f"PR-AUC {r['pr_auc']:.4f} (B {r['pr_auc_ET-B']:.4f}, D {r['pr_auc_ET-D']:.4f})"
                              + (f"  ARS {r['ars']:.3f}" if kind == "s2t" else ""), flush=True)


def summarise(df: pd.DataFrame) -> dict:
    t2t = df[df["kind"] == "t2t"].groupby(["direction", "feature_set", "model", "seed"])[
        ["pr_auc", "pr_auc_ET-B", "pr_auc_ET-D"]].mean()
    s2t = df[df["kind"] == "s2t"].set_index(["direction", "feature_set", "model", "seed"])
    g = s2t[["ars", "pr_auc", "pr_auc_ET-B", "pr_auc_ET-D", "prevalence"]].join(t2t, rsuffix="_t2t", how="inner")
    for k in ("", "_ET-B", "_ET-D"):
        g[f"G{k}"] = 1 - g[f"pr_auc{k}"] / g[f"pr_auc{k}_t2t"]
    cfg = g.groupby(level=["direction", "feature_set", "model"]).mean()
    table = {f"{d} | {fs} | {m}": {k: (None if pd.isna(v) else round(float(v), 4)) for k, v in row.items()}
             for (d, fs, m), row in cfg.iterrows()}
    h = cfg.dropna(subset=["ars", "G"]).reset_index()
    rho = float(spearmanr(h["ars"], h["G"]).statistic) if len(h) > 2 else float("nan")
    rng, boot, families = np.random.default_rng(0), [], h["model"].unique()
    for _ in range(2000):
        pick = pd.concat([h[h["model"] == m] for m in rng.choice(families, len(families), replace=True)])
        if pick["ars"].nunique() > 1 and pick["G"].nunique() > 1:
            boot.append(spearmanr(pick["ars"], pick["G"]).statistic)
    lo, hi = (np.nanpercentile(boot, [2.5, 97.5]) if boot else (np.nan, np.nan))
    pair = cfg["G"].unstack("feature_set")[["F-sem", "F-all"]].dropna()
    p_b = float(wilcoxon(pair["F-sem"], pair["F-all"], alternative="less").pvalue) if len(pair) > 1 else float("nan")
    return {"configurations": table,
            "H3a": {"configurations": int(len(h)), "spearman_rho": rho, "ci95_clustered_by_family": [float(lo), float(hi)],
                    "supported": bool(lo > 0)},
            "H3b_f_sem_part": {"pairs": int(len(pair)), "median_G_f_sem": float(pair["F-sem"].median()),
                               "median_G_f_all": float(pair["F-all"].median()), "wilcoxon_p_one_sided": p_b,
                               "note": "the rule-baseline part of H3b comes in S6; Holm in S8"}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seeds", nargs="+", type=int, default=[0, 1, 2, 3, 4])
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()
    interim = load_paths()["interim_dir"]
    caps, meta = load(interim)
    if not args.summary_only:
        run(caps, meta, args.seeds)
    inputs = {p.name: sha256_file(p) for p in [interim / "s5_features.json", ROOT / "results" / "S5a_prepare.json"]}
    out = write_result("S5_transfer", {"results": summarise(pd.read_csv(RUNS))},
                       run_metadata("scripts/13_s5_transfer.py", inputs_sha256=inputs))
    print(f"[S5] Done -> {out}")


if __name__ == "__main__":
    main()
