"""Blocked cross-validation, models and metrics shared by the modelling stages."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score, matthews_corrcoef, precision_recall_curve, roc_auc_score, roc_curve
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

# Protocol Section 9.2
WINDOWS = {"rogue_ap": (1_198_551, 1_973_111), "evil_twin": (1_420_038, 3_778_728)}
K_BLOCKS = 5
PURGE = 10_000            # frames removed from training on each side of a held-out block
CLEAN_SHARE = 0.2         # last part of the pre-attack period, kept out of training for the clean-period check
MAX_NEGATIVES = 100_000   # normal frames sampled per training set (all attack frames are kept)
PREDICT_ROWS = 100_000

# Fields used by the published filters (protocol Section 7.3)
FILTER_VARIABLES = ["frame.number", "frame.len", "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.protected",
                    "ip.src", "ip.dst", "wlan.sa", "wlan.da", "wlan.ta", "wlan.ra", "wlan.bssid"]

GRIDS = {
    "LR": [{"C": 0.1}, {"C": 1.0}, {"C": 10.0}],
    "DT": [{"max_depth": 8}, {"max_depth": 16}, {"max_depth": None}],
    "RF": [{"max_depth": None}, {"max_depth": 20}],
    "XGB": [{"max_depth": 4}, {"max_depth": 8}],
    "MLP": [{"alpha": 1e-4}, {"alpha": 1e-3}],
}
DETERMINISTIC = {"LR"}


@dataclass
class Capture:
    name: str
    X: np.ndarray            # memory-mapped float32 matrix
    y: np.ndarray
    fn: np.ndarray
    columns: list[str]
    families: dict[str, str]

    @classmethod
    def load(cls, interim: Path, name: str) -> "Capture":
        meta = json.loads((interim / f"awid3_{name}_features.json").read_text(encoding="utf-8"))
        cols = [c["name"] for c in meta["columns"]]
        return cls(name, np.load(interim / meta["matrix"], mmap_mode="r"),
                   np.load(interim / f"awid3_{name}_y.npy"), np.load(interim / f"awid3_{name}_fn.npy"),
                   cols, {c["name"]: c["family"] for c in meta["columns"]})

    def col_index(self, names: list[str]) -> np.ndarray:
        return np.array([self.columns.index(c) for c in names if c in self.columns], dtype=int)

    def rows(self, idx: np.ndarray, cols: np.ndarray) -> np.ndarray:
        """Rows by index (sorted), selected columns, read in chunks from the memory map."""
        out = np.empty((len(idx), len(cols)), dtype=np.float32)
        for s in range(0, len(idx), PREDICT_ROWS):
            part = idx[s:s + PREDICT_ROWS]
            out[s:s + len(part)] = np.asarray(self.X[part])[:, cols]
        return out


@dataclass
class Fold:
    k: int
    test: np.ndarray
    val: np.ndarray
    train: np.ndarray        # all rows allowed for the final fit
    tune_train: np.ndarray   # rows allowed for tuning (val block and its purge zone removed)


def _purge(rows: np.ndarray, fn: np.ndarray, held: np.ndarray) -> np.ndarray:
    lo, hi = fn[held[0]] - PURGE, fn[held[-1]] + PURGE
    return rows[(fn[rows] < lo) | (fn[rows] > hi)]


def make_folds(cap: Capture) -> tuple[list[Fold], np.ndarray, dict]:
    lo, hi = WINDOWS[cap.name]
    window = np.flatnonzero((cap.fn >= lo) & (cap.fn <= hi))
    blocks = np.array_split(window, K_BLOCKS)
    pre = np.flatnonzero(cap.fn < lo)
    n_clean = int(len(pre) * CLEAN_SHARE)
    clean, pre_train = pre[len(pre) - n_clean:], pre[:len(pre) - n_clean]
    folds = []
    for k in range(K_BLOCKS):
        test = blocks[k]
        val = blocks[k + 1] if k < K_BLOCKS - 1 else blocks[k - 1]
        others = np.concatenate([blocks[j] for j in range(K_BLOCKS) if j != k])
        train = np.concatenate([pre_train, _purge(others, cap.fn, test)])
        tune_train = _purge(train[~np.isin(train, val)], cap.fn, val)
        folds.append(Fold(k, test, val, np.sort(train), np.sort(tune_train)))
    info = {"window": [lo, hi], "pre_window_train_rows": int(len(pre_train)), "clean_rows": int(len(clean)),
            "blocks": [{"k": k, "rows": int(len(b)), "attack": int(cap.y[b].sum()),
                        "frame_number": [int(cap.fn[b[0]]), int(cap.fn[b[-1]])]} for k, b in enumerate(blocks)]}
    return folds, clean, info


def sample_training(rows: np.ndarray, y: np.ndarray, seed: int) -> np.ndarray:
    pos = rows[y[rows] == 1]
    neg = rows[y[rows] == 0]
    if len(neg) > MAX_NEGATIVES:
        neg = np.random.default_rng(seed).choice(neg, MAX_NEGATIVES, replace=False)
    return np.sort(np.concatenate([pos, neg]))


def make_model(family: str, params: dict, seed: int, pos_weight: float):
    tree_fill = SimpleImputer(strategy="constant", fill_value=-1, keep_empty_features=True)
    if family == "LR":
        return make_pipeline(SimpleImputer(strategy="median", add_indicator=True, keep_empty_features=True),
                             StandardScaler(), LogisticRegression(C=params["C"], class_weight="balanced", max_iter=1000))
    if family in ("DT", "DT3"):
        return make_pipeline(tree_fill, DecisionTreeClassifier(max_depth=params["max_depth"], class_weight="balanced",
                                                               random_state=seed))
    if family == "RF":
        return make_pipeline(tree_fill, RandomForestClassifier(n_estimators=300, max_depth=params["max_depth"],
                                                               class_weight="balanced_subsample", n_jobs=-1,
                                                               random_state=seed))
    if family == "XGB":
        from xgboost import XGBClassifier
        return make_pipeline(tree_fill, XGBClassifier(n_estimators=300, max_depth=params["max_depth"], learning_rate=0.1,
                                                      tree_method="hist", scale_pos_weight=pos_weight, n_jobs=-1,
                                                      random_state=seed, eval_metric="aucpr"))
    if family == "MLP":
        return make_pipeline(SimpleImputer(strategy="median", add_indicator=True, keep_empty_features=True),
                             StandardScaler(), MLPClassifier(hidden_layer_sizes=(64, 32), alpha=params["alpha"],
                                                             early_stopping=True, max_iter=200, random_state=seed))
    raise ValueError(family)


def fit(cap: Capture, family: str, params: dict, seed: int, rows: np.ndarray, cols: np.ndarray, sample_seed: int):
    idx = sample_training(rows, cap.y, sample_seed)
    yt = cap.y[idx]
    pos_weight = float((yt == 0).sum()) / max(int(yt.sum()), 1)
    model = make_model(family, params, seed, pos_weight)
    model.fit(cap.rows(idx, cols), yt)
    return model, len(idx), int(yt.sum())


def predict(model, cap: Capture, rows: np.ndarray, cols: np.ndarray) -> np.ndarray:
    out = np.empty(len(rows), dtype=np.float32)
    for s in range(0, len(rows), PREDICT_ROWS):
        part = rows[s:s + PREDICT_ROWS]
        out[s:s + len(part)] = model.predict_proba(cap.rows(part, cols))[:, 1]
    return out


def pr_auc(y: np.ndarray, s: np.ndarray) -> float:
    return float(average_precision_score(y, s)) if 0 < y.sum() < len(y) else float("nan")


def f1_threshold(y: np.ndarray, s: np.ndarray) -> float:
    if y.sum() == 0:
        return 0.5
    p, r, t = precision_recall_curve(y, s)
    f1 = 2 * p * r / np.maximum(p + r, 1e-12)
    i = int(np.nanargmax(f1[:-1])) if len(t) else 0
    return float(t[i]) if len(t) else 0.5


def metrics(y: np.ndarray, s: np.ndarray, threshold: float) -> dict:
    out = {"n": int(len(y)), "attack": int(y.sum()), "prevalence": float(y.mean()), "pr_auc": pr_auc(y, s)}
    if 0 < y.sum() < len(y):
        out["roc_auc"] = float(roc_auc_score(y, s))
        fpr, tpr, _ = roc_curve(y, s)
        for target in (1e-3, 1e-2):
            out[f"recall_at_fpr_{target:g}"] = float(tpr[fpr <= target].max()) if (fpr <= target).any() else 0.0
        pred = s >= threshold
        out["mcc"] = float(matthews_corrcoef(y, pred))
        out["f1"] = float(f1_score(y, pred, zero_division=0))
    return out
