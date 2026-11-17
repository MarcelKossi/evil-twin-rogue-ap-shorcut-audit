"""Per-feature attributions (mean |contribution| over an evaluation sample)."""

from __future__ import annotations

import numpy as np
from scipy import sparse


def _tree_contributions(tree, Z: np.ndarray) -> np.ndarray:
    """Saabas contributions of one sklearn tree: change in P(attack) at each split on the path."""
    t = tree.tree_
    v = t.value[:, 0, :]
    v = (v / v.sum(axis=1, keepdims=True))[:, 1]
    parent = np.full(t.node_count, -1)
    for side in (t.children_left, t.children_right):
        has = side >= 0
        parent[side[has]] = np.flatnonzero(has)
    child = np.flatnonzero(parent >= 0)
    M = sparse.csr_matrix((v[child] - v[parent[child]], (child, t.feature[parent[child]])),
                          shape=(t.node_count, Z.shape[1]))
    return np.asarray((tree.decision_path(Z) @ M).todense())


def mean_abs_attribution(model, family: str, X: np.ndarray) -> np.ndarray | None:
    """Mean |attribution| per input column; None for the MLP (excluded from attribution scores)."""
    pre, est = model[:-1], model[-1]
    Z = pre.transform(X)
    if family == "XGB":                      # exact TreeSHAP, native to XGBoost
        import xgboost
        contrib = est.get_booster().predict(xgboost.DMatrix(Z), pred_contribs=True)[:, :-1]
    elif family == "DT":
        contrib = _tree_contributions(est, Z)
    elif family == "RF":
        contrib = sum(_tree_contributions(t, Z) for t in est.estimators_) / len(est.estimators_)
    elif family == "LR":                     # linear SHAP on standardised inputs (training mean = 0)
        contrib = Z * est.coef_[0]
    else:
        return None
    imp = np.abs(contrib).mean(axis=0)
    n = X.shape[1]
    out = imp[:n].copy()
    imputer = model[0]
    if getattr(imputer, "indicator_", None) is not None:   # missing-value indicators -> their column
        np.add.at(out, imputer.indicator_.features_, imp[n:])
    return out
