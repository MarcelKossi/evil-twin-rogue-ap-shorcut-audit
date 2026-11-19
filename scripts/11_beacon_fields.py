"""Exploratory (added after S4x) - which fields of the capture separate rogue from legitimate beacons?

S2b dropped every column more than 99% missing (protocol 9.3). Fields that exist only in
management frames, such as capabilities and the RSN element, are about 99.6% missing over a
whole capture and were dropped, although the protocol lists RSN and capability information as
semantic evidence (7.1). This script goes back to the Parquet tables and compares, on the
beacons of the attack window only, every field of the capture between rogue beacons (label
attack) and legitimate beacons (label Normal, length different from every rogue beacon length,
as in the perturbation test). For each field: total variation distance between the two value
distributions (missing counted as a value; 0 = same distribution, 1 = no value in common),
whether S2b kept it, its family, and its most frequent values. Fields where most beacons
have a value of their own (timestamps, counters) score close to 1 whatever they mean, so a
field with more distinct values than half the beacons is listed apart, without a TVD reading.

Usage (from the repository root):
    python scripts/11_beacon_fields.py
Output: results/S4y_beacon_fields.json
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.awid3 import NORMAL_LABEL  # noqa: E402
from src.frames import iter_parquet, to_int  # noqa: E402
from src.modeling import WINDOWS  # noqa: E402
from src.utils import ROOT, load_paths, run_metadata, sha256_file, write_result  # noqa: E402

PARQUET = {"rogue_ap": "awid3_rogue_ap.parquet", "evil_twin": "awid3_evil_twin.parquet"}
TAXONOMY = ROOT / "docs" / "taxonomy.csv"
S2B = ROOT / "results" / "S2b_features.json"


def beacons(path: Path, window: tuple[int, int]) -> pd.DataFrame:
    import pyarrow.parquet as pq
    columns = pq.ParquetFile(path).schema.names
    parts = []
    for df in iter_parquet(path, columns, 50_000):   # small batches: all columns are read
        fn = to_int(df["frame.number"])
        keep = fn.between(*window) & (to_int(df["wlan.fc.type"]) == 0) & (to_int(df["wlan.fc.subtype"]) == 8)
        parts.append(df[keep.fillna(False).to_numpy(dtype=bool)])   # rows with a missing number or type are not beacons
    return pd.concat(parts, ignore_index=True)


def tvd(a: pd.Series, b: pd.Series) -> float:
    pa = a.fillna("<missing>").value_counts(normalize=True)
    pb = b.fillna("<missing>").value_counts(normalize=True)
    return float(0.5 * pa.sub(pb, fill_value=0).abs().sum())


def top(s: pd.Series) -> dict:
    return {str(k): round(float(v), 4) for k, v in s.fillna("<missing>").value_counts(normalize=True).head(4).items()}


def main() -> None:
    paths = load_paths()
    fams = pd.read_csv(TAXONOMY).set_index("field")["family"].to_dict()
    s2b = __import__("json").loads(S2B.read_text(encoding="utf-8"))["captures"]
    out = {}
    for name, file in PARQUET.items():
        path = paths["interim_dir"] / file
        b = beacons(path, WINDOWS[name])
        rogue = b["Label"] != NORMAL_LABEL
        flen = to_int(b["frame.len"])
        legit = ~rogue & ~flen.isin(flen[rogue].unique())
        info = s2b[name] if isinstance(s2b[name], dict) else eval(s2b[name])
        rows = []
        for c in b.columns:
            if c in ("Label", "frame.number"):
                continue
            rows.append({"field": c, "family": fams.get(c, "not classified"),
                         "kept_in_s2b": c not in info["dropped"], "s2b_reason": info["dropped"].get(c),
                         "tvd": round(tvd(b.loc[rogue, c], b.loc[legit, c]), 4),
                         "distinct": int(b.loc[rogue | legit, c].nunique()),
                         "rogue_values": top(b.loc[rogue, c]), "legit_values": top(b.loc[legit, c])})
        rows.sort(key=lambda r: -r["tvd"])
        n = int((rogue | legit).sum())
        unique = [r for r in rows if r["distinct"] > n / 2]
        rows = [r for r in rows if r["distinct"] <= n / 2]
        out[name] = {"rogue_beacons": int(rogue.sum()), "legit_beacons": int(legit.sum()),
                     "left_out_normal_beacons": int((~rogue & ~legit).sum()),
                     "fields_tvd_at_least_0.5": [r for r in rows if r["tvd"] >= 0.5],
                     "fields_tvd_below_0.5": [{k: r[k] for k in ("field", "family", "kept_in_s2b", "tvd")}
                                              for r in rows if r["tvd"] < 0.5],
                     "fields_mostly_unique_values": [{k: r[k] for k in ("field", "family", "kept_in_s2b", "distinct")}
                                                     for r in unique]}
        sep = out[name]["fields_tvd_at_least_0.5"]
        print(f"[S4y] {name}: {int(rogue.sum())} rogue / {int(legit.sum())} legitimate beacons; "
              f"{len(sep)} fields with TVD >= 0.5", flush=True)
        for r in sep[:25]:
            print(f"    {r['tvd']:.3f}  {r['family']:<15} kept={r['kept_in_s2b']!s:<5} {r['field']:<40} "
                  f"rogue {r['rogue_values']}  legit {r['legit_values']}")
        print(f"    set apart (mostly unique values): {[r['field'] for r in out[name]['fields_mostly_unique_values']]}")
    inputs = {p.name: sha256_file(p) for p in [TAXONOMY, S2B]}
    res = write_result("S4y_beacon_fields", {"exploratory": True, "results": out},
                       run_metadata("scripts/11_beacon_fields.py", inputs_sha256=inputs))
    print(f"[S4y] Done -> {res}")


if __name__ == "__main__":
    main()
