"""Stage S2b - numeric feature matrices for the AWID3 Evil_Twin and Rogue_AP captures.

Three passes over each Parquet file (read in batches):
  1. profile every column: missing rate, share of values that parse as numbers
     (decimal or 0x.. hex), min and max;
  2. for text columns that are kept, collect their distinct values;
  3. write the matrix.
Columns more than 99% missing or constant are dropped and logged (protocol 9.3).
Numeric columns are stored as float32 after subtracting the column minimum, so
large values such as epoch times keep their resolution. Text columns
(addresses, names, payloads) are label-encoded on sorted distinct values, as
commonly done in the literature; columns with more than 50,000 distinct values
are hash-encoded instead. Rows without label or frame number are excluded.
Missing values stay NaN; each model handles them as set in the protocol.

Usage (from the repository root):
    python scripts/06_build_features.py
Output, per capture <c> in {evil_twin, rogue_ap}:
    data/interim/awid3_<c>_X.npy   float32 matrix (rows x kept columns), read memory-mapped
    data/interim/awid3_<c>_y.npy   1 = attack, 0 = normal
    data/interim/awid3_<c>_fn.npy  frame.number
    data/interim/awid3_<c>_features.json  column list, kind, offset, family
    results/S2b_features.json
"""

from __future__ import annotations

import json
import sys
import time
import zlib
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.awid3 import NORMAL_LABEL  # noqa: E402
from src.frames import iter_parquet  # noqa: E402
from src.utils import ROOT, load_paths, run_metadata, sha256_file, write_result  # noqa: E402

CAPTURES = {"rogue_ap": "awid3_rogue_ap.parquet", "evil_twin": "awid3_evil_twin.parquet"}
SKIP = {"Label", "source_file", "row_in_file"}
MAX_MISSING = 0.99
NUMERIC_SHARE = 0.999      # a column is numeric if at least this share of its values parse
MAX_CATEGORIES = 50_000
BATCH_ROWS = 50_000         # rows per batch; 254 text columns per row
HASH_MOD = 2**23           # hash codes stay exact in float32


def _hex(value: str) -> float:
    try:
        return float(int(value, 16))
    except ValueError:
        return np.nan


def parse_numeric(s: pd.Series) -> pd.Series:
    """Decimal or 0x.. hex values as float64; anything else becomes NaN."""
    s = s.astype("string").str.strip()
    hex_mask = s.str.lower().str.startswith("0x", na=False)
    out = pd.to_numeric(s.where(~hex_mask), errors="coerce").astype("float64")
    if hex_mask.any():
        out[hex_mask] = s[hex_mask].map(_hex).astype("float64")
    return out


def valid_rows(df: pd.DataFrame) -> pd.Series:
    return df["Label"].notna() & parse_numeric(df["frame.number"]).notna()


def profile(path: Path, columns: list[str]) -> tuple[dict, int]:
    stats = {c: {"nonnull": 0, "numeric": 0, "min": np.inf, "max": -np.inf} for c in columns}
    n = 0
    for df in iter_parquet(path, columns + ["Label"], BATCH_ROWS):
        df = df.loc[valid_rows(df)]
        n += len(df)
        for c in columns:
            col = df[c]
            nonnull = col.notna()
            stats[c]["nonnull"] += int(nonnull.sum())
            num = parse_numeric(col[nonnull])
            ok = num.notna()
            stats[c]["numeric"] += int(ok.sum())
            if ok.any():
                stats[c]["min"] = min(stats[c]["min"], float(num[ok].min()))
                stats[c]["max"] = max(stats[c]["max"], float(num[ok].max()))
    return stats, n


def decide(stats: dict, n: int) -> tuple[dict, dict]:
    kinds, dropped = {}, {}
    for c, s in stats.items():
        missing = 1 - s["nonnull"] / n
        if missing > MAX_MISSING:
            dropped[c] = f"missing {missing:.4f}"
            continue
        is_num = s["nonnull"] > 0 and s["numeric"] / s["nonnull"] >= NUMERIC_SHARE
        if is_num and s["min"] == s["max"] and s["nonnull"] == n:
            dropped[c] = "constant"
            continue
        kinds[c] = "numeric" if is_num else "text"
    return kinds, dropped


def collect_categories(path: Path, text_cols: list[str]) -> dict:
    values = {c: set() for c in text_cols}
    overflow = set()
    for df in iter_parquet(path, text_cols + ["Label", "frame.number"], BATCH_ROWS):
        df = df.loc[valid_rows(df)]
        for c in text_cols:
            if c in overflow:
                continue
            values[c].update(df[c].dropna().unique().tolist())
            if len(values[c]) > MAX_CATEGORIES:
                overflow.add(c)
                values[c] = set()
    mapping = {}
    for c in text_cols:
        if c in overflow:
            mapping[c] = None
        else:
            mapping[c] = {v: float(i) for i, v in enumerate(sorted(values[c]))}
    return mapping


def encode_text(col: pd.Series, mapping: dict | None) -> np.ndarray:
    if mapping is None:
        return col.map(lambda v: float(zlib.crc32(str(v).encode()) % HASH_MOD) if pd.notna(v) else np.nan).to_numpy("float64")
    return col.map(mapping).to_numpy("float64")


def build(name: str, path: Path, out_dir: Path, families: dict) -> dict:
    t0 = time.time()
    import pyarrow.parquet as pq
    all_cols = [c for c in pq.ParquetFile(path).schema_arrow.names if c not in SKIP]

    print(f"[S2b] {name}: pass 1/3 profiling {len(all_cols)} columns", flush=True)
    stats, n = profile(path, all_cols)
    kinds, dropped = decide(stats, n)
    kept = [c for c in all_cols if c in kinds]
    text_cols = [c for c in kept if kinds[c] == "text"]

    print(f"[S2b] {name}: pass 2/3 categories of {len(text_cols)} text columns", flush=True)
    mapping = collect_categories(path, text_cols)
    for c in text_cols:
        if mapping[c] is not None and len(mapping[c]) <= 1 and stats[c]["nonnull"] == n:
            dropped[c] = "constant"
    kept = [c for c in kept if c not in dropped]
    text_cols = [c for c in text_cols if c not in dropped]

    print(f"[S2b] {name}: pass 3/3 writing {n:,} x {len(kept)} matrix", flush=True)
    tmp = out_dir / f"awid3_{name}_X.tmp.npy"
    X = np.lib.format.open_memmap(tmp, mode="w+", dtype=np.float32, shape=(n, len(kept)))
    y = np.zeros(n, dtype=np.int8)
    fn = np.zeros(n, dtype=np.int64)
    offsets = {c: (stats[c]["min"] if kinds[c] == "numeric" else 0.0) for c in kept}
    row = 0
    for df in iter_parquet(path, kept + ["Label"] + (["frame.number"] if "frame.number" not in kept else []), BATCH_ROWS):
        df = df.loc[valid_rows(df)]
        m = len(df)
        block = np.empty((m, len(kept)), dtype=np.float32)
        for j, c in enumerate(kept):
            if kinds[c] == "numeric":
                block[:, j] = (parse_numeric(df[c]).to_numpy("float64") - offsets[c]).astype(np.float32)
            else:
                block[:, j] = encode_text(df[c], mapping[c]).astype(np.float32)
        X[row:row + m] = block
        y[row:row + m] = (df["Label"] != NORMAL_LABEL).to_numpy()
        fn[row:row + m] = parse_numeric(df["frame.number"]).to_numpy().astype(np.int64)
        row += m
    X.flush()
    del X
    final = out_dir / f"awid3_{name}_X.npy"
    if final.exists():
        final.unlink()
    tmp.rename(final)
    np.save(out_dir / f"awid3_{name}_y.npy", y)
    np.save(out_dir / f"awid3_{name}_fn.npy", fn)

    columns = [{"name": c, "kind": kinds[c], "offset": offsets[c], "family": families.get(c, "?"),
                "missing_rate": round(1 - stats[c]["nonnull"] / n, 6),
                "encoding": ("number" if kinds[c] == "numeric" else
                             ("hash" if mapping[c] is None else f"label ({len(mapping[c])} values)"))}
               for c in kept]
    meta = {"rows": n, "columns": columns, "matrix": final.name}
    with open(out_dir / f"awid3_{name}_features.json", "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=1)
    return {"rows": n, "attack_rows": int(y.sum()), "kept": len(kept), "dropped": dropped,
            "kept_by_family": pd.Series([col["family"] for col in columns]).value_counts().to_dict(),
            "text_columns": {c: columns[kept.index(c)]["encoding"] for c in text_cols},
            "frame_number_monotonic": bool(np.all(np.diff(fn) > 0)),
            "seconds": round(time.time() - t0, 1)}


def main() -> None:
    paths = load_paths()
    out_dir = paths["interim_dir"]
    tax = pd.read_csv(ROOT / "docs" / "taxonomy.csv", dtype=str, keep_default_na=False)
    families = dict(zip(tax["field"], tax["family"]))
    summary, inputs = {}, {}
    for name, fname in CAPTURES.items():
        path = out_dir / fname
        inputs[fname] = sha256_file(path)
        summary[name] = build(name, path, out_dir, families)
        s = summary[name]
        print(f"  {name}: {s['rows']:,} rows ({s['attack_rows']:,} attack), {s['kept']} columns kept, "
              f"{len(s['dropped'])} dropped, by family {s['kept_by_family']}, {s['seconds']} s")
    out = write_result("S2b_features", {"captures": summary},
                       run_metadata("scripts/06_build_features.py", inputs_sha256=inputs))
    print(f"[S2b] Done -> {out}")


if __name__ == "__main__":
    main()
