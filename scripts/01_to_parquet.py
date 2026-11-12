"""Stage S1a - convert the AWID3 Evil_Twin and Rogue_AP CSVs to Parquet.

All 254 columns are kept as text, exactly as exported; typing happens later
(S2). Two columns are added to trace every row back to the source:
source_file and row_in_file. Rows are not filtered here.

Usage (from the repository root):
    python scripts/01_to_parquet.py
Output:
    data/interim/awid3_evil_twin.parquet, data/interim/awid3_rogue_ap.parquet
    results/S1_parquet_manifest.json
"""

from __future__ import annotations

import argparse
import sys
import time
import zipfile
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.awid3 import class_members, read_member  # noqa: E402
from src.utils import load_paths, run_metadata, sha256_file, write_result  # noqa: E402

CHUNK_ROWS = 100_000


def convert_class(zf: zipfile.ZipFile, name: str, out_path: Path) -> dict:
    members = class_members(zf, name)
    if not members:
        sys.exit(f"No CSV found for {name}.")
    writer = None
    schema = None
    total = 0
    per_file = {}
    t0 = time.time()
    try:
        for member in members:
            n_file = 0
            for chunk in read_member(zf, member, CHUNK_ROWS):
                chunk["source_file"] = member.split("/")[-1]
                chunk["row_in_file"] = range(n_file, n_file + len(chunk))
                n_file += len(chunk)
                if schema is None:
                    fields = [pa.field(c, pa.string()) for c in chunk.columns if c not in ("row_in_file",)]
                    schema = pa.schema(fields + [pa.field("row_in_file", pa.int64())])
                    writer = pq.ParquetWriter(out_path, schema, compression="zstd")
                chunk = chunk[[f.name for f in schema]]
                writer.write_table(pa.Table.from_pandas(chunk, schema=schema, preserve_index=False))
            per_file[member] = n_file
            total += n_file
            print(f"[S1a] {name:<9} {member.split('/')[-1]:<22} {n_file:>7,} rows", flush=True)
    finally:
        if writer is not None:
            writer.close()
    return {
        "parquet": str(out_path.name),
        "rows": total,
        "n_columns": len(schema),
        "files": len(members),
        "rows_per_file": per_file,
        "parquet_bytes": out_path.stat().st_size,
        "parquet_sha256": sha256_file(out_path),
        "seconds": round(time.time() - t0, 1),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--classes", nargs="+", default=["Evil_Twin", "Rogue_AP"])
    args = parser.parse_args()

    paths = load_paths()
    out_dir = paths["interim_dir"]
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = {}
    with zipfile.ZipFile(paths["awid3_csv_zip"]) as zf:
        for name in args.classes:
            out_path = out_dir / f"awid3_{name.lower()}.parquet"
            summary[name] = convert_class(zf, name, out_path)

    out = write_result("S1_parquet_manifest", {"classes": summary},
                       run_metadata("scripts/01_to_parquet.py", archive=paths["awid3_csv_zip"].name))
    print(f"\n[S1a] Done -> {out}")
    for name, s in summary.items():
        print(f"  {name}: {s['rows']:,} rows, {s['parquet_bytes'] / 1e9:.2f} GB, {s['seconds']} s")


if __name__ == "__main__":
    main()
