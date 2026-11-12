"""Stage S0 - inventory of the AWID3 CSV archive (Evil_Twin and Rogue_AP).

Reads the official zip directly, without extracting it, and records what the
later stages depend on: file layout, headers, row counts, label column and
values, frame.number continuity, raw encoding of the filter fields and their
missing rates. The data is only read, never modified.

Usage (from the repository root):
    python scripts/00_inventory.py            # inventory -> results/S0_inventory.json
    python scripts/00_inventory.py --hash     # SHA-256 of the archives -> results/S0_archive_hashes.json
"""

from __future__ import annotations

import argparse
import io
import re
import sys
import time
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.utils import load_paths, natural_key, run_metadata, sha256_file, write_result  # noqa: E402

TARGET_CLASSES = {"eviltwin": "Evil_Twin", "rogueap": "Rogue_AP"}

# Fields used by the published AWID3 filters (protocol, Section 6.1).
FILTER_FIELDS = [
    "frame.number", "frame.len", "wlan.fc.type_subtype", "wlan.fc.protected",
    "ip.src", "ip.dst", "wlan.sa", "wlan.da", "wlan.ta", "wlan.ra", "wlan.bssid",
]
NA_VALUES = ["", "?", "nan", "NaN"]
CHUNK_ROWS = 500_000


def normalise(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def find_class(member: str) -> str | None:
    """Return the target class whose name appears in the member path, if any."""
    key = normalise(member)
    for token, label in TARGET_CLASSES.items():
        if token in key:
            return label
    return None


def find_label_column(columns: list[str]) -> str:
    """Pick the label column: a column named like 'label', otherwise the last column."""
    for col in columns:
        if col.strip().lower() in {"label", "class", "attack"}:
            return col
    return columns[-1]


def archive_layout(zf: zipfile.ZipFile) -> dict:
    """Top-level view of the whole archive: CSV count and size per folder."""
    per_folder = defaultdict(lambda: {"csv_files": 0, "uncompressed_bytes": 0})
    for info in zf.infolist():
        if info.is_dir() or not info.filename.lower().endswith(".csv"):
            continue
        folder = str(Path(info.filename).parent)
        per_folder[folder]["csv_files"] += 1
        per_folder[folder]["uncompressed_bytes"] += info.file_size
    return dict(sorted(per_folder.items(), key=lambda kv: natural_key(kv[0])))


def inspect_member(zf: zipfile.ZipFile, member: str) -> dict:
    """Read one CSV member in chunks and summarise the fields S1 needs."""
    with zf.open(member) as raw:
        header = pd.read_csv(io.TextIOWrapper(raw, encoding="utf-8", errors="replace"), nrows=0)
    columns = [c.strip() for c in header.columns]
    label_col = find_label_column(columns)
    wanted = [c for c in FILTER_FIELDS if c in columns] + [label_col]

    n_rows = 0
    labels: Counter = Counter()
    subtype_raw: Counter = Counter()
    protected_raw: Counter = Counter()
    label_by_subtype: Counter = Counter()
    missing = Counter()
    first_fn = last_fn = None
    monotonic = True
    prev_fn = None

    with zf.open(member) as raw:
        reader = pd.read_csv(
            io.TextIOWrapper(raw, encoding="utf-8", errors="replace"),
            usecols=lambda c: c.strip() in wanted,
            dtype=str,
            na_values=NA_VALUES,
            keep_default_na=False,
            chunksize=CHUNK_ROWS,
        )
        for chunk in reader:
            chunk.columns = [c.strip() for c in chunk.columns]
            n_rows += len(chunk)
            labels.update(chunk[label_col].fillna("<missing>"))
            for col in wanted:
                missing[col] += int(chunk[col].isna().sum())
            if "wlan.fc.type_subtype" in chunk:
                st = chunk["wlan.fc.type_subtype"].fillna("<missing>")
                subtype_raw.update(st)
                label_by_subtype.update(zip(chunk[label_col].fillna("<missing>"), st))
            if "wlan.fc.protected" in chunk:
                protected_raw.update(chunk["wlan.fc.protected"].fillna("<missing>"))
            if "frame.number" in chunk:
                fn = pd.to_numeric(chunk["frame.number"], errors="coerce").dropna()
                if fn.empty:
                    continue
                if first_fn is None:
                    first_fn = int(fn.iloc[0])
                if prev_fn is not None and fn.iloc[0] <= prev_fn:
                    monotonic = False
                if not fn.is_monotonic_increasing:
                    monotonic = False
                prev_fn = fn.iloc[-1]
                last_fn = int(prev_fn)

    return {
        "rows": n_rows,
        "n_columns": len(columns),
        "columns": columns,
        "label_column": label_col,
        "label_counts": dict(labels.most_common()),
        "frame_number_first": first_fn,
        "frame_number_last": last_fn,
        "frame_number_increasing": monotonic,
        "missing_counts": {c: missing[c] for c in wanted},
        "type_subtype_raw_counts": dict(subtype_raw.most_common(30)),
        "protected_raw_counts": dict(protected_raw.most_common()),
        "label_by_type_subtype": {f"{lab} | {st}": n for (lab, st), n in label_by_subtype.most_common(40)},
    }


def summarise_class(files: dict[str, dict]) -> dict:
    """Merge per-file results for one class and check consistency across files."""
    names = sorted(files, key=natural_key)
    headers = {tuple(files[n]["columns"]) for n in names}
    labels: Counter = Counter()
    missing: Counter = Counter()
    rows = 0
    for n in names:
        labels.update(files[n]["label_counts"])
        missing.update(files[n]["missing_counts"])
        rows += files[n]["rows"]

    gaps = []
    for prev, nxt in zip(names, names[1:]):
        a, b = files[prev]["frame_number_last"], files[nxt]["frame_number_first"]
        if a is not None and b is not None and b != a + 1:
            gaps.append({"after": prev, "before": nxt, "last": a, "next_first": b})

    return {
        "files_in_order": names,
        "identical_headers": len(headers) == 1,
        "total_rows": rows,
        "label_counts": dict(labels.most_common()),
        "missing_rate": {c: round(missing[c] / rows, 6) if rows else None for c in missing},
        "frame_number_min": min((files[n]["frame_number_first"] for n in names if files[n]["frame_number_first"] is not None), default=None),
        "frame_number_max": max((files[n]["frame_number_last"] for n in names if files[n]["frame_number_last"] is not None), default=None),
        "frame_number_continuous_across_files": not gaps,
        "frame_number_gaps": gaps,
        "all_files_increasing": all(files[n]["frame_number_increasing"] for n in names),
    }


def run_inventory(zip_path: Path) -> None:
    t0 = time.time()
    with zipfile.ZipFile(zip_path) as zf:
        layout = archive_layout(zf)
        members = sorted(
            (i.filename for i in zf.infolist()
             if not i.is_dir() and i.filename.lower().endswith(".csv") and find_class(i.filename)),
            key=natural_key,
        )
        if not members:
            sys.exit(f"No Evil_Twin / Rogue_AP CSV found in {zip_path}. See the layout with --layout-only.")

        sizes = {i.filename: (i.file_size, i.compress_size) for i in zf.infolist()}
        per_class: dict[str, dict[str, dict]] = defaultdict(dict)
        for member in members:
            label = find_class(member)
            print(f"[S0] {label:<9} {member} ({sizes[member][0] / 1e6:,.0f} MB)", flush=True)
            info = inspect_member(zf, member)
            info["uncompressed_bytes"], info["compressed_bytes"] = sizes[member]
            per_class[label][member] = info

    classes = {label: summarise_class(files) for label, files in per_class.items()}
    for files in per_class.values():
        first = next(iter(files.values()))
        for info in files.values():
            if info["columns"] == first["columns"] and info is not first:
                info["columns"] = "same as first file"

    meta = run_metadata("scripts/00_inventory.py", archive=zip_path.name,
                        elapsed_seconds=round(time.time() - t0, 1))
    out = write_result("S0_inventory", {"archive_layout": layout, "classes": classes,
                                         "files": per_class}, meta)

    print(f"\n[S0] Done in {meta['elapsed_seconds']} s -> {out}")
    for label, s in classes.items():
        print(f"  {label}: {len(s['files_in_order'])} files, {s['total_rows']:,} rows, "
              f"labels={s['label_counts']}, frame.number {s['frame_number_min']}..{s['frame_number_max']}, "
              f"continuous={s['frame_number_continuous_across_files']}, same headers={s['identical_headers']}")


def run_hashes(paths: dict[str, Path]) -> None:
    archives = [p for key, p in paths.items() if key.endswith(("_zip", "_archive")) and p.is_file()]
    awid2 = paths.get("awid2_dir")
    if awid2 and awid2.is_dir():
        archives += sorted(awid2.glob("AWID-*-R-*.tar.gz"))
    hashes = {}
    for p in archives:
        t0 = time.time()
        print(f"[S0] hashing {p.name} ({p.stat().st_size / 1e9:.1f} GB)", flush=True)
        hashes[p.name] = {"sha256": sha256_file(p), "bytes": p.stat().st_size,
                          "seconds": round(time.time() - t0, 1)}
    out = write_result("S0_archive_hashes", {"archives": hashes},
                       run_metadata("scripts/00_inventory.py --hash"))
    print(f"[S0] Done -> {out}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--hash", action="store_true", help="only compute SHA-256 of the archives")
    parser.add_argument("--layout-only", action="store_true", help="only print the archive folders")
    args = parser.parse_args()

    paths = load_paths()
    if args.hash:
        run_hashes(paths)
        return
    zip_path = paths["awid3_csv_zip"]
    if args.layout_only:
        with zipfile.ZipFile(zip_path) as zf:
            for folder, info in archive_layout(zf).items():
                print(f"{info['csv_files']:>4} csv  {info['uncompressed_bytes'] / 1e9:7.2f} GB  {folder}")
        return
    run_inventory(zip_path)


if __name__ == "__main__":
    main()
