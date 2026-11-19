"""Stage S5, part 1 - AWID2 preparation and field alignment with AWID3 Evil_Twin (protocol 6.2, 9.2-9.4).

AWID2: AWID-ATK-R-Trn and -Tst, read from their tar.gz archives (no header, '?' = missing).
Column names come from configs/awid2_columns.txt: a public list of the 155 names, checked
against the data (2026-11-19); the duplicated name at position 153 gets the suffix '_2'.
AWID2 names are mapped to AWID3 names ('wlan_mgt.' -> 'wlan.', 'radiotap.channel.type.' ->
'radiotap.channel.flags.'). Rows labelled evil_twin (attack) and normal are kept; rows of the
other AWID2 attack classes are left out and counted.

Shared fields: AWID3 Evil_Twin columns that exist in AWID2 after mapping. Both datasets are
written with the same encoding, in two passes (profile, then encode):
  - numeric if at least 99.9% of the non-missing values parse as numbers in both datasets,
    stored as float32 minus the minimum over both datasets;
  - otherwise text, label-encoded on the sorted union of the values of both datasets (the same
    string gets the same code in both), or hash-encoded above 50,000 values.
The missingness rule of protocol 9.3 is applied later, in the source domain of each direction;
missing rates of both datasets are stored here. AWID3 rows and labels are checked against S2b.

Exploratory, decided on 2026-11-20 before running: on AWID2 beacons, every field is compared
between rogue beacons and normal beacons of the impersonated BSSID, as S4y did on AWID3.

Usage (from the repository root):
    python scripts/12_s5_prepare.py
Output: data/interim/s5_{awid3,awid2}_{X,y,fn}.npy, data/interim/s5_awid2_split.npy (0 = Trn, 1 = Tst),
        data/interim/s5_features.json, results/S5a_prepare.json
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tarfile
import zlib
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.frames import iter_parquet  # noqa: E402
from src.utils import ROOT, load_paths, run_metadata, sha256_file, write_result  # noqa: E402


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


s2b = _load("s2b", "06_build_features.py")       # parse_numeric, valid_rows
s4y = _load("s4y", "11_beacon_fields.py")         # tvd, top

AWID2_FILES = {"Trn": "AWID-ATK-R-Trn.tar.gz", "Tst": "AWID-ATK-R-Tst.tar.gz"}
COLUMNS = ROOT / "configs" / "awid2_columns.txt"
TAXONOMY = ROOT / "docs" / "taxonomy.csv"
RENAME = [("wlan_mgt.", "wlan."), ("radiotap.channel.type.", "radiotap.channel.flags.")]
SKIP = {"Label", "source_file", "row_in_file", "frame.number"}
CHUNK = 100_000
NUMERIC_SHARE, MAX_CATEGORIES, HASH_MOD = 0.999, 50_000, 2**23


def awid2_names() -> list[str]:
    names = [l.strip() for l in COLUMNS.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(names) == 155, len(names)
    names[152] += "_2"
    for old, new in RENAME:
        names = [new + n[len(old):] if n.startswith(old) else n for n in names]
    return names


def awid2_chunks(awid2_dir: Path, names: list[str]):
    """(file, chunk) over Trn then Tst, in file order, all values as strings."""
    for split, file in AWID2_FILES.items():
        with tarfile.open(awid2_dir / file, "r:gz") as tar:
            members = sorted((m for m in tar.getmembers() if m.isfile()), key=lambda m: m.name)
            for m in members:
                text = io.TextIOWrapper(tar.extractfile(m), encoding="utf-8", errors="replace")
                for df in pd.read_csv(text, header=None, names=names, dtype=str, na_values=["?"],
                                      keep_default_na=False, chunksize=CHUNK):
                    yield split, df


def awid3_chunks(path: Path, cols: list[str]):
    for df in iter_parquet(path, cols + ["Label", "frame.number"], 50_000):
        yield df.loc[s2b.valid_rows(df)]


def profile(chunks, cols: list[str], keep_rows) -> tuple[dict, int]:
    st = {c: {"nonnull": 0, "numeric": 0, "min": np.inf, "values": set()} for c in cols}
    n = 0
    for df in chunks:
        df = df.loc[keep_rows(df)]
        n += len(df)
        for c in cols:
            col = df[c].dropna()
            st[c]["nonnull"] += len(col)
            num = s2b.parse_numeric(col)
            st[c]["numeric"] += int(num.notna().sum())
            if num.notna().any():
                st[c]["min"] = min(st[c]["min"], float(num.min()))
            if st[c]["values"] is not None:
                st[c]["values"].update(col.unique().tolist())
                if len(st[c]["values"]) > MAX_CATEGORIES:
                    st[c]["values"] = None
    return st, n


def encode(df: pd.DataFrame, spec: dict) -> np.ndarray:
    out = np.empty((len(df), len(spec)), dtype=np.float32)
    for j, (c, s) in enumerate(spec.items()):
        if s["kind"] == "numeric":
            out[:, j] = (s2b.parse_numeric(df[c]) - s["offset"]).to_numpy("float64")
        elif s["mapping"] is None:
            out[:, j] = df[c].map(lambda v: float(zlib.crc32(str(v).encode()) % HASH_MOD) if pd.notna(v) else np.nan)
        else:
            out[:, j] = df[c].map(s["mapping"]).to_numpy("float64")
    return out


def main() -> None:
    paths = load_paths()
    interim, awid2_dir = paths["interim_dir"], paths["awid2_dir"]
    pq_path = interim / "awid3_evil_twin.parquet"
    import pyarrow.parquet as pq
    a3_cols = [c for c in pq.ParquetFile(pq_path).schema.names if c not in SKIP]
    names = awid2_names()
    shared = [c for c in a3_cols if c in names]
    fams = pd.read_csv(TAXONOMY).set_index("field")["family"].to_dict()
    is_kept = lambda df: df["class"].isin(["normal", "evil_twin"])                      # noqa: E731

    # Pass 1: counts and profiles
    counts = {}
    for split, df in awid2_chunks(awid2_dir, names):
        for k, v in df["class"].value_counts().items():
            counts.setdefault(split, {}).setdefault(k, 0)
            counts[split][k] += int(v)
    st2, n2 = profile((df for _, df in awid2_chunks(awid2_dir, names)), shared, is_kept)
    st3, n3 = profile(awid3_chunks(pq_path, shared), shared, lambda df: df.index == df.index)
    spec = {}
    for c in shared:
        numeric = all(s["nonnull"] == 0 or s["numeric"] / s["nonnull"] >= NUMERIC_SHARE for s in (st2[c], st3[c]))
        v = None if st2[c]["values"] is None or st3[c]["values"] is None else st2[c]["values"] | st3[c]["values"]
        spec[c] = {"kind": "numeric" if numeric else "text",
                   "offset": (lambda m: m if np.isfinite(m) else 0.0)(min(st2[c]["min"], st3[c]["min"])) if numeric else 0.0,
                   "mapping": None if numeric or v is None or len(v) > MAX_CATEGORIES
                   else {x: float(i) for i, x in enumerate(sorted(v))}}
    # Pass 2: matrices
    out = {}
    for tag, n, chunks in (("awid2", n2, awid2_chunks(awid2_dir, names)), ("awid3", n3, awid3_chunks(pq_path, shared))):
        X = np.lib.format.open_memmap(interim / f"s5_{tag}_X.npy", mode="w+", dtype=np.float32, shape=(n, len(shared)))
        y, fn, split_ = np.zeros(n, np.int8), np.zeros(n, np.int64), np.zeros(n, np.int8)
        i = 0
        for item in chunks:
            split, df = item if tag == "awid2" else ("", item)
            if tag == "awid2":
                df = df.loc[is_kept(df)]
                y[i:i + len(df)] = (df["class"] == "evil_twin").to_numpy()
                fn[i:i + len(df)] = np.arange(i + 1, i + 1 + len(df))
                split_[i:i + len(df)] = split == "Tst"
            else:
                y[i:i + len(df)] = (df["Label"] != "Normal").to_numpy()
                fn[i:i + len(df)] = s2b.parse_numeric(df["frame.number"]).to_numpy("int64")
            X[i:i + len(df)] = encode(df, spec)
            i += len(df)
        assert i == n
        X.flush()
        np.save(interim / f"s5_{tag}_y.npy", y)
        np.save(interim / f"s5_{tag}_fn.npy", fn)
        if tag == "awid2":
            np.save(interim / "s5_awid2_split.npy", split_)
        out[tag] = {"rows": n, "attack": int(y.sum())}
    # AWID3 rows must be those of S2b
    assert np.array_equal(np.load(interim / "s5_awid3_fn.npy"), np.load(interim / "awid3_evil_twin_fn.npy"))
    assert np.array_equal(np.load(interim / "s5_awid3_y.npy"), np.load(interim / "awid3_evil_twin_y.npy"))
    cols = [{"name": c, "family": fams.get(c, "U"), "kind": spec[c]["kind"], "offset": spec[c]["offset"],
             "missing_awid3": round(1 - st3[c]["nonnull"] / n3, 6), "missing_awid2": round(1 - st2[c]["nonnull"] / n2, 6)}
            for c in shared]
    (interim / "s5_features.json").write_text(json.dumps({"columns": cols}, indent=1), encoding="utf-8")

    # Exploratory: AWID2 beacons, rogue vs normal beacons of the impersonated BSSID
    parts = []
    for _, df in awid2_chunks(awid2_dir, names):
        parts.append(df[(df["wlan.fc.type_subtype"].str.lower() == "0x08") & is_kept(df)])
    b = pd.concat(parts, ignore_index=True)
    rogue = b["class"] == "evil_twin"
    bssid = b.loc[rogue, "wlan.bssid"].mode().iloc[0]
    legit = ~rogue & (b["wlan.bssid"] == bssid)
    miss2 = {c: 1 - st2[c]["nonnull"] / n2 for c in shared}
    rows = []
    for c in b.columns:
        if c == "class":
            continue
        n_b = int((rogue | legit).sum())
        rows.append({"field": c, "family": fams.get(c, "not classified"), "shared_with_awid3": c in shared,
                     "missing_awid2": round(miss2[c], 4) if c in miss2 else None,
                     "tvd": round(s4y.tvd(b.loc[rogue, c], b.loc[legit, c]), 4),
                     "distinct": int(b.loc[rogue | legit, c].nunique()),
                     "rogue_values": s4y.top(b.loc[rogue, c]), "legit_values": s4y.top(b.loc[legit, c])})
    rows = [r for r in rows if r["distinct"] <= int((rogue | legit).sum()) / 2]
    rows.sort(key=lambda r: -r["tvd"])
    beacons = {"impersonated_bssid": bssid, "rogue_beacons": int(rogue.sum()), "legit_beacons": int(legit.sum()),
               "fields_tvd_at_least_0.5": [r for r in rows if r["tvd"] >= 0.5],
               "fields_tvd_below_0.5": [{k: r[k] for k in ("field", "family", "tvd")} for r in rows if r["tvd"] < 0.5]}
    print(f"[S5a] AWID2: {n2} rows kept ({out['awid2']['attack']} evil_twin); AWID3: {n3} rows; {len(shared)} shared fields")
    for r in beacons["fields_tvd_at_least_0.5"]:
        print(f"    {r['tvd']:.3f} {r['family']:<15} {r['field']:<40} rogue {r['rogue_values']}  legit {r['legit_values']}")

    inputs = {p.name: sha256_file(p) for p in [COLUMNS, TAXONOMY] + [awid2_dir / f for f in AWID2_FILES.values()]}
    res = write_result("S5a_prepare", {
        "awid2_class_counts": counts, "rows": out, "rename_rules": RENAME,
        "shared_fields": cols, "awid3_fields_not_in_awid2": [c for c in a3_cols if c not in names],
        "awid2_beacons_exploratory": beacons}, run_metadata("scripts/12_s5_prepare.py", inputs_sha256=inputs))
    print(f"[S5a] Done -> {res}")


if __name__ == "__main__":
    main()
