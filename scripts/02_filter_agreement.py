"""Stage S1b - agreement between the AWID3 labels and the published filters (H1a).

The AWID3 website gives one Wireshark display filter per attack. This script
applies them to the Parquet data and compares the result with the Label
column. The CSV export has no wlan.fc.type_subtype, wlan.addr or ip.addr
column, so the filters are translated as follows (S0 finding):
    type_subtype = 16 * wlan.fc.type + wlan.fc.subtype   (Wireshark encoding)
    wlan.addr    = any of wlan.sa, wlan.da, wlan.ta, wlan.ra, wlan.bssid
    ip.addr      = ip.src or ip.dst
The encoding of type/subtype is checked on the data before use.

Usage (from the repository root):
    python scripts/02_filter_agreement.py
Output:
    results/S1_filter_agreement.json
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.awid3 import ATTACK_LABEL, NORMAL_LABEL  # noqa: E402
from src.utils import load_paths, run_metadata, sha256_file, write_result  # noqa: E402

KAPPA_THRESHOLD = 0.80  # protocol, H1a
BATCH_ROWS = 200_000

ROGUE_WINDOW = (1_198_551, 1_973_111)
ET_WINDOW = (1_420_038, 3_778_728)
ET_IP = "192.168.30.1"
ET_MAC = "0c:9d:92:54:fe:35"

ADDR_FIELDS = ["wlan.sa", "wlan.da", "wlan.ta", "wlan.ra", "wlan.bssid"]
IP_FIELDS = ["ip.src", "ip.dst"]
COLUMNS = ["frame.number", "frame.len", "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.protected",
           *ADDR_FIELDS, *IP_FIELDS, "Label", "source_file"]

SUBTASK = {8: "ET-B beacon", 10: "ET-M disassoc", 12: "ET-M deauth", 40: "ET-D QoS data"}
FRAME_NAMES = {0: "assoc req", 1: "assoc resp", 4: "probe req", 5: "probe resp", 8: "beacon",
               10: "disassoc", 11: "auth", 12: "deauth", 13: "action", 27: "RTS", 28: "CTS",
               29: "ACK", 32: "data", 36: "null", 40: "QoS data", 44: "QoS null"}


# ---------- parsing ----------

def to_int(series: pd.Series) -> pd.Series:
    """Parse integer fields written either in decimal or as 0x.. hex."""
    s = series.astype("string").str.strip()
    hex_mask = s.str.lower().str.startswith("0x", na=False)
    out = pd.to_numeric(s.where(~hex_mask), errors="coerce")
    if hex_mask.any():
        out[hex_mask] = s[hex_mask].map(lambda v: int(v, 16))
    return out


def has_value(frame: pd.DataFrame, fields: list[str], value: str) -> pd.Series:
    """True where any of the fields equals value (fields may hold comma-separated lists)."""
    pattern = rf"(?:^|,)\s*{re.escape(value.lower())}\s*(?:,|$)"
    hit = pd.Series(False, index=frame.index)
    for f in fields:
        if f in frame:
            hit |= frame[f].astype("string").str.lower().str.contains(pattern, regex=True, na=False)
    return hit


def frame_name(code: float) -> str:
    if pd.isna(code):
        return "missing"
    code = int(code)
    return f"{code} ({FRAME_NAMES.get(code, '?')})"


# ---------- statistics ----------

def agreement(tp: int, fp: int, fn: int, tn: int) -> dict:
    n = tp + tn + fp + fn
    po = (tp + tn) / n
    pe = ((tp + fp) * (tp + fn) + (fn + tn) * (fp + tn)) / n**2
    kappa = (po - pe) / (1 - pe) if pe < 1 else float("nan")
    denom = np.sqrt(float(tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denom if denom else float("nan")
    return {
        "n": n, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "cohen_kappa": round(kappa, 6),
        "filter_precision": round(tp / (tp + fp), 6) if tp + fp else None,
        "filter_recall": round(tp / (tp + fn), 6) if tp + fn else None,
        "mcc": round(mcc, 6),
        "H1a_kappa_threshold": KAPPA_THRESHOLD,
        "H1a_met": bool(kappa >= KAPPA_THRESHOLD),
    }


def describe(values: list[np.ndarray]) -> dict:
    arr = np.concatenate(values) if values else np.array([])
    return pd.Series(arr).describe().round(1).to_dict()


# ---------- reading in batches (the full table does not fit in memory) ----------

def iter_batches(path: Path, batch_rows: int = BATCH_ROWS) -> Iterator[pd.DataFrame]:
    parquet = pq.ParquetFile(path)
    for batch in parquet.iter_batches(batch_size=batch_rows, columns=COLUMNS):
        yield batch.to_pandas()


def prepare(df: pd.DataFrame) -> pd.DataFrame:
    df["fn"] = to_int(df["frame.number"])
    df["flen"] = to_int(df["frame.len"])
    df["ftype"] = to_int(df["wlan.fc.type"])
    df["fsub"] = to_int(df["wlan.fc.subtype"])
    df["st"] = 16 * df["ftype"] + df["fsub"]
    df["prot"] = to_int(df["wlan.fc.protected"])
    return df


def clauses_for(df: pd.DataFrame, attack: str) -> tuple[dict[str, pd.Series], pd.Series, pd.Series]:
    """Return the filter clauses, the full filter and the frame.number window mask."""
    if attack == "Rogue_AP":
        lo, hi = ROGUE_WINDOW
        clauses = {
            "beacon (type_subtype==8)": df["st"] == 8,
            "frame.len<264": df["flen"] < 264,
            "frame.number in window": df["fn"].between(lo, hi),
        }
        filt = clauses["beacon (type_subtype==8)"] & clauses["frame.len<264"] & clauses["frame.number in window"]
    else:
        lo, hi = ET_WINDOW
        clauses = {
            "beacon and frame.len<242": (df["st"] == 8) & (df["flen"] < 242),
            "disassoc/deauth/QoS data unprotected": df["st"].isin([10, 12, 40]) & (df["prot"] == 0),
            "frame.number in window": df["fn"].between(lo, hi),
            "ip.addr==192.168.30.1": has_value(df, IP_FIELDS, ET_IP),
            "wlan.addr==rogue MAC": has_value(df, ADDR_FIELDS, ET_MAC),
        }
        c = list(clauses.values())
        filt = (c[0] | c[1]) & c[2] & (c[3] | c[4])
    return clauses, filt, df["fn"].between(lo, hi)


class Tally:
    """Accumulates every statistic of one attack over the batches."""

    def __init__(self, attack: str):
        self.attack = attack
        self.rows_total = 0
        self.excluded = 0
        self.excluded_examples: list[dict] = []
        self.cm = Counter()
        self.labels = Counter()
        self.type_raw = Counter()
        self.subtype_raw = Counter()
        self.st_all = Counter()
        self.by_type = {k: Counter() for k in ("attack", "filter_pos", "false_neg", "false_pos", "subtask")}
        self.clause_attack = Counter()
        self.clause_normal_window = Counter()
        self.n_attack = 0
        self.n_normal_window = 0
        self.attack_outside_window = 0
        self.attack_fn_min = None
        self.attack_fn_max = None
        self.fn_seen = np.zeros(4_000_000, dtype=bool)
        self.fn_duplicates = 0
        self.len_attack: list[np.ndarray] = []
        self.len_normal_beacons_window: list[np.ndarray] = []

    def mark_frame_numbers(self, fn: np.ndarray) -> None:
        if fn.max() >= len(self.fn_seen):
            grown = np.zeros(int(fn.max() * 1.2) + 1, dtype=bool)
            grown[: len(self.fn_seen)] = self.fn_seen
            self.fn_seen = grown
        self.fn_duplicates += int(self.fn_seen[fn].sum()) + int(len(fn) - len(np.unique(fn)))
        self.fn_seen[fn] = True

    def add(self, df: pd.DataFrame) -> None:
        self.rows_total += len(df)
        fn_raw = to_int(df["frame.number"])
        bad = df["Label"].isna() | fn_raw.isna()
        if bad.any():
            self.excluded += int(bad.sum())
            room = 10 - len(self.excluded_examples)
            if room > 0:
                self.excluded_examples += df.loc[bad, ["source_file", "frame.number", "Label"]].head(room).astype(str).to_dict("records")
        df = prepare(df.loc[~bad].copy())

        self.labels.update(df["Label"])
        self.type_raw.update(df["wlan.fc.type"].fillna("<missing>"))
        self.subtype_raw.update(df["wlan.fc.subtype"].fillna("<missing>"))
        self.st_all.update(df["st"].map(frame_name))
        self.mark_frame_numbers(df["fn"].to_numpy(dtype=np.int64))

        y = df["Label"] != NORMAL_LABEL
        clauses, filt, in_window = clauses_for(df, self.attack)
        st_names = df["st"].map(frame_name)

        self.cm["tp"] += int((y & filt).sum()); self.cm["fp"] += int((~y & filt).sum())
        self.cm["fn"] += int((y & ~filt).sum()); self.cm["tn"] += int((~y & ~filt).sum())

        self.by_type["attack"].update(st_names[y])
        self.by_type["filter_pos"].update(st_names[filt])
        self.by_type["false_neg"].update(st_names[y & ~filt])
        self.by_type["false_pos"].update(st_names[~y & filt])

        normal_window = ~y & in_window
        self.n_attack += int(y.sum())
        self.n_normal_window += int(normal_window.sum())
        for name, c in clauses.items():
            self.clause_attack[name] += int(c[y].sum())
            self.clause_normal_window[name] += int(c[normal_window].sum())

        if y.any():
            fa = df.loc[y, "fn"]
            self.attack_fn_min = int(fa.min()) if self.attack_fn_min is None else min(self.attack_fn_min, int(fa.min()))
            self.attack_fn_max = int(fa.max()) if self.attack_fn_max is None else max(self.attack_fn_max, int(fa.max()))
            self.attack_outside_window += int((y & ~in_window).sum())
            if self.attack == "Evil_Twin":
                self.by_type["subtask"].update(df.loc[y, "st"].map(
                    lambda v: SUBTASK.get(int(v), "other") if pd.notna(v) else "missing"))
            else:
                self.len_attack.append(df.loc[y, "flen"].to_numpy())
        if self.attack == "Rogue_AP":
            self.len_normal_beacons_window.append(df.loc[normal_window & (df["st"] == 8), "flen"].to_numpy())

    def result(self) -> dict:
        seen = np.flatnonzero(self.fn_seen)
        absent = int(seen[-1] - seen[0] + 1 - len(seen)) if len(seen) else None
        labels_seen = sorted(self.labels)
        rates = lambda counts, n: {k: {"pass": v, "rate": round(v / n, 6) if n else None} for k, v in counts.items()}
        out = {
            "data_checks": {
                "rows_total": self.rows_total,
                "rows_excluded_missing_label_or_frame_number": self.excluded,
                "excluded_examples": self.excluded_examples,
                "frame_number_range": [int(seen[0]), int(seen[-1])] if len(seen) else None,
                "frame_numbers_absent_in_range": absent,
                "duplicate_frame_numbers": self.fn_duplicates,
            },
            "encoding_check": {
                "wlan.fc.type_raw_values": dict(self.type_raw.most_common(10)),
                "wlan.fc.subtype_raw_values": dict(self.subtype_raw.most_common(20)),
                "derived_type_subtype_top": dict(self.st_all.most_common(20)),
            },
            "labels_seen": {k: self.labels[k] for k in labels_seen},
            "unexpected_labels": [v for v in labels_seen if v not in (NORMAL_LABEL, ATTACK_LABEL[self.attack])],
            "agreement": agreement(self.cm["tp"], self.cm["fp"], self.cm["fn"], self.cm["tn"]),
            "labelled_attack_frame_number_range": [self.attack_fn_min, self.attack_fn_max],
            "labelled_attack_outside_filter_window": self.attack_outside_window,
            "clause_pass_rates_on_labelled_attack": rates(self.clause_attack, self.n_attack),
            "clause_pass_rates_on_normal_inside_window": rates(self.clause_normal_window, self.n_normal_window),
            "labelled_attack_by_frame_type": dict(self.by_type["attack"].most_common()),
            "filter_positive_by_frame_type": dict(self.by_type["filter_pos"].most_common()),
            "false_negatives_by_frame_type": dict(self.by_type["false_neg"].most_common()),
            "false_positives_by_frame_type": dict(self.by_type["false_pos"].most_common()),
        }
        if self.attack == "Evil_Twin":
            out["evil_twin_subtasks"] = dict(self.by_type["subtask"].most_common())
        else:
            out["frame_len_labelled_attack"] = describe(self.len_attack)
            out["frame_len_normal_beacons_in_window"] = describe(self.len_normal_beacons_window)
        return out


def main() -> None:
    paths = load_paths()
    files = {"Rogue_AP": paths["interim_dir"] / "awid3_rogue_ap.parquet",
             "Evil_Twin": paths["interim_dir"] / "awid3_evil_twin.parquet"}
    output, inputs = {}, {}
    for attack, path in files.items():
        print(f"[S1b] {attack}: reading {path.name} in batches", flush=True)
        tally = Tally(attack)
        for batch in iter_batches(path):
            tally.add(batch)
        inputs[path.name] = sha256_file(path)
        output[attack] = tally.result()
        a = output[attack]["agreement"]
        print(f"  n={a['n']:,} tp={a['tp']:,} fp={a['fp']:,} fn={a['fn']:,} "
              f"kappa={a['cohen_kappa']:.4f} precision={a['filter_precision']} recall={a['filter_recall']} "
              f"H1a_met={a['H1a_met']}")

    out = write_result("S1_filter_agreement", {"filters": {
        "Rogue_AP": "wlan.fc.type_subtype==8 && frame.number>=1198551 && frame.number<=1973111 && frame.len<264",
        "Evil_Twin": "((wlan.fc.type_subtype==8 && frame.len<242) || ((wlan.fc.type_subtype==10 || "
                     "wlan.fc.type_subtype==12 || wlan.fc.type_subtype==40) && wlan.fc.protected==0)) && "
                     "frame.number>=1420038 && frame.number<=3778728 && (ip.addr==192.168.30.1 || "
                     "wlan.addr==0c:9d:92:54:fe:35)"}, "results": output},
        run_metadata("scripts/02_filter_agreement.py", inputs_sha256=inputs))
    print(f"\n[S1b] Done -> {out}")


if __name__ == "__main__":
    main()
