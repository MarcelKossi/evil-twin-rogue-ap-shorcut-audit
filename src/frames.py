"""Helpers for 802.11 frame fields exported by tshark (AWID3 CSV)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd

ADDR_FIELDS = ["wlan.sa", "wlan.da", "wlan.ta", "wlan.ra", "wlan.bssid"]
IP_FIELDS = ["ip.src", "ip.dst"]
FRAME_CLASS = {0: "management", 1: "control", 2: "data"}
FRAME_NAMES = {0: "assoc req", 1: "assoc resp", 4: "probe req", 5: "probe resp", 8: "beacon",
               10: "disassoc", 11: "auth", 12: "deauth", 13: "action", 21: "VHT NDP ann.",
               24: "block ack req", 25: "block ack", 27: "RTS", 28: "CTS", 29: "ACK",
               32: "data", 36: "null", 40: "QoS data", 44: "QoS null"}


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


def add_frame_codes(df: pd.DataFrame) -> pd.DataFrame:
    """Numeric frame.number, frame.len, type, subtype, type_subtype and protection flag."""
    df["fn"] = to_int(df["frame.number"])
    df["flen"] = to_int(df["frame.len"])
    df["ftype"] = to_int(df["wlan.fc.type"])
    df["st"] = 16 * df["ftype"] + to_int(df["wlan.fc.subtype"])
    df["prot"] = to_int(df["wlan.fc.protected"])
    return df


def iter_parquet(path: Path, columns: list[str], batch_rows: int = 200_000) -> Iterator[pd.DataFrame]:
    """Read a Parquet file in batches (the full tables do not fit in memory)."""
    import pyarrow.parquet as pq
    for batch in pq.ParquetFile(path).iter_batches(batch_size=batch_rows, columns=columns):
        yield batch.to_pandas()


def agreement(tp: int, fp: int, fn: int, tn: int) -> dict:
    """Confusion counts, Cohen's kappa, precision, recall and MCC of a rule against labels."""
    n = tp + tn + fp + fn
    po = (tp + tn) / n
    pe = ((tp + fp) * (tp + fn) + (fn + tn) * (fp + tn)) / n**2
    kappa = (po - pe) / (1 - pe) if pe < 1 else float("nan")
    denom = np.sqrt(float(tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return {
        "n": n, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "cohen_kappa": round(kappa, 6),
        "precision": round(tp / (tp + fp), 6) if tp + fp else None,
        "recall": round(tp / (tp + fn), 6) if tp + fn else None,
        "mcc": round((tp * tn - fp * fn) / denom, 6) if denom else None,
    }
