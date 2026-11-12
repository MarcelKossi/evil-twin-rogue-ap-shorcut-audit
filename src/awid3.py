"""AWID3 CSV archive: locating the class folders and reading the CSV members."""

from __future__ import annotations

import io
import re
import zipfile
from typing import Iterator

import pandas as pd

from src.utils import natural_key

# Folder token (normalised) -> class name used in this project.
CLASSES = {"eviltwin": "Evil_Twin", "rogueap": "Rogue_AP"}
# Value of the Label column for the attack frames of each class (checked in S0).
ATTACK_LABEL = {"Evil_Twin": "Evil_Twin", "Rogue_AP": "RogueAP"}
NORMAL_LABEL = "Normal"
NA_VALUES = ["", "?", "nan", "NaN"]


def _normalise(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def class_of(member: str) -> str | None:
    key = _normalise(member)
    for token, name in CLASSES.items():
        if token in key:
            return name
    return None


def class_members(zf: zipfile.ZipFile, name: str) -> list[str]:
    """CSV members of one class, in natural order (file_0, file_1, ..., file_10)."""
    members = [i.filename for i in zf.infolist()
               if not i.is_dir() and i.filename.lower().endswith(".csv") and class_of(i.filename) == name]
    return sorted(members, key=natural_key)


def read_member(zf: zipfile.ZipFile, member: str, chunksize: int, usecols=None) -> Iterator[pd.DataFrame]:
    """Yield chunks of one CSV member as strings, with stripped column names."""
    with zf.open(member) as raw:
        text = io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
        reader = pd.read_csv(text, dtype=str, na_values=NA_VALUES, keep_default_na=False,
                             chunksize=chunksize, usecols=usecols)
        for chunk in reader:
            chunk.columns = [c.strip() for c in chunk.columns]
            yield chunk
