"""Shared helpers: project paths, run metadata and result files."""

from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_paths(config: Path | None = None) -> dict[str, Path]:
    """Read configs/paths.yaml and resolve every entry against the repository root."""
    config = config or ROOT / "configs" / "paths.yaml"
    with open(config, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return {key: (ROOT / value).resolve() for key, value in raw.items()}


def git_commit() -> str | None:
    """Current commit hash, with a '-dirty' suffix if the working tree has changes."""
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
        # Only tracked code and docs count; results, the journal and the generated taxonomy change on runs.
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no", "--", ".",
             ":(exclude)results", ":(exclude)docs/journal.md", ":(exclude)docs/taxonomy.csv"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip()
        return commit + ("-dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return None


def uncommitted_files() -> list[str] | None:
    """Tracked files (outside results/, the journal and the taxonomy) that differ from the last commit."""
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no", "--", ".",
             ":(exclude)results", ":(exclude)docs/journal.md", ":(exclude)docs/taxonomy.csv"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        return [line[3:] for line in out.splitlines() if line.strip()]
    except (OSError, subprocess.CalledProcessError):
        return None


def package_versions() -> dict[str, str | None]:
    from importlib.metadata import PackageNotFoundError, version
    out = {}
    for name in ("numpy", "pandas", "pyarrow", "scikit-learn", "xgboost"):
        try:
            out[name] = version(name)
        except PackageNotFoundError:
            out[name] = None
    return out


def run_metadata(script: str, **extra: Any) -> dict[str, Any]:
    """Metadata stored with every result file."""
    meta = {
        "script": script,
        "git_commit": git_commit(),
        "uncommitted_files": uncommitted_files(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "packages": package_versions(),
    }
    meta.update(extra)
    return meta


def write_result(name: str, payload: dict[str, Any], meta: dict[str, Any]) -> Path:
    """Write results/<name>.json with metadata first."""
    out_dir = ROOT / "results"
    out_dir.mkdir(exist_ok=True)
    path = out_dir / f"{name}.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, **payload}, fh, indent=2, ensure_ascii=False, default=str)
    return path


def sha256_file(path: Path, block_size: int = 8 * 1024 * 1024) -> str:
    """SHA-256 of a file, read in blocks."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(block_size), b""):
            digest.update(block)
    return digest.hexdigest()


def natural_key(text: str) -> list:
    """Sort key so that 'file_10' comes after 'file_9'."""
    return [int(tok) if tok.isdigit() else tok.lower() for tok in re.split(r"(\d+)", text)]
