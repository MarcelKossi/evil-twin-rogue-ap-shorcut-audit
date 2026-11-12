# Runbook

Commands for the Windows command prompt (cmd), run from the repository root.
Each stage is run only after the output of the previous one has been checked.

At the start of every session:

```cmd
cd /d D:\evil-twin-shorcut-audit
.venv\Scripts\activate.bat
```

## 1. Environment (once)

```cmd
cd /d D:\evil-twin-shorcut-audit
python --version
python -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 2. Git and protocol freeze (once)

```cmd
git init
git branch -M main
git remote add origin <repository-url>
git add .
git status
git commit -m "Repository structure and protocol v0.3"
git tag -a prereg-v0.3 -m "Protocol frozen before any experiment"
git push -u origin main --tags
```

`git status` must not list `data/`.

## 3. Stage S0 - inventory

| Command | Output | Time |
|---|---|---|
| `python scripts/00_inventory.py --layout-only` | Folder list of the AWID3 zip (printed) | < 1 min |
| `python scripts/00_inventory.py` | `results/S0_inventory.json` | about 2 min |
| `python scripts/00_inventory.py --hash` | `results/S0_archive_hashes.json` | about 2 min |

```cmd
git add results/S0_inventory.json results/S0_archive_hashes.json docs/journal.md
git commit -m "S0: AWID3 inventory and archive hashes"
```

## 4. Stage S1 - Parquet conversion and label/filter agreement

| Command | Output | Time |
|---|---|---|
| `python scripts/01_to_parquet.py` | `data/interim/awid3_evil_twin.parquet`, `data/interim/awid3_rogue_ap.parquet`, `results/S1_parquet_manifest.json` | about 10-20 min |
| `python scripts/02_filter_agreement.py` | `results/S1_filter_agreement.json` | about 2-5 min |

```cmd
git add results/S1_parquet_manifest.json results/S1_filter_agreement.json docs/journal.md
git commit -m "S1: Parquet conversion and label/filter agreement"
```

## 5. Stage S1c - label diagnostics (exploratory)

| Command | Output | Time |
|---|---|---|
| `python scripts/03_label_diagnostics.py` | `results/S1c_label_diagnostics.json` | about 5-10 min |

```cmd
git add results/S1c_label_diagnostics.json docs/journal.md
git commit -m "S1c: label diagnostics"
```
