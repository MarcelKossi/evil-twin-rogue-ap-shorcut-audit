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

## 6. Stage S1d - figures of the label structure

| Command | Output | Time |
|---|---|---|
| `python scripts/04_figures_labels.py` | `figures/fig1_rogue_ap_capture.png`, `figures/fig2_evil_twin_capture.png`, `results/S1d_figure_data.json` | about 5 min |

```cmd
git add figures results/S1d_figure_data.json docs/journal.md RESULTS.md
git commit -m "S1d: label structure figures and preliminary results"
```

## 7. Stage S2 - feature taxonomy

| Command | Output | Time |
|---|---|---|
| `python scripts/05_taxonomy_agreement.py` | `docs/taxonomy.csv`, `results/S2_taxonomy_agreement.json` | < 1 min |

Inputs: the three annotations in `docs/annotation/` and the manual changes in
`docs/annotation/manual_overrides.csv`.

```cmd
git add docs scripts src results
git commit -m "S2: feature taxonomy"
```

## 8. Stage S2b - feature matrices

| Command | Output | Time |
|---|---|---|
| `python scripts/06_build_features.py` | `data/interim/awid3_*_X.npy`, `_y.npy`, `_fn.npy`, `_features.json`; `results/S2b_features.json` | about 20-40 min |

Needs about 3 GB free on the data disk.

## 9. Stage S3 - do detectors learn the labelling rule? (H1b, H1c)

| Command | Output | Time |
|---|---|---|
| `python scripts/07_s3_label_rule.py --seeds 0` | first pass, seed 0 only | about 1-2 h |
| `python scripts/07_s3_label_rule.py` | all seeds (finished runs are skipped) | several hours |

Results: `results/S3_runs.csv` (one row per run) and `results/S3_label_rule.json` (H1b, H1c).
The script can be stopped and restarted; finished runs are kept.

```cmd
git add results docs RUNBOOK.md
git commit -m "S3: label rule (H1b, H1c)"
```

## 10. Stage S4 - reliance on artefacts (H2a, H2b, H2c)

| Command | Output | Time |
|---|---|---|
| `python scripts/08_s4_reliance.py` | `results/S4_runs.csv`, `results/S4_reliance.json` | several hours (overnight) |

Stop and restart at any time; finished runs are kept.

```cmd
git add results docs RUNBOOK.md
git commit -m "S4: reliance on artefacts (H2a, H2b, H2c)"
```

## 11. Re-run of S3 with the corrected folds (after S4)

```cmd
move results\S3_runs.csv results\S3_runs_v1.csv
move results\S3_label_rule.json results\S3_label_rule_v1.json
python scripts/07_s3_label_rule.py
git add results docs
git commit -m "S3 re-run with corrected folds"
```
