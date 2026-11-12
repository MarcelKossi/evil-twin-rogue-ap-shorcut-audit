# Runbook

Commands for Windows PowerShell, run from the repository root
(`D:\evil-twin-shorcut-audit`). Each stage is run only after the output of
the previous one has been checked.

## 1. Environment (once)

```powershell
cd D:\evil-twin-shorcut-audit
python --version                      # 3.10 to 3.12
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
python -m pip install --upgrade pip
pip install -r requirements.txt
```

In every new terminal: `cd D:\evil-twin-shorcut-audit` then `.\.venv\Scripts\Activate.ps1`.

## 2. Git and protocol freeze (once)

```powershell
git init
git branch -M main
git remote add origin <repository-url>
git add .
git status                            # data/ must not appear
git commit -m "Repository structure and protocol v0.3"
git tag -a prereg-v0.3 -m "Protocol frozen before any experiment"
git push -u origin main --tags
```

## 3. Stage S0 - inventory

| Command | Output | Expected time |
|---|---|---|
| `python scripts/00_inventory.py --layout-only` | Folder list of the AWID3 zip, printed | < 1 min |
| `python scripts/00_inventory.py` | `results/S0_inventory.json` | about 5-15 min |
| `python scripts/00_inventory.py --hash` | `results/S0_archive_hashes.json` | about 5-10 min |

Then:

```powershell
git add results/S0_inventory.json results/S0_archive_hashes.json
git commit -m "S0: AWID3 inventory and archive hashes"
```

## 4. Stage S1 - Parquet conversion and label/filter agreement

To be added after S0 is reviewed.
