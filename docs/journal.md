# Run journal

One entry per working session: what was run, on which commit, what came out,
and any deviation from `docs/protocol_v0.3.md`.

## 2026-11-12

- Set up the repository structure and wrote protocol v0.3 (`docs/protocol_v0.3.md`). It is frozen with the tag `prereg-v0.3` before any experiment.
- Data on disk (`data/`): `AWID3_Dataset_CSV.zip` (14.5 GB), `AWID3_Dataset.zip` (12.1 GB, pcap) and the AWID2 distribution `DATASET.tar.gz` (11.7 GB), already unpacked into per-subset archives, including `AWID-ATK-R-Trn.tar.gz` (60 MB) and `AWID-ATK-R-Tst.tar.gz` (19 MB).
- Full extraction of the AWID3 CSV archive failed for lack of disk space (`data/AWID3_Dataset_CSV/` is empty). Decision, taken before freezing and written into protocol Section 6.1: the CSV members are read directly from the zip, and only Evil_Twin and Rogue_AP are converted to Parquet in S1.
- AWID2 does not need a full extraction: only the two ATK-R archives are used (protocol Section 6.2).
- Next: S0 inventory.
