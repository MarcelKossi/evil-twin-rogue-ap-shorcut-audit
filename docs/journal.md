# Run journal

One entry per working session: what was run, on which commit, what came out,
and any deviation from `docs/protocol_v0.3.md`.

## 2026-11-12

- Set up the repository structure and wrote protocol v0.3 (`docs/protocol_v0.3.md`). It is frozen with the tag `prereg-v0.3` before any experiment.
- Data on disk (`data/`): `AWID3_Dataset_CSV.zip` (14.5 GB), `AWID3_Dataset.zip` (12.1 GB, pcap) and the AWID2 distribution `DATASET.tar.gz` (11.7 GB), already unpacked into per-subset archives, including `AWID-ATK-R-Trn.tar.gz` (60 MB) and `AWID-ATK-R-Tst.tar.gz` (19 MB).
- Full extraction of the AWID3 CSV archive failed for lack of disk space (`data/AWID3_Dataset_CSV/` is empty). Decision, taken before freezing and written into protocol Section 6.1: the CSV members are read directly from the zip, and only Evil_Twin and Rogue_AP are converted to Parquet in S1.
- AWID2 does not need a full extraction: only the two ATK-R archives are used (protocol Section 6.2).
- Next: S0 inventory.

## 2026-11-12 - S0 inventory

- Ran `scripts/00_inventory.py` (119 s) and `scripts/00_inventory.py --hash`. Outputs: `results/S0_inventory.json`, `results/S0_archive_hashes.json`. No git hash was recorded because the repository was not yet initialised; S0 is re-run after the freeze commit so that the results carry it.
- AWID3 CSV archive: 13 attack folders (`CSV/1.Deauth` ... `CSV/13.Website_spoofing`). Used here: `CSV/4.Rogue_AP` (40 files, 2.49 GB) and `CSV/12.Evil_Twin` (76 files, 5.24 GB). 254 columns, identical headers in every file, label column `Label`.
- Counts confirm the secondary sources cited in protocol Section 6.1:
  - Rogue_AP: 1,973,185 rows; Normal 1,971,875, RogueAP 1,310.
  - Evil_Twin: 3,778,706 rows; Normal 3,673,854, Evil_Twin 104,827, and 25 rows with no label.
- Label strings are `Normal`, `RogueAP` (no underscore) and `Evil_Twin`.
- `frame.number` is increasing within files and continuous across files.
  - Rogue_AP: 1 to 1,973,193. A few frame numbers are absent (files 2, 33, 35, 36).
  - Evil_Twin: 1 to 3,778,728, which is exactly the upper bound of the published Evil_Twin filter. A few frame numbers are absent in 26 files; files 56 and 57 hold 6 and 10 extra rows and the 25 unlabelled rows, probably broken lines in the export. Rows without label or frame number are excluded and counted in S1.
  - The Rogue_AP filter window ends at 1,973,111, 82 frames before the end of the capture.
- Attack frames sit in files 23-39 for Rogue_AP (frame.number >= 1,150,001) and files 28-75 for Evil_Twin (>= 1,400,001), consistent with the lower bounds of the filters.
- The CSV has no `wlan.fc.type_subtype`, `wlan.addr` or `ip.addr` column. It has `wlan.fc.type`, `wlan.fc.subtype` and the individual address fields. The filters are therefore applied in S1 as: type_subtype = 16 x type + subtype (Wireshark encoding: beacon 8, disassociation 10, deauthentication 12, QoS Data 40); `wlan.addr` = any of `wlan.sa`, `wlan.da`, `wlan.ta`, `wlan.ra`, `wlan.bssid`; `ip.addr` = `ip.src` or `ip.dst`. This is a translation of the published filters, not a deviation from the protocol; the encoding is checked on the data in S1.
- Fields available for the semantic family include `wlan.seq`, `wlan.fixed.timestamp` (beacon TSF), `wlan.fixed.beacon` (beacon interval), the capability bits, `wlan.fixed.reason_code`, `wlan.rsn.capabilities.mfpc`, `wlan.ssid`, `radiotap.dbm_antsignal` and `wlan_radio.channel`. RSN cipher-suite fields are not exported, which limits rule R2 (protocol Section 9.6).
- Missing rates: `ip.src` / `ip.dst` 58-66% (non-IP frames), `wlan.sa` / `wlan.da` / `wlan.bssid` about 57-58%.
- Next: S1.
