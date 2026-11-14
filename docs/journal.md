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

## 2026-11-13 - S1 Parquet conversion and label/filter agreement (H1a)

- S1a (`scripts/01_to_parquet.py`) ran on commit `e6971b6` while the script itself was not yet committed; it was committed unchanged in `0890d07`. Evil_Twin: 3,778,706 rows, 1.70 GB Parquet, 630 s. Rogue_AP: 1,973,185 rows, 0.78 GB, 361 s. 256 columns (254 + `source_file` + `row_in_file`). Row counts equal S0.
- S1b (`scripts/02_filter_agreement.py`): the first run loaded the full Evil_Twin table and failed for lack of memory. The script now reads the Parquet files in batches of 200,000 rows (commit `0890d07`); the computation is unchanged.
- Encoding check: `wlan.fc.type` takes 0/1/2 (management/control/data). With type_subtype = 16 x type + subtype, beacons are 8 and the other codes are consistent with Wireshark (RTS 27, CTS 28, ACK 29, block ack 25, QoS Data 40). The translation of the filters is confirmed.
- **Rogue_AP: the published filter reproduces the labels exactly.** kappa = 1.000 (TP 1,310, FP 0, FN 0). All 1,310 attack frames are beacons of exactly 263 bytes; the 1,690 normal beacons inside the window are 342-343 bytes. The labelled attack frames span exactly frame.number 1,198,551-1,973,111, the bounds of the filter.
- **Evil_Twin: near-exact agreement.** 27 rows excluded (no label or no frame number, files 56-57). kappa = 0.9959 (TP 104,168, FP 183, FN 659; filter precision 0.9982, recall 0.9937). The labelled attack frames span exactly 1,420,038-3,778,728. Every labelled attack frame involves the MAC address 0c:9d:92:54:fe:35 (100%) and 95.3% involve the IP 192.168.30.1.
- Composition of the Evil_Twin label: QoS Data 100,574 (95.9%), beacons 3,568 (3.4%), QoS Null 360, Data 250, probe responses 26, association requests 22, disassociation 17, deauthentication 10. The false negatives of the filter are exactly the frame types it does not list (QoS Null, Data, probe response, association request). The false positives are 143 short beacons, 36 QoS Data and 4 disassociation frames that meet the filter but are labelled Normal.
- The Rogue_AP capture contains 62,459 deauthentication frames, all labelled Normal.
- **Gate G0:** kappa >= 0.80 for both attacks, so RQ1 (label provenance) is the headline of the paper, as planned in protocol Section 14.
- **Deviation 1** (decided after seeing the S1 counts, before any model is trained): sub-task ET-M (deauthentication/disassociation) has only 27 labelled frames and is too small to analyse on its own. It is reported descriptively only. ET-D (post-association data, 95.9%) and ET-B (beacons, 3.4%) are kept. In practice the AWID3 Evil_Twin class is mostly data traffic of victims already associated with the rogue AP, not impersonation frames.
- Next: S1c label diagnostics (exploratory), then S2.

## 2026-11-13 - S1c label diagnostics (exploratory)

- Ran `scripts/03_label_diagnostics.py` on commit `d66fa93` (clean tree). Output: `results/S1c_label_diagnostics.json`. These analyses are not in protocol v0.3 and are reported as exploratory.
- **Rogue_AP capture.** The 1,310 attack beacons carry SSID `ASUS_5G` and BSSID `0c:9d:92:54:fe:34`, the same SSID and BSSID as the 5,634 beacons labelled Normal. The rogue AP therefore clones the legitimate AP's identity, and the only difference visible in the beacon frames exported here is the length: 263 bytes for every attack beacon, 342-343 bytes for the legitimate beacons (plus 1 beacon of 1,618 bytes). No 263-byte beacon exists outside the filter window, so the labels are recovered by beacon length alone; the frame.number window is redundant for this class.
- The Rogue_AP capture contains 62,455 unprotected deauthentication frames with source address `0c:9d:92:54:fe:34` inside the filter window, and 1 outside it. All are labelled Normal. Their timing is consistent with forged deauthentication accompanying the rogue AP, but the source address is the cloned one, so their origin cannot be established from the frames alone.
- **Evil_Twin capture.** The rogue AP uses SSID `ASUS_5G` (the legitimate SSID) and BSSID `0c:9d:92:54:fe:35`, which differs from `...:34` only in the last byte. Its beacons come in two lengths, 241 and 150 bytes (1,784 of each labelled Evil_Twin). Legitimate beacons are 342-343 bytes.
- A simpler rule than the published filter reproduces the Evil_Twin labels almost as well: frame.number in the window AND frame involving `0c:9d:92:54:fe:35` AND management or data frame gives kappa = 0.9943 (recall 1.000, precision 0.989; 1,174 false positives).
- 208 rogue beacons are labelled Normal (5.5% of the rogue beacons): 143 beacons of 150 bytes inside the window and 65 beacons of 241 bytes before the window, the first one at frame 1,351,181, about 69,000 frames before the labelled attack period starts. The rogue AP is active before the labelled period.
- 25,169 control frames involving the rogue AP inside the window (ACK, CTS, block ack) are labelled Normal: the labelling covers management and data frames only.
- Next: S1d figures for the label structure, then S2 taxonomy.

## 2026-11-13 - S1d figures

- Ran `scripts/04_figures_labels.py`. Outputs: `figures/fig1_rogue_ap_capture.png`, `figures/fig2_evil_twin_capture.png`, `results/S1d_figure_data.json`. Counts agree with S1 and S1c.
- Rogue_AP: the unprotected deauthentication frames (62,458; 62,457 inside the filter window) start exactly at the window and coincide with the 263-byte rogue beacons; none before it. This strengthens the reading that they belong to the attack, although they are labelled Normal.
- Evil_Twin: the rogue AP uses two beacon configurations in sequence, 241 bytes from about frame 1.35 M to 2.75 M, then 150 bytes until the end of the capture. The rogue beacons labelled Normal are not scattered: they form two contiguous blocks, one just before the labelled window (241 bytes) and one around frames 2.85-2.95 M (150 bytes).
- The labelled Evil_Twin data traffic comes in bursts between about 1.75 M and 2.7 M frames.

## 2026-11-15 - S2 feature taxonomy

- Defined the annotation guidelines (`docs/taxonomy_guidelines.md`): four families (S semantic, A artefact, C attacker-controllable, U ambiguous/unrelated) and the question to ask for each field.
- **Deviation 2** (protocol Section 7.1 planned a blind second human annotator on 30% of the fields): the 253 fields were annotated independently by three large language model instances (Claude Opus, Sonnet and Haiku) configured as IEEE 802.11 security experts. Each received only the guidelines and the field list, with no information on the study or the data. I set the decision rule, reviewed the result and approved the taxonomy. The procedure, prompt and raw annotations are in `docs/annotation/`. A human check on the 30% sample (`docs/taxonomy_blind_sample.csv`) stays possible and will be reported if done.
- Decision rule: final family = majority vote of the three annotators. Every field had a majority of at least two.
- Agreement (`results/S2_taxonomy_agreement.json`): Fleiss' kappa 0.876 on all 253 fields (89.3% unanimous), 0.802 on the 40 802.11/radio fields not cited as examples in the guidelines.
- Final families: S 11, A 112, C 8, U 122. Main points: the channel/frequency fields are artefacts (in monitor mode they report the frequency the capture card was tuned to; the AP's announced channel is in the DS Parameter Set element, not exported); inter-frame times and receiver-side radio fields are artefacts; information-element lengths are attacker-controllable; EAPOL type and the Key MIC flag are semantic.
- Planned robustness check: the reliance scores of S4 will also be computed under the alternative assignment of every non-unanimous field, so that no conclusion rests on a contested field.
- Author review: I checked the ten decisions that weigh most on the results (frame.number, frame.len, SSID, MAC addresses, frame type and Protected bit, channel/frequency, signal strength, inter-frame times, information-element lengths, EAPOL type and Key MIC flag) and the block rules for the remaining fields, and accepted them. I reworded the justification of `ip.src` and `ip.dst` (recorded in `docs/annotation/author_overrides.csv`). No family was changed. The ESS and IBSS capability bits keep separate justifications: ESS = 1 marks an infrastructure BSS (an AP), IBSS = 1 an ad hoc network; both are semantic, though every AP, rogue or legitimate, sets them the same way.
