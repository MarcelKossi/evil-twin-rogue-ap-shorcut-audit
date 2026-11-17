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
- Went through the ten decisions that matter most for the results (frame.number, frame.len, SSID, MAC addresses, frame type and Protected bit, channel/frequency, signal strength, inter-frame times, IE lengths, EAPOL type and Key MIC flag) and the block rules for the other fields. Agree with all of them. Reworded the justification of `ip.src` and `ip.dst` (kept in `docs/annotation/manual_overrides.csv`); no family changed. ESS and IBSS are two different bits of Capability Information: ESS = 1 means infrastructure BSS (an AP), IBSS = 1 an ad hoc network. Both semantic, but any AP, rogue or not, sets them the same way, so they should not separate much.
- Ran `scripts/05_taxonomy_agreement.py`: S 11, A 112, C 8, U 122; Fleiss' kappa 0.876 (all fields), 0.802 (802.11 fields not cited in the guidelines).

## 2026-11-15 - S2b features and S3 set-up (before any model result)

- `scripts/06_build_features.py` turns each capture into a float32 matrix (memory-mapped `.npy` in `data/interim/`). Columns more than 99% missing or constant are dropped and listed in `results/S2b_features.json`. Hex fields are parsed. Numeric columns are stored minus their minimum so that epoch times keep their resolution in float32. Text columns (addresses, names, payloads) are label-encoded on sorted values; above 50,000 distinct values they are hash-encoded. Rows without label or frame number are excluded, as in S1.
- `scripts/07_s3_label_rule.py` runs H1b and H1c with the blocked protocol of Section 9.2.
- **Deviation 3.** Section 9.2 says the pre-attack normal frames go into training in every fold *and* serve as a clean-period false-positive check, which cannot both hold for the same frames. I keep the last 20% of the pre-attack period out of training and use it for the clean-period check; the rest is used for training.
- **Deviation 4** (memory and run time on my laptop): each training set keeps all attack frames and a random sample of at most 100,000 normal frames (seed = fold number). Evaluation always uses the full held-out block. Hyperparameters are tuned once per fold with seed 0 and reused for the other seeds; logistic regression is deterministic and run once; the depth-3 tree of H1b is not tuned.
- **Deviation 5.** For H1c the 95% CI of the relative PR-AUC drop is a bootstrap over the 5 folds (seed-averaged), not the block bootstrap of Section 10. It is coarse; the block bootstrap will be added when test predictions are stored in S4.

## 2026-11-16 - S2b feature matrices

- Ran `scripts/06_build_features.py` on `46dd547` (clean tree): 257 s for Rogue_AP, 463 s for Evil_Twin. Output in `results/S2b_features.json`.
- Rogue_AP: 1,973,185 rows (1,310 attack), 76 columns kept (A 39, U 29, S 5, C 3), 177 dropped (170 more than 99% missing, 7 constant).
- Evil_Twin: 3,778,679 rows (104,827 attack), 72 columns kept (A 37, U 28, S 4, C 3), 181 dropped (174 missing, 7 constant). `wlan.fixed.reason_code` is kept for Rogue_AP (96.7% missing) and dropped for Evil_Twin.
- The 7 constant columns are the same in both captures, among them `radiotap.channel.freq`, `wlan_radio.channel` and `wlan_radio.frequency`: the capture stayed on one channel the whole time, which agrees with classing these fields as artefacts in S2.
- All 12 filter variables are kept, so H1b and H1c can use them.
- Several fields that look numeric are stored as text because some frames hold more than one value (e.g. `radiotap.dbm_antsignal` with one value per antenna, IP and TCP fields of encapsulated packets); they are label-encoded like the other text columns. `frame.time` and a few TCP fields have more than 50,000 distinct values and are hash-encoded.
- Only 4-5 kept columns are semantic. A semantic-only detector (F-sem, S4-S5) will depend on the derived per-BSSID features.
- S2b ran outside the virtual environment (system Python; the prompt had no `(.venv)`). S3 then stopped on `No module named 'xgboost'`. Re-running S2b and S3 inside `.venv` so that every result comes from the pinned packages; result files now also record the package versions.

## 2026-11-17 - S3 results (H1b, H1c)

- Re-ran S2b and S3 inside `.venv` on `3e70913` (clean tree; numpy 1.26.4, pandas 2.2.3, scikit-learn 1.5.2, xgboost 2.1.1). S3: 470 runs, 2 h 25 of model time. Outputs: `results/S3_runs.csv`, `results/S3_label_rule.json`.
- Blocks: Rogue_AP 5 x 154,911 frames with 187-326 attack frames each; Evil_Twin 5 x 471,732 frames with 22,853 / 59,426 / 20,717 / 688 / 1,143 attack frames. Blocks 3 and 4 of Evil_Twin hold almost only rogue beacons.
- **H1b, Rogue_AP: supported.** Depth-3 tree on the filter variables: mean PR-AUC 0.9988; best model on all features (RF) 1.000; ratio 0.999 (threshold 0.95).
- **H1b, Evil_Twin: not supported.** Depth-3 tree 0.870 vs XGB 0.979, ratio 0.889. Per block, the tree matches the best models on blocks 0-2 (0.976-0.997) and falls on blocks 3-4 (0.614, 0.767), where the best models also drop (XGB 0.897 on block 3).
- **H1c: not supported for either capture.** Removing the filter variables costs >= 20% PR-AUC for 1/5 models on Rogue_AP (LR only) and 2/5 on Evil_Twin (LR, DT). RF, XGB and DT stay at 1.000 on Rogue_AP without them; on Evil_Twin RF goes from 0.959 to 0.954 and XGB from 0.979 to 0.968.
- Without the filter variables the false-positive rate on the clean pre-attack period rises sharply on Evil_Twin (secondary metric): XGB 0.02% -> 1.37%, LR 0.02% -> 3.3%, DT 0.007% -> 20%. On Rogue_AP it stays near zero.
- Reading: the filter variables are sufficient for Rogue_AP but not necessary, for either capture. The same information is available in other fields. My guess, to be checked with the attributions of S4 and not a result yet: fields that carry frame length indirectly (e.g. `wlan_radio.duration`, the airtime computed from length and rate) or the rogue AP's position (signal strength).

## 2026-11-17 - S4 set-up (before any S4 result)

- `scripts/08_s4_reliance.py` runs RQ2: feature sets F-all, F-noA (no artefacts) and F-sem (semantic fields only), 5 model families, seeds 0-4, under the blocked protocol and under one stratified random 80/20 split (H2b). Attribution shares per family are computed on an evaluation sample of each test set (attack frames up to 10,000, 20,000 rows in total), as in Section 7.4.
- **Deviation 6.** Section 7.4 asks for TreeSHAP on DT, RF and XGB. Exact TreeSHAP is too slow on my laptop for trees of unbounded depth, so DT and RF use path (Saabas) contributions: the change in P(attack) at each split on the decision path, credited to the split feature. They add up exactly to the model output (checked), but they are not Shapley values. XGB keeps exact TreeSHAP (native in XGBoost), LR keeps linear SHAP. The conclusions will be checked against the XGB values and the permutation importance.
- **Deviation 7.** Grouped permutation importance (the secondary method) is computed for seed 0 only, to save time. F-chatz is not run yet: I first need the exact list of the 16 features of Chatzoglou et al. (2022). The random-split runs reuse the hyperparameters chosen on blocked fold 0; the blocked F-all runs reuse the S3 configurations.

## 2026-11-17 - code review before S4, fixes

- Had the evaluation code (S2b, S3, S4) reviewed independently for leakage, without access to the hypotheses or results. Verdict: no test row reaches model fitting, preprocessing, tuning or thresholds in the blocked protocol; the fold sets are disjoint and the 10,000-frame purge works, for tuning too. The capture-wide label encoding uses no labels and is benign.
- Fixed before any S4 result:
  - the clean period (end of the pre-attack period) had no purge: training rows right before and after it were kept, so the clean-period false-positive rate was optimistic. Training rows within 10,000 frames of the clean period are now removed;
  - the validation block is now purged against the test block, so tuning and thresholds no longer see frames next to the test block;
  - the random split of H2b now draws its test set from the attack window only, the same population as the blocked protocol (the first version drew from the whole capture, which changes the attack share and makes PR-AUC not comparable);
  - `Capture.load` checks that rows are in increasing frame.number order (true for both captures, see S2b) and maps any unknown family to U.
- S4 now tunes every feature set itself instead of reusing the S3 configurations.
- Consequence for S3: the clean-period false-positive rates reported above are optimistic (for F-all and F-noFV alike, so the comparison between them stands but not the absolute values), and tuning saw frames next to the test block. I will re-run S3 with the corrected folds after S4, keep the first run as `S3_runs_v1.csv` / `S3_label_rule_v1.json`, and report the corrected numbers.
- Note on H1c: F-noFV still contains other fields that encode the position in the capture (`frame.time_relative`, `frame.time_epoch`, `radiotap.timestamp.ts`, the `wlan_radio` timestamps). The filter variables of protocol Section 7.3 include `frame.number` only, so H1c does not remove position information. F-noA in S4 removes all of it.
- F-chatz is now included in S4 (it was left out in deviation 7): the 16 features of Chatzoglou et al. (2022) as listed, identically, by three later studies that reuse them (Khalid et al. 2025, Ahmad et al. 2025 with public code, Solpan et al. 2026). I could not read the 2022 paper itself yet; the list must be checked against it before the paper. These 16 features contain no MAC, IP or time field, but they do contain `frame.len`, `radiotap.dbm_antsignal` and `wlan.duration`.
- Planned, exploratory, added after S3: (1) a perturbation test: give the trained models copies of the real rogue beacons in which only the fields the attacker sets in his tool are changed to the legitimate AP's values (beacon length 263 -> 342 and the airtime that follows), and measure how much detection drops; training data untouched; (2) a reproduction of published AWID3 pipelines, first Ahmad et al. 2025 (arXiv:2510.11898, public code, 16 features, random 70/30 split) and then Solpan et al. 2026 (code public; SMOTE applied before the train/test split). Both will be reported whatever the outcome.
