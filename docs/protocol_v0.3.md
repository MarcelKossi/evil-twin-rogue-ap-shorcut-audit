# Research Protocol v0.3 — Pre-registration

**Title:** Attack, Capture, or Labelling Rule? Auditing What Evil Twin Detectors Learn on Public 802.11 Datasets

## 0. Document control

| Item | Value |
|---|---|
| Version | 0.3 (frozen) |
| Date frozen | 2026-11-12 |
| Git tag | `prereg-v0.3` |
| Author | Kossi Tamplare |
| Status | Pre-registration. No model has been trained and no label/filter agreement has been computed at the time of freezing. |
| Change policy | This file is never edited after tagging. Deviations are logged in `docs/journal.md` (Section 15). |

Facts marked **[V]** were verified by the author on a primary source. Facts marked **[TBV]** (to be verified) come from secondary sources and must be confirmed in Stage S0 before use.

---

## 1. Summary

Machine-learning detectors of Evil Twin and Rogue Access Point (AP) attacks trained on the public AWID datasets routinely report 98–100% detection performance. We hypothesise that part of this performance does not come from learning the attack. Instead, it may come from three sources:

1. **Capture artefacts.** Frame counters, timestamps and laboratory-specific identifiers.
2. **The labelling rule.** AWID3 publishes Wireshark display filters that isolate attack frames using frame-number ranges, frame-length thresholds and one specific MAC/IP address.
3. **Attacker-controllable fields.** For example, beacon length.

We will audit what lightweight detectors actually rely on, using four methods:
- label/filter agreement analysis;
- attribution grouped by feature family (SHAP and grouped permutation importance), confirmed by retraining ablations;
- a comparison between random and blocked splitting protocols;
- cross-dataset transfer between AWID3, AWID2 and, if available, a third dataset.

We will also test whether features with protocol meaning, and a transparent rule baseline, transfer better than "99%" models. Finally, we will test whether synthetic oversampling of the rare Rogue_AP class improves detection or only the reported numbers.

All experiments run on public data, on a laptop CPU, within about 12 weeks.

---

## 2. Background and motivation

**Evil Twin and Rogue AP.**
- A *rogue AP* is any unauthorised access point.
- An *Evil Twin* is a rogue AP that impersonates a legitimate one. It copies the SSID and sometimes the BSSID. It often forces clients to disconnect from the legitimate AP using forged deauthentication or disassociation frames, then captures their reconnection.

**Why it matters for IoT.**
- IoT devices auto-reconnect to known networks (Preferred Network List).
- They have no user interface to notice anomalies.
- They frequently run WPA2-PSK without Protected Management Frames (IEEE 802.11w / PMF).

IoT is the motivation of this study, **not** its experimental domain (Section 5).

**State of detection research.**
- Public 802.11 intrusion datasets (AWID2, AWID3) contain Evil Twin traffic.
- Studies on them report near-perfect accuracy.
- Chatzoglou et al. (2022) warned that the Wi-Fi IDS field is dominated by "false or half-true assumptions" that lead to overfitting to validation datasets.
- Cross-version transfer studies (Yonbawi et al., 2025; Khalid et al., 2025) show that high in-dataset scores do not guarantee transfer. They do not explain why, and they do not study Evil Twin specifically.

**Shortcut learning.**
- A model may solve a benchmark through spurious cues that do not hold in deployment (Geirhos et al., 2020).
- In security ML, data snooping, spurious correlations and inappropriate baselines are documented pitfalls (Arp et al., 2022). Leakage is a recognised reproducibility problem across ML-based science (Kapoor & Narayanan, 2023).
- Roy & Minu (2026) recently showed shortcut learning on an IoT **flow** dataset. Raw timestamps raised tree models to 99.28% Macro-F1, and random splitting inflated recall by up to 14 points **[V]**.
- No study has done this for 802.11 frame-level detection, for Evil Twin, or with respect to a dataset's published labelling filters.

---

## 3. Problem statement and research gap

**Problem.** Reported Evil Twin and Rogue AP detection scores on AWID may overestimate real detection capability, because models can exploit capture artefacts and labelling-rule variables rather than the attack's protocol-level evidence.

**Gap.** No published work, to our knowledge as of the freeze date, does any of the following:
- (a) measures the agreement between AWID3's Evil_Twin / Rogue_AP labels and the dataset's published filters;
- (b) quantifies how much 802.11 detectors rely on artefact or filter variables, with ablation confirmation;
- (c) relates that reliance to cross-dataset transfer failure for Evil Twin;
- (d) evaluates synthetic oversampling of the rare Rogue_AP class with respect to transfer and artefact reliance.

**Novelty boundary.** The *idea* of shortcut learning in IDS is not new (Roy & Minu, 2026). Our novelty lies in:
- the 802.11 frame level;
- the Evil Twin / Rogue AP attack family;
- the label-provenance audit against published filters;
- the cross-version link between reliance and transfer.

---

## 4. Positioning against the closest work

| Work | What it does | What it does not do |
|---|---|---|
| Kolias et al. 2016; Chatzoglou et al. 2021 | Release AWID2 / AWID3 | Do not audit labels against filters |
| Chatzoglou et al. 2022 | Expert selection of 16 transferable features; F1 up to 99.55% | No reliance measurement, no Evil Twin focus, no label audit |
| Yonbawi et al. 2025; Khalid et al. 2025 | AWID ↔ AWID3 transferability | No explanation of the failure; Evil Twin not studied [TBV] |
| Bhandari et al. 2020 | SHAP on AWID; observes time-feature covariate shift between train and test | Does not frame it as leakage or a shortcut; uses a random split [TBV] |
| Roy & Minu 2026 | Shortcut learning and split leakage on an IoT flow dataset [V] | No Wi-Fi, no 802.11, no AWID, no cross-dataset test [V] |
| Ibrahim et al. 2026 (preprint) | AWID2 → AWID3 domain adaptation, open-set [TBV] | No shortcut / leakage analysis reported [TBV] |

---

## 5. Scope, assumptions and threat model

**In scope.**
- Frame-level, passive, network-side detection of Evil Twin and Rogue AP from 802.11 monitor-mode captures (radiotap + 802.11 headers), as represented in the public AWID CSVs.
- Lightweight models runnable on a CPU.

**Out of scope.**
- Hardware testbeds, client-side detection, LLMs, federated learning, IP-only datasets.
- Claims about IoT deployment performance. The IoT relevance is argued, not measured, and this is stated as a limitation.

**Threat model.** The attacker:
- controls a rogue AP running standard tools (e.g., hostapd / airbase-ng);
- can set the SSID, BSSID, channel, beacon content and length, and transmit power;
- can send unprotected deauthentication / disassociation frames when PMF is not enforced.

The attacker cannot control the defender's capture timestamps or frame counters. Fields the attacker can set are classified as *attacker-controllable* (Section 7.1).

---

## 6. Data

### 6.1 AWID3 (primary dataset)

- **Network:** WPA2-Enterprise (802.1X), released by Chatzoglou et al. (2021). PMF is reported as enabled for the 802.11 attacks [TBV].
- **Format:** CSV extracted with tshark, about 254 features [TBV]. One capture folder per attack.
- **Classes used:** `Evil_Twin` and `Rogue_AP` (separate classes on the dataset website [V]).
- **Access:** read directly from the official archive `AWID3_Dataset_CSV.zip` (about 14.5 GB) without full extraction. Only the Evil_Twin and Rogue_AP members are converted to Parquet (Stage S1).
- **Expected counts (secondary sources [TBV], to be confirmed in S0):**

| Capture | Attack frames | Normal frames | Total | Attack prevalence |
|---|---|---|---|---|
| Evil_Twin | 104,827 | 3,673,854 | 3,778,681 | ≈ 2.8% |
| Rogue_AP | 1,310 | 1,971,875 | 1,973,185 | ≈ 0.066% |

**Published filters [V]** (AWID3 website). They are described as capturing more than 95% of attack frames. The website does not state that these filters were used to assign the labels.

- **Rogue_AP:**
  `wlan.fc.type_subtype==8 && frame.number>=1198551 && frame.number<=1973111 && frame.len<264`
- **Evil_Twin:**
  `((wlan.fc.type_subtype==8 && frame.len<242) || ((wlan.fc.type_subtype==10 || wlan.fc.type_subtype==12 || wlan.fc.type_subtype==40) && wlan.fc.protected==0)) && frame.number>=1420038 && frame.number<=3778728 && (ip.addr==192.168.30.1 || wlan.addr==0c:9d:92:54:fe:35)`

**Field interpretation**, assuming Wireshark ≥ 3 encoding of `wlan.fc.type_subtype` (to be confirmed in S0):
- 8 = Beacon;
- 10 = Disassociation;
- 12 = Deauthentication;
- 40 (0x28) = QoS Data.

**Consequences of the filters (inferences to be verified in S0):**
- The attack windows extend to the end of each capture. The variable `frame.number` therefore separates "before attack" from "attack period".
- The Evil_Twin label mixes three behaviours (Section 7.2).

### 6.2 AWID2-ATK-R (transfer dataset)

- **Network:** WEP. Reduced attack-level version, with train (Trn) and test (Tst) files, 155 features.
- **Format:** possibly no header row; missing values may be encoded as `?` [TBV].
- **Label used:** `evil_twin`. Reported counts: 2,633 (Trn) and 611 (Tst) [TBV].
- **Rogue AP:** no Rogue_AP class. Rogue AP transfer therefore relies on Section 6.3.
- **Access:** the official AWID2 distribution provides the reduced subsets as separate archives (`AWID-ATK-R-Trn.tar.gz`, about 60 MB; `AWID-ATK-R-Tst.tar.gz`, about 19 MB). Only these two archives are used.

### 6.3 Optional third dataset

- **WPA3 Attacks Dataset** (Mendeley Data, DOI 10.17632/cxx5t5nw7z.1, May 2026). Reported to include separate Rogue AP and Evil Twin classes, PCAP and CSV, WPA3/SAE [TBV].
- It will be used only if its licence permits research use and publication, and its labelling is documented.
- If it is unavailable, all analyses involving a third domain are reported as not performed. This does not invalidate RQ1–RQ3.

### 6.4 Excluded

- **AFSD (IEEE DataPort):** subscription-only, simulated [V]. Excluded.
- **Synthetic beacon datasets with documented label leakage:** excluded.

---

## 7. Definitions

### 7.1 Feature families

Every feature is assigned to exactly one family in `docs/taxonomy.csv`. Each row gives the field name, the family, a one-line justification referencing IEEE 802.11-2020 or capture tooling, and its presence in AWID2 / AWID3 / the third dataset.

| Code | Family | Definition | Examples |
|---|---|---|---|
| **S** | Semantic | Has a protocol meaning that is plausibly causally related to impersonation, and the attacker cannot set it freely without consequences | Frame type/subtype; protection flag; RSN / capability information; sequence-number and TSF consistency (derived per BSSID); channel; deauth/disassoc reason codes |
| **A** | Artefact | Depends on the capture session, the tool or the lab, not on the attack | `frame.number`, absolute timestamps (`frame.time*`, `radiotap.mactime`), capture-order counters, lab-specific MAC / IP identifiers |
| **C** | Attacker-controllable | Carries real signal in this capture, but a competent attacker can set it to mimic the legitimate AP | `frame.len` of beacons, SSID, BSSID, beacon interval, transmit power / RSSI |
| **U** | Ambiguous | Status depends on use or encoding | Raw TSF (artefact as an absolute value, semantic as a per-BSSID delta) |

**Taxonomy rules:**
- The taxonomy is completed in Stage S2, **before** any attribution result is computed.
- Ambiguous fields are reported separately and excluded from the reliance scores' numerator and denominator in a sensitivity analysis.
- A second annotator (co-author or colleague), blind to model results, independently classifies a random 30% of fields. Agreement is reported as Cohen's κ.

### 7.2 Evil Twin sub-tasks

Following the published filter, Evil_Twin-labelled frames are partitioned by frame type:
- **ET-B (beacon impersonation):** Beacon frames (subtype 8).
- **ET-M (forced disconnection):** unprotected Deauthentication / Disassociation frames (subtypes 12 / 10).
- **ET-D (post-association traffic):** unprotected QoS Data frames (subtype 40) to or from the rogue network.

Performance and reliance are reported overall and per sub-task. This shows which behaviour a so-called "Evil Twin detector" actually detects.

### 7.3 Filter variables

FV = {`frame.number`, `frame.len`, `wlan.fc.type_subtype`, `wlan.fc.protected`, IP address fields, WLAN address fields}.

### 7.4 Reliance scores

For a trained model *m*, evaluated on an evaluation sample *E*, the attribution of feature *j* is
I_j = mean over *E* of |φ_ij|, where φ_ij is the SHAP value.

The following scores are defined:
- **ARS (Artefact Reliance Score)** = Σ_{j∈A} I_j / Σ_j I_j
- **ACRS (Artefact + Controllable Reliance Score)** = Σ_{j∈A∪C} I_j / Σ_j I_j
- **FRS (Filter Reliance Score)** = Σ_{j∈FV} I_j / Σ_j I_j

**Attribution methods:**
- **Primary:** exact or efficient SHAP.
  - TreeSHAP for Decision Tree, Random Forest and XGBoost.
  - LinearSHAP for Logistic Regression.
  - The MLP is excluded from SHAP scores.
- **Secondary (all five models, including the MLP):** grouped permutation importance. This is the drop in PR-AUC when all features of a family are permuted jointly, with 10 repetitions.
- **Confirmatory:** retraining ablation. The family is removed, the model is retrained with the same seed, and the PR-AUC drop is measured.

**Evaluation sample E:** all positive frames of the test fold (capped at 10,000), plus a uniform random sample of negatives, for a total of n = 20,000 frames per fold.

---

## 8. Research questions and hypotheses

All thresholds below are **frozen**. The pilot (Stages S0–S1) may only check feasibility; it cannot change thresholds. Each hypothesis states what is concluded if it is rejected. Every outcome is reported.

### RQ1 — Label provenance

*Can AWID3's Evil_Twin and Rogue_AP labels be reproduced by the published filters, and do detectors learn the filter?*

- **H1a (agreement).** For each attack, the published filter reproduces the labels with Cohen's κ ≥ 0.80. We also report the confusion matrix, the filter's precision and recall against the labels, and the share of labelled attack frames outside the filter's `frame.number` window.
  - *If rejected:* the labels were not assigned by the filter alone. We characterise the disagreement by frame type and time, and report it as a label-quality finding. RQ2–RQ3 then become the core.
- **H1b (filter sufficiency).** A decision tree of depth ≤ 3, trained only on FV, reaches at least 0.95 × the PR-AUC of the best model trained on all features, under the blocked protocol (Section 9.2).
- **H1c (filter necessity).** Removing FV and retraining reduces PR-AUC by at least 20% relative, with the 95% CI of the drop excluding 0, for at least 3 of the 5 model families.

### RQ2 — Artefact reliance and evaluation protocol

*How much do detectors rely on artefacts, and does the common random split inflate both performance and reliance?*

- **H2a (reliance).** Under the blocked protocol with feature set F-all, the median ARS across the four SHAP-scored models is ≥ 0.25. Removing family A reduces PR-AUC by at least 10% relative (CI excluding 0) for at least 3 of the 5 models.
  - *Rationale:* a quarter of decision attribution on fields with no protocol meaning is operationally unacceptable for a deployed detector.
- **H2b (split inflation).** Compared with the blocked protocol, a random frame-level split (as commonly used in the literature) yields:
  - higher PR-AUC, tested with a paired Wilcoxon signed-rank test over model × feature-set × seed, one-sided, α = 0.05 after Holm correction;
  - higher ARS, tested the same way.
- **H2c (stability).** The ranking of the four families (S, A, C, U) by attribution is stable: mean pairwise Kendall τ ≥ 0.6 across seeds within a model, and reported (not tested) across models.

### RQ3 — Transfer

*Does artefact reliance predict transfer failure, and what transfers?*

**Transfer gap.** For a configuration trained on source domain *s* and tested on target domain *t*:

G = 1 − PR-AUC(s→t) / PR-AUC(t→t)

where PR-AUC(t→t) is the in-domain blocked-protocol score of the same model and feature set trained on *t*. This normalises for different target prevalences.

- **H3a.** Across configurations (5 models × 4 feature sets × 2 directions, seed-averaged), Spearman's ρ between source-domain ARS and G is > 0. Supported if the lower bound of the 95% bootstrap CI (2,000 resamples, clustered by model family) is > 0.
  - Main pair: AWID3 ↔ AWID2, Evil Twin only, on the shared feature set.
  - The third dataset is added when available.
- **H3b.** The transfer gap of F-sem models and of the rule baseline (Section 9.6) is lower than that of F-all models. Tested with a paired one-sided Wilcoxon test across model × direction, Holm-corrected. We also report that their in-domain PR-AUC may be lower; that trade-off is the expected finding.

**Confounder control for RQ3.**
- AWID2 is WEP, AWID3 is WPA2-Enterprise. Part of the gap is genuine protocol change, not artefact.
- We therefore restrict transfer to shared fields, report per sub-task (ET-B / ET-M / ET-D), and treat ET-B as the cleanest test of impersonation, since beacons are protocol-version-agnostic.

### RQ4 — Imbalance probe

*Does synthetic oversampling improve detection or only reported numbers?*

- **H4.** For Rogue_AP and Evil_Twin, using Random Forest and XGBoost with F-all, SMOTE applied to the training folds only, compared with class weighting:
  - (i) increases in-domain PR-AUC;
  - (ii) does not reduce the transfer gap (Δ G ≥ 0, or CI including 0);
  - (iii) increases ARS.

  All three must hold for H4 to be supported.

- Arms: no treatment, class weighting, SMOTE, and, if Section 6.3 is available, augmentation with real Rogue AP frames from the third dataset.
- **Synthetic samples never enter any validation or test set.**
- Rogue_AP transfer is evaluated only if the third dataset is available. Otherwise H4(ii) is tested on Evil_Twin only.

---

## 9. Experimental design

### 9.1 Stages

| Stage | Content | Output |
|---|---|---|
| S0 | Data inventory: files, sizes, headers, row counts, label values, `frame.number` continuity, `type_subtype` encoding, SHA-256 of archives | `results/S0_inventory.json` |
| S1 | Conversion to Parquet (needed columns only); **Test 0 = H1a** | `results/S1_filter_agreement.json` — **Gate G0** |
| S2 | Taxonomy (`docs/taxonomy.csv`), preprocessing, feature sets | Taxonomy frozen by commit before S3 |
| S3 | RQ1: H1b, H1c; sub-task breakdown | `results/S3_*` |
| S4 | RQ2: models × feature sets × seeds; SHAP, permutation, ablation; random vs blocked | `results/S4_*` — **Gate G1** |
| S5 | AWID2 preparation, feature alignment, transfer (RQ3a) | `results/S5_*` |
| S6 | Rule baseline, H3b | `results/S6_*` |
| S7 | Imbalance probe (RQ4) | `results/S7_*` — **Gate G2** |
| S8 | Statistics, figures, writing | Paper |

### 9.2 Splitting protocols

- **Blocked protocol (primary, in-domain).**
  - The attack window (the `frame.number` range containing labelled attack frames) is cut into K = 5 contiguous blocks of equal frame count.
  - Leave-one-block-out cross-validation is used. A purge gap of 10,000 frames is removed on each side of the test block from the training data.
  - Frames before the attack window (normal-only) are added to training in every fold, and reported separately as a "clean period" false-positive check.
  - Hyperparameters are tuned on the training block adjacent to the test block (inner validation), never on the test block.
- **Random protocol (comparison only, H2b).** Stratified random 80/20 frame-level split, mimicking common practice.
- **Cross-dataset protocol (RQ3).** Train on all of the source domain, test on all of the target domain, using the shared feature set.

### 9.3 Preprocessing

- Every column is profiled before use: name, dtype, unique values, missing rate.
- Columns that are constant or more than 99% missing in the source domain are dropped. They are logged, not silently removed.
- Hex fields are parsed to integers.
- Identifiers (MAC, IP, SSID) are label-encoded **only** in F-all. This mimics common literature practice, and the audit measures its effect.
- Missing values:
  - tree models: −1 sentinel;
  - LR / MLP: median imputation plus a missing indicator, then standardisation fitted on training data only.

### 9.4 Feature sets

| Set | Content | Purpose |
|---|---|---|
| F-all | All usable fields, including identifiers and time fields | Replicates common practice |
| F-noA | F-all minus family A | Ablation |
| F-sem | Family S only (plus derived per-BSSID deltas) | What transfers |
| F-chatz | The 16 features of Chatzoglou et al. (2022), if present | Literature reference |
| F-filter | FV only | H1b |

For transfer, every set is intersected with the fields shared by source and target.

### 9.5 Models

| Model | Configuration |
|---|---|
| LR | Logistic regression, L2 penalty, class weights |
| DT | Decision tree; depth ≤ 3 for H1b, tuned otherwise |
| RF | Random forest, 300 trees, class weights |
| XGB | XGBoost, `scale_pos_weight` set from the training prevalence |
| MLP | 2 hidden layers (64, 32), early stopping |

- Each model has a small grid of at most 6 configurations, tuned on inner validation by PR-AUC.
- Seeds are {0, 1, 2, 3, 4}.

### 9.6 Rule baseline

Window-based rules, defined **a priori**. Parameters are fixed here and not tuned on test data.
- **Reference profile:** learned from the first 60 seconds of the pre-attack normal period (BSSID whitelist; per-BSSID RSN/capability profile).

| Rule | Description |
|---|---|
| R1 | Known SSID announced by a BSSID absent from the whitelist |
| R2 | Beacon whose RSN/capability profile differs from the reference profile of its SSID |
| R3 | Sequence-number discontinuity > 100 within a BSSID in a 1 s window |
| R4 | Non-monotonic TSF within a BSSID |
| R5 | ≥ 10 unprotected deauthentication / disassociation frames in 1 s |

- The rule score is the number of fired rules (0–5). PR-AUC is computed from that score.
- Rules whose fields are missing in a dataset are reported as not applicable.

### 9.7 Metrics

- **Primary:** PR-AUC (average precision). It is always reported with the prevalence baseline.
- **Secondary:**
  - ROC-AUC;
  - Matthews correlation coefficient at the threshold maximising F1 on inner validation;
  - recall at false-positive rate 10⁻³ and 10⁻²;
  - false-positive rate on the clean period.

---

## 10. Statistical analysis

- Results are reported as mean ± standard deviation over seeds, with 95% CIs from a block bootstrap of the test predictions (block = 1,000 contiguous frames, 2,000 resamples).
- Paired comparisons use Wilcoxon signed-rank tests, one-sided where the hypothesis is directional.
- Correlations use Spearman's ρ with a clustered bootstrap CI.
- **Multiple testing:** Holm correction across the confirmatory family {H1c, H2a, H2b, H3a, H3b, H4}, at α = 0.05.
- Effect sizes are reported for every test.
- H1a and H2c are descriptive, with thresholds and no p-values.
- Any analysis not listed in this document is labelled **exploratory** in the paper.

---

## 11. Expected contributions

**Guaranteed, independent of outcomes:**
1. **C1** — The first label-provenance audit of AWID3 Evil_Twin and Rogue_AP against the published filters, with a sub-task decomposition of the Evil_Twin label.
2. **C2** — An 802.11 feature taxonomy (S/A/C/U), justified against the standard and double-annotated, plus reliance scores validated by ablation.
3. **C3** — An open, reproducible evaluation protocol (blocked splits, transfer gap, checklist) for Wi-Fi intrusion detection.

**Conditional on results:**
4. **C4** — Quantified evidence that reported scores overestimate detection capability (H1, H2).
5. **C5** — A minimal semantic feature set and a rule baseline that transfer better (H3b).
6. **C6** — Evidence on whether synthetic oversampling inflates numbers without improving generalisation (H4).

---

## 12. Threats to validity

- **Single capture per attack.** Results describe one attacker device and one environment per class.
- **Label noise.** The filters cover about 95% of attack frames; the true labelling procedure is undocumented.
- **Protocol change.** AWID2 (WEP) vs AWID3 (WPA2-Enterprise, PMF). Mitigated by shared features and sub-task analysis, not eliminated.
- **Feature alignment.** Field names and tshark versions may differ between datasets.
- **Attribution reliability.** SHAP is unreliable with correlated features. Mitigated by family-level grouping, permutation importance and retraining ablation.
- **Taxonomy subjectivity.** Mitigated by standard-based justification and blind double annotation.
- **External validity.** No IoT-specific capture. IoT relevance is argued from device behaviour, not measured.
- **Thin Rogue_AP class.** About 1.3k frames, roughly 2 minutes of beacons. Results are reported with CIs and are not over-interpreted.

---

## 13. Reproducibility and research integrity

- Raw data is read-only and is never committed. Archives are identified by SHA-256 in `results/S0_archive_hashes.json`.
- Every reported number is produced by a script in `scripts/`. Each script writes JSON to `results/` with the git commit hash, seed, input hash and timestamp.
- The environment is pinned in `requirements.txt`.
- Every run is logged in `docs/journal.md`.
- Code is released under an open licence at submission. Derived data is not redistributed; scripts regenerate it from the official datasets.
- **Ethics:** public datasets only; no attack is performed against any network.

---

## 14. Decision gates and timeline

| Week | Dates | Stage | Gate |
|---|---|---|---|
| 0 | 12–15 Nov 2026 | Freeze protocol, repo setup | — |
| 1 | 16–22 Nov | S0, S1 | **G0:** H1a result decides whether RQ1 is the headline (κ ≥ 0.80) or label quality is (κ < 0.80) |
| 2 | 23–29 Nov | S2 taxonomy, preprocessing | Taxonomy committed |
| 3 | 30 Nov–6 Dec | S3 (RQ1) | — |
| 4–5 | 7–20 Dec | S4 (RQ2) | **G1:** target venue chosen; decision on early arXiv preprint of RQ1–RQ2 |
| 6 | 21–27 Dec | S5 AWID2 preparation | AWID2 disk solution required by this week |
| 7 | 28 Dec–3 Jan 2027 | S5 transfer, S6 rules | — |
| 8 | 4–10 Jan | S7 imbalance probe | **G2:** results frozen; writing starts |
| 9 | 11–17 Jan | S8 statistics, figures | — |
| 10–11 | 18–31 Jan | Writing | — |
| 12 | 1–7 Feb | Internal review, submission | — |

---

## 15. Deviation policy

Any departure from this protocol is logged in `docs/journal.md` with:
- the date;
- what changed;
- why;
- whether it was decided before or after seeing the affected results.

Deviations decided after seeing results are labelled as such in the paper. A major revision creates `docs/protocol_v0.4.md` with a new tag. This file stays unchanged.

---

## 16. References

Verification status refers to the author's own reading at freeze date.

1. Kolias, C., Kambourakis, G., Stavrou, A., Gritzalis, S. (2016). Intrusion detection in 802.11 networks: Empirical evaluation of threats and a public dataset. *IEEE Communications Surveys & Tutorials*, 18(1), 184–208.
2. Chatzoglou, E., Kambourakis, G., Kolias, C. (2021). Empirical evaluation of attacks against IEEE 802.11 enterprise networks: The AWID3 dataset. *IEEE Access*, 9, 34188–34205.
3. Chatzoglou, E., Kambourakis, G., Kolias, C., Smiliotopoulos, C. (2022). Pick quality over quantity: Expert feature selection and data preprocessing for 802.11 intrusion detection systems. *IEEE Access*, 10, 64761. [TBV: full read pending]
4. Yonbawi, S., et al. (2025). Transferability evaluation in Wi-Fi intrusion detection systems through machine learning and deep learning approaches. *IEEE Access*, 13, 11248–11264. [TBV]
5. Khalid, N., et al. (2025). An investigation of feature reduction, transferability, and generalization in AWID datasets for secure Wi-Fi networks. *PLOS ONE*, 20(1). doi:10.1371/journal.pone.0306747. [TBV]
6. Bhandari, S., et al. (2020). Feature selection improves tree-based classification for wireless intrusion detection. *SNTA Workshop*. [TBV]
7. Roy, U. S., Minu, M. J. (2026). Unmasking shortcut learning in IoT intrusion detection. arXiv:2609.28725. [V: abstract]
8. Ibrahim, et al. (2026). Preprint, Research Square rs-10601468. [TBV]
9. Arp, D., et al. (2022). Dos and don'ts of machine learning in computer security. *USENIX Security Symposium*.
10. Geirhos, R., et al. (2020). Shortcut learning in deep neural networks. *Nature Machine Intelligence*, 2, 665–673.
11. Kapoor, S., Narayanan, A. (2023). Leakage and the reproducibility crisis in machine-learning-based science. *Patterns*, 4(9).
12. Lundberg, S. M., Lee, S.-I. (2017). A unified approach to interpreting model predictions. *NeurIPS*.
13. Lundberg, S. M., et al. (2020). From local explanations to global understanding with explainable AI for trees. *Nature Machine Intelligence*, 2, 56–67.
14. Chawla, N. V., et al. (2002). SMOTE: Synthetic minority over-sampling technique. *JAIR*, 16, 321–357.
15. Saito, T., Rehmsmeier, M. (2015). The precision-recall plot is more informative than the ROC plot when evaluating binary classifiers on imbalanced datasets. *PLOS ONE*, 10(3).
16. IEEE Std 802.11-2020. Wireless LAN Medium Access Control (MAC) and Physical Layer (PHY) Specifications.
17. WPA3 Attacks Dataset (2026). Mendeley Data, doi:10.17632/cxx5t5nw7z.1. [TBV: licence and labelling]