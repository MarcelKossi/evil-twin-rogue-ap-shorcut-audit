# Preliminary results

*Status: 20 November 2026. Stages S0-S4 of the pre-registered protocol
([`docs/protocol_v0.3.md`](docs/protocol_v0.3.md), tag `prereg-v0.3`), plus
the exploratory stage S4x and the perturbation test. The first sections
describe the labels of AWID3; the S3, S4, S4x and perturbation sections
describe detectors trained on them.*

## Question

Public Evil Twin and Rogue AP detectors trained on AWID3 report near-perfect
scores. Before asking what these detectors learn, I checked what the labels
themselves encode. The AWID3 website publishes one Wireshark display filter
per attack; I measured how well these filters reproduce the labels.

## Main result: the labels follow the published filters

| | Rogue_AP | Evil_Twin |
|---|---|---|
| Frames in the capture | 1,973,185 | 3,778,679 (27 malformed rows excluded) |
| Frames labelled as attack | 1,310 | 104,827 |
| Agreement filter vs labels (Cohen's kappa) | **1.000** | **0.996** |
| Filter precision / recall | 1.000 / 1.000 | 0.998 / 0.994 |
| Labelled attack frames outside the filter's frame.number window | 0 | 0 |

Source: [`results/S1_filter_agreement.json`](results/S1_filter_agreement.json).
The pre-registered threshold for H1a was kappa >= 0.80.

## What the labels contain

**Rogue_AP** ([`figures/fig1_rogue_ap_capture.png`](figures/fig1_rogue_ap_capture.png))

- The rogue AP clones the legitimate AP: same SSID (`ASUS_5G`), same BSSID
  (`0c:9d:92:54:fe:34`).
- Every one of the 1,310 attack frames is a beacon of exactly **263 bytes**;
  the legitimate beacons are 342-343 bytes. No 263-byte beacon exists outside
  the attack window, so the label is recovered by beacon length alone.
- Beacon length is set by the attacker's software configuration: it is
  a fingerprint of this particular attack run, not of rogue APs in general.
- 62,455 unprotected deauthentication frames carrying the cloned address
  appear inside the attack window (1 outside). They start with the rogue
  beacons and none appear before; all are labelled Normal.

**Evil_Twin** ([`figures/fig2_evil_twin_capture.png`](figures/fig2_evil_twin_capture.png))

- The rogue AP uses the legitimate SSID with BSSID `0c:9d:92:54:fe:35`.
- **Every** labelled attack frame involves this MAC address; 95% also involve
  the IP `192.168.30.1`.
- The class is mostly **post-association data traffic** of victims connected
  to the rogue AP: QoS Data 95.9%, beacons 3.4%, deauthentication and
  disassociation 27 frames in total.
- A rule using only the time window, the rogue MAC address and the frame
  class reproduces the labels with kappa = 0.994.
- The rogue AP runs two beacon configurations in sequence (241 bytes, then
  150 bytes); legitimate beacons are 342-343 bytes.
- 208 rogue beacons (5.5%) are labelled Normal, in two contiguous blocks: 65
  just before the labelled attack period (the rogue AP is active about 69,000
  frames earlier) and 143 around frames 2.85-2.95 M.

Sources: [`results/S1c_label_diagnostics.json`](results/S1c_label_diagnostics.json)
(exploratory, not in the pre-registered plan),
[`results/S1d_figure_data.json`](results/S1d_figure_data.json).

## What this means, and what it does not

- On AWID3, the ground truth for Evil Twin and Rogue AP is a near-deterministic
  function of a few fields: a frame length, a position in the capture file
  (`frame.number`) and the attacker's addresses.
- A detector can therefore reach near-perfect scores on these classes by
  learning one attack run's fingerprint. Whether published detectors actually
  do this is the next step (H1b, H1c and RQ2 of the protocol).
- I do not claim that the AWID3 labels are wrong. Labelling by filter is a
  legitimate design choice; the point is what it implies for evaluation.
  Whether the labels were produced by the filters or the filters were written
  to match the labels cannot be told from the data.

## Reproducing

Data: AWID3 CSV release (University of the Aegean). Commands in
[`RUNBOOK.md`](RUNBOOK.md), stages S0-S1d. Every result file records the git
commit, the input SHA-256 and the run time.

## Do detectors learn the rule? (S3, pre-registered H1b and H1c)

Blocked evaluation: the attack period is cut into 5 consecutive blocks, each
held out in turn with a 10,000-frame gap; 5 model families, 5 seeds. Results
of the re-run with the folds corrected after the code review (purge around the
clean period, validation purged from the test block).

| | Rogue_AP | Evil_Twin |
|---|---|---|
| Depth-3 tree on the filter fields (mean PR-AUC) | 0.999 | 0.874 |
| Best model on all fields | 1.000 (RF) | 0.959 (RF) |
| H1b: depth-3 tree >= 95% of best | **supported** (99.9%) | not supported (91%) |
| H1c: removing the filter fields costs >= 20% for >= 3/5 models | not supported (1/5) | not supported (2/5) |

- On Rogue_AP, three questions on the fields of the labelling rule match the
  best detector.
- Removing those fields does not stop the strongest models (RF, XGB) from
  detecting either attack: the information is also present in other fields.
  Which ones, and whether they are artefacts or real protocol evidence, is the
  question of S4.
- On Evil_Twin, removing the filter fields multiplies the false-positive rate
  on clean traffic: XGB 0.018% -> 0.81%, RF 0.014% -> 0.31%, decision tree
  0.022% -> 20%.
- The first run, before the fold corrections, gave the same conclusions for
  H1b and H1c (`results/S3_label_rule_v1.json`, `results/S3_runs_v1.csv`).
  The scores on all fields now equal those of S4, which uses the same folds.
- The filter fields include `frame.number` but not the other fields that
  encode the position in the capture (relative and absolute times, capture
  timestamps), which stay in the "without filter fields" models.

Source: [`results/S3_label_rule.json`](results/S3_label_rule.json),
[`results/S3_runs.csv`](results/S3_runs.csv).

## Do detectors rely on capture artefacts? (S4, pre-registered H2a-H2c)

Five model families (LR, DT, RF, XGB, MLP), 5 seeds, the blocked protocol of
S3 and, for H2b, a random 80/20 split of the attack window. Four field sets:

- **F-all**: every usable field;
- **F-noA**: without capture artefacts (family A);
- **F-sem**: 802.11 semantic fields only (family S);
- **F-chatz**: the 16 expert features of Chatzoglou et al. (2022), as reused
  in later work.

Mean PR-AUC, blocked protocol:

| | Rogue_AP | Evil_Twin |
|---|---|---|
| F-all (RF / XGB) | 1.000 / 1.000 | 0.958 / 0.955 |
| F-noA (RF / XGB) | 1.000 / 1.000 | 0.969 / 0.960 |
| F-chatz (RF / XGB) | 1.000 / 1.000 | 0.918 / 0.984 |
| F-sem (RF / XGB) | 0.436 / 0.436 | 0.786 / 0.785 |

| Hypothesis | Rogue_AP | Evil_Twin |
|---|---|---|
| H2a: median ARS >= 0.25 **and** removing A costs >= 10% for >= 3/5 models | not supported (ARS 0.67; 1/5) | not supported (ARS 0.69; 0/5) |
| H2b: random split gives higher PR-AUC **and** higher ARS | not supported (PR-AUC 0.844 vs 0.844) | not supported as a whole: PR-AUC 0.998 vs 0.898 (p = 8.5e-16), ARS not higher (p = 0.20) |
| H2c: ranking of families stable across seeds (tau >= 0.6) | supported (0.82-1.00) | supported (0.83-1.00) |

- **The models use the artefacts, but do not need them.** Most of the
  attribution goes to family A, yet RF and XGB reach the same PR-AUC without
  it.
- **With 802.11 semantics only, a rogue beacon cannot be told from a real
  one.** On Rogue_AP, F-sem gives 0.32-0.48 in every block, almost the same for
  all models. On Evil_Twin, F-sem reaches 0.995-1.000 on blocks 0-2, which are
  mostly the victims' data frames, and drops to 0.40 and 0.52 on blocks 3-4,
  which are mostly beacons.
- F-sem also costs false alarms on clean traffic: 0.08-0.22% (Evil_Twin) and
  0.15-0.20% (Rogue_AP), against at most 0.03% and 0% with F-all.
- **Random splits inflate the Evil_Twin scores**, from 0.898 to 0.998.
- p-values are raw; Holm correction across the confirmatory family comes at
  the end. Permutation importance is computed for seed 0 only and is
  descriptive. The ARS part of H2b was tested on F-all only by the S4 script;
  adding F-chatz gives the same conclusion (journal, deviation 8).

Sources: [`results/S4_reliance.json`](results/S4_reliance.json),
[`results/S4_runs.csv`](results/S4_runs.csv).

## Which fields decide? (S4x, exploratory)

S4 records attribution by feature family only. S4x refits the decision tree
and XGBoost (seed 0, S4 settings) and keeps the attribution of every field,
first on the usual evaluation sample, then on beacon frames only.

**What separates a rogue beacon from a real one**, on the beacons of the
attack window:

| Field (family) | Rogue_AP: rogue / legitimate | Separates them? |
|---|---|---|
| `wlan.fc.type` (S) | management / management | no |
| `wlan.duration` (U) | 0 / 0 | no |
| `frame.len` (C) | 263 / 342-343 bytes | **yes** |
| received signal strength (C) | weaker / stronger | **almost** |

On Evil_Twin beacons, signal strength separates them as well. Frame length
is set by the attacker's software. Signal strength depends on the attacker's
transmit power and position, and on where the sensor stands.

**Why attribution missed it.** On the usual evaluation sample, mostly normal
frames, `frame.len` received 0.4% of the decision tree's attribution and
`wlan.fc.type` 84%. Restricted to beacons, `frame.len` rises to 53%. The
attribution rewards the fields that sort the bulk of the traffic, such as
frame type and addresses, not the field that settles the decision between
two look-alike frames. This is why a high artefact share (H2a) did not mean
that the models depended on artefacts.

**Evil_Twin data frames.** Without artefacts, the models rely on
`wlan.fc.protected` and on the presence of an IP header (`ip.ttl`): the rogue
AP is open, so the victims' data is not encrypted. This is real evidence for
this attack setup, but it would disappear with a WPA2-protected Evil Twin.

**A labelling error the detectors catch.** On Evil_Twin beacons, every model
scores 1.000 in every block except block 3 (0.805). Block 3 holds 590 rogue
beacons labelled attack and the 143 rogue beacons labelled Normal found in
S1c: 590 / (590 + 143) = 0.805. The models rank the mislabelled beacons with
the attack frames, so the drop comes from the labels, not from the detectors.
The perturbation test confirms it (below).

Sources: [`results/S4x_field_detail.json`](results/S4x_field_detail.json),
[`results/S4x_field_runs.csv`](results/S4x_field_runs.csv),
[`results/S4x_beacon_runs.csv`](results/S4x_beacon_runs.csv).

## Would a careful attacker go unnoticed? (perturbation test, exploratory)

The models of the S4 blocked protocol (same settings, same training rows, same
alert threshold; 5 seeds) receive the real rogue beacons of each held-out
block, changed in one of three ways, with values copied from real legitimate
beacons; nothing is retrained:

- **L**: the legitimate length (and the airtime that follows from it);
- **P**: the legitimate received signal strength;
- **L+P**: both.

The design was fixed in the journal before any result.

Share of rogue beacons still flagged, RF / XGB / DT:

| | Unmodified | L | P | L+P |
|---|---|---|---|---|
| Rogue_AP, F-noA | 99 / 97 / 100% | **0 / 0 / 0%** | 48 / 57 / 100% | **0 / 0 / 0%** |
| Rogue_AP, F-chatz | 99 / 97 / 100% | **0 / 0 / 0%** | 55 / 33 / 100% | **0 / 0 / 0%** |
| Evil_Twin, F-noA | 99 / 96 / 96% | 29 / 85 / 79% | **0 / 18 / 0%** | **0 / 0 / 0%** |
| Evil_Twin, F-chatz | 98 / 71 / 39% | 19 / 69 / 39% | **0 / 18 / 0%** | **0 / 0 / 0%** |

- **Copying two values from a real beacon is enough.** On Rogue_AP the length
  alone does it; on Evil_Twin, mostly the signal strength. With both, the tree
  models trained on the 16 published features or on all non-artefact fields
  flag no rogue beacon.
- They also stop ranking rogue beacons above real ones: beacon PR-AUC drops
  from 1.00 to 0.44-0.51, where 0.44 is what a detector that cannot tell them
  apart scores.
- **Evil_Twin with all fields** (F-all): DT and XGB keep flagging 81% and 73%
  of the rogue beacons in every variant. They recognise the rogue BSSID, which
  the test does not change and which the Rogue_AP attacker shows can be cloned.
- On Evil_Twin, the test covers the impersonation only: 96% of the attack
  frames are the victims' data frames, which stay detected.
- **The 143 rogue beacons labelled Normal** are flagged at 100% by 11 of the
  15 model and field-set pairs.
- Logistic regression is left out: on Rogue_AP beacons it flags 50-100% of the
  legitimate ones. Results vary little across seeds (DT and XGB identical, RF
  standard deviation at most 0.09).

Sources: [`results/S4p_perturbation.json`](results/S4p_perturbation.json),
[`results/S4p_perturbation_runs.csv`](results/S4p_perturbation_runs.csv).

## Next

- Transfer to AWID2 (S5), rule baseline (S6) and SMOTE probe (S7).
- After the preprint: reproduction of published AWID3 pipelines (Ahmad et al.
  2025, then Solpan et al. 2026).
