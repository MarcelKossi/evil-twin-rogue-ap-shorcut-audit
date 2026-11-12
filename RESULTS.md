# Preliminary results

*Status: 13 November 2026. Stages S0-S1 of the pre-registered protocol
([`docs/protocol_v0.3.md`](docs/protocol_v0.3.md), tag `prereg-v0.3`). No
detection model has been trained yet; everything below describes the labels
of the AWID3 dataset, not the behaviour of detectors.*

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

## Next

S2 feature taxonomy (semantic / artefact / attacker-controllable / ambiguous),
then S3: do lightweight detectors learn the labelling rule?
