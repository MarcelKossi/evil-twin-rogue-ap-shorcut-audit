# Attack, Capture, or Labelling Rule? Auditing What Evil Twin Detectors Learn on Public 802.11 Datasets

**Kossi Tamplare**, GD Goenka University

_Status (18 November 2026): stages S0-S4 of the pre-registered protocol and the
exploratory stage S4x done; further exploratory analyses in progress. All
results below are **preliminary**._

---

## Why this research

An **Evil Twin** is a fake Wi-Fi access point that copies the name (SSID), and
sometimes the hardware address (BSSID), of a real one, so that devices connect
to it instead. IoT devices are an easy target: they reconnect automatically to
known networks and have no screen to warn anyone.

Machine-learning detectors of Evil Twin and Rogue AP attacks trained on the
public AWID datasets report 98-100% detection. This project asks **what these
detectors actually learn**:

- **the attack itself**, that is, real 802.11 evidence that a fake AP is present;
- **capture artefacts**: frame counters, timestamps and addresses that belong
  to one recording in one lab;
- **the labelling rule**: AWID3 publishes the Wireshark filter of each attack,
  based on frame-number ranges, frame lengths and the attacker's address;
- or **fields the attacker sets**, such as beacon length or transmit power.

If a detector relies on anything but the first, its 99% says little about a
real network.

## The idea

```
AWID3 capture ──> label provenance: do the published filters reproduce the labels?      (RQ1)
              ──> detectors trained on 4 field sets:
                    all fields | no artefacts | 802.11 semantics only | 16 fields from the literature
                  └─> which fields carry the decision? attribution + ablation           (RQ2)
              ──> transfer AWID3 <-> AWID2                                              (RQ3)
              ──> does SMOTE improve detection, or only the reported numbers?           (RQ4)
```

Every one of the 253 fields of the capture is classified as **S** (802.11
semantics), **A** (capture artefact), **C** (controllable by the attacker) or
**U** (ambiguous or outside 802.11). The hypotheses, thresholds and analysis
plan were frozen before any experiment in
[`docs/protocol_v0.3.md`](docs/protocol_v0.3.md) (git tag `prereg-v0.3`).
Analyses added afterwards are labelled exploratory.

## What was done

1. **Inventory** of the AWID3 Rogue_AP and Evil_Twin captures (5.7 million frames).
2. **Label provenance**: agreement between the published filters and the labels.
3. **Feature taxonomy**: 253 fields classified S/A/C/U by three blind annotators
   (instances of a large language model configured as expert annotators),
   majority vote, then checked and validated by me.
4. **Blocked evaluation**: the attack period is cut into 5 consecutive blocks,
   each held out in turn with a 10,000-frame gap, instead of the random
   frame-level split used in most published work.
5. **Detectors**: logistic regression, decision tree, random forest, XGBoost and
   a small neural network, 5 seeds each, on the 4 field sets.
6. **Reliance**: attribution by feature family (SHAP and path contributions),
   permutation importance, and retraining without each family.

## What we found so far

**1. The labels are the published filters.** The filters reproduce the labels
with Cohen's kappa = 1.000 (Rogue_AP) and 0.996 (Evil_Twin). On Rogue_AP, every
attack frame is a 263-byte beacon of a fake AP that clones the real one; real
beacons are 342-343 bytes. On Evil_Twin, 143 fake beacons are labelled as normal
traffic, and the detectors flag them anyway.

**2. Detectors do not need the labelling rule, nor the artefacts, to score well.**
Removing the filter fields, or all capture artefacts, barely changes the scores
of the strongest models. The information is present in several redundant fields.

**3. With 802.11 evidence only, a fake beacon cannot be told from a real one.**

| PR-AUC, blocked evaluation, mean of 5 models | Rogue_AP | Evil_Twin |
|---|---|---|
| All fields | 0.99 | 0.92 |
| Without capture artefacts | 0.95 | 0.91 |
| 802.11 semantic fields only | 0.43 | 0.77 |

On Evil_Twin, the semantic fields still detect the victims' data traffic (the
fake AP is open, so their data is not encrypted), but not the fake beacons.

**4. What separates fake beacons from real ones is length and signal strength**
(exploratory). Beacon length is set by the attacker's software; received signal
strength depends on the attacker's transmit power and position, and on where
the sensor stands. Both describe this particular recording rather than Evil Twins
in general.

**5. Random splits inflate the scores.** On Evil_Twin, PR-AUC rises from 0.90
(blocked) to 0.998 (random split).

**6. Attribution shows where a model looks, not what it depends on.** Most of
the attribution goes to capture artefacts, yet removing them costs less than
10%. On a sample made mostly of normal frames, attribution rewards the fields
that sort the bulk of the traffic (frame type, addresses), not the field that
settles the decision: restricted to beacons, the share of beacon length rises
from 0.4% to 53% (exploratory).

### Hypotheses: outcome so far

| | Hypothesis | Outcome |
|---|---|---|
| H1a | The published filters reproduce the labels | **Supported** for both attacks |
| H1b | A depth-3 tree on the filter fields matches the best model | **Supported** for Rogue_AP, **not** for Evil_Twin |
| H1c | Removing the filter fields costs >= 20% | **Not supported** (other fields carry the same information) |
| H2a | Detectors rely on artefacts | **Not supported**: high attribution, but small ablation cost |
| H2b | Random splits inflate scores and artefact reliance | **Partly**: scores inflated on Evil_Twin, artefact share not |
| H2c | The ranking of field families is stable | **Supported** |
| H3a-b, H4 | Transfer, rule baseline, SMOTE | Not yet tested |

Multiple-testing correction (Holm) is applied at the end, across the
confirmatory family. Details and every number: [`RESULTS.md`](RESULTS.md).

## What it means, for now

High scores on AWID3 Evil Twin and Rogue AP can be reached without detecting the
attack: from the labelling rule, from capture artefacts, or from details the
attacker controls. The next experiments test whether a slightly more careful
attacker would go unnoticed.

## Limitations

- **One attack run per class** in AWID3, recorded in one lab.
- **Taxonomy**: the S/A/C/U classes are a judgement; some fields are both a lab
  artefact and an attacker's choice (for example the BSSID).
- **Attribution methods**: path contributions for trees are not exact Shapley
  values (deviation 6 in the journal).
- **Preliminary numbers**: S3 will be re-run with corrected folds.

## Next steps

- **Perturbation test** (exploratory): give the trained models the real fake
  beacons with the legitimate length, the legitimate signal strength, or both,
  and measure how much detection drops.
- **Reproduction** of published AWID3 pipelines (Ahmad et al. 2025, Solpan et al. 2026).
- **Transfer** AWID3 <-> AWID2 (S5), rule baseline (S6), SMOTE probe (S7),
  statistics and paper (S8).

## Progress

| Stage | Question | Status |
|---|---|---|
| S0 | Data inventory | Done |
| S1 | H1a - label provenance | Done |
| S2 | Feature taxonomy | Done |
| S2b | Feature matrices | Done |
| S3 | H1b, H1c - labelling rule | Done; re-run with corrected folds pending |
| S4 | H2a-c - reliance on artefacts | Done |
| S4x | Which single fields decide (exploratory) | Done |
| - | Perturbation test (exploratory) | Planned |
| - | Reproduction of published pipelines (exploratory) | Planned |
| S5 | H3a - transfer AWID3 <-> AWID2 | Planned |
| S6 | H3b - rule baseline | Planned |
| S7 | H4 - imbalance probe | Planned |
| S8 | Statistics, figures, paper | Planned |

## Repository guide

| Path | Content |
|---|---|
| `docs/` | Protocol, research journal (every decision and deviation), feature taxonomy |
| `scripts/` | One script per stage |
| `src/` | Shared code |
| `configs/paths.yaml` | Data locations, relative to the repository root |
| `results/` | Machine-generated results behind every number (git commit, package versions, input SHA-256) |
| `figures/` | Figures |
| [`RESULTS.md`](RESULTS.md) | Results in detail |
| [`RUNBOOK.md`](RUNBOOK.md) | Every command, in order |

Everything runs on a laptop CPU (8 GB of RAM).

## Data

The datasets are not redistributed. They can be requested from the AWID project
(University of the Aegean): AWID3 (CSV release) and AWID2 (reduced attack-level
subsets AWID-ATK-R-Trn / AWID-ATK-R-Tst). Place them under `data/` as listed in
`configs/paths.yaml`.

## References

- Chatzoglou, E., Kambourakis, G., Kolias, C. (2021). Empirical evaluation of attacks against IEEE 802.11 enterprise networks: The AWID3 dataset. *IEEE Access*, 9, 34188-34205.
- Kolias, C., Kambourakis, G., Stavrou, A., Gritzalis, S. (2016). Intrusion detection in 802.11 networks: Empirical evaluation of threats and a public dataset. *IEEE Communications Surveys & Tutorials*, 18(1), 184-208.
- Arp, D., et al. (2022). Dos and don'ts of machine learning in computer security. *USENIX Security Symposium*.
- Geirhos, R., et al. (2020). Shortcut learning in deep neural networks. *Nature Machine Intelligence*, 2, 665-673.
- Kapoor, S., Narayanan, A. (2023). Leakage and the reproducibility crisis in machine-learning-based science. *Patterns*, 4(9).

Full list: Section 16 of the protocol.
