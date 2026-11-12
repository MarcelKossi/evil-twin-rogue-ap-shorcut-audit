# Evil Twin shortcut audit

Code and protocol for the study *Attack, Capture, or Labelling Rule? Auditing
What Evil Twin Detectors Learn on Public 802.11 Datasets*.

The study checks what lightweight Evil Twin and Rogue AP detectors trained on
the public AWID datasets actually rely on: the attack itself, capture
artefacts (frame counters, timestamps, lab identifiers) or the rule used to
label the data. The hypotheses, thresholds and analysis plan are fixed in
[`docs/protocol_v0.3.md`](docs/protocol_v0.3.md) before any experiment.

## Layout

| Path | Content |
|---|---|
| `docs/` | Protocol, run journal, feature taxonomy |
| `scripts/` | One script per stage of the protocol (S0-S8) |
| `src/` | Shared code |
| `configs/paths.yaml` | Data locations, relative to the repository root |
| `results/` | Machine-generated results (JSON) behind every reported number |
| `figures/` | Figures for the paper |

## Data

The datasets are not redistributed. They can be requested from the AWID
project (University of the Aegean): AWID3 (CSV release) and AWID2 (reduced
attack-level subsets AWID-ATK-R-Trn / AWID-ATK-R-Tst). Place them under
`data/` as listed in `configs/paths.yaml`.

## Reproducing

Every step, in order, is in [`RUNBOOK.md`](RUNBOOK.md).
