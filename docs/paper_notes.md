# Paper notes

Working notes for writing the paper: decisions on wording, and the claims with the
evidence behind each. Numbers come from the files in `results/`; claims marked
exploratory come from analyses added after the protocol was frozen.

## Title (decided 2026-11-20)

Intrusion Detection in Wi-Fi Networks: What Do Evil Twin Detectors Learn from Public 802.11 Datasets – the Attack, the Capture, or the Labelling Rule?

- Spaced en dash (British usage, consistent with "Labelling"); in LaTeX: `--`.
- "Wi-Fi" rather than "IoT" in the title: AWID3 emulates an enterprise network and
  AWID2 a small office network, with laptops and phones only. The audited works
  (Chatzoglou et al. 2022, Khalid et al. 2025, Ahmad et al. 2025, Solpan et al. 2026)
  put "Wi-Fi" or "802.11" in their titles and mention IoT only as context.

## Opening sentence of the abstract (decided 2026-11-20)

Wi-Fi is the access layer of most IoT deployments, which makes Evil Twin attacks a
direct threat to connected devices that reconnect automatically and have no screen to
warn their users.

## Claims to make, with their evidence

| Claim | Evidence | Status |
|---|---|---|
| AWID3 labels reproduce the published Wireshark filters | `S1_filter_agreement.json` (kappa 1.000 and 0.996) | pre-registered (H1a) |
| Random splits inflate Evil_Twin scores | `S4_reliance.json` (0.898 -> 0.998) | pre-registered (H2b, score part) |
| Attribution shows where a model looks, not what it needs | `S4_reliance.json`, `S4x_field_detail.json` | pre-registered (H2a rejected) + exploratory |
| Rogue beacons differ from real ones in length and signal strength | `S4x_field_detail.json`, `S4y_beacon_fields.json` | exploratory |
| Copying length and signal from a real beacon defeats tree models trained on the 16 published features | `S4p_perturbation.json` | exploratory |
| A common cleaning rule (drop columns >99% missing) removes the one 802.11 field that separates rogue from real beacons in AWID3 (`mfpc`) | `S4y_beacon_fields.json`, `S2b_features.json` | exploratory |
| In both datasets the rogue AP announces weaker security in part or all of its beacons, and its beacons are shorter; the fields differ between datasets and the attacker can copy them | `S4y_beacon_fields.json`, `S5a_prepare.json` | exploratory |
| Detectors do not transfer between AWID3 and AWID2 (G 0.91-1.00 for models above 0.5 in-domain) | `S5_transfer.json` | pre-registered; H3a not supported (rho 0.31, CI includes 0) |
| One semantic rule transfers: unprotected frames among protected normal traffic (XGB, F-sem, AWID2 -> AWID3 data frames, 0.995) | `S5_transfer.json` | pre-registered stage, result not hypothesised |
| G is uninformative when the in-domain score is near chance (F-sem on AWID2) | `S5_transfer.json` | to state with H3b |
| Untrained rules (protocol 9.6) beat transferred models on a new network: AWID2 0.54 vs <= 0.07; R2 flags every rogue announcement in AWID3 | `S6_rules.json` | pre-registered stage; H3b rule part p = 0.002 (deviation 9) |
| R5 fires on the unprotected deauthentications labelled Normal in Rogue_AP (62,428 vs 62,455 in S1c) | `S6_rules.json`, `S1c_label_diagnostics.json` | descriptive |

## To say in the limitations

- One attack run per class, one lab per dataset; no IoT device traffic in AWID.
- Perturbation done in feature space on recorded frames, not a new capture.
- The published detectors themselves were not reproduced (planned for the journal version).
