# Feature taxonomy: guidelines

This file defines how each AWID3 field is assigned to one family (protocol
Section 7.1). It is used by both annotators. 

## The question to ask for each field

*If a different attacker ran the same attack in a different place, with
different equipment, on another day, would this field still separate attack
frames from normal frames, and for a reason given by the 802.11 standard?*

## Families

| Code | Family | Rule | Typical fields |
|---|---|---|---|
| **S** | Semantic | The field has a meaning in the IEEE 802.11 protocol that is plausibly related to AP impersonation or its effects, and the attacker cannot set it freely without breaking the attack or the protocol. | Frame type/subtype, Protected bit, To/From DS, channel, capability bits, reason code, RSN capabilities |
| **A** | Artefact | The value depends on the recording (capture tool, capture card, clock, position in the file) or identifies a specific lab device, host or session. It would change in another capture of the same attack. | frame.number, capture timestamps, radiotap metadata, MAC and IP address values, session IDs, nonces, keys, payloads |
| **C** | Attacker-controllable | The field carries real signal in this capture, but a competent attacker sets it to whatever the legitimate AP shows. | frame length of beacons, SSID, beacon interval, country element, signal strength |
| **U** | Ambiguous / unrelated | The status depends on how the field is used (raw value vs. derived relation), or the field belongs to upper-layer traffic with no direct relation to impersonation. | raw sequence number, raw beacon TSF, rates, retry bits, TCP/UDP/DNS/HTTP/TLS fields |

Rules of thumb:

1. A raw identifier is always **A**, even when it is the attacker's address. A
   *relation* between identifiers (same SSID announced by two BSSIDs) is a
   derived feature and belongs to **S**.
2. A raw counter or clock (sequence number, TSF) is **U**; its *consistency*
   over time for one transmitter is a derived **S** feature.
3. Anything added by the receiver or the capture software is **A**.
4. Upper-layer fields are **U**, except identifiers, payloads and time or
   frame references, which are **A**.
5. When two families fit, choose the one that a reviewer could least dispute
   and write the reason in `notes`.

