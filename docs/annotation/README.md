# Feature taxonomy annotation

The family of each AWID3 field (protocol Section 7.1) was set as follows.

1. Guidelines: `guidelines_as_given.md` defines the four families (S, A, C, U)
   and the question to ask for each field.
2. Three annotators, each a separate large language model instance configured
   as an IEEE 802.11 security expert, classified all 253 fields independently.
   Each received only the guidelines and the field list (`fields.txt`), with
   no information on the study, the data or any other annotation. Prompt below.
   - Annotator A: Claude Opus (Anthropic), run on 2026-11-15
   - Annotator B: Claude Sonnet (Anthropic), run on 2026-11-15
   - Annotator C: Claude Haiku (Anthropic), run on 2026-11-15
3. Final family = majority vote of the three annotators (every field had a
   majority of at least two). I went through the result, mainly the fields
   where the annotators disagreed, and kept it. Changes I make by hand (a
   different family, with the reason, or my own wording of a justification)
   go in `manual_overrides.csv` and are applied by the script.
4. `scripts/05_taxonomy_agreement.py` computes the majority and the agreement
   statistics (`results/S2_taxonomy_agreement.json`) and writes
   `docs/taxonomy.csv`.

## Prompt given to each annotator

> You are an independent expert in IEEE 802.11 (Wi-Fi) security, wireless
> capture tooling (Wireshark/tshark, radiotap) and intrusion detection. You are
> asked to annotate fields for a study on detecting Evil Twin / rogue access
> point attacks from 802.11 frames. You have no other context about the study
> and must not look for any.
>
> Inputs (read only these two files): the annotation rules (four families S,
> A, C, U) and 253 field names exported by tshark from monitor-mode captures.
>
> Task: assign every field to exactly one family (S, A, C or U) following the
> guidelines, with a one-sentence justification grounded in the field's
> meaning (IEEE 802.11-2020, radiotap, or the upper-layer protocol). You may
> consult public documentation (e.g. the Wireshark display filter reference)
> to understand a field. Work field by field; do not assign whole prefixes
> mechanically without checking that each field fits. Do not search for the
> study, its dataset results or prior annotations.
>
> Output: a CSV with header `field,family,justification,confidence`
> (confidence = high/medium/low) containing all 253 fields in the input order.
