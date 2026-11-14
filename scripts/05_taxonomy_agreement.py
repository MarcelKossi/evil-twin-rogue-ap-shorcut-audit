"""Stage S2 - final feature taxonomy and inter-annotator agreement.

Reads the three independent annotations in docs/annotation/, sets each
field's family to the majority vote, applies the author's documented
decisions in docs/annotation/author_overrides.csv (a different family and/or
the author's own justification wording), and reports agreement (pairwise Cohen's
kappa, Fleiss' kappa) on all fields, on 802.11/radio fields, and on the fields
not cited as examples in the guidelines.

Usage (from the repository root):
    python scripts/05_taxonomy_agreement.py
Output:
    docs/taxonomy.csv (family, justification and notes columns rewritten)
    results/S2_taxonomy_agreement.json
"""

from __future__ import annotations

import itertools
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.utils import ROOT, run_metadata, sha256_file, write_result  # noqa: E402

ANNOTATORS = ["A", "B", "C"]
FAMILIES = ["S", "A", "C", "U"]
LINK_PREFIXES = {"frame", "radiotap", "wlan", "wlan_radio", "wlan_rsna_eapol", "eapol", "llc", "ip"}
# Fields cited as examples in the guidelines (agreement on them is partly given).
NAMED_IN_GUIDELINES = {
    "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.protected", "wlan.fc.ds", "radiotap.channel.freq",
    "wlan_radio.channel", "wlan_radio.frequency", "wlan.fixed.capabilities.ess", "wlan.fixed.capabilities.ibss",
    "wlan.fixed.reason_code", "wlan.rsn.capabilities.mfpc", "frame.number", "frame.time", "frame.time_epoch",
    "frame.time_relative", "radiotap.mactime", "radiotap.timestamp.ts", "wlan.sa", "wlan.da", "wlan.ta",
    "wlan.ra", "wlan.bssid", "ip.src", "ip.dst", "frame.len", "wlan.ssid", "wlan.fixed.beacon",
    "wlan.country_info.code", "wlan.country_info.fnm", "radiotap.dbm_antsignal", "wlan_radio.signal_dbm",
    "wlan.seq", "wlan.fixed.timestamp", "radiotap.datarate", "wlan_radio.data_rate", "wlan.fc.retry",
}


def cohen_kappa(a: pd.Series, b: pd.Series) -> float:
    po = (a == b).mean()
    pe = sum((a == c).mean() * (b == c).mean() for c in FAMILIES)
    return float(round((po - pe) / (1 - pe), 3))


def fleiss_kappa(labels: pd.DataFrame) -> float:
    n = labels.shape[1]
    counts = labels.apply(lambda row: pd.Series(Counter(row)), axis=1).reindex(columns=FAMILIES).fillna(0)
    p_i = ((counts**2).sum(axis=1) - n) / (n * (n - 1))
    p_j = counts.sum() / counts.values.sum()
    pe = (p_j**2).sum()
    return float(round((p_i.mean() - pe) / (1 - pe), 3))


def agreement(labels: pd.DataFrame) -> dict:
    return {
        "n_fields": len(labels),
        "fleiss_kappa": fleiss_kappa(labels),
        "cohen_kappa": {f"{a}-{b}": cohen_kappa(labels[a], labels[b])
                        for a, b in itertools.combinations(ANNOTATORS, 2)},
        "percent_unanimous": float(round((labels.nunique(axis=1) == 1).mean() * 100, 1)),
    }


def main() -> None:
    ann_dir = ROOT / "docs" / "annotation"
    ann = {k: pd.read_csv(ann_dir / f"annotator_{k}.csv").set_index("field") for k in ANNOTATORS}
    fields = list(ann["A"].index)
    for k in ANNOTATORS:
        if set(ann[k].index) != set(fields):
            sys.exit(f"Annotator {k} does not cover the same fields.")
    labels = pd.DataFrame({k: ann[k].loc[fields, "family"].str.strip().str.upper() for k in ANNOTATORS})

    majority, justification, notes = {}, {}, {}
    for f in fields:
        votes = Counter(labels.loc[f])
        family, n = votes.most_common(1)[0]
        if n < 2:
            sys.exit(f"No majority for {f}: {dict(votes)}")
        majority[f] = family
        first = next(k for k in ANNOTATORS if labels.loc[f, k] == family)
        justification[f] = ann[first].loc[f, "justification"]
        notes[f] = "" if n == 3 else "votes " + " ".join(f"{k}:{labels.loc[f, k]}" for k in ANNOTATORS)

    contested = {f: notes[f] for f in fields if notes[f]}  # annotator disagreements only
    overrides_path = ann_dir / "author_overrides.csv"
    overrides = {}
    if overrides_path.exists():
        ov = pd.read_csv(overrides_path, dtype=str, keep_default_na=False)
        for _, row in ov.iterrows():
            f, fam = row["field"].strip(), row["family"].strip().upper()
            if f not in majority or fam not in FAMILIES:
                sys.exit(f"Invalid author decision: {row.to_dict()}")
            text = row.get("justification", "").strip()
            overrides[f] = {"majority": majority[f], "author": fam, "reason": row["reason"],
                            "justification": text or None}
            if fam != majority[f]:
                notes[f] = (notes[f] + "; " if notes[f] else "") + f"author decision {majority[f]}->{fam}: {row['reason']}"
                majority[f] = fam
            if text:
                justification[f] = text

    link = [f for f in fields if f.split(".")[0] in LINK_PREFIXES]
    subsets = {
        "all_fields": fields,
        "not_named_in_guidelines": [f for f in fields if f not in NAMED_IN_GUIDELINES],
        "link_layer": link,
        "link_layer_not_named": [f for f in link if f not in NAMED_IN_GUIDELINES],
    }
    stats = {name: agreement(labels.loc[sub]) for name, sub in subsets.items()}

    tax_path = ROOT / "docs" / "taxonomy.csv"
    tax = pd.read_csv(tax_path, dtype=str, keep_default_na=False).set_index("field")
    tax = tax.reindex(fields)
    tax["family"] = pd.Series(majority)
    tax["justification"] = pd.Series(justification)
    tax["notes"] = pd.Series(notes)
    tax.reset_index().to_csv(tax_path, index=False)

    counts = Counter(majority.values())
    inputs = {f"annotator_{k}.csv": sha256_file(ann_dir / f"annotator_{k}.csv") for k in ANNOTATORS}
    out = write_result("S2_taxonomy_agreement",
                       {"final_family_counts": {c: counts.get(c, 0) for c in FAMILIES},
                        "agreement": stats, "fields_not_unanimous": contested,
                        "author_overrides": overrides},
                       run_metadata("scripts/05_taxonomy_agreement.py", inputs_sha256=inputs))
    print(f"[S2] Final families: {dict(counts)}; not unanimous: {len(contested)}; author decisions: {len(overrides)}")
    for name, s in stats.items():
        print(f"  {name:<24} n={s['n_fields']:>3} Fleiss={s['fleiss_kappa']} unanimous={s['percent_unanimous']}% "
              f"pairs={s['cohen_kappa']}")
    print(f"[S2] Done -> {tax_path} and {out}")


if __name__ == "__main__":
    main()
