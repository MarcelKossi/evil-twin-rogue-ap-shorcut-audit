"""Stage S1c - label diagnostics (exploratory, RQ1).

Follows up on S1b. For each capture it identifies the attacker device from the
labelled attack frames and checks, over the whole capture:
  - how frames involving the attacker are labelled, by frame class and by
    position relative to the filter window;
  - a simpler candidate rule: in window AND involves the attacker AND
    management or data frame;
  - the attacker's beacons (length, SSID) inside and outside the window,
    and the attacker beacons labelled Normal;
  - deauthentication / disassociation frames and their senders.
These analyses are not in protocol v0.3 and are reported as exploratory.

Usage (from the repository root):
    python scripts/03_label_diagnostics.py
Output:
    results/S1c_label_diagnostics.json
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.awid3 import NORMAL_LABEL  # noqa: E402
from src.frames import (ADDR_FIELDS, FRAME_CLASS, IP_FIELDS, add_frame_codes, agreement,  # noqa: E402
                        frame_name, has_value, iter_parquet)
from src.utils import load_paths, run_metadata, sha256_file, write_result  # noqa: E402

COLUMNS = ["frame.number", "frame.len", "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.protected",
           *ADDR_FIELDS, *IP_FIELDS, "wlan.ssid", "Label"]

CAPTURES = {
    "Rogue_AP": {"file": "awid3_rogue_ap.parquet", "window": (1_198_551, 1_973_111), "mac": None},
    "Evil_Twin": {"file": "awid3_evil_twin.parquet", "window": (1_420_038, 3_778_728), "mac": "0c:9d:92:54:fe:35"},
}


def clean(df: pd.DataFrame) -> pd.DataFrame:
    df = df.loc[df["Label"].notna()].copy()
    df = add_frame_codes(df)
    return df.loc[df["fn"].notna()]


def top(counter: Counter, n: int = 15) -> dict:
    return {" | ".join(map(str, k)) if isinstance(k, tuple) else str(k): v for k, v in counter.most_common(n)}


def attacker_identity(path: Path) -> dict:
    """First pass: addresses, SSID and lengths seen in the labelled attack frames."""
    fields = {f: Counter() for f in ["wlan.sa", "wlan.ta", "wlan.bssid", "wlan.ssid"]}
    beacon_len = Counter()
    for df in iter_parquet(path, COLUMNS):
        df = clean(df)
        att = df.loc[df["Label"] != NORMAL_LABEL]
        for f, c in fields.items():
            c.update(att[f].fillna("<missing>"))
        beacon_len.update(att.loc[att["st"] == 8, "flen"].astype(int))
    return {"fields": {f: top(c, 5) for f, c in fields.items()}, "beacon_len": top(beacon_len, 5)}


def pick_mac(identity: dict) -> str:
    """Most frequent BSSID (else transmitter) in the attack frames."""
    for f in ("wlan.bssid", "wlan.ta", "wlan.sa"):
        for value in identity["fields"][f]:
            if value != "<missing>":
                return value.lower()
    raise ValueError("No attacker address found in the attack frames.")


def diagnose(path: Path, window: tuple[int, int], mac: str, attack_beacon_lens: set[int]) -> dict:
    lo, hi = window
    by_class = Counter()
    beacons = Counter()
    beacon_ssid = Counter()
    deauth = Counter()
    alt = Counter()
    attacker_beacons_normal: list[int] = []
    attacker_beacons_attack_fn = []

    for df in iter_parquet(path, COLUMNS):
        df = clean(df)
        y = df["Label"] != NORMAL_LABEL
        inw = df["fn"].between(lo, hi)
        hit = has_value(df, ADDR_FIELDS, mac)
        fclass = df["ftype"].map(lambda v: FRAME_CLASS.get(int(v), "other") if pd.notna(v) else "missing")
        lab = y.map({True: "attack", False: "normal"})
        pos = inw.map({True: "in window", False: "outside window"})
        who = hit.map({True: "attacker", False: "other"})

        by_class.update(zip(lab, pos, who, fclass))

        b = df["st"] == 8
        beacons.update(zip(lab[b], pos[b], who[b], df.loc[b, "flen"].astype(int)))
        beacon_ssid.update(zip(lab[b], who[b], df.loc[b, "wlan.ssid"].fillna("<missing>")))

        d = df["st"].isin([10, 12])
        deauth.update(zip(lab[d], pos[d], df.loc[d, "st"].map(frame_name), df.loc[d, "wlan.sa"].fillna("<missing>"),
                          df.loc[d, "prot"].astype("Int64").astype(str)))

        rule = inw & hit & df["ftype"].isin([0, 2])
        alt["tp"] += int((y & rule).sum()); alt["fp"] += int((~y & rule).sum())
        alt["fn"] += int((y & ~rule).sum()); alt["tn"] += int((~y & ~rule).sum())

        ab = b & hit
        attacker_beacons_normal += df.loc[ab & ~y, "fn"].astype(int).tolist()
        attacker_beacons_attack_fn += df.loc[ab & y, "fn"].astype(int).tolist()
        # Beacons with the attacker's beacon length but another address (possible missed attack frames).
        same_len_other = b & ~hit & df["flen"].isin(list(attack_beacon_lens))
        beacons.update(zip(lab[same_len_other], pos[same_len_other],
                           ["other address, attacker beacon length"] * int(same_len_other.sum()),
                           df.loc[same_len_other, "flen"].astype(int)))

    normal_b = sorted(attacker_beacons_normal)
    return {
        "attacker_mac": mac,
        "frames_by_label_window_address_class": top(by_class, 40),
        "candidate_rule_window_attacker_mgmt_or_data": agreement(alt["tp"], alt["fp"], alt["fn"], alt["tn"]),
        "beacons_by_label_window_address_length": top(beacons, 30),
        "beacon_ssid_by_label_address": top(beacon_ssid, 15),
        "attacker_beacons_labelled_normal": {
            "count": len(normal_b),
            "frame_number_min": normal_b[0] if normal_b else None,
            "frame_number_max": normal_b[-1] if normal_b else None,
            "first_20": normal_b[:20],
        },
        "attacker_beacons_labelled_attack_frame_number_range":
            [min(attacker_beacons_attack_fn), max(attacker_beacons_attack_fn)] if attacker_beacons_attack_fn else None,
        "deauth_disassoc_by_label_window_type_sender_protected": top(deauth, 20),
    }


def main() -> None:
    paths = load_paths()
    output, inputs = {}, {}
    for attack, cfg in CAPTURES.items():
        path = paths["interim_dir"] / cfg["file"]
        print(f"[S1c] {attack}: pass 1 (attacker identity)", flush=True)
        identity = attacker_identity(path)
        mac = cfg["mac"] or pick_mac(identity)
        lens = {int(k) for k in identity["beacon_len"]}
        print(f"[S1c] {attack}: pass 2 (diagnostics, attacker {mac})", flush=True)
        output[attack] = {"attack_frame_identity": identity, **diagnose(path, cfg["window"], mac, lens)}
        inputs[path.name] = sha256_file(path)
        a = output[attack]["candidate_rule_window_attacker_mgmt_or_data"]
        print(f"  candidate rule: kappa={a['cohen_kappa']} tp={a['tp']:,} fp={a['fp']:,} fn={a['fn']:,}; "
              f"attacker beacons labelled Normal: {output[attack]['attacker_beacons_labelled_normal']['count']}")

    out = write_result("S1c_label_diagnostics", {"status": "exploratory", "results": output},
                       run_metadata("scripts/03_label_diagnostics.py", inputs_sha256=inputs))
    print(f"\n[S1c] Done -> {out}")


if __name__ == "__main__":
    main()
