"""Stage S1d - figures of the label structure of the AWID3 captures.

Two descriptive figures built from the Parquet data (no model involved):
  fig1_rogue_ap_capture.png   beacons of ASUS_5G by length and position, and the
                              unprotected deauthentication frames, Rogue_AP capture
  fig2_evil_twin_capture.png  labelled Evil_Twin frames by position and type, and
                              beacons of ASUS_5G by length and origin, Evil_Twin capture
The dashed lines are the frame.number bounds of the published filters.

Usage (from the repository root):
    python scripts/04_figures_labels.py
Output:
    figures/fig1_rogue_ap_capture.png, figures/fig2_evil_twin_capture.png
    results/S1d_figure_data.json
"""

from __future__ import annotations

import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.awid3 import NORMAL_LABEL  # noqa: E402
from src.frames import ADDR_FIELDS, add_frame_codes, has_value, iter_parquet  # noqa: E402
from src.utils import ROOT, load_paths, run_metadata, sha256_file, write_result  # noqa: E402

COLUMNS = ["frame.number", "frame.len", "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.protected",
           *ADDR_FIELDS, "Label"]
ROGUE_WINDOW = (1_198_551, 1_973_111)
ET_WINDOW = (1_420_038, 3_778_728)
ET_ROGUE_MAC = "0c:9d:92:54:fe:35"

# Chart colours (validated categorical slots 1-3) and neutral inks.
C_NORMAL, C_ATTACK, C_MISSED = "#2a78d6", "#eb6834", "#1baf7a"
INK, INK_2, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": GRID, "axes.labelcolor": INK_2, "xtick.color": INK_2, "ytick.color": INK_2,
    "text.color": INK, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
    "axes.spines.top": False, "axes.spines.right": False, "font.size": 9,
    "axes.titlesize": 10, "axes.titleweight": "bold", "legend.frameon": False,
})


def collect(path: Path, attack: str) -> dict[str, pd.DataFrame]:
    beacons, deauth, attack_frames = [], [], []
    for df in iter_parquet(path, COLUMNS):
        df = add_frame_codes(df.loc[df["Label"].notna()].copy())
        df = df.loc[df["fn"].notna()]
        y = df["Label"] != NORMAL_LABEL
        b = df["st"] == 8
        part = df.loc[b, ["fn", "flen"]].assign(attack=y[b])
        if attack == "Evil_Twin":
            part["rogue_mac"] = has_value(df.loc[b], ADDR_FIELDS, ET_ROGUE_MAC)
        beacons.append(part)
        d = (df["st"] == 12) & (df["prot"] == 0)
        deauth.append(df.loc[d, ["fn"]].assign(attack=y[d]))
        attack_frames.append(df.loc[y, ["fn", "st"]])
    return {"beacons": pd.concat(beacons), "deauth": pd.concat(deauth), "attack": pd.concat(attack_frames)}


def window_lines(ax, window):
    for x in window:
        ax.axvline(x / 1e6, color=INK_2, linestyle=(0, (4, 3)), linewidth=1)


def fig_rogue(data: dict, out: Path) -> dict:
    b, d = data["beacons"], data["deauth"]
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(7.2, 5.2), sharex=True,
                                   gridspec_kw={"height_ratios": [3, 2], "hspace": 0.25})
    norm, att = b.loc[~b["attack"]], b.loc[b["attack"]]
    ax1.scatter(norm["fn"] / 1e6, norm["flen"], s=9, color=C_NORMAL, marker="o", linewidths=0,
                label=f"Beacons labelled Normal (n={len(norm):,})")
    ax1.scatter(att["fn"] / 1e6, att["flen"], s=12, color=C_ATTACK, marker="^", linewidths=0,
                label=f"Beacons labelled RogueAP (n={len(att):,})")
    window_lines(ax1, ROGUE_WINDOW)
    ax1.set_ylabel("Beacon length (bytes)")
    ax1.set_title("Rogue_AP capture: every beacon has SSID ASUS_5G and BSSID 0c:9d:92:54:fe:34", loc="left")
    ax1.legend(loc="center left", fontsize=8)
    ax1.set_ylim(200, 400)

    bins = np.arange(0, b["fn"].max() + 20_000, 20_000)
    counts, edges = np.histogram(d["fn"], bins=bins)
    ax2.bar(edges[:-1] / 1e6, counts, width=0.018, align="edge", color=C_NORMAL, linewidth=0)
    window_lines(ax2, ROGUE_WINDOW)
    ax2.set_ylabel("Unprotected deauth\nper 20k frames")
    ax2.set_xlabel("frame.number (millions)   - - -  bounds of the published Rogue_AP filter")
    ax2.set_title(f"Unprotected deauthentication frames, all labelled Normal (n={len(d):,})", loc="left")
    fig.savefig(out, dpi=200, bbox_inches="tight")
    plt.close(fig)
    inw = d["fn"].between(*ROGUE_WINDOW)
    return {"beacons_normal": len(norm), "beacons_attack": len(att),
            "beacon_lengths_attack": sorted(att["flen"].astype(int).unique().tolist()),
            "beacon_lengths_normal": sorted(norm["flen"].astype(int).unique().tolist()),
            "unprotected_deauth_total": len(d), "unprotected_deauth_in_window": int(inw.sum()),
            "unprotected_deauth_labelled_attack": int(d["attack"].sum())}


def fig_evil_twin(data: dict, out: Path) -> dict:
    a, b = data["attack"], data["beacons"]
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(7.2, 5.2), sharex=True,
                                   gridspec_kw={"height_ratios": [2, 3], "hspace": 0.25})
    bins = np.arange(0, b["fn"].max() + 50_000, 50_000)
    is_data = a["st"] == 40
    c_data, edges = np.histogram(a.loc[is_data, "fn"], bins=bins)
    c_other, _ = np.histogram(a.loc[~is_data, "fn"], bins=bins)
    ax1.bar(edges[:-1] / 1e6, c_data, width=0.046, align="edge", color=C_NORMAL, linewidth=0,
            label=f"QoS Data frames (n={int(is_data.sum()):,})")
    ax1.bar(edges[:-1] / 1e6, c_other, width=0.046, align="edge", bottom=c_data, color=C_ATTACK,
            linewidth=0, label=f"Beacons and other frames (n={int((~is_data).sum()):,})")
    window_lines(ax1, ET_WINDOW)
    ax1.set_ylabel("Frames labelled\nEvil_Twin per 50k")
    ax1.set_title("Evil_Twin capture: what the Evil_Twin label contains", loc="left")
    ax1.legend(loc="upper left", fontsize=8)

    legit = b.loc[~b["rogue_mac"]]
    rogue_att = b.loc[b["rogue_mac"] & b["attack"]]
    rogue_norm = b.loc[b["rogue_mac"] & ~b["attack"]]
    ax2.scatter(legit["fn"] / 1e6, legit["flen"], s=8, color=C_NORMAL, marker="o", linewidths=0,
                label=f"Legitimate AP beacons (n={len(legit):,})")
    ax2.scatter(rogue_att["fn"] / 1e6, rogue_att["flen"], s=12, color=C_ATTACK, marker="^", linewidths=0,
                label=f"Rogue AP beacons labelled Evil_Twin (n={len(rogue_att):,})")
    ax2.scatter(rogue_norm["fn"] / 1e6, rogue_norm["flen"], s=22, color=C_MISSED, marker="x", linewidths=1.2,
                label=f"Rogue AP beacons labelled Normal (n={len(rogue_norm):,})")
    window_lines(ax2, ET_WINDOW)
    ax2.set_ylabel("Beacon length (bytes)")
    ax2.set_xlabel("frame.number (millions)   - - -  bounds of the published Evil_Twin filter")
    ax2.set_title("Beacons of SSID ASUS_5G: legitimate AP vs rogue AP (0c:9d:92:54:fe:35)", loc="left")
    ax2.set_ylim(120, 450)
    ax2.legend(loc="upper left", fontsize=8, ncol=1, borderaxespad=0.2)
    fig.savefig(out, dpi=200, bbox_inches="tight")
    plt.close(fig)
    before = rogue_norm["fn"] < ET_WINDOW[0]
    return {"attack_frames": len(a), "attack_qos_data": int(is_data.sum()),
            "legit_beacons": len(legit), "rogue_beacons_labelled_attack": len(rogue_att),
            "rogue_beacons_labelled_normal": len(rogue_norm),
            "rogue_beacons_labelled_normal_before_window": int(before.sum()),
            "first_rogue_beacon_frame_number": int(b.loc[b["rogue_mac"], "fn"].min()),
            "rogue_beacon_lengths": sorted(b.loc[b["rogue_mac"], "flen"].astype(int).unique().tolist()),
            "legit_beacon_lengths": sorted(legit["flen"].astype(int).unique().tolist())}


def main() -> None:
    paths = load_paths()
    fig_dir = ROOT / "figures"
    fig_dir.mkdir(exist_ok=True)
    rogue_path = paths["interim_dir"] / "awid3_rogue_ap.parquet"
    et_path = paths["interim_dir"] / "awid3_evil_twin.parquet"

    print("[S1d] Rogue_AP: collecting", flush=True)
    rogue = fig_rogue(collect(rogue_path, "Rogue_AP"), fig_dir / "fig1_rogue_ap_capture.png")
    print("[S1d] Evil_Twin: collecting", flush=True)
    et = fig_evil_twin(collect(et_path, "Evil_Twin"), fig_dir / "fig2_evil_twin_capture.png")

    out = write_result("S1d_figure_data", {"Rogue_AP": rogue, "Evil_Twin": et},
                       run_metadata("scripts/04_figures_labels.py",
                                    inputs_sha256={rogue_path.name: sha256_file(rogue_path),
                                                   et_path.name: sha256_file(et_path)}))
    print(f"[S1d] Done -> {out} and figures/")
    print(f"  Rogue_AP: {rogue}")
    print(f"  Evil_Twin: {et}")


if __name__ == "__main__":
    main()
