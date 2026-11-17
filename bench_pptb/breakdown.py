#!/usr/bin/env python3
"""Latency-breakdown figure from an already-run sweep.

Each run dir written by run_once_n.sh (via netem_sweep.sh / nodes_sweep.sh)
contains a metrics.txt whose machine-readable line is

    CSV,<label>,<batch>,<outputs>,<tps>,<e2e_s>,<agree_s>,<recon_s>

This scans the run dirs matching a label prefix, and renders the per-batch
median latency split into the two measured windows -- the agreement window
(BATCH-START -> ACS decide D) and the reconstruction window (RECON-START ->
last beacon output) -- stacked, the way the advisor's "latency breakdown at
the sweet point" asks for.

Usage:
    breakdown.py --results <results_dir> --prefix n16_b --out breakdown.png
    breakdown.py --results <results_dir> --prefix d0_b  --out breakdown.png
"""
import argparse
import csv
import glob
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


def read_row(metrics_path):
    with open(metrics_path, errors="ignore") as f:
        line = next((l for l in f if l.startswith("CSV,")), None)
    if not line:
        return None
    parts = line.rstrip("\n").split(",")
    if len(parts) < 8:
        return None

    def num(x):
        try:
            return float(x)
        except ValueError:
            return None

    return {
        "batch": int(parts[2]),
        "e2e": num(parts[5]),
        "agree": num(parts[6]),
        "recon": num(parts[7]),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True, help="results dir holding the run subdirs")
    ap.add_argument("--prefix", required=True, help="run-label prefix, e.g. n16_b or d0_b")
    ap.add_argument("--out", required=True)
    ap.add_argument("--title", default="")
    args = ap.parse_args()

    rows = []
    for d in glob.glob(os.path.join(args.results, args.prefix + "*")):
        m = os.path.join(d, "metrics.txt")
        if os.path.isfile(m):
            r = read_row(m)
            if r and r["agree"] is not None and r["recon"] is not None:
                rows.append(r)
    if not rows:
        raise SystemExit(f"no usable metrics.txt under {args.results}/{args.prefix}*")

    rows.sort(key=lambda r: r["batch"])
    B = [r["batch"] for r in rows]
    agree = np.array([r["agree"] * 1000 for r in rows])
    recon = np.array([r["recon"] * 1000 for r in rows])

    agree_color, recon_color = "#4C72B0", "#DD8452"
    x = range(len(B))
    fig, ax = plt.subplots(figsize=(1.6 + 1.0 * len(B), 5))
    ax.bar(x, agree, label="agreement (BATCH-START -> ACS decide D)", color=agree_color)
    ax.bar(x, recon, bottom=agree, label="reconstruction (two-layer OEC)", color=recon_color)
    for i in x:
        ax.text(i, (agree + recon)[i], f"{(agree + recon)[i]:.0f} ms",
                ha="center", va="bottom", fontsize=8)
    ax.set_xticks(list(x))
    ax.set_xticklabels([str(b) for b in B])
    ax.set_xlabel("Batch size B")
    ax.set_ylabel("Median latency (ms)")
    ax.set_title(args.title or "PraHRand per-batch latency breakdown")
    ax.legend()
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(args.out, dpi=150)
    print("wrote", args.out)


if __name__ == "__main__":
    main()
