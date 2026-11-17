#!/usr/bin/env python3
"""Render a (batch x <x-axis>) heatmap.

Color encodes throughput (beacons/s); the text inside each cell shows both the
throughput and the median end-to-end latency (ms). This mirrors the HashRand
Figure 3 style (one metric as color, the number printed in the cell) while
folding in the latency/throughput trade-off that defines the batch sweet spot.

The x-axis column is selectable with --xcol so the same renderer serves both
experiments:
  * injected network delay  (--xcol delay_ms, from netem_sweep.sh)
  * committee size           (--xcol nodes,    from nodes_sweep.sh)

Input CSV columns: <xcol>,batch,tps,e2e_median_ms
"""
import argparse
import csv

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--n", default="")
    ap.add_argument("--xcol", default="delay_ms",
                    help="CSV column to use as the x-axis (e.g. delay_ms or nodes)")
    ap.add_argument("--xlabel", default="Injected one-way delay (ms)",
                    help="x-axis label shown on the figure")
    args = ap.parse_args()

    tps, lat = {}, {}
    batches, delays = set(), set()
    with open(args.csv) as f:
        for row in csv.DictReader(f):
            try:
                d = int(row[args.xcol])
                b = int(row["batch"])
            except (ValueError, KeyError):
                continue
            t, e = row.get("tps", ""), row.get("e2e_median_ms", "")
            tps[(b, d)] = float(t) if t not in ("", "NA") else float("nan")
            lat[(b, d)] = float(e) if e not in ("", "NA") else float("nan")
            batches.add(b)
            delays.add(d)

    if not batches or not delays:
        raise SystemExit("no usable rows in CSV")

    batches = sorted(batches)   # y axis, smallest at bottom (origin lower)
    delays = sorted(delays)     # x axis
    Z = np.array([[tps.get((b, d), float("nan")) for d in delays] for b in batches])

    fig, ax = plt.subplots(figsize=(2.0 + 1.1 * len(delays), 1.5 + 0.7 * len(batches)))
    im = ax.imshow(Z, cmap="Blues", aspect="auto", origin="lower")
    ax.set_xticks(range(len(delays)))
    ax.set_xticklabels([str(d) for d in delays])
    ax.set_yticks(range(len(batches)))
    ax.set_yticklabels([str(b) for b in batches])
    ax.set_xlabel(args.xlabel)
    ax.set_ylabel("Batch size B")
    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label("Throughput (beacons/s)")

    vmax = np.nanmax(Z) if np.isfinite(Z).any() else 1.0
    for i, b in enumerate(batches):
        for j, d in enumerate(delays):
            t = tps.get((b, d), float("nan"))
            e = lat.get((b, d), float("nan"))
            if not np.isfinite(t):
                txt = "NA"
            elif np.isfinite(e):
                txt = f"{t:.0f}\n{e:.0f} ms"
            else:
                txt = f"{t:.0f}"
            color = "white" if (np.isfinite(t) and t > 0.6 * vmax) else "black"
            ax.text(j, i, txt, ha="center", va="center", fontsize=8, color=color)

    title = "PraHRand throughput (color) & median latency (text)"
    if args.n:
        title = f"PraHRand n={args.n}: throughput (color) & median latency (text)"
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(args.out, dpi=150)
    print("wrote", args.out)


if __name__ == "__main__":
    main()
