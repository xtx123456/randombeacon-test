#!/usr/bin/env python3
"""Plot player-elimination overhead vs injected delay.

Input CSV (from elim_netem_sweep.sh):
    delay_ms,batch,honest_e2e_ms,faulty_e2e_ms,overhead_ms,complaint_ms,ban_ms

Renders grouped bars (honest vs one-bad-dealer median e2e) per delay, with the
overhead (faulty - honest) printed above each pair.
"""
import argparse
import csv

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


def num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return float("nan")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--title", default="")
    args = ap.parse_args()

    delays, batches, honest, faulty, over = [], [], [], [], []
    with open(args.csv) as f:
        for row in csv.DictReader(f):
            try:
                delays.append(int(row["delay_ms"]))
            except (ValueError, KeyError):
                continue
            batches.append(row.get("batch", ""))
            honest.append(num(row.get("honest_e2e_ms")))
            faulty.append(num(row.get("faulty_e2e_ms")))
            over.append(num(row.get("overhead_ms")))

    if not delays:
        raise SystemExit("no usable rows in CSV")

    order = np.argsort(delays)
    delays = [delays[i] for i in order]
    batches = [batches[i] for i in order]
    honest = [honest[i] for i in order]
    faulty = [faulty[i] for i in order]
    over = [over[i] for i in order]

    # Name the batch per tick only when the sweet spot differs across delays.
    if len(set(batches)) > 1:
        ticks = [f"{d}\nB={b}" for d, b in zip(delays, batches)]
    else:
        ticks = [str(d) for d in delays]

    x = np.arange(len(delays))
    w = 0.38
    fig, ax = plt.subplots(figsize=(1.8 + 1.1 * len(delays), 5))
    ax.bar(x - w / 2, honest, w, label="honest path", color="#4C72B0")
    ax.bar(x + w / 2, faulty, w, label="one bad dealer (verify + evict)", color="#DD8452")
    for i in range(len(delays)):
        top = max(honest[i], faulty[i])
        if np.isfinite(over[i]) and np.isfinite(top):
            ax.text(x[i], top, f"+{over[i]:.0f} ms", ha="center", va="bottom", fontsize=9)
    ax.set_xticks(x)
    ax.set_xticklabels(ticks)
    ax.set_xlabel("Injected one-way delay (ms)")
    ax.set_ylabel("Median end-to-end latency (ms)")
    ax.set_title(args.title or "PraHRand n=4: player-elimination overhead vs delay")
    ax.legend()
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(args.out, dpi=150)
    print("wrote", args.out)


if __name__ == "__main__":
    main()
