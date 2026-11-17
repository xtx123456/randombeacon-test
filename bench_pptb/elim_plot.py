#!/usr/bin/env python3
"""Plot player-elimination overhead vs injected delay.

Input CSV (from elim_netem_sweep.sh): one row per delay per repeat, carrying
honest_e2e_ms / faulty_e2e_ms (the eviction round in each run) and overhead_ms.
Repeats of the same delay are collapsed by median, since a run yields exactly
one sample of the one-time verify+evict cost.

Renders grouped bars (honest vs one-bad-dealer) per delay, with the overhead
(faulty - honest) printed above each pair.
"""
import argparse
import csv
import statistics
from collections import OrderedDict

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
    ap.add_argument("--ylabel", default="",
                    help="override for pre-eviction-round CSVs, whose bars are "
                         "steady-state medians rather than a single round")
    args = ap.parse_args()

    reps = OrderedDict()
    with open(args.csv) as f:
        for row in csv.DictReader(f):
            try:
                d = int(row["delay_ms"])
            except (ValueError, KeyError):
                continue
            e = reps.setdefault(d, {"batch": row.get("batch", ""),
                                    "h": [], "f": [], "o": []})
            for key, col in (("h", "honest_e2e_ms"), ("f", "faulty_e2e_ms"),
                             ("o", "overhead_ms")):
                v = num(row.get(col))
                if np.isfinite(v):
                    e[key].append(v)

    if not reps:
        raise SystemExit("no usable rows in CSV")

    def med(xs):
        return statistics.median(xs) if xs else float("nan")

    delays = sorted(reps)
    batches = [reps[d]["batch"] for d in delays]
    honest = [med(reps[d]["h"]) for d in delays]
    faulty = [med(reps[d]["f"]) for d in delays]
    over = [med(reps[d]["o"]) for d in delays]
    nreps = max(len(reps[d]["o"]) for d in delays)

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
    # Headroom so the legend clears the annotations above the tallest pair.
    top = np.nanmax(np.concatenate([honest, faulty]))
    if np.isfinite(top):
        ax.set_ylim(0, top * 1.22)
    ax.set_xticks(x)
    ax.set_xticklabels(ticks)
    ax.set_xlabel("Injected one-way delay (ms)")
    ax.set_ylabel(args.ylabel or ("Eviction-round end-to-end latency (ms)"
                                  + (f", median of {nreps} runs" if nreps > 1 else "")))
    ax.set_title(args.title or "PraHRand n=4: player-elimination overhead vs delay")
    ax.legend()
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(args.out, dpi=150)
    print("wrote", args.out)


if __name__ == "__main__":
    main()
