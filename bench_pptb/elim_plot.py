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


def audit_plot(args):
    """complaint -> ban per delay: how long detecting and evicting the dealer took.

    Unlike overhead_ms this is read straight off two markers in one run, so it
    is not a difference of two noisy medians.
    """
    reps = OrderedDict()
    with open(args.csv) as f:
        for row in csv.DictReader(f):
            try:
                d = int(row["delay_ms"])
            except (ValueError, KeyError):
                continue
            gap = num(row.get("ban_ms")) - num(row.get("complaint_ms"))
            e = reps.setdefault(d, {"batch": row.get("batch", ""), "gap": []})
            if np.isfinite(gap):
                e["gap"].append(gap)

    if not reps:
        raise SystemExit("no usable rows in CSV")

    delays = sorted(reps)
    batches = [reps[d]["batch"] for d in delays]
    gaps = [statistics.median(reps[d]["gap"]) if reps[d]["gap"] else float("nan")
            for d in delays]

    x = np.arange(len(delays))
    fig, ax = plt.subplots(figsize=(1.8 + 1.1 * len(delays), 5))
    ax.bar(x, gaps, 0.55, color="#DD8452")
    for i, g in enumerate(gaps):
        if np.isfinite(g):
            ax.text(x[i], g, f"{g:.0f} ms", ha="center", va="bottom", fontsize=9)
    top = np.nanmax(gaps)
    if np.isfinite(top):
        ax.set_ylim(0, top * 1.18)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{d}\nB={b}" for d, b in zip(delays, batches)]
                       if len(set(batches)) > 1 else [str(d) for d in delays])
    ax.set_xlabel("Injected one-way delay (ms)")
    ax.set_ylabel(args.ylabel or "First COMPLAINT -> first BAN (ms)")
    ax.set_title(args.title or "PraHRand: detecting and evicting one bad dealer")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(args.out, dpi=150)
    print("wrote", args.out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--title", default="")
    ap.add_argument("--ylabel", default="",
                    help="override for pre-eviction-round CSVs, whose bars are "
                         "steady-state medians rather than a single round")
    ap.add_argument("--metric", choices=("overhead", "audit"), default="overhead",
                    help="overhead: honest vs faulty bars. audit: the measured "
                         "complaint->ban interval, which is a direct reading "
                         "rather than a difference of two medians")
    args = ap.parse_args()

    if args.metric == "audit":
        audit_plot(args)
        return

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
    ax.set_ylabel(args.ylabel or ("Audit-round end-to-end latency (ms)"
                                  + (f", median of {nreps} runs" if nreps > 1 else "")))
    ax.set_title(args.title or "PraHRand n=4: player-elimination overhead vs delay")
    ax.legend()
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(args.out, dpi=150)
    print("wrote", args.out)


if __name__ == "__main__":
    main()
