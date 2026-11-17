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


def width_for(n, per=1.1, pad=1.8):
    """Figure width in inches for n x-axis groups.

    Floored, because a one-delay run is a normal way to re-check a single
    point and the title and legend still have to fit.
    """
    return max(7.0, pad + per * n)


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
    fig, ax = plt.subplots(figsize=(width_for(len(delays)), 5))
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


def stages_plot(args):
    """The elimination path split into its three measured phases.

    The ban is logged before recovery starts, so complaint->ban alone is
    attribution, not the cost of eliminating a dealer. Stacking the phases
    stops the cheapest one from standing in for the whole path.
    """
    phases = [("attribution (COMPLAINT -> BAN)", "complaint_ms", "ban_ms", "#DD8452"),
              ("share repair (BAN -> AWSS-RECOVERED)", "ban_ms", "recovered_ms", "#4C72B0"),
              ("full audit (-> AUDIT-COMPLETE)", "recovered_ms", "audit_done_ms", "#55A868")]

    reps = OrderedDict()
    with open(args.csv) as f:
        rd = csv.DictReader(f)
        missing = [c for _, a, b, _ in phases for c in (a, b)
                   if c not in (rd.fieldnames or ())]
        if missing:
            raise SystemExit("CSV lacks the stage columns "
                             f"{sorted(set(missing))}; rebuild it with reanalyze.sh")
        for row in rd:
            try:
                d = int(row["delay_ms"])
            except (ValueError, KeyError):
                continue
            e = reps.setdefault(d, {"batch": row.get("batch", ""),
                                    "p": [[] for _ in phases]})
            for i, (_, a, b, _c) in enumerate(phases):
                gap = num(row.get(b)) - num(row.get(a))
                if np.isfinite(gap):
                    e["p"][i].append(gap)

    if not reps:
        raise SystemExit("no usable rows in CSV")

    delays = sorted(reps)
    batches = [reps[d]["batch"] for d in delays]
    # A phase with no sample is 0 height but still reported in the total below,
    # so a missing marker cannot quietly shrink the bar.
    vals = [[statistics.median(reps[d]["p"][i]) if reps[d]["p"][i] else 0.0
             for d in delays] for i in range(len(phases))]

    x = np.arange(len(delays))
    fig, ax = plt.subplots(figsize=(width_for(len(delays), 1.2, 2.2), 5))
    bottom = np.zeros(len(delays))
    for i, (label, _a, _b, color) in enumerate(phases):
        ax.bar(x, vals[i], 0.55, bottom=bottom, label=label, color=color)
        bottom += np.array(vals[i])
    for i, total in enumerate(bottom):
        ax.text(x[i], total, f"{total:.0f} ms", ha="center", va="bottom", fontsize=9)
    top = bottom.max() if len(bottom) else 0.0
    if top > 0:
        ax.set_ylim(0, top * 1.25)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{d}\nB={b}" for d, b in zip(delays, batches)]
                       if len(set(batches)) > 1 else [str(d) for d in delays])
    ax.set_xlabel("Injected one-way delay (ms)")
    ax.set_ylabel(args.ylabel or "Elimination path, by phase (ms)")
    ax.set_title(args.title or "PraHRand: where the elimination path spends its time")
    ax.legend(fontsize=8)
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
    ap.add_argument("--metric", choices=("overhead", "audit", "stages"), default="overhead",
                    help="overhead: honest vs faulty bars. audit: the measured "
                         "complaint->ban interval, which is a direct reading "
                         "rather than a difference of two medians. stages: that "
                         "interval plus the share repair and full audit that "
                         "follow the ban, which it does not cover")
    args = ap.parse_args()

    if args.metric == "audit":
        audit_plot(args)
        return
    if args.metric == "stages":
        stages_plot(args)
        return

    reps = OrderedDict()
    round_col = None
    with open(args.csv) as f:
        rd = csv.DictReader(f)
        # Which round the bars compare is a property of the CSV, not of the
        # caller: pre-fix CSVs are scored on the post-ban eviction round, whose
        # smaller D makes the faulty run legitimately faster.
        for col in ("audit_round", "evict_round"):
            if col in (rd.fieldnames or ()):
                round_col = col
                break
        for row in rd:
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
    fig, ax = plt.subplots(figsize=(width_for(len(delays)), 5))
    ax.bar(x - w / 2, honest, w, label="honest path", color="#4C72B0")
    ax.bar(x + w / 2, faulty, w, label="one bad dealer (verify + evict)", color="#DD8452")
    for i in range(len(delays)):
        top = np.nanmax([honest[i], faulty[i]])
        if np.isfinite(over[i]) and np.isfinite(top):
            # Signed: a post-eviction round on a smaller D can be faster, and
            # "+-24219 ms" would read as a formatting bug rather than a speedup.
            ax.text(x[i], top, f"{over[i]:+.0f} ms", ha="center", va="bottom", fontsize=9)
        elif np.isfinite(top):
            # Say why a bar is missing, so a run that ended before the round
            # completed does not read as a measured zero.
            ax.text(x[i], top, "no\nsample", ha="center", va="bottom", fontsize=8,
                    color="#B04C4C")
    # Headroom so the legend clears the annotations above the tallest pair.
    top = np.nanmax(np.concatenate([honest, faulty]))
    if np.isfinite(top):
        ax.set_ylim(0, top * 1.22)
    ax.set_xticks(x)
    ax.set_xticklabels(ticks)
    ax.set_xlabel("Injected one-way delay (ms)")
    # No round column at all means the oldest CSVs, whose bars are steady-state
    # medians over the whole run rather than one round.
    which = {"audit_round": "Audit-round (ban fires in it)",
             "evict_round": "Eviction-round (first round after the ban)"}.get(
                 round_col, "Steady-state median")
    ax.set_ylabel(args.ylabel or (f"{which} end-to-end latency (ms)"
                                  + (f", median of {nreps} runs" if nreps > 1 else "")))
    ax.set_title(args.title or "PraHRand n=4: player-elimination overhead vs delay")
    ax.legend()
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(args.out, dpi=150)
    print("wrote", args.out)


if __name__ == "__main__":
    main()
