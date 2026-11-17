#!/usr/bin/env python3
"""Render the evaluation figures from a sweep summary.csv into an output dir."""
import csv
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

summary = Path(sys.argv[1])
outdir = Path(sys.argv[2])
outdir.mkdir(parents=True, exist_ok=True)

rows = list(csv.DictReader(summary.open()))
honest = [r for r in rows if r["label"].startswith("honest_b")]
honest.sort(key=lambda r: int(r["batch"]))
B = [int(r["batch"]) for r in honest]
tps = [float(r["tps"]) for r in honest]
e2e = [float(r["e2e_median_s"]) * 1000 for r in honest]
agree = [float(r["agree_median_s"]) * 1000 for r in honest]
recon = [float(r["recon_median_s"]) * 1000 for r in honest]

# Figure 1: throughput vs latency vs batch size (the sweet-spot curve).
fig, ax1 = plt.subplots(figsize=(8, 5))
ax1.set_xscale("log", base=2)
ax1.plot(B, tps, "o-", color="tab:blue", label="throughput (outputs/s)")
ax1.set_xlabel("batch size B")
ax1.set_ylabel("throughput (beacon outputs / s)", color="tab:blue")
ax1.tick_params(axis="y", labelcolor="tab:blue")
ax2 = ax1.twinx()
ax2.plot(B, e2e, "s--", color="tab:red", label="per-batch latency (ms)")
ax2.set_ylabel("per-batch e2e latency (ms, median)", color="tab:red")
ax2.tick_params(axis="y", labelcolor="tab:red")
ax1.set_xticks(B)
ax1.set_xticklabels([str(b) for b in B])
plt.title("PraHRand n=4, f=1 (single machine): throughput vs latency vs batch size")
fig.tight_layout()
fig.savefig(outdir / "sweetspot_tps_latency.png", dpi=130)

# Figure 2: latency breakdown (agreement vs reconstruction) stacked by batch.
fig, ax = plt.subplots(figsize=(8, 5))
x = range(len(B))
ax.bar(x, agree, label="agreement (BATCH-START -> ACS decide D)", color="tab:orange")
ax.bar(x, recon, bottom=agree, label="reconstruction (two-layer OEC)", color="tab:green")
ax.set_xticks(list(x))
ax.set_xticklabels([str(b) for b in B])
ax.set_xlabel("batch size B")
ax.set_ylabel("median latency (ms)")
ax.set_title("Per-batch latency breakdown")
ax.legend()
fig.tight_layout()
fig.savefig(outdir / "latency_breakdown.png", dpi=130)

# Figure 3: player-elimination overhead (honest vs one bad dealer) at fixed B.
eh = next((r for r in rows if r["label"].startswith("elim_honest")), None)
ef = next((r for r in rows if r["label"].startswith("elim_faulty")), None)
if eh and ef:
    fig, (axl, axr) = plt.subplots(1, 2, figsize=(10, 4.5))
    labels = ["honest", "1 bad dealer\n(verify + evict)"]
    lat = [float(eh["e2e_median_s"]) * 1000, float(ef["e2e_median_s"]) * 1000]
    thr = [float(eh["tps"]), float(ef["tps"])]
    axl.bar(labels, lat, color=["tab:blue", "tab:red"])
    axl.set_ylabel("per-batch e2e latency (ms, median)")
    axl.set_title(f"Latency @ B={eh['batch']} (overhead on critical path)")
    for i, v in enumerate(lat):
        axl.text(i, v, f"{v:.0f} ms", ha="center", va="bottom")
    axr.bar(labels, thr, color=["tab:blue", "tab:red"])
    axr.set_ylabel("throughput (outputs/s)")
    axr.set_title(f"Throughput @ B={eh['batch']} (|D|=4 vs |D|=3 after eviction)")
    for i, v in enumerate(thr):
        axr.text(i, v, f"{v:.0f}", ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(outdir / "elimination_overhead.png", dpi=130)

print("wrote figures to", outdir)
