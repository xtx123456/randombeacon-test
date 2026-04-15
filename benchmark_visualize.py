#!/usr/bin/env python3
"""
Phase 5: Benchmark Visualization for hashrand vs ppt_beacon comparison.
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

# Benchmark Data (N=4, f=1, freq=10)
batch_sizes = [10, 20, 40]

bea_throughput = [
    2012 * 10 / 38.409,   # batch=10
    2018 * 20 / 47.478,   # batch=20
    1909 * 40 / 66.974,   # batch=40
]
ppt_throughput = [
    2001 * 10 / 45.499,   # batch=10
    2001 * 20 / 66.180,   # batch=20
    1396 * 40 / 66.962,   # batch=40
]
bea_latency = [
    38.409 / 2012 * 1000,
    47.478 / 2018 * 1000,
    66.974 / 1909 * 1000,
]
ppt_latency = [
    45.499 / 2001 * 1000,
    66.180 / 2001 * 1000,
    66.962 / 1396 * 1000,
]

# Phase progression
phases = ['Baseline\n(hashrand)', 'Phase 2\n(ACS)', 'Phase 3\n(Merkle)', 'Phase 4A\n(SS-AVSS)', 'Phase 4B\n(Two-Field\n+Batch)']
phase_tp = [768, 781, 756, 676, 632]
phase_lat = [25.6, 25.6, 26.4, 29.6, 31.7]

plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 11, 'axes.titlesize': 14, 'figure.dpi': 150})

BEA = '#2196F3'
PPT = '#FF5722'
GRN = '#4CAF50'

# Figure 1: Throughput + Latency bars
fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))
x = np.arange(len(batch_sizes))
w = 0.35

b1 = axes[0].bar(x - w/2, bea_throughput, w, label='hashrand (baseline)', color=BEA, alpha=0.85)
b2 = axes[0].bar(x + w/2, ppt_throughput, w, label='ppt_beacon (refactored)', color=PPT, alpha=0.85)
axes[0].set_xlabel('Batch Size')
axes[0].set_ylabel('Throughput (beacons/sec)')
axes[0].set_title('Throughput: hashrand vs ppt_beacon')
axes[0].set_xticks(x)
axes[0].set_xticklabels([f'B={b}' for b in batch_sizes])
axes[0].legend(loc='upper left')
axes[0].set_ylim(0, max(max(bea_throughput), max(ppt_throughput)) * 1.2)
for bar in b1:
    h = bar.get_height()
    axes[0].annotate(f'{h:.0f}', xy=(bar.get_x() + bar.get_width()/2, h), xytext=(0, 3), textcoords="offset points", ha='center', fontsize=9)
for bar in b2:
    h = bar.get_height()
    axes[0].annotate(f'{h:.0f}', xy=(bar.get_x() + bar.get_width()/2, h), xytext=(0, 3), textcoords="offset points", ha='center', fontsize=9)

b3 = axes[1].bar(x - w/2, bea_latency, w, label='hashrand (baseline)', color=BEA, alpha=0.85)
b4 = axes[1].bar(x + w/2, ppt_latency, w, label='ppt_beacon (refactored)', color=PPT, alpha=0.85)
axes[1].set_xlabel('Batch Size')
axes[1].set_ylabel('Latency (ms/round)')
axes[1].set_title('Latency: hashrand vs ppt_beacon')
axes[1].set_xticks(x)
axes[1].set_xticklabels([f'B={b}' for b in batch_sizes])
axes[1].legend(loc='upper left')
axes[1].set_ylim(0, max(max(bea_latency), max(ppt_latency)) * 1.2)
for bar in b3:
    h = bar.get_height()
    axes[1].annotate(f'{h:.1f}', xy=(bar.get_x() + bar.get_width()/2, h), xytext=(0, 3), textcoords="offset points", ha='center', fontsize=9)
for bar in b4:
    h = bar.get_height()
    axes[1].annotate(f'{h:.1f}', xy=(bar.get_x() + bar.get_width()/2, h), xytext=(0, 3), textcoords="offset points", ha='center', fontsize=9)

plt.tight_layout()
plt.savefig('/home/ubuntu/hashrand-p3-main/benchmark_comparison.png', dpi=150, bbox_inches='tight')
plt.close()
print("Saved benchmark_comparison.png")

# Figure 2: Phase Progression
fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))
xp = np.arange(len(phases))

axes[0].plot(xp, phase_tp, 'o-', color=PPT, linewidth=2, markersize=8, label='ppt_beacon throughput')
axes[0].axhline(y=768, color=BEA, linestyle='--', linewidth=1.5, alpha=0.7, label='hashrand baseline (768)')
axes[0].fill_between(xp, phase_tp, alpha=0.1, color=PPT)
axes[0].set_xlabel('Development Phase')
axes[0].set_ylabel('Throughput (beacons/sec)')
axes[0].set_title('ppt_beacon Throughput Across Phases')
axes[0].set_xticks(xp)
axes[0].set_xticklabels(phases, fontsize=9)
axes[0].legend(loc='lower left')
axes[0].set_ylim(500, 900)
for i, v in enumerate(phase_tp):
    axes[0].annotate(f'{v}', xy=(i, v), xytext=(0, 10), textcoords="offset points", ha='center', fontsize=9, fontweight='bold')

axes[1].plot(xp, phase_lat, 's-', color=PPT, linewidth=2, markersize=8, label='ppt_beacon latency')
axes[1].axhline(y=25.6, color=BEA, linestyle='--', linewidth=1.5, alpha=0.7, label='hashrand baseline (25.6ms)')
axes[1].fill_between(xp, phase_lat, alpha=0.1, color=PPT)
axes[1].set_xlabel('Development Phase')
axes[1].set_ylabel('Latency (ms/round)')
axes[1].set_title('ppt_beacon Latency Across Phases')
axes[1].set_xticks(xp)
axes[1].set_xticklabels(phases, fontsize=9)
axes[1].legend(loc='upper left')
axes[1].set_ylim(20, 40)
for i, v in enumerate(phase_lat):
    axes[1].annotate(f'{v}', xy=(i, v), xytext=(0, 10), textcoords="offset points", ha='center', fontsize=9, fontweight='bold')

plt.tight_layout()
plt.savefig('/home/ubuntu/hashrand-p3-main/phase_progression.png', dpi=150, bbox_inches='tight')
plt.close()
print("Saved phase_progression.png")

# Figure 3: Feature comparison
fig, ax = plt.subplots(figsize=(10, 5))
features = ['ACS-Driven Reconstruction', 'Merkle Tree Blame', 'SS-AVSS Poly Commits', 'Two-Field Degree Test', 'Batch Extraction', 'Deferred Complaint']
hashrand_f = [0, 0, 0, 0, 0, 0]
ppt_f = [1, 1, 1, 1, 1, 1]
xf = np.arange(len(features))
w2 = 0.35
ax.barh(xf + w2/2, hashrand_f, w2, label='hashrand (baseline)', color=BEA, alpha=0.6)
ax.barh(xf - w2/2, ppt_f, w2, label='ppt_beacon (refactored)', color=PPT, alpha=0.85)
ax.set_xlabel('Feature Implemented')
ax.set_title('Security & Optimization Feature Comparison')
ax.set_yticks(xf)
ax.set_yticklabels(features)
ax.set_xlim(-0.1, 1.5)
ax.set_xticks([0, 1])
ax.set_xticklabels(['No', 'Yes'])
ax.legend(loc='lower right')
for i in range(len(ppt_f)):
    ax.text(1.05, i - w2/2, '\u2713', fontsize=16, color=GRN, fontweight='bold', va='center')
    ax.text(0.05, i + w2/2, '\u2717', fontsize=14, color='#999', va='center')
plt.tight_layout()
plt.savefig('/home/ubuntu/hashrand-p3-main/feature_comparison.png', dpi=150, bbox_inches='tight')
plt.close()
print("Saved feature_comparison.png")
print("\nAll visualizations generated!")
