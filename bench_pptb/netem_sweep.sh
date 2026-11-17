#!/usr/bin/env bash
# Heatmap experiment (single machine, fixed n): sweep batch size x injected
# one-way network delay, measuring throughput and median end-to-end latency.
#
# The network delay is emulated with `tc netem` on the loopback interface, so a
# uniform one-way delay is added to every message between the local node
# processes. Output is a CSV of (delay_ms, batch, tps, e2e_median_ms) plus a
# rendered heatmap (color = throughput, cell text = median latency).
#
# Requires root (tc). netem is applied to `lo`; a trap always removes it on exit.
#
# tunable env (defaults target n=16):
#   TESTDIR   node-config dir            (default testdata/cc_16)
#   IP        ip_file matching TESTDIR   (default $TESTDIR/ip_file)
#   TRANSPORT secmsg|lite                (default secmsg)
#   FREQ      --frequency                (default 1; pure PPT pins it to 1 anyway)
#   BATCHES   batch sizes to sweep       (default "1 8 32 64 128 256")
#   DELAYS    one-way delays in ms       (default "0 10 30 60")
#   RUNTIME   seconds per cell           (default 30; raise for high delay)
#   WARMUP    rounds trimmed per end     (default 10)
#   NETEM_IFACE loopback iface           (default lo)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TESTDIR="${TESTDIR:-$ROOT/testdata/cc_16}"
IP="${IP:-$TESTDIR/ip_file}"
TRANSPORT="${TRANSPORT:-secmsg}"
FREQ="${FREQ:-1}"
BATCHES="${BATCHES:-1 8 32 64 128 256}"
DELAYS="${DELAYS:-0 10 30 60}"
RUNTIME="${RUNTIME:-30}"
WARMUP="${WARMUP:-10}"
NETEM_IFACE="${NETEM_IFACE:-lo}"

[ "$(id -u)" -eq 0 ] || { echo "tc netem needs root; re-run as root"; exit 1; }
command -v tc >/dev/null || { echo "tc not found (install iproute2)"; exit 1; }

# The ip_file (node 0..n-1 then syncer, one per line) is gitignored, so derive it
# from the committed net_map when absent. update_config maps line index -> node id,
# and the final line (index n) -> syncer address.
if [ ! -f "$IP" ]; then
  echo "[netem_sweep] generating $IP from $TESTDIR/nodes-0.json net_map"
  python3 - "$TESTDIR/nodes-0.json" "$IP" <<'PY'
import json, sys
nm = json.load(open(sys.argv[1]))["net_map"]
with open(sys.argv[2], "w") as f:
    for k in sorted(nm, key=int):
        f.write(nm[k] + "\n")
PY
fi

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="$ROOT/bench_pptb/results/heatmap_$STAMP"
mkdir -p "$OUT"
CSV="$OUT/heatmap.csv"
echo "delay_ms,batch,tps,e2e_median_ms" > "$CSV"

cleanup_netem() { tc qdisc del dev "$NETEM_IFACE" root 2>/dev/null || true; }
trap cleanup_netem EXIT

for d in $DELAYS; do
  cleanup_netem
  if [ "$d" -gt 0 ]; then
    tc qdisc add dev "$NETEM_IFACE" root netem delay "${d}ms"
    echo "########## netem delay ${d}ms on $NETEM_IFACE ##########"
  else
    echo "########## no netem (delay 0ms) ##########"
  fi
  for b in $BATCHES; do
    label="d${d}_b${b}"
    WARMUP="$WARMUP" BOOT_OFFSET_MS="${BOOT_OFFSET_MS:-8000}" \
      bash "$ROOT/bench_pptb/run_once_n.sh" \
      "$b" "$FREQ" "$RUNTIME" "$TRANSPORT" "$OUT" "$label" "$TESTDIR" "$IP"
    line=$(grep '^CSV,' "$OUT/$label/metrics.txt" 2>/dev/null | tail -1 || true)
    tps=$(echo "$line" | cut -d, -f5)
    e2e_s=$(echo "$line" | cut -d, -f6)
    e2e_ms=$(awk -v x="$e2e_s" 'BEGIN{ if (x=="") print ""; else printf "%.1f", x*1000 }')
    echo "$d,$b,${tps:-NA},${e2e_ms:-NA}" >> "$CSV"
  done
done
cleanup_netem

echo
echo "CSV: $CSV"
column -s, -t "$CSV" || cat "$CSV"
python3 "$ROOT/bench_pptb/heatmap.py" --csv "$CSV" --out "$OUT/heatmap.png" --n "$(find "$TESTDIR" -maxdepth 1 -name 'nodes-*.json' | wc -l | tr -d ' ')" || true
echo "heatmap: $OUT/heatmap.png"
echo "results dir: $OUT"
