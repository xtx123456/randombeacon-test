#!/usr/bin/env bash
# Player-elimination one-time overhead vs injected network delay (n=4, f=1).
#
# For each injected one-way delay, run an honest batch and a one-bad-dealer batch
# at a fixed (sweet-spot) batch size, and report how much extra end-to-end
# latency the fault path (complaint -> assist -> recovery -> ban -> audit) adds
# over the honest path. Overhead is defined exactly as in sweep.sh/plot.py:
#   overhead = faulty-run median e2e  -  honest-run median e2e.
# The first-COMPLAINT and first-BAN offsets from the faulty run are also recorded
# so the complaint->ban->audit timeline is visible.
#
# Needs root (tc netem on lo); mirrors netem_sweep.sh's tc handling and always
# removes the qdisc on exit.
#
# env:
#   DELAYS    one-way delays ms       (default "0 10 30 40 50")
#   BATCH     sweet-spot batch size   (default 500)
#   FAULTY    bad dealer id           (default 3; victim defaults to (id+1) mod n)
#   TRANSPORT secmsg|lite             (default secmsg; secmsg carries the complaint evidence)
#   FREQ      --frequency             (default 1)
#   RUNTIME   seconds per run         (default 120)
#   WARMUP    rounds trimmed per end  (default 2; small so the eviction rounds count)
#   NETEM_IFACE loopback iface        (default lo)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DELAYS="${DELAYS:-0 10 30 40 50}"
BATCH="${BATCH:-500}"
FAULTY="${FAULTY:-3}"
TRANSPORT="${TRANSPORT:-secmsg}"
FREQ="${FREQ:-1}"
RUNTIME="${RUNTIME:-120}"
WARMUP="${WARMUP:-2}"
NETEM_IFACE="${NETEM_IFACE:-lo}"
TESTDIR="$ROOT/testdata/cc_4"
IP="$TESTDIR/ip_file"

[ "$(id -u)" -eq 0 ] || { echo "tc netem needs root; re-run as root"; exit 1; }
command -v tc >/dev/null || { echo "tc not found (install iproute2)"; exit 1; }

# derive the gitignored cc_4 ip_file from the committed net_map when absent
if [ ! -f "$IP" ]; then
  python3 - "$TESTDIR/nodes-0.json" "$IP" <<'PY'
import json, sys
nm = json.load(open(sys.argv[1]))["net_map"]
with open(sys.argv[2], "w") as f:
    for k in sorted(nm, key=int):
        f.write(nm[k] + "\n")
PY
fi

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="$ROOT/bench_pptb/results/elim_netem_$STAMP"
mkdir -p "$OUT"
CSV="$OUT/elim_overhead.csv"
echo "delay_ms,batch,honest_e2e_ms,faulty_e2e_ms,overhead_ms,complaint_ms,ban_ms" > "$CSV"

cleanup_netem() { tc qdisc del dev "$NETEM_IFACE" root 2>/dev/null || true; }
trap cleanup_netem EXIT

e2e_ms() {  # $1 metrics.txt -> median e2e ms (CSV line field 6, seconds)
  local s
  s=$(grep '^CSV,' "$1" 2>/dev/null | tail -1 | cut -d, -f6)
  awk -v x="$s" 'BEGIN{ if (x=="") print ""; else printf "%.1f", x*1000 }'
}
marker_ms() {  # $1 metrics.txt ; $2 text pattern -> the "+N ms" offset value
  grep "$2" "$1" 2>/dev/null | grep -oE '\+[0-9]+ ms' | grep -oE '[0-9]+' | head -1
}

for d in $DELAYS; do
  cleanup_netem
  if [ "$d" -gt 0 ]; then
    tc qdisc add dev "$NETEM_IFACE" root netem delay "${d}ms"
    echo "########## netem delay ${d}ms ##########"
  else
    echo "########## no netem (0ms) ##########"
  fi

  hl="h_d${d}"; fl="f_d${d}"
  WARMUP="$WARMUP" BOOT_OFFSET_MS="${BOOT_OFFSET_MS:-8000}" \
    bash "$ROOT/bench_pptb/run_once_n.sh" "$BATCH" "$FREQ" "$RUNTIME" "$TRANSPORT" "$OUT" "$hl" "$TESTDIR" "$IP"
  WARMUP="$WARMUP" BOOT_OFFSET_MS="${BOOT_OFFSET_MS:-8000}" \
    bash "$ROOT/bench_pptb/run_once_n.sh" "$BATCH" "$FREQ" "$RUNTIME" "$TRANSPORT" "$OUT" "$fl" "$TESTDIR" "$IP" "$FAULTY"

  he=$(e2e_ms "$OUT/$hl/metrics.txt")
  fe=$(e2e_ms "$OUT/$fl/metrics.txt")
  ov=$(awk -v f="$fe" -v h="$he" 'BEGIN{ if (f==""||h=="") print ""; else printf "%.1f", f-h }')
  cm=$(marker_ms "$OUT/$fl/metrics.txt" "first COMPLAINT at")
  bm=$(marker_ms "$OUT/$fl/metrics.txt" "first BAN")
  echo "$d,$BATCH,${he:-NA},${fe:-NA},${ov:-NA},${cm:-NA},${bm:-NA}" >> "$CSV"
done
cleanup_netem

echo
echo "CSV: $CSV"
column -s, -t "$CSV" || cat "$CSV"
python3 "$ROOT/bench_pptb/elim_plot.py" --csv "$CSV" --out "$OUT/elim_overhead.png" || true
echo "plot: $OUT/elim_overhead.png"
echo "results dir: $OUT"
