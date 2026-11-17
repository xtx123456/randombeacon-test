#!/usr/bin/env bash
# Heatmap experiment (single machine): sweep committee size n x batch size,
# measuring throughput (color) and median end-to-end latency (cell text).
#
# Unlike netem_sweep.sh this needs NO network emulation and NO privileges: the
# x-axis is the committee size, not an injected delay, so it runs anywhere --
# including a GPU cloud container (e.g. AutoDL) that lacks CAP_NET_ADMIN and
# cannot load sch_netem.
#
# For each node count without a ready config dir, the configs are generated with
# the genconfig tool using the same port scheme as the committed testdata/cc_*.
#
# PPT requires exactly n=3f+1, so every swept node count must satisfy
# n mod 3 == 1 (4, 7, 10, 13, 16, 19, 22, 25, 28, 31, 34, 37, 40, ...); any
# other n is skipped with a note. The fault bound f=(n-1)/3 is then exact.
#
# tunable env (defaults target a scalability curve):
#   NODES     committee sizes to sweep   (default "4 7 13 16 22 31", all 3f+1)
#   BATCHES   batch sizes to sweep       (default "8 32 64 128 256")
#   TRANSPORT secmsg|lite                (default secmsg)
#   FREQ      --frequency                (default 1)
#   RUNTIME   seconds per cell           (default 180; raise for large n/batch)
#   WARMUP    rounds trimmed per end     (default 10)
#   BASE_PORT / CLIENT_BASE_PORT / CLIENT_RUN_PORT  genconfig ports
#                                        (default 8500 / 7000 / 9000)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
NODES="${NODES:-4 7 13 16 22 31}"
BATCHES="${BATCHES:-8 32 64 128 256}"
TRANSPORT="${TRANSPORT:-secmsg}"
FREQ="${FREQ:-1}"
RUNTIME="${RUNTIME:-180}"
WARMUP="${WARMUP:-10}"
BASE_PORT="${BASE_PORT:-8500}"
CLIENT_BASE_PORT="${CLIENT_BASE_PORT:-7000}"
CLIENT_RUN_PORT="${CLIENT_RUN_PORT:-9000}"

BIN="$ROOT/target/release/node"
GENCONFIG="$ROOT/target/release/genconfig"
[ -x "$BIN" ] || { echo "node binary missing: $BIN (build: cargo build --release -p node)"; exit 1; }

# Ensure testdata/cc_<n> holds n node configs plus the (gitignored) ip_file.
# Returns non-zero (and does nothing) for a node count PPT cannot run.
gen_cc() {
  local n="$1" dir="$ROOT/testdata/cc_$1" have f
  if [ $((n % 3)) -ne 1 ]; then
    echo "[nodes_sweep] SKIP n=$n: PPT requires n=3f+1 (n mod 3 == 1), e.g. 4,7,10,13,16,19,22,..."
    return 1
  fi
  f=$(( (n - 1) / 3 ))
  have=$(find "$dir" -maxdepth 1 -name 'nodes-*.json' 2>/dev/null | wc -l | tr -d ' ')
  if [ "$have" -ne "$n" ]; then
    if [ ! -x "$GENCONFIG" ]; then
      echo "[nodes_sweep] building genconfig"
      cargo build --release -p genconfig
    fi
    echo "[nodes_sweep] generating configs for n=$n f=$f at $dir"
    mkdir -p "$dir"
    # genconfig writes ip_file to CWD and the rest to --target, so run it inside
    # the target dir. --local true is what emits ip_file and the syncer file.
    ( cd "$dir" && "$GENCONFIG" --NumNodes "$n" --faults "$f" --delay 10 --blocksize 100 \
        --client_base_port "$CLIENT_BASE_PORT" --target . --payload 100 \
        --out_type json --base_port "$BASE_PORT" --client_run_port "$CLIENT_RUN_PORT" \
        --local true )
  fi
  if [ ! -f "$dir/ip_file" ]; then
    echo "[nodes_sweep] deriving $dir/ip_file from net_map"
    python3 - "$dir/nodes-0.json" "$dir/ip_file" <<'PY'
import json, sys
nm = json.load(open(sys.argv[1]))["net_map"]
with open(sys.argv[2], "w") as f:
    for k in sorted(nm, key=int):
        f.write(nm[k] + "\n")
PY
  fi
}

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="$ROOT/bench_pptb/results/nodes_heatmap_$STAMP"
mkdir -p "$OUT"
CSV="$OUT/nodes_heatmap.csv"
echo "nodes,batch,tps,e2e_median_ms" > "$CSV"

for n in $NODES; do
  gen_cc "$n" || continue
  TESTDIR="$ROOT/testdata/cc_$n"
  IP="$TESTDIR/ip_file"
  echo "########## n=$n ##########"
  for b in $BATCHES; do
    label="n${n}_b${b}"
    WARMUP="$WARMUP" BOOT_OFFSET_MS="${BOOT_OFFSET_MS:-8000}" \
      bash "$ROOT/bench_pptb/run_once_n.sh" \
      "$b" "$FREQ" "$RUNTIME" "$TRANSPORT" "$OUT" "$label" "$TESTDIR" "$IP"
    line=$(grep '^CSV,' "$OUT/$label/metrics.txt" 2>/dev/null | tail -1 || true)
    tps=$(echo "$line" | cut -d, -f5)
    e2e_s=$(echo "$line" | cut -d, -f6)
    e2e_ms=$(awk -v x="$e2e_s" 'BEGIN{ if (x=="") print ""; else printf "%.1f", x*1000 }')
    echo "$n,$b,${tps:-NA},${e2e_ms:-NA}" >> "$CSV"
  done
done

echo
echo "CSV: $CSV"
column -s, -t "$CSV" || cat "$CSV"
python3 "$ROOT/bench_pptb/heatmap.py" --csv "$CSV" --out "$OUT/nodes_heatmap.png" \
  --xcol nodes --xlabel "Number of nodes n" || true
echo "heatmap: $OUT/nodes_heatmap.png"
echo "results dir: $OUT"
