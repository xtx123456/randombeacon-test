#!/usr/bin/env bash
# One single-machine PPTB run for an arbitrary node count (syncer + N node
# processes). The node count is derived from the number of nodes-*.json files in
# TESTDIR. Every child PID is tracked and stopped by PID -- never pkill/killall.
#
# usage:
#   run_once_n.sh <batch> <freq> <runtime_sec> <transport> <outdir> <label> <testdir> <ipfile> [faulty_dealer_id]
#
# optional env:
#   WARMUP          rounds trimmed at each end by analyze.py (default 20)
#   BOOT_OFFSET_MS  how far in the future the synchronized protocol start is set
#                   (default 5000; raise it for large n or high injected delay)
set -euo pipefail

BATCH="$1"; FREQ="$2"; RUNTIME="$3"; TRANSPORT="$4"; OUTDIR="$5"; LABEL="$6"; TESTDIR="$7"; IP="$8"
FAULTY="${9:-}"
WARMUP="${WARMUP:-20}"
BOOT_OFFSET_MS="${BOOT_OFFSET_MS:-5000}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BIN="$ROOT/target/release/node"
TRI=32862

NODE_COUNT=$(find "$TESTDIR" -maxdepth 1 -name 'nodes-*.json' | wc -l | tr -d ' ')
[ "$NODE_COUNT" -ge 1 ] || { echo "no nodes-*.json under $TESTDIR"; exit 1; }

RUNDIR="$OUTDIR/$LABEL"
mkdir -p "$RUNDIR" "$ROOT/logs"
rm -f "$ROOT/logs/"*.log

st=$(( $(date +%s%3N) + BOOT_OFFSET_MS ))
PIDS=()

"$BIN" --config "$TESTDIR/nodes-0.json" --ip "$IP" --sleep "$st" --vsstype sync \
  --epsilon 10 --delta 5000 --val 100 --tri "$TRI" --syncer "$TESTDIR/syncer" \
  --batch "$BATCH" --frequency "$FREQ" > "$ROOT/logs/syncer.log" 2>&1 &
PIDS+=($!)

for ((i=0; i<NODE_COUNT; i++)); do
  env ${FAULTY:+PPT_FAULTY_DEALER=$FAULTY} "$BIN" \
    --config "$TESTDIR/nodes-$i.json" --ip "$IP" --sleep "$st" \
    --epsilon 10 --delta 10 --val 100 --tri "$TRI" \
    --vsstype ppt --transport "$TRANSPORT" --syncer "$TESTDIR/syncer" \
    --batch "$BATCH" --frequency "$FREQ" > "$ROOT/logs/$i.log" 2>&1 &
  PIDS+=($!)
done

echo "[run_once_n] label=$LABEL n=$NODE_COUNT batch=$BATCH freq=$FREQ transport=$TRANSPORT faulty=${FAULTY:-none} runtime=${RUNTIME}s pids=${PIDS[*]}"
sleep 2
sleep "$RUNTIME"

for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
sleep 1
for pid in "${PIDS[@]}"; do kill -9 "$pid" 2>/dev/null || true; done

cp "$ROOT/logs/syncer.log" "$RUNDIR/syncer.log"
for ((i=0; i<NODE_COUNT; i++)); do cp "$ROOT/logs/$i.log" "$RUNDIR/node$i.log" 2>/dev/null || true; done

python3 "$ROOT/bench_pptb/analyze.py" --syncer "$RUNDIR/syncer.log" --node "$RUNDIR/node0.log" \
  --batch "$BATCH" --warmup "$WARMUP" --label "$LABEL" | tee "$RUNDIR/metrics.txt"
