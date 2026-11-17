#!/usr/bin/env bash
# One n=4 (f=1) single-machine PPTB run, 4 node processes + 1 syncer.
# Tracks every child PID and stops them by PID (never pkill -f).
#
# usage: run_once.sh <batch> <freq> <runtime_sec> <transport> <outdir> <label> [faulty_dealer_id]
set -euo pipefail

BATCH="$1"; FREQ="$2"; RUNTIME="$3"; TRANSPORT="$4"; OUTDIR="$5"; LABEL="$6"
FAULTY="${7:-}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export LIBRARY_PATH="/tmp/gmplink:${LIBRARY_PATH:-}"
BIN="$ROOT/target/release/node"
TESTDIR="$ROOT/testdata/cc_4"
IP="$ROOT/ip_file"
TRI=32862
BOOT_WAIT=2
RUNDIR="$OUTDIR/$LABEL"
mkdir -p "$RUNDIR" "$ROOT/logs"
rm -f "$ROOT/logs/"*.log

st=$(( $(date +%s%3N) + 1500 ))
PIDS=()

"$BIN" --config "$TESTDIR/nodes-0.json" --ip "$IP" --sleep "$st" --vsstype sync \
  --epsilon 10 --delta 5000 --val 100 --tri "$TRI" --syncer "$TESTDIR/syncer" \
  --batch "$BATCH" --frequency "$FREQ" > "$ROOT/logs/syncer.log" 2>&1 &
PIDS+=($!)

for i in 0 1 2 3; do
  env ${FAULTY:+PPT_FAULTY_DEALER=$FAULTY} "$BIN" \
    --config "$TESTDIR/nodes-$i.json" --ip "$IP" --sleep "$st" \
    --epsilon 10 --delta 10 --val 100 --tri "$TRI" \
    --vsstype ppt --transport "$TRANSPORT" --syncer "$TESTDIR/syncer" \
    --batch "$BATCH" --frequency "$FREQ" > "$ROOT/logs/$i.log" 2>&1 &
  PIDS+=($!)
done

echo "[run_once] label=$LABEL batch=$BATCH freq=$FREQ transport=$TRANSPORT faulty=${FAULTY:-none} pids=${PIDS[*]}"
sleep "$BOOT_WAIT"
sleep "$RUNTIME"

for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
sleep 1
for pid in "${PIDS[@]}"; do kill -9 "$pid" 2>/dev/null || true; done

cp "$ROOT/logs/syncer.log" "$RUNDIR/syncer.log"
for i in 0 1 2 3; do cp "$ROOT/logs/$i.log" "$RUNDIR/node$i.log" 2>/dev/null || true; done

python3 "$ROOT/bench_pptb/analyze.py" --syncer "$RUNDIR/syncer.log" --node "$RUNDIR/node0.log" \
  --batch "$BATCH" --label "$LABEL" | tee "$RUNDIR/metrics.txt"
