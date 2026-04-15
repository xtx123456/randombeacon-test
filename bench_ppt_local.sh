#!/usr/bin/env bash
set -euo pipefail

ROOT="$PWD"
TESTDIR="$ROOT/testdata/cc_4"
OUTDIR="$ROOT/bench_results/$(date +%Y%m%d_%H%M%S)_ppt"
PROTO="ppt"

# ========= 可调参数 =========
# BATCHES=(20 50 100 200)
# FREQS=(5 10 20)
# RUNS=3
BATCHES=(20)
FREQS=(5)
RUNS=1

# 实际运行时长（秒）
RUNTIME=95

# 如果你的机器较慢，可以把下面这个调大一点
BOOT_WAIT=3
STOP_WAIT=3
# ==========================

mkdir -p "$OUTDIR"
mkdir -p "$ROOT/logs"

cd "$ROOT"

echo "protocol,batch,frequency,run,runtime_sec,recon_count,recon_per_sec,round_count,round_per_sec" > "$OUTDIR/summary.csv"

cleanup() {
  pkill -f "$ROOT/target/release/node" 2>/dev/null || true
  pkill -f "$ROOT/target/debug/node" 2>/dev/null || true
  pkill -f "target/release/node" 2>/dev/null || true
  pkill -f "target/debug/node" 2>/dev/null || true
}

for b in "${BATCHES[@]}"; do
  for f in "${FREQS[@]}"; do
    for r in $(seq 1 $RUNS); do
      echo "=================================================="
      echo "Running protocol=$PROTO batch=$b frequency=$f run=$r"
      echo "=================================================="

      cleanup
      sleep "$STOP_WAIT"

      rm -f logs/*.log || true

      TESTDIR="$TESTDIR" TYPE=release bash ./scripts/beacon-test.sh "$TESTDIR/syncer" "$PROTO" "$b" "$f" &
      DRIVER_PID=$!

      sleep "$BOOT_WAIT"
      sleep "$RUNTIME"

      cleanup
      sleep "$STOP_WAIT"

      wait $DRIVER_PID 2>/dev/null || true

      LOGFILE="$OUTDIR/syncer_${PROTO}_b${b}_f${f}_r${r}.log"
      cp logs/syncer.log "$LOGFILE"

      for i in 0 1 2 3; do
        if [ -f "logs/$i.log" ]; then
          cp "logs/$i.log" "$OUTDIR/node${i}_${PROTO}_b${b}_f${f}_r${r}.log"
        fi
      done

      RECON_COUNT=$(grep -c "All n nodes completed reconstruction" "$LOGFILE" || true)
      ROUND_COUNT=$(grep -c "All n nodes completed round" "$LOGFILE" || true)

      RECON_COUNT=${RECON_COUNT:-0}
      ROUND_COUNT=${ROUND_COUNT:-0}

      RECON_PER_SEC=$(python3 - <<PY
runtime = float("${RUNTIME}")
count = int("${RECON_COUNT}")
print(f"{count/runtime:.6f}")
PY
)

      ROUND_PER_SEC=$(python3 - <<PY
runtime = float("${RUNTIME}")
count = int("${ROUND_COUNT}")
print(f"{count/runtime:.6f}")
PY
)

      echo "$PROTO,$b,$f,$r,$RUNTIME,$RECON_COUNT,$RECON_PER_SEC,$ROUND_COUNT,$ROUND_PER_SEC" >> "$OUTDIR/summary.csv"

      echo "Saved:"
      echo "  syncer log : $LOGFILE"
      echo "  recon_count: $RECON_COUNT"
      echo "  round_count: $ROUND_COUNT"
      echo "  recon_per_sec: $RECON_PER_SEC"
      echo "  round_per_sec: $ROUND_PER_SEC"
    done
  done
done

echo
echo "All benchmarks finished."
echo "Summary: $OUTDIR/summary.csv"
