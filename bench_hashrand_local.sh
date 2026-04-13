#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/xietianxiu/random beacon/hashrand/hashrand-rs"
TESTDIR="testdata/cc_4"
OUTDIR="$ROOT/bench_results/$(date +%Y%m%d_%H%M%S)"

# 你可以自己改这两个参数列表
BATCHES=(20 50 100 200)
FREQS=(5 10 20)
RUNS=3

mkdir -p "$OUTDIR"
mkdir -p "$ROOT/logs"

cd "$ROOT"

echo "batch,frequency,run,beacons_per_60s,beacons_per_sec" > "$OUTDIR/summary.csv"

for b in "${BATCHES[@]}"; do
  for f in "${FREQS[@]}"; do
    for r in $(seq 1 $RUNS); do
      echo "=== Running batch=$b frequency=$f run=$r ==="

      pkill -f target/release/node || true
      pkill -f target/debug/node || true
      sleep 2

      rm -f logs/*.log

      TESTDIR="$TESTDIR" TYPE=release bash ./scripts/beacon-test.sh "$TESTDIR/syncer" bea "$b" "$f"

      # syncer 统计窗口是 30~90 秒，所以等 95 秒更稳
      sleep 95

      pkill -f target/release/node || true
      pkill -f target/debug/node || true
      sleep 2

      LOGFILE="$OUTDIR/syncer_b${b}_f${f}_r${r}.log"
      cp logs/syncer.log "$LOGFILE"

      COUNT=$(grep -oE 'Beacons in 60 seconds: [0-9]+' "$LOGFILE" | tail -1 | awk '{print $5}')
      COUNT=${COUNT:-0}

      PERSEC=$(python3 - <<PY
count = int("${COUNT}")
print(f"{count/60:.6f}")
PY
)

      echo "$b,$f,$r,$COUNT,$PERSEC" >> "$OUTDIR/summary.csv"
      echo "Saved result: batch=$b frequency=$f run=$r beacons60=$COUNT"
    done
  done
done

echo "All benchmarks finished."
echo "Results saved in: $OUTDIR"