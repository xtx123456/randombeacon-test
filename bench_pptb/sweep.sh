#!/usr/bin/env bash
# Drives the three evaluation experiments for n=4, f=1 on one machine:
#   (1) batch-size sweet-spot sweep (honest): TPS vs latency.
#   (2) latency breakdown is emitted per run by analyze.py.
#   (3) player-elimination overhead: honest vs one-bad-dealer at a fixed batch.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="$ROOT/bench_pptb/results/$STAMP"
mkdir -p "$OUT"

TRANSPORT="${TRANSPORT:-secmsg}"
FREQ="${FREQ:-10}"
RUNTIME="${RUNTIME:-40}"
BATCHES="${BATCHES:-1 4 8 16 32 64 128 256}"
ELIM_BATCH="${ELIM_BATCH:-32}"

SUMMARY="$OUT/summary.csv"
echo "label,batch,beacon_outputs,tps,e2e_median_s,agree_median_s,recon_median_s" > "$SUMMARY"

append() { grep '^CSV,' "$1" | sed 's/^CSV,//' >> "$SUMMARY" || true; }

echo "########## (1) sweet-spot sweep (honest) ##########"
for b in $BATCHES; do
  bash "$ROOT/bench_pptb/run_once.sh" "$b" "$FREQ" "$RUNTIME" "$TRANSPORT" "$OUT" "honest_b$b"
  append "$OUT/honest_b$b/metrics.txt"
done

echo "########## (3) player-elimination overhead at batch=$ELIM_BATCH ##########"
bash "$ROOT/bench_pptb/run_once.sh" "$ELIM_BATCH" "$FREQ" "$RUNTIME" "$TRANSPORT" "$OUT" "elim_honest_b$ELIM_BATCH"
append "$OUT/elim_honest_b$ELIM_BATCH/metrics.txt"
bash "$ROOT/bench_pptb/run_once.sh" "$ELIM_BATCH" "$FREQ" "$RUNTIME" "$TRANSPORT" "$OUT" "elim_faulty_b$ELIM_BATCH" 3
append "$OUT/elim_faulty_b$ELIM_BATCH/metrics.txt"

echo
echo "===== SUMMARY ($SUMMARY) ====="
column -s, -t "$SUMMARY"
echo
echo "results dir: $OUT"
