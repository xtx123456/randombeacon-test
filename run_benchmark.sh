#!/usr/bin/env bash
# Compare BEA vs PPT over multiple batch sizes.
#
# Usage:
#   bash run_benchmark.sh [duration_secs] [frequency] [batch_list_csv] [runs]
#
# Examples:
#   bash run_benchmark.sh
#   bash run_benchmark.sh 60 10 5,10,20,50,100 3
#
# Outputs:
#   bench_results/<timestamp>/
#     - summary.csv
#     - *.log
#
# Notes:
#   1) Throughput:
#        - rounds/sec
#        - reconstructions/sec
#   2) "Latency" here is a sink-side observable proxy:
#        - gap between consecutive "completed round" log timestamps
#        - gap between consecutive "completed reconstruction" log timestamps
#      This is NOT true end-to-end protocol latency.

set -euo pipefail

DURATION="${1:-60}"
FREQ="${2:-10}"
BATCH_LIST_CSV="${3:-5,10,20,50,100}"
RUNS="${4:-3}"

ROOT="$(pwd)"
TESTDIR="${TESTDIR:-$ROOT/testdata/cc_4}"
LOGDIR="${LOGDIR:-$ROOT/logs}"
BIN="${BIN:-$ROOT/target/release/node}"
TRI="${TRI:-32862}"

STAMP="$(date +%Y%m%d_%H%M%S)"
OUTDIR="$ROOT/bench_results/$STAMP"
mkdir -p "$OUTDIR"
mkdir -p "$LOGDIR"

IFS=',' read -r -a BATCHES <<< "$BATCH_LIST_CSV"
PROTOCOLS=("bea" "ppt")

echo "=== Benchmark sweep start ==="
echo "ROOT=$ROOT"
echo "TESTDIR=$TESTDIR"
echo "LOGDIR=$LOGDIR"
echo "BIN=$BIN"
echo "OUTDIR=$OUTDIR"
echo "DURATION=$DURATION"
echo "FREQ=$FREQ"
echo "BATCHES=${BATCHES[*]}"
echo "RUNS=$RUNS"

cleanup() {
    pkill -f "$ROOT/target/release/node" 2>/dev/null || true
    pkill -f "$ROOT/target/debug/node" 2>/dev/null || true
}

write_header_if_needed() {
    local csv="$1"
    if [ ! -f "$csv" ]; then
        cat > "$csv" <<'EOF'
protocol,batch,frequency,run,duration_sec,recon_count,recon_per_sec,round_count,round_per_sec,round_gap_count,round_gap_mean_ms,round_gap_median_ms,round_gap_p95_ms,recon_gap_count,recon_gap_mean_ms,recon_gap_median_ms,recon_gap_p95_ms,acs_trigger,acs_decide,acs_recon,batch_extract,two_field,blame,first_round_ts,last_round_ts
EOF
    fi
}

SUMMARY_CSV="$OUTDIR/summary.csv"
write_header_if_needed "$SUMMARY_CSV"

run_one_case() {
    local protocol="$1"
    local batch="$2"
    local run_id="$3"

    echo
    echo "=================================================="
    echo "Running protocol=$protocol batch=$batch freq=$FREQ run=$run_id duration=${DURATION}s"
    echo "=================================================="

    cleanup
    sleep 2

    rm -f "$LOGDIR"/*.log 2>/dev/null || true

    local curr_date
    curr_date=$(date +"%s%3N")
    local st_time=$((curr_date + 10000))

    # Start syncer
    "$BIN" \
        --config "$TESTDIR/nodes-0.json" \
        --ip ip_file \
        --sleep "$st_time" \
        --vsstype sync \
        --epsilon 10 \
        --delta 5000 \
        --val 100 \
        --tri "$TRI" \
        --syncer "$TESTDIR/syncer" \
        --batch "$batch" \
        --frequency "$FREQ" \
        > "$LOGDIR/syncer.log" 2>&1 &
    local SYNCER_PID=$!

    sleep 2

    # Start 4 consensus nodes
    local NODE_PIDS=()
    for i in 0 1 2 3; do
        "$BIN" \
            --config "$TESTDIR/nodes-${i}.json" \
            --ip ip_file \
            --sleep "$st_time" \
            --epsilon 10 \
            --delta 10 \
            --val 100 \
            --tri "$TRI" \
            --vsstype "$protocol" \
            --syncer "$TESTDIR/syncer" \
            --batch "$batch" \
            --frequency "$FREQ" \
            > "$LOGDIR/${i}.log" 2>&1 &
        NODE_PIDS+=($!)
    done

    echo "All processes started, waiting ${DURATION}s..."
    sleep "$DURATION"

    cleanup
    sleep 2

    wait "$SYNCER_PID" 2>/dev/null || true
    for pid in "${NODE_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    # Save raw logs for this case
    local CASE_PREFIX="${protocol}_b${batch}_f${FREQ}_r${run_id}"
    cp "$LOGDIR/syncer.log" "$OUTDIR/${CASE_PREFIX}_syncer.log"
    for i in 0 1 2 3; do
        [ -f "$LOGDIR/${i}.log" ] && cp "$LOGDIR/${i}.log" "$OUTDIR/${CASE_PREFIX}_node${i}.log"
    done

    # Parse metrics using Python
    python3 - "$OUTDIR/${CASE_PREFIX}_syncer.log" "$OUTDIR/${CASE_PREFIX}_node0.log" "$protocol" "$batch" "$FREQ" "$run_id" "$DURATION" "$SUMMARY_CSV" <<'PY'
import sys, re, csv, statistics
from datetime import datetime

syncer_log = sys.argv[1]
node0_log = sys.argv[2]
protocol = sys.argv[3]
batch = int(sys.argv[4])
freq = int(sys.argv[5])
run_id = int(sys.argv[6])
duration = float(sys.argv[7])
summary_csv = sys.argv[8]

ts_pat = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)')
round_pat = re.compile(r'All n nodes completed round ')
recon_pat = re.compile(r'All n nodes completed reconstruction ')

def parse_ts(line: str):
    m = ts_pat.search(line)
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%fZ")

round_ts = []
recon_ts = []

with open(syncer_log, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        t = parse_ts(line)
        if t is None:
            continue
        if round_pat.search(line):
            round_ts.append(t)
        if recon_pat.search(line):
            recon_ts.append(t)

round_count = len(round_ts)
recon_count = len(recon_ts)
round_per_sec = round_count / duration if duration > 0 else 0.0
recon_per_sec = recon_count / duration if duration > 0 else 0.0

def gaps_ms(ts_list):
    if len(ts_list) < 2:
        return []
    out = []
    for a, b in zip(ts_list[:-1], ts_list[1:]):
        out.append((b - a).total_seconds() * 1000.0)
    return out

def stat_triplet(vals):
    if not vals:
        return (0, "", "", "")
    vals_sorted = sorted(vals)
    mean_v = statistics.mean(vals_sorted)
    median_v = statistics.median(vals_sorted)
    p95_index = max(0, min(len(vals_sorted)-1, int(0.95 * (len(vals_sorted)-1))))
    p95_v = vals_sorted[p95_index]
    return (len(vals_sorted), f"{mean_v:.6f}", f"{median_v:.6f}", f"{p95_v:.6f}")

round_gaps = gaps_ms(round_ts)
recon_gaps = gaps_ms(recon_ts)

round_gap_count, round_gap_mean, round_gap_median, round_gap_p95 = stat_triplet(round_gaps)
recon_gap_count, recon_gap_mean, recon_gap_median, recon_gap_p95 = stat_triplet(recon_gaps)

first_round_ts = round_ts[0].strftime("%H:%M:%S.%f")[:-3] if round_ts else "N/A"
last_round_ts = round_ts[-1].strftime("%H:%M:%S.%f")[:-3] if round_ts else "N/A"

acs_trigger = acs_decide = acs_recon = batch_extract = two_field = blame = 0

if protocol == "ppt":
    try:
        with open(node0_log, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        acs_trigger = text.count("ACS-TRIGGER")
        acs_decide = text.count("ACS-DECIDE")
        acs_recon = text.count("ACS-RECON")
        batch_extract = text.count("BATCH-EXTRACT")
        two_field = text.count("TWO-FIELD")
        blame = text.count("BLAME")
    except FileNotFoundError:
        pass

row = [
    protocol,
    batch,
    freq,
    run_id,
    int(duration),
    recon_count,
    f"{recon_per_sec:.6f}",
    round_count,
    f"{round_per_sec:.6f}",
    round_gap_count,
    round_gap_mean,
    round_gap_median,
    round_gap_p95,
    recon_gap_count,
    recon_gap_mean,
    recon_gap_median,
    recon_gap_p95,
    acs_trigger,
    acs_decide,
    acs_recon,
    batch_extract,
    two_field,
    blame,
    first_round_ts,
    last_round_ts,
]

with open(summary_csv, "a", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(row)

print("=== Results ===")
print(f"Protocol: {protocol}")
print(f"Batch size: {batch}")
print(f"Frequency: {freq}")
print(f"Duration (sec): {int(duration)}")
print(f"Completed reconstructions: {recon_count}")
print(f"Reconstructions/sec: {recon_per_sec:.6f}")
print(f"Completed rounds: {round_count}")
print(f"Rounds/sec: {round_per_sec:.6f}")
print(f"Round gap count: {round_gap_count}")
print(f"Round gap mean (ms): {round_gap_mean}")
print(f"Round gap median (ms): {round_gap_median}")
print(f"Round gap p95 (ms): {round_gap_p95}")
print(f"Recon gap count: {recon_gap_count}")
print(f"Recon gap mean (ms): {recon_gap_mean}")
print(f"Recon gap median (ms): {recon_gap_median}")
print(f"Recon gap p95 (ms): {recon_gap_p95}")
print(f"First round timestamp: {first_round_ts}")
print(f"Last round timestamp: {last_round_ts}")
if protocol == "ppt":
    print(f"ACS triggers: {acs_trigger}")
    print(f"ACS decisions: {acs_decide}")
    print(f"ACS reconstructions: {acs_recon}")
    print(f"Batch extractions: {batch_extract}")
    print(f"Two-field stores: {two_field}")
    print(f"Blames: {blame}")
print("=== Case complete ===")
PY
}

for protocol in "${PROTOCOLS[@]}"; do
    for batch in "${BATCHES[@]}"; do
        for run_id in $(seq 1 "$RUNS"); do
            run_one_case "$protocol" "$batch" "$run_id"
        done
    done
done

echo
echo "=== All benchmark runs complete ==="
echo "Summary CSV: $SUMMARY_CSV"
echo "Raw logs dir: $OUTDIR"
echo
echo "Quick view:"
column -s, -t "$SUMMARY_CSV" || cat "$SUMMARY_CSV"