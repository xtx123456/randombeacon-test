#!/usr/bin/env bash
# Fair BEA vs PPT benchmark for 16-node setting, batch size = 20.
#
# Usage:
#   TESTDIR=/path/to/testdata/cc_16 bash run_benchmark.sh [duration_secs] [frequency] [runs]
#
# Example:
#   TESTDIR="$PWD/testdata/cc_16" bash run_benchmark.sh 60 1 1
#
# Outputs:
#   bench_results/<timestamp>/
#     - summary.csv
#     - *.log

set -euo pipefail

DURATION="${1:-60}"
FREQ="${2:-1}"
RUNS="${3:-1}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTDIR="${TESTDIR:-$ROOT/testdata/cc_16}"
LOGDIR="${LOGDIR:-$ROOT/logs}"
BIN="${BIN:-$ROOT/target/release/node}"
TRI="${TRI:-32862}"
IP_FILE="${IP_FILE:-$ROOT/ip_file}"

# 你目前只要 batch=20
BATCHES=(20 50 100)
PROTOCOLS=("bea" "ppt")

if [ ! -x "$BIN" ]; then
    echo "Error: binary not found or not executable: $BIN"
    echo "Please build first: cargo build --release"
    exit 1
fi

if [ ! -d "$TESTDIR" ]; then
    echo "Error: TESTDIR does not exist: $TESTDIR"
    exit 1
fi

if [ ! -f "$IP_FILE" ]; then
    echo "Error: ip_file not found: $IP_FILE"
    exit 1
fi

if [ ! -f "$TESTDIR/syncer" ]; then
    echo "Error: syncer file not found in $TESTDIR"
    exit 1
fi

NODE_COUNT=$(find "$TESTDIR" -maxdepth 1 -type f -name 'nodes-*.json' | wc -l | tr -d ' ')
if [ "${NODE_COUNT}" -le 0 ]; then
    echo "Error: no nodes-*.json found in $TESTDIR"
    exit 1
fi

if [ ! -f "$TESTDIR/nodes-0.json" ]; then
    echo "Error: missing $TESTDIR/nodes-0.json"
    exit 1
fi

STAMP="$(date +%Y%m%d_%H%M%S)"
OUTDIR="$ROOT/bench_results/$STAMP"
mkdir -p "$OUTDIR"
mkdir -p "$LOGDIR"

echo "=== Benchmark sweep start ==="
echo "ROOT=$ROOT"
echo "TESTDIR=$TESTDIR"
echo "LOGDIR=$LOGDIR"
echo "BIN=$BIN"
echo "IP_FILE=$IP_FILE"
echo "OUTDIR=$OUTDIR"
echo "NODE_COUNT=$NODE_COUNT"
echo "DURATION=$DURATION"
echo "FREQ=$FREQ"
echo "BATCHES=${BATCHES[*]}"
echo "RUNS=$RUNS"

cleanup() {
    pkill -f "$ROOT/target/release/node" 2>/dev/null || true
    pkill -f "$ROOT/target/debug/node" 2>/dev/null || true
    pkill -f "beacon-test.sh" 2>/dev/null || true
    pkill -f "/syncer" 2>/dev/null || true
}

write_header_if_needed() {
    local csv="$1"
    if [ ! -f "$csv" ]; then
        cat > "$csv" <<'EOF'
protocol,batch,frequency,run,duration_sec,node_count,unique_batch_count,batch_throughput_wall,batch_active_window_sec,batch_throughput_active,first_batch_round,last_batch_round,internal_progress_span,internal_progress_units_per_sec,batch_gap_count,batch_gap_mean_ms,batch_gap_median_ms,batch_gap_p95_ms,unique_beacon_count,beacon_throughput_wall,beacon_active_window_sec,beacon_throughput_active,recon_gap_count,recon_gap_mean_ms,recon_gap_median_ms,recon_gap_p95_ms,acs_trigger,acs_decide,acs_recon,batch_recover,two_field,post_complaint,post_blame,first_batch_ts,last_batch_ts,first_beacon_ts,last_beacon_ts
EOF
    fi
}

SUMMARY_CSV="$OUTDIR/summary.csv"
write_header_if_needed "$SUMMARY_CSV"
STAGE_CSV="$OUTDIR/stage_summary.csv"

run_one_case() {
    local protocol="$1"
    local BATCH="$2"
    local run_id="$3"

    echo
    echo "=================================================="
    echo "Running protocol=$protocol batch=$BATCH freq=$FREQ run=$run_id duration=${DURATION}s nodes=$NODE_COUNT"
    echo "=================================================="

    cleanup
    sleep 2

    rm -f "$LOGDIR"/*.log 2>/dev/null || true

    local curr_date
    curr_date=$(date +"%s%3N")
    local st_time=$((curr_date + 10000))

    "$BIN" \
        --config "$TESTDIR/nodes-0.json" \
        --ip "$IP_FILE" \
        --sleep "$st_time" \
        --vsstype sync \
        --epsilon 10 \
        --delta 5000 \
        --val 100 \
        --tri "$TRI" \
        --syncer "$TESTDIR/syncer" \
        --batch "$BATCH" \
        --frequency "$FREQ" \
        > "$LOGDIR/syncer.log" 2>&1 &
    local SYNCER_PID=$!

    sleep 2

    local NODE_PIDS=()
    for ((i=0; i<NODE_COUNT; i++)); do
        "$BIN" \
            --config "$TESTDIR/nodes-${i}.json" \
            --ip "$IP_FILE" \
            --sleep "$st_time" \
            --epsilon 10 \
            --delta 10 \
            --val 100 \
            --tri "$TRI" \
            --vsstype "$protocol" \
            --syncer "$TESTDIR/syncer" \
            --batch "$BATCH" \
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

    local CASE_PREFIX="${protocol}_n${NODE_COUNT}_b${BATCH}_f${FREQ}_r${run_id}"
    cp "$LOGDIR/syncer.log" "$OUTDIR/${CASE_PREFIX}_syncer.log"

    for ((i=0; i<NODE_COUNT; i++)); do
        if [ -f "$LOGDIR/${i}.log" ]; then
            cp "$LOGDIR/${i}.log" "$OUTDIR/${CASE_PREFIX}_node${i}.log"
        fi
    done

    python3 - \
        "$OUTDIR/${CASE_PREFIX}_syncer.log" \
        "$OUTDIR/${CASE_PREFIX}_node0.log" \
        "$protocol" \
        "$BATCH" \
        "$FREQ" \
        "$run_id" \
        "$DURATION" \
        "$NODE_COUNT" \
        "$SUMMARY_CSV" <<'PY'
import sys, re, csv, statistics
from datetime import datetime

syncer_log = sys.argv[1]
node0_log = sys.argv[2]
protocol = sys.argv[3]
batch = int(sys.argv[4])
freq = int(sys.argv[5])
run_id = int(sys.argv[6])
duration = float(sys.argv[7])
node_count = int(sys.argv[8])
summary_csv = sys.argv[9]

ts_pat = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)')
round_pat = re.compile(r'All n nodes completed round (\d+)')
recon_pat = re.compile(r'All n nodes completed reconstruction for round (\d+) and index (\d+)')

def parse_ts(line: str):
    m = ts_pat.search(line)
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%fZ")

def fmt_float(x):
    if x is None:
        return ""
    return f"{x:.6f}"

def active_window_sec(ts_list):
    if len(ts_list) < 2:
        return None
    return (ts_list[-1] - ts_list[0]).total_seconds()

def throughput(count, seconds):
    if seconds is None or seconds <= 0:
        return None
    return count / seconds

def gaps_ms(ts_list):
    if len(ts_list) < 2:
        return []
    return [(b - a).total_seconds() * 1000.0 for a, b in zip(ts_list[:-1], ts_list[1:])]

def stat_triplet(vals):
    if not vals:
        return (0, "", "", "")
    vals_sorted = sorted(vals)
    mean_v = statistics.mean(vals_sorted)
    median_v = statistics.median(vals_sorted)
    p95_index = max(0, min(len(vals_sorted) - 1, int(0.95 * (len(vals_sorted) - 1))))
    p95_v = vals_sorted[p95_index]
    return (len(vals_sorted), f"{mean_v:.6f}", f"{median_v:.6f}", f"{p95_v:.6f}")

round_first_ts = {}
recon_first_ts = {}

with open(syncer_log, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        t = parse_ts(line)
        if t is None:
            continue

        m_round = round_pat.search(line)
        if m_round:
            rid = int(m_round.group(1))
            round_first_ts.setdefault(rid, t)
            continue

        m_recon = recon_pat.search(line)
        if m_recon:
            rid = int(m_recon.group(1))
            coin = int(m_recon.group(2))
            recon_first_ts.setdefault((rid, coin), t)
            continue

round_items = sorted(round_first_ts.items(), key=lambda kv: (kv[1], kv[0]))
recon_items = sorted(recon_first_ts.items(), key=lambda kv: (kv[1], kv[0][0], kv[0][1]))

round_ids = [rid for rid, _ in round_items]
round_ts = [ts for _, ts in round_items]

recon_keys = [k for k, _ in recon_items]
recon_ts = [ts for _, ts in recon_items]

unique_batch_count = len(round_ids)
unique_beacon_count = len(recon_keys)

batch_throughput_wall = throughput(unique_batch_count, duration)
beacon_throughput_wall = throughput(unique_beacon_count, duration)

batch_window = active_window_sec(round_ts)
beacon_window = active_window_sec(recon_ts)

batch_throughput_active = throughput(unique_batch_count, batch_window)
beacon_throughput_active = throughput(unique_beacon_count, beacon_window)

first_batch_round = round_ids[0] if round_ids else ""
last_batch_round = round_ids[-1] if round_ids else ""
internal_progress_span = (round_ids[-1] - round_ids[0]) if len(round_ids) >= 2 else ""
internal_progress_units_per_sec = (
    (round_ids[-1] - round_ids[0]) / batch_window
    if len(round_ids) >= 2 and batch_window and batch_window > 0
    else None
)

batch_gaps = gaps_ms(round_ts)
recon_gaps = gaps_ms(recon_ts)

batch_gap_count, batch_gap_mean, batch_gap_median, batch_gap_p95 = stat_triplet(batch_gaps)
recon_gap_count, recon_gap_mean, recon_gap_median, recon_gap_p95 = stat_triplet(recon_gaps)

first_batch_ts = round_ts[0].strftime("%H:%M:%S.%f")[:-3] if round_ts else "N/A"
last_batch_ts = round_ts[-1].strftime("%H:%M:%S.%f")[:-3] if round_ts else "N/A"
first_beacon_ts = recon_ts[0].strftime("%H:%M:%S.%f")[:-3] if recon_ts else "N/A"
last_beacon_ts = recon_ts[-1].strftime("%H:%M:%S.%f")[:-3] if recon_ts else "N/A"

acs_trigger = acs_decide = acs_recon = batch_recover = two_field = post_complaint = post_blame = 0
if protocol == "ppt":
    try:
        with open(node0_log, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        acs_trigger = text.count("ACS-TRIGGER")
        acs_decide = text.count("ACS-DECIDE")
        acs_recon = text.count("ACS-RECON")
        batch_recover = text.count("BATCH-RECOVER")
        two_field = text.count("TWO-FIELD")
        post_complaint = text.count("POST-COMPLAINT")
        post_blame = text.count("POST-BLAME")
    except FileNotFoundError:
        pass

row = [
    protocol,
    batch,
    freq,
    run_id,
    int(duration),
    node_count,
    unique_batch_count,
    fmt_float(batch_throughput_wall),
    fmt_float(batch_window),
    fmt_float(batch_throughput_active),
    first_batch_round,
    last_batch_round,
    internal_progress_span,
    fmt_float(internal_progress_units_per_sec),
    batch_gap_count,
    batch_gap_mean,
    batch_gap_median,
    batch_gap_p95,
    unique_beacon_count,
    fmt_float(beacon_throughput_wall),
    fmt_float(beacon_window),
    fmt_float(beacon_throughput_active),
    recon_gap_count,
    recon_gap_mean,
    recon_gap_median,
    recon_gap_p95,
    acs_trigger,
    acs_decide,
    acs_recon,
    batch_recover,
    two_field,
    post_complaint,
    post_blame,
    first_batch_ts,
    last_batch_ts,
    first_beacon_ts,
    last_beacon_ts,
]

with open(summary_csv, "a", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(row)

print("=== Results ===")
print(f"Protocol: {protocol}")
print(f"Node count: {node_count}")
print(f"Batch size: {batch}")
print(f"Frequency arg: {freq}")
print(f"Duration (sec): {int(duration)}")
print(f"Unique completed batches: {unique_batch_count}")
print(f"Batch throughput (wall): {fmt_float(batch_throughput_wall)}")
print(f"Batch active window (sec): {fmt_float(batch_window)}")
print(f"Batch throughput (active): {fmt_float(batch_throughput_active)}")
print(f"First batch round: {first_batch_round}")
print(f"Last batch round: {last_batch_round}")
print(f"Internal progress span: {internal_progress_span}")
print(f"Internal progress units/sec: {fmt_float(internal_progress_units_per_sec)}")
print(f"Batch gap count: {batch_gap_count}")
print(f"Batch gap mean (ms): {batch_gap_mean}")
print(f"Batch gap median (ms): {batch_gap_median}")
print(f"Batch gap p95 (ms): {batch_gap_p95}")
print(f"Unique completed beacon outputs: {unique_beacon_count}")
print(f"Beacon throughput (wall): {fmt_float(beacon_throughput_wall)}")
print(f"Beacon active window (sec): {fmt_float(beacon_window)}")
print(f"Beacon throughput (active): {fmt_float(beacon_throughput_active)}")
print(f"Recon gap count: {recon_gap_count}")
print(f"Recon gap mean (ms): {recon_gap_mean}")
print(f"Recon gap median (ms): {recon_gap_median}")
print(f"Recon gap p95 (ms): {recon_gap_p95}")
print(f"First batch timestamp: {first_batch_ts}")
print(f"Last batch timestamp: {last_batch_ts}")
print(f"First beacon timestamp: {first_beacon_ts}")
print(f"Last beacon timestamp: {last_beacon_ts}")
if protocol == "ppt":
    print(f"ACS triggers: {acs_trigger}")
    print(f"ACS decisions: {acs_decide}")
    print(f"ACS reconstructions: {acs_recon}")
    print(f"Batch recover: {batch_recover}")
    print(f"Two-field logs: {two_field}")
    print(f"Post-complaint logs: {post_complaint}")
    print(f"Post-blame logs: {post_blame}")
print("=== Case complete ===")
PY

    python3 "$ROOT/scripts/stage_throughput.py" \
        "$OUTDIR/${CASE_PREFIX}_syncer.log" \
        "$OUTDIR/${CASE_PREFIX}_node0.log" \
        "$protocol" \
        "$BATCH" \
        "$STAGE_CSV"
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
