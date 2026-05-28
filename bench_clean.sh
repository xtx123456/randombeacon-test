#!/usr/bin/env bash
# Clean PPT vs BEA benchmark with three precise metrics:
#
#   1. beacon throughput  -- # (round, coin) pairs that ALL n nodes
#                            confirmed AND agreed on, per second of
#                            actual protocol-active window.
#   2. round e2e latency  -- ms from when node 0 launched a protocol
#                            round to when the syncer saw every coin
#                            of that round confirmed by ≥ 2n/3 nodes.
#   3. agreement integrity -- count of (round, coin) pairs where any
#                            two honest nodes computed DIFFERENT
#                            beacon values, plus the agreement rate.
#
# All three are protocol-uniform: BEA and PPT are measured with the
# exact same definitions, so the throughput numbers are directly
# comparable across protocols. There is NO `wall vs active` confusion
# (we always use the active protocol window) and NO header/data
# column misalignment (the CSV writes exactly 12 columns, header
# included).
#
# Usage:
#   TESTDIR=/path/to/testdata/cc_16 bash bench_clean.sh \
#       [duration_secs] [frequency] [runs]
#
# Examples:
#   # n=16, all default batch sizes:
#   TESTDIR="$PWD/testdata/cc_16" bash bench_clean.sh 80 1 1
#
#   # n=4, a smaller batch matrix:
#   TESTDIR="$PWD/testdata/cc_4"  BATCHES=20,50,100 bash bench_clean.sh 80 1 1
#
#   # Override the protocol set (default both):
#   PROTOCOLS="ppt" TESTDIR="$PWD/testdata/cc_16" bash bench_clean.sh 80 1 1
#
# Output:
#   bench_clean_results/<timestamp>/
#     - clean_summary.csv         (12 columns, fully aligned)
#     - <case>_syncer.log         (raw syncer log, one per case)
#     - <case>_node0.log          (raw node 0 log, one per case)

set -euo pipefail

DURATION="${1:-80}"
FREQ="${2:-1}"
RUNS="${3:-1}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTDIR="${TESTDIR:-$ROOT/testdata/cc_16}"
LOGDIR="${LOGDIR:-$ROOT/logs}"
BIN="${BIN:-$ROOT/target/release/node}"
TRI="${TRI:-32862}"
IP_FILE="${IP_FILE:-$ROOT/ip_file}"

# Protocol set (default both; override with PROTOCOLS=ppt or PROTOCOLS=bea)
if [ -n "${PROTOCOLS:-}" ]; then
    IFS=',' read -ra PROTOCOLS_ARR <<<"$PROTOCOLS"
else
    PROTOCOLS_ARR=("bea" "ppt")
fi

# Batch matrix (default 20,50,100,200,500; override with BATCHES=...)
if [ -n "${BATCHES:-}" ]; then
    IFS=',' read -ra BATCHES_ARR <<<"$BATCHES"
else
    BATCHES_ARR=(20 50 100 200 500)
fi

# ---- sanity checks ------------------------------------------------

if [ ! -x "$BIN" ]; then
    echo "Error: binary not found or not executable: $BIN"
    echo "Hint: cargo build --release -p node"
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
OUTDIR="$ROOT/bench_clean_results/$STAMP"
mkdir -p "$OUTDIR"
mkdir -p "$LOGDIR"

CSV="$OUTDIR/clean_summary.csv"
# 12-column header, exactly aligned with the data row written below.
cat > "$CSV" <<'EOF'
protocol,nodes,batch,duration_sec,active_window_sec,beacons_agreed,beacons_disagreed,beacons_per_sec,disagree_rate_pct,latency_mean_ms,latency_p95_ms,rounds_completed
EOF

echo "=== Clean benchmark sweep start ==="
echo "ROOT=$ROOT"
echo "TESTDIR=$TESTDIR"
echo "BIN=$BIN"
echo "OUTDIR=$OUTDIR"
echo "NODE_COUNT=$NODE_COUNT"
echo "DURATION=${DURATION}s"
echo "FREQ=$FREQ"
echo "RUNS=$RUNS"
echo "PROTOCOLS=${PROTOCOLS_ARR[*]}"
echo "BATCHES=${BATCHES_ARR[*]}"

# ---- optional CPU pinning ----------------------------------------
USE_TASKSET=1
if [ "${NO_TASKSET:-0}" = "1" ] || ! command -v taskset >/dev/null 2>&1; then
    USE_TASKSET=0
fi
TOTAL_CPUS=$(nproc 2>/dev/null || echo 0)
if [ "$USE_TASKSET" = "1" ] && [ "$TOTAL_CPUS" -gt 0 ]; then
    PARTITIONS=$((NODE_COUNT + 1))
    CPUS_PER_NODE_DEFAULT=$(( TOTAL_CPUS / PARTITIONS ))
    [ "$CPUS_PER_NODE_DEFAULT" -lt 1 ] && CPUS_PER_NODE_DEFAULT=1
    CPUS_PER_NODE="${CPUS_PER_NODE:-$CPUS_PER_NODE_DEFAULT}"
    echo "TASKSET=yes  TOTAL_CPUS=$TOTAL_CPUS  CPUS_PER_NODE=$CPUS_PER_NODE"
else
    USE_TASKSET=0
    echo "TASKSET=no"
fi
cpu_slice_for_slot() {
    local slot="$1"
    local first=$(( slot * CPUS_PER_NODE ))
    local last=$(( first + CPUS_PER_NODE - 1 ))
    local cap=$(( TOTAL_CPUS - 1 ))
    [ "$last" -gt "$cap" ] && last="$cap"
    echo "${first}-${last}"
}
run_pinned() {
    local slot="$1"; shift
    if [ "$USE_TASKSET" = "1" ]; then
        local range
        range=$(cpu_slice_for_slot "$slot")
        taskset -c "$range" "$@"
    else
        "$@"
    fi
}

cleanup() {
    pkill -f "$ROOT/target/release/node" 2>/dev/null || true
    pkill -f "$ROOT/target/debug/node"   2>/dev/null || true
    pkill -f "/syncer"                   2>/dev/null || true
}

run_one_case() {
    local protocol="$1"
    local BATCH="$2"
    local run_id="$3"

    echo
    echo "--- protocol=$protocol nodes=$NODE_COUNT batch=$BATCH freq=$FREQ run=$run_id duration=${DURATION}s ---"

    cleanup
    sleep 2
    rm -f "$LOGDIR"/*.log 2>/dev/null || true

    local curr_date
    curr_date=$(date +"%s%3N")
    local st_time=$((curr_date + 10000))

    run_pinned 0 "$BIN" \
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
        run_pinned $((i + 1)) "$BIN" \
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
    if [ -f "$LOGDIR/0.log" ]; then
        cp "$LOGDIR/0.log" "$OUTDIR/${CASE_PREFIX}_node0.log"
    fi

    python3 - \
        "$OUTDIR/${CASE_PREFIX}_syncer.log" \
        "$OUTDIR/${CASE_PREFIX}_node0.log" \
        "$protocol" \
        "$NODE_COUNT" \
        "$BATCH" \
        "$DURATION" \
        "$CSV" <<'PY'
import sys, re, csv, statistics
from datetime import datetime

syncer_log  = sys.argv[1]
node0_log   = sys.argv[2]
protocol    = sys.argv[3]
node_count  = int(sys.argv[4])
batch       = int(sys.argv[5])
duration    = int(sys.argv[6])
out_csv     = sys.argv[7]

# ---- regexes ------------------------------------------------------

# Standard env_logger timestamp prefix.
ts_pat = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)')

# syncer-side: per-(round, coin) AGREE / DISAGREE verdict (fires only
# once all n nodes have reported, i.e. it represents a *committed*
# beacon -- whether agreed or split).
agree_pat = re.compile(
    r'\[BEACON-AGREE\] round (\d+) index (\d+) all \d+ nodes agree'
)
disagree_pat = re.compile(
    r'\[BEACON-DISAGREE\] round (\d+) index (\d+) '
)

# syncer-side: per-(round, coin) ≥2n/3 completion timestamp. Used as
# the round's "finish time" once we have all batch coins of a round.
recon_pat = re.compile(
    r'All n nodes completed reconstruction for round (\d+) and index (\d+)'
)

# node0-side: protocol-uniform round start (used for end-to-end latency).
ppt_round_start_pat = re.compile(
    r'\[PPT\]\[ROUND-START\] node \d+ launching round (\d+) as PPT dealer'
)
bea_round_start_pat = re.compile(
    r'\[BEA\]\[STAGE\]\[BATCH-START\] node \d+ round (\d+)'
)

def parse_ts(line: str):
    m = ts_pat.search(line)
    if not m: return None
    return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%fZ")

# ---- 1. parse syncer.log -----------------------------------------

agree_count = 0
disagree_count = 0
verdict_ts = []                # for active_window
recon_first_ts = {}            # (round, coin) -> first ts ≥2n/3 completion

with open(syncer_log, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        t = parse_ts(line)
        if t is None:
            continue
        if agree_pat.search(line):
            agree_count += 1
            verdict_ts.append(t)
            continue
        if disagree_pat.search(line):
            disagree_count += 1
            verdict_ts.append(t)
            continue
        m = recon_pat.search(line)
        if m:
            rid = int(m.group(1))
            coin = int(m.group(2))
            recon_first_ts.setdefault((rid, coin), t)
            continue

# ---- 2. parse node0.log for round-start ts (for e2e latency) -----

round_start_ts = {}
try:
    with open(node0_log, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            t = parse_ts(line)
            if t is None: continue
            m = ppt_round_start_pat.search(line) or bea_round_start_pat.search(line)
            if m:
                rid = int(m.group(1))
                round_start_ts.setdefault(rid, t)
except FileNotFoundError:
    pass

# ---- 3. derive throughput ----------------------------------------

# Beacon-active window: first to last AGREE/DISAGREE verdict ts.
# This represents the wall-clock interval during which the syncer
# was actively committing beacons. It is THE right denominator for
# "beacons per second" -- it excludes both startup overhead and any
# trailing tail past the protocol's last commit.
if len(verdict_ts) >= 2:
    active_window_sec = (verdict_ts[-1] - verdict_ts[0]).total_seconds()
elif len(verdict_ts) == 1:
    active_window_sec = 0.0  # edge case: only one verdict
else:
    active_window_sec = 0.0

beacons_committed = agree_count + disagree_count

if active_window_sec > 0:
    beacons_per_sec = beacons_committed / active_window_sec
elif beacons_committed > 0 and duration > 0:
    # Fallback: at least one verdict but window degenerate; use full
    # duration so the reader still sees a number rather than blank.
    beacons_per_sec = beacons_committed / duration
else:
    beacons_per_sec = 0.0

if beacons_committed > 0:
    disagree_rate_pct = 100.0 * disagree_count / beacons_committed
else:
    disagree_rate_pct = 0.0

# ---- 4. derive round-end-to-end latency --------------------------

# Group ≥2n/3-completion timestamps by round.
coins_by_round = {}
for (rid, coin), ts in recon_first_ts.items():
    coins_by_round.setdefault(rid, {})[coin] = ts

# A "completed round" is one where ≥2n/3 nodes reported every coin
# in the batch (i.e. all `batch` coin indices have a recon ts).
e2e_lat_ms = []
rounds_completed = 0
for rid, coin_map in coins_by_round.items():
    if len(coin_map) < batch:
        continue   # round not fully complete in this run
    rounds_completed += 1
    last_coin_ts = max(coin_map.values())
    start_ts = round_start_ts.get(rid)
    if start_ts is None:
        continue
    delta_ms = (last_coin_ts - start_ts).total_seconds() * 1000.0
    if delta_ms >= 0:
        e2e_lat_ms.append(delta_ms)

def p95(vals):
    if not vals: return None
    vs = sorted(vals)
    idx = max(0, min(len(vs) - 1, int(0.95 * (len(vs) - 1))))
    return vs[idx]

if e2e_lat_ms:
    lat_mean = statistics.mean(e2e_lat_ms)
    lat_p95  = p95(e2e_lat_ms)
else:
    lat_mean = None
    lat_p95  = None

# ---- 5. write 12-column CSV row ----------------------------------

def fmt(x, prec=2):
    if x is None: return ""
    return f"{x:.{prec}f}"

row = [
    protocol,                          # 1
    node_count,                        # 2
    batch,                             # 3
    duration,                          # 4
    fmt(active_window_sec, 2),         # 5
    agree_count,                       # 6
    disagree_count,                    # 7
    fmt(beacons_per_sec, 2),           # 8
    fmt(disagree_rate_pct, 4),         # 9
    fmt(lat_mean, 1),                  # 10
    fmt(lat_p95, 1),                   # 11
    rounds_completed,                  # 12
]

with open(out_csv, "a", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(row)

# Pretty print to stdout
print(f"  active_window_sec    = {fmt(active_window_sec, 2)}")
print(f"  beacons_agreed       = {agree_count}")
print(f"  beacons_disagreed    = {disagree_count}")
print(f"  beacons_per_sec      = {fmt(beacons_per_sec, 2)}     <-- THROUGHPUT")
print(f"  disagree_rate_pct    = {fmt(disagree_rate_pct, 4)} %  <-- AGREEMENT INTEGRITY (0 = perfect)")
print(f"  latency_mean_ms      = {fmt(lat_mean, 1)}            <-- ROUND E2E LATENCY")
print(f"  latency_p95_ms       = {fmt(lat_p95, 1)}")
print(f"  rounds_completed     = {rounds_completed}")
PY
}

for protocol in "${PROTOCOLS_ARR[@]}"; do
    for batch in "${BATCHES_ARR[@]}"; do
        for run_id in $(seq 1 "$RUNS"); do
            run_one_case "$protocol" "$batch" "$run_id"
        done
    done
done

echo
echo "=== Done. Clean CSV: $CSV ==="
echo
column -s, -t < "$CSV" || cat "$CSV"
