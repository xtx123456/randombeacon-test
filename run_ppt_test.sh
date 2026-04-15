#!/bin/bash
set -euo pipefail

cd /home/ubuntu/hashrand-p3-main

killall node 2>/dev/null || true
sleep 1
rm -f logs/*.log
mkdir -p logs

TESTDIR="testdata/cc_4"
tri="32862"
curr_date=$(date +"%s%3N")
st_time=$((curr_date + 10000))
BATCH=20
FREQ=10
TYPE="ppt"

echo "st_time=$st_time"

# Start syncer first
./target/release/node \
    --config "$TESTDIR/nodes-0.json" \
    --ip ip_file \
    --sleep "$st_time" \
    --vsstype sync \
    --epsilon 10 \
    --delta 5000 \
    --val 100 \
    --tri "$tri" \
    --syncer "$TESTDIR/syncer" \
    --batch "$BATCH" \
    --frequency "$FREQ" > logs/syncer.log 2>&1 &

sleep 2

# Start 4 consensus nodes
for i in 0 1 2 3; do
    ./target/release/node \
        --config "$TESTDIR/nodes-${i}.json" \
        --ip ip_file \
        --sleep "$st_time" \
        --epsilon 10 \
        --delta 10 \
        --val 100 \
        --tri "$tri" \
        --vsstype "$TYPE" \
        --syncer "$TESTDIR/syncer" \
        --batch "$BATCH" \
        --frequency "$FREQ" > "logs/${i}.log" 2>&1 &
done

echo "All 5 processes started"
sleep 3
echo "Running processes: $(ps aux | grep 'target/release/node' | grep -v grep | wc -l)"
