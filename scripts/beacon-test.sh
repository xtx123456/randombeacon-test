#!/usr/bin/env bash
set -euo pipefail

# 只清理本项目的 node 进程
pkill -f "/target/release/node" 2>/dev/null || true
pkill -f "/target/debug/node" 2>/dev/null || true
rm -rf /tmp/*.db &>/dev/null || true

tri=32862

TESTDIR="${TESTDIR:-testdata/cc_4}"
TYPE="${TYPE:-release}"

NODE_COUNT=$(find "$TESTDIR" -maxdepth 1 -name 'nodes-*.json' | wc -l | tr -d ' ')
if [ "$NODE_COUNT" -le 0 ]; then
  echo "No nodes-*.json found under $TESTDIR"
  exit 1
fi

curr_date=$(date +"%s%3N")
sleep_ms=100
st_time=$((curr_date + sleep_ms))

echo "$st_time"
echo "TESTDIR=$TESTDIR"
echo "NODE_COUNT=$NODE_COUNT"

mkdir -p logs

"./target/$TYPE/node" \
  --config "$TESTDIR/nodes-0.json" \
  --ip ip_file \
  --sleep "$st_time" \
  --vsstype sync \
  --epsilon 10 \
  --delta 5000 \
  --val 100 \
  --tri "$tri" \
  --syncer "$1" \
  --batch "$3" \
  --frequency "$4" > logs/syncer.log &

for ((i=0; i<NODE_COUNT; i++)); do
  "./target/$TYPE/node" \
    --config "$TESTDIR/nodes-$i.json" \
    --ip ip_file \
    --sleep "$st_time" \
    --epsilon 10 \
    --delta 10 \
    --val 100 \
    --tri "$tri" \
    --vsstype "$2" \
    --syncer "$1" \
    --batch "$3" \
    --frequency "$4" > "logs/$i.log" &
done