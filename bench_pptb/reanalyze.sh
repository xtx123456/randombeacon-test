#!/usr/bin/env bash
# Re-score already-collected runs with the current analyze.py. Nothing is
# re-run: every run dir keeps its syncer.log and node0.log, so a correction to
# the analyzer can be applied to results you already have.
#
# This exists because the analyzer's completion marker changed: the syncer's
# "All n nodes completed reconstruction" line actually fires at 2n/3 reports, so
# rounds timed against it could end before this node's own reconstruction.
# analyze.py now prefers the all-n [BEACON-AGREE] markers, and the saved logs
# already contain them.
#
# usage:
#   reanalyze.sh <results_dir>
#
# Rewrites <results_dir>/<label>/metrics.txt for every run dir, then rebuilds
# the sweep CSV beside it from the label format the sweep used:
#   d<delay>_b<batch>              netem_sweep.sh       -> heatmap.csv
#   n<nodes>_b<batch>              nodes_sweep.sh       -> nodes_heatmap.csv
#   {h,f}_d<delay>_b<batch>[_r<k>] elim_netem_sweep.sh  -> elim_overhead.csv
#
# env:
#   WARMUP  rounds trimmed per end (default 10, matching both heatmap sweeps;
#           pass 2 for an elimination results dir)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/bench_pptb/lib_metrics.sh"
WARMUP="${WARMUP:-10}"

DIR="${1:-}"
[ -n "$DIR" ] && [ -d "$DIR" ] || { echo "usage: reanalyze.sh <results_dir>"; exit 1; }
DIR="$(cd "$DIR" && pwd)"

rescored=0
for d in "$DIR"/*/; do
  label="$(basename "$d")"
  [ -f "$d/syncer.log" ] && [ -f "$d/node0.log" ] || continue
  # Every sweep ends its label with _b<batch>.
  batch="$(printf '%s' "$label" | sed -n 's/.*_b\([0-9]\{1,\}\).*/\1/p')"
  [ -n "$batch" ] || { echo "skip $label (no _b<batch> in label)"; continue; }
  python3 "$ROOT/bench_pptb/analyze.py" --syncer "$d/syncer.log" --node "$d/node0.log" \
    --batch "$batch" --warmup "$WARMUP" --label "$label" > "$d/metrics.txt"
  rescored=$((rescored + 1))
done
[ "$rescored" -gt 0 ] || { echo "no run dirs with saved logs under $DIR"; exit 1; }
echo "rescored $rescored run(s) in $DIR"

# -- rebuild whichever sweep CSV this dir holds -------------------------------
heat_csv() {  # $1 out csv ; $2 header ; $3 label prefix holding the x value
  local csv="$1" header="$2" prefix="$3" tmp label x b tps e2e
  tmp="$(mktemp)"
  for d in "$DIR/$prefix"*_b*/; do
    label="$(basename "$d")"
    x="${label#"$prefix"}"; x="${x%%_b*}"
    b="${label##*_b}"
    tps=$(tps_of "$d/metrics.txt")
    e2e=$(e2e_ms "$d/metrics.txt")
    echo "$x,$b,${tps:-NA},${e2e:-NA}" >> "$tmp"
  done
  { echo "$header"; sort -t, -k1,1n -k2,2n "$tmp"; } > "$csv"
  rm -f "$tmp"
  echo "rebuilt $csv"
}

if ls "$DIR"/d*_b*/metrics.txt >/dev/null 2>&1; then
  heat_csv "$DIR/heatmap.csv" "delay_ms,batch,tps,e2e_median_ms" "d"

elif ls "$DIR"/n*_b*/metrics.txt >/dev/null 2>&1; then
  heat_csv "$DIR/nodes_heatmap.csv" "nodes,batch,tps,e2e_median_ms" "n"

elif ls "$DIR"/h_d*_b*/metrics.txt >/dev/null 2>&1; then
  CSV="$DIR/elim_overhead.csv"
  echo "$ELIM_CSV_HEADER" > "$CSV"
  for h in "$DIR"/h_d*_b*/; do
    label="$(basename "$h")"
    f="$DIR/f_${label#h_}"
    [ -f "$f/metrics.txt" ] || { echo "skip $label (no matching faulty run)"; continue; }
    rest="${label#h_d}"; delay="${rest%%_b*}"
    rest="${rest#*_b}"; batch="${rest%%_r*}"
    rep="${label##*_r}"; [ "$rep" = "$label" ] && rep=1
    elim_row "$h/metrics.txt" "$f/metrics.txt" "$delay" "$batch" "$rep" >> "$CSV"
  done
  echo "rebuilt $CSV"

else
  echo "no recognised sweep labels; metrics.txt files were still rewritten"
  exit 0
fi

echo
grep -l 'WARNING' "$DIR"/*/metrics.txt 2>/dev/null | while read -r m; do
  echo "$(basename "$(dirname "$m")"): $(grep -h 'WARNING' "$m" | head -1)"
done
