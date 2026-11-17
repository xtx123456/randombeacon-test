#!/usr/bin/env bash
# Player-elimination overhead vs injected network delay (default n=16, f=5).
#
# For each injected one-way delay, run an honest batch and a bad-dealer batch at a
# fixed (sweet-spot) batch size, and report how much extra end-to-end latency the
# fault path (complaint -> assist -> recovery -> ban -> audit) adds over the
# honest path.
#
# Verifying and evicting a dealer is a ONE-TIME event: the bad dealer is
# complained about and banned in the eviction round (round 1 in practice) and is
# gone from D afterwards. So the headline number is read off that round --
#   overhead = faulty round-E e2e  -  honest round-E e2e,
# where E is the round in which D shrinks -- and a run only has to be long enough
# to cover round E plus a few more. Running longer buys no extra sample of the
# one-time cost; repeat the pair with REPS instead. The steady-state median
# difference (the old definition, which averages the one-time cost away) is kept
# alongside as steady_overhead_ms, together with the first-COMPLAINT and
# first-BAN offsets.
#
# The advisor's experiment is "verify + remove ONE bad dealer", so FAULTY is a
# single id by default. f=N is only the tolerance bound, not the number of
# evictions: one bad dealer is still caught and evicted in ~1 round regardless of
# f. To test the worst case (evict several at once) pass a comma list, e.g.
# FAULTY="3,5,7,9,11" for 5 faulty dealers at n=16, f=5.
#
# Needs root (tc netem on lo); mirrors netem_sweep.sh's tc handling and always
# removes the qdisc on exit.
#
# env:
#   NODES     committee size (3f+1)   (default 16; resolves TESTDIR=testdata/cc_<NODES>)
#   TESTDIR   explicit config dir     (default testdata/cc_$NODES)
#   DELAYS    one-way delays ms       (default "0 10 30 40 50")
#   BATCH     sweet-spot batch size   (default 500), used for every delay
#   PAIRS     per-delay batch sizes as "<delay>:<batch> ..." -- use this when the
#             sweet spot differs per delay, e.g. PAIRS="0:800 10:1000 30:500".
#             When set it overrides DELAYS/BATCH.
#   FAULTY    bad dealer id or list   (default 3; victim defaults to (id+1) mod n)
#   TRANSPORT secmsg|lite             (default secmsg; secmsg carries the complaint evidence)
#   FREQ      --frequency             (default 1)
#   RUNTIME   seconds per run         (default 240; only has to cover the
#             eviction round plus a few more, since the headline number is a
#             single round. Raise it only if you also care about the
#             steady-state columns, whose sample counts are in honest_n/faulty_n.)
#   REPS      repeats per delay       (default 1; each repeat is its own CSV row
#             and the plot takes the median, since one run yields exactly one
#             sample of the one-time cost)
#   WARMUP    rounds trimmed per end  (default 2; affects the steady-state
#             columns only -- per-round rows are untrimmed)
#   NETEM_IFACE loopback iface        (default lo)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
NODES="${NODES:-16}"
DELAYS="${DELAYS:-0 10 30 40 50}"
BATCH="${BATCH:-500}"
PAIRS="${PAIRS:-}"
FAULTY="${FAULTY:-3}"
TRANSPORT="${TRANSPORT:-secmsg}"
FREQ="${FREQ:-1}"
RUNTIME="${RUNTIME:-240}"
REPS="${REPS:-1}"
WARMUP="${WARMUP:-2}"
NETEM_IFACE="${NETEM_IFACE:-lo}"
TESTDIR="${TESTDIR:-$ROOT/testdata/cc_$NODES}"
IP="$TESTDIR/ip_file"

[ "$(id -u)" -eq 0 ] || { echo "tc netem needs root; re-run as root"; exit 1; }
command -v tc >/dev/null || { echo "tc not found (install iproute2)"; exit 1; }
[ -d "$TESTDIR" ] && [ -f "$TESTDIR/nodes-0.json" ] || {
  echo "config dir not found: $TESTDIR (expected testdata/cc_$NODES; generate it with nodes_sweep.sh's genconfig step, or set TESTDIR)"; exit 1; }

# derive the gitignored ip_file from the committed net_map when absent
if [ ! -f "$IP" ]; then
  python3 - "$TESTDIR/nodes-0.json" "$IP" <<'PY'
import json, sys
nm = json.load(open(sys.argv[1]))["net_map"]
with open(sys.argv[2], "w") as f:
    for k in sorted(nm, key=int):
        f.write(nm[k] + "\n")
PY
fi

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="$ROOT/bench_pptb/results/elim_netem_$STAMP"
mkdir -p "$OUT"
CSV="$OUT/elim_overhead.csv"
echo "delay_ms,batch,rep,evict_round,honest_e2e_ms,faulty_e2e_ms,overhead_ms,steady_honest_ms,steady_faulty_ms,steady_overhead_ms,complaint_ms,ban_ms,honest_n,faulty_n" > "$CSV"

cleanup_netem() { tc qdisc del dev "$NETEM_IFACE" root 2>/dev/null || true; }
trap cleanup_netem EXIT

e2e_ms() {  # $1 metrics.txt -> median e2e ms (CSV line field 6, seconds)
  local s
  s=$(grep '^CSV,' "$1" 2>/dev/null | tail -1 | cut -d, -f6)
  awk -v x="$s" 'BEGIN{ if (x=="") print ""; else printf "%.1f", x*1000 }'
}
e2e_n() {  # $1 metrics.txt -> number of rounds behind that median (CSV field 9)
  grep '^CSV,' "$1" 2>/dev/null | tail -1 | cut -d, -f9
}
marker_ms() {  # $1 metrics.txt ; $2 text pattern -> the "+N ms" offset value
  grep "$2" "$1" 2>/dev/null | grep -oE '\+[0-9]+ ms' | grep -oE '[0-9]+' | head -1
}
round_ms() {  # $1 metrics.txt ; $2 round -> that single round's e2e in ms
  awk -F, -v r="$2" '$1=="ROUND" && $2==r { printf "%.1f", $3*1000; f=1; exit } END{ if (!f) print "" }' "$1"
}
evict_round_of() {  # $1 metrics.txt -> round in which D shrank, else empty
  grep 'decided-set D shrinks at' "$1" 2>/dev/null | grep -oE 'round [0-9]+' | grep -oE '[0-9]+' | head -1
}
diff_ms() {  # $1 faulty ms ; $2 honest ms -> difference, or empty
  awk -v f="$1" -v h="$2" 'BEGIN{ if (f==""||h=="") print ""; else printf "%.1f", f-h }'
}

# Work list of "<delay>:<batch>" items: PAIRS verbatim, else DELAYS x BATCH.
WORK="$PAIRS"
if [ -z "$WORK" ]; then
  for d in $DELAYS; do WORK="$WORK $d:$BATCH"; done
fi

for item in $WORK; do
  d="${item%%:*}"; b="${item##*:}"
  cleanup_netem
  if [ "$d" -gt 0 ]; then
    tc qdisc add dev "$NETEM_IFACE" root netem delay "${d}ms"
    echo "########## netem delay ${d}ms, batch ${b} ##########"
  else
    echo "########## no netem (0ms), batch ${b} ##########"
  fi

  for ((rep=1; rep<=REPS; rep++)); do
    hl="h_d${d}_b${b}_r${rep}"; fl="f_d${d}_b${b}_r${rep}"
    WARMUP="$WARMUP" BOOT_OFFSET_MS="${BOOT_OFFSET_MS:-8000}" \
      bash "$ROOT/bench_pptb/run_once_n.sh" "$b" "$FREQ" "$RUNTIME" "$TRANSPORT" "$OUT" "$hl" "$TESTDIR" "$IP"
    WARMUP="$WARMUP" BOOT_OFFSET_MS="${BOOT_OFFSET_MS:-8000}" \
      bash "$ROOT/bench_pptb/run_once_n.sh" "$b" "$FREQ" "$RUNTIME" "$TRANSPORT" "$OUT" "$fl" "$TESTDIR" "$IP" "$FAULTY"

    hm="$OUT/$hl/metrics.txt"; fm="$OUT/$fl/metrics.txt"

    # One-time cost: compare the same round index in both runs.
    er=$(evict_round_of "$fm"); er="${er:-1}"
    hr=$(round_ms "$hm" "$er"); fr=$(round_ms "$fm" "$er")
    ov=$(diff_ms "$fr" "$hr")

    # Steady-state difference, for reference only.
    she=$(e2e_ms "$hm"); sfe=$(e2e_ms "$fm")
    sov=$(diff_ms "$sfe" "$she")

    cm=$(marker_ms "$fm" "first COMPLAINT at")
    bm=$(marker_ms "$fm" "first BAN")
    hn=$(e2e_n "$hm"); fn=$(e2e_n "$fm")
    echo "$d,$b,$rep,$er,${hr:-NA},${fr:-NA},${ov:-NA},${she:-NA},${sfe:-NA},${sov:-NA},${cm:-NA},${bm:-NA},${hn:-0},${fn:-0}" >> "$CSV"
    [ -n "$hr" ] && [ -n "$fr" ] || \
      echo "!! delay=${d}ms batch=${b} rep=${rep}: round $er missing from one of the runs -- raise RUNTIME so it completes"
  done
done
cleanup_netem

echo
echo "CSV: $CSV"
column -s, -t "$CSV" || cat "$CSV"
python3 "$ROOT/bench_pptb/elim_plot.py" --csv "$CSV" --out "$OUT/elim_overhead.png" \
  --title "PraHRand n=$NODES: player-elimination overhead vs delay" || true
echo "plot: $OUT/elim_overhead.png"
echo "results dir: $OUT"
