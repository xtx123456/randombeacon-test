#!/usr/bin/env bash
# Readers for a run dir's metrics.txt, shared by the sweeps and by reanalyze.sh
# so a CSV rebuilt from saved logs is byte-identical to one written live.
#
# analyze.py's machine-readable line is:
#   CSV,<label>,<batch>,<outputs>,<tps>,<e2e_s>,<agree_s>,<recon_s>,<e2e_samples>
# and its untrimmed per-round lines are:
#   ROUND,<round>,<e2e_s>,<agree_s>,<recon_s>

csv_field() {  # $1 metrics.txt ; $2 1-based field -> raw value
  grep '^CSV,' "$1" 2>/dev/null | tail -1 | cut -d, -f"$2"
}

tps_of() { csv_field "$1" 5; }

e2e_ms() {  # median e2e in ms
  awk -v x="$(csv_field "$1" 6)" 'BEGIN{ if (x=="") print ""; else printf "%.1f", x*1000 }'
}

e2e_n() {  # rounds behind that median
  csv_field "$1" 9
}

marker_ms() {  # $1 metrics.txt ; $2 text pattern -> the "+N ms" offset value
  grep "$2" "$1" 2>/dev/null | grep -oE '\+[0-9]+ ms' | grep -oE '[0-9]+' | head -1
}

round_ms() {  # $1 metrics.txt ; $2 round -> that single round's e2e in ms
  awk -F, -v r="$2" '$1=="ROUND" && $2==r { printf "%.1f", $3*1000; f=1; exit } END{ if (!f) print "" }' "$1"
}

evict_round_of() {  # round the banned dealer left D, else empty
  # Second pattern is the wording used before the detection was corrected.
  grep -E 'banned dealer leaves D|decided-set D shrinks at' "$1" 2>/dev/null \
    | grep -oE 'round [0-9]+' | grep -oE '[0-9]+' | head -1
}

diff_ms() {  # $1 faulty ms ; $2 honest ms -> difference, or empty
  awk -v f="$1" -v h="$2" 'BEGIN{ if (f==""||h=="") print ""; else printf "%.1f", f-h }'
}

elim_row() {  # $1 honest metrics.txt ; $2 faulty metrics.txt ; $3 delay ; $4 batch ; $5 rep
  local hm="$1" fm="$2" d="$3" b="$4" rep="$5"
  local er hr fr ov she sfe sov cm bm hn fn

  # One-time cost: the same round index in both runs. Without an observed
  # eviction there is nothing to compare, so report NA rather than guess a round.
  er=$(evict_round_of "$fm")
  if [ -n "$er" ]; then
    hr=$(round_ms "$hm" "$er"); fr=$(round_ms "$fm" "$er")
    ov=$(diff_ms "$fr" "$hr")
  else
    er="NA"; hr=""; fr=""; ov=""
  fi

  # Steady-state difference, for reference only.
  she=$(e2e_ms "$hm"); sfe=$(e2e_ms "$fm")
  sov=$(diff_ms "$sfe" "$she")

  cm=$(marker_ms "$fm" "first COMPLAINT at")
  bm=$(marker_ms "$fm" "first BAN")
  hn=$(e2e_n "$hm"); fn=$(e2e_n "$fm")

  echo "$d,$b,$rep,$er,${hr:-NA},${fr:-NA},${ov:-NA},${she:-NA},${sfe:-NA},${sov:-NA},${cm:-NA},${bm:-NA},${hn:-0},${fn:-0}"
}

ELIM_CSV_HEADER="delay_ms,batch,rep,evict_round,honest_e2e_ms,faulty_e2e_ms,overhead_ms,steady_honest_ms,steady_faulty_ms,steady_overhead_ms,complaint_ms,ban_ms,honest_n,faulty_n"
