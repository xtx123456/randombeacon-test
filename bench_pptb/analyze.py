#!/usr/bin/env python3
"""Per-run analyzer for the n=4 PPTB single-machine beacon experiments.

Consumes one syncer log plus one node log and reports exactly the metrics the
evaluation needs:

  * TPS            -- beacon outputs per second (syncer "completed reconstruction"
                      events over the active window).
  * e2e latency    -- per batch (round), BATCH-START -> last beacon output.
  * breakdown      -- agreement window (BATCH-START -> ACS-DECIDE) and
                      reconstruction window (RECON-START -> last output).
  * elimination    -- first COMPLAINT / first BAN wall-clock offsets, and the
                      round at which the banned dealer leaves the decided set D.
  * per-round rows  -- untrimmed "ROUND,<r>,<e2e>,<agree>,<recon>" lines, so a
                      one-time cost can be read off the round it happened in.

Latency statistics skip the first/last `--warmup` rounds so startup and the
truncated final round do not distort steady-state numbers.
"""
import argparse
import re
import statistics
from datetime import datetime
from pathlib import Path

TS = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)")
BATCH_START = re.compile(r"\[PPT\]\[STAGE\]\[BATCH-START\].*round (\d+)")
ACS_DECIDE = re.compile(r"\[PPT\]\[STAGE\]\[ACS-DECIDE\].*round (\d+) dealers \[([0-9, ]*)\]")
RECON_START = re.compile(r"\[PPT\]\[STAGE\]\[RECON-START\].*round (\d+)")
RECON_DONE = re.compile(r"completed reconstruction for round (\d+) and index (\d+)")
# Despite its wording the line above fires at 2n/3 reports, so it can predate
# this node's own reconstruction. These two fire only once all n have reported.
ALL_DONE = re.compile(r"\[BEACON-(?:AGREE|DISAGREE)\] round (\d+) index (\d+)")
COMPLAINT = re.compile(r"\[PPT\]\[STAGE\]\[COMPLAINT\].*dealer (\d+)")
BAN = re.compile(r"\[PPT\]\[STAGE\]\[BAN\].*banned dealer (\d+)")

# Below this many surviving rounds the medians are noise, so say so loudly.
MIN_SAMPLES = 5


def ts(line):
    m = TS.search(line)
    return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%fZ") if m else None


def first_per_round(path, pat):
    out = {}
    for line in Path(path).read_text(errors="ignore").splitlines():
        m = pat.search(line)
        t = ts(line)
        if m and t:
            r = int(m.group(1))
            if r not in out:
                out[r] = t
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--syncer", required=True)
    ap.add_argument("--node", required=True)
    ap.add_argument("--batch", type=int, required=True)
    ap.add_argument("--label", default="run")
    ap.add_argument("--warmup", type=int, default=20)
    args = ap.parse_args()

    bs = first_per_round(args.node, BATCH_START)
    ad = first_per_round(args.node, ACS_DECIDE)
    rs = first_per_round(args.node, RECON_START)

    # Decided-set sizes per round, and last beacon-output time per round.
    dset = {}
    for line in Path(args.node).read_text(errors="ignore").splitlines():
        m = ACS_DECIDE.search(line)
        if m:
            r = int(m.group(1))
            members = [x for x in m.group(2).split(",") if x.strip() != ""]
            dset.setdefault(r, len(members))

    syncer_lines = Path(args.syncer).read_text(errors="ignore").splitlines()

    def completions(pat):
        last, events, times = {}, 0, []
        for line in syncer_lines:
            m = pat.search(line)
            t = ts(line)
            if m and t:
                r = int(m.group(1))
                events += 1
                times.append(t)
                if r not in last or t > last[r]:
                    last[r] = t
        return last, events, times

    # An all-n completion is never earlier than this node's own reconstruction,
    # so the windows below stay non-negative. Older logs only have the 2n/3 line.
    last_out, out_events, out_ts = completions(ALL_DONE)
    quorum_only = not last_out
    if quorum_only:
        last_out, out_events, out_ts = completions(RECON_DONE)

    # TPS over the active output window.
    tps = None
    if len(out_ts) >= 2:
        win = (max(out_ts) - min(out_ts)).total_seconds()
        tps = out_events / win if win > 0 else None

    all_rounds = sorted(r for r in bs if r in last_out)
    rounds = all_rounds
    if args.warmup > 0 and len(rounds) > 2 * args.warmup:
        rounds = rounds[args.warmup:-args.warmup]

    def stats(xs):
        xs = sorted(x for x in xs if x is not None and x >= 0)
        if not xs:
            return None
        n = len(xs)
        return {
            "n": n,
            "mean": statistics.mean(xs),
            "median": statistics.median(xs),
            "p95": xs[min(n - 1, int(0.95 * (n - 1)))],
        }

    e2e = [(last_out[r] - bs[r]).total_seconds() for r in rounds]
    agree = [(ad[r] - bs[r]).total_seconds() for r in rounds if r in ad]
    recon = [(last_out[r] - rs[r]).total_seconds() for r in rounds if r in rs]

    # stats() drops negatives, so say when that happened rather than silently
    # reporting a window over fewer rounds than the others.
    neg = sum(1 for xs in (e2e, agree, recon) for x in xs if x < 0)
    if neg:
        print(f"WARNING: dropped {neg} negative window(s) -- this node's markers were "
              "compared against a completion timestamp recorded before it finished")

    # Elimination markers (earliest across the node log provided).
    comp_ts = ban_ts = None
    banned = None
    for line in Path(args.node).read_text(errors="ignore").splitlines():
        if comp_ts is None and COMPLAINT.search(line):
            comp_ts = ts(line)
        mb = BAN.search(line)
        if mb and ban_ts is None:
            ban_ts = ts(line)
            banned = int(mb.group(1))
    evict_round = None
    if banned is not None:
        for r in sorted(dset):
            if dset[r] <= args.batch and banned is not None:
                pass
        # Round where decided-set size first drops (banned dealer excluded).
        sizes = [(r, dset[r]) for r in sorted(dset)]
        if sizes:
            base = max(s for _, s in sizes)
            for r, s in sizes:
                if s < base:
                    evict_round = r
                    break

    def fmt(s):
        return "NA" if s is None else f"{s*1000:.1f}ms(med {s and ''})"

    print(f"=== {args.label} (batch={args.batch}) ===")
    print(f"beacon outputs           : {out_events}"
          + (" (2n/3 quorum -- no all-n markers in this log)" if quorum_only else " (all n nodes)"))
    print(f"TPS (outputs/sec)        : {tps:.1f}" if tps else "TPS: NA")
    for name, s in (("e2e BATCH-START->out", stats(e2e)),
                    ("  agreement (->ACS)", stats(agree)),
                    ("  reconstruction", stats(recon))):
        if s:
            print(f"{name:24s}: median {s['median']*1000:7.1f} ms | mean {s['mean']*1000:7.1f} ms | p95 {s['p95']*1000:7.1f} ms | n={s['n']}")
        else:
            print(f"{name:24s}: NA")
    if comp_ts and bs:
        t0 = min(bs.values())
        print(f"first COMPLAINT at       : +{(comp_ts - t0).total_seconds()*1000:.0f} ms from first BATCH-START")
    if ban_ts and bs:
        t0 = min(bs.values())
        print(f"first BAN (dealer {banned}) at   : +{(ban_ts - t0).total_seconds()*1000:.0f} ms from first BATCH-START")
    if evict_round is not None:
        print(f"decided-set D shrinks at : round {evict_round} (banned dealer excluded)")

    # Untrimmed per-round rows. The verify+evict cost is a one-time event in the
    # eviction round, so it has to be read off that round directly -- a longer
    # run cannot produce a second sample of it, and the steady-state median
    # averages it away.
    def f6(x):
        return "" if x is None else f"{x:.6f}"

    for r in all_rounds:
        print("ROUND," + ",".join([
            str(r),
            f6((last_out[r] - bs[r]).total_seconds()),
            f6((ad[r] - bs[r]).total_seconds() if r in ad else None),
            f6((last_out[r] - rs[r]).total_seconds() if r in rs else None),
        ]))

    # Machine-readable one-liner for CSV aggregation.
    se = stats(e2e); sa = stats(agree); sr = stats(recon)
    if se is None or se["n"] < MIN_SAMPLES:
        got = 0 if se is None else se["n"]
        print(f"WARNING: only {got} round(s) left after trimming {args.warmup} per end "
              f"({len(bs)} BATCH-START, {len(last_out)} completed at the syncer) -- "
              f"raise RUNTIME before trusting these medians")
    print("CSV," + ",".join(str(x) for x in [
        args.label, args.batch, out_events,
        f"{tps:.3f}" if tps else "",
        f"{se['median']:.6f}" if se else "",
        f"{sa['median']:.6f}" if sa else "",
        f"{sr['median']:.6f}" if sr else "",
        se["n"] if se else 0,
    ]))


if __name__ == "__main__":
    main()
