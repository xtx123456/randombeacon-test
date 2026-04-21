#!/usr/bin/env python3
import csv
import re
import statistics
import sys
from datetime import datetime
from pathlib import Path


TS_PAT = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)")
SYNC_BATCH_PAT = re.compile(r"All n nodes completed round (\d+)")
SYNC_RECON_PAT = re.compile(r"All n nodes completed reconstruction for round (\d+) and index (\d+)")

PPT_STAGE_PATS = {
    "batch_start": re.compile(r"\[PPT\]\[STAGE\]\[BATCH-START\].*round (\d+)"),
    "acs_decide": re.compile(r"\[PPT\]\[STAGE\]\[ACS-DECIDE\].*round (\d+)"),
    "recon_start": re.compile(r"\[PPT\]\[STAGE\]\[RECON-START\].*round (\d+)"),
    "beacon_out": re.compile(r"\[PPT\]\[STAGE\]\[BEACON-OUT\].*round (\d+) coin (\d+)"),
}

BEA_STAGE_PATS = {
    "batch_start": re.compile(r"\[BEA\]\[STAGE\]\[BATCH-START\].*round (\d+)"),
    "gather_ready": re.compile(r"\[BEA\]\[STAGE\]\[GATHER-READY\].*round (\d+)"),
    "recon_start": re.compile(r"\[BEA\]\[STAGE\]\[RECON-START\].*round (\d+) coin (\d+)"),
    "beacon_out": re.compile(r"\[BEA\]\[STAGE\]\[BEACON-OUT\].*round (\d+) coin (\d+)"),
}


PHASE_CONFIG = {
    "ppt": {
        "preprocess": {"source": "batch_complete", "anchor": "batch_start"},
        "subset_convergence": {"source": "acs_decide", "anchor": "batch_start"},
        "reconstruction": {"source": "recon_complete", "anchor": "recon_start"},
        "beacon_output": {"source": "beacon_out", "anchor": "recon_start"},
    },
    "bea": {
        "preprocess": {"source": "batch_complete", "anchor": "batch_start"},
        "subset_convergence": {"source": "gather_ready", "anchor": "batch_start"},
        "reconstruction": {"source": "recon_complete", "anchor": "recon_start"},
        "beacon_output": {"source": "beacon_out", "anchor": "recon_start"},
    },
}


def parse_ts(line: str):
    m = TS_PAT.search(line)
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%fZ")


def active_window_sec(ts_list):
    if len(ts_list) < 2:
        return None
    return (ts_list[-1] - ts_list[0]).total_seconds()


def throughput(units, seconds):
    if seconds is None or seconds <= 0:
        return None
    return units / seconds


def fmt(x):
    if x is None:
        return ""
    return f"{x:.6f}"


def units_per_event(source: str, batch_size: int) -> int:
    if source in ("batch_start", "batch_complete", "acs_decide", "gather_ready"):
        return batch_size
    return 1


def percentile(sorted_vals, p: float):
    if not sorted_vals:
        return None
    idx = max(0, min(len(sorted_vals) - 1, int(p * (len(sorted_vals) - 1))))
    return sorted_vals[idx]


def duration_stats(seconds_list):
    if not seconds_list:
        return {
            "matched_count": 0,
            "mean": None,
            "median": None,
            "p95": None,
            "max": None,
        }
    vals = sorted(seconds_list)
    return {
        "matched_count": len(vals),
        "mean": statistics.mean(vals),
        "median": statistics.median(vals),
        "p95": percentile(vals, 0.95),
        "max": vals[-1],
    }


def collect_syncer_events(syncer_log: Path):
    out = {
        "batch_complete": [],
        "recon_complete": [],
    }
    with syncer_log.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            ts = parse_ts(line)
            if ts is None:
                continue

            m = SYNC_BATCH_PAT.search(line)
            if m:
                round_id = int(m.group(1))
                out["batch_complete"].append(((round_id,), ts))
                continue

            m = SYNC_RECON_PAT.search(line)
            if m:
                round_id = int(m.group(1))
                coin = int(m.group(2))
                out["recon_complete"].append(((round_id, coin), ts))
    return out


def collect_node_events(node_log: Path, protocol: str):
    patterns = PPT_STAGE_PATS if protocol == "ppt" else BEA_STAGE_PATS
    out = {name: [] for name in patterns.keys()}
    with node_log.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            ts = parse_ts(line)
            if ts is None:
                continue
            for stage, pat in patterns.items():
                m = pat.search(line)
                if not m:
                    continue
                if stage in ("beacon_out",):
                    round_id = int(m.group(1))
                    coin = int(m.group(2))
                    out[stage].append(((round_id, coin), ts))
                else:
                    round_id = int(m.group(1))
                    out[stage].append(((round_id,), ts))
                break
    return out


def ensure_header(csv_path: Path):
    if csv_path.exists():
        return
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "protocol",
            "batch",
            "phase",
            "event_source",
            "anchor_source",
            "event_count",
            "units_per_event",
            "total_units",
            "wall_throughput",
            "active_window_sec",
            "active_throughput",
            "matched_latency_count",
            "latency_mean_sec",
            "latency_median_sec",
            "latency_p95_sec",
            "latency_max_sec",
            "first_ts",
            "last_ts",
        ])


def build_anchor_lookup(anchor_events):
    exact = {}
    by_round = {}
    for key, ts in anchor_events:
        exact.setdefault(key, ts)
        by_round.setdefault((key[0],), ts)
    return exact, by_round


def match_latency_seconds(source_events, anchor_events):
    exact_anchor, round_anchor = build_anchor_lookup(anchor_events)
    deltas = []
    for key, source_ts in source_events:
        anchor_ts = exact_anchor.get(key)
        if anchor_ts is None:
            anchor_ts = round_anchor.get((key[0],))
        if anchor_ts is None:
            continue
        delta = (source_ts - anchor_ts).total_seconds()
        if delta >= 0:
            deltas.append(delta)
    return deltas


def main():
    if len(sys.argv) != 6:
        print(
            "usage: stage_throughput.py <syncer_log> <node0_log> <protocol> <batch_size> <output_csv>",
            file=sys.stderr,
        )
        return 1

    syncer_log = Path(sys.argv[1])
    node_log = Path(sys.argv[2])
    protocol = sys.argv[3]
    batch_size = int(sys.argv[4])
    out_csv = Path(sys.argv[5])

    syncer_events = collect_syncer_events(syncer_log)
    node_events = collect_node_events(node_log, protocol)
    all_events = {}
    all_events.update(node_events)
    all_events.update(syncer_events)

    ensure_header(out_csv)

    rows = []
    for phase, cfg in PHASE_CONFIG[protocol].items():
        source = cfg["source"]
        anchor = cfg["anchor"]
        event_pairs = all_events.get(source, [])
        if not event_pairs:
            continue

        ts_list = sorted(ts for _, ts in event_pairs)
        event_units = units_per_event(source, batch_size)
        total_units = len(ts_list) * event_units
        wall_tp = throughput(
            total_units,
            (ts_list[-1] - ts_list[0]).total_seconds() if len(ts_list) >= 2 else None,
        )
        active_sec = active_window_sec(ts_list)
        active_tp = throughput(total_units, active_sec)

        latency = duration_stats(
            match_latency_seconds(event_pairs, all_events.get(anchor, []))
        )

        rows.append([
            protocol,
            batch_size,
            phase,
            source,
            anchor,
            len(ts_list),
            event_units,
            total_units,
            fmt(wall_tp),
            fmt(active_sec),
            fmt(active_tp),
            latency["matched_count"],
            fmt(latency["mean"]),
            fmt(latency["median"]),
            fmt(latency["p95"]),
            fmt(latency["max"]),
            ts_list[0].isoformat() + "Z",
            ts_list[-1].isoformat() + "Z",
        ])

    with out_csv.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

    for row in rows:
        print(
            f"{row[0]} batch={row[1]} phase={row[2]} source={row[3]} active_tp={row[10] or 'NA'} latency_mean={row[12] or 'NA'} matched={row[11]}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
