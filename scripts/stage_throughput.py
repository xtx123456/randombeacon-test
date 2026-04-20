#!/usr/bin/env python3
import csv
import re
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


def stage_units_per_event(protocol: str, stage: str, batch_size: int) -> int:
    if stage in ("batch_start", "batch_complete", "acs_decide", "gather_ready"):
        return batch_size
    if protocol == "ppt" and stage == "recon_start":
        return batch_size
    return 1


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
            if SYNC_BATCH_PAT.search(line):
                out["batch_complete"].append(ts)
                continue
            if SYNC_RECON_PAT.search(line):
                out["recon_complete"].append(ts)
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
                if pat.search(line):
                    out[stage].append(ts)
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
            "stage",
            "event_count",
            "units_per_event",
            "total_units",
            "wall_throughput",
            "active_window_sec",
            "active_throughput",
            "first_ts",
            "last_ts",
        ])


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
    for stage, ts_list in all_events.items():
        if not ts_list:
            continue
        ts_list = sorted(ts_list)
        units_per_event = stage_units_per_event(protocol, stage, batch_size)
        total_units = len(ts_list) * units_per_event
        wall_tp = throughput(total_units, (ts_list[-1] - ts_list[0]).total_seconds() if len(ts_list) >= 2 else None)
        active_sec = active_window_sec(ts_list)
        active_tp = throughput(total_units, active_sec)
        rows.append([
            protocol,
            batch_size,
            stage,
            len(ts_list),
            units_per_event,
            total_units,
            fmt(wall_tp),
            fmt(active_sec),
            fmt(active_tp),
            ts_list[0].isoformat() + "Z",
            ts_list[-1].isoformat() + "Z",
        ])

    with out_csv.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

    for row in rows:
        print(
            f"{row[0]} batch={row[1]} stage={row[2]} events={row[3]} units={row[5]} active_tp={row[8] or 'NA'}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
