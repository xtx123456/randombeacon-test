# PPTB single-machine evaluation (n=4, f=1)

Measures the three metrics requested for the PraHRand evaluation:

1. **Batch-size sweet spot** — throughput (beacon outputs/s) vs per-batch latency as
   batch size `B` varies.
2. **Latency breakdown** — per batch, split into the agreement window
   (`BATCH-START -> ACS decide D`) and the reconstruction window
   (`RECON-START -> last beacon output`).
3. **Player-elimination overhead** — honest run vs one-bad-dealer run at a fixed
   batch: does verifying and evicting a faulty dealer add latency on the critical
   path?

All runs are `n=4, f=1`, one machine, 4 node processes + 1 syncer, transport
`secmsg` (the transport that carries transferable complaint evidence and so
exercises the complaint -> audit -> ban path).

## Build

The workspace pulls in a legacy BLS comparison baseline (`curv`/`rust-crypto`)
that only compiles on older Rust and needs the GMP library:

```bash
rustup toolchain install 1.65.0 --profile minimal
rustup override set 1.65.0                 # inside the repo
# GMP without root: link the runtime lib under a dev-style name
mkdir -p /tmp/gmplink && ln -sf /usr/lib/x86_64-linux-gnu/libgmp.so.10 /tmp/gmplink/libgmp.so
LIBRARY_PATH=/tmp/gmplink cargo +1.65.0 build --release
```

## Run

```bash
# Full sweep (sweet spot + elimination overhead), ~6 min:
RUNTIME=30 BATCHES="1 4 8 16 32 64 128 256" ELIM_BATCH=32 bash bench_pptb/sweep.sh

# One honest run at a given batch:
bash bench_pptb/run_once.sh 32 10 30 secmsg bench_pptb/results/manual honest_b32

# One run with node 3 as a bad dealer (injects inconsistent shares every round):
bash bench_pptb/run_once.sh 32 10 30 secmsg bench_pptb/results/manual faulty_b32 3

# Figures from a summary.csv:
python3 bench_pptb/plot.py bench_pptb/results/<stamp>/summary.csv /opt/cursor/artifacts
```

Arguments to `run_once.sh`: `<batch> <freq> <runtime_sec> <transport> <outdir> <label> [faulty_dealer_id]`.

## Heatmaps (batch sweet-spot trade-off)

Two sweeps render the HashRand-Figure-3-style heatmap (color = throughput,
cell text = throughput + median end-to-end latency, y-axis = batch size):

```bash
# x-axis = injected one-way network delay (needs root + CAP_NET_ADMIN + sch_netem):
DELAYS="0 10 30 60" RUNTIME=180 BATCHES="8 32 64 128 256" bash bench_pptb/netem_sweep.sh

# x-axis = committee size n (no privileges/netem needed; runs anywhere):
NODES="4 7 13 16 22 31" RUNTIME=180 BATCHES="8 32 64 128 256" bash bench_pptb/nodes_sweep.sh
```

`netem_sweep.sh` emulates the delay with `tc netem` on `lo`, so it only works on
a host where you have root and the kernel exposes `sch_netem` (a shared container
such as AutoDL that lacks `CAP_NET_ADMIN` cannot run it). `nodes_sweep.sh` varies
the committee size instead, so it has no such requirement; node counts must be of
the form `n=3f+1` (4, 7, 10, 13, 16, ...) and missing config dirs are generated
on the fly with `genconfig`. Each sweep writes `heatmap.csv` + a rendered PNG
under `bench_pptb/results/`; `heatmap.py --xcol {delay_ms,nodes}` renders either.

## Latency breakdown (at the sweet spot)

The agreement vs reconstruction split that `analyze.py` reports per run is saved
in every run dir's `metrics.txt` (the `CSV,...` line's `agree_s` / `recon_s`
fields). `breakdown.py` turns those into the stacked per-batch breakdown figure
without re-running anything — point it at a sweep's results dir and a run-label
prefix:

```bash
# node-count sweep, the n=16 series:
python3 bench_pptb/breakdown.py --results bench_pptb/results/nodes_heatmap_<stamp> \
    --prefix n16_b --out ~/breakdown_n16.png --title "PraHRand n=16 latency breakdown"

# netem sweep, the 0 ms-delay series:
python3 bench_pptb/breakdown.py --results bench_pptb/results/heatmap_<stamp> \
    --prefix d0_b --out ~/breakdown_d0.png
```

Each bar stacks agreement (BATCH-START -> ACS decide D), the transform/setup gap
(ACS-decide -> recon-start), and reconstruction (RECON-START -> last output), so
the bars add up to the end-to-end latency.

## Fault injection

Set `PPT_FAULTY_DEALER=<id>` (comma list allowed) in a node's environment. That
node, when acting as dealer, corrupts one recipient's already-committed share
bytes (`PPT_FAULT_VICTIM` overrides the default victim `(id+1) mod n`). The
public Merkle roots stay honest, so the victim becomes unhappy, files a post-ACS
complaint, and the complaint-driven audit attributes the fault and bans the
dealer. The switch is a no-op when the variable is unset, so honest benchmarks
are unaffected.

Markers added for measurement: `[PPT][STAGE][COMPLAINT]`, `[PPT][STAGE][BAN]`,
and the existing `[PPT][STAGE][BATCH-START|ACS-DECIDE|RECON-START]`.
