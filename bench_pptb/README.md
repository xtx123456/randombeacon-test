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
