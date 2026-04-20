# PPT Beacon

This repository contains a Rust implementation of a **PPT-style hash-based asynchronous random beacon**.

The implementation is built around the following ideas:

- **Hash-based beacon construction**
- **ACS-driven selection**
- **Batch randomness reconstruction**
- **Post-ACS complaint / accountability**
- **Two-field optimization for low-entropy beacon values**
- **Batched network delivery for reconstruction packets**

This codebase is derived from the original HashRand-style project structure, but the current `ppt_beacon` module is intended to implement the **PPT protocol path** rather than the legacy HashRand path.

## Main idea

At a high level, the protocol works as follows:

1. Nodes run sharing / AVSS-related steps for candidate beacon contributions.
2. After enough instances complete, nodes enter **ACS** and agree on the set of completed dealers.
3. Only the dealers selected by ACS are reconstructed.
4. Reconstruction is performed in **batch**, using a super-inverse-matrix style extraction method.
5. After recovery, nodes multicast the recovered shares for **post-ACS complaint / accountability**.
6. The recovered randomness is used for beacon output and committee handoff.

## Current implementation highlights

Compared with the older HashRand-style flow, the current `ppt_beacon` path includes:

- **ACS as the main agreement layer**
- **Pure PPT-style round progression**
- **Batched `BeaconConstruct` messages**
- **Batched recovery of multiple coins**
- **Ready-coin based recovery trigger**
- **Complaint moved after ACS**
- **Two-field degree testing support**
- **Hash / Merkle based commitment verification**

## Repository structure

The most important module is:

- `consensus/ppt_beacon/` — main PPT beacon implementation

Useful submodules include:

- `src/node/process.rs` — protocol message dispatch and ACS decision handling
- `src/node/gather/` — witness / gather logic before ACS
- `src/node/acs/` — ACS state machine
- `src/node/batch_wss/secret_reconstruct.rs` — batch reconstruction and post-complaint logic
- `src/node/shamir/two_field.rs` — two-field sharing and batch extraction utilities
- `src/node/ctrbc/` — round state and commitment-related state

## Build

```bash
cargo build --release
```

## Run a simple local PPT test

```bash
bash run_ppt_test.sh
```

## Run benchmark

```bash
bash run_benchmark.sh
```

This will run the local benchmark sweep and collect results under `bench_results/`.

## Notes

- The codebase still inherits some structure from the original project layout.
- The active protocol path for this work is `ppt_beacon`.
- Benchmark behavior depends on the current output policy and logging configuration.
- This repository is primarily intended for **protocol research, implementation, and evaluation**, rather than production deployment.

## Summary

This project implements a **hash-based asynchronous random beacon following the PPT design direction**, with ACS-based dealer selection, batched reconstruction, post-ACS accountability, and two-field optimization.
