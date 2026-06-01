## Cursor Cloud specific instructions

### Product overview

Rust workspace implementing a **PPT-style hash-based asynchronous random beacon** (`consensus/ppt_beacon/`). The runnable binary is `node` (4 consensus nodes + 1 syncer on localhost). See `README.md` for protocol context.

### System dependencies (one-time on a fresh VM)

- **GMP**: `sudo apt-get install -y libgmp-dev` (required to link `node`; missing `-lgmp` otherwise).
- **Rust 1.70.0**: The default toolchain (1.83+) fails on transitive `rustc-serialize` 0.3.24. Use `rustup toolchain install 1.70.0` and `rustup override set 1.70.0` in `/workspace` before building.

### Build

```bash
cargo build --release -p node
```

Full workspace release build: `cargo build --release`.

### Tests

```bash
cargo test --release --lib
```

`cargo test --release` (with doctests) fails on the `crypto` crate doc-test ambiguity; library unit tests pass (including `ppt_beacon` two-field / batch extractor tests).

Optional lint: `cargo clippy -p ppt_beacon --release` (warnings only).

### Run local PPT demo (hello-world)

From repo root, after building:

```bash
bash scripts/beacon-test.sh testdata/cc_4/syncer ppt 20 10
```

This starts 5 processes (syncer on `nodes-0.json` with `--vsstype sync`, four nodes with `--vsstype ppt`). Logs go to `logs/syncer.log` and `logs/{0..3}.log`. Expect `[PPT]` lines: round start, AVSS complete, ACS decide, batch reconstruction.

Stop cluster: `pkill -f "/target/release/node"`.

**Note:** `run_ppt_test.sh` hardcodes `cd /home/ubuntu/hashrand-p3-main`; prefer `scripts/beacon-test.sh` from `/workspace`.

### Benchmarks (optional)

`bash run_benchmark.sh` / `bench_ppt_local.sh` — Python viz deps in `benchmark/requirements.txt` (`pip install -r benchmark/requirements.txt`).

### Services

| Service | Required? | How |
|--------|-----------|-----|
| Local `node` cluster (ports in `ip_file`) | Yes, for E2E demo | `scripts/beacon-test.sh` |
| External DB / Docker | No | — |

No long-running dev server; nodes are the application.
