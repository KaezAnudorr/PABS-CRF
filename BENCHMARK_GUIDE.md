# PABS-CRF Benchmark Guide

This guide describes the reproducible benchmark paths included in the repository.
All reported timings should come from release builds on an otherwise idle machine.

## Quick functional check

```bash
cargo run --release --example quickstart
```

## Matched PABS and ML-DSA baseline

The matched baseline executable measures one configuration per process. Use
`PABS_BENCH_ITERS` to set the number of timed signing and verification
iterations.

```bash
cargo build --locked --release --example matched_mldsa_baseline
PABS_BENCH_ITERS=100 cargo run --locked --release --example matched_mldsa_baseline -- pabs-128
PABS_BENCH_ITERS=100 cargo run --locked --release --example matched_mldsa_baseline -- mldsa-44
```

Supported configurations are `pabs-128`, `pabs-192`, `pabs-256`,
`mldsa-44`, `mldsa-65`, and `mldsa-87`.

## Comprehensive benchmark

```bash
python3 scripts/run_comprehensive_benchmark.py --rounds 10
```

The runner records the operating system, architecture, CPU model, memory,
Rust version, Git commit, per-operation timings, and cache statistics.

## Native ARM64 benchmark

Open **Actions -> Native ARM64 benchmark -> Run workflow** on GitHub. The
workflow runs on Ubuntu 24.04 ARM64 and:

1. records the runner manifest;
2. builds the release benchmark;
3. measures all six PABS/ML-DSA configurations in separate processes;
4. validates every JSON timing record;
5. uploads the raw evidence as a downloadable artifact for 90 days.

The default is 100 timed signing and verification iterations per scheme.

## Reproducibility rules

- Use the committed `Cargo.lock` with `--locked`.
- Record the exact Git commit and runner manifest.
- Use separate processes for different schemes.
- Keep the machine idle and avoid mixing debug and release measurements.
- Report units, iteration counts, and failures together with the timing values.
