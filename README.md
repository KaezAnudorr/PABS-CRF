# PABS-CRF

[![CI](https://github.com/KaezAnudorr/PABS-CRF/actions/workflows/ci.yml/badge.svg)](https://github.com/KaezAnudorr/PABS-CRF/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)

Research implementation of a lattice-based predicate attribute-based signature
(PABS) scheme with a cryptographic reverse firewall (CRF). The artifact provides
a Rust implementation of the `setup -> keygen -> sign -> verify` workflow,
attribute-policy evaluation, key puncturing, signature rerandomization, and
compressed signature transport.

> [!IMPORTANT]
> This repository is an academic research prototype. It has not received an
> independent security audit and must not be used to protect production data or
> systems. The 128/192/256 labels identify experimental parameter profiles; they
> are not claims of standards certification or production-ready security.

## Highlights

- Module-LWE-oriented PABS research implementation in Rust
- `AND`/`OR` attribute policies represented through LSSS structures
- Structured v4 API plus compatibility wrappers for the earlier map-based API
- Key puncturing and puncture-state tests
- Cryptographic reverse-firewall transformation path
- Compressed signature serialization and validation
- Experimental parameter profiles for 128, 192, and 256-bit targets
- Correctness, negative-security, regression, and benchmark test suites

## Requirements

- A recent stable [Rust toolchain](https://www.rust-lang.org/tools/install)
- Cargo, installed with Rust
- Optional: Python 3 for benchmark orchestration
- Optional: SageMath for the lattice-estimator helper

The repository is developed with Rust 2021 edition. Linux, macOS, and Windows
are supported by the core crate; platform-specific benchmark scripts may require
Bash, PowerShell, or Linux utilities.

## Quick start

```bash
git clone https://github.com/KaezAnudorr/PABS-CRF.git
cd PABS-CRF
cargo build --release --locked
cargo run --release --example quickstart
```

The quick-start example uses the preferred structured API:

```rust
use pabs_crf::keygen::KeyGen;
use pabs_crf::setup::Setup;
use pabs_crf::sign::sign_structured;
use pabs_crf::verify::verify_signature_struct;
use pabs_crf::{PabsCrfResult, Policy};

fn main() -> PabsCrfResult<()> {
    let setup = Setup::new();
    let keygen = KeyGen::new();

    let (public_parameters, master_secret_key) =
        setup.try_generate_structured(128)?;
    let user_secret_key = keygen.try_generate_structured(
        &public_parameters,
        &master_secret_key,
        &["admin", "finance"],
    )?;

    let policy = Policy::parse("admin AND finance")?;
    let message = b"PABS-CRF research artifact";
    let signature = sign_structured(&user_secret_key, message, &policy, 0)?;

    assert!(verify_signature_struct(
        &public_parameters,
        message,
        &policy,
        &signature,
    )?);

    Ok(())
}
```

## Testing

Run the default correctness and security-oriented test suite:

```bash
cargo test --locked
```

Performance thresholds are intentionally excluded from the default test run
because debug builds and host hardware are not comparable. Run the NTT
performance check explicitly in release mode:

```bash
cargo test --release --test ntt_benchmark benchmark_ntt_performance -- --ignored --nocapture
```

Some expensive known-answer tests are also ignored by default. Run the
256-bit KAT cases explicitly in release mode:

```bash
cargo test --release --locked --test kat_vectors -- --ignored
```

## Benchmarks

The main Criterion benchmarks can be run with:

```bash
cargo bench --locked
```

For the cross-configuration benchmark suite and raw result layout, see
[BENCHMARK_GUIDE.md](BENCHMARK_GUIDE.md). Benchmark results should always report
the host CPU, compiler version, operating mode, cache state, number of
iterations, and whether compressed verification was measured.

## Repository structure

```text
.
|-- src/                 Core scheme, algebra, CRF, and serialization modules
|-- tests/               Correctness, security, regression, and KAT tests
|-- examples/            Quick start, audits, and performance examples
|-- benches/             Criterion and workload benchmarks
|-- scripts/             Benchmark and estimator automation
|-- .github/workflows/   Continuous integration and manual ARM64 benchmark
|-- IMPLEMENTATION_SCOPE.md
|-- SECURITY_MODEL.md
`-- Cargo.toml
```

## Scope and limitations

The artifact is intended to support research validation and reproducible
experimentation. Please read [IMPLEMENTATION_SCOPE.md](IMPLEMENTATION_SCOPE.md)
and [SECURITY_MODEL.md](SECURITY_MODEL.md) before interpreting security or
performance results. In particular:

- the default fast mode prioritizes research experimentation;
- strict sampling mode has different performance and rejection behavior;
- benchmark comparisons do not imply equivalence with standardized or audited
  ML-DSA implementations;
- constant-time behavior and the complete construction have not been
  independently verified.

## Citation

If you use this code in academic work, please cite the accompanying paper. The
final BibTeX entry, paper URL, and DOI will be added here when they are publicly
available. Until then, cite this repository with its URL and the commit hash used
for your experiments.

## License

This project is released under the [MIT License](LICENSE).
