# Benchmark Inventory

The public artifact provides three complementary evaluation paths.

| Path | Purpose | Main output |
| --- | --- | --- |
| Quickstart | Functional setup/sign/verify check | Console success or failure |
| Comprehensive runner | Local multi-configuration measurements | Structured records and logs |
| Native ARM64 workflow | Cross-architecture PABS/ML-DSA comparison | JSON timings, resource records, runner manifest |

## Metrics

The benchmark code reports:

- key generation, signing, and verification time;
- verification success for every measured scheme;
- peak process resource usage on the ARM64 workflow;
- platform, CPU, memory, Rust, Cargo, and commit metadata.

## Interpretation

The benchmark is an academic reproducibility aid, not a production security or
certification result. Comparisons are meaningful only when schemes use matched
security tiers, the same iteration count, release builds, and the same runner.
Raw records should be retained with any table or claim derived from them.

See [BENCHMARK_GUIDE.md](BENCHMARK_GUIDE.md) for commands and workflow details.
