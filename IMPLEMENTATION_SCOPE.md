# IMPLEMENTATION_SCOPE

## Purpose

This repository is maintained as a research artifact for validating the
PABS-CRF workflow, policy integration, compression path, and rerandomization
interface under lattice-based components.

## Core Scope

The current implementation is intended to provide:

- structured `setup -> keygen -> sign -> verify` execution
- compatibility wrappers for legacy `HashMap<String, Vec<u8>>` callers
- benchmarkable signing, verification, and compressed verification paths
- explicit cache management hooks for policy and NTT preprocessing

## Explicitly Out Of Scope

The current codebase does not yet aim to provide:

- production-grade side-channel hardening
- strict GPV-distribution preimage sampling
- irreversible CRF privacy protection
- formally audited parameter labeling across multiple security tiers

## Architectural Direction

The preferred development direction is:

- keep structured objects as the primary API surface
- isolate legacy maps inside the compatibility layer
- keep cache logic observable and manually clearable for benchmark hygiene
- separate artifact claims from cryptographic aspirations not yet realized in code

## Current Engineering Decisions

- `compat` isolates legacy map conversion from the main cryptographic flow.
- `lsss` caches are bounded and expose clear/stat hooks.
- MLWE NTT caches are bounded and keyed with deterministic SHA-256 digests
  instead of process-local hasher output.
- Gaussian parameter σ defaults to **100** across all security tiers. The
  `TopTierParameterModel` base constructors (`for_security_level`) pass
  `sigma = 100.0` to `with_sigma()`, which proportionally scales the masking
  bound γ₁ to accommodate larger witness norms. This replaces the earlier
  σ = 3.0 baseline (retained only as the struct literal default that is
  immediately overridden). See `SECURITY_MODEL.md` for the security rationale
  and the gap to the full MP12 requirement (σ ≈ 360).
- **Operating Modes**: The scheme supports two operating modes via `TopTierParameterModel`:
  - *Fast mode* (`for_security_level`, default): Uses $\sigma = 100$, providing computational
    indistinguishability for the re-randomization layer. This is the benchmark default and
    appropriate for academic prototyping.
  - *Strict mode* (`for_security_level_strict`): Uses $\sigma = 360$, meeting the
    Micciancio-Peikert bound for meaningful statistical preimage indistinguishability.
    Strict mode increases signature rejection rate and signing latency but strengthens
    privacy claims. Use `for_security_level_strict(level)` to enable.

## Guidance For Benchmarks And Papers

When reporting results derived from this repository:

- label the artifact as an academic prototype
- state whether cache measurements are cold or warm
- state whether compressed verification is included
- avoid implying equivalence with industrial ML-DSA implementations
