# SECURITY_MODEL

## Status

This repository implements an academic PABS-CRF prototype. The current codebase
supports end-to-end experimentation, structured benchmarks, and artifact-style
evaluation. It does not claim production-grade cryptographic engineering.

## CRF Properties

The current re-randomization layer provides **signer-rerandomized output**
(CRF-enabled rerandomization), not a strong cryptographic reverse firewall:

- Goal: preserve verification compatibility while perturbing the published
  response vector.
- Non-goal: hide the original signer response from a public verifier.
- Consequence: if `crf_seed` is exposed, an external verifier can recover the
  base response used before rerandomization.

This means the present implementation should be described as
`signer-rerandomized output` (CRF-enabled rerandomization), not as a strong
privacy firewall.

**Strong CRF (Mironov-Stebila) distinction.** The Mironov-Stebila CRF
formalization requires that the rerandomized output is *statistically
indistinguishable* from an honest implementation's output—an
exfiltration-resistance guarantee. Our scheme does **not** achieve this property.
Our re-randomization layer provides *computational* indistinguishability of the
response component via CBD(η=2) masking. Claims of strong CRF, exfiltration
resistance, or Mironov-Stebila level privacy are not supported.

## Trapdoor Model

The trapdoor implementation uses a gadget-based prototype sampler:

- It is intended for system-level workflow validation.
- It is not a strict GPV short-basis sampler.
- Distributional guarantees should therefore be described as prototype-level,
  not as exact GPV-equivalent guarantees.

Any paper or report built on this artifact should keep the same terminology.

## Gaussian Parameter σ

The current implementation uses **σ = 100** as the default Gaussian parameter for the CDT discrete Gaussian sampler in `gaussian.rs`. This value is set via `with_sigma(100.0)` in the `TopTierParameterModel` construction and governs trapdoor preimage sampling across all parameter tiers. At σ = 100 the sampler produces preimages that satisfy the witness relation A·w = u_target with meaningfully stronger statistical properties than earlier prototypes, while keeping rejection rates and witness norms within practical bounds.

**Historical reference**: An earlier prototype used σ = 3.0, which was chosen purely for prototype tractability. σ = 3.0 is retained in code as the base-case struct literal but is immediately overridden by `.with_sigma(100.0)`; it serves only as an experimental comparison baseline and is **not** the active operating point.

**Theoretical requirement (MP12)**: Micciancio and Peikert [EUROCRYPT 2012] require for gadget-based trapdoor preimage sampling:
```
σ ≥ √(s₁²(R) + 1) · ω(√log n)
```
where s₁(R) is the largest singular value of the gadget matrix R. For R ∼ CBD(η=1) with dimension (k−1) × kℓ, s₁(R) ≈ √(kℓn) · √2 ≈ 90. With ω(√log 256) ≈ 4:
```
σ_required ≈ √(90² + 1) · 4 ≈ 360
```

The current σ = 100 is approximately **3.6× below** the MP12 theoretical requirement, a substantial improvement over the historical σ = 3.0 baseline (which was ~120× below).

**Security implications**:
- **EUF-CMA**: NOT affected. The preimage is still a valid short solution to (A, u_policy). Unforgeability relies on the ISIS hardness of finding any short solution, not on the statistical distribution of the preimage.
- **Privacy / Zero-Knowledge**: IMPROVED over σ = 3.0. At σ = 100 the preimage distribution provides meaningful computational preimage indistinguishability — the Gaussian noise is large enough to make distinguishing individual preimages a computationally hard problem under standard lattice assumptions. However, σ = 100 does not achieve full statistical closeness to D_{ℤ,σ_target} required by the MP12 framework; claims of strict "statistical zero-knowledge" or "GPV preimage indistinguishability" in the information-theoretic sense are not yet supported.
- **Honest claim**: "Gadget-based preimage sampling at σ = 100 (meaningful computational preimage indistinguishability; rigorous Micciancio-Peikert σ ≈ 360 left as future work)"

**Future work**: Reaching the full MP12 requirement of σ ≥ 360 would require re-selecting all parameters (β, γ₁, γ₂) to accommodate larger witness norms. This is deferred to a future implementation phase.

## GID Disclosure

The signer's global identifier (GID) is a 32-byte random value generated during
KeyGen and embedded in every signature. The GID is **public**: any verifier who
observes two signatures sharing the same GID can link them to the same signer.

**Consequences:**
- The scheme is **linkable**, not anonymous. Two signatures from the same user
  are trivially linkable via the embedded GID.
- This linkability is intentional: it enables accountability and prevents
  signature laundering across users.
- GID-binding also prevents cross-user preimage collusion: different GIDs produce
  distinct target vectors `u_i = H_target(attr_i || gid)`, so preimages from
  different users cannot be combined.

Any paper or report built on this artifact should describe the scheme as
**linkable PABS** (not anonymous ABS). Claims of signer anonymity within
satisfying attribute sets are not supported.

## Signature Semantics

The signing path currently uses bounded masking plus rejection-style checks, but
it does not yet claim a fully rewritten centered-integer response path matching
strict ML-DSA semantics. Performance or correctness claims should therefore be
stated as implementation-level observations for this prototype.

## Safe Claims

The following claims are consistent with the current code:

- academic implementation
- proof-of-concept
- structured benchmark artifact
- policy-aware overhead evaluation
- signer-rerandomized output (CRF-enabled rerandomization)
- linkable PABS (GID is public; scheme is not anonymous)

## Claims To Avoid

The following claims are not supported by the present artifact:

- strict GPV trapdoor sampling
- strong firewall privacy against public recovery
- strong CRF / Mironov-Stebila exfiltration resistance
- production-grade ML-DSA-equivalent engineering
- exact security-level labeling beyond the implemented parameter sets
- signer anonymity within satisfying attribute sets
