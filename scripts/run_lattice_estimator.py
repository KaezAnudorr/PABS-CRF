#!/usr/bin/env python3
"""
Lattice Security Estimator for PABS-CRF Scheme Parameters

This script estimates the lattice-based security of the MLWE parameters used
in the PABS-CRF scheme across three security levels (128/192/256-bit).

Methodology:
  - Core-SVP model (ADPS16) for classical and quantum costs
  - Primal uSVP attack estimation
  - Dual attack estimation
  - Root Hermite factor based BKZ cost analysis

References:
  [USENIX:ADPS16] Albrecht et al., "Estimating quantum resistance for lattice attacks", 2016
  [PhD:Chen13]    Chen, "Lattice Reduction and Cryptanalysis", 2013
  [AC:AlbPliSco15] Albrecht, Player, Scott, "On the Concrete Hardness of LWE", 2015

Extracted from academic_implementation_v4/src/mlwe.rs:
  - 128-bit: k=4, n=256, q=8380417, eta=2, tau=39
  - 192-bit: k=6, n=256, q=8380417, eta=2, tau=49
  - 256-bit: k=8, n=256, q=8380417, eta=2, tau=60
"""

import math
import sys
from dataclasses import dataclass, field
from typing import List, Tuple, Optional


# ============================================================================
# Root Hermite Factor (δ₀) from BKZ block size β
# ============================================================================

# Lookup table for β ≤ 40 (from lattice-estimator reduction.py)
_SMALL_DELTA = {
    2: 1.02190, 5: 1.01862, 10: 1.01616, 15: 1.01485,
    20: 1.01420, 25: 1.01342, 28: 1.01331, 40: 1.01295,
}
_SMALL_KEYS = sorted(_SMALL_DELTA.keys())


def root_hermite_factor(beta: int) -> float:
    """Compute root Hermite factor δ₀ from BKZ block size β."""
    if beta <= 2:
        return 1.02190
    if beta < 40:
        for i in range(1, len(_SMALL_KEYS)):
            if _SMALL_KEYS[i] > beta:
                return _SMALL_DELTA[_SMALL_KEYS[i - 1]]
    if beta == 40:
        return _SMALL_DELTA[40]
    return ((beta / (2 * math.pi * math.e)) * (math.pi * beta) ** (1.0 / beta)) ** (
        1.0 / (2 * (beta - 1))
    )


def beta_from_delta(delta: float) -> int:
    """Invert root Hermite factor to find BKZ block size β."""
    if delta >= 1.02190:
        return 2
    for b in range(40, 4096):
        if root_hermite_factor(b) < delta:
            return b
    return 4096


# ============================================================================
# SVP Cost Models (ADPS16)
# ============================================================================

def svp_cost_classical(beta: int) -> float:
    """Classical SVP cost for BKZ-β: 2^(0.292·β)"""
    return 0.292 * beta


def svp_cost_quantum(beta: int) -> float:
    """Quantum SVP cost for BKZ-β: 2^(0.265·β)"""
    return 0.265 * beta


def svp_cost_paranoid(beta: int) -> float:
    """Paranoid (optimistic) SVP cost: 2^(0.2075·β)"""
    return 0.2075 * beta


def bkz_svp_repeat(beta: int, d: int) -> int:
    """Number of SVP calls in BKZ-β for lattice dimension d."""
    if beta < d:
        return 8 * d
    return 1


# ============================================================================
# LWE / MLWE Parameter Model
# ============================================================================

@dataclass
class MLWEParams:
    """MLWE parameters for the PABS-CRF scheme."""
    name: str
    k: int           # Module rank
    n: int           # Polynomial degree (ring dimension)
    q: int           # Modulus
    eta1: int        # Secret key CBD parameter
    eta2: int        # Error CBD parameter
    tau: int         # Challenge Hamming weight
    beta: int        # Norm bound = tau * eta_max
    sigma: float     # Gaussian noise std dev (for estimation)
    target_bits: int # Target security level

    @property
    def lwe_n(self) -> int:
        """Total LWE secret dimension (k × n)."""
        return self.k * self.n

    @property
    def sigma_s(self) -> float:
        """Standard deviation of secret distribution CBD(η1)."""
        return math.sqrt(self.eta1 / 2.0)

    @property
    def sigma_e(self) -> float:
        """Standard deviation of error distribution CBD(η2)."""
        return math.sqrt(self.eta2 / 2.0)


# ============================================================================
# Parameter Sets (from mlwe.rs)
# ============================================================================

PARAMS_128 = MLWEParams(
    name="PABS-CRF-128 (ML-DSA-44 eq.)",
    k=4, n=256, q=8380417,
    eta1=2, eta2=2, tau=39, beta=78,
    sigma=3.0, target_bits=128,
)

PARAMS_192 = MLWEParams(
    name="PABS-CRF-192 (ML-DSA-65 eq.)",
    k=6, n=256, q=8380417,
    eta1=2, eta2=2, tau=49, beta=98,
    sigma=3.0, target_bits=192,
)

PARAMS_256 = MLWEParams(
    name="PABS-CRF-256 (ML-DSA-87 eq.)",
    k=8, n=256, q=8380417,
    eta1=2, eta2=2, tau=60, beta=120,
    sigma=3.0, target_bits=256,
)


# ============================================================================
# Primal uSVP Attack Estimation
# ============================================================================

def estimate_primal_usvp(params: MLWEParams, m_samples: Optional[int] = None) -> dict:
    """
    Estimate cost of primal uSVP attack on the MLWE instance.

    The attack embeds the LWE problem into a unique-SVP lattice of dimension
    d = lwe_n + m, then uses BKZ-β to find a short vector.

    Following lattice-estimator's PrimalUSVP.cost_gsa(), the attack succeeds
    when the BKZ output satisfies:
        δ₀^d · q^(m/d) < σ_e · √(β-1) · ξ

    where ξ = max(1, σ_e/σ_s) is the normal form factor.
    """
    n_total = params.lwe_n
    if m_samples is None:
        m_samples = n_total

    sigma_s = params.sigma_s
    sigma_e = params.sigma_e
    q = params.q

    xi = max(1.0, sigma_e / sigma_s)

    best_classical = None
    best_quantum = None
    best_beta_c = None
    best_beta_q = None
    results_by_beta = []

    for beta in range(40, min(n_total + m_samples, 2048)):
        delta = root_hermite_factor(beta)
        d = n_total + m_samples

        if d < beta:
            d = beta
        if d == beta and d < m_samples:
            d += 1

        tau = sigma_e

        lhs = math.log(tau * math.sqrt(beta - 1)) if beta > 1 else math.log(tau)
        rhs = (math.log(delta) * (2 * beta - d - 1)
               + (math.log(xi) * n_total + math.log(q) * (d - n_total - 1)) / d)

        if rhs >= lhs:
            cost_c = svp_cost_classical(beta)
            cost_q = svp_cost_quantum(beta)
            repeat = bkz_svp_repeat(beta, d)
            total_c = cost_c + math.log2(repeat) if repeat > 1 else cost_c
            total_q = cost_q + math.log2(repeat) if repeat > 1 else cost_q

            if best_classical is None or total_c < best_classical:
                best_classical = total_c
                best_beta_c = beta
            if best_quantum is None or total_q < best_quantum:
                best_quantum = total_q
                best_beta_q = beta

            results_by_beta.append((beta, d, total_c, total_q))
            break

    return {
        "method": "Primal uSVP (GSA)",
        "lwe_dimension": n_total,
        "num_samples": m_samples,
        "embedding_dim": n_total + m_samples,
        "best_classical_bits": best_classical,
        "best_quantum_bits": best_quantum,
        "best_beta_classical": best_beta_c,
        "best_beta_quantum": best_beta_q,
    }


# ============================================================================
# Dual Attack Estimation
# ============================================================================

def estimate_dual_attack(params: MLWEParams, m_samples: Optional[int] = None) -> dict:
    """
    Estimate cost of dual attack on the MLWE instance.

    The dual attack finds a short vector v in the dual lattice such that
    <v, (A, b)> reveals information about the secret. Following the
    [INDOCRYPT:EspJouKau20] formulation in lattice-estimator.

    For each β, the dual vector has norm ≈ δ₀^d · q^((n-ζ)/d) where
    the new LWE noise is σ' = σ_s · δ₀^d / c^(m/(n+m)).

    We use a simplified model that searches for the optimal β.
    """
    n_total = params.lwe_n
    if m_samples is None:
        m_samples = n_total

    sigma_s = params.sigma_s
    sigma_e = params.sigma_e
    q = params.q

    d = n_total + m_samples

    best_classical = None
    best_quantum = None
    best_beta = None

    for beta in range(40, min(d, 2048)):
        delta = root_hermite_factor(beta)

        c = sigma_s * q / sigma_e
        m_opt = max(1, int(math.ceil(
            math.sqrt(n_total * math.log(c) / math.log(delta)) - n_total
        )))
        m_opt = min(m_samples, m_opt)
        d_local = n_total + m_opt

        rho = 1.0
        sigma_prime = rho * sigma_s * delta ** d_local / c ** (m_opt / d_local)
        gap = sigma_prime * q

        if gap < 1.0:
            cost_c = svp_cost_classical(beta)
            cost_q = svp_cost_quantum(beta)
            repeat = bkz_svp_repeat(beta, d_local)
            total_c = cost_c + math.log2(repeat) if repeat > 1 else cost_c
            total_q = cost_q + math.log2(repeat) if repeat > 1 else cost_q

            if best_classical is None or total_c < best_classical:
                best_classical = total_c
                best_beta = beta
            if best_quantum is None or total_q < best_quantum:
                best_quantum = total_q
            break

    return {
        "method": "Dual Attack",
        "lwe_dimension": n_total,
        "num_samples": m_samples,
        "best_classical_bits": best_classical,
        "best_quantum_bits": best_quantum,
        "best_beta": best_beta,
    }


# ============================================================================
# Core-SVP (Rough Estimate per NIST methodology)
# ============================================================================

def estimate_core_svp(params: MLWEParams) -> dict:
    """
    Core-SVP rough estimate following NIST PQC methodology.

    Uses the primal uSVP condition from the lattice-estimator (PrimalUSVP.cost_gsa):
        lhs = log(σ_e · √(β-1))
        rhs = log(δ₀)·(2β-d-1) + (n·log(ξ) + (d-n-1)·log(q)) / d

    Attack succeeds when lhs ≤ rhs. We search over β and use d = 2n as embedding dim.
    """
    n_total = params.lwe_n
    sigma_s = params.sigma_s
    sigma_e = params.sigma_e
    q = params.q
    xi = max(1.0, sigma_e / sigma_s)

    best_c = float('inf')
    best_q = float('inf')
    best_beta_c = 0
    best_beta_q = 0

    for beta in range(40, 2048):
        delta = root_hermite_factor(beta)
        d = 2 * n_total

        lhs = math.log(sigma_e * math.sqrt(max(beta - 1, 1)))
        rhs = (math.log(delta) * (2 * beta - d - 1)
               + (math.log(xi) * n_total + (d - n_total - 1) * math.log(q)) / d)

        if rhs >= lhs:
            c = svp_cost_classical(beta)
            q_cost = svp_cost_quantum(beta)
            if c < best_c:
                best_c = c
                best_beta_c = beta
            if q_cost < best_q:
                best_q = q_cost
                best_beta_q = beta
            break

    if best_c == float('inf'):
        best_c = 0
        best_q = 0

    return {
        "method": "Core-SVP (NIST methodology)",
        "lwe_dimension": n_total,
        "classical_bits": best_c,
        "quantum_bits": best_q,
        "bkz_block_classical": best_beta_c,
        "bkz_block_quantum": best_beta_q,
    }


# ============================================================================
# BKZ Block Size vs Security Sweep
# ============================================================================

def sweep_bkz_security(params: MLWEParams) -> List[dict]:
    """Sweep BKZ block sizes and report the security at each point."""
    n_total = params.lwe_n
    sigma_s = params.sigma_s
    sigma_e = params.sigma_e
    q = params.q
    xi = max(1.0, sigma_e / sigma_s)
    d = 2 * n_total

    results = []
    for beta in [40, 50, 60, 70, 80, 100, 120, 140, 160, 180, 200, 250, 300, 350, 400, 500, 600, 700, 800]:
        if beta >= d:
            break
        delta = root_hermite_factor(beta)

        lhs = math.log(sigma_e * math.sqrt(max(beta - 1, 1)))
        rhs = (math.log(delta) * (2 * beta - d - 1)
               + (math.log(xi) * n_total + (d - n_total - 1) * math.log(q)) / d)
        succeeds = rhs >= lhs

        cost_c = svp_cost_classical(beta)
        cost_q = svp_cost_quantum(beta)

        results.append({
            "beta": beta,
            "delta_0": delta,
            "lhs_log2": lhs,
            "rhs_log2": rhs,
            "classical_log2": cost_c,
            "quantum_log2": cost_q,
            "succeeds": succeeds,
        })

    return results


# ============================================================================
# Module-LWE to LWE Reduction Analysis
# ============================================================================

def module_lwe_analysis(params: MLWEParams) -> dict:
    """
    Analyze the Module-LWE to LWE reduction.

    For Module-LWE(n, k, q, σ) over ring R_q = Z_q[X]/(X^n+1):
    - Equivalent LWE dimension: k * n
    - The module structure provides no additional hardness beyond standard LWE
      with the same total dimension (under the ring-LWE assumption)
    """
    n_total = params.lwe_n
    log_q = math.log2(params.q)

    return {
        "module_rank": params.k,
        "ring_degree": params.n,
        "total_lwe_dimension": n_total,
        "log2_q": log_q,
        "sigma_secret": params.sigma_s,
        "sigma_error": params.sigma_e,
        "noise_to_modulus_ratio": params.sigma_e / params.q,
        "log2_noise_modulus": math.log2(params.sigma_e / params.q),
    }


# ============================================================================
# Main Estimation Routine
# ============================================================================

def run_estimation(params: MLWEParams) -> dict:
    """Run full security estimation for a parameter set."""
    print(f"\n{'='*80}")
    print(f"  Parameter Set: {params.name}")
    print(f"  Target Security: {params.target_bits}-bit")
    print(f"{'='*80}")

    print(f"\n  --- MLWE Parameters ---")
    print(f"  Module rank k      = {params.k}")
    print(f"  Ring degree n      = {params.n}")
    print(f"  Total LWE dim k*n  = {params.lwe_n}")
    print(f"  Modulus q          = {params.q} (≈ 2^{math.log2(params.q):.1f})")
    print(f"  η₁ (secret)       = {params.eta1}")
    print(f"  η₂ (error)        = {params.eta2}")
    print(f"  σ (secret)        = {params.sigma_s:.4f}")
    print(f"  σ (error)         = {params.sigma_e:.4f}")
    print(f"  τ (challenge HW)  = {params.tau}")
    print(f"  β (norm bound)    = {params.beta}")

    mlwe_info = module_lwe_analysis(params)
    print(f"\n  --- Module-LWE Analysis ---")
    print(f"  Noise/Modulus      = {mlwe_info['noise_to_modulus_ratio']:.6e}")
    print(f"  log₂(σ/q)         = {mlwe_info['log2_noise_modulus']:.2f}")

    print(f"\n  --- Core-SVP Estimation ---")
    core = estimate_core_svp(params)
    print(f"  Classical security = 2^{core['classical_bits']:.1f}  (BKZ-β={core['bkz_block_classical']})")
    print(f"  Quantum security   = 2^{core['quantum_bits']:.1f}  (BKZ-β={core['bkz_block_quantum']})")

    print(f"\n  --- Primal uSVP Attack ---")
    primal = estimate_primal_usvp(params)
    if primal['best_classical_bits'] is not None:
        print(f"  Classical security = 2^{primal['best_classical_bits']:.1f}  (β={primal['best_beta_classical']}, d={primal['embedding_dim']})")
        print(f"  Quantum security   = 2^{primal['best_quantum_bits']:.1f}  (β={primal['best_beta_quantum']})")
    else:
        print(f"  No feasible attack found within β ≤ 2048")

    print(f"\n  --- Dual Attack ---")
    dual = estimate_dual_attack(params)
    if dual['best_classical_bits'] is not None:
        print(f"  Classical security = 2^{dual['best_classical_bits']:.1f}  (β={dual['best_beta']})")
        print(f"  Quantum security   = 2^{dual['best_quantum_bits']:.1f}")
    else:
        print(f"  No feasible attack found within β ≤ 2048")

    print(f"\n  --- BKZ Block Size Sweep ---")
    sweep = sweep_bkz_security(params)
    print(f"  {'β':>5s}  {'δ₀':>10s}  {'lhs (log₂)':>12s}  {'rhs (log₂)':>12s}  {'Classical':>10s}  {'Quantum':>10s}  {'Solves?':>8s}")
    print(f"  {'-'*5}  {'-'*10}  {'-'*12}  {'-'*12}  {'-'*10}  {'-'*10}  {'-'*8}")
    for r in sweep:
        print(f"  {r['beta']:5d}  {r['delta_0']:10.6f}  {r['lhs_log2']:12.2f}  {r['rhs_log2']:12.2f}  {r['classical_log2']:10.1f}  {r['quantum_log2']:10.1f}  {'YES' if r['succeeds'] else 'no':>8s}")

    return {
        "params": params,
        "core_svp": core,
        "primal_usvp": primal,
        "dual_attack": dual,
        "bkz_sweep": sweep,
        "module_lwe": mlwe_info,
    }


def print_summary(results: List[dict]):
    """Print a summary table of all security levels."""
    print(f"\n{'='*80}")
    print(f"  SECURITY SUMMARY")
    print(f"{'='*80}")
    print(f"  {'Level':>12s}  {'Classical':>12s}  {'Quantum':>12s}  {'Target':>8s}  {'Meets?':>8s}")
    print(f"  {'-'*12}  {'-'*12}  {'-'*12}  {'-'*8}  {'-'*8}")

    for r in results:
        p = r["params"]
        c = r["core_svp"]
        classical = c["classical_bits"]
        quantum = c["quantum_bits"]
        meets_classical = classical >= p.target_bits
        meets_quantum = quantum >= p.target_bits
        status_c = "YES" if meets_classical else "NO"
        status_q = "YES" if meets_quantum else "NO"

        print(f"  {p.name[:12]:>12s}  2^{classical:6.1f}  2^{quantum:6.1f}  {p.target_bits:>5d}-bit  C:{status_c} Q:{status_q}")

    print(f"\n  Notes:")
    print(f"  - Classical: Core-SVP cost using ADPS16 sieving (0.292·β)")
    print(f"  - Quantum:   Core-SVP cost using Grover-accelerated sieving (0.265·β)")
    print(f"  - Meets = security bits ≥ target bits")
    print(f"  - MLWE dimension = module_rank × ring_degree")
    print(f"  - All parameters use q = 8380417, n = 256, η = 2")
    print()


def main():
    print("PABS-CRF Lattice Security Estimator")
    print("====================================")
    print("Method: Core-SVP (ADPS16) + Primal uSVP + Dual Attack")
    print("Parameters from: academic_implementation_v4/src/mlwe.rs")

    results = []
    for params in [PARAMS_128, PARAMS_192, PARAMS_256]:
        result = run_estimation(params)
        results.append(result)

    print_summary(results)

    return results


if __name__ == "__main__":
    main()
