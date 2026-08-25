//! Samplers for lattice-based cryptography in PABS-CRF
//!
//! # Academic Reference
//! Gentry, Craig; Peikert, Chris; Vaikuntanathan, Vinod (STOC 2008).
//! "Trapdoors for Hard Lattices and New Cryptographic Constructions."
//!
//! Discrete Gaussian sampling and centered binomial distribution (CBD) for
//! lattice trapdoors and error distribution sampling.

use crate::mlwe::{MLWEParameters, Polynomial, PolynomialVector};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Metadata describing a sampler invocation used by tests and audits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplerMetadata {
    /// Human-readable sampler name.
    pub sampler_name: String,
    /// Distribution label.
    pub distribution: String,
}

/// Sample a bounded mask vector used by the firewall.
pub fn sample_bounded_mask_vector(
    params: &MLWEParameters,
    width: usize,
    bound: i32,
    rng: &mut impl RngCore,
) -> PolynomialVector {
    PolynomialVector {
        elements: (0..width)
            .map(|_| Polynomial::rand_poly_uniform(params.n, bound.unsigned_abs(), rng))
            .collect(),
    }
}

/// Sample a small vector with centered coefficients from a simple CBD-like distribution.
pub fn sample_small_vector(
    params: &MLWEParameters,
    width: usize,
    eta: i32,
    rng: &mut impl RngCore,
) -> PolynomialVector {
    PolynomialVector {
        elements: (0..width)
            .map(|_| Polynomial::rand_poly(params.n, eta, rng))
            .collect(),
    }
}
