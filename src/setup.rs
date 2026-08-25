//! System setup for the PABS-CRF scheme
//!
//! Generates trapdoor matrix A with basis T following the Dilithium framework.
//! Public parameters pp contain (A, params).
//! Master secret key msk contains (A, T, params).

use crate::compat::{master_secret_key_to_legacy_map, public_parameters_to_legacy_map, LegacyMap};
use crate::errors::{PabsCrfError, PabsCrfResult};
use crate::mlwe::{MLWEKeyPair, MLWEParameters, PolynomialMatrix};
use crate::parameter_sets::TopTierParameterModel;
use crate::trapdoor::strict::TrapdoorMode;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Canonical serialization key for public parameters.
pub const PP_STRUCT_KEY: &str = "pp_struct";
/// Legacy serialization key for public parameters.
pub const LEGACY_PP_STRUCT_KEY: &str = "matrix_a_struct";
/// Canonical serialization key for the master secret key.
pub const MSK_STRUCT_KEY: &str = "msk_struct";

/// Public parameters for the PABS-CRF scheme
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicParameters {
    pub params: MLWEParameters,
    pub parameter_model: TopTierParameterModel,
    pub transport_version: String,
    pub firewall_domain_separator: String,
    pub matrix_a: PolynomialMatrix,
    pub matrix_a_seed: [u8; 32],
}

/// Master secret key for the PABS-CRF scheme
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct MasterSecretKey {
    /// MLWE parameters
    pub params: MLWEParameters,
    /// Formal top-tier parameter model.
    pub parameter_model: TopTierParameterModel,
    /// Trapdoor mode label for auditability.
    pub trapdoor_mode: TrapdoorMode,
    /// Public matrix A
    pub matrix_a: PolynomialMatrix,
    /// Trapdoor basis T for matrix A
    pub trapdoor_t: PolynomialMatrix,
}

fn select_parameters(security_level: u32) -> MLWEParameters {
    TopTierParameterModel::for_security_level(security_level)
        .protocol
        .mlwe
}

/// Deserialize structured public parameters from bytes.
pub fn deserialize_public_parameters(bytes: &[u8]) -> PabsCrfResult<PublicParameters> {
    bincode::deserialize(bytes).map_err(|e| {
        PabsCrfError::DeserializationError(format!(
            "Failed to deserialize public parameters: {}",
            e
        ))
    })
}

/// Deserialize structured master secret material from bytes.
pub fn deserialize_master_secret_key(bytes: &[u8]) -> PabsCrfResult<MasterSecretKey> {
    bincode::deserialize(bytes).map_err(|e| {
        PabsCrfError::DeserializationError(format!(
            "Failed to deserialize master secret key: {}",
            e
        ))
    })
}

/// Generate structured public parameters and master secret key for the requested security level.
pub fn try_setup_structured(
    security_level: u32,
) -> PabsCrfResult<(PublicParameters, MasterSecretKey)> {
    try_setup_structured_with_sigma(security_level, 100.0)
}

/// Generate structured public parameters and master secret key with a custom
/// Gaussian σ for trapdoor preimage sampling.
pub fn try_setup_structured_with_sigma(
    security_level: u32,
    sigma: f64,
) -> PabsCrfResult<(PublicParameters, MasterSecretKey)> {
    let parameter_model =
        TopTierParameterModel::for_security_level_with_sigma(security_level, sigma);
    let params = parameter_model.protocol.mlwe;
    let mut matrix_a_seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut matrix_a_seed);

    let a_prime = MLWEKeyPair::generate_a_prime_from_seed(&matrix_a_seed, &params);

    let strict = crate::trapdoor::strict::StrictTrapdoor::new(&params);
    // Trapdoor randomness is secret and independent of the public matrix seed.
    // Deriving it from matrix_a_seed would let anyone reconstruct the master key.
    let mut trapdoor_rng = rand::thread_rng();
    let (matrix_a, trapdoor_t) = strict.generate_with_a_prime(a_prime, &mut trapdoor_rng)?;

    let pp = PublicParameters {
        params: params.clone(),
        parameter_model: parameter_model.clone(),
        transport_version: parameter_model.protocol.transport_version.clone(),
        firewall_domain_separator: parameter_model.protocol.firewall_domain_separator.clone(),
        matrix_a: matrix_a.clone(),
        matrix_a_seed,
    };

    let msk = MasterSecretKey {
        params: params.clone(),
        parameter_model,
        trapdoor_mode: TrapdoorMode::Strict,
        matrix_a: matrix_a,
        trapdoor_t: trapdoor_t,
    };

    Ok((pp, msk))
}

/// Generate structured public parameters and master secret key.
pub fn setup_structured(security_level: u32) -> (PublicParameters, MasterSecretKey) {
    try_setup_structured(security_level).expect("Structured setup failed")
}

/// Generate structured public parameters and master secret key with a custom σ.
pub fn setup_structured_with_sigma(
    security_level: u32,
    sigma: f64,
) -> (PublicParameters, MasterSecretKey) {
    try_setup_structured_with_sigma(security_level, sigma)
        .expect("Structured setup with sigma failed")
}

/// Legacy system setup that returns HashMaps.
///
/// In PABS-CRF, the master key is a trapdoor matrix T for public matrix A.
pub fn try_setup(security_level: u32) -> PabsCrfResult<(LegacyMap, LegacyMap)> {
    let (pp_struct, msk_struct) = try_setup_structured(security_level)?;
    let pp = public_parameters_to_legacy_map(&pp_struct)?;
    let msk = master_secret_key_to_legacy_map(&msk_struct)?;
    Ok((pp, msk))
}

/// Legacy setup wrapper that returns HashMaps.
pub fn setup(security_level: u32) -> (LegacyMap, LegacyMap) {
    try_setup(security_level).expect("Legacy setup failed")
}

/// Convenience wrapper for system setup.
pub struct Setup;

impl Setup {
    /// Create a setup facade.
    pub fn new() -> Self {
        Self
    }

    /// Generate public parameters and the master secret key.
    pub fn generate(&self, security_level: u32) -> (LegacyMap, LegacyMap) {
        setup(security_level)
    }

    /// Generate structured public parameters and the master secret key with explicit errors.
    pub fn try_generate_structured(
        &self,
        security_level: u32,
    ) -> PabsCrfResult<(PublicParameters, MasterSecretKey)> {
        try_setup_structured(security_level)
    }

    /// Generate legacy public parameters and secret key with explicit errors.
    pub fn try_generate(&self, security_level: u32) -> PabsCrfResult<(LegacyMap, LegacyMap)> {
        try_setup(security_level)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_same_seed_produces_same_a_prime() {
        let params = MLWEParameters::new_128();
        let seed = [42u8; 32];
        let a_prime_1 = MLWEKeyPair::generate_a_prime_from_seed(&seed, &params);
        let a_prime_2 = MLWEKeyPair::generate_a_prime_from_seed(&seed, &params);
        assert_eq!(a_prime_1.rows, a_prime_2.rows);
        assert_eq!(a_prime_1.cols, a_prime_2.cols);
        for (row1, row2) in a_prime_1.elements.iter().zip(a_prime_2.elements.iter()) {
            for (p1, p2) in row1.iter().zip(row2.iter()) {
                assert_eq!(p1.coeffs, p2.coeffs);
            }
        }
    }

    #[test]
    fn test_a_prime_coefficients_in_range() {
        let params = MLWEParameters::new_128();
        let seed = [7u8; 32];
        let a_prime = MLWEKeyPair::generate_a_prime_from_seed(&seed, &params);
        let q = params.q;
        for row in &a_prime.elements {
            for poly in row {
                for &c in &poly.coeffs {
                    assert!(
                        c >= 0 && c < q as i32,
                        "Coefficient {} out of range [0, {})",
                        c,
                        q
                    );
                }
            }
        }
    }

    #[test]
    fn test_different_seed_produces_different_a_prime() {
        let params = MLWEParameters::new_128();
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];
        let a_prime_1 = MLWEKeyPair::generate_a_prime_from_seed(&seed1, &params);
        let a_prime_2 = MLWEKeyPair::generate_a_prime_from_seed(&seed2, &params);
        let mut any_diff = false;
        for (row1, row2) in a_prime_1.elements.iter().zip(a_prime_2.elements.iter()) {
            for (p1, p2) in row1.iter().zip(row2.iter()) {
                if p1.coeffs != p2.coeffs {
                    any_diff = true;
                    break;
                }
            }
            if any_diff {
                break;
            }
        }
        assert!(
            any_diff,
            "Different seeds should produce different A-prime matrices"
        );
    }

    fn build_full_a_from_seeds(
        public_seed: &[u8; 32],
        trapdoor_seed: &[u8; 32],
        params: &MLWEParameters,
    ) -> (PolynomialMatrix, PolynomialMatrix) {
        let a_prime = MLWEKeyPair::generate_a_prime_from_seed(public_seed, params);
        let mut sub_rng = StdRng::from_seed(*trapdoor_seed);
        let strict = crate::trapdoor::strict::StrictTrapdoor::new(params);
        strict.generate_with_a_prime(a_prime, &mut sub_rng).unwrap()
    }

    #[test]
    fn test_same_public_and_trapdoor_seeds_produce_same_full_matrix() {
        let params = MLWEParameters::new_128();
        let public_seed = [99u8; 32];
        let trapdoor_seed = [17u8; 32];
        let (a1, _t1) = build_full_a_from_seeds(&public_seed, &trapdoor_seed, &params);
        let (a2, _t2) = build_full_a_from_seeds(&public_seed, &trapdoor_seed, &params);
        assert_eq!(a1.rows, a2.rows);
        assert_eq!(a1.cols, a2.cols);
        for (row1, row2) in a1.elements.iter().zip(a2.elements.iter()) {
            for (p1, p2) in row1.iter().zip(row2.iter()) {
                assert_eq!(
                    p1.coeffs, p2.coeffs,
                    "Full A matrix not deterministic for fixed seed"
                );
            }
        }
    }

    #[test]
    fn test_full_a_matrix_coefficients_in_range() {
        let params = MLWEParameters::new_128();
        let public_seed = [13u8; 32];
        let trapdoor_seed = [29u8; 32];
        let (a_full, _) = build_full_a_from_seeds(&public_seed, &trapdoor_seed, &params);
        let q = params.q;
        for row in &a_full.elements {
            for poly in row {
                for &c in &poly.coeffs {
                    assert!(
                        c >= 0 && c < q as i32,
                        "Coefficient {} out of range [0, {})",
                        c,
                        q
                    );
                }
            }
        }
    }

    #[test]
    fn test_public_seed_does_not_determine_trapdoor() {
        let params = MLWEParameters::new_128();
        let public_seed = [41u8; 32];
        let (a1, t1) = build_full_a_from_seeds(&public_seed, &[1u8; 32], &params);
        let (a2, t2) = build_full_a_from_seeds(&public_seed, &[2u8; 32], &params);

        assert_ne!(
            t1, t2,
            "Independent secret seeds must produce different trapdoors"
        );
        assert_ne!(
            a1, a2,
            "The public seed fixes A-prime, not the trapdoor-dependent full matrix"
        );
    }
}
