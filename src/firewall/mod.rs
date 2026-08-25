//! Cryptographic reverse firewall for the structured PABS signing path.

use crate::algebra::{matrix_vector_mul, vector_sub};
use crate::errors::{PabsCrfError, PabsCrfResult};
use crate::mlwe::{MLWEParameters, Polynomial, PolynomialMatrix, PolynomialVector};
use crate::pabs::types::{CorePredicateSignature, FirewallSignature};
use crate::samplers::sample_small_vector;
use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256};

/// Domain separator for the Fiat-Shamir compatible CRF transcript.
pub const CRF_TRANSCRIPT_DOMAIN: &[u8] = b"PABS-CRF::CryptographicReverseFirewall::v4";

/// CRF pre-commitment created before the core signer derives its challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrfPrecommitment {
    mask: PolynomialVector,
    delta: PolynomialVector,
    delta_bytes: Vec<u8>,
}

impl CrfPrecommitment {
    /// Public correction term `delta = A*r`.
    pub fn delta(&self) -> &PolynomialVector {
        &self.delta
    }

    /// Canonical bytes of `delta`, used as Fiat-Shamir input.
    pub fn delta_bytes(&self) -> &[u8] {
        &self.delta_bytes
    }
}

/// Cryptographic reverse firewall used by the v4 formal path.
///
/// Fiat-Shamir signatures cannot be safely post-processed after the challenge
/// is fixed. This CRF is therefore two-stage: it first samples a secret mask
/// `r` and exposes only `delta=A*r`; the signer binds `delta` into the
/// challenge; then the CRF emits `z_final=z+r` after an integer-domain rejection
/// check. The verifier subtracts the public correction from `A*z-c*u_policy`.
pub struct StrongFirewall {
    params: MLWEParameters,
    max_attempts: usize,
}

/// Paper-facing name for the firewall API.
pub type CryptographicReverseFirewall = StrongFirewall;

impl StrongFirewall {
    /// Create a firewall bound to the supplied parameters and retry budget.
    pub fn new(params: MLWEParameters, max_attempts: usize) -> Self {
        Self {
            params,
            max_attempts,
        }
    }

    /// Generate a CRF pre-commitment to be bound into the core challenge.
    pub fn precommit(
        &self,
        matrix_a: &PolynomialMatrix,
        rng: &mut impl RngCore,
    ) -> PabsCrfResult<CrfPrecommitment> {
        if self.max_attempts == 0 {
            return Err(PabsCrfError::InvalidParameters(
                "CRF max_attempts must be positive".to_string(),
            ));
        }
        if matrix_a.rows == 0 || matrix_a.cols == 0 {
            return Err(PabsCrfError::InvalidParameters(
                "CRF precommit requires a non-empty public matrix".to_string(),
            ));
        }

        let mask = sample_small_vector(&self.params, matrix_a.cols, self.params.eta2, rng);
        self.precommit_with_mask(matrix_a, mask)
    }

    /// Build a CRF pre-commitment from a supplied mask for deterministic tests.
    pub fn precommit_with_mask(
        &self,
        matrix_a: &PolynomialMatrix,
        mask: PolynomialVector,
    ) -> PabsCrfResult<CrfPrecommitment> {
        if mask.elements.len() != matrix_a.cols {
            return Err(PabsCrfError::InvalidInput(format!(
                "CRF mask dimension mismatch: mask={}, matrix_cols={}",
                mask.elements.len(),
                matrix_a.cols
            )));
        }

        let delta = matrix_vector_mul(matrix_a, &mask, self.params.q);
        let delta_bytes = serialize_polynomial_vector_for_hash(&delta);
        Ok(CrfPrecommitment {
            mask,
            delta,
            delta_bytes,
        })
    }

    /// Transform a core signature when the caller has already bound the
    /// pre-commitment's delta bytes into the core challenge.
    pub fn finalize_precommitted(
        &self,
        core: CorePredicateSignature,
        matrix_a: &PolynomialMatrix,
        precommit: CrfPrecommitment,
        pk_hash: &[u8],
        tau: u64,
    ) -> PabsCrfResult<FirewallSignature> {
        let expected_delta = matrix_vector_mul(matrix_a, &precommit.mask, self.params.q);
        if expected_delta != precommit.delta {
            return Err(PabsCrfError::SecurityViolation(
                "CRF precommitment failed delta=A*r consistency check".to_string(),
            ));
        }
        if serialize_polynomial_vector_for_hash(&precommit.delta) != precommit.delta_bytes {
            return Err(PabsCrfError::SecurityViolation(
                "CRF precommitment has non-canonical delta bytes".to_string(),
            ));
        }

        self.finalize_with_parts(core, precommit.delta, precommit.mask, pk_hash, tau)
    }

    /// Convenience wrapper retained for callers that manage challenge binding.
    pub fn transform_with_mask(
        &self,
        core: CorePredicateSignature,
        matrix_a: &PolynomialMatrix,
        mask: PolynomialVector,
        pk_hash: &[u8],
        tau: u64,
    ) -> PabsCrfResult<FirewallSignature> {
        let precommit = self.precommit_with_mask(matrix_a, mask)?;
        self.finalize_precommitted(core, matrix_a, precommit, pk_hash, tau)
    }

    /// Legacy single-call transform. It is intentionally rejected because a CRF
    /// for this Fiat-Shamir path must pre-commit before core signing.
    pub fn transform(
        &self,
        _core: CorePredicateSignature,
        matrix_a: &PolynomialMatrix,
        _pk_hash: &[u8],
        _tau: u64,
    ) -> PabsCrfResult<FirewallSignature> {
        let mut rng = thread_rng();
        let precommit = self.precommit(matrix_a, &mut rng)?;
        Err(PabsCrfError::InvalidInput(format!(
            "CRF transform requires pre-challenge binding of delta ({} bytes); use precommit + finalize_precommitted",
            precommit.delta_bytes.len()
        )))
    }

    fn finalize_with_parts(
        &self,
        core: CorePredicateSignature,
        delta: PolynomialVector,
        mask: PolynomialVector,
        pk_hash: &[u8],
        tau: u64,
    ) -> PabsCrfResult<FirewallSignature> {
        let q = self.params.q;
        let z_bound = (self.params.gamma1 - self.params.beta as u32) as i64;

        let z_centered = core.z.center_coefficients(q);
        let z_int = PolynomialVector {
            elements: z_centered
                .elements
                .iter()
                .zip(mask.elements.iter())
                .map(|(z_i, m_i)| z_i.add_integer(m_i))
                .collect(),
        };

        if z_int.infinity_norm_integer() >= z_bound {
            return Err(PabsCrfError::SecurityViolation(
                "CRF integer-domain rejection check failed".to_string(),
            ));
        }

        let z = PolynomialVector {
            elements: z_int
                .elements
                .iter()
                .map(|p| Polynomial::from_coeffs(&p.coeffs, q))
                .collect(),
        };

        let firewall_tag = firewall_tag(
            &z,
            &delta,
            &core.challenge,
            &core.policy_digest,
            &core.message_hash,
            pk_hash,
            tau,
            &core.gid,
            &core.parameter_set_id,
        )?;

        Ok(FirewallSignature {
            z,
            challenge: core.challenge,
            hints: core.hints,
            policy: core.policy,
            message_hash: core.message_hash,
            attributes_used: core.attributes_used,
            policy_digest: core.policy_digest,
            firewall_delta: delta,
            firewall_tag,
            parameter_set_id: core.parameter_set_id,
            pk_hash: pk_hash.to_vec(),
            crf_seed: None,
            tau,
            gid: core.gid,
        })
    }

    /// Validate CRF metadata integrity before full signature verification.
    pub fn validate_metadata(&self, signature: &FirewallSignature) -> PabsCrfResult<()> {
        let expected = firewall_tag(
            &signature.z,
            &signature.firewall_delta,
            &signature.challenge,
            &signature.policy_digest,
            &signature.message_hash,
            &signature.pk_hash,
            signature.tau,
            &signature.gid,
            &signature.parameter_set_id,
        )?;
        if expected != signature.firewall_tag {
            return Err(PabsCrfError::VerificationFailed(
                "CRF metadata tag mismatch".to_string(),
            ));
        }
        Ok(())
    }

    /// Subtract the public CRF correction from `A*z-c*u_policy`.
    pub fn verifier_adjusted_commitment(
        &self,
        az_minus_cu: &PolynomialVector,
        signature: &FirewallSignature,
    ) -> PabsCrfResult<PolynomialVector> {
        vector_sub(az_minus_cu, &signature.firewall_delta, self.params.q)
    }

    /// Deprecated compatibility helper. A verifier cannot subtract
    /// `firewall_delta` from `z` because they live in different dimensions.
    #[deprecated(note = "use verifier_adjusted_commitment on A*z-c*u_policy")]
    pub fn verifier_adjusted_response(
        &self,
        signature: &FirewallSignature,
    ) -> PabsCrfResult<PolynomialVector> {
        vector_sub(&signature.z, &signature.firewall_delta, self.params.q)
    }
}

fn firewall_tag(
    z: &PolynomialVector,
    delta: &PolynomialVector,
    challenge: &Polynomial,
    policy_digest: &[u8],
    message_hash: &[u8],
    pk_hash: &[u8],
    tau: u64,
    gid: &[u8; 32],
    parameter_set_id: &str,
) -> PabsCrfResult<Vec<u8>> {
    let z_bytes = bincode::serialize(z).map_err(|e| {
        PabsCrfError::SerializationError(format!("Failed to serialize CRF z: {}", e))
    })?;
    let delta_bytes = bincode::serialize(delta).map_err(|e| {
        PabsCrfError::SerializationError(format!("Failed to serialize CRF delta: {}", e))
    })?;
    let challenge_bytes = bincode::serialize(challenge).map_err(|e| {
        PabsCrfError::SerializationError(format!("Failed to serialize CRF challenge: {}", e))
    })?;

    let mut hasher = Sha256::new();
    hasher.update(CRF_TRANSCRIPT_DOMAIN);
    hasher.update(b"::FirewallTag||");
    hasher.update(&(parameter_set_id.len() as u32).to_le_bytes());
    hasher.update(parameter_set_id.as_bytes());
    hasher.update(&tau.to_le_bytes());
    hasher.update(gid);
    hasher.update(&(policy_digest.len() as u32).to_le_bytes());
    hasher.update(policy_digest);
    hasher.update(&(message_hash.len() as u32).to_le_bytes());
    hasher.update(message_hash);
    hasher.update(&(pk_hash.len() as u32).to_le_bytes());
    hasher.update(pk_hash);
    hasher.update(&(challenge_bytes.len() as u32).to_le_bytes());
    hasher.update(&challenge_bytes);
    hasher.update(&(z_bytes.len() as u32).to_le_bytes());
    hasher.update(&z_bytes);
    hasher.update(&(delta_bytes.len() as u32).to_le_bytes());
    hasher.update(&delta_bytes);
    Ok(hasher.finalize().to_vec())
}

/// Canonical polynomial-vector serialization used for Fiat-Shamir CRF binding.
pub fn serialize_polynomial_vector_for_hash(pv: &PolynomialVector) -> Vec<u8> {
    let mut bytes = Vec::new();
    for poly in &pv.elements {
        for &coeff in &poly.coeffs {
            bytes.extend_from_slice(&(coeff as i64).to_le_bytes());
        }
    }
    bytes
}
