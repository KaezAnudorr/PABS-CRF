//! Signature verification for the structured v4 PABS-CRF path.

use crate::algebra::{matrix_vector_mul_sub_poly_mul_ntt, vector_within_infinity_bound};
use crate::compat::{get_public_parameters, get_signature, LegacyMap};
use crate::errors::{PabsCrfError, PabsCrfResult};
use crate::firewall::{serialize_polynomial_vector_for_hash, CryptographicReverseFirewall};
use crate::lsss::derive_policy_target_cached;
use crate::mlwe::MLWESignature;
use crate::policy::Policy;
use crate::puncture_tree::PunctureTree;
use crate::serialization::decompress_firewall_signature;
use crate::setup::PublicParameters;
use crate::sign::{CompressedSignature, Signature};
use sha2::{Digest, Sha256};

/// Verify a PABS-CRF signature against the public parameters and policy (Legacy HashMap API).
pub fn verify(
    pp: &LegacyMap,
    message: &[u8],
    policy: &Policy,
    signature: &LegacyMap,
) -> PabsCrfResult<bool> {
    let pp_struct = get_public_parameters(pp)?;
    let sig_struct = match get_signature(signature) {
        Ok(sig) => sig,
        Err(_) => return Ok(false),
    };

    let required_keys = [
        "message_hash",
        "policy",
        "challenge",
        "z",
        "firewall_delta",
        "firewall_tag",
        "policy_digest",
        "parameter_set_id",
        "attributes_used",
    ];
    if required_keys
        .iter()
        .any(|key| !signature.contains_key(*key))
    {
        return Ok(false);
    }

    if let Some(message_hash) = signature.get("message_hash") {
        if message_hash != &sig_struct.message_hash {
            return Ok(false);
        }
    }
    if let Some(policy_bytes) = signature.get("policy") {
        let raw_policy: Policy = match bincode::deserialize(policy_bytes) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        if raw_policy != sig_struct.policy {
            return Ok(false);
        }
    }
    if let Some(challenge_bytes) = signature.get("challenge") {
        let raw_challenge = match bincode::serialize(&sig_struct.challenge) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        if challenge_bytes != &raw_challenge {
            return Ok(false);
        }
    }
    if let Some(z_bytes) = signature.get("z") {
        let raw_z = match bincode::serialize(&sig_struct.z) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        if z_bytes != &raw_z {
            return Ok(false);
        }
    }
    if let Some(delta_bytes) = signature.get("firewall_delta") {
        let raw_delta = match bincode::serialize(&sig_struct.firewall_delta) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        if delta_bytes != &raw_delta {
            return Ok(false);
        }
    }

    verify_signature_struct(&pp_struct, message, policy, &sig_struct)
}

/// Verify a structured signature against the public parameters and policy.
pub fn verify_signature_struct(
    pp_struct: &PublicParameters,
    message: &[u8],
    policy: &Policy,
    sig_struct: &Signature,
) -> PabsCrfResult<bool> {
    if sig_struct.policy != *policy {
        return Ok(false);
    }

    let current_hash = Sha256::digest(message).to_vec();
    if sig_struct.message_hash != current_hash {
        return Ok(false);
    }

    if sig_struct.policy_digest != crate::pabs::policy_digest(policy) {
        return Ok(false);
    }

    if sig_struct.parameter_set_id != pp_struct.parameter_model.protocol.security_target.as_str() {
        return Ok(false);
    }

    let attr_refs: Vec<&str> = sig_struct
        .attributes_used
        .iter()
        .map(|s| s.as_str())
        .collect();
    if !policy.satisfies(&attr_refs) {
        return Ok(false);
    }

    let params = &pp_struct.params;
    let q = params.q;
    let z_bound = MLWESignature::verification_z_bound(params, 0);
    if !vector_within_infinity_bound(&sig_struct.z, q, z_bound) {
        return Ok(false);
    }

    let firewall = CryptographicReverseFirewall::new(
        pp_struct.parameter_model.protocol.mlwe,
        pp_struct
            .parameter_model
            .implementation
            .firewall_max_attempts,
    );
    if firewall.validate_metadata(sig_struct).is_err() {
        return Ok(false);
    }

    let u_policy =
        derive_policy_target_cached(policy, &sig_struct.attributes_used, &sig_struct.gid, params)?;
    let pk_hash = MLWESignature::compute_pk_hash(&u_policy, q);
    if sig_struct.pk_hash != pk_hash {
        return Ok(false);
    }

    let az_minus_cu = matrix_vector_mul_sub_poly_mul_ntt(
        &pp_struct.matrix_a,
        &sig_struct.z,
        &u_policy,
        &sig_struct.challenge,
        q,
    );
    let w_prime = firewall.verifier_adjusted_commitment(&az_minus_cu, sig_struct)?;

    let w1_prime = match &sig_struct.hints {
        Some(hints) => {
            let hint_count: usize = hints
                .elements
                .iter()
                .flat_map(|p| p.coeffs.iter())
                .filter(|&&c| c != 0)
                .count();
            if hint_count > 80 {
                return Ok(false);
            }
            w_prime.use_hint(hints, params.gamma2, q)
        }
        None => return Ok(false),
    };

    let tr = MLWESignature::compute_system_tr(&pp_struct.matrix_a, &u_policy);
    let delta_bytes = serialize_polynomial_vector_for_hash(&sig_struct.firewall_delta);
    let context = crate::pabs::challenge_context(
        &sig_struct.policy_digest,
        sig_struct.tau,
        &sig_struct.gid,
        &sig_struct.parameter_set_id,
    );
    let challenge_prime = MLWESignature::derive_challenge_public(
        params,
        &w1_prime,
        message,
        &context,
        &tr,
        &pk_hash,
        &delta_bytes,
    );

    Ok(challenge_prime.coeffs == sig_struct.challenge.coeffs)
}

fn verify_compact_signature(
    pp_struct: &PublicParameters,
    message: &[u8],
    policy: &Policy,
    compressed: &CompressedSignature,
) -> PabsCrfResult<bool> {
    let attributes_used = match compressed.witness_attributes(policy) {
        Ok(attrs) => attrs,
        Err(_) => return Ok(false),
    };
    let signature = decompress_firewall_signature(
        compressed,
        policy.clone(),
        Sha256::digest(message).to_vec(),
        attributes_used,
        &pp_struct.params,
    )?;
    verify_signature_struct(pp_struct, message, policy, &signature)
}

/// Convenience wrapper for the verification API.
pub struct Verify;

impl Verify {
    /// Create a verifier facade.
    pub fn new() -> Self {
        Self
    }

    /// Verify a single signature.
    pub fn verify(
        &self,
        pp: &LegacyMap,
        message: &[u8],
        policy: &Policy,
        signature: &LegacyMap,
    ) -> PabsCrfResult<bool> {
        verify(pp, message, policy, signature)
    }

    /// Verify a batch of signatures independently.
    pub fn batch_verify(
        &self,
        pp: &LegacyMap,
        messages: &[&[u8]],
        policies: &[Policy],
        signatures: &[LegacyMap],
    ) -> Vec<PabsCrfResult<bool>> {
        if messages.len() != policies.len() || messages.len() != signatures.len() {
            return vec![Err(PabsCrfError::InvalidInput(format!(
                "Input length mismatch: messages={}, policies={}, signatures={}",
                messages.len(),
                policies.len(),
                signatures.len()
            )))];
        }
        messages
            .iter()
            .zip(policies.iter())
            .zip(signatures.iter())
            .map(|((msg, policy), sig)| self.verify(pp, msg, policy, sig))
            .collect()
    }

    /// Verify with locally-held puncture state.
    /// Note: this is NOT public revocation. The puncture tree is signer-private.
    /// External verifiers cannot perform this check.
    #[deprecated(note = "use verify for public verification; this is signer self-check only")]
    pub fn verify_with_local_puncture_state(
        &self,
        sk: &LegacyMap,
        pp: &LegacyMap,
        message: &[u8],
        policy: &Policy,
        signature: &LegacyMap,
        tau: u64,
    ) -> PabsCrfResult<bool> {
        let tree_bytes = sk.get("puncture_tree").ok_or_else(|| {
            PabsCrfError::InvalidInput("Missing 'puncture_tree' in secret key".to_string())
        })?;
        let tree: PunctureTree = bincode::deserialize(tree_bytes).map_err(|e| {
            PabsCrfError::DeserializationError(format!(
                "Failed to deserialize puncture tree: {}",
                e
            ))
        })?;

        if let Some(count_bytes) = sk.get("puncture_count") {
            if count_bytes.len() == 8 {
                let mut bytes_arr = [0u8; 8];
                bytes_arr.copy_from_slice(count_bytes);
                let stored_count = u64::from_le_bytes(bytes_arr);
                let tree_count = tree.puncture_count as u64;
                if stored_count != tree_count {
                    return Err(PabsCrfError::VerificationFailed(format!(
                        "Puncture state inconsistency: count={}, tree_count={}",
                        stored_count, tree_count
                    )));
                }
            }
        }

        if tree.is_punctured(tau)? {
            return Err(PabsCrfError::VerificationFailed(format!(
                "Tag {} has been punctured",
                tau
            )));
        }

        self.verify(pp, message, policy, signature)
    }

    #[deprecated(note = "renamed to verify_with_local_puncture_state")]
    pub fn verify_punctured(
        &self,
        sk: &LegacyMap,
        pp: &LegacyMap,
        message: &[u8],
        policy: &Policy,
        signature: &LegacyMap,
        tau: u64,
    ) -> PabsCrfResult<bool> {
        self.verify_with_local_puncture_state(sk, pp, message, policy, signature, tau)
    }

    /// Decompress and verify a compressed signature blob.
    pub fn verify_compressed(
        &self,
        pp: &LegacyMap,
        message: &[u8],
        policy: &Policy,
        compressed_sig: &[u8],
    ) -> PabsCrfResult<bool> {
        let pp_struct = get_public_parameters(pp)?;
        let compressed = CompressedSignature::from_bytes(compressed_sig)?;
        verify_compact_signature(&pp_struct, message, policy, &compressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlwe::{MLWEParameters, Polynomial, PolynomialVector};
    use crate::{keygen, setup};
    use std::collections::HashMap;

    #[test]
    fn test_verify_requires_structured_public_parameters() {
        let params = MLWEParameters::new_128();
        let policy = Policy::parse("admin").unwrap();
        let signature = Signature {
            z: PolynomialVector::new(params.m, params.n),
            challenge: Polynomial::new(params.n),
            hints: None,
            policy: policy.clone(),
            message_hash: sha2::Sha256::digest(b"msg").to_vec(),
            attributes_used: vec!["admin".to_string()],
            policy_digest: crate::pabs::policy_digest(&policy),
            firewall_delta: PolynomialVector::new(params.k, params.n),
            firewall_tag: vec![1u8; 32],
            parameter_set_id: "top-tier-128".to_string(),
            pk_hash: Vec::new(),
            crf_seed: None,
            tau: 0,
            gid: [0u8; 32],
        };

        let mut signature_map = HashMap::new();
        signature_map.insert(
            "sig_struct".to_string(),
            bincode::serialize(&signature).unwrap(),
        );

        let err = verify(&HashMap::new(), b"msg", &policy, &signature_map).unwrap_err();
        assert!(matches!(err, PabsCrfError::DeserializationError(_)));
    }

    #[test]
    fn test_verify_compressed_end_to_end() {
        let (pp, msk) = setup(128);
        let sk = keygen(&pp, &msk, &["admin", "finance"]);
        let policy = Policy::parse("admin AND finance").unwrap();
        let message = b"compressed verification path";

        let signer = crate::sign::Sign::new();
        let verifier = Verify::new();
        let compressed = signer
            .sign_compressed(&sk, message, &policy, 0)
            .expect("compressed signing should succeed");

        assert!(verifier
            .verify_compressed(&pp, message, &policy, &compressed)
            .expect("compressed verification should succeed"));

        let wrong_policy = Policy::parse("admin").unwrap();
        assert!(!verifier
            .verify_compressed(&pp, message, &wrong_policy, &compressed)
            .expect("verification should return false on policy mismatch"));
    }
}
