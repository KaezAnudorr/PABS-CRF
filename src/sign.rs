//! Signature generation for the structured v4 PABS-CRF path.

use crate::compat::{get_user_secret_key, signature_to_legacy_map, LegacyMap};
use crate::errors::{PabsCrfError, PabsCrfResult};
use crate::firewall::CryptographicReverseFirewall;
use crate::keygen::UserSecretKey;
use crate::pabs;
use crate::pabs::types::{CompressedFirewallSignature, FirewallSignature};
use crate::policy::Policy;
use crate::serialization::{
    compress_firewall_signature, deserialize_compressed_signature, serialize_compressed_signature,
};
use rand::thread_rng;

/// Public signature type for PABS-CRF.
pub type Signature = FirewallSignature;
/// Compressed signature type for network transport and storage.
pub type CompressedSignature = CompressedFirewallSignature;

impl FirewallSignature {
    /// Compress the final firewall signature into the formal transport object.
    pub fn compress(
        &self,
        params: &crate::mlwe::MLWEParameters,
    ) -> PabsCrfResult<CompressedSignature> {
        let witness_rows = pabs::witness_rows_from_attributes(&self.policy, &self.attributes_used)?;
        Ok(compress_firewall_signature(self, witness_rows, params))
    }

    /// Convert the structured firewall signature into the legacy HashMap representation.
    pub fn to_signature_map(&self) -> PabsCrfResult<LegacyMap> {
        signature_to_legacy_map(self)
    }
}

impl CompressedFirewallSignature {
    /// Recover the witness attribute names against a public policy.
    pub fn witness_attributes(&self, policy: &Policy) -> PabsCrfResult<Vec<String>> {
        let lsss = crate::lsss::lsss_from_policy_cached(policy)?;
        let mut attrs = Vec::with_capacity(self.witness_rows.len());
        for &row in &self.witness_rows {
            let idx = row as usize;
            let attr = lsss.row_to_attr().get(idx).ok_or_else(|| {
                PabsCrfError::InvalidInput(format!(
                    "Witness row {} is out of range for policy",
                    idx
                ))
            })?;
            attrs.push(attr.clone());
        }
        Ok(attrs)
    }

    /// Serialize and zstd-compress the transport object.
    pub fn to_bytes(&self) -> PabsCrfResult<Vec<u8>> {
        serialize_compressed_signature(self)
    }

    /// Parse a zstd-compressed transport blob.
    pub fn from_bytes(blob: &[u8]) -> PabsCrfResult<Self> {
        deserialize_compressed_signature(blob)
    }
}

/// Deserialize a structured signature from bytes.
pub fn deserialize_signature(bytes: &[u8]) -> PabsCrfResult<Signature> {
    bincode::deserialize(bytes).map_err(|e| {
        PabsCrfError::DeserializationError(format!("Failed to deserialize signature: {}", e))
    })
}

/// Generate a PABS-CRF signature for `message` under `policy` using structured inputs.
pub fn sign_structured(
    sk: &UserSecretKey,
    message: &[u8],
    policy: &Policy,
    tau: u64,
) -> PabsCrfResult<Signature> {
    if sk.is_punctured(tau)? {
        return Err(PabsCrfError::InvalidInput(format!(
            "Cannot sign under punctured tag tau={}",
            tau
        )));
    }

    let parameter_model = sk.parameter_model.clone();
    let mlwe_params = parameter_model.protocol.mlwe;
    let max_attempts = parameter_model.implementation.firewall_max_attempts;

    for _ in 0..max_attempts {
        let mut rng = thread_rng();
        let firewall = CryptographicReverseFirewall::new(mlwe_params, max_attempts);
        let precommit = firewall.precommit(&sk.matrix_a, &mut rng)?;

        let (core, _witness_rows, pk_hash) = pabs::core_sign(
            sk,
            message,
            policy,
            &parameter_model,
            precommit.delta_bytes(),
            tau,
            &mut rng,
        )?;

        match firewall.finalize_precommitted(core, &sk.matrix_a, precommit, &pk_hash, tau) {
            Ok(sig) => return Ok(sig),
            Err(_) => continue,
        }
    }

    Err(PabsCrfError::SecurityViolation(format!(
        "Sign structured failed after {} firewall attempts",
        max_attempts
    )))
}

/// Generate a PABS-CRF signature for `message` under `policy` (Legacy HashMap API).
pub fn sign(sk: &LegacyMap, message: &[u8], policy: &Policy, tau: u64) -> PabsCrfResult<LegacyMap> {
    let sk_struct = get_user_secret_key(sk)?;
    let sig_struct = sign_structured(&sk_struct, message, policy, tau)?;
    sig_struct.to_signature_map()
}

/// Convenience wrapper for the signing API.
pub struct Sign;

impl Sign {
    /// Create a signer facade.
    pub fn new() -> Self {
        Self
    }

    /// Generate a predicate signature for `message` under `policy`.
    pub fn generate(
        &self,
        sk: &LegacyMap,
        message: &[u8],
        policy: &Policy,
        tau: u64,
    ) -> PabsCrfResult<LegacyMap> {
        sign(sk, message, policy, tau)
    }

    /// Generate and return a zstd-compressed signature blob.
    pub fn sign_compressed(
        &self,
        sk: &LegacyMap,
        message: &[u8],
        policy: &Policy,
        tau: u64,
    ) -> PabsCrfResult<Vec<u8>> {
        let sk_struct = get_user_secret_key(sk)?;
        self.sign_compressed_structured(&sk_struct, message, policy, tau)
    }

    /// Generate and return a zstd-compressed signature blob from structured inputs.
    pub fn sign_compressed_structured(
        &self,
        sk: &UserSecretKey,
        message: &[u8],
        policy: &Policy,
        tau: u64,
    ) -> PabsCrfResult<Vec<u8>> {
        let sig_struct = sign_structured(sk, message, policy, tau)?;
        sig_struct.compress(&sk.params)?.to_bytes()
    }

    /// Generate multiple signatures in batch.
    pub fn batch_sign(
        &self,
        sk: &LegacyMap,
        messages: &[&[u8]],
        policies: &[Policy],
        taus: &[u64],
    ) -> Vec<PabsCrfResult<LegacyMap>> {
        if messages.len() != policies.len() || messages.len() != taus.len() {
            return vec![Err(PabsCrfError::InvalidInput(
                "Mismatched messages, policies and taus lengths".to_string(),
            ))];
        }
        messages
            .iter()
            .zip(policies.iter())
            .zip(taus.iter())
            .map(|((m, p), &t)| self.generate(sk, m, p, t))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlwe::{MLWEParameters, Polynomial, PolynomialVector};
    use std::collections::HashMap;

    #[test]
    fn test_compressed_signature_encodes_witness_rows() {
        let params = MLWEParameters::new_128();
        let policy = Policy::parse("admin AND finance").expect("policy should parse");

        let mut z = PolynomialVector::new(params.m, params.n);
        for (poly_idx, poly) in z.elements.iter_mut().enumerate() {
            for (coeff_idx, coeff) in poly.coeffs.iter_mut().enumerate() {
                *coeff = ((poly_idx + coeff_idx) as i32 % 17) - 8;
            }
        }

        let mut challenge = Polynomial::new(params.n);
        challenge.coeffs[1] = 1;
        challenge.coeffs[9] = -1;

        let signature = FirewallSignature {
            z,
            challenge,
            hints: None,
            policy: policy.clone(),
            message_hash: vec![42u8; 32],
            attributes_used: vec!["admin".to_string(), "finance".to_string()],
            policy_digest: vec![1u8; 32],
            firewall_delta: PolynomialVector::new(params.k, params.n),
            firewall_tag: vec![3u8; 32],
            parameter_set_id: "top-tier-128".to_string(),
            pk_hash: Vec::new(),
            crf_seed: None,
            tau: 0,
            gid: [0u8; 32],
        };

        let compressed = signature
            .compress(&params)
            .expect("compression should succeed");
        let blob = compressed.to_bytes().expect("compression should succeed");
        let decoded = CompressedFirewallSignature::from_bytes(&blob)
            .expect("compressed signature should deserialize");

        assert_eq!(decoded.packed_z, compressed.packed_z);
        assert_eq!(decoded.encoded_c, compressed.encoded_c);
        assert_eq!(decoded.witness_rows, vec![0, 1]);
        assert_eq!(
            decoded
                .witness_attributes(&policy)
                .expect("witness rows should decode"),
            signature.attributes_used
        );
    }

    #[test]
    fn test_sign_requires_structured_secret_key() {
        let mut sk = HashMap::new();
        sk.insert(
            "attributes".to_string(),
            bincode::serialize(&vec!["admin".to_string()]).unwrap(),
        );

        let err = sign(&sk, b"msg", &Policy::parse("admin").unwrap(), 0).unwrap_err();
        assert!(matches!(err, PabsCrfError::DeserializationError(_)));
    }

    #[test]
    fn test_puncture_prevents_signing() {
        let (pp, msk) = crate::setup::setup_structured(128);
        let mut sk = crate::keygen::keygen_structured(&pp, &msk, &["admin", "finance"]).unwrap();
        let policy = Policy::parse("admin AND finance").unwrap();
        let message = b"puncture test message";

        sk.puncture(42).unwrap();
        let err = sign_structured(&sk, message, &policy, 42).unwrap_err();
        assert!(
            matches!(err, PabsCrfError::InvalidInput(ref s) if s.contains("punctured tag tau=42"))
        );
    }

    #[test]
    fn test_sign_with_non_punctured_tag_succeeds() {
        let (pp, msk) = crate::setup::setup_structured(128);
        let mut sk = crate::keygen::keygen_structured(&pp, &msk, &["admin", "finance"]).unwrap();
        let policy = Policy::parse("admin AND finance").unwrap();
        let message = b"non-punctured tag test";

        sk.puncture(1).unwrap();
        let sig = sign_structured(&sk, message, &policy, 2).unwrap();
        assert!(crate::verify::verify_signature_struct(&pp, message, &policy, &sig).unwrap());
    }

    #[test]
    fn test_puncture_tag_included_in_challenge() {
        let (pp, msk) = crate::setup::setup_structured(128);
        let sk = crate::keygen::keygen_structured(&pp, &msk, &["admin", "finance"]).unwrap();
        let policy = Policy::parse("admin AND finance").unwrap();
        let message = b"challenge divergence test";

        let sig42 = sign_structured(&sk, message, &policy, 42).unwrap();
        let sig43 = sign_structured(&sk, message, &policy, 43).unwrap();

        assert_ne!(sig42.challenge.coeffs, sig43.challenge.coeffs);
    }

    #[test]
    fn test_verify_checks_tau() {
        let (pp, msk) = crate::setup::setup_structured(128);
        let sk = crate::keygen::keygen_structured(&pp, &msk, &["admin", "finance"]).unwrap();
        let policy = Policy::parse("admin AND finance").unwrap();
        let message = b"tau binding verification test";

        let sig = sign_structured(&sk, message, &policy, 42).unwrap();
        assert_eq!(sig.tau, 42);
        assert!(crate::verify::verify_signature_struct(&pp, message, &policy, &sig).unwrap());
    }

    #[test]
    fn test_verify_rejects_bound_metadata_tampering() {
        let (pp, msk) = crate::setup::setup_structured(128);
        let sk = crate::keygen::keygen_structured(&pp, &msk, &["admin", "finance"]).unwrap();
        let policy = Policy::parse("admin AND finance").unwrap();
        let message = b"metadata binding verification test";

        let sig = sign_structured(&sk, message, &policy, 42).unwrap();
        assert!(crate::verify::verify_signature_struct(&pp, message, &policy, &sig).unwrap());

        let assert_rejected = |label: &str, tampered: Signature| {
            assert!(
                !crate::verify::verify_signature_struct(&pp, message, &policy, &tampered).unwrap(),
                "tampered {} field was accepted",
                label
            );
        };

        let mut tampered = sig.clone();
        tampered.parameter_set_id = "top-tier-192".to_string();
        assert_rejected("parameter_set_id", tampered);

        let mut tampered = sig.clone();
        tampered.pk_hash[0] ^= 0x01;
        assert_rejected("pk_hash", tampered);

        let mut tampered = sig.clone();
        tampered.policy_digest[0] ^= 0x01;
        assert_rejected("policy_digest", tampered);

        let mut tampered = sig.clone();
        tampered.message_hash[0] ^= 0x01;
        assert_rejected("message_hash", tampered);

        let mut tampered = sig.clone();
        tampered.tau ^= 0x01;
        assert_rejected("tau", tampered);

        let mut tampered = sig.clone();
        tampered.gid[0] ^= 0x01;
        assert_rejected("gid", tampered);

        let mut tampered = sig.clone();
        tampered.firewall_tag[0] ^= 0x01;
        assert_rejected("firewall_tag", tampered);

        let mut tampered = sig.clone();
        let q = pp.params.q as i32;
        tampered.firewall_delta.elements[0].coeffs[0] =
            (tampered.firewall_delta.elements[0].coeffs[0] + 1).rem_euclid(q);
        assert_rejected("firewall_delta", tampered);
    }
}
