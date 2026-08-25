//! Legacy compatibility helpers for `HashMap<String, Vec<u8>>` APIs.
//!
//! Core cryptographic flows should operate on structured objects. This module
//! isolates the legacy map conversions used by older tests, examples, and
//! benchmarks so they do not leak into the main scheme logic.

use crate::errors::{PabsCrfError, PabsCrfResult};
use crate::keygen::UserSecretKey;
use crate::setup::{
    deserialize_master_secret_key, deserialize_public_parameters, MasterSecretKey,
    PublicParameters, LEGACY_PP_STRUCT_KEY, MSK_STRUCT_KEY, PP_STRUCT_KEY,
};
use crate::sign::{deserialize_signature, Signature};
use serde::Serialize;
use std::collections::HashMap;

/// Legacy byte-map representation kept for backwards compatibility.
/// HashMap preserved for API continuity. Deterministic serialization
/// for KAT replay (audit C2/M2) should be implemented by serialization
/// wrappers that explicitly sort keys before bincode encoding if needed.
pub type LegacyMap = HashMap<String, Vec<u8>>;

const SK_STRUCT_KEY: &str = "sk_struct";
const SIG_STRUCT_KEY: &str = "sig_struct";

fn serialize_field<T: Serialize>(label: &str, value: &T) -> PabsCrfResult<Vec<u8>> {
    bincode::serialize(value).map_err(|e| {
        PabsCrfError::SerializationError(format!("Failed to serialize {}: {}", label, e))
    })
}

fn insert_serialized<T: Serialize>(
    map: &mut LegacyMap,
    key: &str,
    label: &str,
    value: &T,
) -> PabsCrfResult<()> {
    map.insert(key.to_string(), serialize_field(label, value)?);
    Ok(())
}

fn insert_u64(map: &mut LegacyMap, key: &str, value: u64) {
    map.insert(key.to_string(), value.to_le_bytes().to_vec());
}

fn insert_params_fields(
    map: &mut LegacyMap,
    params: &crate::mlwe::MLWEParameters,
) -> PabsCrfResult<()> {
    insert_serialized(map, "params", "params", params)?;
    insert_u64(map, "params_n", params.n as u64);
    insert_u64(map, "params_k", params.k as u64);
    insert_u64(map, "params_q", params.q as u64);
    insert_u64(map, "params_eta1", params.eta1 as u64);
    insert_u64(map, "params_eta2", params.eta2 as u64);
    insert_u64(map, "params_gamma1", params.gamma1 as u64);
    insert_u64(map, "params_gamma2", params.gamma2 as u64);
    insert_u64(map, "params_beta", params.beta as u64);
    insert_u64(map, "params_m", params.m as u64);
    insert_u64(map, "params_ell", params.ell as u64);
    insert_u64(map, "params_base", params.base as u64);
    map.insert(
        "params_sigma".to_string(),
        params.sigma.to_le_bytes().to_vec(),
    );
    insert_u64(map, "params_tau", params.tau as u64);
    Ok(())
}

/// Extract structured public parameters from a legacy map.
pub fn get_public_parameters(pp: &LegacyMap) -> PabsCrfResult<PublicParameters> {
    let bytes = pp
        .get(PP_STRUCT_KEY)
        .or_else(|| pp.get(LEGACY_PP_STRUCT_KEY))
        .ok_or_else(|| {
            PabsCrfError::DeserializationError("Missing structured public parameters".to_string())
        })?;
    deserialize_public_parameters(bytes)
}

/// Extract a structured master secret key from a legacy map.
pub fn get_master_secret_key(msk: &LegacyMap) -> PabsCrfResult<MasterSecretKey> {
    let bytes = msk.get(MSK_STRUCT_KEY).ok_or_else(|| {
        PabsCrfError::DeserializationError("Missing structured master secret key".to_string())
    })?;
    deserialize_master_secret_key(bytes)
}

/// Extract a structured user secret key from a legacy map.
pub fn get_user_secret_key(sk: &LegacyMap) -> PabsCrfResult<UserSecretKey> {
    let bytes = sk.get(SK_STRUCT_KEY).ok_or_else(|| {
        PabsCrfError::DeserializationError("Missing structured user secret key".to_string())
    })?;
    crate::keygen::deserialize_user_secret_key(bytes)
}

/// Extract a structured signature from a legacy map.
pub fn get_signature(signature: &LegacyMap) -> PabsCrfResult<Signature> {
    let bytes = signature.get(SIG_STRUCT_KEY).ok_or_else(|| {
        PabsCrfError::DeserializationError("Missing structured signature".to_string())
    })?;
    deserialize_signature(bytes)
}

/// Convert structured public parameters into the legacy map layout.
pub fn public_parameters_to_legacy_map(pp: &PublicParameters) -> PabsCrfResult<LegacyMap> {
    let mut map = LegacyMap::new();
    let pp_struct_bytes = serialize_field("public parameters", pp)?;
    map.insert(PP_STRUCT_KEY.to_string(), pp_struct_bytes.clone());
    map.insert(LEGACY_PP_STRUCT_KEY.to_string(), pp_struct_bytes);
    insert_params_fields(&mut map, &pp.params)?;
    insert_serialized(&mut map, "matrix_A", "matrix_A", &pp.matrix_a)?;
    map.insert("matrix_a_seed".to_string(), pp.matrix_a_seed.to_vec());
    Ok(map)
}

/// Convert a structured master secret key into the legacy map layout.
pub fn master_secret_key_to_legacy_map(msk: &MasterSecretKey) -> PabsCrfResult<LegacyMap> {
    let mut map = LegacyMap::new();
    insert_serialized(&mut map, MSK_STRUCT_KEY, "msk_struct", msk)?;
    insert_params_fields(&mut map, &msk.params)?;
    insert_serialized(&mut map, "secret_key", "trapdoor_t", &msk.trapdoor_t)?;
    insert_serialized(&mut map, "matrix_A", "matrix_A", &msk.matrix_a)?;
    Ok(map)
}

/// Convert a structured user secret key into the legacy map layout.
pub fn user_secret_key_to_legacy_map(sk: &UserSecretKey) -> PabsCrfResult<LegacyMap> {
    let mut map = LegacyMap::new();
    insert_serialized(&mut map, SK_STRUCT_KEY, "sk_struct", sk)?;
    insert_serialized(&mut map, "attributes", "attributes", &sk.attributes)?;
    insert_serialized(&mut map, "secret_key", "preimages", &sk.preimages)?;
    insert_serialized(&mut map, "matrix_A", "matrix_A", &sk.matrix_a)?;
    insert_serialized(
        &mut map,
        "puncture_tree",
        "puncture_tree",
        &sk.puncture_tree,
    )?;
    map.insert(
        "puncture_count".to_string(),
        sk.puncture_count.to_le_bytes().to_vec(),
    );
    map.insert("gid".to_string(), sk.gid.to_vec());
    insert_params_fields(&mut map, &sk.params)?;
    Ok(map)
}

/// Convert a structured signature into the legacy map layout.
pub fn signature_to_legacy_map(signature: &Signature) -> PabsCrfResult<LegacyMap> {
    let mut map = LegacyMap::new();
    insert_serialized(&mut map, SIG_STRUCT_KEY, "sig_struct", signature)?;
    insert_serialized(&mut map, "z", "z", &signature.z)?;
    insert_serialized(&mut map, "challenge", "challenge", &signature.challenge)?;
    insert_serialized(&mut map, "policy", "policy", &signature.policy)?;
    insert_serialized(
        &mut map,
        "firewall_delta",
        "firewall_delta",
        &signature.firewall_delta,
    )?;
    map.insert("firewall_tag".to_string(), signature.firewall_tag.clone());
    map.insert("message_hash".to_string(), signature.message_hash.clone());
    map.insert("policy_digest".to_string(), signature.policy_digest.clone());
    map.insert(
        "parameter_set_id".to_string(),
        signature.parameter_set_id.as_bytes().to_vec(),
    );
    map.insert(
        "attributes_used".to_string(),
        serialize_field("attributes_used", &signature.attributes_used)?,
    );
    map.insert("gid".to_string(), signature.gid.to_vec());
    if let Some(ref hints) = signature.hints {
        insert_serialized(&mut map, "hints", "hints", hints)?;
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlwe::{MLWEParameters, Polynomial, PolynomialVector};
    use crate::pabs::types::FirewallSignature;
    use crate::policy::Policy;

    fn make_signature_with_hints(hints: Option<PolynomialVector>) -> FirewallSignature {
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
        FirewallSignature {
            z,
            challenge,
            hints,
            policy,
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
        }
    }

    #[test]
    fn test_legacy_map_contains_hints() {
        let params = MLWEParameters::new_128();
        let mut hints = PolynomialVector::new(params.k, params.n);
        for (i, poly) in hints.elements.iter_mut().enumerate() {
            for (j, coeff) in poly.coeffs.iter_mut().enumerate() {
                *coeff = ((i + j) as i32 % 5) - 2;
            }
        }
        let sig = make_signature_with_hints(Some(hints));
        let map = signature_to_legacy_map(&sig).expect("legacy map conversion should succeed");
        assert!(
            map.contains_key("hints"),
            "legacy map should contain 'hints' key when hints are present"
        );
        let restored: PolynomialVector = bincode::deserialize(map.get("hints").unwrap())
            .expect("hints should deserialize back to PolynomialVector");
        assert_eq!(restored, sig.hints.unwrap());
    }

    #[test]
    fn test_legacy_map_no_hints_when_none() {
        let sig = make_signature_with_hints(None);
        let map = signature_to_legacy_map(&sig).expect("legacy map conversion should succeed");
        assert!(
            !map.contains_key("hints"),
            "legacy map should NOT contain 'hints' key when hints are None"
        );
    }
}
