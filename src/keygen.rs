//! Key generation for the PABS-CRF scheme
//!
//! Generates user secret key sk_S containing:
//! - attributes (bincode serialized Vec<String>)
//! - secret_key (MLWE secret polynomial vector s)
//! - error_vector (MLWE error polynomial vector e)
//! - matrix_A (MLWE public matrix A)
//! - puncture_tree (binary tree for key revocation)
//! - puncture_count (revocation counter)
//! - params (MLWE parameters)

use crate::compat::{
    get_master_secret_key, get_public_parameters, user_secret_key_to_legacy_map, LegacyMap,
};
use crate::errors::{PabsCrfError, PabsCrfResult};
use crate::mlwe::{MLWEParameters, PolynomialMatrix, PolynomialVector};
use crate::parameter_sets::TopTierParameterModel;
use crate::puncture_tree::{PunctureTree, MAX_PUNCTURE_DEPTH};
use crate::setup::PublicParameters;
use crate::trapdoor::strict::TrapdoorMode;
use rand::thread_rng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// User secret key for the PABS-CRF scheme
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct UserSecretKey {
    pub params: MLWEParameters,
    pub parameter_model: TopTierParameterModel,
    pub trapdoor_mode: TrapdoorMode,
    #[zeroize(skip)]
    pub gid: [u8; 32],
    pub attributes: Vec<String>,
    pub preimages: Vec<PolynomialVector>,
    pub matrix_a: PolynomialMatrix,
    pub puncture_tree: PunctureTree,
    pub puncture_count: u64,
    pub witness_schema: String,
}

/// Deserialize a structured user secret key from bytes.
pub fn deserialize_user_secret_key(bytes: &[u8]) -> PabsCrfResult<UserSecretKey> {
    bincode::deserialize(bytes).map_err(|e| {
        PabsCrfError::DeserializationError(format!("Failed to deserialize user secret key: {}", e))
    })
}

impl UserSecretKey {
    /// Check whether the given puncture tag has been punctured.
    pub fn is_punctured(&self, tau: u64) -> PabsCrfResult<bool> {
        self.puncture_tree.is_punctured(tau)
    }

    /// Puncture the given tag, preventing future signing under it.
    /// Returns `true` if the tag was newly punctured, `false` if already punctured.
    pub fn puncture(&mut self, tau: u64) -> PabsCrfResult<bool> {
        let was_new = self.puncture_tree.puncture(tau)?;
        if was_new {
            self.puncture_count += 1;
        }
        Ok(was_new)
    }
}

/// Derive a user secret key bound to the supplied attribute list.
pub fn keygen_structured(
    pp: &PublicParameters,
    msk: &crate::setup::MasterSecretKey,
    attributes: &[&str],
) -> PabsCrfResult<UserSecretKey> {
    let mut rng = thread_rng();
    let params = &pp.params;
    let trapdoor = crate::trapdoor::strict::StrictTrapdoor::new(params);

    let mut gid = [0u8; 32];
    rng.fill_bytes(&mut gid);

    let attr_strings: Vec<String> = attributes.iter().map(|s| s.to_string()).collect();
    for attr in &attr_strings {
        crate::policy::Policy::validate_attribute_name(attr)?;
    }
    let mut user_preimages = Vec::new();
    for attr in &attr_strings {
        let u_target = crate::utils::hash_to_target_vector_with_gid(attr, &gid, params);
        let s_i = trapdoor.sample_preimage(&msk.matrix_a, &msk.trapdoor_t, &u_target, &mut rng)?;
        user_preimages.push(s_i);
    }

    let revocation_depth = pp.parameter_model.implementation.revocation_tree_depth;
    if revocation_depth > MAX_PUNCTURE_DEPTH {
        return Err(PabsCrfError::InvalidParameters(format!(
            "revocation_tree_depth={} exceeds MAX_PUNCTURE_DEPTH={}",
            revocation_depth, MAX_PUNCTURE_DEPTH
        )));
    }
    let tree = PunctureTree::new(revocation_depth);

    Ok(UserSecretKey {
        params: params.clone(),
        parameter_model: pp.parameter_model.clone(),
        trapdoor_mode: msk.trapdoor_mode,
        gid,
        attributes: attr_strings,
        preimages: user_preimages,
        matrix_a: pp.matrix_a.clone(),
        puncture_tree: tree,
        puncture_count: 0,
        witness_schema: "attribute-preimage/v4".to_string(),
    })
}

/// Derive a user secret key bound to the supplied attribute list (Legacy HashMap API).
pub fn keygen(pp: &LegacyMap, msk: &LegacyMap, attributes: &[&str]) -> LegacyMap {
    try_keygen(pp, msk, attributes).expect("Structured key generation failed")
}

/// Derive a user secret key and propagate serialization / parameter failures explicitly (Legacy HashMap API).
pub fn try_keygen(
    pp: &LegacyMap,
    msk: &LegacyMap,
    attributes: &[&str],
) -> PabsCrfResult<LegacyMap> {
    let pp_struct = get_public_parameters(pp)?;
    let msk_struct = get_master_secret_key(msk)?;

    let sk_struct = keygen_structured(&pp_struct, &msk_struct, attributes)?;
    user_secret_key_to_legacy_map(&sk_struct)
}

/// Convenience wrapper for attribute key generation.
pub struct KeyGen;

impl KeyGen {
    /// Create a key generation facade.
    pub fn new() -> Self {
        Self
    }

    /// Generate a user key for `attributes`.
    pub fn generate(&self, pp: &LegacyMap, msk: &LegacyMap, attributes: &[&str]) -> LegacyMap {
        keygen(pp, msk, attributes)
    }

    /// Generate a user key for `attributes` with explicit error propagation.
    pub fn try_generate(
        &self,
        pp: &LegacyMap,
        msk: &LegacyMap,
        attributes: &[&str],
    ) -> PabsCrfResult<LegacyMap> {
        try_keygen(pp, msk, attributes)
    }

    /// Generate a structured user key without going through the legacy map layer.
    pub fn try_generate_structured(
        &self,
        pp: &PublicParameters,
        msk: &crate::setup::MasterSecretKey,
        attributes: &[&str],
    ) -> PabsCrfResult<UserSecretKey> {
        keygen_structured(pp, msk, attributes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn test_user_secret_key_zeroize() {
        let (pp, msk) = crate::setup::setup_structured(128);
        let mut sk = keygen_structured(&pp, &msk, &["attr1", "attr2"]).unwrap();
        sk.zeroize();
        assert!(sk.attributes.iter().all(|s| s.is_empty()));
        assert!(sk
            .preimages
            .iter()
            .all(|pv| pv.elements.iter().all(|p| p.coeffs.iter().all(|&c| c == 0))));
        assert!(sk.puncture_count == 0);
    }

    #[test]
    fn test_keygen_uses_configured_revocation_tree_depth() {
        let (mut pp, mut msk) = crate::setup::setup_structured(128);
        pp.parameter_model.implementation.revocation_tree_depth = 12;
        msk.parameter_model.implementation.revocation_tree_depth = 12;

        let sk = keygen_structured(&pp, &msk, &["attr1"]).unwrap();

        assert_eq!(sk.puncture_tree.max_depth, 12);
    }

    #[test]
    fn test_master_secret_key_zeroize() {
        let (_, mut msk) = crate::setup::setup_structured(128);
        msk.zeroize();
        assert!(msk
            .matrix_a
            .elements
            .iter()
            .all(|row| row.iter().all(|p| p.coeffs.iter().all(|&c| c == 0))));
        assert!(msk
            .trapdoor_t
            .elements
            .iter()
            .all(|row| row.iter().all(|p| p.coeffs.iter().all(|&c| c == 0))));
    }
}
