//! Key puncturing for the PABS-CRF scheme
//!
//! This module implements the puncturing mechanism using a binary tree
//! for efficient O(log n) puncture operations and membership checks.

use crate::errors::{PabsCrfError, PabsCrfResult};
use crate::puncture_tree::PunctureTree;
use std::collections::HashMap;

/// Extract puncture tree from signing key with explicit error handling
fn extract_puncture_tree(sk: &HashMap<String, Vec<u8>>) -> PabsCrfResult<PunctureTree> {
    let tree_bytes = sk.get("puncture_tree").ok_or_else(|| {
        PabsCrfError::DeserializationError("Missing puncture_tree field in signing key".to_string())
    })?;

    bincode::deserialize(tree_bytes).map_err(|e| {
        PabsCrfError::DeserializationError(format!("Failed to deserialize puncture_tree: {}", e))
    })
}

/// Key puncturing function with explicit error handling
///
/// # Arguments
/// * `sk` - User signing key
/// * `tau` - Time tag to puncture
///
/// # Returns
/// Punctured signing key or error
pub fn puncture(
    sk: &HashMap<String, Vec<u8>>,
    tau: u64,
) -> PabsCrfResult<HashMap<String, Vec<u8>>> {
    // Create a copy of the key
    let mut punctured_sk = sk.clone();

    // Extract current puncture tree (explicit error, no silent fallback)
    let mut tree = extract_puncture_tree(&punctured_sk)?;

    // Puncture the tag
    let _was_punctured = tree.puncture(tau)?;

    // Update tree in key (panic on serialization failure - internal invariant violation)
    let tree_bytes = bincode::serialize(&tree).map_err(|e| {
        PabsCrfError::SerializationError(format!("Failed to serialize puncture_tree: {}", e))
    })?;
    punctured_sk.insert("puncture_tree".to_string(), tree_bytes);

    // Update puncture count
    let count = tree.puncture_count as u64;
    punctured_sk.insert("puncture_count".to_string(), count.to_le_bytes().to_vec());

    Ok(punctured_sk)
}

/// Puncture struct
pub struct Puncture;

impl Puncture {
    /// Create a new puncture instance
    pub fn new() -> Self {
        Self
    }

    /// Puncture a key with explicit error handling
    pub fn puncture(
        &self,
        sk: &HashMap<String, Vec<u8>>,
        tau: u64,
    ) -> PabsCrfResult<HashMap<String, Vec<u8>>> {
        puncture(sk, tau)
    }

    /// Puncture multiple tags with explicit error handling
    pub fn puncture_multiple(
        &self,
        sk: &HashMap<String, Vec<u8>>,
        taus: &[u64],
    ) -> PabsCrfResult<HashMap<String, Vec<u8>>> {
        let mut punctured_sk = sk.clone();

        // Extract current puncture tree (explicit error, no silent fallback)
        let mut tree = extract_puncture_tree(&punctured_sk)?;

        // Puncture all tags
        for &tau in taus {
            tree.puncture(tau)?;
        }

        // Update tree in key (explicit error on serialization failure)
        let tree_bytes = bincode::serialize(&tree).map_err(|e| {
            PabsCrfError::SerializationError(format!("Failed to serialize puncture_tree: {}", e))
        })?;
        punctured_sk.insert("puncture_tree".to_string(), tree_bytes);
        punctured_sk.insert(
            "puncture_count".to_string(),
            tree.puncture_count.to_le_bytes().to_vec(),
        );

        Ok(punctured_sk)
    }

    /// Check if a tag is punctured with explicit error handling
    pub fn is_punctured(&self, sk: &HashMap<String, Vec<u8>>, tau: u64) -> PabsCrfResult<bool> {
        let tree = extract_puncture_tree(sk)?;
        Ok(tree.is_punctured(tau)?)
    }

    /// Get all punctured tags with explicit error handling
    pub fn get_punctured_tags(&self, sk: &HashMap<String, Vec<u8>>) -> PabsCrfResult<Vec<u64>> {
        let tree = extract_puncture_tree(sk)?;
        Ok(tree.get_punctured_tags())
    }

    /// Get puncture proof for a tag with explicit error handling
    pub fn get_puncture_proof(
        &self,
        sk: &HashMap<String, Vec<u8>>,
        tau: u64,
    ) -> PabsCrfResult<Option<Vec<u64>>> {
        let tree = extract_puncture_tree(sk)?;
        Ok(tree.get_puncture_proof(tau)?)
    }
}
