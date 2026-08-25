use crate::mlwe::{Polynomial, PolynomialVector};
use crate::policy::Policy;
use serde::{Deserialize, Serialize};

/// Core signer output before firewall transformation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorePredicateSignature {
    /// Base response vector.
    pub z: PolynomialVector,
    /// Sparse Fiat-Shamir challenge.
    pub challenge: Polynomial,
    /// Verification hints.
    pub hints: Option<PolynomialVector>,
    /// Bound policy.
    pub policy: Policy,
    /// Hash of the message.
    pub message_hash: Vec<u8>,
    /// Attributes used in the witness.
    pub attributes_used: Vec<String>,
    /// Hash of the lowered policy relation.
    pub policy_digest: Vec<u8>,
    /// Parameter set identifier.
    pub parameter_set_id: String,
    /// User GID bound to the target vector derivation (S-1 anti-collusion).
    pub gid: [u8; 32],
}

/// Final publishable signature verified directly by external verifiers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirewallSignature {
    /// Firewall-rerandomized response vector.
    pub z: PolynomialVector,
    /// Sparse Fiat-Shamir challenge.
    pub challenge: Polynomial,
    /// Verification hints.
    pub hints: Option<PolynomialVector>,
    /// Bound policy.
    pub policy: Policy,
    /// Hash of the message.
    pub message_hash: Vec<u8>,
    /// Attributes used in the witness.
    pub attributes_used: Vec<String>,
    /// Hash of the lowered policy relation.
    pub policy_digest: Vec<u8>,
    /// Public correction term `delta = A * r`.
    pub firewall_delta: PolynomialVector,
    /// Integrity tag for firewall metadata.
    pub firewall_tag: Vec<u8>,
    /// Parameter set identifier.
    pub parameter_set_id: String,
    /// SHA-256 hash of the system public key, included in challenge derivation.
    pub pk_hash: Vec<u8>,
    /// Legacy field retained for compatibility but unused on the formal path.
    pub crf_seed: Option<Vec<u8>>,
    /// Puncture tag under which this signature was produced.
    pub tau: u64,
    /// User GID bound to the target vector derivation (S-1 anti-collusion).
    pub gid: [u8; 32],
}

/// Compact transport/storage representation of the final firewall signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompressedFirewallSignature {
    /// Bit-packed response vector.
    pub packed_z: Vec<u8>,
    /// Sparse encoded challenge.
    pub encoded_c: Vec<u8>,
    /// Optional packed hints.
    pub packed_hints: Option<Vec<u8>>,
    /// Packed correction term.
    pub packed_delta: Vec<u8>,
    /// Witness rows in the lowered policy matrix.
    pub witness_rows: Vec<u16>,
    /// Hash of the lowered policy relation.
    pub policy_digest: Vec<u8>,
    /// Integrity tag for firewall metadata.
    pub firewall_tag: Vec<u8>,
    /// Parameter set identifier.
    pub parameter_set_id: String,
    /// SHA-256 hash of the system public key, included in challenge derivation.
    pub pk_hash: Vec<u8>,
    /// Legacy field retained for compatibility but unused on the formal path.
    pub crf_seed: Option<Vec<u8>>,
    /// Puncture tag under which this signature was produced.
    pub tau: u64,
    /// User GID bound to the target vector derivation (S-1 anti-collusion).
    pub gid: [u8; 32],
}
