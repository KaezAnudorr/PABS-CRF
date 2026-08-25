//! PABS-CRF: Lattice-based Predicate Attribute-Based Signature with Cryptographic Reverse Firewall
//!
//! This library implements a lattice-based predicate attribute-based signature scheme
//! with cryptographic reverse firewall, based on Module-LWE for post-quantum security.

#![warn(missing_docs)]

/// Shared algebra helpers used by the structured path.
pub mod algebra;
pub mod canonical;
pub mod compat;
pub mod compression;
pub mod errors;
/// Reverse-firewall transformation and validation logic.
pub mod firewall;
/// CDT discrete Gaussian sampler for GPV preimage sampling.
pub mod gaussian;
pub mod hardware_root;
pub mod keygen;
pub mod lsss;
pub mod mlwe;
pub mod optimization;
/// Structured PABS mainline objects and signing helpers.
pub mod pabs;
/// Top-tier protocol, implementation, and analysis parameter models.
pub mod parameter_sets;
pub mod policy;
pub mod puncture;
pub mod puncture_tree;
/// Sampling-related helper types and metadata.
pub mod samplers;
/// Structured signature serialization and transport helpers.
pub mod serialization;
pub mod setup;
pub mod sign;
pub mod trapdoor;
pub mod utils;
pub mod verify;

pub use errors::{PabsCrfError, PabsCrfResult};
pub use firewall::{CryptographicReverseFirewall, StrongFirewall};
pub use gaussian::CdtGaussianSampler;
pub use hardware_root::{FullChainProtection, HardwarePunctureState, HardwareType, PunctureProof};
pub use keygen::{deserialize_user_secret_key, keygen, try_keygen, KeyGen, UserSecretKey};
pub use lsss::LSSSShareMatrix;
pub use mlwe::{MLWEKeyPair, MLWEParameters, MLWESignature};
pub use pabs::types::{CompressedFirewallSignature, CorePredicateSignature, FirewallSignature};
pub use parameter_sets::{
    AnalysisParameterSet, ImplementationParameterSet, ProtocolParameterSet, SecurityTarget,
    TopTierParameterModel,
};
pub use policy::Policy;
pub use puncture::{puncture, Puncture};
pub use puncture_tree::PunctureTree;
pub use setup::{deserialize_master_secret_key, deserialize_public_parameters};
pub use setup::{setup, MasterSecretKey, PublicParameters, Setup};
pub use sign::{sign, CompressedSignature, Sign, Signature};
#[allow(deprecated)]
pub use utils::SideChannelProtection;
pub use utils::{ConstantTimeOps, HashUtils};
pub use verify::{verify, Verify};
