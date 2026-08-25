use crate::mlwe::MLWEParameters;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Default signer-local revocation tree depth used by the benchmark configuration.
pub const DEFAULT_REVOCATION_TREE_DEPTH: usize = 31;

fn default_revocation_tree_depth() -> usize {
    DEFAULT_REVOCATION_TREE_DEPTH
}

/// Security target label used by the formal protocol path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub enum SecurityTarget {
    /// Nominal 128-bit target.
    Bits128,
    /// Nominal 192-bit target.
    Bits192,
    /// Nominal 256-bit target.
    Bits256,
}

impl SecurityTarget {
    /// Parse a security target from the public setup level.
    pub fn from_level(level: u32) -> Self {
        match level {
            256 => Self::Bits256,
            192 => Self::Bits192,
            _ => Self::Bits128,
        }
    }

    /// Stable identifier used in serialized artifacts.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bits128 => "top-tier-128",
            Self::Bits192 => "top-tier-192",
            Self::Bits256 => "top-tier-256",
        }
    }
}

/// Protocol-facing parameter set shared by setup, signing, verification and compression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct ProtocolParameterSet {
    /// Security label.
    pub security_target: SecurityTarget,
    /// Underlying MLWE parameter set reused by the implementation.
    pub mlwe: MLWEParameters,
    /// Version string for structured transport formats.
    pub transport_version: String,
    /// Domain separation label for transcript hashing.
    pub firewall_domain_separator: String,
}

/// Implementation knobs that do not change the protocol semantics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct ImplementationParameterSet {
    /// Maximum number of firewall rejection retries.
    pub firewall_max_attempts: usize,
    /// Whether verification should assert matrix/vector dimension matches.
    pub enforce_dimension_checks: bool,
    /// Depth of the signer-local revocation tree.
    #[serde(default = "default_revocation_tree_depth")]
    pub revocation_tree_depth: usize,
}

/// Analysis-facing knobs and identifiers used by tests and evaluation scripts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct AnalysisParameterSet {
    /// Label emitted in reports.
    pub report_label: String,
    /// Whether tests should record witness norm distributions.
    pub collect_witness_norm_stats: bool,
}

/// Aggregated formal parameter model used by the v4 structured path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
pub struct TopTierParameterModel {
    /// Protocol semantics.
    pub protocol: ProtocolParameterSet,
    /// Implementation-only settings.
    pub implementation: ImplementationParameterSet,
    /// Analysis-only settings.
    pub analysis: AnalysisParameterSet,
}

impl TopTierParameterModel {
    /// Construct the formal parameter model for a requested setup level.
    pub fn for_security_level(level: u32) -> Self {
        Self::for_security_level_with_sigma(level, 100.0)
    }

    /// Construct the formal parameter model with a custom Gaussian σ for
    /// trapdoor preimage sampling.  The MLWE parameters are derived from
    /// the security level and then `.with_sigma(sigma)` is applied, which
    /// proportionally scales `gamma1` to keep the norm bounds satisfiable.
    pub fn for_security_level_with_sigma(level: u32, sigma: f64) -> Self {
        let security_target = SecurityTarget::from_level(level);
        let base_mlwe = match security_target {
            SecurityTarget::Bits256 => MLWEParameters::new_256(),
            SecurityTarget::Bits192 => MLWEParameters::new_192(),
            SecurityTarget::Bits128 => MLWEParameters::new_128(),
        };
        let mlwe = base_mlwe.with_sigma(sigma);

        Self {
            protocol: ProtocolParameterSet {
                security_target,
                mlwe,
                transport_version: "firewall-signature/v4".to_string(),
                firewall_domain_separator: "PABS-CRF::Firewall::v4".to_string(),
            },
            implementation: ImplementationParameterSet {
                firewall_max_attempts: 128,
                enforce_dimension_checks: true,
                revocation_tree_depth: DEFAULT_REVOCATION_TREE_DEPTH,
            },
            analysis: AnalysisParameterSet {
                report_label: format!("pabs-crf-{}-sigma-{:.1}", security_target.as_str(), sigma),
                collect_witness_norm_stats: true,
            },
        }
    }

    pub fn for_security_level_strict(level: u32) -> Self {
        Self::for_security_level_with_sigma(level, 360.0)
    }
}
