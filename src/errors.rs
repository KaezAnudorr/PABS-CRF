//! Error types for the PABS-CRF scheme
//!
//! This module defines structured error types to replace unwrap() and panic() calls,
//! providing better error handling and debugging capabilities.
//!
//! All core APIs use this error type so failures propagate explicitly,
//! avoiding implicit fallbacks such as unwrap_or_default() that can hide errors.

use std::fmt;

/// Main error type for the PABS-CRF scheme
#[derive(Debug, Clone)]
pub enum PabsCrfError {
    /// Invalid parameters
    InvalidParameters(String),
    /// Key generation failed
    KeyGenFailed(String),
    /// Signing failed
    SignFailed(String),
    /// Verification failed
    VerificationFailed(String),
    /// Puncture operation failed
    PunctureFailed(String),
    /// Serialization error
    SerializationError(String),
    /// Deserialization error
    DeserializationError(String),
    /// Policy parsing error
    PolicyError(String),
    /// Memory allocation error
    OutOfMemory(String),
    /// Security violation
    SecurityViolation(String),
    /// Trapdoor sampling error
    TrapdoorError(String),
    /// Polynomial operation error
    PolynomialError(String),
    /// Invalid input (missing fields, wrong length, etc.)
    InvalidInput(String),
    /// Compression error
    CompressionError(String),
}

impl fmt::Display for PabsCrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PabsCrfError::InvalidParameters(msg) => write!(f, "Invalid parameters: {}", msg),
            PabsCrfError::KeyGenFailed(msg) => write!(f, "Key generation failed: {}", msg),
            PabsCrfError::SignFailed(msg) => write!(f, "Signing failed: {}", msg),
            PabsCrfError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            PabsCrfError::PunctureFailed(msg) => write!(f, "Puncture operation failed: {}", msg),
            PabsCrfError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            PabsCrfError::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
            PabsCrfError::PolicyError(msg) => write!(f, "Policy error: {}", msg),
            PabsCrfError::OutOfMemory(msg) => write!(f, "Out of memory: {}", msg),
            PabsCrfError::SecurityViolation(msg) => write!(f, "Security violation: {}", msg),
            PabsCrfError::TrapdoorError(msg) => write!(f, "Trapdoor sampling error: {}", msg),
            PabsCrfError::PolynomialError(msg) => write!(f, "Polynomial operation error: {}", msg),
            PabsCrfError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            PabsCrfError::CompressionError(msg) => write!(f, "Compression error: {}", msg),
        }
    }
}

impl std::error::Error for PabsCrfError {}

/// Result type alias for PABS-CRF operations
pub type PabsCrfResult<T> = Result<T, PabsCrfError>;
