//! Hardware Root of Trust integration for puncture state protection
//!
//! This module provides interfaces for integrating with hardware security
//! modules (TPM 2.0, ARM TrustZone TEE) to protect puncture state from
//! software-level subversion attacks (ASA).
//!
//! # Security Architecture
//! ```text
//! +------------------------------------------------------+
//! |              Software layer (subvertible)            |
//! |  +-----------------------------------------------+   |
//! |  | Signing implementation (may be backdoored)    |   |
//! |  |       v                                       |   |
//! |  | CRF rerandomization sanitizes emitted output  |   |
//! |  +-----------------------------------------------+   |
//! +------------------------------------------------------+
//! |          Hardware layer (root-of-trust protected)     |
//! |  +-----------------------------------------------+   |
//! |  | TPM/TEE secure area                           |   |
//! |  | - Puncture-state storage                      |   |
//! |  | - Secure key deletion                         |   |
//! |  | - Puncture-proof generation                   |   |
//! |  +-----------------------------------------------+   |
//! +------------------------------------------------------+
//! ```

//! # Implementation Note (Academic Mock)
//!
//! Current implementation provides a functional mock of the hardware-protected
//! state using software simulation with real ed25519 asymmetric signatures.
//! To integrate with real hardware, the `SoftwareSimulated` type should be
//! replaced with actual TPM/TEE calls.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{debug, info};

/// Hardware security module type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareType {
    /// TPM 2.0 (Trusted Platform Module)
    Tpm20,
    /// ARM TrustZone TEE
    TrustZoneTee,
    /// Intel SGX (Software Guard Extensions)
    IntelSgx,
    /// Secure Element (generic)
    SecureElement,
    /// Software simulation (for testing only)
    SoftwareSimulated,
}

/// A trait defining the Hardware Root of Trust interface.
/// This allows plugging in actual hardware drivers (TPM/TEE) while
/// maintaining the software-based simulation for academic verification.
pub trait HardwareRootOfTrust {
    /// Record that `tag` has been punctured in protected state.
    fn puncture(&mut self, tag: u64);
    /// Query whether `tag` has already been punctured.
    fn is_punctured(&self, tag: u64) -> bool;
    /// Produce a hardware-backed proof for the puncture status of `tag`.
    fn generate_puncture_proof(&self, tag: u64) -> PunctureProof;
    /// Securely erase a key reference inside the trusted component.
    fn secure_erase_key(&mut self, key_id: &str);
}

/// Puncture state stored in hardware
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwarePunctureState {
    hw_type: HardwareType,
    punctured_tags: HashSet<u64>,
    hw_signature: Vec<u8>,
    version: u64,
    hw_pubkey: Vec<u8>,
    hw_secret_key: Option<Vec<u8>>,
}

impl HardwareRootOfTrust for HardwarePunctureState {
    fn puncture(&mut self, tag: u64) {
        if self.punctured_tags.insert(tag) {
            self.version += 1;
            self.sign_state();
            info!(
                "Hardware-protected puncture: tag={}, version={}",
                tag, self.version
            );
        }
    }

    fn is_punctured(&self, tag: u64) -> bool {
        self.punctured_tags.contains(&tag)
    }

    fn generate_puncture_proof(&self, tag: u64) -> PunctureProof {
        let payload = {
            let mut p = Vec::new();
            p.extend_from_slice(&tag.to_le_bytes());
            p.extend_from_slice(&self.version.to_le_bytes());
            p
        };

        let hw_signature = if let Some(sk_bytes) = &self.hw_secret_key {
            if sk_bytes.len() == 32 {
                if let Ok(sk_bytes_arr) = <[u8; 32]>::try_from(sk_bytes.as_slice()) {
                    let signing_key = SigningKey::from_bytes(&sk_bytes_arr);
                    let sig = signing_key.sign(&payload);
                    sig.to_bytes().to_vec()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        PunctureProof {
            tag,
            punctured: self.is_punctured(tag),
            version: self.version,
            hw_signature,
            hw_type: self.hw_type,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    fn secure_erase_key(&mut self, key_id: &str) {
        info!("Hardware-secure erase requested for key: {}", key_id);
    }
}

impl HardwarePunctureState {
    pub fn new_with_keypair(hw_type: HardwareType, signing_key: &SigningKey) -> Self {
        let mut state = Self {
            hw_type,
            punctured_tags: HashSet::new(),
            hw_signature: Vec::new(),
            version: 0,
            hw_pubkey: signing_key.verifying_key().to_bytes().to_vec(),
            hw_secret_key: Some(signing_key.to_bytes().to_vec()),
        };
        state.sign_state();
        state
    }

    pub fn new(hw_type: HardwareType) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::new_with_keypair(hw_type, &signing_key)
    }

    pub fn puncture_count(&self) -> usize {
        self.punctured_tags.len()
    }

    pub fn get_punctured_tags(&self) -> &HashSet<u64> {
        &self.punctured_tags
    }

    fn compute_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        let mut tags: Vec<&u64> = self.punctured_tags.iter().collect();
        tags.sort();
        for tag in tags {
            payload.extend_from_slice(&tag.to_le_bytes());
        }
        payload.extend_from_slice(&self.version.to_le_bytes());
        payload
    }

    fn sign_state(&mut self) {
        if let Some(sk_bytes) = &self.hw_secret_key {
            if sk_bytes.len() == 32 {
                if let Ok(sk_bytes_arr) = <[u8; 32]>::try_from(sk_bytes.as_slice()) {
                    let signing_key = SigningKey::from_bytes(&sk_bytes_arr);
                    let payload = self.compute_payload();
                    let sig = signing_key.sign(&payload);
                    self.hw_signature = sig.to_bytes().to_vec();
                    return;
                }
            }
        }
    }

    pub fn puncture_with_keypair(&mut self, tag: u64, signing_key: &SigningKey) {
        if self.punctured_tags.insert(tag) {
            self.version += 1;
            let payload = self.compute_payload();
            let sig = signing_key.sign(&payload);
            self.hw_signature = sig.to_bytes().to_vec();
        }
    }

    pub fn verify(&self) -> bool {
        if self.hw_signature.len() != 64 || self.hw_pubkey.len() != 32 {
            return false;
        }
        let pubkey_bytes: [u8; 32] = match self.hw_pubkey.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig_bytes: [u8; 64] = match self.hw_signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let verifying_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&sig_bytes);
        let payload = self.compute_payload();
        verifying_key.verify(&payload, &sig).is_ok()
    }

    pub fn verify_integrity(&self) -> bool {
        self.verify()
    }

    pub fn get_pubkey(&self) -> Option<VerifyingKey> {
        if self.hw_pubkey.len() != 32 {
            return None;
        }
        let pubkey_bytes: [u8; 32] = match self.hw_pubkey.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return None,
        };
        VerifyingKey::from_bytes(&pubkey_bytes).ok()
    }
}

/// Hardware-attested puncture proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PunctureProof {
    /// The punctured tag
    pub tag: u64,
    /// Whether the tag is punctured
    pub punctured: bool,
    /// Version number of puncture state
    pub version: u64,
    /// ed25519 hardware signature (64 bytes)
    pub hw_signature: Vec<u8>,
    /// Hardware type
    pub hw_type: HardwareType,
    /// Timestamp of proof generation
    pub timestamp: u64,
}

impl PunctureProof {
    pub fn verify_with_pubkey(&self, verifying_key: &VerifyingKey) -> bool {
        let payload = {
            let mut p = Vec::new();
            p.extend_from_slice(&self.tag.to_le_bytes());
            p.extend_from_slice(&self.version.to_le_bytes());
            p
        };
        if self.hw_signature.len() != 64 {
            return false;
        }
        let sig_bytes: [u8; 64] = match self.hw_signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&sig_bytes);
        verifying_key.verify(&payload, &sig).is_ok()
    }

    #[deprecated(note = "use verify_with_pubkey instead; this method always returns false")]
    pub fn verify(&self) -> bool {
        false
    }
}

pub struct FullChainProtection {
    hw_state: HardwarePunctureState,
    hw_signing_key: SigningKey,
    crf_count: u64,
}

impl FullChainProtection {
    pub fn new(hw_type: HardwareType, _attr_count: usize) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let hw_state = HardwarePunctureState::new_with_keypair(hw_type, &signing_key);
        Self {
            hw_state,
            hw_signing_key: signing_key,
            crf_count: 0,
        }
    }

    pub fn puncture_with_protection(&mut self, tag: u64) {
        self.hw_state
            .puncture_with_keypair(tag, &self.hw_signing_key);
        info!(
            "Full-chain puncture executed: tag={}, punctured_total={}",
            tag,
            self.hw_state.puncture_count()
        );
    }

    pub fn verify_puncture(&self, tag: u64) -> bool {
        let is_punctured = self.hw_state.is_punctured(tag);
        debug!(
            "Full-chain puncture check: tag={}, is_punctured={}",
            tag, is_punctured
        );
        is_punctured
    }

    pub fn record_crf_operation(&mut self) {
        self.crf_count += 1;
    }

    pub fn cumulative_statistical_distance(&self) -> f64 {
        let q = self.crf_count as f64;
        let term1 = q * 2f64.powi(-128);
        let term2 = (q * q / 2.0) * 2f64.powi(-256);
        term1 + term2
    }

    pub fn security_status(&self) -> SecurityStatus {
        let hw_integrity = self.hw_state.verify_integrity();
        let crf_distance = self.cumulative_statistical_distance();

        SecurityStatus {
            hw_integrity,
            crf_count: self.crf_count,
            crf_statistical_distance: crf_distance,
            puncture_count: self.hw_state.puncture_count(),
        }
    }

    pub fn generate_report(&self) -> String {
        let status = self.security_status();
        format!(
            "Full-Chain Security Report:\n\
             ┌─────────────────────────────────────────┐\n\
             │ Hardware Integrity: {:?}\n\
             │ CRF Operations: {}\n\
             │ CRF Statistical Distance: {:.2e}\n\
             │ Punctured Tags: {}\n\
             └─────────────────────────────────────────┘",
            status.hw_integrity,
            status.crf_count,
            status.crf_statistical_distance,
            status.puncture_count,
        )
    }

    pub fn get_hw_pubkey(&self) -> VerifyingKey {
        self.hw_signing_key.verifying_key()
    }

    pub fn generate_puncture_proof(&self, tag: u64) -> PunctureProof {
        self.hw_state.generate_puncture_proof(tag)
    }
}

/// Security status report
#[derive(Debug, Clone)]
pub struct SecurityStatus {
    pub hw_integrity: bool,
    pub crf_count: u64,
    pub crf_statistical_distance: f64,
    pub puncture_count: usize,
}

impl SecurityStatus {
    pub fn is_secure(&self) -> bool {
        self.hw_integrity && self.crf_statistical_distance < 1e-12
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_puncture_state() {
        let mut state = HardwarePunctureState::new(HardwareType::SoftwareSimulated);
        assert!(!state.is_punctured(42));
        state.puncture(42);
        assert!(state.is_punctured(42));
        assert!(!state.is_punctured(43));
        assert_eq!(state.puncture_count(), 1);
    }

    #[test]
    fn test_puncture_proof() {
        let mut state = HardwarePunctureState::new(HardwareType::SoftwareSimulated);
        state.puncture(100);
        let pubkey = state.get_pubkey().expect("should have pubkey");
        let proof = state.generate_puncture_proof(100);
        assert!(proof.punctured);
        assert!(proof.verify_with_pubkey(&pubkey));
        assert_eq!(proof.version, 1);
    }

    #[test]
    fn test_full_chain_protection() {
        let mut fc = FullChainProtection::new(HardwareType::SoftwareSimulated, 10);
        fc.puncture_with_protection(1);
        fc.puncture_with_protection(2);
        assert!(fc.verify_puncture(1));
        assert!(fc.verify_puncture(2));
        assert!(!fc.verify_puncture(3));

        for _ in 0..1000 {
            fc.record_crf_operation();
        }

        let status = fc.security_status();
        assert!(status.hw_integrity);
        assert_eq!(status.puncture_count, 2);
        assert_eq!(status.crf_count, 1000);
    }

    #[test]
    fn test_hw_integrity_verification() {
        let mut state = HardwarePunctureState::new(HardwareType::SoftwareSimulated);
        state.puncture(1);
        state.puncture(2);
        assert!(state.verify_integrity());

        let mut tampered = state.clone();
        tampered.punctured_tags.insert(3);
        assert!(!tampered.verify_integrity());
    }

    #[test]
    fn test_security_report() {
        let mut fc = FullChainProtection::new(HardwareType::SoftwareSimulated, 5);
        fc.puncture_with_protection(1);
        fc.record_crf_operation();
        let report = fc.generate_report();
        assert!(report.contains("Hardware Integrity"));
        assert!(report.contains("CRF Operations"));
    }

    #[test]
    fn test_ed25519_signature_verification() {
        let mut state = HardwarePunctureState::new(HardwareType::SoftwareSimulated);
        state.puncture(42);
        state.puncture(99);

        assert!(
            state.verify(),
            "ed25519 signature over puncture state must verify"
        );

        let pubkey = state.get_pubkey().unwrap();
        let proof = state.generate_puncture_proof(42);
        assert!(
            proof.verify_with_pubkey(&pubkey),
            "puncture proof must verify with correct pubkey"
        );

        let mut csprng = OsRng;
        let wrong_signing_key = SigningKey::generate(&mut csprng);
        assert!(
            !proof.verify_with_pubkey(&wrong_signing_key.verifying_key()),
            "puncture proof must NOT verify with wrong pubkey"
        );
    }

    #[test]
    fn test_tampered_signature_fails() {
        let mut state = HardwarePunctureState::new(HardwareType::SoftwareSimulated);
        state.puncture(1);
        assert!(state.verify());

        let mut tampered = state.clone();
        if !tampered.hw_signature.is_empty() {
            tampered.hw_signature[0] ^= 0xff;
        }
        assert!(
            !tampered.verify(),
            "tampered signature must fail ed25519 verification"
        );
    }

    #[test]
    fn test_puncture_proof_no_key_fails() {
        let proof = PunctureProof {
            tag: 1,
            punctured: true,
            version: 1,
            hw_signature: Vec::new(),
            hw_type: HardwareType::SoftwareSimulated,
            timestamp: 0,
        };
        assert!(
            !proof.verify(),
            "legacy verify() must return false without pubkey context"
        );
    }
}
