use ed25519_dalek::SigningKey;
use pabs_crf::hardware_root::{
    HardwarePunctureState, HardwareRootOfTrust, HardwareType, PunctureProof,
};
use rand::rngs::OsRng;

#[test]
fn test_verify_with_pubkey_correct_key_succeeds() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let state =
        HardwarePunctureState::new_with_keypair(HardwareType::SoftwareSimulated, &signing_key);

    let mut mutated = state.clone();
    mutated.puncture(42);

    let proof = mutated.generate_puncture_proof(42);
    let pubkey = signing_key.verifying_key();

    assert!(proof.punctured);
    assert_eq!(proof.tag, 42);
    assert_eq!(proof.version, 1);
    assert!(
        proof.verify_with_pubkey(&pubkey),
        "verify_with_pubkey with correct key must succeed"
    );
}

#[test]
fn test_verify_with_pubkey_wrong_key_fails() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let state =
        HardwarePunctureState::new_with_keypair(HardwareType::SoftwareSimulated, &signing_key);

    let mut mutated = state.clone();
    mutated.puncture(100);

    let proof = mutated.generate_puncture_proof(100);
    let wrong_key = SigningKey::generate(&mut OsRng);
    let wrong_pubkey = wrong_key.verifying_key();

    assert!(
        !proof.verify_with_pubkey(&wrong_pubkey),
        "verify_with_pubkey with wrong key must fail"
    );
}

#[test]
fn test_verify_with_pubkey_empty_signature_fails() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let proof = PunctureProof {
        tag: 1,
        punctured: true,
        version: 1,
        hw_signature: Vec::new(),
        hw_type: HardwareType::SoftwareSimulated,
        timestamp: 0,
    };

    let pubkey = signing_key.verifying_key();
    assert!(
        !proof.verify_with_pubkey(&pubkey),
        "verify_with_pubkey with empty signature must fail"
    );
}

#[test]
fn test_deprecated_verify_always_returns_false() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let state =
        HardwarePunctureState::new_with_keypair(HardwareType::SoftwareSimulated, &signing_key);

    let mut mutated = state.clone();
    mutated.puncture(99);

    let proof = mutated.generate_puncture_proof(99);

    #[allow(deprecated)]
    let result = proof.verify();
    assert!(!result, "deprecated verify() must always return false");
}

#[test]
fn test_verify_with_pubkey_unpunctured_tag() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let state =
        HardwarePunctureState::new_with_keypair(HardwareType::SoftwareSimulated, &signing_key);

    let mut mutated = state.clone();
    mutated.puncture(1);
    mutated.puncture(2);

    let proof = mutated.generate_puncture_proof(999);
    let pubkey = signing_key.verifying_key();

    assert!(!proof.punctured, "tag 999 was not punctured");
    assert_eq!(proof.tag, 999);
    assert!(
        proof.verify_with_pubkey(&pubkey),
        "proof for unpunctured tag must still verify against correct key"
    );
}

#[test]
fn test_verify_with_pubkey_multiple_proofs() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let state =
        HardwarePunctureState::new_with_keypair(HardwareType::SoftwareSimulated, &signing_key);

    let mut mutated = state.clone();
    mutated.puncture(10);
    mutated.puncture(20);
    mutated.puncture(30);

    let pubkey = signing_key.verifying_key();

    for tag in [10, 20, 30] {
        let proof = mutated.generate_puncture_proof(tag);
        assert!(proof.punctured);
        assert_eq!(proof.version, 3);
        assert!(
            proof.verify_with_pubkey(&pubkey),
            "proof for tag {} must verify",
            tag
        );
    }
}

#[test]
fn test_verify_with_pubkey_tampered_signature_fails() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let state =
        HardwarePunctureState::new_with_keypair(HardwareType::SoftwareSimulated, &signing_key);

    let mut mutated = state.clone();
    mutated.puncture(50);

    let mut proof = mutated.generate_puncture_proof(50);
    if !proof.hw_signature.is_empty() {
        proof.hw_signature[0] ^= 0xFF;
    }

    let pubkey = signing_key.verifying_key();
    assert!(
        !proof.verify_with_pubkey(&pubkey),
        "tampered proof must fail verification"
    );
}
