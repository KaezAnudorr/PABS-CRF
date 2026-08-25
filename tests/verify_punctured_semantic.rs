use ed25519_dalek::SigningKey;
use pabs_crf::hardware_root::{
    FullChainProtection, HardwarePunctureState, HardwareRootOfTrust, HardwareType, PunctureProof,
};
use rand::rngs::OsRng;

#[test]
fn test_deprecated_verify_always_returns_false() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let state =
        HardwarePunctureState::new_with_keypair(HardwareType::SoftwareSimulated, &signing_key);
    let mut mutated = state.clone();
    mutated.puncture(7);
    let proof = mutated.generate_puncture_proof(7);

    #[allow(deprecated)]
    let result = proof.verify();
    assert!(
        !result,
        "deprecated PunctureProof::verify() must always return false"
    );
}

#[test]
fn test_deprecated_verify_false_even_for_valid_proof() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let mut state =
        HardwarePunctureState::new_with_keypair(HardwareType::SoftwareSimulated, &signing_key);
    state.puncture(1);
    state.puncture(2);
    state.puncture(3);

    let proof = state.generate_puncture_proof(1);
    assert!(proof.punctured, "tag 1 should be punctured");
    assert_eq!(proof.version, 3);

    #[allow(deprecated)]
    let result = proof.verify();
    assert!(
        !result,
        "deprecated verify() must return false regardless of proof validity"
    );
}

#[test]
fn test_deprecated_verify_false_for_unpunctured_tag() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let state =
        HardwarePunctureState::new_with_keypair(HardwareType::SoftwareSimulated, &signing_key);

    let proof = state.generate_puncture_proof(999);
    assert!(!proof.punctured, "tag 999 was not punctured");

    #[allow(deprecated)]
    let result = proof.verify();
    assert!(
        !result,
        "deprecated verify() must return false even for valid unpunctured proof"
    );
}

#[test]
fn test_verify_with_pubkey_correct_key_succeeds() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let mut state =
        HardwarePunctureState::new_with_keypair(HardwareType::SoftwareSimulated, &signing_key);
    state.puncture(42);

    let proof = state.generate_puncture_proof(42);
    let pubkey = signing_key.verifying_key();

    assert!(proof.punctured);
    assert!(
        proof.verify_with_pubkey(&pubkey),
        "verify_with_pubkey with correct ed25519 key must succeed"
    );
}

#[test]
fn test_verify_with_pubkey_wrong_key_fails() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let mut state =
        HardwarePunctureState::new_with_keypair(HardwareType::SoftwareSimulated, &signing_key);
    state.puncture(100);

    let proof = state.generate_puncture_proof(100);
    let wrong_key = SigningKey::generate(&mut OsRng);
    let wrong_pubkey = wrong_key.verifying_key();

    assert!(
        !proof.verify_with_pubkey(&wrong_pubkey),
        "verify_with_pubkey with wrong ed25519 key must fail"
    );
}

#[test]
fn test_verify_with_pubkey_generated_proof_passes() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let mut state =
        HardwarePunctureState::new_with_keypair(HardwareType::SoftwareSimulated, &signing_key);

    state.puncture(10);
    state.puncture(20);
    state.puncture(30);

    let pubkey = signing_key.verifying_key();

    for tag in [10, 20, 30] {
        let proof = state.generate_puncture_proof(tag);
        assert!(proof.punctured, "tag {} should be punctured", tag);
        assert_eq!(proof.version, 3);
        assert!(
            proof.verify_with_pubkey(&pubkey),
            "proof for tag {} must pass verify_with_pubkey",
            tag
        );
    }
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
fn test_verify_with_pubkey_tampered_signature_fails() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let mut state =
        HardwarePunctureState::new_with_keypair(HardwareType::SoftwareSimulated, &signing_key);
    state.puncture(50);

    let mut proof = state.generate_puncture_proof(50);
    if !proof.hw_signature.is_empty() {
        proof.hw_signature[0] ^= 0xFF;
    }

    let pubkey = signing_key.verifying_key();
    assert!(
        !proof.verify_with_pubkey(&pubkey),
        "tampered proof must fail ed25519 verification"
    );
}

#[test]
fn test_full_chain_protection_generate_and_verify_proof() {
    let mut fc = FullChainProtection::new(HardwareType::SoftwareSimulated, 5);
    fc.puncture_with_protection(100);
    fc.puncture_with_protection(200);

    let proof_100 = fc.generate_puncture_proof(100);
    let proof_200 = fc.generate_puncture_proof(200);
    let pubkey = fc.get_hw_pubkey();

    assert!(proof_100.punctured);
    assert!(proof_200.punctured);
    assert!(
        proof_100.verify_with_pubkey(&pubkey),
        "full-chain proof for tag 100 must verify"
    );
    assert!(
        proof_200.verify_with_pubkey(&pubkey),
        "full-chain proof for tag 200 must verify"
    );
}

#[test]
fn test_full_chain_protection_wrong_pubkey_fails() {
    let mut fc = FullChainProtection::new(HardwareType::SoftwareSimulated, 5);
    fc.puncture_with_protection(42);

    let proof = fc.generate_puncture_proof(42);
    let wrong_key = SigningKey::generate(&mut OsRng);

    assert!(
        !proof.verify_with_pubkey(&wrong_key.verifying_key()),
        "full-chain proof must fail with wrong pubkey"
    );
}

#[test]
fn test_hardware_puncture_state_verify_integrity_after_puncture() {
    let mut state = HardwarePunctureState::new(HardwareType::SoftwareSimulated);
    assert!(
        state.verify_integrity(),
        "fresh state should have valid integrity"
    );

    state.puncture(1);
    state.puncture(2);
    state.puncture(3);
    assert!(
        state.verify_integrity(),
        "integrity should hold after punctures"
    );
}

#[test]
fn test_hardware_puncture_state_integrity_preserved_through_serialization() {
    let mut state = HardwarePunctureState::new(HardwareType::SoftwareSimulated);
    assert!(
        state.verify_integrity(),
        "fresh state should have valid integrity"
    );

    state.puncture(1);
    state.puncture(2);
    state.puncture(3);
    assert!(
        state.verify_integrity(),
        "integrity should hold after punctures"
    );

    let bytes = bincode::serialize(&state).expect("serialize");
    let restored: HardwarePunctureState = bincode::deserialize(&bytes).expect("deserialize");
    assert!(
        restored.verify_integrity(),
        "integrity should survive serialize/deserialize roundtrip"
    );
}

#[test]
fn test_hardware_puncture_state_corrupted_bytes_fails_integrity() {
    let mut state = HardwarePunctureState::new(HardwareType::SoftwareSimulated);
    state.puncture(1);
    assert!(state.verify_integrity());

    let mut bytes = bincode::serialize(&state).expect("serialize");
    if !bytes.is_empty() {
        bytes[0] ^= 0xFF;
    }
    if let Ok(tampered) = bincode::deserialize::<HardwarePunctureState>(&bytes) {
        assert!(
            !tampered.verify_integrity(),
            "corrupted bytes must fail integrity check"
        );
    }
}

#[test]
fn test_puncture_proof_version_increments() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let mut state =
        HardwarePunctureState::new_with_keypair(HardwareType::SoftwareSimulated, &signing_key);

    state.puncture(1);
    let proof_v1 = state.generate_puncture_proof(1);
    assert_eq!(proof_v1.version, 1);

    state.puncture(2);
    let proof_v2 = state.generate_puncture_proof(1);
    assert_eq!(proof_v2.version, 2);

    state.puncture(3);
    let proof_v3 = state.generate_puncture_proof(1);
    assert_eq!(proof_v3.version, 3);
}
