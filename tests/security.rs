//! Security tests for the PABS-CRF scheme

use pabs_crf::*;

#[test]
fn test_crf_undetectability() {
    // Test CRF undetectability
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);

    let policy = Policy::parse("admin AND finance").expect("Valid policy");
    let message = b"Hello, World!";

    // Generate multiple signatures for the same message
    let mut signatures = Vec::new();
    for _ in 0..10 {
        signatures.push(sign(&sk, message, &policy, 0).expect("Signing should succeed"));
    }

    // All signatures should be different due to CRF re-randomization
    let mut unique_signatures = std::collections::HashSet::new();
    for sig in &signatures {
        let sig_str = serde_json::to_string(sig).unwrap();
        unique_signatures.insert(sig_str);
    }

    // All signatures should be unique
    assert_eq!(unique_signatures.len(), signatures.len());

    // Tampering with any core component should fail verification
    // Tamper with message_hash (cryptographically verified)
    let mut tampered_hash = signatures[0].clone();
    tampered_hash.insert("message_hash".to_string(), vec![0u8; 32]);
    assert!(!verify(&pp, message, &policy, &tampered_hash).expect("Tampered hash should not error"));

    // Tamper with sigma2 (length and content verified)
    let mut tampered_sigma2 = signatures[1].clone();
    if let Some(c) = tampered_sigma2.get_mut("challenge") {
        for byte in c.iter_mut().take(4) {
            *byte ^= 0xFF;
        }
    }
    assert!(!verify(&pp, message, &policy, &tampered_sigma2)
        .expect("Tampered challenge should not error"));

    // All signatures should verify correctly
    for sig in &signatures {
        assert!(verify(&pp, message, &policy, sig).expect("Verification should succeed"));
    }
}

#[test]
fn test_puncture_security() {
    // Test puncture security
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);

    let policy = Policy::parse("admin AND finance").expect("Valid policy");
    let message = b"Hello, World!";
    let tau = 12345;

    // Puncture the key
    let punctured_sk = puncture(&sk, tau).expect("puncture should succeed");

    // Create a verifier
    let verifier = Verify::new();

    // Generate signature with original key
    let signature = sign(&sk, message, &policy, 0).expect("Signing should succeed");

    // Verify should fail for punctured key
    let result = verifier.verify_with_local_puncture_state(
        &punctured_sk,
        &pp,
        message,
        &policy,
        &signature,
        tau,
    );
    assert!(result.is_err(), "Punctured verification should fail");

    // Verify should succeed for non-punctured tag
    let other_tau = 67890;
    let result = verifier.verify_with_local_puncture_state(
        &punctured_sk,
        &pp,
        message,
        &policy,
        &signature,
        other_tau,
    );
    assert!(result.expect("Verification should succeed"));

    // Negative: corrupted puncture tree must fail
    let mut corrupted_sk = punctured_sk.clone();
    corrupted_sk.insert("puncture_tree".to_string(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(verifier
        .verify_with_local_puncture_state(
            &corrupted_sk,
            &pp,
            message,
            &policy,
            &signature,
            other_tau
        )
        .is_err());
}

#[test]
fn test_constant_time_eq_basic_distinct_inputs() {
    // Test side channel protection
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);

    let policy = Policy::parse("admin AND finance").expect("Valid policy");
    let message = b"Hello, World!";

    // Test constant time comparison
    let signature1 = sign(&sk, message, &policy, 0).expect("Signing should succeed");
    let signature2 = sign(&sk, message, &policy, 0).expect("Signing should succeed");

    // Compare signatures using constant time comparison
    let sig1_str = serde_json::to_string(&signature1).unwrap();
    let sig2_str = serde_json::to_string(&signature2).unwrap();

    let result =
        SideChannelProtection::constant_time_compare(sig1_str.as_bytes(), sig2_str.as_bytes());

    // Signatures should be different due to CRF
    assert!(!result);
}

#[test]
fn test_params_match_documentation() {
    // Test quantum resistance (parameter validation)
    // This test verifies that MLWE parameters are set correctly for post-quantum security
    let params = pabs_crf::MLWEParameters::new_128();

    // Verify parameters meet minimum requirements for 128-bit security
    // Dilithium-style parameters: k=4, n=256, q=8380417
    assert!(params.n == 256);
    assert!(params.q == 8380417);
    assert!(params.k == 4);
    assert!(params.eta1 == 2);
    assert!(params.eta2 == 2);
    assert!(params.gamma1 == 4190207);
    assert!(params.gamma2 == 95232);
}

#[test]
fn test_malformed_signature_rejected() {
    // Test signature unforgeability
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);

    let policy = Policy::parse("admin AND finance").expect("Valid policy");
    let message = b"Hello, World!";

    // Generate valid signature
    let valid_signature = sign(&sk, message, &policy, 0).expect("Signing should succeed");
    assert!(verify(&pp, message, &policy, &valid_signature).expect("Verification should succeed"));

    // Create a forged signature with missing components
    let mut forged_signature = std::collections::HashMap::new();
    forged_signature.insert("sigma1".to_string(), vec![0u8; 256]);
    // Missing sigma2 - should fail verification

    // Forged signature should not verify
    let result = verify(&pp, message, &policy, &forged_signature);
    assert!(result.is_ok(), "Verification should return Ok");
    assert!(
        !result.unwrap(),
        "Forged signature should fail verification"
    );

    // Negative: corrupted policy field should fail verification
    let mut corrupted_policy_sig = valid_signature.clone();
    corrupted_policy_sig.insert("policy".to_string(), vec![0xAA, 0xBB, 0xCC]);
    assert!(!verify(&pp, message, &policy, &corrupted_policy_sig)
        .expect("Corrupted policy should not error"));

    // Negative: missing message_hash should fail verification
    let mut missing_hash_sig = valid_signature.clone();
    missing_hash_sig.remove("message_hash");
    assert!(
        !verify(&pp, message, &policy, &missing_hash_sig).expect("Missing hash should not error")
    );
}
