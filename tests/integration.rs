//! Integration tests for the PABS-CRF scheme

use pabs_crf::*;
use std::sync::Arc;
use std::thread;

#[test]
fn test_full_workflow() {
    // Test full workflow from setup to verification
    // 1. System setup
    let (pp, msk) = setup(128);

    // 2. Key generation
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);

    // 3. Policy creation
    let policy = Policy::parse("admin AND finance").expect("Valid policy");

    // 4. Signature generation
    let message = b"Hello, World!";
    let signature = sign(&sk, message, &policy, 0).expect("Signing should succeed");

    // 5. Signature verification
    assert!(verify(&pp, message, &policy, &signature).expect("Verification should succeed"));

    // Negative: wrong message must fail verification
    assert!(!verify(&pp, b"Hello, world!", &policy, &signature)
        .expect("Wrong message should not error"));

    // Negative: unrelated policy must fail verification
    let wrong_policy = Policy::parse("user AND hr").expect("Valid policy");
    assert!(
        !verify(&pp, message, &wrong_policy, &signature).expect("Wrong policy should not error")
    );

    // Negative: tampered signature must fail verification
    let mut tampered_signature = signature.clone();
    // Tamper with message_hash which is verified by recomputing the hash
    if let Some(hash_bytes) = tampered_signature.get_mut("message_hash") {
        if hash_bytes.len() > 0 {
            hash_bytes[0] ^= 0x01;
        }
    }
    assert!(!verify(&pp, message, &policy, &tampered_signature)
        .expect("Tampered signature should not error"));

    // 6. Key puncturing
    let tau = 12345;
    let punctured_sk = puncture(&sk, tau).expect("puncture should succeed");

    // 7. Punctured verification should fail
    let verifier = Verify::new();
    let result = verifier.verify_with_local_puncture_state(
        &punctured_sk,
        &pp,
        message,
        &policy,
        &signature,
        tau,
    );
    assert!(result.is_err(), "Punctured verification should fail");
}

#[test]
fn test_multi_user_scenario() {
    // Test multi-user scenario
    let (pp, msk) = setup(128);

    // Create multiple users with different attributes
    let users = vec![
        ("user1", vec!["admin", "finance"]),
        ("user2", vec!["user", "finance"]),
        ("user3", vec!["user", "admin"]),
    ];

    let mut keys = Vec::new();
    for (_, attrs) in &users {
        let sk = keygen(&pp, &msk, attrs);
        keys.push(sk);
    }

    // Test different policies
    let policies = vec![
        Policy::parse("admin AND finance").expect("Valid policy"), // Should be satisfied by user1
        Policy::parse("user AND finance").expect("Valid policy"),  // Should be satisfied by user2
        Policy::parse("user AND admin").expect("Valid policy"),    // Should be satisfied by user3
    ];

    let message = b"Test message";

    // Test each user with their respective policy
    for (i, (_user, _attrs)) in users.iter().enumerate() {
        let policy = &policies[i];
        let sk = &keys[i];

        // User should be able to sign their policy
        let signature = sign(sk, message, policy, 0).expect("Signing should succeed");
        assert!(verify(&pp, message, policy, &signature).expect("Verification should succeed"));
    }

    // Negative: user1 should not satisfy user3's policy
    assert!(sign(&keys[0], message, &policies[2], 0).is_err());
    // Negative: user2 should not satisfy user1's policy
    assert!(sign(&keys[1], message, &policies[0], 0).is_err());
    // Negative: user3 should not satisfy user2's policy
    assert!(sign(&keys[2], message, &policies[1], 0).is_err());
}

#[test]
fn test_concurrent_signing() {
    // Test concurrent signing
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attributes);

    let policy = Policy::parse("admin").expect("Valid policy");
    let message = b"Hello, World!";

    // Create an arc to share the key across threads
    let sk_arc = Arc::new(sk);
    let policy_arc = Arc::new(policy.clone());
    let message_vec = message.to_vec();

    // Run multiple signing operations concurrently
    let mut handles = Vec::new();
    for i in 0..10 {
        let sk = Arc::clone(&sk_arc);
        let policy = Arc::clone(&policy_arc);
        let message = message_vec.clone();

        let handle = thread::spawn(move || {
            let sig = sign(&sk, &message, &policy, 0);
            (i, sig)
        });

        handles.push(handle);
    }

    // Collect results
    let mut signatures = Vec::new();
    for handle in handles {
        let (_, sig) = handle.join().unwrap();
        signatures.push(sig.expect("Concurrent signing should succeed"));
    }

    // All signatures should verify
    for sig in &signatures {
        assert!(verify(&pp, message, &policy, sig).expect("Verification should succeed"));
    }
}

#[test]
fn test_batch_operations() {
    // Test batch operations
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attributes);

    let policy = Policy::parse("admin").expect("Valid policy");

    // Create multiple messages with correct type
    let msg1: &[u8] = b"Message 1";
    let msg2: &[u8] = b"Message 2";
    let msg3: &[u8] = b"Message 3";
    let msg4: &[u8] = b"Message 4";
    let msg5: &[u8] = b"Message 5";
    let messages: &[&[u8]] = &[msg1, msg2, msg3, msg4, msg5];

    // Create signer and verifier
    let signer = Sign::new();
    let verifier = Verify::new();

    // Create policies for each message
    let policies = vec![policy.clone(); 5];

    // Batch sign
    let signatures = signer.batch_sign(&sk, messages, &policies, &[0; 5]);
    assert_eq!(signatures.len(), messages.len());

    // All signatures should succeed
    for sig_result in &signatures {
        assert!(sig_result.is_ok(), "Batch signing should succeed");
    }

    // Extract valid signatures for verification
    let valid_sigs: Vec<_> = signatures.iter().filter_map(|r| r.clone().ok()).collect();

    // Batch verify
    let results = verifier.batch_verify(&pp, messages, &policies[..valid_sigs.len()], &valid_sigs);
    assert_eq!(results.len(), valid_sigs.len());

    // All verifications should succeed
    for result in results {
        assert!(result.expect("Verification should succeed"));
    }

    // Negative: mismatched batch lengths should return an error result
    let bad_results = signer.batch_sign(&sk, messages, &policies[..4], &[0; 5]);
    assert_eq!(bad_results.len(), 1);
    assert!(bad_results[0].is_err());

    let bad_verify = verifier.batch_verify(&pp, messages, &policies[..4], &valid_sigs);
    assert_eq!(bad_verify.len(), 1);
    assert!(bad_verify[0].is_err());
}

#[test]
fn test_policy_evaluation() {
    // Test policy evaluation with different attribute sets
    let policies = vec![
        Policy::parse("admin").expect("Valid policy"),
        Policy::parse("admin AND finance").expect("Valid policy"),
        Policy::parse("admin OR user").expect("Valid policy"),
        Policy::parse("(admin AND finance) OR user").expect("Valid policy"),
    ];

    assert!(
        Policy::parse("NOT admin").is_err(),
        "v4 formal path must reject NOT"
    );

    let attribute_sets = vec![
        vec!["admin"],
        vec!["admin", "finance"],
        vec!["user"],
        vec!["user", "finance"],
        vec!["guest"],
    ];

    // Expected results: (policy_index, attribute_set_index) -> should_satisfy
    let expected = vec![
        (0, 0, true),
        (0, 1, true),
        (0, 2, false),
        (0, 3, false),
        (0, 4, false),
        (1, 0, false),
        (1, 1, true),
        (1, 2, false),
        (1, 3, false),
        (1, 4, false),
        (2, 0, true),
        (2, 1, true),
        (2, 2, true),
        (2, 3, true),
        (2, 4, false),
        (3, 0, false),
        (3, 1, true),
        (3, 2, true),
        (3, 3, true),
        (3, 4, false),
    ];

    for (policy_idx, attr_idx, should_satisfy) in expected {
        let policy = &policies[policy_idx];
        let attrs = &attribute_sets[attr_idx];
        assert_eq!(policy.satisfies(attrs), should_satisfy);
    }
}
