//! Regression tests for the PABS-CRF scheme

use pabs_crf::*;

#[test]
fn test_module_import_fix() {
    // Test that module imports work correctly
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attributes);

    let policy = Policy::parse("admin").expect("Valid policy");
    let message = b"Hello, World!";
    let signature = sign(&sk, message, &policy, 0).expect("Signing should succeed");

    assert!(verify(&pp, message, &policy, &signature).expect("Verification should succeed"));
}

#[test]
fn test_binary_tree_puncture_fix() {
    // Test that binary tree puncture works correctly
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attributes);

    let tau = 12345;
    let punctured_sk = puncture(&sk, tau).expect("Puncture should succeed");

    // Verify that the key was punctured
    let puncture = Puncture::new();
    assert!(puncture
        .is_punctured(&punctured_sk, tau)
        .expect("is_punctured should succeed"));
    assert!(!puncture
        .is_punctured(&sk, tau)
        .expect("is_punctured should succeed"));

    // Verify that signing still works with non-punctured tags
    let policy = Policy::parse("admin").expect("Valid policy");
    let message = b"Hello, World!";
    let signature = sign(&punctured_sk, message, &policy, 0).expect("Signing should succeed");
    assert!(verify(&pp, message, &policy, &signature).expect("Verification should succeed"));

    // Regression: the punctured tag itself must be rejected by punctured verification
    let verifier = Verify::new();
    assert!(verifier
        .verify_with_local_puncture_state(&punctured_sk, &pp, message, &policy, &signature, tau)
        .is_err());
}

#[test]
fn test_version_compatibility() {
    // Test version compatibility
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attributes);

    // Test that all core functions work as expected
    let policy = Policy::parse("admin").expect("Valid policy");
    let message = b"Hello, World!";

    // Sign and verify
    let signature = sign(&sk, message, &policy, 0).expect("Signing should succeed");
    assert!(verify(&pp, message, &policy, &signature).expect("Verification should succeed"));

    // Puncture and verify punctured
    let tau = 12345;
    let punctured_sk = puncture(&sk, tau).expect("puncture should succeed");
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

    // Regression: malformed batch inputs should be rejected, not truncated
    let signer = Sign::new();
    let messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2"];
    let policies = vec![policy.clone()];
    let batch_results = signer.batch_sign(&sk, &messages, &policies, &[0, 0]);
    assert_eq!(batch_results.len(), 1);
    assert!(batch_results[0].is_err());

    // Batch operations
    let policies = vec![policy.clone(), policy.clone()];
    let signatures = signer.batch_sign(&sk, &messages, &policies, &[0, 0]);
    assert_eq!(signatures.len(), messages.len());
}

#[test]
fn test_performance_regression() {
    // Test performance regression
    use std::time::Instant;

    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);

    let policy = Policy::parse("admin AND finance").expect("Valid policy");
    let message = b"Hello, World!";

    // Measure signing time
    let start = Instant::now();
    let signature = sign(&sk, message, &policy, 0).expect("Signing should succeed");
    let sign_time = start.elapsed();

    // Measure verification time
    let start = Instant::now();
    let result = verify(&pp, message, &policy, &signature).expect("Verification should succeed");
    let verify_time = start.elapsed();

    // Ensure operations complete within reasonable time
    assert!(sign_time.as_millis() < 1000); // Under 1 second
    assert!(verify_time.as_millis() < 100); // Under 100ms
    assert!(result);
}

#[test]
fn test_serialization_compatibility() {
    // Test serialization compatibility
    let (_pp, msk) = setup(128);
    let attributes = vec!["user", "admin"];
    let sk = keygen(&_pp, &msk, &attributes);

    // Serialize and deserialize the key
    let sk_bytes = bincode::serialize(&sk).unwrap();
    let deserialized_sk: std::collections::HashMap<String, Vec<u8>> =
        bincode::deserialize(&sk_bytes).unwrap();

    // Verify that the deserialized key works
    let policy = Policy::parse("admin").expect("Valid policy");
    let message = b"Hello, World!";
    let signature = sign(&deserialized_sk, message, &policy, 0).expect("Signing should succeed");
    assert!(!signature.is_empty());

    // Test signature serialization
    let sig_bytes = bincode::serialize(&signature).unwrap();
    let deserialized_sig: std::collections::HashMap<String, Vec<u8>> =
        bincode::deserialize(&sig_bytes).unwrap();
    assert!(!deserialized_sig.is_empty());

    // Regression: corrupted serialized data should fail to deserialize
    let corrupted = vec![0xFF, 0x00, 0x01];
    assert!(
        bincode::deserialize::<std::collections::HashMap<String, Vec<u8>>>(&corrupted).is_err()
    );
}

#[test]
fn test_error_handling() {
    // Test error handling
    let (pp, msk) = setup(128);
    let attributes = vec!["user"];
    let sk = keygen(&pp, &msk, &attributes);

    // Test policy not satisfied now returns an error
    let policy = Policy::parse("admin").expect("Valid policy");
    let message = b"Hello, World!";
    let signature = sign(&sk, message, &policy, 0);
    assert!(
        signature.is_err(),
        "Signing should fail when policy not satisfied"
    );

    // Test invalid security level falls back to safe defaults
    let fallback = setup(100);
    assert!(!fallback.0.is_empty());
    assert!(!fallback.1.is_empty());

    // Regression: batch verify should reject mismatched lengths
    let verifier = Verify::new();
    let sig = sign(
        &keygen(&pp, &msk, &vec!["admin"]),
        message,
        &Policy::parse("admin").unwrap(),
        0,
    )
    .unwrap();
    let batch = verifier.batch_verify(&pp, &[message], &[], &[sig]);
    assert_eq!(batch.len(), 1);
    assert!(batch[0].is_err());
}
