//! Basic functionality tests for the PABS-CRF scheme

use pabs_crf::*;

#[test]
fn test_setup() {
    // Test system setup
    let (pp, msk) = setup(128);
    assert!(!pp.is_empty());
    assert!(!msk.is_empty());
}

#[test]
fn test_setup_different_security_levels() {
    // Test setup with different security levels
    let (pp_128, msk_128) = setup(128);
    let (pp_192, msk_192) = setup(192);
    let (pp_256, msk_256) = setup(256);

    assert!(!pp_128.is_empty());
    assert!(!msk_128.is_empty());
    assert!(!pp_192.is_empty());
    assert!(!msk_192.is_empty());
    assert!(!pp_256.is_empty());
    assert!(!msk_256.is_empty());
}

#[test]
fn test_keygen() {
    // Test key generation
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);
    assert!(!sk.is_empty());
    assert!(sk.contains_key("attributes"));
    assert!(sk.contains_key("secret_key"));
    assert!(sk.contains_key("matrix_A"));
    assert!(sk.contains_key("puncture_tree"));
    assert!(sk.contains_key("puncture_count"));
}

#[test]
fn test_sign_verify() {
    // Test signature generation and verification
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);

    let policy = Policy::parse("admin AND finance").expect("Valid policy");
    let message = b"Hello, World!";

    let signature = sign(&sk, message, &policy, 0).expect("Signing should succeed");
    assert!(!signature.is_empty());

    let result = verify(&pp, message, &policy, &signature).expect("Verification should succeed");
    assert!(result);
}

#[test]
fn test_batch_operations() {
    // Test batch operations
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attributes);

    let policy = Policy::parse("admin").expect("Valid policy");
    let messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2", b"Message 3"];

    let signer = Sign::new();
    let verifier = Verify::new();

    // Batch sign with explicit policy vector
    let policies = vec![policy.clone(); messages.len()];
    let signatures = signer.batch_sign(&sk, &messages, &policies, &[0; 3]);
    assert_eq!(signatures.len(), messages.len());

    // All signatures should succeed
    for sig_result in &signatures {
        assert!(sig_result.is_ok(), "Batch signing should succeed");
    }

    // Batch verify
    let valid_signatures: Vec<_> = signatures.iter().filter_map(|r| r.clone().ok()).collect();
    let results = verifier.batch_verify(
        &pp,
        &messages[..valid_signatures.len()],
        &vec![policy.clone(); valid_signatures.len()],
        &valid_signatures,
    );
    assert_eq!(results.len(), valid_signatures.len());

    // All verifications should succeed
    for result in results {
        assert!(result.expect("Verification should succeed"));
    }
}

#[test]
fn test_puncture() {
    // Test key puncturing
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
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
}

#[test]
fn test_puncture_multiple() {
    // Test multiple punctures
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attributes);

    let taus = vec![1, 2, 3, 4, 5];
    let puncture = Puncture::new();
    let punctured_sk = puncture
        .puncture_multiple(&sk, &taus)
        .expect("Puncture multiple should succeed");

    // Verify all tags are punctured
    for tau in &taus {
        assert!(puncture
            .is_punctured(&punctured_sk, *tau)
            .expect("is_punctured should succeed"));
    }

    // Verify non-punctured tag is still valid
    assert!(!puncture
        .is_punctured(&punctured_sk, 6)
        .expect("is_punctured should succeed"));
}

#[test]
fn test_policy_satisfaction() {
    // Test policy satisfaction
    let policy = Policy::parse("admin AND finance").expect("Valid policy");

    // Test satisfied attributes
    let attributes1 = vec!["user", "admin", "finance"];
    assert!(policy.satisfies(&attributes1));

    // Test unsatisfied attributes
    let attributes2 = vec!["user", "admin"];
    assert!(!policy.satisfies(&attributes2));
}

#[test]
fn test_policy_variations() {
    // Test different policy variations
    let policies = vec![
        Policy::parse("admin").expect("Valid policy"),
        Policy::parse("admin AND finance").expect("Valid policy"),
        Policy::parse("admin OR user").expect("Valid policy"),
    ];

    let attribute_sets = vec![
        vec!["admin"],
        vec!["admin", "finance"],
        vec!["user"],
        vec!["user", "finance"],
    ];

    // Test admin policy
    assert!(policies[0].satisfies(&attribute_sets[0]));
    assert!(policies[0].satisfies(&attribute_sets[1]));
    assert!(!policies[0].satisfies(&attribute_sets[2]));
    assert!(!policies[0].satisfies(&attribute_sets[3]));

    // Test admin AND finance policy
    assert!(!policies[1].satisfies(&attribute_sets[0]));
    assert!(policies[1].satisfies(&attribute_sets[1]));
    assert!(!policies[1].satisfies(&attribute_sets[2]));
    assert!(!policies[1].satisfies(&attribute_sets[3]));

    // Test admin OR user policy
    assert!(policies[2].satisfies(&attribute_sets[0]));
    assert!(policies[2].satisfies(&attribute_sets[1]));
    assert!(policies[2].satisfies(&attribute_sets[2]));
    assert!(policies[2].satisfies(&attribute_sets[3]));
}

#[test]
fn test_crf_basic() {
    // Test basic CRF functionality
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attributes);

    let policy = Policy::parse("admin").expect("Valid policy");
    let message = b"Hello, World!";

    // Generate multiple signatures
    let mut signatures = Vec::new();
    for _ in 0..5 {
        signatures.push(sign(&sk, message, &policy, 0).expect("Signing should succeed"));
    }

    // All signatures should verify
    for sig in &signatures {
        assert!(verify(&pp, message, &policy, sig).expect("Verification should succeed"));
    }

    // All signatures should be different
    let mut unique = std::collections::HashSet::new();
    for sig in &signatures {
        let sig_str = serde_json::to_string(sig).unwrap();
        unique.insert(sig_str);
    }
    assert_eq!(unique.len(), signatures.len());
}
