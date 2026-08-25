//! Edge case tests for the PABS-CRF scheme

use pabs_crf::*;

#[test]
fn test_invalid_security_level() {
    // Test invalid security level now falls back to defaults
    let (pp, msk) = setup(100);
    assert!(!pp.is_empty());
    assert!(!msk.is_empty());

    // The fallback should still produce a usable signing workflow
    let attributes = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attributes);
    let policy = Policy::parse("admin").expect("Valid policy");
    let message = b"fallback security level";
    let signature =
        sign(&sk, message, &policy, 0).expect("Signing should succeed with fallback params");
    assert!(verify(&pp, message, &policy, &signature)
        .expect("Verification should succeed with fallback params"));
}

#[test]
fn test_policy_not_satisfied() {
    // Test policy not satisfied by user attributes - should now return error
    let (pp, msk) = setup(128);
    let attributes = vec!["user"];
    let sk = keygen(&pp, &msk, &attributes);

    let policy = Policy::parse("admin AND finance").expect("Valid policy");
    let message = b"Hello, World!";

    // This should now return an error
    let signature = sign(&sk, message, &policy, 0);
    assert!(
        signature.is_err(),
        "Signing should fail when policy not satisfied"
    );
}

#[test]
fn test_empty_attributes() {
    // Test empty attributes
    let (pp, msk) = setup(128);
    let attributes: Vec<&str> = vec![];

    // This should work but may not satisfy any policy
    let sk = keygen(&pp, &msk, &attributes);
    assert!(!sk.is_empty());

    // Test policy satisfaction with empty attributes
    let policy = Policy::parse("user").expect("Valid policy");
    assert!(!policy.satisfies(&attributes));

    // Negative: empty attribute set should not allow signing a non-empty policy
    assert!(sign(&sk, b"empty attrs", &policy, 0).is_err());
}

#[test]
fn test_large_attribute_set() {
    // Test large attribute set
    let (pp, msk) = setup(128);

    // Create a large set of attributes
    let mut attributes: Vec<String> = Vec::new();
    for i in 0..100 {
        attributes.push(format!("attr_{}", i));
    }

    // Convert to &str slice
    let attr_refs: Vec<&str> = attributes.iter().map(|s| s.as_str()).collect();

    // This should work without OOM
    let sk = keygen(&pp, &msk, &attr_refs);
    assert!(!sk.is_empty());

    // Special-character attribute names should be handled safely by structured serialization
    let special_attrs = vec!["role:doctor", "department:cardiology", "admin,finance"];
    let special_sk = keygen(&pp, &msk, &special_attrs);
    assert!(!special_sk.is_empty());

    let special_policy =
        Policy::parse("role:doctor AND department:cardiology").expect("Valid policy");
    let special_signature =
        sign(&special_sk, b"special attrs", &special_policy, 0).expect("Signing should succeed");
    assert!(
        verify(&pp, b"special attrs", &special_policy, &special_signature)
            .expect("Verification should succeed")
    );
}

#[test]
fn test_deep_policy() {
    // Test deep policy
    let (pp, msk) = setup(128);
    let attributes = vec!["a1", "a2", "a3", "a4", "a5"];
    let sk = keygen(&pp, &msk, &attributes);

    // Create a deep nested policy
    let policy_str = "a1 AND a2 AND a3 AND a4 AND a5";
    let policy = Policy::parse(policy_str).expect("Valid policy");

    // This should work
    let message = b"Test message";
    let signature = sign(&sk, message, &policy, 0).expect("Signing should succeed");
    assert!(verify(&pp, message, &policy, &signature).expect("Verification should succeed"));

    // Nested policy should also work and exercise parser structure
    let nested_policy =
        Policy::parse("(a1 AND a2) AND (a3 AND (a4 AND a5))").expect("Valid nested policy");
    let nested_signature = sign(&sk, message, &nested_policy, 0).expect("Signing should succeed");
    assert!(verify(&pp, message, &nested_policy, &nested_signature)
        .expect("Verification should succeed"));
}

#[test]
fn test_long_message() {
    // Test long message
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attributes);

    // Create a long message
    let long_message = vec![0u8; 10000]; // 10KB message

    let policy = Policy::parse("admin").expect("Valid policy");
    let signature = sign(&sk, &long_message, &policy, 0).expect("Signing should succeed");
    assert!(verify(&pp, &long_message, &policy, &signature).expect("Verification should succeed"));

    // Empty message should also remain signable for valid policy
    let empty_message = Vec::new();
    let empty_signature =
        sign(&sk, &empty_message, &policy, 0).expect("Signing should succeed for empty message");
    assert!(verify(&pp, &empty_message, &policy, &empty_signature)
        .expect("Verification should succeed for empty message"));
}

#[test]
fn test_puncture_multiple_tags() {
    // Test puncturing multiple tags
    let (_pp, msk) = setup(128);
    let attributes = vec!["user", "admin"];
    let sk = keygen(&_pp, &msk, &attributes);

    // Puncture multiple tags
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

    // Re-puncturing an existing tag should remain consistent
    let repunctured_sk = puncture
        .puncture_multiple(&punctured_sk, &[3, 6])
        .expect("Re-puncture should succeed");
    assert!(puncture
        .is_punctured(&repunctured_sk, 3)
        .expect("is_punctured should succeed"));
    assert!(puncture
        .is_punctured(&repunctured_sk, 6)
        .expect("is_punctured should succeed"));
}

#[test]
fn test_signature_size() {
    // Test signature size
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attributes);

    let policy = Policy::parse("admin").expect("Valid policy");
    let message = b"Hello, World!";
    let signature = sign(&sk, message, &policy, 0).expect("Signing should succeed");

    // Serialize signature to check size
    let sig_bytes = serde_json::to_vec(&signature).unwrap();
    eprintln!("Signature serialized size: {} bytes", sig_bytes.len());

    assert!(sig_bytes.len() < 500 * 1024);

    // A tampered signature should still serialize, but verification must fail
    let mut tampered = signature.clone();
    if let Some(c) = tampered.get_mut("challenge") {
        if c.len() >= 4 {
            c[0] ^= 0xFF;
        }
    }
    assert!(!verify(&pp, message, &policy, &tampered).expect("Tampered signature should not error"));
}
