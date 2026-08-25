use pabs_crf::keygen::keygen_structured;
use pabs_crf::policy::Policy;
use pabs_crf::setup::setup_structured;
use pabs_crf::sign::sign_structured;
use pabs_crf::verify::verify_signature_struct;

#[test]
fn test_firewall_tag_nonempty_and_correct_length() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["admin", "finance"]).unwrap();
    let policy = Policy::parse("admin AND finance").unwrap();
    let message = b"tag length test";

    let sig = sign_structured(&sk, message, &policy, 0).unwrap();

    assert!(
        !sig.firewall_tag.is_empty(),
        "firewall_tag must not be empty"
    );
    assert_eq!(
        sig.firewall_tag.len(),
        32,
        "firewall_tag must be 32 bytes (SHA-256 output)"
    );
    assert!(verify_signature_struct(&pp, message, &policy, &sig).unwrap());
}

#[test]
fn test_firewall_tag_deterministic_from_signature_components() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["admin", "finance"]).unwrap();
    let policy = Policy::parse("admin AND finance").unwrap();
    let message = b"deterministic tag test";

    let sig = sign_structured(&sk, message, &policy, 0).unwrap();
    let tag1 = sig.firewall_tag.clone();
    let tag2 = sig.firewall_tag.clone();

    assert_eq!(
        tag1, tag2,
        "reading firewall_tag twice from same signature must be stable"
    );
    assert!(verify_signature_struct(&pp, message, &policy, &sig).unwrap());
}

#[test]
fn test_firewall_tag_crf_rerandomization() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["admin", "finance"]).unwrap();
    let policy = Policy::parse("admin AND finance").unwrap();
    let message = b"CRF rerandomization test";

    let mut tags = Vec::new();
    for _ in 0..3 {
        let sig = sign_structured(&sk, message, &policy, 0).unwrap();
        assert!(verify_signature_struct(&pp, message, &policy, &sig).unwrap());
        tags.push(sig.firewall_tag);
    }

    let all_same = tags.windows(2).all(|w| w[0] == w[1]);
    assert!(
        !all_same,
        "CRF must rerandomize z/delta, so tags should differ across signing attempts"
    );
}

#[test]
fn test_firewall_tag_different_messages_different_tags() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["admin", "finance"]).unwrap();
    let policy = Policy::parse("admin AND finance").unwrap();

    let msg_a = b"message alpha";
    let msg_b = b"message beta";

    let sig_a = sign_structured(&sk, msg_a, &policy, 0).unwrap();
    let sig_b = sign_structured(&sk, msg_b, &policy, 0).unwrap();

    assert!(verify_signature_struct(&pp, msg_a, &policy, &sig_a).unwrap());
    assert!(verify_signature_struct(&pp, msg_b, &policy, &sig_b).unwrap());

    assert_ne!(
        sig_a.firewall_tag, sig_b.firewall_tag,
        "different messages must produce different firewall_tags (domain separation)"
    );
}

#[test]
fn test_firewall_tag_different_policies_different_tags() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["admin", "finance", "user"]).unwrap();
    let message = b"policy domain test";

    let policy_admin = Policy::parse("admin").unwrap();
    let policy_admin_finance = Policy::parse("admin AND finance").unwrap();

    let sig_admin = sign_structured(&sk, message, &policy_admin, 0).unwrap();
    let sig_admin_finance = sign_structured(&sk, message, &policy_admin_finance, 0).unwrap();

    assert!(verify_signature_struct(&pp, message, &policy_admin, &sig_admin).unwrap());
    assert!(
        verify_signature_struct(&pp, message, &policy_admin_finance, &sig_admin_finance).unwrap()
    );

    assert_ne!(
        sig_admin.firewall_tag, sig_admin_finance.firewall_tag,
        "different policies must produce different firewall_tags"
    );
}

#[test]
fn test_firewall_tag_included_in_signature_metadata() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["admin"]).unwrap();
    let policy = Policy::parse("admin").unwrap();
    let message = b"metadata inclusion test";

    let sig = sign_structured(&sk, message, &policy, 0).unwrap();

    assert!(!sig.firewall_tag.is_empty());
    assert_eq!(sig.parameter_set_id, "top-tier-128");
    assert!(sig.crf_seed.is_none(), "formal path must not set crf_seed");
    assert!(verify_signature_struct(&pp, message, &policy, &sig).unwrap());
}
