//! Acceptance tests for the formal v4 mainline.

use pabs_crf::keygen::KeyGen;
use pabs_crf::setup::Setup;
use pabs_crf::sign::sign_structured;
use pabs_crf::verify::{verify_signature_struct, Verify};
use pabs_crf::*;

#[test]
fn test_top_tier_v4_structured_metadata() {
    let setup = Setup::new();
    let keygen = KeyGen::new();

    let (pp, msk) = setup
        .try_generate_structured(128)
        .expect("structured setup should succeed");
    let sk = keygen
        .try_generate_structured(&pp, &msk, &["admin", "finance"])
        .expect("structured keygen should succeed");

    assert_eq!(pp.transport_version, "firewall-signature/v4");
    assert_eq!(pp.firewall_domain_separator, "PABS-CRF::Firewall::v4");
    assert_eq!(
        pp.parameter_model.protocol.security_target,
        SecurityTarget::Bits128
    );
    assert_eq!(msk.trapdoor_mode, pabs_crf::trapdoor::TrapdoorMode::Strict);
    assert_eq!(sk.trapdoor_mode, pabs_crf::trapdoor::TrapdoorMode::Strict);
    assert_eq!(sk.witness_schema, "attribute-preimage/v4");
}

#[test]
fn test_top_tier_v4_structured_signature_uses_firewall_path() {
    let setup = Setup::new();
    let keygen = KeyGen::new();
    let (pp, msk) = setup
        .try_generate_structured(128)
        .expect("structured setup should succeed");
    let sk = keygen
        .try_generate_structured(&pp, &msk, &["admin", "finance"])
        .expect("structured keygen should succeed");

    let policy = Policy::parse("admin AND finance").expect("policy should parse");
    let message = b"top-tier-v4 firewall signature";
    let signature =
        sign_structured(&sk, message, &policy, 0).expect("structured sign should succeed");

    assert!(signature.crf_seed.is_none());
    assert_eq!(signature.parameter_set_id, SecurityTarget::Bits128.as_str());
    assert_eq!(signature.firewall_delta.elements.len(), pp.params.k);
    assert!(!signature.firewall_tag.is_empty());
    assert!(verify_signature_struct(&pp, message, &policy, &signature).unwrap());
    assert!(!verify_signature_struct(&pp, b"wrong message", &policy, &signature).unwrap());
    assert!(!verify_signature_struct(
        &pp,
        message,
        &Policy::parse("admin").expect("policy should parse"),
        &signature,
    )
    .unwrap());
}

#[test]
fn test_top_tier_v4_compressed_signature_roundtrip() {
    let (pp, msk) = setup(128);
    let sk = keygen(&pp, &msk, &["admin", "finance"]);
    let policy = Policy::parse("admin AND finance").expect("policy should parse");
    let message = b"top-tier-v4 compressed signature";

    let signer = Sign::new();
    let verifier = Verify::new();
    let blob = signer
        .sign_compressed(&sk, message, &policy, 0)
        .expect("compressed sign should succeed");

    let compressed = CompressedFirewallSignature::from_bytes(&blob)
        .expect("compressed signature should deserialize");
    let mut attrs = compressed
        .witness_attributes(&policy)
        .expect("witness rows should decode");
    attrs.sort();

    assert!(compressed.crf_seed.is_none());
    assert_eq!(
        compressed.parameter_set_id,
        SecurityTarget::Bits128.as_str()
    );
    assert_eq!(attrs, vec!["admin".to_string(), "finance".to_string()]);
    assert!(verifier
        .verify_compressed(&pp, message, &policy, &blob)
        .expect("compressed verification should succeed"));
}

#[test]
fn test_top_tier_v4_legacy_signature_map_hides_crf_seed() {
    let (pp, msk) = setup(128);
    let sk = keygen(&pp, &msk, &["admin", "finance"]);
    let policy = Policy::parse("admin AND finance").expect("policy should parse");
    let message = b"top-tier-v4 legacy compatibility";

    let signature = sign(&sk, message, &policy, 0).expect("sign should succeed");

    assert!(!signature.contains_key("crf_seed"));
    assert!(verify(&pp, message, &policy, &signature).unwrap());
}
