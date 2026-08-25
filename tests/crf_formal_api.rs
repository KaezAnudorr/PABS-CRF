use pabs_crf::firewall::{CryptographicReverseFirewall, CRF_TRANSCRIPT_DOMAIN};
use pabs_crf::keygen::keygen_structured;
use pabs_crf::policy::Policy;
use pabs_crf::setup::setup_structured;
use pabs_crf::sign::sign_structured;
use pabs_crf::verify::verify_signature_struct;

#[test]
fn test_crf_domain_separator_is_explicit() {
    assert!(
        CRF_TRANSCRIPT_DOMAIN.starts_with(b"PABS-CRF::CryptographicReverseFirewall"),
        "CRF transcript must use an explicit domain separator"
    );
}

#[test]
fn test_crf_precommit_delta_is_challenge_bound() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["admin", "finance"]).unwrap();
    let policy = Policy::parse("admin AND finance").unwrap();
    let message = b"crf delta challenge binding";

    let sig = sign_structured(&sk, message, &policy, 7).unwrap();
    assert!(verify_signature_struct(&pp, message, &policy, &sig).unwrap());

    let mut tampered = sig.clone();
    tampered.firewall_delta.elements[0].coeffs[0] =
        tampered.firewall_delta.elements[0].coeffs[0].wrapping_add(1);

    assert!(
        !verify_signature_struct(&pp, message, &policy, &tampered).unwrap(),
        "tampering with the public CRF correction must invalidate verification"
    );
}

#[test]
fn test_crf_tag_binds_challenge_and_metadata() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["admin", "finance"]).unwrap();
    let policy = Policy::parse("admin AND finance").unwrap();
    let message = b"crf metadata binding";

    let sig = sign_structured(&sk, message, &policy, 9).unwrap();
    let firewall = CryptographicReverseFirewall::new(pp.params, 128);
    firewall.validate_metadata(&sig).unwrap();

    let mut tampered_challenge = sig.clone();
    if let Some(c) = tampered_challenge
        .challenge
        .coeffs
        .iter_mut()
        .find(|c| **c != 0)
    {
        *c = c.wrapping_neg();
    }
    assert!(
        firewall.validate_metadata(&tampered_challenge).is_err(),
        "CRF tag must bind the Fiat-Shamir challenge"
    );

    let mut tampered_tau = sig.clone();
    tampered_tau.tau = tampered_tau.tau.wrapping_add(1);
    assert!(
        firewall.validate_metadata(&tampered_tau).is_err(),
        "CRF tag must bind puncture-tag metadata"
    );
}

#[test]
fn test_single_call_transform_requires_prechallenge_binding() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["admin"]).unwrap();
    let policy = Policy::parse("admin").unwrap();
    let sig = sign_structured(&sk, b"legacy transform guard", &policy, 0).unwrap();
    let firewall = CryptographicReverseFirewall::new(pp.params, 128);

    let core = pabs_crf::pabs::types::CorePredicateSignature {
        z: sig.z.clone(),
        challenge: sig.challenge.clone(),
        hints: sig.hints.clone(),
        policy: sig.policy.clone(),
        message_hash: sig.message_hash.clone(),
        attributes_used: sig.attributes_used.clone(),
        policy_digest: sig.policy_digest.clone(),
        parameter_set_id: sig.parameter_set_id.clone(),
        gid: sig.gid,
    };

    let err = firewall
        .transform(core, &pp.matrix_a, &sig.pk_hash, sig.tau)
        .unwrap_err();
    assert!(
        err.to_string().contains("pre-challenge binding"),
        "CRF must reject unsafe post-challenge-only transformation"
    );
}
