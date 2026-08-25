use pabs_crf::keygen::keygen_structured;
use pabs_crf::mlwe::MLWEParameters;
use pabs_crf::policy::Policy;
use pabs_crf::setup::{setup_structured, setup_structured_with_sigma};
use pabs_crf::sign::sign_structured;
use pabs_crf::verify::verify_signature_struct;

#[test]
fn test_default_sigma_is_100() {
    let (pp, _msk) = setup_structured(128);
    assert!((pp.params.sigma - 100.0).abs() < f64::EPSILON);

    assert!((MLWEParameters::new_128().sigma - 100.0).abs() < f64::EPSILON);
    assert!((MLWEParameters::new_192().sigma - 100.0).abs() < f64::EPSILON);
    assert!((MLWEParameters::new_256().sigma - 100.0).abs() < f64::EPSILON);
}

#[test]
fn test_sigma100_full_pipeline_128() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).unwrap();
    let policy = Policy::parse("attr_A AND attr_B").unwrap();
    let msg = b"sigma100 test";
    let sig = sign_structured(&sk, msg, &policy, 0).unwrap();
    assert!(verify_signature_struct(&pp, msg, &policy, &sig).unwrap());

    let wrong_msg = b"wrong message";
    assert!(!verify_signature_struct(&pp, wrong_msg, &policy, &sig).unwrap());
}

#[test]
fn test_sigma100_full_pipeline_192() {
    let (pp, msk) = setup_structured(192);
    let sk = keygen_structured(&pp, &msk, &["attr_A", "attr_B", "attr_C"]).unwrap();
    let policy = Policy::parse("attr_A AND attr_B").unwrap();
    let msg = b"sigma100 192-bit test";
    let sig = sign_structured(&sk, msg, &policy, 0).unwrap();
    assert!(verify_signature_struct(&pp, msg, &policy, &sig).unwrap());
}

#[test]
fn test_sigma100_signature_norm_bound() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).unwrap();
    let policy = Policy::parse("attr_A AND attr_B").unwrap();
    let msg = b"sigma100 norm bound test";
    let sig = sign_structured(&sk, msg, &policy, 0).unwrap();

    let q = pp.params.q;
    let gamma1 = pp.params.gamma1;
    let beta = pp.params.beta;
    let z_centered = sig.z.center_coefficients(q);
    let norm = z_centered.infinity_norm_integer();
    let bound = (gamma1 - beta as u32) as i64;

    eprintln!(
        "norm = {}, bound = gamma1({}) - beta({}) = {}",
        norm, gamma1, beta, bound
    );
    assert!(
        norm < bound,
        "norm {} must be < gamma1-beta {}",
        norm,
        bound
    );
}

#[test]
fn test_sigma3_still_available_via_with_sigma() {
    let (pp, msk) = setup_structured_with_sigma(128, 3.0);
    assert!((pp.params.sigma - 3.0).abs() < f64::EPSILON);

    let sk = keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).unwrap();
    let policy = Policy::parse("attr_A AND attr_B").unwrap();
    let msg = b"sigma3 legacy test";
    let sig = sign_structured(&sk, msg, &policy, 0).unwrap();
    assert!(verify_signature_struct(&pp, msg, &policy, &sig).unwrap());
}
