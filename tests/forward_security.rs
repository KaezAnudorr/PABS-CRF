use pabs_crf::errors::PabsCrfError;
use pabs_crf::keygen::keygen_structured;
use pabs_crf::policy::Policy;
use pabs_crf::setup::setup_structured;
use pabs_crf::sign::sign_structured;
use pabs_crf::verify::verify_signature_struct;

#[test]
fn test_puncture_prevents_signing() {
    let (pp, msk) = setup_structured(128);
    let mut sk = keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).unwrap();
    let policy = Policy::parse("attr_A AND attr_B").unwrap();
    let message = b"forward security test";

    sk.puncture(42).unwrap();
    let err = sign_structured(&sk, message, &policy, 42).unwrap_err();
    assert!(matches!(err, PabsCrfError::InvalidInput(ref s) if s.contains("punctured tag tau=42")));
    eprintln!("test_puncture_prevents_signing: signing under punctured tag correctly rejected");
}

#[test]
fn test_unpunctured_tag_still_works() {
    let (pp, msk) = setup_structured(128);
    let mut sk = keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).unwrap();
    let policy = Policy::parse("attr_A AND attr_B").unwrap();
    let message = b"unpunctured tag test";

    sk.puncture(1).unwrap();
    let sig = sign_structured(&sk, message, &policy, 2).unwrap();
    assert!(verify_signature_struct(&pp, message, &policy, &sig).unwrap());
    eprintln!(
        "test_unpunctured_tag_still_works: signing with tau=2 after puncturing tau=1 succeeded"
    );
}

#[test]
fn test_pre_puncture_signature_still_verifies() {
    let (pp, msk) = setup_structured(128);
    let mut sk = keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).unwrap();
    let policy = Policy::parse("attr_A AND attr_B").unwrap();
    let message = b"pre-puncture signature test";

    let sig = sign_structured(&sk, message, &policy, 42).unwrap();
    assert!(verify_signature_struct(&pp, message, &policy, &sig).unwrap());

    sk.puncture(42).unwrap();
    assert!(verify_signature_struct(&pp, message, &policy, &sig).unwrap());
    eprintln!("test_pre_puncture_signature_still_verifies: signature produced before puncture still verifies after puncture");
}

#[test]
fn test_multiple_punctures_cumulative() {
    let (pp, msk) = setup_structured(128);
    let mut sk = keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).unwrap();
    let policy = Policy::parse("attr_A AND attr_B").unwrap();
    let message = b"multiple punctures test";

    sk.puncture(1).unwrap();
    sk.puncture(2).unwrap();
    sk.puncture(3).unwrap();

    let sig = sign_structured(&sk, message, &policy, 4).unwrap();
    assert!(verify_signature_struct(&pp, message, &policy, &sig).unwrap());

    let err1 = sign_structured(&sk, message, &policy, 1).unwrap_err();
    assert!(matches!(err1, PabsCrfError::InvalidInput(ref s) if s.contains("punctured tag tau=1")));

    let err2 = sign_structured(&sk, message, &policy, 2).unwrap_err();
    assert!(matches!(err2, PabsCrfError::InvalidInput(ref s) if s.contains("punctured tag tau=2")));

    let err3 = sign_structured(&sk, message, &policy, 3).unwrap_err();
    assert!(matches!(err3, PabsCrfError::InvalidInput(ref s) if s.contains("punctured tag tau=3")));

    eprintln!("test_multiple_punctures_cumulative: all three punctured tags blocked, unpunctured tag=4 works");
}

#[test]
fn test_puncture_count_tracking() {
    let (pp, msk) = setup_structured(128);
    let mut sk = keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).unwrap();

    assert_eq!(sk.puncture_count, 0);

    let newly1 = sk.puncture(10).unwrap();
    assert!(newly1);
    assert_eq!(sk.puncture_count, 1);

    let newly2 = sk.puncture(20).unwrap();
    assert!(newly2);
    assert_eq!(sk.puncture_count, 2);

    let newly3 = sk.puncture(10).unwrap();
    assert!(!newly3);
    assert_eq!(sk.puncture_count, 2);

    eprintln!(
        "test_puncture_count_tracking: count={}, re-puncture returned false",
        sk.puncture_count
    );
}
