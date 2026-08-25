use pabs_crf::keygen::keygen_structured;
use pabs_crf::mlwe::MLWEParameters;
use pabs_crf::policy::Policy;
use pabs_crf::setup::setup_structured_with_sigma;
use pabs_crf::sign::sign_structured;
use pabs_crf::verify::verify_signature_struct;

#[test]
fn test_sigma_360_produces_valid_parameters() {
    let params = MLWEParameters::new_128().with_sigma(360.0);
    assert_eq!(params.sigma(), 360.0, "sigma should be preserved");
    assert!(params.gamma1 > 0, "gamma1 must be positive");
    assert!(
        params.gamma1 < params.q / 2,
        "gamma1={} must be < q/2={}",
        params.gamma1,
        params.q / 2
    );
    params
        .validate_parameter_consistency()
        .expect("sigma=360 parameters must be internally consistent");
}

#[test]
fn test_gamma1_in_valid_range_sigma_360() {
    let params = MLWEParameters::new_128().with_sigma(360.0);
    let q = params.q;
    assert!(
        params.gamma1 > 0 && params.gamma1 <= q / 2 - 1,
        "gamma1={} must satisfy 0 < gamma1 <= q/2 - 1 = {}",
        params.gamma1,
        q / 2 - 1
    );
}

#[test]
fn test_gamma1_in_valid_range_sigma_100() {
    let params = MLWEParameters::new_128().with_sigma(100.0);
    let q = params.q;
    assert!(
        params.gamma1 > 0 && params.gamma1 <= q / 2 - 1,
        "gamma1={} must satisfy 0 < gamma1 <= q/2 - 1 = {}",
        params.gamma1,
        q / 2 - 1
    );
}

#[test]
fn test_gamma1_scales_with_sigma_before_saturation() {
    let base_gamma1: u32 = 1 << 19;

    let params_small = MLWEParameters::new_128().with_sigma(3.0);
    let scale_small = (3.0f64 / 3.0).ceil() as u32;
    let expected_small = base_gamma1.saturating_mul(scale_small);
    assert_eq!(
        params_small.gamma1, expected_small,
        "sigma=3.0: gamma1 should equal base_gamma1 * ceil(3/3) = base_gamma1"
    );

    let params_medium = MLWEParameters::new_128().with_sigma(10.0);
    let scale_medium = (10.0f64 / 3.0).ceil() as u32;
    let expected_medium = base_gamma1
        .saturating_mul(scale_medium)
        .min(params_medium.q / 2 - 1);
    assert_eq!(
        params_medium.gamma1, expected_medium,
        "sigma=10.0: gamma1 should follow scaling formula"
    );

    assert!(
        params_medium.gamma1 > params_small.gamma1,
        "larger sigma (10.0) should produce larger gamma1 ({}) than sigma=3.0 ({})",
        params_medium.gamma1,
        params_small.gamma1
    );
}

#[test]
fn test_sigma_360_gamma1_at_least_as_large_as_sigma_100() {
    let params_100 = MLWEParameters::new_128().with_sigma(100.0);
    let params_360 = MLWEParameters::new_128().with_sigma(360.0);

    assert!(
        params_360.gamma1 >= params_100.gamma1,
        "sigma=360 gamma1 ({}) should be >= sigma=100 gamma1 ({})",
        params_360.gamma1,
        params_100.gamma1
    );

    let base_gamma1: u32 = 1 << 19;
    let scale_100 = (100.0f64 / 3.0).ceil() as u32;
    let scale_360 = (360.0f64 / 3.0).ceil() as u32;
    assert!(
        scale_360 > scale_100,
        "unscaled gamma1 for sigma=360 (base*{}) should exceed sigma=100 (base*{})",
        scale_360,
        scale_100
    );

    let _raw_100 = base_gamma1.saturating_mul(scale_100);
    let raw_360 = base_gamma1.saturating_mul(scale_360);
    if raw_360 <= params_360.q / 2 - 1 {
        assert!(
            params_360.gamma1 > params_100.gamma1,
            "when unsaturated, sigma=360 should produce strictly larger gamma1"
        );
    }
}

#[test]
fn test_sigma_360_full_sign_verify_cycle() {
    let (pp, msk) = setup_structured_with_sigma(128, 360.0);

    assert_eq!(pp.params.sigma(), 360.0, "params should carry sigma=360");

    let sk = keygen_structured(&pp, &msk, &["admin", "finance"]).expect("keygen with sigma=360");

    for (i, preimage) in sk.preimages.iter().enumerate() {
        let centered = preimage.center_coefficients(pp.params.q);
        let norm = centered.infinity_norm_integer();
        assert!(
            norm <= pp.params.gamma1 as i64,
            "preimage[{}] norm {} exceeds gamma1 {}",
            i,
            norm,
            pp.params.gamma1
        );
    }

    let policy = Policy::parse("admin AND finance").expect("policy");
    let message = b"sigma 360 strict mode test";

    let sig = sign_structured(&sk, message, &policy, 0).expect("sign with sigma=360");
    let valid = verify_signature_struct(&pp, message, &policy, &sig)
        .expect("verify with sigma=360 should not error");
    assert!(valid, "sigma=360 sign/verify cycle should succeed");
}

#[test]
fn test_sigma_360_wrong_message_fails() {
    let (pp, msk) = setup_structured_with_sigma(128, 360.0);
    let sk = keygen_structured(&pp, &msk, &["admin"]).expect("keygen");

    let policy = Policy::parse("admin").expect("policy");
    let sig = sign_structured(&sk, b"correct message", &policy, 0).expect("sign");

    let valid = verify_signature_struct(&pp, b"wrong message", &policy, &sig)
        .expect("verify should not error");
    assert!(!valid, "sigma=360 signature on wrong message must fail");
}

#[test]
fn test_sigma_360_wrong_policy_fails() {
    let (pp, msk) = setup_structured_with_sigma(128, 360.0);
    let sk = keygen_structured(&pp, &msk, &["admin", "finance"]).expect("keygen");

    let policy_admin_fin = Policy::parse("admin AND finance").expect("policy");
    let sig = sign_structured(&sk, b"test", &policy_admin_fin, 0).expect("sign");

    let policy_admin = Policy::parse("admin").expect("policy");
    let valid = verify_signature_struct(&pp, b"test", &policy_admin, &sig)
        .expect("verify should not error");
    assert!(!valid, "sigma=360 signature under wrong policy must fail");
}

#[test]
fn test_sigma_360_z_bound_positive() {
    let params = MLWEParameters::new_128().with_sigma(360.0);
    let z_bound = (params.gamma1 as i64 - params.beta as i64) as i32;
    assert!(
        z_bound > 0,
        "z_bound (gamma1 - beta = {} - {} = {}) must be positive",
        params.gamma1,
        params.beta,
        z_bound
    );
}
