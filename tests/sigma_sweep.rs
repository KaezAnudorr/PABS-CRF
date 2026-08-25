//! Sigma sweep tests for the PABS-CRF v4 crate.
//!
//! Exercises the full setup → keygen → sign → verify pipeline at
//! σ ∈ {3.0, 10, 30, 100, 360} to characterise the performance–security
//! trade-off of CDT Gaussian preimage sampling.

use pabs_crf::keygen::keygen_structured;
use pabs_crf::mlwe::MLWEParameters;
use pabs_crf::policy::Policy;
use pabs_crf::setup::setup_structured_with_sigma;
use pabs_crf::sign::sign_structured;
use pabs_crf::verify::verify_signature_struct;

fn run_pipeline(sigma: f64) {
    let (pp, msk) = setup_structured_with_sigma(128, sigma);
    let params = pp.params;

    assert_eq!(params.sigma(), sigma, "sigma should be preserved in params");

    let sk = keygen_structured(&pp, &msk, &["admin", "finance"]).expect("keygen should succeed");

    for (i, preimage) in sk.preimages.iter().enumerate() {
        let centered = preimage.center_coefficients(params.q);
        let norm = centered.infinity_norm_integer();
        println!(
            "  [σ={:.1}] preimage[{}] infinity_norm = {} (gamma1={})",
            sigma, i, norm, params.gamma1
        );
        assert!(
            norm <= params.gamma1 as i64,
            "preimage[{}] norm {} exceeds gamma1 {}",
            i,
            norm,
            params.gamma1
        );
    }

    let policy = Policy::parse("admin AND finance").expect("policy should parse");
    let message = b"sigma sweep test message";

    let sig = sign_structured(&sk, message, &policy, 0).expect("sign should succeed");

    let valid =
        verify_signature_struct(&pp, message, &policy, &sig).expect("verify should not error");
    assert!(valid, "signature should verify");

    let wrong_msg_valid = verify_signature_struct(&pp, b"wrong message", &policy, &sig)
        .expect("verify should not error");
    assert!(
        !wrong_msg_valid,
        "signature on wrong message should NOT verify"
    );

    let sig_bytes = bincode::serialize(&sig).expect("serialization should succeed");
    println!(
        "  [σ={:.1}] signature size = {} bytes, gamma1={}, z_bound={}",
        sigma,
        sig_bytes.len(),
        params.gamma1,
        params.gamma1 - params.beta as u32
    );
}

#[test]
fn test_sigma_3_0_full_pipeline() {
    run_pipeline(3.0);
}

#[test]
fn test_sigma_10_full_pipeline() {
    run_pipeline(10.0);
}

#[test]
fn test_sigma_30_full_pipeline() {
    run_pipeline(30.0);
}

#[test]
fn test_sigma_100_full_pipeline() {
    run_pipeline(100.0);
}

#[test]
fn test_sigma_360_full_pipeline() {
    run_pipeline(360.0);
}

#[test]
fn test_with_sigma_preserves_structural_params() {
    let base = MLWEParameters::new_128();
    let larger = MLWEParameters::new_128().with_sigma(200.0);
    let smaller = MLWEParameters::new_128().with_sigma(10.0);

    assert_eq!(larger.k, base.k, "k should be unchanged");
    assert_eq!(larger.n, base.n, "n should be unchanged");
    assert_eq!(larger.q, base.q, "q should be unchanged");
    assert_eq!(larger.eta1, base.eta1, "eta1 should be unchanged");
    assert_eq!(larger.eta2, base.eta2, "eta2 should be unchanged");
    assert_eq!(larger.tau, base.tau, "tau should be unchanged");
    assert_eq!(larger.ell, base.ell, "ell should be unchanged");
    assert_eq!(larger.base, base.base, "base should be unchanged");
    assert_eq!(larger.m, base.m, "m should be unchanged");

    assert_eq!(larger.sigma, 200.0, "sigma should be updated to 200");
    assert!(
        larger.gamma1 >= base.gamma1,
        "gamma1 should scale up or stay same for larger sigma"
    );
    assert!(larger.gamma1 < larger.q / 2, "gamma1 must remain < q/2");

    assert_eq!(smaller.sigma, 10.0, "sigma should be updated to 10");
    assert!(
        smaller.gamma1 <= base.gamma1,
        "gamma1 should scale down for smaller sigma"
    );
    assert!(smaller.gamma1 > 0, "gamma1 must be positive");
}

#[test]
fn test_with_sigma_gamma1_capped_at_q_half() {
    let params = MLWEParameters::new_128().with_sigma(360.0);
    assert!(
        params.gamma1 <= params.q / 2 - 1,
        "gamma1 must be capped at q/2 - 1, got {}",
        params.gamma1
    );
}

#[test]
fn test_with_sigma_rejects_nonpositive() {
    let result = std::panic::catch_unwind(|| {
        let _ = MLWEParameters::new_128().with_sigma(0.0);
    });
    assert!(result.is_err(), "with_sigma(0.0) should panic");

    let result = std::panic::catch_unwind(|| {
        let _ = MLWEParameters::new_128().with_sigma(-1.0);
    });
    assert!(result.is_err(), "with_sigma(-1.0) should panic");
}
