use pabs_crf::MLWEParameters;

#[test]
fn test_128bit_z_bound_not_trivially_true() {
    let params = MLWEParameters::top_tier_128();
    let bound_z = params.gamma1 as i64 - params.beta as i64;
    assert!(
        bound_z < params.q as i64 / 2,
        "z bound must be less than q/2 to be non-trivial: bound_z={}, q/2={}",
        bound_z,
        params.q / 2
    );
    assert!(bound_z > 0, "z bound must be positive");
}

#[test]
fn test_192bit_z_bound_not_trivially_true() {
    let params = MLWEParameters::top_tier_192();
    let bound_z = params.gamma1 as i64 - params.beta as i64;
    assert!(
        bound_z < params.q as i64 / 2,
        "z bound must be less than q/2 to be non-trivial: bound_z={}, q/2={}",
        bound_z,
        params.q / 2
    );
    assert!(bound_z > 0, "z bound must be positive");
}

#[test]
fn test_256bit_z_bound_not_trivially_true() {
    let params = MLWEParameters::top_tier_256();
    let bound_z = params.gamma1 as i64 - params.beta as i64;
    assert!(
        bound_z < params.q as i64 / 2,
        "z bound must be less than q/2 to be non-trivial: bound_z={}, q/2={}",
        bound_z,
        params.q / 2
    );
    assert!(bound_z > 0, "z bound must be positive");
}

#[test]
fn test_tau_beta_consistency() {
    for (name, params) in [
        ("128", MLWEParameters::top_tier_128()),
        ("192", MLWEParameters::top_tier_192()),
        ("256", MLWEParameters::top_tier_256()),
    ] {
        let eta_max = params.eta1.max(params.eta2);
        let expected_beta = (params.tau as i32) * eta_max;
        assert_eq!(
            params.beta, expected_beta,
            "{}-bit: beta should equal tau*eta_max = {}*{} = {}, got {}",
            name, params.tau, eta_max, expected_beta, params.beta
        );
    }
}

#[test]
fn test_gamma1_within_valid_range() {
    for (name, params) in [
        ("128", MLWEParameters::top_tier_128()),
        ("192", MLWEParameters::top_tier_192()),
        ("256", MLWEParameters::top_tier_256()),
    ] {
        assert!(
            params.gamma1 > 0,
            "{}-bit: gamma1 must be positive, got {}",
            name,
            params.gamma1,
        );
        assert!(
            params.gamma1 <= params.q / 2 - 1,
            "{}-bit: gamma1 must be <= q/2-1, got gamma1={}, q/2-1={}",
            name,
            params.gamma1,
            params.q / 2 - 1,
        );
    }
}

#[test]
fn test_gamma2_positive_and_less_than_half_q() {
    for (name, params) in [
        ("128", MLWEParameters::top_tier_128()),
        ("192", MLWEParameters::top_tier_192()),
        ("256", MLWEParameters::top_tier_256()),
    ] {
        assert!(
            params.gamma2 > 0,
            "{}-bit: gamma2 must be positive, got {}",
            name,
            params.gamma2
        );
        assert!(
            (params.gamma2 as u32) < params.q / 2,
            "{}-bit: gamma2 must be less than q/2, got gamma2={}, q/2={}",
            name,
            params.gamma2,
            params.q / 2
        );
    }
}

#[test]
fn test_eta_values_consistent() {
    for (name, params) in [
        ("128", MLWEParameters::top_tier_128()),
        ("192", MLWEParameters::top_tier_192()),
        ("256", MLWEParameters::top_tier_256()),
    ] {
        assert!(
            params.eta1 > 0 && params.eta2 > 0,
            "{}-bit: eta values must be positive, got eta1={}, eta2={}",
            name,
            params.eta1,
            params.eta2
        );
    }
}

#[test]
fn test_parameter_consistency_validation_passes() {
    for (name, params) in [
        ("128", MLWEParameters::top_tier_128()),
        ("192", MLWEParameters::top_tier_192()),
        ("256", MLWEParameters::top_tier_256()),
    ] {
        assert!(
            params.validate_parameter_consistency().is_ok(),
            "{}-bit: validate_parameter_consistency should pass",
            name
        );
    }
}

#[test]
fn test_192bit_parameters_match_mldsa_65() {
    let params = MLWEParameters::top_tier_192();
    assert_eq!(params.k, 6, "ML-DSA-65: k should be 6");
    assert_eq!(params.ell, 5, "ML-DSA-65: ell should be 5");
    assert_eq!(params.tau, 49, "ML-DSA-65: tau should be 49");
    assert_eq!(params.eta1, 2, "ML-DSA-65: eta1 should be 2");
    assert_eq!(params.eta2, 2, "ML-DSA-65: eta2 should be 2");
    assert_eq!(
        params.gamma1, 4190207,
        "ML-DSA-65: gamma1 should be scaled for sigma=100 (q/2-1)"
    );
    assert_eq!(params.gamma2, 95232, "ML-DSA-65: gamma2 should be 95232");
}

#[test]
fn test_256bit_parameters_match_mldsa_87() {
    let params = MLWEParameters::top_tier_256();
    assert_eq!(params.k, 8, "ML-DSA-87: k should be 8");
    assert_eq!(params.ell, 6, "ML-DSA-87: ell should be 6");
    assert_eq!(params.tau, 60, "ML-DSA-87: tau should be 60");
    assert_eq!(params.eta1, 2, "ML-DSA-87: eta1 should be 2");
    assert_eq!(params.eta2, 2, "ML-DSA-87: eta2 should be 2");
    assert_eq!(
        params.gamma1, 4190207,
        "ML-DSA-87: gamma1 should be scaled for sigma=100 (q/2-1)"
    );
    assert_eq!(params.gamma2, 95232, "ML-DSA-87: gamma2 should be 95232");
}

#[test]
fn test_128bit_parameters_match_mldsa_44() {
    let params = MLWEParameters::top_tier_128();
    assert_eq!(params.k, 4, "ML-DSA-44: k should be 4");
    assert_eq!(params.ell, 4, "ML-DSA-44: ell should be 4");
    assert_eq!(params.tau, 39, "ML-DSA-44: tau should be 39");
    assert_eq!(params.eta1, 2, "ML-DSA-44: eta1 should be 2");
    assert_eq!(params.eta2, 2, "ML-DSA-44: eta2 should be 2");
    assert_eq!(
        params.gamma1, 4190207,
        "ML-DSA-44: gamma1 should be scaled for sigma=100 (q/2-1)"
    );
}
