use pabs_crf::keygen::keygen_structured;
use pabs_crf::lsss::LSSSShareMatrix;
use pabs_crf::policy::Policy;
use pabs_crf::setup::setup_structured;
use pabs_crf::sign::sign_structured;
use pabs_crf::verify::verify_signature_struct;

fn reconstruction_constants_within_q_half(coeffs: &[i64], q: u32) {
    let half_q = q as i64 / 2;
    for &c in coeffs {
        assert!(
            c.abs() < half_q,
            "reconstruction constant {} exceeds |q/2| = {}",
            c,
            half_q
        );
    }
}

fn and_policy_reconstruction_bound(policy_str: &str) {
    let q = 8380417u32;
    let policy = Policy::parse(policy_str).expect("policy should parse");
    let lsss = policy.to_lsss().expect("LSSS conversion should succeed");

    let all_attrs: Vec<String> = lsss.row_to_attr().to_vec();
    let constants = lsss
        .get_reconstruction_constants(&all_attrs, q)
        .expect("all attributes should satisfy AND policy");

    reconstruction_constants_within_q_half(&constants, q);
}

fn or_policy_reconstruction_bound(policy_str: &str, satisfying_attrs: &[&str]) {
    let q = 8380417u32;
    let policy = Policy::parse(policy_str).expect("policy should parse");
    let lsss = policy.to_lsss().expect("LSSS conversion should succeed");

    let attrs_str: Vec<String> = satisfying_attrs.iter().map(|s| s.to_string()).collect();
    let constants = lsss
        .get_reconstruction_constants(&attrs_str, q)
        .expect("satisfying attrs should yield reconstruction constants");

    reconstruction_constants_within_q_half(&constants, q);
}

#[test]
fn test_simple_and_reconstruction_constants_bounded() {
    and_policy_reconstruction_bound("A AND B");
}

#[test]
fn test_three_way_and_reconstruction_constants_bounded() {
    and_policy_reconstruction_bound("A AND B AND C");
}

#[test]
fn test_simple_or_single_attr_reconstruction_constants_bounded() {
    or_policy_reconstruction_bound("A OR B", &["A"]);
}

#[test]
fn test_simple_or_second_attr_reconstruction_constants_bounded() {
    or_policy_reconstruction_bound("A OR B", &["B"]);
}

#[test]
fn test_nested_and_or_reconstruction_constants_bounded() {
    let q = 8380417u32;
    let policy = Policy::parse("(A AND B) OR C").expect("policy should parse");
    let lsss = policy.to_lsss().expect("LSSS conversion should succeed");

    let ab: Vec<String> = vec!["A".to_string(), "B".to_string()];
    let constants_ab = lsss
        .get_reconstruction_constants(&ab, q)
        .expect("{A,B} should satisfy (A AND B) OR C");
    reconstruction_constants_within_q_half(&constants_ab, q);

    let c_only: Vec<String> = vec!["C".to_string()];
    let constants_c = lsss
        .get_reconstruction_constants(&c_only, q)
        .expect("{C} should satisfy (A AND B) OR C");
    reconstruction_constants_within_q_half(&constants_c, q);
}

#[test]
fn test_lsss_share_and_reconstruct_roundtrip() {
    let q = 8380417u32;
    let matrix = LSSSShareMatrix::from_boolean_tree("(A AND B) OR C").expect("LSSS");
    let secret = 42424i64;

    let shares = matrix.share(secret, q);
    assert_eq!(shares.len(), matrix.rows());

    let ab_shares: Vec<(usize, i64)> = shares
        .iter()
        .enumerate()
        .filter(|(_, _)| matrix.row_to_attr()[0] == "A" || matrix.row_to_attr()[1] == "B")
        .map(|(i, &s)| (i, s))
        .collect();
    let ab_attrs: Vec<String> = ab_shares
        .iter()
        .map(|(i, _)| matrix.row_to_attr()[*i].clone())
        .collect();
    if ab_attrs.contains(&"A".to_string()) && ab_attrs.contains(&"B".to_string()) {
        let reconstructed = matrix
            .reconstruct(&ab_shares, q)
            .expect("reconstruction should succeed");
        assert_eq!(reconstructed, secret);
    }
}

#[test]
fn test_sign_verify_simple_and_policy() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["admin", "finance"]).expect("keygen");

    let policy = Policy::parse("admin AND finance").expect("policy");
    let message = b"lsss norm bound test AND";

    let sig = sign_structured(&sk, message, &policy, 0).expect("sign");
    let valid = verify_signature_struct(&pp, message, &policy, &sig).expect("verify");
    assert!(valid, "AND policy sign/verify should succeed");
}

#[test]
fn test_sign_verify_simple_or_policy() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["admin", "finance"]).expect("keygen");

    let policy = Policy::parse("admin OR finance").expect("policy");
    let message = b"lsss norm bound test OR";

    let sig = sign_structured(&sk, message, &policy, 0).expect("sign");
    let valid = verify_signature_struct(&pp, message, &policy, &sig).expect("verify");
    assert!(valid, "OR policy sign/verify should succeed");
}

#[test]
fn test_sign_verify_nested_policy() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["admin", "finance", "user"]).expect("keygen");

    let policy = Policy::parse("(admin AND finance) OR user").expect("policy");
    let message = b"lsss norm bound test nested";

    let sig = sign_structured(&sk, message, &policy, 0).expect("sign");
    let valid = verify_signature_struct(&pp, message, &policy, &sig).expect("verify");
    assert!(valid, "nested policy sign/verify should succeed");
}

#[test]
fn test_sign_verify_single_attribute_policy() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["admin"]).expect("keygen");

    let policy = Policy::parse("admin").expect("policy");
    let message = b"lsss norm bound test single";

    let sig = sign_structured(&sk, message, &policy, 0).expect("sign");
    let valid = verify_signature_struct(&pp, message, &policy, &sig).expect("verify");
    assert!(valid, "single attribute policy sign/verify should succeed");
}

#[test]
fn test_reconstruction_correctness_via_share_reconstruct() {
    let q = 8380417u32;
    let matrix = LSSSShareMatrix::from_boolean_tree("(A AND B) OR C").expect("LSSS");
    let secret = 99999i64;

    let shares = matrix.share(secret, q);

    let a_idx = matrix.row_to_attr().iter().position(|a| a == "A").unwrap();
    let b_idx = matrix.row_to_attr().iter().position(|a| a == "B").unwrap();
    let c_idx = matrix.row_to_attr().iter().position(|a| a == "C").unwrap();

    let reconstructed_ab = matrix
        .reconstruct(&[(a_idx, shares[a_idx]), (b_idx, shares[b_idx])], q)
        .expect("{{A,B}} should reconstruct");
    assert_eq!(
        reconstructed_ab, secret,
        "reconstruction via {{A,B}} must recover secret"
    );

    let reconstructed_c = matrix
        .reconstruct(&[(c_idx, shares[c_idx])], q)
        .expect("{{C}} should reconstruct");
    assert_eq!(
        reconstructed_c, secret,
        "reconstruction via {{C}} must recover secret"
    );
}

#[test]
fn test_reconstruction_constants_none_for_nonsatisfying() {
    let q = 8380417u32;
    let policy = Policy::parse("(A AND B) OR C").expect("policy");
    let lsss = policy.to_lsss().expect("LSSS");

    let a_only: Vec<String> = vec!["A".to_string()];
    assert!(
        lsss.get_reconstruction_constants(&a_only, q).is_none(),
        "{{A}} alone should NOT satisfy (A AND B) OR C"
    );

    let b_only: Vec<String> = vec!["B".to_string()];
    assert!(
        lsss.get_reconstruction_constants(&b_only, q).is_none(),
        "{{B}} alone should NOT satisfy (A AND B) OR C"
    );
}
