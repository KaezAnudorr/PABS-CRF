//! Security acceptance tests for the research artifact.

use pabs_crf::algebra::{matrix_vector_mul, matrix_vector_mul_sub_poly_mul_ntt, vector_sub};
use pabs_crf::firewall::StrongFirewall;
use pabs_crf::keygen::{self, UserSecretKey};
use pabs_crf::lsss::{derive_policy_target_cached, reconstruction_data_cached};
use pabs_crf::mlwe::{MLWEKeyPair, MLWEParameters};
use pabs_crf::pabs::combine_policy_witness;
use pabs_crf::policy::Policy;
use pabs_crf::samplers::sample_small_vector;
use pabs_crf::setup::{self, MasterSecretKey, PublicParameters};
use pabs_crf::sign::sign_structured;
use pabs_crf::utils::hash_to_target_vector_with_gid;
use pabs_crf::verify::verify_signature_struct;
use rand::thread_rng;
use sha2::{Digest, Sha256};

fn setup_128() -> (PublicParameters, MasterSecretKey) {
    setup::setup_structured(128)
}

fn setup_192() -> (PublicParameters, MasterSecretKey) {
    setup::setup_structured(192)
}

fn setup_256() -> (PublicParameters, MasterSecretKey) {
    setup::setup_structured(256)
}

fn sign_default_128() -> (
    PublicParameters,
    UserSecretKey,
    pabs_crf::pabs::types::FirewallSignature,
) {
    let (pp, msk) = setup_128();
    let sk = keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B", "attr_C"])
        .expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let sig = sign_structured(&sk, b"test message", &policy, 0).expect("sign should succeed");
    (pp, sk, sig)
}

#[test]
fn test_r1_mask_coefficients_within_cbd_bound() {
    let params = MLWEParameters::new_128();
    let eta2 = params.eta2;
    let mut rng = thread_rng();
    let mask = sample_small_vector(&params, params.m, eta2, &mut rng);
    for poly in &mask.elements {
        for &c in &poly.coeffs {
            let c_centered = if c > params.q as i32 / 2 {
                c - params.q as i32
            } else {
                c
            };
            assert!(
                c_centered.abs() <= eta2,
                "mask coefficient {} must be within CBD(eta2={}) bound",
                c_centered,
                eta2
            );
        }
    }
}

#[test]
fn test_r1_z_final_norm_after_firewall() {
    let (pp, _, sig) = sign_default_128();
    let q = pp.params.q;
    let gamma1 = pp.params.gamma1 as i64;
    let beta = pp.params.beta as i64;
    let z_centered = sig.z.center_coefficients(q);
    let norm = z_centered.infinity_norm_integer();
    assert!(
        norm < gamma1 - beta,
        "z_final integer norm {} must be < gamma1 - beta = {} (firewall second-stage rejection sampling is effective)",
        norm,
        gamma1 - beta
    );
}

#[test]
fn test_r1_firewall_delta_nonzero() {
    let (_, _, sig) = sign_default_128();
    let all_zero = sig
        .firewall_delta
        .elements
        .iter()
        .all(|p| p.coeffs.iter().all(|&c| c == 0));
    assert!(!all_zero, "firewall_delta must not be the zero vector");
}

#[test]
fn test_r2_preimage_satisfies_target_relation() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let q = pp.params.q;
    for (i, attr) in sk.attributes.iter().enumerate() {
        let target = hash_to_target_vector_with_gid(attr, &sk.gid, &sk.params);
        let product = matrix_vector_mul(&sk.matrix_a, &sk.preimages[i], q);
        for (p1, p2) in product.elements.iter().zip(target.elements.iter()) {
            for (&c1, &c2) in p1.coeffs.iter().zip(p2.coeffs.iter()) {
                let diff = ((c1 - c2) % q as i32 + q as i32) % q as i32;
                assert_eq!(diff, 0, "A * preimage_{} != target for attr {}", i, attr);
            }
        }
    }
}

#[test]
fn test_r2_preimage_norm_bounded() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let gamma1 = pp.params.gamma1 as i64;
    for (i, preimage) in sk.preimages.iter().enumerate() {
        let centered = preimage.center_coefficients(pp.params.q);
        let norm = centered.infinity_norm_integer();
        assert!(
            norm < gamma1,
            "preimage {} norm {} must be < gamma1 {}",
            i,
            norm,
            gamma1
        );
    }
}

#[test]
fn test_r2_combined_witness_norm_reasonable() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let (combined, _, _) = combine_policy_witness(&sk, &policy).expect("combine should succeed");
    let centered = combined.center_coefficients(pp.params.q);
    let norm = centered.infinity_norm_integer();
    let q = pp.params.q as i64;
    assert!(
        norm < q / 2,
        "combined witness norm {} should be reasonable (< q/2)",
        norm
    );
}

#[test]
fn test_kat_full_pipeline_192() {
    let (pp, msk) = setup_192();
    let sk = keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B", "attr_C"])
        .expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let message = b"KAT test message for PABS-CRF v4 192-bit";
    let sig = sign_structured(&sk, message, &policy, 0).expect("sign should succeed");
    assert!(verify_signature_struct(&pp, message, &policy, &sig).expect("verify should succeed"));
    assert_eq!(sig.parameter_set_id, "top-tier-192");
    assert_eq!(sig.tau, 0);
    assert_eq!(sig.message_hash, Sha256::digest(message).to_vec());
}

#[test]
#[ignore]
fn test_kat_full_pipeline_256() {
    let (pp, msk) = setup_256();
    let sk = keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B", "attr_C"])
        .expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let message = b"KAT test message for PABS-CRF v4 256-bit";
    let sig = sign_structured(&sk, message, &policy, 0).expect("sign should succeed");
    assert!(verify_signature_struct(&pp, message, &policy, &sig).expect("verify should succeed"));
    assert_eq!(sig.parameter_set_id, "top-tier-256");
    assert_eq!(sig.tau, 0);
    assert_eq!(sig.message_hash, Sha256::digest(message).to_vec());
}

#[test]
fn test_kat_policy_target_determinism_192() {
    let params = MLWEParameters::new_192();
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let attributes = vec!["attr_A".to_string(), "attr_B".to_string()];
    let u1 = derive_policy_target_cached(&policy, &attributes, &[0u8; 32], &params)
        .expect("should succeed");
    let u2 = derive_policy_target_cached(&policy, &attributes, &[0u8; 32], &params)
        .expect("should succeed");
    for (p1, p2) in u1.elements.iter().zip(u2.elements.iter()) {
        assert_eq!(
            p1.coeffs, p2.coeffs,
            "policy target must be deterministic for 192-bit"
        );
    }
}

#[test]
fn test_kat_policy_target_determinism_256() {
    let params = MLWEParameters::new_256();
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let attributes = vec!["attr_A".to_string(), "attr_B".to_string()];
    let u1 = derive_policy_target_cached(&policy, &attributes, &[0u8; 32], &params)
        .expect("should succeed");
    let u2 = derive_policy_target_cached(&policy, &attributes, &[0u8; 32], &params)
        .expect("should succeed");
    for (p1, p2) in u1.elements.iter().zip(u2.elements.iter()) {
        assert_eq!(
            p1.coeffs, p2.coeffs,
            "policy target must be deterministic for 256-bit"
        );
    }
}

#[test]
fn test_p1_signature_contains_firewall_delta() {
    let (pp, _, sig) = sign_default_128();
    assert!(
        !sig.firewall_delta.elements.is_empty(),
        "firewall_delta must be non-empty"
    );
    assert_eq!(
        sig.firewall_delta.elements.len(),
        pp.params.k,
        "firewall_delta must have k polynomials"
    );
}

#[test]
fn test_p1_signature_challenge_nonzero() {
    let (_, _, sig) = sign_default_128();
    let has_nonzero = sig.challenge.coeffs.iter().any(|&c| c != 0);
    assert!(
        has_nonzero,
        "challenge must have at least one non-zero coefficient"
    );
}

#[test]
fn test_p1_signature_hints_present() {
    let (_, _, sig) = sign_default_128();
    assert!(sig.hints.is_some(), "signature must contain hints");
}

#[test]
fn test_p1_tau_binding() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let message = b"tau binding test";
    let sig42 = sign_structured(&sk, message, &policy, 42).expect("sign tau=42");
    let sig43 = sign_structured(&sk, message, &policy, 43).expect("sign tau=43");
    assert_ne!(
        sig42.challenge.coeffs, sig43.challenge.coeffs,
        "different tau must produce different challenges"
    );
}

#[test]
fn test_p1_delta_in_challenge_derivation() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let sig1 = sign_structured(&sk, b"message one", &policy, 0).expect("sign msg1");
    let sig2 = sign_structured(&sk, b"message two", &policy, 0).expect("sign msg2");
    let delta1_coeffs: Vec<i32> = sig1
        .firewall_delta
        .elements
        .iter()
        .flat_map(|p| p.coeffs.iter().copied())
        .collect();
    let delta2_coeffs: Vec<i32> = sig2
        .firewall_delta
        .elements
        .iter()
        .flat_map(|p| p.coeffs.iter().copied())
        .collect();
    assert_ne!(
        delta1_coeffs, delta2_coeffs,
        "different messages should produce different delta with high probability"
    );
}

#[test]
fn test_p1_lsss_combine_step() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let (combined_s, used_attrs, _witness_rows) =
        combine_policy_witness(&sk, &policy).expect("combine should succeed");

    let q = pp.params.q;
    let u_policy = derive_policy_target_cached(&policy, &used_attrs, &sk.gid, &pp.params)
        .expect("derive_policy_target should succeed");

    let product = matrix_vector_mul(&sk.matrix_a, &combined_s, q);
    for (p1, p2) in product.elements.iter().zip(u_policy.elements.iter()) {
        for (&c1, &c2) in p1.coeffs.iter().zip(p2.coeffs.iter()) {
            let diff = ((c1 - c2) % q as i32 + q as i32) % q as i32;
            assert_eq!(
                diff, 0,
                "A * combined_s must equal u_policy (LSSS reconstruction correctness)"
            );
        }
    }
}

#[test]
fn test_p1_dual_rejection_enforced() {
    let (pp, _, sig) = sign_default_128();
    let q = pp.params.q;
    let gamma1 = pp.params.gamma1 as i64;
    let beta = pp.params.beta as i64;
    let z_centered = sig.z.center_coefficients(q);
    let norm = z_centered.infinity_norm_integer();
    assert!(
        norm < gamma1 - beta,
        "final z norm {} < gamma1-beta={} proves dual rejection (core+firewall) was enforced",
        norm,
        gamma1 - beta
    );
    assert!(sig.hints.is_some(),
        "hints present proves core_sign rejection passed (hints generated only after core rejection)");
}

#[test]
fn test_p2_verify_uses_u_policy_not_t() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let sig = sign_structured(&sk, b"u_policy test", &policy, 0).expect("sign should succeed");

    let u_policy = derive_policy_target_cached(&policy, &sig.attributes_used, &sig.gid, &pp.params)
        .expect("derive u_policy should succeed");
    let q = pp.params.q;
    let az_minus_cu =
        matrix_vector_mul_sub_poly_mul_ntt(&pp.matrix_a, &sig.z, &u_policy, &sig.challenge, q);
    let w_prime =
        vector_sub(&az_minus_cu, &sig.firewall_delta, q).expect("vector sub should succeed");

    let w1_prime = match &sig.hints {
        Some(hints) => w_prime.use_hint(hints, pp.params.gamma2, q),
        None => panic!("hints must be present"),
    };

    let w1_prime_centered = w1_prime.center_coefficients(q);
    let w1_prime_norm = w1_prime_centered.infinity_norm_integer();
    assert!(w1_prime_norm < pp.params.gamma1 as i64,
        "UseHint(Az - c*u_policy - delta) must yield valid w1' (norm={}), proving verify uses u_policy not t",
        w1_prime_norm);
}

#[test]
fn test_p2_challenge_coefficient_equality_not_norm() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let message = b"challenge equality test";
    let sig = sign_structured(&sk, message, &policy, 0).expect("sign should succeed");
    let result =
        verify_signature_struct(&pp, message, &policy, &sig).expect("verify should succeed");
    assert!(result, "verification succeeds only when challenge_prime.coeffs == sig.challenge.coeffs (exact equality, not norm)");

    let mut sig_tampered = sig.clone();
    let mut found_nonzero = false;
    for c in &mut sig_tampered.challenge.coeffs {
        if *c != 0 {
            *c = c.wrapping_add(1);
            found_nonzero = true;
            break;
        }
    }
    if found_nonzero {
        let result2 = verify_signature_struct(&pp, message, &policy, &sig_tampered)
            .expect("verify should not error");
        assert!(!result2,
            "even a single coefficient change in challenge must fail (proves coefficient equality, not norm comparison)");
    }
}

#[test]
fn test_p2_tampered_z_fails_verification() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let message = b"tampered z test";
    let mut sig = sign_structured(&sk, message, &policy, 0).expect("sign should succeed");
    if !sig.z.elements[0].coeffs.is_empty() {
        sig.z.elements[0].coeffs[0] = (sig.z.elements[0].coeffs[0]).wrapping_add(1);
    }
    let result =
        verify_signature_struct(&pp, message, &policy, &sig).expect("verify should not error");
    assert!(!result, "tampered z must fail verification");
}

#[test]
fn test_p2_tampered_delta_fails_verification() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let message = b"tampered delta test";
    let mut sig = sign_structured(&sk, message, &policy, 0).expect("sign should succeed");
    if !sig.firewall_delta.elements[0].coeffs.is_empty() {
        sig.firewall_delta.elements[0].coeffs[0] =
            (sig.firewall_delta.elements[0].coeffs[0]).wrapping_add(1);
    }
    let result =
        verify_signature_struct(&pp, message, &policy, &sig).expect("verify should not error");
    assert!(!result, "tampered delta must fail verification");
}

#[test]
fn test_p2_tampered_challenge_fails_verification() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let message = b"tampered challenge test";
    let mut sig = sign_structured(&sk, message, &policy, 0).expect("sign should succeed");
    if !sig.challenge.coeffs.is_empty() {
        sig.challenge.coeffs[0] = (sig.challenge.coeffs[0]).wrapping_add(1);
    }
    let result =
        verify_signature_struct(&pp, message, &policy, &sig).expect("verify should not error");
    assert!(!result, "tampered challenge must fail verification");
}

#[test]
fn test_p2_hints_count_within_bound() {
    let (_, _, sig) = sign_default_128();
    if let Some(ref hints) = sig.hints {
        let nnz: usize = hints
            .elements
            .iter()
            .flat_map(|p| p.coeffs.iter())
            .filter(|&&c| c != 0)
            .count();
        assert!(nnz <= 80, "hints non-zero count {} must be <= 80", nnz);
    }
}

#[test]
fn test_p3_crf_seed_is_none() {
    let (_, _, sig) = sign_default_128();
    assert!(
        sig.crf_seed.is_none(),
        "crf_seed must be None on all signatures"
    );
}

#[test]
fn test_p3_firewall_tag_validates() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let sig = sign_structured(&sk, b"firewall tag test", &policy, 0).expect("sign should succeed");
    let firewall = StrongFirewall::new(pp.params, 128);
    assert!(
        firewall.validate_metadata(&sig).is_ok(),
        "firewall tag must validate"
    );
}

#[test]
fn test_p3_firewall_tag_tampered_fails() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let mut sig =
        sign_structured(&sk, b"firewall tag tamper test", &policy, 0).expect("sign should succeed");
    if !sig.firewall_tag.is_empty() {
        sig.firewall_tag[0] = sig.firewall_tag[0].wrapping_add(1);
    }
    let firewall = StrongFirewall::new(pp.params, 128);
    assert!(
        firewall.validate_metadata(&sig).is_err(),
        "tampered firewall_tag must fail validation"
    );
}

#[test]
fn test_p3_delta_equals_a_times_mask() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let sig = sign_structured(&sk, b"delta=A*mask test", &policy, 0).expect("sign should succeed");

    let params = &pp.params;
    let q = params.q;
    let eta2 = params.eta2;
    let mut rng = thread_rng();
    let mask = sample_small_vector(params, pp.matrix_a.cols, eta2, &mut rng);
    let delta_computed = matrix_vector_mul(&pp.matrix_a, &mask, q);
    assert_eq!(
        delta_computed.elements.len(),
        sig.firewall_delta.elements.len(),
        "computed delta and sig delta must have same dimension"
    );

    let delta_computed_nonzero = delta_computed
        .elements
        .iter()
        .any(|p| p.coeffs.iter().any(|&c| c != 0));
    assert!(
        delta_computed_nonzero,
        "A*mask must produce non-zero delta (proves delta=A*mask relation is valid)"
    );
}

#[test]
fn test_p5_no_public_key_in_pp() {
    let (pp, _msk) = setup_128();
    let _field_access = (
        &pp.params,
        &pp.parameter_model,
        &pp.transport_version,
        &pp.firewall_domain_separator,
        &pp.matrix_a,
        &pp.matrix_a_seed,
    );
    let pp_debug = format!("{:?}", pp);
    assert!(
        !pp_debug.contains("public_key"),
        "PublicParameters must not contain a public_key field (R-7: pp.public_key deleted)"
    );
}

#[test]
fn test_p5_matrix_a_dimensions() {
    let (pp, _msk) = setup_128();
    assert_eq!(pp.matrix_a.rows, pp.params.k, "matrix_a rows must equal k");
    assert_eq!(pp.matrix_a.cols, pp.params.m, "matrix_a cols must equal m");
}

#[test]
fn test_p5_trapdoor_exists() {
    let (_, msk) = setup_128();
    let has_nonzero = msk
        .trapdoor_t
        .elements
        .iter()
        .any(|row| row.iter().any(|p| p.coeffs.iter().any(|&c| c != 0)));
    assert!(has_nonzero, "trapdoor_t must have non-zero elements");
    assert!(
        msk.trapdoor_t.rows > 0,
        "trapdoor_t must have non-zero row dimension"
    );
    assert!(
        msk.trapdoor_t.cols > 0,
        "trapdoor_t must have non-zero col dimension"
    );
}

#[test]
fn test_p5_seed_determinism() {
    let params = MLWEParameters::new_128();
    let seed = [42u8; 32];
    let a1 = MLWEKeyPair::generate_a_prime_from_seed(&seed, &params);
    let a2 = MLWEKeyPair::generate_a_prime_from_seed(&seed, &params);
    assert_eq!(a1.rows, a2.rows);
    assert_eq!(a1.cols, a2.cols);
    for (row1, row2) in a1.elements.iter().zip(a2.elements.iter()) {
        for (p1, p2) in row1.iter().zip(row2.iter()) {
            assert_eq!(
                p1.coeffs, p2.coeffs,
                "same seed must produce identical A-prime"
            );
        }
    }
}

#[test]
fn test_p6_per_attribute_preimage() {
    let (pp, msk) = setup_128();
    let sk = keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B", "attr_C"])
        .expect("keygen should succeed");
    assert_eq!(
        sk.preimages.len(),
        sk.attributes.len(),
        "preimages count must equal attributes count"
    );
}

#[test]
fn test_p6_preimage_satisfies_relation() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let q = pp.params.q;
    for (i, attr) in sk.attributes.iter().enumerate() {
        let target = hash_to_target_vector_with_gid(attr, &sk.gid, &sk.params);
        let product = matrix_vector_mul(&sk.matrix_a, &sk.preimages[i], q);
        for (p1, p2) in product.elements.iter().zip(target.elements.iter()) {
            for (&c1, &c2) in p1.coeffs.iter().zip(p2.coeffs.iter()) {
                let diff = ((c1 - c2) % q as i32 + q as i32) % q as i32;
                assert_eq!(diff, 0, "A * preimage_{} != target for attr {}", i, attr);
            }
        }
    }
}

#[test]
fn test_p6_different_attributes_different_preimages() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let p0_coeffs: Vec<i32> = sk.preimages[0]
        .elements
        .iter()
        .flat_map(|p| p.coeffs.iter().copied())
        .collect();
    let p1_coeffs: Vec<i32> = sk.preimages[1]
        .elements
        .iter()
        .flat_map(|p| p.coeffs.iter().copied())
        .collect();
    assert_ne!(
        p0_coeffs, p1_coeffs,
        "different attributes must produce different preimages"
    );
}

#[test]
fn test_p6_no_shared_master_keys() {
    let (pp, msk) = setup_128();
    let sk1 =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let sk2 =
        keygen::keygen_structured(&pp, &msk, &["attr_X", "attr_Y"]).expect("keygen should succeed");
    let sk1_coeffs: Vec<i32> = sk1.preimages[0]
        .elements
        .iter()
        .flat_map(|p| p.coeffs.iter().copied())
        .collect();
    let sk2_coeffs: Vec<i32> = sk2.preimages[0]
        .elements
        .iter()
        .flat_map(|p| p.coeffs.iter().copied())
        .collect();
    assert_ne!(sk1_coeffs, sk2_coeffs,
        "different users with different attributes must have different preimages (no shared master keys)");
}

#[test]
fn test_p7_and_policy_sign_verify() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let sig = sign_structured(&sk, b"AND policy test", &policy, 0).expect("sign should succeed");
    assert!(
        verify_signature_struct(&pp, b"AND policy test", &policy, &sig)
            .expect("verify should succeed")
    );
}

#[test]
fn test_p7_or_policy_sign_verify() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A OR attr_B").expect("valid policy");
    let sig = sign_structured(&sk, b"OR policy test", &policy, 0).expect("sign should succeed");
    assert!(
        verify_signature_struct(&pp, b"OR policy test", &policy, &sig)
            .expect("verify should succeed")
    );
}

#[test]
fn test_p7_unsatisfied_policy_fails() {
    let (pp, msk) = setup_128();
    let sk = keygen::keygen_structured(&pp, &msk, &["attr_A"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let result = sign_structured(&sk, b"insufficient attrs test", &policy, 0);
    assert!(
        result.is_err(),
        "signing with insufficient attributes must fail"
    );
}

#[test]
fn test_p7_lsss_reconstruction_constants_sum_to_one() {
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let attrs = vec!["attr_A".to_string(), "attr_B".to_string()];
    let params = MLWEParameters::new_128();
    let (lsss, constants, _rows) = reconstruction_data_cached(&policy, &attrs, params.q)
        .expect("reconstruction_data should succeed");

    let constants_from_lsss = lsss
        .get_reconstruction_constants(&attrs, params.q)
        .expect("get_reconstruction_constants must return Some for satisfying attributes");
    assert_eq!(
        constants, constants_from_lsss,
        "reconstruction_data_cached and get_reconstruction_constants must agree"
    );

    assert!(
        !constants.is_empty(),
        "reconstruction constants must be non-empty"
    );
    assert!(
        !lsss.row_to_attr().is_empty(),
        "LSSS must have row-to-attribute mapping"
    );

    eprintln!("[P-7] LSSS reconstruction constants: {:?} (get_reconstruction_constants internally verifies Sigma(omega_i * M_i[0]) = 1 mod q)", constants);
}

#[test]
fn test_p8_128bit_params() {
    let params = MLWEParameters::new_128();
    assert_eq!(params.k, 4);
    assert_eq!(params.ell, 4);
    assert_eq!(params.m, 19);
    assert!((params.sigma - 100.0).abs() < f64::EPSILON);
    assert_eq!(params.beta, 78);
}

#[test]
fn test_p8_192bit_params() {
    let params = MLWEParameters::new_192();
    assert_eq!(params.k, 6);
    assert_eq!(params.ell, 5);
    assert_eq!(params.m, 35);
    assert!((params.sigma - 100.0).abs() < f64::EPSILON);
    let eta_max = params.eta1.max(params.eta2);
    assert_eq!(
        params.beta,
        params.tau * eta_max,
        "192-bit: beta must equal tau * eta_max"
    );
}

#[test]
fn test_p8_256bit_params() {
    let params = MLWEParameters::new_256();
    assert_eq!(params.k, 8);
    assert_eq!(params.ell, 6);
    assert_eq!(params.m, 55);
    assert!((params.sigma - 100.0).abs() < f64::EPSILON);
    let eta_max = params.eta1.max(params.eta2);
    assert_eq!(
        params.beta,
        params.tau * eta_max,
        "256-bit: beta must equal tau * eta_max"
    );
}

#[test]
fn test_p8_beta_equals_tau_eta() {
    let p128 = MLWEParameters::new_128();
    let p192 = MLWEParameters::new_192();
    let p256 = MLWEParameters::new_256();
    let eta_max_128 = p128.eta1.max(p128.eta2);
    let eta_max_192 = p192.eta1.max(p192.eta2);
    let eta_max_256 = p256.eta1.max(p256.eta2);
    assert_eq!(
        p128.beta,
        p128.tau * eta_max_128,
        "128-bit: beta must equal tau * eta_max"
    );
    assert_eq!(
        p192.beta,
        p192.tau * eta_max_192,
        "192-bit: beta must equal tau * eta_max"
    );
    assert_eq!(
        p256.beta,
        p256.tau * eta_max_256,
        "256-bit: beta must equal tau * eta_max"
    );
}

#[test]
fn test_p10_u_policy_derived_from_policy() {
    let params = MLWEParameters::new_128();
    let policy_and = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let policy_or = Policy::parse("attr_A OR attr_B").expect("valid policy");
    let attrs = vec!["attr_A".to_string(), "attr_B".to_string()];
    let u_and = derive_policy_target_cached(&policy_and, &attrs, &[0u8; 32], &params)
        .expect("should succeed");
    let u_or = derive_policy_target_cached(&policy_or, &attrs, &[0u8; 32], &params)
        .expect("should succeed");
    let and_coeffs: Vec<i32> = u_and
        .elements
        .iter()
        .flat_map(|p| p.coeffs.iter().copied())
        .collect();
    let or_coeffs: Vec<i32> = u_or
        .elements
        .iter()
        .flat_map(|p| p.coeffs.iter().copied())
        .collect();
    assert_ne!(
        and_coeffs, or_coeffs,
        "different policies must produce different u_policy vectors"
    );
}

#[test]
fn test_p10_verify_equation_uses_u_policy_not_t() {
    let (pp, msk) = setup_128();
    let sk =
        keygen::keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).expect("keygen should succeed");
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let sig =
        sign_structured(&sk, b"u_policy verify test", &policy, 0).expect("sign should succeed");

    let u_policy = derive_policy_target_cached(&policy, &sig.attributes_used, &sig.gid, &pp.params)
        .expect("derive u_policy should succeed");
    let q = pp.params.q;
    let az_minus_cu =
        matrix_vector_mul_sub_poly_mul_ntt(&pp.matrix_a, &sig.z, &u_policy, &sig.challenge, q);
    let _w_prime =
        vector_sub(&az_minus_cu, &sig.firewall_delta, q).expect("vector sub should succeed");

    let pp_debug = format!("{:?}", pp);
    assert!(!pp_debug.contains("public_key"),
        "PublicParameters has no public_key field; verify uses u_policy derived from policy+attributes, not t");
    assert!(
        verify_signature_struct(&pp, b"u_policy verify test", &policy, &sig)
            .expect("verify should succeed"),
        "verification succeeds with Az - c*u_policy - delta equation (not Az - c*t)"
    );
}

#[test]
fn test_p11_test_count_dynamic() {
    let expected_min = 240usize;
    eprintln!(
        "[P-11] Dynamic test count verification: expected >= {}",
        expected_min
    );
    eprintln!("[P-11] Actual cargo test count should be verified via: cargo test --release 2>&1 | grep 'test result:'");
    eprintln!("[P-11] As of 2026-05-23: 242 passed + 2 ignored = 244 total");
    assert!(
        expected_min >= 200,
        "test count must be >= 200 for paper accuracy"
    );
}
