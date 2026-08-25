//! KAT (Known Answer Test) vector tests for the PABS-CRF scheme.
//!
//! These tests verify deterministic behavior of core cryptographic components
//! and the correctness of the full signing pipeline. Where possible, fixed
//! seeds are used so that the same inputs always produce the same outputs.

use pabs_crf::keygen;
use pabs_crf::lsss::derive_policy_target_cached;
use pabs_crf::mlwe::{MLWEKeyPair, MLWEParameters};
use pabs_crf::policy::Policy;
use pabs_crf::setup;
use pabs_crf::sign::sign_structured;
use pabs_crf::utils::hash_to_target_vector_with_gid;
use pabs_crf::verify::verify_signature_struct;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

fn build_full_a_from_seed(
    seed: &[u8; 32],
    params: &MLWEParameters,
) -> (
    pabs_crf::mlwe::PolynomialMatrix,
    pabs_crf::mlwe::PolynomialMatrix,
) {
    let a_prime = MLWEKeyPair::generate_a_prime_from_seed(seed, params);
    let mut sub_seed = [0u8; 32];
    sub_seed.copy_from_slice(&Sha256::digest([&seed[..], b"-trapdoor"].concat()));
    let mut sub_rng = StdRng::from_seed(sub_seed);
    let strict = pabs_crf::trapdoor::strict::StrictTrapdoor::new(params);
    strict.generate_with_a_prime(a_prime, &mut sub_rng).unwrap()
}

#[test]
fn test_kat_matrix_a_from_seed_determinism() {
    let params = MLWEParameters::new_128();
    let seed = [0xAB; 32];

    let a1 = MLWEKeyPair::generate_matrix_a_from_seed(&seed, &params);
    let a2 = MLWEKeyPair::generate_matrix_a_from_seed(&seed, &params);

    assert_eq!(a1.rows, a2.rows, "row count mismatch");
    assert_eq!(a1.cols, a2.cols, "col count mismatch");
    for (row1, row2) in a1.elements.iter().zip(a2.elements.iter()) {
        for (p1, p2) in row1.iter().zip(row2.iter()) {
            assert_eq!(
                p1.coeffs, p2.coeffs,
                "generate_matrix_a_from_seed not deterministic"
            );
        }
    }

    let different_seed = [0xCD; 32];
    let a3 = MLWEKeyPair::generate_matrix_a_from_seed(&different_seed, &params);
    let mut any_diff = false;
    for (row1, row2) in a1.elements.iter().zip(a3.elements.iter()) {
        for (p1, p2) in row1.iter().zip(row2.iter()) {
            if p1.coeffs != p2.coeffs {
                any_diff = true;
                break;
            }
        }
        if any_diff {
            break;
        }
    }
    assert!(any_diff, "different seeds must produce different matrices");
}

#[test]
fn test_kat_a_prime_from_seed_determinism() {
    let params = MLWEParameters::new_128();
    let seed = [0x42; 32];

    let a_prime_1 = MLWEKeyPair::generate_a_prime_from_seed(&seed, &params);
    let a_prime_2 = MLWEKeyPair::generate_a_prime_from_seed(&seed, &params);

    assert_eq!(a_prime_1.rows, a_prime_2.rows);
    assert_eq!(a_prime_1.cols, a_prime_2.cols);
    for (row1, row2) in a_prime_1.elements.iter().zip(a_prime_2.elements.iter()) {
        for (p1, p2) in row1.iter().zip(row2.iter()) {
            assert_eq!(
                p1.coeffs, p2.coeffs,
                "generate_a_prime_from_seed not deterministic"
            );
        }
    }

    assert_eq!(
        a_prime_1.rows, params.k,
        "A-prime row count should be k={}",
        params.k
    );
    assert_eq!(
        a_prime_1.cols,
        params.k - 1,
        "A-prime col count should be k-1={}",
        params.k - 1
    );
}

#[test]
fn test_kat_full_a_matrix_from_seed_determinism() {
    let params = MLWEParameters::new_128();
    let seed = [0x99; 32];

    let (a1, t1) = build_full_a_from_seed(&seed, &params);
    let (a2, t2) = build_full_a_from_seed(&seed, &params);

    assert_eq!(a1.rows, a2.rows);
    assert_eq!(a1.cols, a2.cols);
    for (row1, row2) in a1.elements.iter().zip(a2.elements.iter()) {
        for (p1, p2) in row1.iter().zip(row2.iter()) {
            assert_eq!(
                p1.coeffs, p2.coeffs,
                "full A matrix not deterministic for fixed seed"
            );
        }
    }

    for (row1, row2) in t1.elements.iter().zip(t2.elements.iter()) {
        for (p1, p2) in row1.iter().zip(row2.iter()) {
            assert_eq!(
                p1.coeffs, p2.coeffs,
                "trapdoor T not deterministic for fixed seed"
            );
        }
    }

    assert_eq!(a1.rows, params.k);
    assert_eq!(a1.cols, params.m);
}

#[test]
fn test_kat_policy_target_determinism() {
    let params = MLWEParameters::new_128();
    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let attributes = vec!["attr_A".to_string(), "attr_B".to_string()];

    let u_policy_1 = derive_policy_target_cached(&policy, &attributes, &[0u8; 32], &params)
        .expect("derive_policy_target_cached should succeed");
    let u_policy_2 = derive_policy_target_cached(&policy, &attributes, &[0u8; 32], &params)
        .expect("derive_policy_target_cached should succeed");

    assert_eq!(u_policy_1.elements.len(), u_policy_2.elements.len());
    for (p1, p2) in u_policy_1.elements.iter().zip(u_policy_2.elements.iter()) {
        assert_eq!(
            p1.coeffs, p2.coeffs,
            "derive_policy_target_cached not deterministic"
        );
    }

    let policy_or = Policy::parse("attr_A OR attr_C").expect("valid policy");
    let attrs_or = vec!["attr_A".to_string(), "attr_C".to_string()];
    let u_or = derive_policy_target_cached(&policy_or, &attrs_or, &[0u8; 32], &params)
        .expect("derive_policy_target_cached should succeed for OR policy");
    assert_ne!(
        u_policy_1.elements[0].coeffs, u_or.elements[0].coeffs,
        "different policies must yield different targets"
    );
}

#[test]
fn test_kat_full_pipeline_128() {
    let (pp, msk) = setup::setup_structured(128);

    let attributes = &["attr_A", "attr_B", "attr_C"];
    let sk =
        keygen::keygen_structured(&pp, &msk, attributes).expect("keygen_structured should succeed");

    assert_eq!(sk.attributes.len(), 3);
    assert_eq!(sk.attributes[0], "attr_A");
    assert_eq!(sk.attributes[1], "attr_B");
    assert_eq!(sk.attributes[2], "attr_C");
    assert_eq!(sk.matrix_a.rows, pp.matrix_a.rows);
    assert_eq!(sk.matrix_a.cols, pp.matrix_a.cols);

    let policy = Policy::parse("attr_A AND attr_B").expect("valid policy");
    let message = b"KAT test message for PABS-CRF v4";
    let tau: u64 = 0;

    let sig = sign_structured(&sk, message, &policy, tau).expect("sign_structured should succeed");

    assert!(
        verify_signature_struct(&pp, message, &policy, &sig)
            .expect("verify_signature_struct should succeed"),
        "signature verification must succeed"
    );

    assert_eq!(sig.tau, tau);
    assert_eq!(sig.parameter_set_id, "top-tier-128");
    assert_eq!(sig.policy, policy);
    assert_eq!(sig.message_hash, Sha256::digest(message).to_vec());

    let wrong_msg = b"wrong message";
    assert!(
        !verify_signature_struct(&pp, wrong_msg, &policy, &sig)
            .expect("verify should not error on wrong message"),
        "wrong message must fail verification"
    );

    let wrong_policy = Policy::parse("attr_B AND attr_C").expect("valid policy");
    assert!(
        !verify_signature_struct(&pp, message, &wrong_policy, &sig)
            .expect("verify should not error on wrong policy"),
        "wrong policy must fail verification"
    );
}

#[test]
fn test_kat_full_pipeline_128_variant_b() {
    let (pp, msk) = setup::setup_structured(128);

    let attributes = &["dept_hr", "dept_eng", "clearance_3"];
    let sk =
        keygen::keygen_structured(&pp, &msk, attributes).expect("keygen_structured should succeed");

    assert_eq!(sk.attributes.len(), 3);
    assert_eq!(sk.attributes[0], "dept_hr");
    assert_eq!(sk.attributes[1], "dept_eng");
    assert_eq!(sk.attributes[2], "clearance_3");
    assert_eq!(sk.matrix_a.rows, pp.matrix_a.rows);
    assert_eq!(sk.matrix_a.cols, pp.matrix_a.cols);
    assert_eq!(sk.gid.len(), 32);

    let policy = Policy::parse("dept_hr OR dept_eng").expect("valid policy");
    let message = b"KAT test message for PABS-CRF v4 128-bit variant B";
    let tau: u64 = 0;

    let sig = sign_structured(&sk, message, &policy, tau).expect("sign_structured should succeed");

    assert!(
        verify_signature_struct(&pp, message, &policy, &sig)
            .expect("verify_signature_struct should succeed"),
        "signature verification must succeed"
    );

    assert_eq!(sig.tau, tau);
    assert_eq!(sig.parameter_set_id, "top-tier-128");
    assert_eq!(sig.policy, policy);
    assert_eq!(sig.message_hash, Sha256::digest(message).to_vec());

    let wrong_msg = b"wrong message";
    assert!(
        !verify_signature_struct(&pp, wrong_msg, &policy, &sig)
            .expect("verify should not error on wrong message"),
        "wrong message must fail verification"
    );

    let wrong_policy = Policy::parse("dept_hr AND dept_eng").expect("valid policy");
    assert!(
        !verify_signature_struct(&pp, message, &wrong_policy, &sig)
            .expect("verify should not error on wrong policy"),
        "wrong policy must fail verification"
    );
}

#[test]
fn test_kat_full_pipeline_192() {
    let (pp, msk) = setup::setup_structured(192);

    let attributes = &["role_manager", "dept_finance"];
    let sk =
        keygen::keygen_structured(&pp, &msk, attributes).expect("keygen_structured should succeed");

    assert_eq!(sk.attributes.len(), 2);
    assert_eq!(sk.attributes[0], "role_manager");
    assert_eq!(sk.attributes[1], "dept_finance");
    assert_eq!(sk.matrix_a.rows, pp.matrix_a.rows);
    assert_eq!(sk.matrix_a.cols, pp.matrix_a.cols);
    assert_eq!(sk.gid.len(), 32);

    let policy = Policy::parse("role_manager AND dept_finance").expect("valid policy");
    let message = b"KAT test message for PABS-CRF v4 192-bit";
    let tau: u64 = 0;

    let sig = sign_structured(&sk, message, &policy, tau).expect("sign_structured should succeed");

    assert!(
        verify_signature_struct(&pp, message, &policy, &sig)
            .expect("verify_signature_struct should succeed"),
        "signature verification must succeed"
    );

    assert_eq!(sig.tau, tau);
    assert_eq!(sig.parameter_set_id, "top-tier-192");
    assert_eq!(sig.policy, policy);
    assert_eq!(sig.message_hash, Sha256::digest(message).to_vec());

    let wrong_msg = b"wrong message";
    assert!(
        !verify_signature_struct(&pp, wrong_msg, &policy, &sig)
            .expect("verify should not error on wrong message"),
        "wrong message must fail verification"
    );

    let wrong_policy = Policy::parse("role_manager OR dept_finance").expect("valid policy");
    assert!(
        !verify_signature_struct(&pp, message, &wrong_policy, &sig)
            .expect("verify should not error on wrong policy"),
        "wrong policy must fail verification"
    );
}

#[test]
fn test_kat_policy_target_determinism_192() {
    let params = MLWEParameters::new_192();
    let policy = Policy::parse("role_manager AND dept_finance").expect("valid policy");
    let attributes = vec!["role_manager".to_string(), "dept_finance".to_string()];

    let u_policy_1 = derive_policy_target_cached(&policy, &attributes, &[0u8; 32], &params)
        .expect("derive_policy_target_cached should succeed");
    let u_policy_2 = derive_policy_target_cached(&policy, &attributes, &[0u8; 32], &params)
        .expect("derive_policy_target_cached should succeed");

    assert_eq!(u_policy_1.elements.len(), u_policy_2.elements.len());
    for (p1, p2) in u_policy_1.elements.iter().zip(u_policy_2.elements.iter()) {
        assert_eq!(
            p1.coeffs, p2.coeffs,
            "derive_policy_target_cached not deterministic at 192-bit"
        );
    }

    let policy_or = Policy::parse("role_manager OR dept_finance").expect("valid policy");
    let u_or = derive_policy_target_cached(&policy_or, &attributes, &[0u8; 32], &params)
        .expect("derive_policy_target_cached should succeed for OR policy");
    assert_ne!(
        u_policy_1.elements[0].coeffs, u_or.elements[0].coeffs,
        "different policies must yield different targets at 192-bit"
    );
}

#[test]
#[ignore]
fn test_kat_full_pipeline_256() {
    let (pp, msk) = setup::setup_structured(256);

    let attributes = &["level5", "compartment_alpha"];
    let sk =
        keygen::keygen_structured(&pp, &msk, attributes).expect("keygen_structured should succeed");

    assert_eq!(sk.attributes.len(), 2);
    assert_eq!(sk.attributes[0], "level5");
    assert_eq!(sk.attributes[1], "compartment_alpha");
    assert_eq!(sk.matrix_a.rows, pp.matrix_a.rows);
    assert_eq!(sk.matrix_a.cols, pp.matrix_a.cols);
    assert_eq!(sk.gid.len(), 32);

    let policy = Policy::parse("level5 AND compartment_alpha").expect("valid policy");
    let message = b"KAT test message for PABS-CRF v4 256-bit";
    let tau: u64 = 0;

    let sig = sign_structured(&sk, message, &policy, tau).expect("sign_structured should succeed");

    assert!(
        verify_signature_struct(&pp, message, &policy, &sig)
            .expect("verify_signature_struct should succeed"),
        "signature verification must succeed"
    );

    assert_eq!(sig.tau, tau);
    assert_eq!(sig.parameter_set_id, "top-tier-256");
    assert_eq!(sig.policy, policy);
    assert_eq!(sig.message_hash, Sha256::digest(message).to_vec());

    let wrong_msg = b"wrong message";
    assert!(
        !verify_signature_struct(&pp, wrong_msg, &policy, &sig)
            .expect("verify should not error on wrong message"),
        "wrong message must fail verification"
    );

    let wrong_policy = Policy::parse("level5 OR compartment_alpha").expect("valid policy");
    assert!(
        !verify_signature_struct(&pp, message, &wrong_policy, &sig)
            .expect("verify should not error on wrong policy"),
        "wrong policy must fail verification"
    );
}

#[test]
fn test_kat_policy_target_determinism_256() {
    let params = MLWEParameters::new_256();
    let policy = Policy::parse("level5 AND compartment_alpha").expect("valid policy");
    let attributes = vec!["level5".to_string(), "compartment_alpha".to_string()];

    let u_policy_1 = derive_policy_target_cached(&policy, &attributes, &[0u8; 32], &params)
        .expect("derive_policy_target_cached should succeed");
    let u_policy_2 = derive_policy_target_cached(&policy, &attributes, &[0u8; 32], &params)
        .expect("derive_policy_target_cached should succeed");

    assert_eq!(u_policy_1.elements.len(), u_policy_2.elements.len());
    for (p1, p2) in u_policy_1.elements.iter().zip(u_policy_2.elements.iter()) {
        assert_eq!(
            p1.coeffs, p2.coeffs,
            "derive_policy_target_cached not deterministic at 256-bit"
        );
    }

    let policy_or = Policy::parse("level5 OR compartment_alpha").expect("valid policy");
    let u_or = derive_policy_target_cached(&policy_or, &attributes, &[0u8; 32], &params)
        .expect("derive_policy_target_cached should succeed for OR policy");
    assert_ne!(
        u_policy_1.elements[0].coeffs, u_or.elements[0].coeffs,
        "different policies must yield different targets at 256-bit"
    );
}

#[test]
fn test_kat_full_pipeline_128_variant_c() {
    let (pp, msk) = setup::setup_structured(128);

    let attributes = &["attr_X", "attr_Y", "attr_Z", "attr_W"];
    let sk =
        keygen::keygen_structured(&pp, &msk, attributes).expect("keygen_structured should succeed");

    assert_eq!(sk.attributes.len(), 4);
    assert_eq!(sk.attributes[0], "attr_X");
    assert_eq!(sk.attributes[1], "attr_Y");
    assert_eq!(sk.attributes[2], "attr_Z");
    assert_eq!(sk.attributes[3], "attr_W");
    assert_eq!(sk.matrix_a.rows, pp.matrix_a.rows);
    assert_eq!(sk.matrix_a.cols, pp.matrix_a.cols);
    assert_eq!(sk.gid.len(), 32);

    let policy = Policy::parse("attr_X AND attr_Y OR attr_Z").expect("valid policy");
    let message = b"KAT test message for PABS-CRF v4 128-bit variant C";
    let tau: u64 = 0;

    let sig = sign_structured(&sk, message, &policy, tau).expect("sign_structured should succeed");

    assert!(
        verify_signature_struct(&pp, message, &policy, &sig)
            .expect("verify_signature_struct should succeed"),
        "signature verification must succeed"
    );

    assert_eq!(sig.tau, tau);
    assert_eq!(sig.parameter_set_id, "top-tier-128");
    assert_eq!(sig.policy, policy);
    assert_eq!(sig.message_hash, Sha256::digest(message).to_vec());

    let wrong_msg = b"wrong message";
    assert!(
        !verify_signature_struct(&pp, wrong_msg, &policy, &sig)
            .expect("verify should not error on wrong message"),
        "wrong message must fail verification"
    );

    let wrong_policy = Policy::parse("attr_X AND attr_W").expect("valid policy");
    assert!(
        !verify_signature_struct(&pp, message, &wrong_policy, &sig)
            .expect("verify should not error on wrong policy"),
        "wrong policy must fail verification"
    );
}

#[test]
fn test_kat_full_pipeline_192_variant_b() {
    let (pp, msk) = setup::setup_structured(192);

    let attributes = &["role_admin", "dept_hr", "clearance_2"];
    let sk =
        keygen::keygen_structured(&pp, &msk, attributes).expect("keygen_structured should succeed");

    assert_eq!(sk.attributes.len(), 3);
    assert_eq!(sk.attributes[0], "role_admin");
    assert_eq!(sk.attributes[1], "dept_hr");
    assert_eq!(sk.attributes[2], "clearance_2");
    assert_eq!(sk.matrix_a.rows, pp.matrix_a.rows);
    assert_eq!(sk.matrix_a.cols, pp.matrix_a.cols);
    assert_eq!(sk.gid.len(), 32);

    let policy = Policy::parse("role_admin OR dept_hr").expect("valid policy");
    let message = b"KAT test message for PABS-CRF v4 192-bit variant B";
    let tau: u64 = 0;

    let sig = sign_structured(&sk, message, &policy, tau).expect("sign_structured should succeed");

    assert!(
        verify_signature_struct(&pp, message, &policy, &sig)
            .expect("verify_signature_struct should succeed"),
        "signature verification must succeed"
    );

    assert_eq!(sig.tau, tau);
    assert_eq!(sig.parameter_set_id, "top-tier-192");
    assert_eq!(sig.policy, policy);
    assert_eq!(sig.message_hash, Sha256::digest(message).to_vec());

    let wrong_msg = b"wrong message";
    assert!(
        !verify_signature_struct(&pp, wrong_msg, &policy, &sig)
            .expect("verify should not error on wrong message"),
        "wrong message must fail verification"
    );

    let wrong_policy = Policy::parse("role_admin AND dept_hr").expect("valid policy");
    assert!(
        !verify_signature_struct(&pp, message, &wrong_policy, &sig)
            .expect("verify should not error on wrong policy"),
        "wrong policy must fail verification"
    );
}

#[test]
fn test_kat_full_pipeline_192_variant_c() {
    let (pp, msk) = setup::setup_structured(192);

    let attributes = &["role_admin", "dept_finance", "clearance_2", "region_eu"];
    let sk =
        keygen::keygen_structured(&pp, &msk, attributes).expect("keygen_structured should succeed");

    assert_eq!(sk.attributes.len(), 4);
    assert_eq!(sk.attributes[0], "role_admin");
    assert_eq!(sk.attributes[1], "dept_finance");
    assert_eq!(sk.attributes[2], "clearance_2");
    assert_eq!(sk.attributes[3], "region_eu");
    assert_eq!(sk.matrix_a.rows, pp.matrix_a.rows);
    assert_eq!(sk.matrix_a.cols, pp.matrix_a.cols);
    assert_eq!(sk.gid.len(), 32);

    let policy =
        Policy::parse("role_admin AND dept_finance AND clearance_2").expect("valid policy");
    let message = b"KAT test message for PABS-CRF v4 192-bit variant C";
    let tau: u64 = 0;

    let sig = sign_structured(&sk, message, &policy, tau).expect("sign_structured should succeed");

    assert!(
        verify_signature_struct(&pp, message, &policy, &sig)
            .expect("verify_signature_struct should succeed"),
        "signature verification must succeed"
    );

    assert_eq!(sig.tau, tau);
    assert_eq!(sig.parameter_set_id, "top-tier-192");
    assert_eq!(sig.policy, policy);
    assert_eq!(sig.message_hash, Sha256::digest(message).to_vec());

    let wrong_msg = b"wrong message";
    assert!(
        !verify_signature_struct(&pp, wrong_msg, &policy, &sig)
            .expect("verify should not error on wrong message"),
        "wrong message must fail verification"
    );

    let wrong_policy = Policy::parse("role_admin OR dept_finance").expect("valid policy");
    assert!(
        !verify_signature_struct(&pp, message, &wrong_policy, &sig)
            .expect("verify should not error on wrong policy"),
        "wrong policy must fail verification"
    );
}

#[test]
#[ignore]
fn test_kat_full_pipeline_256_variant_b() {
    let (pp, msk) = setup::setup_structured(256);

    let attributes = &["level5", "compartment_alpha", "sector_beta"];
    let sk =
        keygen::keygen_structured(&pp, &msk, attributes).expect("keygen_structured should succeed");

    assert_eq!(sk.attributes.len(), 3);
    assert_eq!(sk.attributes[0], "level5");
    assert_eq!(sk.attributes[1], "compartment_alpha");
    assert_eq!(sk.attributes[2], "sector_beta");
    assert_eq!(sk.matrix_a.rows, pp.matrix_a.rows);
    assert_eq!(sk.matrix_a.cols, pp.matrix_a.cols);
    assert_eq!(sk.gid.len(), 32);

    let policy = Policy::parse("level5 OR compartment_alpha").expect("valid policy");
    let message = b"KAT test message for PABS-CRF v4 256-bit variant B";
    let tau: u64 = 0;

    let sig = sign_structured(&sk, message, &policy, tau).expect("sign_structured should succeed");

    assert!(
        verify_signature_struct(&pp, message, &policy, &sig)
            .expect("verify_signature_struct should succeed"),
        "signature verification must succeed"
    );

    assert_eq!(sig.tau, tau);
    assert_eq!(sig.parameter_set_id, "top-tier-256");
    assert_eq!(sig.policy, policy);
    assert_eq!(sig.message_hash, Sha256::digest(message).to_vec());

    let wrong_msg = b"wrong message";
    assert!(
        !verify_signature_struct(&pp, wrong_msg, &policy, &sig)
            .expect("verify should not error on wrong message"),
        "wrong message must fail verification"
    );

    let wrong_policy = Policy::parse("level5 AND compartment_alpha").expect("valid policy");
    assert!(
        !verify_signature_struct(&pp, message, &wrong_policy, &sig)
            .expect("verify should not error on wrong policy"),
        "wrong policy must fail verification"
    );
}

#[test]
#[ignore]
fn test_kat_full_pipeline_256_variant_c() {
    let (pp, msk) = setup::setup_structured(256);

    let attributes = &[
        "level5",
        "compartment_alpha",
        "sector_gamma",
        "domain_delta",
    ];
    let sk =
        keygen::keygen_structured(&pp, &msk, attributes).expect("keygen_structured should succeed");

    assert_eq!(sk.attributes.len(), 4);
    assert_eq!(sk.attributes[0], "level5");
    assert_eq!(sk.attributes[1], "compartment_alpha");
    assert_eq!(sk.attributes[2], "sector_gamma");
    assert_eq!(sk.attributes[3], "domain_delta");
    assert_eq!(sk.matrix_a.rows, pp.matrix_a.rows);
    assert_eq!(sk.matrix_a.cols, pp.matrix_a.cols);
    assert_eq!(sk.gid.len(), 32);

    let policy =
        Policy::parse("level5 AND compartment_alpha AND sector_gamma").expect("valid policy");
    let message = b"KAT test message for PABS-CRF v4 256-bit variant C";
    let tau: u64 = 0;

    let sig = sign_structured(&sk, message, &policy, tau).expect("sign_structured should succeed");

    assert!(
        verify_signature_struct(&pp, message, &policy, &sig)
            .expect("verify_signature_struct should succeed"),
        "signature verification must succeed"
    );

    assert_eq!(sig.tau, tau);
    assert_eq!(sig.parameter_set_id, "top-tier-256");
    assert_eq!(sig.policy, policy);
    assert_eq!(sig.message_hash, Sha256::digest(message).to_vec());

    let wrong_msg = b"wrong message";
    assert!(
        !verify_signature_struct(&pp, wrong_msg, &policy, &sig)
            .expect("verify should not error on wrong message"),
        "wrong message must fail verification"
    );

    let wrong_policy = Policy::parse("level5 OR compartment_alpha").expect("valid policy");
    assert!(
        !verify_signature_struct(&pp, message, &wrong_policy, &sig)
            .expect("verify should not error on wrong policy"),
        "wrong policy must fail verification"
    );
}

#[test]
fn test_kat_gid_binding_determinism() {
    let params_128 = MLWEParameters::new_128();
    let gid_a = [0xAA; 32];
    let gid_b = [0xBB; 32];

    let v1_a = hash_to_target_vector_with_gid("attr_X", &gid_a, &params_128);
    let v1_a_again = hash_to_target_vector_with_gid("attr_X", &gid_a, &params_128);
    for (p1, p2) in v1_a.elements.iter().zip(v1_a_again.elements.iter()) {
        assert_eq!(
            p1.coeffs, p2.coeffs,
            "same (attribute, GID) must produce identical target vector"
        );
    }

    let v1_b = hash_to_target_vector_with_gid("attr_X", &gid_b, &params_128);
    let mut any_diff = false;
    for (p1, p2) in v1_a.elements.iter().zip(v1_b.elements.iter()) {
        if p1.coeffs != p2.coeffs {
            any_diff = true;
            break;
        }
    }
    assert!(
        any_diff,
        "different GID must produce different target vector for same attribute"
    );

    let params_192 = MLWEParameters::new_192();
    let v2_a = hash_to_target_vector_with_gid("role_admin", &gid_a, &params_192);
    let v2_a_again = hash_to_target_vector_with_gid("role_admin", &gid_a, &params_192);
    for (p1, p2) in v2_a.elements.iter().zip(v2_a_again.elements.iter()) {
        assert_eq!(
            p1.coeffs, p2.coeffs,
            "same (attribute, GID) must produce identical target vector at 192-bit"
        );
    }

    let v2_b = hash_to_target_vector_with_gid("role_admin", &gid_b, &params_192);
    let mut any_diff_192 = false;
    for (p1, p2) in v2_a.elements.iter().zip(v2_b.elements.iter()) {
        if p1.coeffs != p2.coeffs {
            any_diff_192 = true;
            break;
        }
    }
    assert!(
        any_diff_192,
        "different GID must produce different target vector at 192-bit"
    );
}
