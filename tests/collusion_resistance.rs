//! S-1 Anti-collusion unit tests
//!
//! Validates that the GID-bound target vector derivation prevents cross-user
//! preimage combination attacks.  When two users U1 and U2 hold disjoint
//! attribute sets, they must not be able to combine their preimages to forge
//! a valid signature under a policy that neither satisfies individually.

use pabs_crf::keygen::keygen_structured;
use pabs_crf::lsss::derive_policy_target_cached;
use pabs_crf::policy::Policy;
use pabs_crf::setup::setup_structured;
use pabs_crf::sign::sign_structured;
use pabs_crf::utils::hash_to_target_vector_with_gid;
use pabs_crf::verify::verify_signature_struct;

#[test]
fn test_collusion_and_policy_fails() {
    let (pp, msk) = setup_structured(128);
    let sk1 = keygen_structured(&pp, &msk, &["admin"]).unwrap();
    let sk2 = keygen_structured(&pp, &msk, &["finance"]).unwrap();

    let policy = Policy::parse("admin AND finance").unwrap();
    let message = b"collusion test message";

    let sig1 = sign_structured(&sk1, message, &policy, 0);
    assert!(
        sig1.is_err(),
        "U1 with only 'admin' should NOT be able to sign under 'admin AND finance'"
    );

    let sig2 = sign_structured(&sk2, message, &policy, 0);
    assert!(
        sig2.is_err(),
        "U2 with only 'finance' should NOT be able to sign under 'admin AND finance'"
    );
}

#[test]
fn test_same_user_sign_succeeds() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["admin", "finance"]).unwrap();

    let policy = Policy::parse("admin AND finance").unwrap();
    let message = b"legitimate sign test";

    let sig = sign_structured(&sk, message, &policy, 0).unwrap();
    assert!(
        verify_signature_struct(&pp, message, &policy, &sig).unwrap(),
        "User with both attributes should sign and verify successfully"
    );
}

#[test]
fn test_different_gid_different_target() {
    let params = pabs_crf::mlwe::MLWEParameters::new_128();
    let gid1 = [1u8; 32];
    let gid2 = [2u8; 32];

    let u_a_gid1 = hash_to_target_vector_with_gid("admin", &gid1, &params);
    let u_a_gid2 = hash_to_target_vector_with_gid("admin", &gid2, &params);

    let mut differ = false;
    for i in 0..u_a_gid1.elements.len() {
        for j in 0..u_a_gid1.elements[i].coeffs.len() {
            if u_a_gid1.elements[i].coeffs[j] != u_a_gid2.elements[i].coeffs[j] {
                differ = true;
                break;
            }
        }
        if differ {
            break;
        }
    }
    assert!(
        differ,
        "Same attribute with different GID must produce different target vectors"
    );

    let u_a_gid1_again = hash_to_target_vector_with_gid("admin", &gid1, &params);
    for i in 0..u_a_gid1.elements.len() {
        for j in 0..u_a_gid1.elements[i].coeffs.len() {
            assert_eq!(
                u_a_gid1.elements[i].coeffs[j], u_a_gid1_again.elements[i].coeffs[j],
                "Same attribute + same GID must be deterministic"
            );
        }
    }
}

#[test]
fn test_or_policy_independent_sign() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["admin"]).unwrap();

    let policy = Policy::parse("admin OR finance").unwrap();
    let message = b"or policy test";

    let sig = sign_structured(&sk, message, &policy, 0).unwrap();
    assert!(
        verify_signature_struct(&pp, message, &policy, &sig).unwrap(),
        "User with 'admin' should sign under 'admin OR finance'"
    );
}

#[test]
fn test_cross_user_preimage_mismatch() {
    let (pp, msk) = setup_structured(128);
    let sk1 = keygen_structured(&pp, &msk, &["admin"]).unwrap();
    let sk2 = keygen_structured(&pp, &msk, &["admin"]).unwrap();

    assert_ne!(
        sk1.gid, sk2.gid,
        "Two different keygen calls must produce different GIDs"
    );

    let u1 = derive_policy_target_cached(
        &Policy::parse("admin").unwrap(),
        &["admin".to_string()],
        &sk1.gid,
        &pp.params,
    )
    .unwrap();
    let u2 = derive_policy_target_cached(
        &Policy::parse("admin").unwrap(),
        &["admin".to_string()],
        &sk2.gid,
        &pp.params,
    )
    .unwrap();

    let mut differ = false;
    for i in 0..u1.elements.len() {
        for j in 0..u1.elements[i].coeffs.len() {
            if u1.elements[i].coeffs[j] != u2.elements[i].coeffs[j] {
                differ = true;
                break;
            }
        }
        if differ {
            break;
        }
    }
    assert!(
        differ,
        "Different GIDs must produce different policy target vectors for the same attribute"
    );
}
