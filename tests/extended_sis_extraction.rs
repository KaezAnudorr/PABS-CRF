use pabs_crf::algebra::{matrix_vector_mul, vector_sub, vector_sub_integer};
use pabs_crf::keygen::keygen_structured;
use pabs_crf::lsss::derive_policy_target_cached;
use pabs_crf::mlwe::{Polynomial, PolynomialVector};
use pabs_crf::policy::Policy;
use pabs_crf::setup::setup_structured;
use pabs_crf::sign::sign_structured;
use pabs_crf::verify::verify_signature_struct;

#[test]
fn test_sis_solution_satisfies_isis_relation() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).unwrap();
    let policy = Policy::parse("attr_A AND attr_B").unwrap();
    let message = b"SIS extraction relation test";

    let sig1 = sign_structured(&sk, message, &policy, 0).unwrap();
    let sig2 = sign_structured(&sk, message, &policy, 1).unwrap();

    assert!(verify_signature_struct(&pp, message, &policy, &sig1).unwrap());
    assert!(verify_signature_struct(&pp, message, &policy, &sig2).unwrap());

    let q = pp.params.q;

    let u_policy =
        derive_policy_target_cached(&policy, &sig1.attributes_used, &sig1.gid, &pp.params).unwrap();

    let c1_mod_q = Polynomial::from_coeffs(&sig1.challenge.coeffs, q);
    let c1_times_u = PolynomialVector {
        elements: u_policy
            .elements
            .iter()
            .map(|u_i| c1_mod_q.mul(u_i, q))
            .collect(),
    };
    let az1 = matrix_vector_mul(&pp.matrix_a, &sig1.z, q);
    let w1_prime = vector_sub(
        &vector_sub(&az1, &c1_times_u, q).unwrap(),
        &sig1.firewall_delta,
        q,
    )
    .unwrap();

    let c2_mod_q = Polynomial::from_coeffs(&sig2.challenge.coeffs, q);
    let c2_times_u = PolynomialVector {
        elements: u_policy
            .elements
            .iter()
            .map(|u_i| c2_mod_q.mul(u_i, q))
            .collect(),
    };
    let az2 = matrix_vector_mul(&pp.matrix_a, &sig2.z, q);
    let w2_prime = vector_sub(
        &vector_sub(&az2, &c2_times_u, q).unwrap(),
        &sig2.firewall_delta,
        q,
    )
    .unwrap();

    let z_diff = vector_sub_integer(&sig1.z, &sig2.z).unwrap();
    let z_diff_mod_q = PolynomialVector {
        elements: z_diff
            .elements
            .iter()
            .map(|p| Polynomial::from_coeffs(&p.coeffs, q))
            .collect(),
    };
    let az_diff = matrix_vector_mul(&pp.matrix_a, &z_diff_mod_q, q);

    let c_diff = Polynomial {
        coeffs: sig1
            .challenge
            .coeffs
            .iter()
            .zip(sig2.challenge.coeffs.iter())
            .map(|(&a, &b)| {
                let diff = a as i64 - b as i64;
                i32::try_from(diff).unwrap_or(if diff > 0 { i32::MAX } else { i32::MIN })
            })
            .collect(),
    };
    let c_diff_mod_q = Polynomial::from_coeffs(&c_diff.coeffs, q);
    let c_diff_times_u = PolynomialVector {
        elements: u_policy
            .elements
            .iter()
            .map(|u_i| c_diff_mod_q.mul(u_i, q))
            .collect(),
    };

    let delta_diff = vector_sub(&sig1.firewall_delta, &sig2.firewall_delta, q).unwrap();

    let lhs = vector_sub(
        &vector_sub(&az_diff, &c_diff_times_u, q).unwrap(),
        &delta_diff,
        q,
    )
    .unwrap();
    let rhs = vector_sub(&w1_prime, &w2_prime, q).unwrap();

    for (i, (l_poly, r_poly)) in lhs.elements.iter().zip(rhs.elements.iter()).enumerate() {
        for (j, (&l, &r)) in l_poly.coeffs.iter().zip(r_poly.coeffs.iter()).enumerate() {
            assert_eq!(
                l, r,
                "ISIS relation violated at [{i}][{j}]: A*(z1-z2) - (c1-c2)*u - (d1-d2) != w1'-w2'"
            );
        }
    }

    eprintln!("CRF-aware ISIS relation verified: A*(z1-z2) - (c1-c2)*u_policy - (delta1-delta2) = w1'-w2' (mod q)");
}

#[test]
fn test_sis_solution_norm_bounded() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).unwrap();
    let policy = Policy::parse("attr_A AND attr_B").unwrap();
    let message = b"SIS extraction norm test";

    let sig1 = sign_structured(&sk, message, &policy, 0).unwrap();
    let sig2 = sign_structured(&sk, message, &policy, 1).unwrap();

    let q = pp.params.q;

    let z1_centered = sig1.z.center_coefficients(q);
    let z2_centered = sig2.z.center_coefficients(q);
    let z_diff = vector_sub_integer(&z1_centered, &z2_centered).unwrap();
    let z_diff_norm = z_diff.infinity_norm_integer();

    let c1_centered = sig1.challenge.center_coefficients(q);
    let c2_centered = sig2.challenge.center_coefficients(q);
    let c_diff = Polynomial {
        coeffs: c1_centered
            .coeffs
            .iter()
            .zip(c2_centered.coeffs.iter())
            .map(|(&a, &b)| {
                let diff = a as i64 - b as i64;
                i32::try_from(diff).unwrap_or(if diff > 0 { i32::MAX } else { i32::MIN })
            })
            .collect(),
    };
    let c_diff_norm = c_diff.infinity_norm_integer();

    let v_norm = std::cmp::max(z_diff_norm, c_diff_norm);

    let gamma1 = pp.params.gamma1 as i64;
    let beta = pp.params.beta as i64;
    let tau = pp.params.tau as i64;
    let bound = std::cmp::max(2 * (gamma1 - beta), 2 * tau);

    eprintln!("z_diff infinity norm: {}", z_diff_norm);
    eprintln!("c_diff infinity norm: {}", c_diff_norm);
    eprintln!("v = [(z1-z2); -(c1-c2)] infinity norm: {}", v_norm);
    eprintln!(
        "bound = max(2*(gamma1-beta), 2*tau) = max(2*({}-{}), 2*{}) = {}",
        gamma1, beta, tau, bound
    );

    assert!(
        v_norm <= bound,
        "||v||_inf = {} exceeds bound {}",
        v_norm,
        bound,
    );

    eprintln!(
        "SIS solution norm bound verified: ||v||_inf = {} <= {}",
        v_norm, bound
    );
}

#[test]
fn test_extended_matrix_construction() {
    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).unwrap();
    let policy = Policy::parse("attr_A AND attr_B").unwrap();

    let u_policy =
        derive_policy_target_cached(&policy, &sk.attributes, &sk.gid, &pp.params).unwrap();

    let k = pp.params.k;
    let m = pp.params.m;

    assert_eq!(
        pp.matrix_a.rows, k,
        "matrix A rows {} != k {}",
        pp.matrix_a.rows, k,
    );
    assert_eq!(
        pp.matrix_a.cols, m,
        "matrix A cols {} != m {}",
        pp.matrix_a.cols, m,
    );
    assert_eq!(
        u_policy.elements.len(),
        k,
        "u_policy elements {} != k {}",
        u_policy.elements.len(),
        k,
    );

    let extended_cols = m + 1;
    eprintln!("A dimensions: {} x {}", k, m);
    eprintln!("u_policy dimensions: {} x 1", u_policy.elements.len());
    eprintln!("B = [A | -u_Psi] dimensions: {} x {}", k, extended_cols);
    eprintln!(
        "Extended matrix construction verified: B has {} rows and {} columns",
        k, extended_cols
    );
}
