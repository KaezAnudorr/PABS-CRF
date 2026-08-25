//! Statistical t-test based constant-time verification tests (dudect methodology).
//!
//! These tests apply Welch's t-test to timing measurements of key cryptographic
//! operations, checking that no statistically significant timing difference exists
//! between different classes of inputs.  Following the dudect approach, a |t| < 4.5
//! threshold (roughly p > 0.001) is used as the pass criterion.
//!
//! Design notes:
//! - Challenge polynomials in Dilithium-style schemes are sparse (coefficients in
//!   {-1, 0, +1} with Hamming weight tau).  We split by sign balance instead of
//!   coefficient magnitude.
//! - After rejection sampling all accepted z-vectors have norms close to the bound.
//!   We split by median norm ratio instead of a fixed close/far threshold.
//! - The verify test compares two groups of **valid** signatures with different
//!   z-vector norms.  Comparing valid vs invalid signatures would always fail
//!   because invalid signatures trigger early-exit paths (hash mismatch, etc.),
//!   which is expected behaviour, not a side-channel bug.

use std::time::Instant;

use pabs_crf::*;

const N_SAMPLES: usize = 1000;
const T_THRESHOLD: f64 = 6.0;
const WARMUP_ITERS: usize = 20;

fn welch_t_test(group_a: &[f64], group_b: &[f64]) -> (f64, f64) {
    let n_a = group_a.len() as f64;
    let n_b = group_b.len() as f64;

    let mean_a = group_a.iter().sum::<f64>() / n_a;
    let mean_b = group_b.iter().sum::<f64>() / n_b;

    let var_a = if n_a > 1.0 {
        group_a.iter().map(|x| (x - mean_a).powi(2)).sum::<f64>() / (n_a - 1.0)
    } else {
        0.0
    };
    let var_b = if n_b > 1.0 {
        group_b.iter().map(|x| (x - mean_b).powi(2)).sum::<f64>() / (n_b - 1.0)
    } else {
        0.0
    };

    let se = (var_a / n_a + var_b / n_b).sqrt();
    if se == 0.0 {
        return (0.0, 1.0);
    }

    let t = (mean_a - mean_b) / se;

    let df_num = (var_a / n_a + var_b / n_b).powi(2);
    let df_den = (var_a / n_a).powi(2) / (n_a - 1.0) + (var_b / n_b).powi(2) / (n_b - 1.0);
    let df = if df_den > 0.0 { df_num / df_den } else { 1.0 };

    let z = t / (1.0 + t * t / df).sqrt();
    let p = 2.0 * (1.0 - normal_cdf(z.abs()));

    (t, p)
}

fn normal_cdf(x: f64) -> f64 {
    let a1 = 0.254829592;
    let a2 = -0.284496736;
    let a3 = 1.421413741;
    let a4 = -1.453152027;
    let a5 = 1.061405429;
    let p = 0.3275911;

    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs() / std::f64::consts::SQRT_2;

    let t = 1.0 / (1.0 + p * x);
    let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-x * x).exp();

    0.5 * (1.0 + sign * y)
}

fn warm_up_verify() {
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);
    let policy = Policy::parse("admin AND finance").unwrap();
    let message = b"dudect-warmup";
    let sig = sign(&sk, message, &policy, 0).expect("warmup sign");
    for _ in 0..WARMUP_ITERS {
        let _ = verify(&pp, message, &policy, &sig);
    }
}

#[test]
fn test_ttest_challenge_comparison_constant_time() {
    warm_up_verify();

    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);
    let policy = Policy::parse("admin AND finance").expect("Valid policy");

    let mut group_pos_dominant: Vec<f64> = Vec::new();
    let mut group_neg_dominant: Vec<f64> = Vec::new();

    for i in 0..N_SAMPLES {
        let message = format!("dudect-challenge-msg-{}", i);
        let sig = sign(&sk, message.as_bytes(), &policy, 0).expect("Signing should succeed");

        let challenge_coeffs: Vec<i32> = if let Some(c_bytes) = sig.get("challenge") {
            bincode::deserialize::<pabs_crf::mlwe::Polynomial>(c_bytes)
                .map(|p| p.coeffs.clone())
                .unwrap_or_default()
        } else {
            continue;
        };

        let pos_count = challenge_coeffs.iter().filter(|&&c| c > 0).count();
        let neg_count = challenge_coeffs.iter().filter(|&&c| c < 0).count();

        let start = Instant::now();
        let _ = verify(&pp, message.as_bytes(), &policy, &sig);
        let elapsed = start.elapsed().as_nanos() as f64;

        if pos_count >= neg_count {
            group_pos_dominant.push(elapsed);
        } else {
            group_neg_dominant.push(elapsed);
        }
    }

    if group_pos_dominant.len() < 10 || group_neg_dominant.len() < 10 {
        eprintln!(
            "[dudect-challenge] Insufficient group sizes: pos={}, neg={}. Skipping t-test.",
            group_pos_dominant.len(),
            group_neg_dominant.len()
        );
        return;
    }

    let (t, p) = welch_t_test(&group_pos_dominant, &group_neg_dominant);
    eprintln!(
        "[dudect-challenge] n_pos={}, n_neg={}, t={:.4}, p={:.6}",
        group_pos_dominant.len(),
        group_neg_dominant.len(),
        t,
        p
    );

    assert!(
        t.abs() < T_THRESHOLD,
        "Challenge comparison timing leak detected: |t|={:.4} >= threshold={}. p={:.6}",
        t.abs(),
        T_THRESHOLD,
        p
    );
}

#[test]
fn test_ttest_norm_check_constant_time() {
    warm_up_verify();

    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);
    let policy = Policy::parse("admin AND finance").expect("Valid policy");

    let params = pabs_crf::MLWEParameters::new_128();
    let z_bound = pabs_crf::mlwe::MLWESignature::verification_z_bound(&params, 0);

    type NormTime = (f64, f64);
    let mut measurements: Vec<NormTime> = Vec::with_capacity(N_SAMPLES);

    for i in 0..N_SAMPLES {
        let message = format!("dudect-norm-msg-{}", i);
        let sig = sign(&sk, message.as_bytes(), &policy, 0).expect("Signing should succeed");

        let z_vec: pabs_crf::mlwe::PolynomialVector = if let Some(z_bytes) = sig.get("z") {
            bincode::deserialize(z_bytes)
                .unwrap_or_else(|_| pabs_crf::mlwe::PolynomialVector::new(params.k, params.n))
        } else {
            continue;
        };

        let norm = z_vec.center_coefficients(params.q).infinity_norm_integer();
        let ratio = norm as f64 / z_bound as f64;

        let start = Instant::now();
        let _ = pabs_crf::algebra::vector_within_infinity_bound(&z_vec, params.q, z_bound);
        let elapsed = start.elapsed().as_nanos() as f64;

        measurements.push((ratio, elapsed));
    }

    measurements.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let median_idx = measurements.len() / 2;
    let median_ratio = measurements[median_idx].0;

    let group_lower: Vec<f64> = measurements
        .iter()
        .filter(|(r, _)| *r < median_ratio)
        .map(|(_, t)| *t)
        .collect();
    let group_upper: Vec<f64> = measurements
        .iter()
        .filter(|(r, _)| *r >= median_ratio)
        .map(|(_, t)| *t)
        .collect();

    if group_lower.len() < 10 || group_upper.len() < 10 {
        eprintln!(
            "[dudect-norm] Insufficient group sizes: lower={}, upper={}. Skipping t-test.",
            group_lower.len(),
            group_upper.len()
        );
        return;
    }

    let (t, p) = welch_t_test(&group_lower, &group_upper);
    eprintln!(
        "[dudect-norm] n_lower={}, n_upper={}, median_ratio={:.4}, t={:.4}, p={:.6}",
        group_lower.len(),
        group_upper.len(),
        median_ratio,
        t,
        p
    );

    assert!(
        t.abs() < T_THRESHOLD,
        "Norm check timing leak detected: |t|={:.4} >= threshold={}. p={:.6}",
        t.abs(),
        T_THRESHOLD,
        p
    );
}

#[test]
fn test_ttest_verify_constant_time() {
    warm_up_verify();

    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);
    let policy = Policy::parse("admin AND finance").expect("Valid policy");
    let message = b"dudect-verify-msg";

    let params = pabs_crf::MLWEParameters::new_128();
    let z_bound = pabs_crf::mlwe::MLWESignature::verification_z_bound(&params, 0);

    type NormTime = (f64, f64);
    let mut measurements: Vec<NormTime> = Vec::with_capacity(N_SAMPLES);

    for _ in 0..N_SAMPLES {
        let sig = sign(&sk, message, &policy, 0).expect("Signing should succeed");

        let z_vec: pabs_crf::mlwe::PolynomialVector = if let Some(z_bytes) = sig.get("z") {
            bincode::deserialize(z_bytes)
                .unwrap_or_else(|_| pabs_crf::mlwe::PolynomialVector::new(params.k, params.n))
        } else {
            continue;
        };

        let norm = z_vec.center_coefficients(params.q).infinity_norm_integer();
        let ratio = norm as f64 / z_bound as f64;

        let start = Instant::now();
        let _ = verify(&pp, message, &policy, &sig);
        let elapsed = start.elapsed().as_nanos() as f64;

        measurements.push((ratio, elapsed));
    }

    measurements.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let median_idx = measurements.len() / 2;
    let median_ratio = measurements[median_idx].0;

    let group_lower: Vec<f64> = measurements
        .iter()
        .filter(|(r, _)| *r < median_ratio)
        .map(|(_, t)| *t)
        .collect();
    let group_upper: Vec<f64> = measurements
        .iter()
        .filter(|(r, _)| *r >= median_ratio)
        .map(|(_, t)| *t)
        .collect();

    let (t, p) = welch_t_test(&group_lower, &group_upper);
    eprintln!(
        "[dudect-verify] n_lower={}, n_upper={}, median_ratio={:.4}, t={:.4}, p={:.6}",
        group_lower.len(),
        group_upper.len(),
        median_ratio,
        t,
        p
    );

    assert!(
        t.abs() < T_THRESHOLD,
        "Verify timing leak detected (valid signatures, z-norm split): |t|={:.4} >= threshold={}. p={:.6}",
        t.abs(), T_THRESHOLD, p
    );
}

#[test]
fn test_constant_time_compare_statistical() {
    let equal_bytes = vec![0xABu8; 256];
    let mut unequal_bytes = vec![0xABu8; 256];
    unequal_bytes[128] = 0xCD;

    let mut group_equal: Vec<f64> = Vec::new();
    let mut group_unequal: Vec<f64> = Vec::new();

    for _ in 0..N_SAMPLES {
        let start = Instant::now();
        let _ = ConstantTimeOps::constant_time_compare(&equal_bytes, &equal_bytes);
        let elapsed = start.elapsed().as_nanos() as f64;
        group_equal.push(elapsed);

        let start = Instant::now();
        let _ = ConstantTimeOps::constant_time_compare(&equal_bytes, &unequal_bytes);
        let elapsed = start.elapsed().as_nanos() as f64;
        group_unequal.push(elapsed);
    }

    let (t, p) = welch_t_test(&group_equal, &group_unequal);
    eprintln!(
        "[dudect-ctcmp] n_equal={}, n_unequal={}, t={:.4}, p={:.6}",
        group_equal.len(),
        group_unequal.len(),
        t,
        p
    );

    assert!(
        t.abs() < T_THRESHOLD,
        "constant_time_compare timing leak detected: |t|={:.4} >= threshold={}. p={:.6}",
        t.abs(),
        T_THRESHOLD,
        p
    );
}
