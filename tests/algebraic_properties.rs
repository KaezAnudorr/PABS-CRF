//! Algebraic properties tests for polynomial and NTT operations
//!
//! These tests verify the mathematical correctness of polynomial arithmetic
//! and NTT/INTT implementations.

use pabs_crf::mlwe::Polynomial;
use rand::thread_rng;

fn naive_mul(a: &Polynomial, b: &Polynomial, q: u32) -> Polynomial {
    let n = a.coeffs.len();
    assert_eq!(n, b.coeffs.len(), "polynomial lengths must match");

    let mut result = vec![0i64; n];
    for i in 0..n {
        for j in 0..n {
            let prod = a.coeffs[i] as i64 * b.coeffs[j] as i64;
            let idx = i + j;
            if idx < n {
                result[idx] += prod;
            } else {
                result[idx - n] -= prod;
            }
        }
    }

    Polynomial::from_coeffs(&result.iter().map(|&c| c as i32).collect::<Vec<_>>(), q)
}

/// Helper: generate random polynomial with coefficients in [-eta, eta]
fn rand_poly(n: usize, eta: u32) -> Polynomial {
    let mut rng = thread_rng();
    Polynomial::rand_poly(n, eta as i32, &mut rng)
}

/// Test polynomial addition is commutative: a + b = b + a
#[test]
fn test_polynomial_addition_commutative() {
    let q = 8380417u32;
    let n = 256usize;

    for _ in 0..10 {
        let a = rand_poly(n, 1000);
        let b = rand_poly(n, 1000);

        let a_plus_b = a.add(&b, q);
        let b_plus_a = b.add(&a, q);

        assert_eq!(
            a_plus_b.coeffs, b_plus_a.coeffs,
            "Polynomial addition should be commutative"
        );
    }
}

/// Test polynomial addition is associative: (a + b) + c = a + (b + c)
#[test]
fn test_polynomial_addition_associative() {
    let q = 8380417u32;
    let n = 256usize;

    for _ in 0..10 {
        let a = rand_poly(n, 1000);
        let b = rand_poly(n, 1000);
        let c = rand_poly(n, 1000);

        let lhs = a.add(&b, q).add(&c, q);
        let rhs = a.add(&b.add(&c, q), q);

        assert_eq!(
            lhs.coeffs, rhs.coeffs,
            "Polynomial addition should be associative"
        );
    }
}

/// Test polynomial multiplication distributes over addition: a * (b + c) = a * b + a * c
#[test]
fn test_polynomial_multiplication_distributive() {
    let q = 8380417u32;
    let n = 64usize; // Use smaller n for efficiency

    for _ in 0..5 {
        let a = rand_poly(n, 100);
        let b = rand_poly(n, 100);
        let c = rand_poly(n, 100);

        // a * (b + c)
        let b_plus_c = b.add(&c, q);
        let lhs = a.mul(&b_plus_c, q);

        // a * b + a * c
        let a_times_b = a.mul(&b, q);
        let a_times_c = a.mul(&c, q);
        let rhs = a_times_b.add(&a_times_c, q);

        assert_eq!(
            lhs.coeffs, rhs.coeffs,
            "Polynomial multiplication should distribute over addition"
        );
    }
}

/// Test NTT round-trip using multiplication identity property.
/// Since NTT is an internal implementation detail, we verify correctness
/// indirectly by checking that multiplication through NTT preserves expected properties.
#[test]
fn test_ntt_intt_roundtrip() {
    let q = 8380417u32;

    // For each supported size, verify NTT multiplication correctness
    for &n in &[64usize, 128, 256] {
        for _ in 0..5 {
            let a = rand_poly(n, 100);
            let b = rand_poly(n, 100);

            // Multiply using NTT-optimized path
            let c = a.mul(&b, q);

            // Verify against naive reference implementation
            let c_naive = naive_mul(&a, &b, q);

            assert_eq!(
                c.coeffs, c_naive.coeffs,
                "NTT multiplication should match naive reference for n={}",
                n
            );
        }
    }
}

/// Test polynomial multiplication against a naive negacyclic reference.
#[test]
fn test_polynomial_multiplication_matches_reference() {
    let q = 8380417u32;
    let n = 64usize;

    for _ in 0..10 {
        let a = rand_poly(n, 100);
        let b = rand_poly(n, 100);

        let fast = a.mul(&b, q);
        let ref_mul = naive_mul(&a, &b, q);

        assert_eq!(
            fast.coeffs, ref_mul.coeffs,
            "mul() should match reference implementation"
        );
    }
}

/// Test multiplication by zero is zero for several sizes.
#[test]
fn test_polynomial_multiplication_by_zero() {
    let q = 8380417u32;

    for &n in &[64usize, 128, 256] {
        let a = rand_poly(n, 1000);
        let zero = Polynomial::from_coeffs(&vec![0i32; n], q);

        let result = a.mul(&zero, q);
        assert!(
            result.coeffs.iter().all(|&c| c == 0),
            "a * 0 should be zero for n={}",
            n
        );
    }
}

/// Test known product: (1+x)(1-x) = 1-x^2 in Z_q[X]/(X^n+1)
#[test]
fn test_known_product() {
    let q = 8380417u32;
    let n = 256usize;

    // A = 1 + x
    let mut a_coeffs = vec![0i32; n];
    a_coeffs[0] = 1;
    a_coeffs[1] = 1;
    let a = Polynomial::from_coeffs(&a_coeffs, q);

    // B = 1 - x = 1 + (q-1)x
    let mut b_coeffs = vec![0i32; n];
    b_coeffs[0] = 1;
    b_coeffs[1] = (q - 1) as i32;
    let b = Polynomial::from_coeffs(&b_coeffs, q);

    let result = a.mul(&b, q);

    // Expected: 1 - x^2 = 1 + 0x + (q-1)x^2 + 0x^3 + ...
    assert_eq!(result.coeffs[0], 1, "Coefficient x^0 should be 1");
    assert_eq!(result.coeffs[1], 0, "Coefficient x^1 should be 0");
    assert_eq!(
        result.coeffs[2],
        (q - 1) as i32,
        "Coefficient x^2 should be q-1"
    );

    // All other coefficients should be 0
    for i in 3..n {
        assert_eq!(result.coeffs[i], 0, "Coefficient x^{} should be 0", i);
    }
}

/// Test parameter sanity for the supported NTT configuration.
#[test]
fn test_parameter_sanity() {
    let q = 8380417u32;
    let eta = 2u32;

    for &n in &[64usize, 128, 256] {
        assert!(q > n as u32, "q should be larger than n");
        assert!(n.is_power_of_two(), "n should be a power of two");
        assert!(eta >= 1 && eta <= 10, "eta should be in a reasonable range");
    }
}

/// Test zero polynomial properties: a + 0 = a, a * 0 = 0
#[test]
fn test_polynomial_zero_element() {
    let q = 8380417u32;
    let n = 256usize;

    let a = rand_poly(n, 1000);
    let zero = Polynomial::from_coeffs(&vec![0i32; n], q);

    // a + 0 = a (compare modulo q)
    let a_plus_zero = a.add(&zero, q);
    for i in 0..n {
        let a_normalized = ((a.coeffs[i] % q as i32) + q as i32) % q as i32;
        assert_eq!(
            a_plus_zero.coeffs[i], a_normalized,
            "a + 0 should equal a (mod q) at index {}",
            i
        );
    }

    // a * 0 = 0
    let a_times_zero = a.mul(&zero, q);
    for i in 0..n {
        assert_eq!(a_times_zero.coeffs[i], 0, "a * 0 should be zero polynomial");
    }
}

/// Test identity element: a * 1 = a
#[test]
fn test_polynomial_identity_element() {
    let q = 8380417u32;
    let n = 256usize;

    let a = rand_poly(n, 100);

    // Identity polynomial: 1 + 0x + 0x^2 + ...
    let mut one_coeffs = vec![0i32; n];
    one_coeffs[0] = 1;
    let one = Polynomial::from_coeffs(&one_coeffs, q);

    // a * 1 should equal a (modulo X^n+1, compare mod q)
    let a_times_one = a.mul(&one, q);

    for i in 0..n {
        let a_normalized = ((a.coeffs[i] % q as i32) + q as i32) % q as i32;
        assert_eq!(
            a_times_one.coeffs[i], a_normalized,
            "a * 1 should equal a (mod q) at index {}",
            i
        );
    }
}
