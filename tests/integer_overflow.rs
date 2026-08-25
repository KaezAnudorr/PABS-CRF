use pabs_crf::mlwe::{Polynomial, PolynomialVector};
use std::panic;

fn make_poly_with_coeffs(coeffs: Vec<i32>) -> Polynomial {
    Polynomial { coeffs }
}

#[test]
fn test_add_integer_max_plus_one_panics() {
    let a = make_poly_with_coeffs(vec![i32::MAX, i32::MAX, 0]);
    let b = make_poly_with_coeffs(vec![1, 0, 0]);

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        a.add_integer(&b);
    }));

    assert!(result.is_err(), "add_integer should panic on i32::MAX + 1");
    let err = result.unwrap_err();
    let msg = err
        .downcast_ref::<String>()
        .map(|s| s.clone())
        .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    assert!(
        msg.contains("coefficient overflow"),
        "Panic message should contain 'coefficient overflow', got: {}",
        msg
    );
}

#[test]
fn test_add_integer_both_max_panics() {
    let a = make_poly_with_coeffs(vec![i32::MAX]);
    let b = make_poly_with_coeffs(vec![i32::MAX]);

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        a.add_integer(&b);
    }));

    assert!(result.is_err(), "add_integer should panic on MAX + MAX");
}

#[test]
fn test_add_integer_negative_overflow_panics() {
    let a = make_poly_with_coeffs(vec![i32::MIN, i32::MIN]);
    let b = make_poly_with_coeffs(vec![-1, 0]);

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        a.add_integer(&b);
    }));

    assert!(
        result.is_err(),
        "add_integer should panic on i32::MIN + (-1)"
    );
}

#[test]
fn test_add_integer_within_range_succeeds() {
    let a = make_poly_with_coeffs(vec![100, -200, i32::MAX]);
    let b = make_poly_with_coeffs(vec![-50, 200, 0]);

    let result = a.add_integer(&b);
    assert_eq!(result.coeffs, vec![50, 0, i32::MAX]);
}

#[test]
fn test_sub_integer_max_minus_min_panics() {
    let a = make_poly_with_coeffs(vec![i32::MAX]);
    let b = make_poly_with_coeffs(vec![i32::MIN]);

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        a.sub_integer(&b);
    }));

    assert!(
        result.is_err(),
        "sub_integer should panic on MAX - MIN (overflow)"
    );
}

#[test]
fn test_sub_integer_min_minus_max_panics() {
    let a = make_poly_with_coeffs(vec![i32::MIN]);
    let b = make_poly_with_coeffs(vec![i32::MAX]);

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        a.sub_integer(&b);
    }));

    assert!(
        result.is_err(),
        "sub_integer should panic on MIN - MAX (overflow)"
    );
}

#[test]
fn test_sub_integer_within_range_works() {
    let a = make_poly_with_coeffs(vec![100, -50]);
    let b = make_poly_with_coeffs(vec![200, -100]);

    let result = a.sub_integer(&b);
    assert_eq!(result.coeffs, vec![-100, 50]);
}

#[test]
fn test_mul_challenge_integer_large_coeff_panics() {
    let large = make_poly_with_coeffs(vec![i32::MAX, i32::MAX, i32::MAX, i32::MAX]);
    let challenge = make_poly_with_coeffs(vec![1, -1, 0, 0]);

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        large.mul_challenge_integer(&challenge);
    }));

    assert!(
        result.is_err(),
        "mul_challenge_integer should panic on overflow"
    );
}

#[test]
fn test_mul_challenge_integer_many_nonzero_entries() {
    let coeffs: Vec<i32> = vec![1000; 8];
    let poly = make_poly_with_coeffs(coeffs.clone());
    let challenge = make_poly_with_coeffs(vec![1, 1, 1, 1, -1, -1, -1, -1]);

    let result = poly.mul_challenge_integer(&challenge);
    assert_eq!(result.coeffs.len(), 8, "output length must match");
    assert!(
        result.coeffs.iter().any(|&c| c != 0),
        "non-trivial challenge must produce non-zero output"
    );
}

#[test]
fn test_mul_challenge_integer_zero_challenge() {
    let a = make_poly_with_coeffs(vec![i32::MAX, i32::MIN, 42]);
    let zero_challenge = make_poly_with_coeffs(vec![0, 0, 0]);

    let result = a.mul_challenge_integer(&zero_challenge);
    assert_eq!(result.coeffs, vec![0, 0, 0]);
}

#[test]
fn test_add_integer_vector_overflow_panics() {
    let a = PolynomialVector {
        elements: vec![make_poly_with_coeffs(vec![i32::MAX])],
    };
    let b = PolynomialVector {
        elements: vec![make_poly_with_coeffs(vec![1])],
    };

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        pabs_crf::algebra::vector_add_integer(&a, &b).unwrap();
    }));

    assert!(
        result.is_err(),
        "vector_add_integer should propagate overflow panic"
    );
}

#[test]
fn test_add_integer_single_max_one_panics() {
    let a = make_poly_with_coeffs(vec![i32::MAX]);
    let b = make_poly_with_coeffs(vec![1]);

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        a.add_integer(&b);
    }));

    assert!(result.is_err());
    let err = result.unwrap_err();
    let msg = if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else {
        String::new()
    };
    assert!(
        msg.contains("coefficient overflow"),
        "Expected overflow panic message, got: {}",
        msg
    );
}
