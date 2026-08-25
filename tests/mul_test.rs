//! Minimal test for polynomial multiplication
use pabs_crf::mlwe::Polynomial;

#[test]
fn test_mul_naive_identity() {
    let q = 8380417u32;
    // Use n < 64 to force naive path
    let n = 32usize;

    let mut coeffs_a = vec![0i32; n];
    coeffs_a[0] = 1;
    coeffs_a[1] = 1;

    let mut coeffs_b = vec![0i32; n];
    coeffs_b[0] = 1;
    coeffs_b[1] = q as i32 - 1; // -1 mod q

    let poly_a = Polynomial::from_coeffs(&coeffs_a, q);
    let poly_b = Polynomial::from_coeffs(&coeffs_b, q);

    let result = poly_a.mul(&poly_b, q);

    println!("Naive n=32 test:");
    println!("  A = {:?}", &poly_a.coeffs[0..4]);
    println!("  B = {:?}", &poly_b.coeffs[0..4]);
    println!("  A*B = {:?}", &result.coeffs[0..4]);
    println!("  Expected: [1, 0, q-1, 0] = [1, 0, 8380416, 0]");

    assert_eq!(result.coeffs[0], 1, "Coefficient x^0 should be 1");
    assert_eq!(result.coeffs[1], 0, "Coefficient x^1 should be 0");
    assert_eq!(
        result.coeffs[2],
        q as i32 - 1,
        "Coefficient x^2 should be -1 mod q"
    );
}

#[test]
fn test_mul_ntt_optimized() {
    let q = 8380417u32;
    let n = 256usize;

    let mut coeffs_a = vec![0i32; n];
    coeffs_a[0] = 1;
    coeffs_a[1] = 1;

    let mut coeffs_b = vec![0i32; n];
    coeffs_b[0] = 1;
    coeffs_b[1] = q as i32 - 1; // -1 mod q

    let poly_a = Polynomial::from_coeffs(&coeffs_a, q);
    let poly_b = Polynomial::from_coeffs(&coeffs_b, q);

    let result = poly_a.mul(&poly_b, q);

    println!("Optimized NTT n=256 test:");
    println!("  A = {:?}", &poly_a.coeffs[0..4]);
    println!("  B = {:?}", &poly_b.coeffs[0..4]);
    println!("  A*B = {:?}", &result.coeffs[0..4]);
    println!("  Expected: [1, 0, q-1, 0] = [1, 0, 8380416, 0]");

    // Check all coefficients
    let mut correct = 0;
    for i in 0..n {
        let expected = if i == 0 {
            1
        } else if i == 2 {
            q as i32 - 1
        } else {
            0
        };
        if result.coeffs[i] == expected {
            correct += 1;
        } else if i < 10 {
            println!(
                "  Coeff {} wrong: got {}, expected {}",
                i, result.coeffs[i], expected
            );
        }
    }
    println!("  Correct coefficients: {}/{}", correct, n);

    assert_eq!(result.coeffs[0], 1, "Coefficient x^0 should be 1");
    assert_eq!(result.coeffs[1], 0, "Coefficient x^1 should be 0");
    assert_eq!(
        result.coeffs[2],
        q as i32 - 1,
        "Coefficient x^2 should be -1 mod q"
    );
}
