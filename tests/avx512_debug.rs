//! Simple AVX-512 identity test using only public APIs
use pabs_crf::mlwe::Polynomial;

#[test]
fn test_identity_n256() {
    let q = 8380417u32;
    let n = 256usize;

    let mut coeffs_a = vec![0i32; n];
    coeffs_a[0] = 1;
    coeffs_a[1] = 1;

    let mut coeffs_one = vec![0i32; n];
    coeffs_one[0] = 1;

    let poly_a = Polynomial::from_coeffs(&coeffs_a, q);
    let poly_one = Polynomial::from_coeffs(&coeffs_one, q);

    let result = poly_a.mul(&poly_one, q);

    println!("A = {:?}", &poly_a.coeffs[0..5]);
    println!("A*1 = {:?}", &result.coeffs[0..5]);
    println!("AVX-512 available: {}", Polynomial::avx512_available());

    assert_eq!(
        &result.coeffs[0..5],
        &[1, 1, 0, 0, 0],
        "A * 1 should equal A"
    );
}
