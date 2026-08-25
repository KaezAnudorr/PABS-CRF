use pabs_crf::canonical::canonical_serialize_w1;
use pabs_crf::mlwe::{Polynomial, PolynomialVector};

fn make_w1(values: &[&[i32]]) -> PolynomialVector {
    PolynomialVector {
        elements: values
            .iter()
            .map(|&coeffs| Polynomial {
                coeffs: coeffs.to_vec(),
            })
            .collect(),
    }
}

#[test]
fn test_deterministic_serialization() {
    let w1 = make_w1(&[&[0, 1, 2, 3, 4, 5, 6, 7], &[7, 6, 5, 4, 3, 2, 1, 0]]);
    let m = 16u32;

    let a = canonical_serialize_w1(&w1, m);
    let b = canonical_serialize_w1(&w1, m);
    assert_eq!(a, b, "two calls must produce identical output");
}

#[test]
fn test_deterministic_different_vectors_differ() {
    let w1_a = make_w1(&[&[0, 0, 0, 0]]);
    let w1_b = make_w1(&[&[0, 0, 0, 1]]);
    let m = 4u32;

    let a = canonical_serialize_w1(&w1_a, m);
    let b = canonical_serialize_w1(&w1_b, m);
    assert_ne!(a, b);
}

#[test]
fn test_all_zero_w1_length() {
    let k = 4;
    let n = 256;
    let zeros: Vec<i32> = vec![0; n];
    let polys: Vec<Polynomial> = (0..k)
        .map(|_| Polynomial {
            coeffs: zeros.clone(),
        })
        .collect();
    let w1 = PolynomialVector { elements: polys };

    let m = 4u32;
    let bits_per_coeff = ((m as f64).log2().ceil() as usize).max(1);
    let expected_len = (k * n * bits_per_coeff + 7) / 8;
    let out = canonical_serialize_w1(&w1, m);
    assert_eq!(out.len(), expected_len);
    assert!(
        out.iter().all(|&b| b == 0),
        "all-zero input must produce all-zero output"
    );
}

#[test]
fn test_max_coefficient_no_panic() {
    let w1 = make_w1(&[&[15, 0, 15, 0, 8, 7, 14, 3]]);
    let m = 16u32;
    let out = canonical_serialize_w1(&w1, m);
    assert!(!out.is_empty());
}

#[test]
fn test_one_byte_boundary() {
    let w1 = make_w1(&[&[3, 3, 3, 3]]);
    let m = 4u32;
    let bits_per_coeff = ((m as f64).log2().ceil() as usize).max(1);
    let total_bits = 1 * 4 * bits_per_coeff;
    let expected_len = (total_bits + 7) / 8;
    let out = canonical_serialize_w1(&w1, m);
    assert_eq!(out.len(), expected_len);
    assert_eq!(out[0], 0b11_11_11_11);
}

#[test]
fn test_two_polynomials_bit_packing() {
    let w1 = make_w1(&[&[1, 0, 0, 0, 0, 0, 0, 0], &[0, 0, 0, 0, 0, 0, 0, 1]]);
    let m = 4u32;
    let out = canonical_serialize_w1(&w1, m);

    let first_poly = out[0];
    assert_eq!(first_poly & 0b11, 1);

    let second_poly_start = 8 * 2 / 8;
    let offset = 8 * 2 % 8;
    let byte_idx = second_poly_start + offset / 8;
    assert!(byte_idx < out.len());
}

#[test]
fn test_end_to_end_sign_verify_with_canonical_w1() {
    use pabs_crf::keygen::keygen_structured;
    use pabs_crf::policy::Policy;
    use pabs_crf::setup::setup_structured;
    use pabs_crf::sign::sign_structured;
    use pabs_crf::verify::verify_signature_struct;

    let (pp, msk) = setup_structured(128);
    let sk = keygen_structured(&pp, &msk, &["attr_A", "attr_B"]).unwrap();
    let policy = Policy::parse("attr_A AND attr_B").unwrap();
    let msg = b"canonical_w1 end-to-end";

    let sig = sign_structured(&sk, msg, &policy, 0).unwrap();
    assert!(
        verify_signature_struct(&pp, msg, &policy, &sig).unwrap(),
        "valid signature must verify under canonical w1 serialization"
    );

    let wrong_msg = b"different message";
    assert!(
        !verify_signature_struct(&pp, wrong_msg, &policy, &sig).unwrap(),
        "wrong message must fail verification"
    );
}

#[test]
fn test_end_to_end_192_with_canonical_w1() {
    use pabs_crf::keygen::keygen_structured;
    use pabs_crf::policy::Policy;
    use pabs_crf::setup::setup_structured;
    use pabs_crf::sign::sign_structured;
    use pabs_crf::verify::verify_signature_struct;

    let (pp, msk) = setup_structured(192);
    let sk = keygen_structured(&pp, &msk, &["attr_A", "attr_B", "attr_C"]).unwrap();
    let policy = Policy::parse("attr_A AND attr_B").unwrap();
    let msg = b"canonical_w1 192-bit";

    let sig = sign_structured(&sk, msg, &policy, 0).unwrap();
    assert!(
        verify_signature_struct(&pp, msg, &policy, &sig).unwrap(),
        "192-bit signature must verify under canonical w1 serialization"
    );
}
