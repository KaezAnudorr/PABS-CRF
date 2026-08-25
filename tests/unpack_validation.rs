use pabs_crf::compression::{unpack_polyvec_mod_q, unpack_z};
use pabs_crf::mlwe::MLWEParameters;

#[test]
fn test_unpack_z_empty_data_returns_error() {
    let result = unpack_z(&[], 4, 256, 1 << 19);
    assert!(
        result.is_err(),
        "unpack_z with empty data must return an error"
    );
}

#[test]
fn test_unpack_z_insufficient_data_returns_error() {
    let params = MLWEParameters::new_128();
    let bits = z_bits(params.gamma1);
    let total_bits = (params.m * params.n) as u64 * bits as u64;
    let expected_bytes = ((total_bits + 7) / 8) as usize;

    let short_data = vec![0u8; expected_bytes / 2];
    let result = unpack_z(&short_data, params.m, params.n, params.gamma1);
    assert!(
        result.is_err(),
        "unpack_z with insufficient data must return an error"
    );
}

#[test]
fn test_unpack_z_correct_size_data_succeeds() {
    let params = MLWEParameters::new_128();
    let bits = z_bits(params.gamma1);
    let total_bits = (params.m * params.n) as u64 * bits as u64;
    let expected_bytes = ((total_bits + 7) / 8) as usize;

    let data = vec![0u8; expected_bytes];
    let result = unpack_z(&data, params.m, params.n, params.gamma1);
    assert!(
        result.is_ok(),
        "unpack_z with correct size data should succeed, got: {:?}",
        result.err()
    );

    let pv = result.unwrap();
    assert_eq!(pv.elements.len(), params.m);
    for poly in &pv.elements {
        assert_eq!(poly.coeffs.len(), params.n);
    }
}

#[test]
fn test_unpack_z_exactly_one_byte_short_returns_error() {
    let params = MLWEParameters::new_128();
    let bits = z_bits(params.gamma1);
    let total_bits = (params.m * params.n) as u64 * bits as u64;
    let expected_bytes = ((total_bits + 7) / 8) as usize;

    let data = vec![0u8; expected_bytes - 1];
    let result = unpack_z(&data, params.m, params.n, params.gamma1);
    assert!(
        result.is_err(),
        "unpack_z one byte short must return an error"
    );
}

#[test]
fn test_unpack_polyvec_mod_q_empty_data_returns_error() {
    let result = unpack_polyvec_mod_q(&[], 4, 256, 8380417);
    assert!(
        result.is_err(),
        "unpack_polyvec_mod_q with empty data must return an error"
    );
}

#[test]
fn test_unpack_polyvec_mod_q_correct_size_data_succeeds() {
    let params = MLWEParameters::new_128();
    let bits = 32 - (params.q - 1).leading_zeros();
    let total_bits = (params.k * params.n) as u64 * bits as u64;
    let expected_bytes = ((total_bits + 7) / 8) as usize;

    let data = vec![0u8; expected_bytes];
    let result = unpack_polyvec_mod_q(&data, params.k, params.n, params.q);
    assert!(
        result.is_ok(),
        "unpack_polyvec_mod_q with correct size data should succeed, got: {:?}",
        result.err()
    );

    let pv = result.unwrap();
    assert_eq!(pv.elements.len(), params.k);
    for poly in &pv.elements {
        assert_eq!(poly.coeffs.len(), params.n);
    }
}

#[test]
fn test_unpack_polyvec_mod_q_insufficient_data_returns_error() {
    let params = MLWEParameters::new_128();
    let bits = 32 - (params.q - 1).leading_zeros();
    let total_bits = (params.k * params.n) as u64 * bits as u64;
    let expected_bytes = ((total_bits + 7) / 8) as usize;

    let short_data = vec![0u8; expected_bytes / 3];
    let result = unpack_polyvec_mod_q(&short_data, params.k, params.n, params.q);
    assert!(
        result.is_err(),
        "unpack_polyvec_mod_q with insufficient data must return an error"
    );
}

fn z_bits(gamma1: u32) -> u32 {
    match gamma1 {
        131072 => 18,
        524288 => 20,
        33554432 => 26,
        _ => {
            let range = 2u64.saturating_mul(gamma1 as u64).saturating_add(1);
            (u64::BITS - range.leading_zeros()).max(1)
        }
    }
}
