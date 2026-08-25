//! Signature compression and bit-packing for PABS-CRF
//!
//! This module implements efficient encoding techniques similar to ML-DSA:
//! 1. Coefficient bit-packing for response vector z
//! 2. Sparse index encoding for challenge polynomial c
//! 3. Commitment compression (HighBits extraction)

use crate::errors::PabsCrfError;
use crate::mlwe::{Polynomial, PolynomialVector};

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

/// Bit-pack a polynomial vector z into a compact byte array.
pub fn pack_z(z: &PolynomialVector, gamma1: u32, _n: usize) -> Vec<u8> {
    let bits = z_bits(gamma1);

    let mut out = Vec::new();
    let mut bit_buf: u64 = 0;
    let mut bit_count: u32 = 0;

    for poly in &z.elements {
        for &c in &poly.coeffs {
            let val = (c + gamma1 as i32) as u64;
            bit_buf |= val << bit_count;
            bit_count += bits;
            while bit_count >= 8 {
                out.push((bit_buf & 0xFF) as u8);
                bit_buf >>= 8;
                bit_count -= 8;
            }
        }
    }
    if bit_count > 0 {
        out.push((bit_buf & 0xFF) as u8);
    }
    out
}

/// Unpack a polynomial vector z from a compact byte array.
pub fn unpack_z(
    data: &[u8],
    k: usize,
    n: usize,
    gamma1: u32,
) -> Result<PolynomialVector, PabsCrfError> {
    let bits = z_bits(gamma1);
    let expected_bits = (k * n) as u64 * bits as u64;
    let expected_bytes = ((expected_bits + 7) / 8) as usize;
    if data.len() < expected_bytes {
        return Err(PabsCrfError::SerializationError(format!(
            "unpack_z: input too short ({} bytes, expected {})",
            data.len(),
            expected_bytes
        )));
    }

    let mut elements = Vec::with_capacity(k);
    let mut bit_buf: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut data_idx = 0;

    for _ in 0..k {
        let mut coeffs = Vec::with_capacity(n);
        for _ in 0..n {
            while bit_count < bits && data_idx < data.len() {
                bit_buf |= (data[data_idx] as u64) << bit_count;
                bit_count += 8;
                data_idx += 1;
            }
            let val = bit_buf & ((1 << bits) - 1);
            bit_buf >>= bits;
            bit_count -= bits;
            coeffs.push((val as i32) - (gamma1 as i32));
        }
        elements.push(Polynomial { coeffs });
    }
    Ok(PolynomialVector { elements })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unpack_hints_short_input_returns_error() {
        let result = unpack_hints(&[0u8; 2], 4, 256);
        assert!(result.is_err());
    }

    #[test]
    fn test_unpack_hints_truncated_data_returns_error() {
        let data = [5, 0, 0, 0, 0, 0];
        let result = unpack_hints(&data, 4, 256);
        assert!(result.is_err());
    }

    #[test]
    fn test_unpack_hints_valid_data() {
        let mut data = vec![1, 0, 0, 0];
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        let result = unpack_hints(&data, 4, 256);
        assert!(result.is_ok());
        let hints = result.unwrap();
        assert_eq!(hints.elements[0].coeffs[0], 1);
    }

    #[test]
    fn test_unpack_hints_index_out_of_range() {
        let mut data = vec![1, 0, 0, 0];
        data.extend_from_slice(&10u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        let result = unpack_hints(&data, 4, 256);
        assert!(result.is_err());
    }

    #[test]
    fn test_pack_unpack_hints_u16_roundtrip() {
        let k = 4;
        let n = 512;
        let mut hints = PolynomialVector::new(k, n);
        hints.elements[1].coeffs[300] = 1;
        hints.elements[3].coeffs[500] = 1;
        let packed = pack_hints(&hints);
        let unpacked = unpack_hints(&packed, k, n).unwrap();
        assert_eq!(unpacked.elements[1].coeffs[300], 1);
        assert_eq!(unpacked.elements[3].coeffs[500], 1);
    }
}

/// Encode a sparse challenge polynomial c.
pub fn encode_challenge(c: &Polynomial, _n: usize) -> Vec<u8> {
    let mut pos_indices = Vec::new();
    let mut neg_indices = Vec::new();
    for (i, &coeff) in c.coeffs.iter().enumerate() {
        if coeff == 1 {
            pos_indices.push(i as u16);
        } else if coeff == -1 {
            neg_indices.push(i as u16);
        }
    }
    let mut out = Vec::new();
    out.push(pos_indices.len() as u8);
    for idx in pos_indices {
        out.extend_from_slice(&idx.to_le_bytes());
    }
    for idx in neg_indices {
        out.extend_from_slice(&idx.to_le_bytes());
    }
    out
}

/// Decode a sparse challenge polynomial c.
pub fn decode_challenge(data: &[u8], n: usize) -> Polynomial {
    let mut coeffs = vec![0i32; n];
    let pos_len = data[0] as usize;
    let mut cursor = 1;
    for _ in 0..pos_len {
        let idx = u16::from_le_bytes([data[cursor], data[cursor + 1]]) as usize;
        coeffs[idx] = 1;
        cursor += 2;
    }
    while cursor + 1 < data.len() {
        let idx = u16::from_le_bytes([data[cursor], data[cursor + 1]]) as usize;
        coeffs[idx] = -1;
        cursor += 2;
    }
    Polynomial { coeffs }
}

/// Losslessly bit-pack a polynomial vector with coefficients reduced mod `q`.
pub fn pack_polyvec_mod_q(v: &PolynomialVector, q: u32) -> Vec<u8> {
    let bits = 32 - (q - 1).leading_zeros();
    let mut out = Vec::new();
    let mut bit_buf: u64 = 0;
    let mut bit_count: u32 = 0;

    for poly in &v.elements {
        for &c in &poly.coeffs {
            let val = (((c % q as i32) + q as i32) % q as i32) as u64;
            bit_buf |= val << bit_count;
            bit_count += bits;
            while bit_count >= 8 {
                out.push((bit_buf & 0xFF) as u8);
                bit_buf >>= 8;
                bit_count -= 8;
            }
        }
    }

    if bit_count > 0 {
        out.push((bit_buf & 0xFF) as u8);
    }

    out
}

/// Pack a sparse binary hint vector.
pub fn pack_hints(hints: &PolynomialVector) -> Vec<u8> {
    let mut indices = Vec::new();
    for (i, poly) in hints.elements.iter().enumerate() {
        for (j, &coeff) in poly.coeffs.iter().enumerate() {
            if coeff != 0 {
                indices.push((i as u16, j as u16));
            }
        }
    }

    let mut out = Vec::new();
    out.extend_from_slice(&(indices.len() as u32).to_le_bytes());
    for (poly_idx, coeff_idx) in indices {
        out.extend_from_slice(&poly_idx.to_le_bytes());
        out.extend_from_slice(&coeff_idx.to_le_bytes());
    }
    out
}

/// Unpack a sparse binary hint vector.
pub fn unpack_hints(data: &[u8], k: usize, n: usize) -> Result<PolynomialVector, PabsCrfError> {
    if data.len() < 4 {
        return Err(PabsCrfError::DeserializationError(
            "unpack_hints: data too short for length header".into(),
        ));
    }

    let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;

    if len * 4 + 4 > data.len() {
        return Err(PabsCrfError::DeserializationError(
            "unpack_hints: data truncated".into(),
        ));
    }

    let mut hints = PolynomialVector::new(k, n);
    let mut cursor = 4;
    for _ in 0..len {
        if cursor + 4 > data.len() {
            return Err(PabsCrfError::DeserializationError(
                "unpack_hints: data truncated at entry".into(),
            ));
        }
        let poly_idx = u16::from_le_bytes([data[cursor], data[cursor + 1]]) as usize;
        let coeff_idx = u16::from_le_bytes([data[cursor + 2], data[cursor + 3]]) as usize;
        if poly_idx >= k || coeff_idx >= n {
            return Err(PabsCrfError::DeserializationError(
                "unpack_hints: index out of range".into(),
            ));
        }
        hints.elements[poly_idx].coeffs[coeff_idx] = 1;
        cursor += 4;
    }
    Ok(hints)
}

/// Losslessly unpack a polynomial vector with coefficients reduced mod `q`.
pub fn unpack_polyvec_mod_q(
    data: &[u8],
    k: usize,
    n: usize,
    q: u32,
) -> Result<PolynomialVector, PabsCrfError> {
    let bits = 32 - (q - 1).leading_zeros();
    let expected_bits = (k * n) as u64 * bits as u64;
    let expected_bytes = ((expected_bits + 7) / 8) as usize;
    if data.len() < expected_bytes {
        return Err(PabsCrfError::SerializationError(format!(
            "unpack_polyvec_mod_q: input too short ({} bytes, expected {})",
            data.len(),
            expected_bytes
        )));
    }
    let mut elements = Vec::with_capacity(k);
    let mut bit_buf: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut data_idx = 0;

    for _ in 0..k {
        let mut coeffs = Vec::with_capacity(n);
        for _ in 0..n {
            while bit_count < bits && data_idx < data.len() {
                bit_buf |= (data[data_idx] as u64) << bit_count;
                bit_count += 8;
                data_idx += 1;
            }

            let mask = if bits == 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };
            let val = (bit_buf & mask) as i32;
            bit_buf >>= bits;
            bit_count = bit_count.saturating_sub(bits);
            coeffs.push(val);
        }
        elements.push(Polynomial { coeffs });
    }

    Ok(PolynomialVector { elements })
}
