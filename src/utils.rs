//! Utility functions for the PABS-CRF scheme

use crate::mlwe::{MLWEParameters, Polynomial, PolynomialMatrix, PolynomialVector};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use subtle::ConstantTimeEq;

/// Hash an attribute to a target polynomial vector u ∈ R_q^k
///
/// This provides a uniform mapping from attribute strings to the lattice coset space,
/// ensuring that the GPV preimage sampling has a well-defined target.
#[deprecated(
    since = "0.3.0",
    note = "Use hash_to_target_vector_with_gid instead — this function does not bind a user GID and is vulnerable to collusion attacks"
)]
pub fn hash_to_target_vector(attribute: &str, params: &MLWEParameters) -> PolynomialVector {
    hash_to_target_vector_with_gid(attribute, &[0u8; 32], params)
}

/// Hash an attribute bound to a user GID to a target polynomial vector u ∈ R_q^k.
///
/// The SHAKE-256 input is `attr || GID`, ensuring that different users
/// obtain distinct target vectors for the same attribute — this is the
/// core mechanism preventing cross-user preimage collusion (S-1 fix).
pub fn hash_to_target_vector_with_gid(
    attribute: &str,
    gid: &[u8; 32],
    params: &MLWEParameters,
) -> PolynomialVector {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, attribute.as_bytes());
    Update::update(&mut hasher, gid);
    let mut reader = hasher.finalize_xof();

    let k = params.k;
    let n = params.n;
    let q = params.q;

    let mut elements = Vec::with_capacity(k);
    for _ in 0..k {
        let mut coeffs = Vec::with_capacity(n);
        for _ in 0..n {
            let mut buf = [0u8; 4];
            reader.read(&mut buf);
            let mut val;
            loop {
                val = u32::from_le_bytes(buf) & 0x7FFFFF;
                if val < q {
                    break;
                }
                reader.read(&mut buf);
            }
            coeffs.push(val as i32);
        }
        elements.push(Polynomial { coeffs });
    }
    PolynomialVector { elements }
}

/// Deserialize a flat byte slice into a polynomial vector of length `k`.
pub fn deserialize_polynomial_vector(bytes: &[u8], k: usize, n: usize, q: u32) -> PolynomialVector {
    let coeff_size = 4;
    let poly_size = n * coeff_size;
    let mut elements = Vec::with_capacity(k);
    for i in 0..k {
        let start = i * poly_size;
        let end = (start + poly_size).min(bytes.len());
        let mut coeffs = Vec::with_capacity(n);
        for j in 0..n {
            let idx = start + j * coeff_size;
            if idx + coeff_size <= end {
                let c = i32::from_le_bytes([
                    bytes[idx],
                    bytes[idx + 1],
                    bytes[idx + 2],
                    bytes[idx + 3],
                ]);
                coeffs.push(((c % q as i32) + q as i32) % q as i32);
            } else {
                coeffs.push(0);
            }
        }
        elements.push(Polynomial { coeffs });
    }
    PolynomialVector { elements }
}

/// Deserialize a flat byte slice into a `rows x cols` polynomial matrix.
pub fn deserialize_polynomial_matrix(
    bytes: &[u8],
    rows: usize,
    cols: usize,
    n: usize,
    q: u32,
) -> PolynomialMatrix {
    let coeff_size = 4;
    let poly_size = n * coeff_size;
    let mut elements = Vec::with_capacity(rows);
    for i in 0..rows {
        let mut row = Vec::with_capacity(cols);
        for j in 0..cols {
            let start = (i * cols + j) * poly_size;
            let end = (start + poly_size).min(bytes.len());
            let mut coeffs = Vec::with_capacity(n);
            for l in 0..n {
                let idx = start + l * coeff_size;
                if idx + coeff_size <= end {
                    let c = i32::from_le_bytes([
                        bytes[idx],
                        bytes[idx + 1],
                        bytes[idx + 2],
                        bytes[idx + 3],
                    ]);
                    coeffs.push(((c % q as i32) + q as i32) % q as i32);
                } else {
                    coeffs.push(0);
                }
            }
            row.push(Polynomial { coeffs });
        }
        elements.push(row);
    }
    PolynomialMatrix {
        rows,
        cols,
        elements,
    }
}

/// Hash utilities
pub struct HashUtils;

impl HashUtils {
    /// Hash message
    pub fn hash_message(message: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        use sha2::Sha256;
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, message);
        hasher.finalize().to_vec()
    }

    /// Hash attribute
    pub fn hash_attribute(attribute: &str) -> Vec<u8> {
        use sha2::Digest;
        use sha2::Sha256;
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, attribute.as_bytes());
        hasher.finalize().to_vec()
    }
}

/// Side channel protection
pub struct ConstantTimeOps;

impl ConstantTimeOps {
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        a.ct_eq(b).into()
    }
}

#[deprecated(since = "0.2.0", note = "Use ConstantTimeOps instead")]
pub type SideChannelProtection = ConstantTimeOps;
