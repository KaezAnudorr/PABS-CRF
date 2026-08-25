use crate::errors::{PabsCrfError, PabsCrfResult};
use crate::mlwe::{MLWEKeyPair, Polynomial, PolynomialMatrix, PolynomialVector};

pub use crate::mlwe::{
    Polynomial as RingPolynomial, PolynomialMatrix as RingMatrix, PolynomialVector as RingVector,
};

/// Subtract two polynomial vectors coefficient-wise modulo `q`.
pub fn vector_sub(
    lhs: &PolynomialVector,
    rhs: &PolynomialVector,
    q: u32,
) -> PabsCrfResult<PolynomialVector> {
    if lhs.elements.len() != rhs.elements.len() {
        return Err(PabsCrfError::InvalidInput(format!(
            "Vector dimension mismatch: lhs={}, rhs={}",
            lhs.elements.len(),
            rhs.elements.len()
        )));
    }

    Ok(PolynomialVector {
        elements: lhs
            .elements
            .iter()
            .zip(rhs.elements.iter())
            .map(|(l, r)| l.sub(r, q))
            .collect(),
    })
}

/// Add two polynomial vectors coefficient-wise modulo `q`.
pub fn vector_add(
    lhs: &PolynomialVector,
    rhs: &PolynomialVector,
    q: u32,
) -> PabsCrfResult<PolynomialVector> {
    if lhs.elements.len() != rhs.elements.len() {
        return Err(PabsCrfError::InvalidInput(format!(
            "Vector dimension mismatch: lhs={}, rhs={}",
            lhs.elements.len(),
            rhs.elements.len()
        )));
    }

    Ok(PolynomialVector {
        elements: lhs
            .elements
            .iter()
            .zip(rhs.elements.iter())
            .map(|(l, r)| l.add(r, q))
            .collect(),
    })
}

/// Add two polynomial vectors in the integer domain (no mod q reduction).
/// Uses i64 accumulators internally to prevent silent overflow.
pub fn vector_add_integer(
    lhs: &PolynomialVector,
    rhs: &PolynomialVector,
) -> PabsCrfResult<PolynomialVector> {
    if lhs.elements.len() != rhs.elements.len() {
        return Err(PabsCrfError::InvalidInput(format!(
            "Vector dimension mismatch: lhs={}, rhs={}",
            lhs.elements.len(),
            rhs.elements.len()
        )));
    }

    Ok(PolynomialVector {
        elements: lhs
            .elements
            .iter()
            .zip(rhs.elements.iter())
            .map(|(l, r)| l.add_integer(r))
            .collect(),
    })
}

/// Subtract two polynomial vectors in the integer domain (no mod q reduction).
/// Uses i64 accumulators internally to prevent silent overflow.
pub fn vector_sub_integer(
    lhs: &PolynomialVector,
    rhs: &PolynomialVector,
) -> PabsCrfResult<PolynomialVector> {
    if lhs.elements.len() != rhs.elements.len() {
        return Err(PabsCrfError::InvalidInput(format!(
            "Vector dimension mismatch: lhs={}, rhs={}",
            lhs.elements.len(),
            rhs.elements.len()
        )));
    }

    Ok(PolynomialVector {
        elements: lhs
            .elements
            .iter()
            .zip(rhs.elements.iter())
            .map(|(l, r)| l.sub_integer(r))
            .collect(),
    })
}

/// Multiply a matrix by a vector using the shared MLWE implementation.
pub fn matrix_vector_mul(a: &PolynomialMatrix, v: &PolynomialVector, q: u32) -> PolynomialVector {
    MLWEKeyPair::matrix_vector_mul(a, v, q)
}

/// Compute `A * z - c * t` using the shared optimized backend.
pub fn matrix_vector_mul_sub_poly_mul_ntt(
    a: &PolynomialMatrix,
    z: &PolynomialVector,
    t: &PolynomialVector,
    c: &Polynomial,
    q: u32,
) -> PolynomialVector {
    MLWEKeyPair::matrix_vector_mul_sub_poly_mul_ntt(a, z, t, c, q)
}

/// Verify that all vector coefficients stay within an infinity bound.
/// Uses the integer domain infinity norm on centered coefficients.
/// Since signature z is stored mod q in [0, q), we must center to (-q/2, q/2]
/// before checking the integer-domain norm, so that originally-negative coefficients
/// (now near q) are correctly interpreted.
pub fn vector_within_infinity_bound(v: &PolynomialVector, q: u32, bound: i64) -> bool {
    v.elements.iter().all(|poly| {
        let centered = poly.center_coefficients(q);
        centered.infinity_norm_integer() < bound
    })
}
