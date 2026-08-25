//! MLWE trapdoor framework for the PABS-CRF scheme
//!
//! This module implements the trapdoor generation, delegation, and preimage
//! sampling mechanisms based on the GPV (Gentry-Peikert-Vaikuntanathan)
//! framework for lattice-based signatures.
//!
//! # Implementation Strategy
//!
//! This mainline implementation uses a structured gadget-based TRAPGEN and
//! preimage sampling construction.
//!
//! A = [A' | G - A'R] where R is the trapdoor.
//!
//! This construction allows efficient solving of SIS-style equations (Ae = u)
//! required for attribute-bound preimage sampling in PABS.
//!
//! In this formal v4 path, we enforce strict relation verification (A*e = u)
//! and parameter consistency through the `StrictTrapdoor` wrapper.

/// Strict trapdoor sampling and verification logic.
pub mod strict;

use crate::gaussian::CdtGaussianSampler;
use crate::mlwe::{MLWEParameters, Polynomial, PolynomialMatrix, PolynomialVector};
use rand::RngCore;
use std::collections::HashMap;

pub use strict::{PrototypeTrapdoor, StrictTrapdoor, TrapdoorMode};

/// MLWE trapdoor struct
///
/// Contains the trapdoor matrix R for matrix A = [A' | I - A'R]
/// such that Ae = u can be solved with short e.
pub struct MLWETrapdoor {
    /// MLWE parameter set used by trapdoor generation and preimage sampling.
    pub params: MLWEParameters,
    /// Trapdoor matrix R ∈ R_q^{(k-1) × k}
    pub trapdoor_r: Option<PolynomialMatrix>,
    /// Public matrix A ∈ R_q^{k × (2k-1)}
    pub public_matrix: Option<PolynomialMatrix>,
}

impl MLWETrapdoor {
    /// Create a new MLWE trapdoor generator
    pub fn new(params: &MLWEParameters) -> Self {
        Self {
            params: params.clone(),
            trapdoor_r: None,
            public_matrix: None,
        }
    }

    /// Generate trapdoor using a gadget-based TRAPGEN algorithm
    ///
    /// Generates a matrix A and corresponding trapdoor R such that:
    /// - A = [A' | G - A'R]
    /// - G is the gadget matrix (I_k ⊗ g)
    /// - R is a small secret matrix
    pub fn generate_trapdoor(&mut self, rng: &mut impl RngCore) -> HashMap<String, Vec<u8>> {
        let q = self.params.q();
        let n = self.params.n();
        let k = self.params.k;
        let ell = self.params.ell;
        let m = self.params.m;

        // 1. Generate random matrix A' ∈ R_q^{k × (k-1)}
        let mut a_prime = PolynomialMatrix::new(k, k - 1, n);
        for i in 0..k {
            for j in 0..(k - 1) {
                let mut coeffs = Vec::with_capacity(n);
                for _ in 0..n {
                    let mut val;
                    loop {
                        val = rng.next_u32() & 0x7FFFFF;
                        if val < q {
                            break;
                        }
                    }
                    coeffs.push(val as i32);
                }
                a_prime.elements[i][j] = Polynomial { coeffs };
            }
        }

        // 2. Generate small random matrix R ∈ R_q^{(k-1) × (k*ell)} (trapdoor)
        // R has coefficients from CBD(1)
        let mut r_matrix = PolynomialMatrix::new(k - 1, k * ell, n);
        for i in 0..(k - 1) {
            for j in 0..(k * ell) {
                let mut coeffs = Vec::with_capacity(n);
                for _ in 0..n {
                    let a = (rng.next_u32() >> 1) & 1;
                    let b = (rng.next_u32() >> 1) & 1;
                    coeffs.push((a as i32) - (b as i32));
                }
                r_matrix.elements[i][j] = Polynomial { coeffs };
            }
        }

        // 3. Compute A_second = G - A'R
        // G is k x (k*ell)
        let mut g_matrix = PolynomialMatrix::new(k, k * ell, n);
        let base = self.params.base;
        for i in 0..k {
            for j in 0..ell {
                let mut coeffs = vec![0; n];
                coeffs[0] = ((base as u64).pow(j as u32) % q as u64) as i32;
                g_matrix.elements[i][i * ell + j] = Polynomial { coeffs };
            }
        }

        let a_prime_r = self._matrix_mul(&a_prime, &r_matrix, q);
        let mut a_second = PolynomialMatrix::new(k, k * ell, n);
        for i in 0..k {
            for j in 0..(k * ell) {
                a_second.elements[i][j] = g_matrix.elements[i][j].sub(&a_prime_r.elements[i][j], q);
            }
        }

        // 4. Full matrix A = [A' | A_second] (dimension k x m)
        let mut a_full = PolynomialMatrix::new(k, m, n);
        for i in 0..k {
            for j in 0..(k - 1) {
                a_full.elements[i][j] = a_prime.elements[i][j].clone();
            }
            for j in 0..(k * ell) {
                a_full.elements[i][j + k - 1] = a_second.elements[i][j].clone();
            }
        }

        self.public_matrix = Some(a_full.clone());
        self.trapdoor_r = Some(r_matrix.clone());

        let mut result = HashMap::new();
        result.insert("A".to_string(), bincode::serialize(&a_full).unwrap());
        result.insert("T".to_string(), bincode::serialize(&r_matrix).unwrap());
        result.insert(
            "params".to_string(),
            bincode::serialize(&self.params).unwrap(),
        );

        result
    }

    pub fn generate_trapdoor_with_a_prime(
        &mut self,
        a_prime: PolynomialMatrix,
        rng: &mut impl RngCore,
    ) -> HashMap<String, Vec<u8>> {
        let q = self.params.q();
        let n = self.params.n();
        let k = self.params.k;
        let ell = self.params.ell;
        let m = self.params.m;

        let mut r_matrix = PolynomialMatrix::new(k - 1, k * ell, n);
        for i in 0..(k - 1) {
            for j in 0..(k * ell) {
                let mut coeffs = Vec::with_capacity(n);
                for _ in 0..n {
                    let a = (rng.next_u32() >> 1) & 1;
                    let b = (rng.next_u32() >> 1) & 1;
                    coeffs.push((a as i32) - (b as i32));
                }
                r_matrix.elements[i][j] = Polynomial { coeffs };
            }
        }

        let mut g_matrix = PolynomialMatrix::new(k, k * ell, n);
        let base = self.params.base;
        for i in 0..k {
            for j in 0..ell {
                let mut coeffs = vec![0; n];
                coeffs[0] = ((base as u64).pow(j as u32) % q as u64) as i32;
                g_matrix.elements[i][i * ell + j] = Polynomial { coeffs };
            }
        }

        let a_prime_r = self._matrix_mul(&a_prime, &r_matrix, q);
        let mut a_second = PolynomialMatrix::new(k, k * ell, n);
        for i in 0..k {
            for j in 0..(k * ell) {
                a_second.elements[i][j] = g_matrix.elements[i][j].sub(&a_prime_r.elements[i][j], q);
            }
        }

        let mut a_full = PolynomialMatrix::new(k, m, n);
        for i in 0..k {
            for j in 0..(k - 1) {
                a_full.elements[i][j] = a_prime.elements[i][j].clone();
            }
            for j in 0..(k * ell) {
                a_full.elements[i][j + k - 1] = a_second.elements[i][j].clone();
            }
        }

        self.public_matrix = Some(a_full.clone());
        self.trapdoor_r = Some(r_matrix.clone());

        let mut result = HashMap::new();
        result.insert("A".to_string(), bincode::serialize(&a_full).unwrap());
        result.insert("T".to_string(), bincode::serialize(&r_matrix).unwrap());
        result.insert(
            "params".to_string(),
            bincode::serialize(&self.params).unwrap(),
        );

        result
    }

    /// Sample preimage using the trapdoor
    ///
    /// Given target u ∈ R_q^k and trapdoor R, samples short vector e ∈ R_q^m such that:
    /// A * e = u (mod q)
    pub fn sample_preimage(
        &self,
        trapdoor_map: &HashMap<String, Vec<u8>>,
        u_target: &PolynomialVector,
        rng: &mut impl RngCore,
    ) -> Vec<u8> {
        let r_matrix: PolynomialMatrix = if let Some(t_bytes) = trapdoor_map.get("T") {
            bincode::deserialize(t_bytes).expect("Failed to deserialize T")
        } else {
            let t_bytes = trapdoor_map
                .get("secret_key")
                .expect("Missing secret_key in trapdoor_map");
            bincode::deserialize(t_bytes).expect("Failed to deserialize secret_key")
        };
        let a_matrix: PolynomialMatrix = if let Some(a_bytes) = trapdoor_map.get("A") {
            bincode::deserialize(a_bytes).expect("Failed to deserialize A")
        } else {
            let q = self.params.q();
            let n = self.params.n();
            let k = self.params.k;
            let m = self.params.m;
            let a_bytes = trapdoor_map
                .get("matrix_A")
                .expect("Missing matrix_A in trapdoor_map");
            bincode::deserialize(a_bytes).unwrap_or_else(|_| {
                crate::utils::deserialize_polynomial_matrix(a_bytes, k, m, n, q)
            })
        };
        self.sample_preimage_structured(&a_matrix, &r_matrix, u_target, rng)
    }

    /// Sample a preimage from explicit structured inputs instead of legacy maps.
    pub fn sample_preimage_structured(
        &self,
        a_matrix: &PolynomialMatrix,
        r_matrix: &PolynomialMatrix,
        u_target: &PolynomialVector,
        rng: &mut impl RngCore,
    ) -> Vec<u8> {
        let q = self.params.q();
        let n = self.params.n();
        let k = self.params.k;
        let ell = self.params.ell;
        let m = self.params.m;

        // To solve Ae = u for A = [A' | G - A'R]:
        // A * [e1 | e2]^T = A'e1 + (G - A'R)e2 = A'(e1 - Re2) + Ge2 = u
        // Pick small e1 = Re2 + noise, and e2 = G^-1(u - A'noise)

        let sigma: f64 = self.params.sigma();

        // 1. Sample small noise e_noise1 ∈ R_q^{k-1}
        let mut e_noise1 = PolynomialVector::new(k - 1, n);
        for i in 0..(k - 1) {
            e_noise1.elements[i] = self._sample_gaussian_poly(sigma, q, rng);
        }

        // 2. Compute u_prime = u - A' * e_noise1
        // We need A' which is the first k-1 columns of A
        let mut a_prime = PolynomialMatrix::new(k, k - 1, n);
        for i in 0..k {
            for j in 0..(k - 1) {
                a_prime.elements[i][j] = a_matrix.elements[i][j].clone();
            }
        }

        let a_prime_e_noise1 = self._matrix_vector_mul(&a_prime, &e_noise1, q);
        let mut u_prime = PolynomialVector::new(k, n);
        for i in 0..k {
            u_prime.elements[i] = u_target.elements[i].sub(&a_prime_e_noise1.elements[i], q);
        }

        // 3. Compute e2 = G^-1(u_prime) ∈ R_q^{k*ell}
        let e2 = self.gadget_decompose(&u_prime);

        // 4. Compute e1 = Re2 + e_noise1 ∈ R_q^{k-1}
        let re2 = self._matrix_vector_mul_custom(r_matrix, &e2, q);
        let mut e1 = PolynomialVector::new(k - 1, n);
        for i in 0..(k - 1) {
            e1.elements[i] = re2.elements[i].add(&e_noise1.elements[i], q);
        }

        // 5. Final preimage e = [e1 | e2] ∈ R_q^m
        let mut e_final = PolynomialVector::new(m, n);
        for i in 0..(k - 1) {
            e_final.elements[i] = e1.elements[i].clone();
        }
        for i in 0..(k * ell) {
            e_final.elements[i + k - 1] = e2.elements[i].clone();
        }

        bincode::serialize(&e_final).expect("Failed to serialize preimage")
    }

    /// Gadget decomposition G^-1(u): Decomposes each coefficient of each polynomial
    /// into its base-B representation.
    pub fn gadget_decompose(&self, u: &PolynomialVector) -> PolynomialVector {
        let k = self.params.k;
        let ell = self.params.ell;
        let n = self.params.n;
        let base = self.params.base as i32;
        let q = self.params.q;

        let mut res = PolynomialVector::new(k * ell, n);
        for i in 0..k {
            for coeff_idx in 0..n {
                let mut val = u.elements[i].coeffs[coeff_idx];
                // Center the value for smaller decomposition results
                if val > (q as i32 / 2) {
                    val -= q as i32;
                }

                // Simple base decomposition
                for j in 0..ell {
                    let digit = if val >= 0 {
                        val % base
                    } else {
                        -((-val) % base)
                    };
                    res.elements[i * ell + j].coeffs[coeff_idx] = digit;
                    val = (val - digit) / base;
                }
            }
        }
        res
    }

    // ==================== Internal Helper Methods ====================

    fn _sample_gaussian_poly(&self, sigma: f64, _q: u32, rng: &mut impl RngCore) -> Polynomial {
        let cdt = CdtGaussianSampler::new(sigma, 64);
        cdt.sample_poly(self.params.n(), rng)
    }

    fn _matrix_vector_mul(
        &self,
        a: &PolynomialMatrix,
        v: &PolynomialVector,
        q: u32,
    ) -> PolynomialVector {
        let mut res = PolynomialVector::new(a.rows, v.elements[0].coeffs.len());
        for i in 0..a.rows {
            let mut sum = Polynomial::new(v.elements[0].coeffs.len());
            for j in 0..a.cols {
                let prod = a.elements[i][j].mul(&v.elements[j], q);
                sum = sum.add(&prod, q);
            }
            res.elements[i] = sum;
        }
        res
    }

    fn _matrix_vector_mul_custom(
        &self,
        a: &PolynomialMatrix,
        v: &PolynomialVector,
        q: u32,
    ) -> PolynomialVector {
        let mut res = PolynomialVector::new(a.rows, v.elements[0].coeffs.len());
        for i in 0..a.rows {
            let mut sum = Polynomial::new(v.elements[0].coeffs.len());
            for j in 0..a.cols.min(v.elements.len()) {
                let prod = a.elements[i][j].mul(&v.elements[j], q);
                sum = sum.add(&prod, q);
            }
            res.elements[i] = sum;
        }
        res
    }

    fn _matrix_mul(&self, a: &PolynomialMatrix, b: &PolynomialMatrix, q: u32) -> PolynomialMatrix {
        let rows = a.rows;
        let cols = b.cols;
        let n = a.elements[0][0].coeffs.len();
        let mut result = PolynomialMatrix::new(rows, cols, n);
        for i in 0..rows {
            for j in 0..cols {
                let mut sum = Polynomial::new(n);
                for k in 0..a.cols {
                    let prod = a.elements[i][k].mul(&b.elements[k][j], q);
                    sum = sum.add(&prod, q);
                }
                result.elements[i][j] = sum;
            }
        }
        result
    }
}
