use crate::errors::{PabsCrfError, PabsCrfResult};
use crate::mlwe::{MLWEParameters, PolynomialMatrix, PolynomialVector};
use crate::trapdoor::MLWETrapdoor;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Explicit trapdoor mode labels kept in the structured key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub enum TrapdoorMode {
    /// Prototype-only trapdoor path retained for comparison.
    Prototype,
    /// Strict structured trapdoor path used by the v4 mainline.
    Strict,
}

/// Transitional wrapper for the original prototype trapdoor.
#[derive(Debug, Clone)]
pub struct PrototypeTrapdoor {
    params: MLWEParameters,
}

/// Structured trapdoor wrapper with explicit contract checks.
#[derive(Debug, Clone)]
pub struct StrictTrapdoor {
    params: MLWEParameters,
}

impl PrototypeTrapdoor {
    /// Construct the legacy-compatible prototype trapdoor.
    pub fn new(params: &MLWEParameters) -> Self {
        Self { params: *params }
    }

    /// Generate the original public matrix and trapdoor.
    pub fn generate(
        &self,
        rng: &mut impl RngCore,
    ) -> PabsCrfResult<(PolynomialMatrix, PolynomialMatrix)> {
        let mut inner = MLWETrapdoor::new(&self.params);
        inner.generate_trapdoor(rng);
        let matrix_a = inner.public_matrix.ok_or_else(|| {
            PabsCrfError::TrapdoorError("Prototype trapdoor did not produce matrix A".to_string())
        })?;
        let trapdoor_t = inner.trapdoor_r.ok_or_else(|| {
            PabsCrfError::TrapdoorError("Prototype trapdoor did not produce trapdoor T".to_string())
        })?;
        Ok((matrix_a, trapdoor_t))
    }
}

impl StrictTrapdoor {
    /// Construct the strict trapdoor wrapper.
    pub fn new(params: &MLWEParameters) -> Self {
        Self { params: *params }
    }

    /// Generate a structured trapdoor pair and validate the resulting dimensions.
    pub fn generate(
        &self,
        rng: &mut impl RngCore,
    ) -> PabsCrfResult<(PolynomialMatrix, PolynomialMatrix)> {
        let prototype = PrototypeTrapdoor::new(&self.params);
        let (matrix_a, trapdoor_t) = prototype.generate(rng)?;

        if matrix_a.rows != self.params.k || matrix_a.cols != self.params.m {
            return Err(PabsCrfError::TrapdoorError(format!(
                "Structured matrix dimensions mismatch: got {}x{}, expected {}x{}",
                matrix_a.rows, matrix_a.cols, self.params.k, self.params.m
            )));
        }
        if trapdoor_t.rows != self.params.k.saturating_sub(1) {
            return Err(PabsCrfError::TrapdoorError(format!(
                "Trapdoor row mismatch: got {}, expected {}",
                trapdoor_t.rows,
                self.params.k.saturating_sub(1)
            )));
        }

        Ok((matrix_a, trapdoor_t))
    }

    pub fn generate_with_a_prime(
        &self,
        a_prime: PolynomialMatrix,
        rng: &mut impl RngCore,
    ) -> PabsCrfResult<(PolynomialMatrix, PolynomialMatrix)> {
        if a_prime.rows != self.params.k || a_prime.cols != self.params.k - 1 {
            return Err(PabsCrfError::TrapdoorError(format!(
                "A-prime dimensions mismatch: got {}x{}, expected {}x{}",
                a_prime.rows,
                a_prime.cols,
                self.params.k,
                self.params.k - 1
            )));
        }

        let mut inner = MLWETrapdoor::new(&self.params);
        inner.generate_trapdoor_with_a_prime(a_prime, rng);
        let matrix_a = inner.public_matrix.ok_or_else(|| {
            PabsCrfError::TrapdoorError(
                "Trapdoor with A-prime did not produce matrix A".to_string(),
            )
        })?;
        let trapdoor_t = inner.trapdoor_r.ok_or_else(|| {
            PabsCrfError::TrapdoorError(
                "Trapdoor with A-prime did not produce trapdoor T".to_string(),
            )
        })?;

        if matrix_a.rows != self.params.k || matrix_a.cols != self.params.m {
            return Err(PabsCrfError::TrapdoorError(format!(
                "Structured matrix dimensions mismatch: got {}x{}, expected {}x{}",
                matrix_a.rows, matrix_a.cols, self.params.k, self.params.m
            )));
        }
        if trapdoor_t.rows != self.params.k.saturating_sub(1) {
            return Err(PabsCrfError::TrapdoorError(format!(
                "Trapdoor row mismatch: got {}, expected {}",
                trapdoor_t.rows,
                self.params.k.saturating_sub(1)
            )));
        }

        Ok((matrix_a, trapdoor_t))
    }

    /// Sample a witness/preimage and verify the linear relation before returning it.
    pub fn sample_preimage(
        &self,
        matrix_a: &PolynomialMatrix,
        trapdoor_t: &PolynomialMatrix,
        u_target: &PolynomialVector,
        rng: &mut impl RngCore,
    ) -> PabsCrfResult<PolynomialVector> {
        let inner = MLWETrapdoor::new(&self.params);
        let bytes = inner.sample_preimage_structured(matrix_a, trapdoor_t, u_target, rng);
        let witness: PolynomialVector = bincode::deserialize(&bytes).map_err(|e| {
            PabsCrfError::DeserializationError(format!(
                "Failed to deserialize strict trapdoor witness: {}",
                e
            ))
        })?;

        self.verify_witness_relation(matrix_a, &witness, u_target)?;
        Ok(witness)
    }

    /// Verify the witness satisfies the target relation.
    pub fn verify_witness_relation(
        &self,
        matrix_a: &PolynomialMatrix,
        witness: &PolynomialVector,
        u_target: &PolynomialVector,
    ) -> PabsCrfResult<()> {
        if witness.elements.len() != matrix_a.cols {
            return Err(PabsCrfError::TrapdoorError(format!(
                "Witness width mismatch: got {}, expected {}",
                witness.elements.len(),
                matrix_a.cols
            )));
        }
        if u_target.elements.len() != matrix_a.rows {
            return Err(PabsCrfError::TrapdoorError(format!(
                "Target height mismatch: got {}, expected {}",
                u_target.elements.len(),
                matrix_a.rows
            )));
        }

        let lhs = crate::algebra::matrix_vector_mul(matrix_a, witness, self.params.q);
        if lhs != *u_target {
            return Err(PabsCrfError::TrapdoorError(
                "Witness relation check failed: A*witness != target".to_string(),
            ));
        }

        let b_witness = self.params.gamma1 as i64;

        let centered = witness.center_coefficients(self.params.q);
        let norm = centered.infinity_norm_integer();
        if norm > b_witness {
            return Err(PabsCrfError::TrapdoorError(format!(
                "Witness norm {} exceeds bound {} (gamma1)",
                norm, b_witness
            )));
        }

        Ok(())
    }
}
