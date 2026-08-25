//! CDT (Cumulative Distribution Table) discrete Gaussian sampler
//!
//! Implements a proper discrete Gaussian distribution D_{Z,sigma} using
//! precomputed cumulative probabilities. This replaces the incorrect
//! Box-Muller continuous approximation previously used for GPV preimage
//! sampling.
//!
//! # Academic Reference
//! Gentry, Craig; Peikert, Chris; Vaikuntanathan, Vinod (STOC 2008).
//! "Trapdoors for Hard Lattices and New Cryptographic Constructions."
//!
//! The CDT approach stores Pr[X <= x] for x = 0, 1, ..., tau*sigma
//! in fixed-point representation. Sampling proceeds by:
//! 1. Draw uniform r in [0, 1) with `precision` bits
//! 2. Binary search the CDT for the smallest x with CDT[x] > r
//! 3. Apply random sign (symmetric distribution)

use crate::mlwe::Polynomial;
use rand::RngCore;

/// CDT-based discrete Gaussian sampler producing samples from D_{Z,sigma}.
///
/// The cumulative distribution table stores Pr[|X| <= x] for x = 0..tau*sigma
/// in fixed-point with `precision` bits. Sampling uses binary search for
/// O(log(tau*sigma)) per sample.
pub struct CdtGaussianSampler {
    table: Vec<u64>,
    sigma_times_256: u64,
    mask: u64,
}

impl CdtGaussianSampler {
    /// Construct a new CDT sampler for the given sigma and fixed-point precision.
    ///
    /// # Arguments
    /// * `sigma` - Standard deviation of the target discrete Gaussian
    /// * `precision` - Number of bits for fixed-point probability representation (typically 64)
    ///
    /// # Panics
    /// Panics if sigma <= 0 or precision == 0 or precision > 63.
    pub fn new(sigma: f64, precision: usize) -> Self {
        assert!(sigma > 0.0, "sigma must be positive");
        assert!(
            precision > 0 && precision <= 64,
            "precision must be in [1, 64]"
        );

        let tail_cutoff = (sigma * 14.0).ceil() as usize;
        let sigma_sq_2 = 2.0 * sigma * sigma;
        let scale = if precision < 64 {
            (1u64 << precision) as f64
        } else {
            (u64::MAX as f64) + 1.0
        };

        let mut rho = Vec::with_capacity(tail_cutoff + 1);
        for x in 0..=tail_cutoff {
            let prob = (-((x as f64) * (x as f64)) / sigma_sq_2).exp();
            rho.push(prob);
        }

        let z: f64 = rho[0] + 2.0 * rho[1..].iter().sum::<f64>();

        let mut table = Vec::with_capacity(tail_cutoff + 1);
        let mut cumulative: f64 = 0.0;
        for x in 0..=tail_cutoff {
            cumulative += if x == 0 { rho[x] } else { 2.0 * rho[x] };
            let fixed_point = ((cumulative / z).min(1.0) * scale) as u64;
            table.push(fixed_point);
        }

        let mask = if precision < 64 {
            (1u64 << precision) - 1
        } else {
            u64::MAX
        };

        CdtGaussianSampler {
            table,
            sigma_times_256: (sigma * 256.0) as u64,
            mask,
        }
    }

    /// Sample a single integer from D_{Z,sigma}.
    ///
    /// Returns a value in the range [-tau*sigma, tau*sigma] where tau = 14.
    pub fn sample(&self, rng: &mut impl RngCore) -> i32 {
        let r = rng.next_u64() & self.mask;
        let x = self.binary_search(r);
        let sign_bit = (rng.next_u64() & 1) as i32;
        let sign: i32 = if sign_bit == 0 { 1 } else { -1 };
        sign * (x as i32)
    }

    /// Sample a polynomial with n coefficients from D_{Z,sigma}.
    ///
    /// Coefficients are stored as raw i32 values (not reduced mod q).
    /// This is the correct representation for GPV preimage sampling
    /// where short vectors in Z are required.
    pub fn sample_poly(&self, n: usize, rng: &mut impl RngCore) -> Polynomial {
        let coeffs: Vec<i32> = (0..n).map(|_| self.sample(rng)).collect();
        Polynomial { coeffs }
    }

    /// Binary search the CDT for the smallest x with table[x] > r.
    fn binary_search(&self, r: u64) -> usize {
        let mut lo = 0usize;
        let mut hi = self.table.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.table[mid] <= r {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo.min(self.table.len() - 1)
    }

    /// Return the sigma parameter as f64.
    pub fn sigma(&self) -> f64 {
        self.sigma_times_256 as f64 / 256.0
    }

    /// Return the tail cutoff (tau * sigma rounded up).
    pub fn tail_cutoff(&self) -> usize {
        self.table.len() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_cdt_zero_centered() {
        let sampler = CdtGaussianSampler::new(3.0, 64);
        let mut rng = StdRng::from_entropy();
        let n = 10000;
        let sum: f64 = (0..n).map(|_| sampler.sample(&mut rng) as f64).sum();
        let mean = sum / n as f64;
        assert!(
            mean.abs() < 0.2,
            "CDT sampler should be approximately zero-centered, got mean={}",
            mean
        );
    }

    #[test]
    fn test_cdt_variance() {
        let sigma = 3.0;
        let sampler = CdtGaussianSampler::new(sigma, 64);
        let mut rng = StdRng::from_entropy();
        let n = 10000;
        let samples: Vec<i32> = (0..n).map(|_| sampler.sample(&mut rng)).collect();
        let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / n as f64;
        let variance: f64 = samples
            .iter()
            .map(|&x| (x as f64 - mean).powi(2))
            .sum::<f64>()
            / n as f64;
        let expected_var = sigma * sigma;
        assert!(
            (variance - expected_var).abs() / expected_var < 0.15,
            "CDT sampler variance should be close to sigma^2={}, got {}",
            expected_var,
            variance
        );
    }

    #[test]
    fn test_cdt_bounded() {
        let sampler = CdtGaussianSampler::new(3.0, 64);
        let mut rng = StdRng::from_entropy();
        let samples: Vec<i32> = (0..1000).map(|_| sampler.sample(&mut rng)).collect();
        let max_abs = samples.iter().map(|&x| x.unsigned_abs()).max().unwrap();
        assert!(
            (max_abs as f64) < 3.0 * 14.0,
            "CDT samples should be bounded by ~14*sigma, got max={}",
            max_abs
        );
    }

    #[test]
    fn test_cdt_symmetry() {
        let sampler = CdtGaussianSampler::new(3.0, 64);
        let mut rng = StdRng::from_entropy();
        let n = 10000;
        let samples: Vec<i32> = (0..n).map(|_| sampler.sample(&mut rng)).collect();
        let pos_count = samples.iter().filter(|&&x| x > 0).count();
        let neg_count = samples.iter().filter(|&&x| x < 0).count();
        let ratio = pos_count as f64 / neg_count as f64;
        assert!(
            ratio > 0.85 && ratio < 1.15,
            "CDT sampler should be approximately symmetric, pos/neg ratio={}",
            ratio
        );
    }

    #[test]
    fn test_cdt_sample_poly() {
        let sampler = CdtGaussianSampler::new(3.0, 64);
        let mut rng = StdRng::from_entropy();
        let poly = sampler.sample_poly(256, &mut rng);
        assert_eq!(poly.coeffs.len(), 256);
        let max_abs = poly.coeffs.iter().map(|&x| x.unsigned_abs()).max().unwrap();
        assert!(
            (max_abs as f64) < 3.0 * 14.0,
            "Poly coefficients should be bounded by ~14*sigma, got max={}",
            max_abs
        );
    }

    #[test]
    fn test_cdt_deterministic_with_seed() {
        let sampler = CdtGaussianSampler::new(3.0, 64);
        let mut rng1 = StdRng::seed_from_u64(42);
        let mut rng2 = StdRng::seed_from_u64(42);
        for _ in 0..100 {
            let a = sampler.sample(&mut rng1);
            let b = sampler.sample(&mut rng2);
            assert_eq!(a, b);
        }
    }
}
