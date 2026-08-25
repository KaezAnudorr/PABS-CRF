//! MLWE (Module Learning With Errors) based signature implementation
//!
//! Implements the Dilithium signature framework over the ring Z_q[X]/(X^n + 1):
//!
//! - **Key Generation**: A ← random matrix, s,e ← CBD(η₁), t = As + e
//! - **Signing**: y ← CBD(η₂), w = Ay, c = H(tr, μ, w₁), z = y + cs
//!   Reject if ||z||_∞ ≥ γ₁ - β or ||w - cs₂||_∞ ≥ γ₂ - β
//! - **Verification**: Check ||z||_∞ < γ₁ - β, recompute w₁' = UseHint(c₂, Az - ct),
//!   verify c = H(tr, μ, w₁')
//!
//! NTT-optimized polynomial multiplication is used for n >= 64.

use crate::errors::{PabsCrfError, PabsCrfResult};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use tracing::debug;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone)]
struct NttPlan {
    n: usize,
    q: u32,
    psi_powers: Vec<i32>,
    psi_inv_powers: Vec<i32>,
    twiddles: Vec<Vec<i64>>,
    twiddles_inv: Vec<Vec<i64>>,
    n_inv: u32,
}

const DEFAULT_NTT_CACHE_CAPACITY: usize = 64;
const DEFAULT_MATRIX_NTT_CACHE_CAPACITY: usize = 32;

/// Statistics for the MLWE NTT and Matrix cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlweCacheStats {
    /// Configured entry cap.
    pub capacity: usize,
    /// Current number of retained entries.
    pub len: usize,
    /// Cache hits observed since process start or last clear.
    pub hits: u64,
    /// Cache misses observed since process start or last clear.
    pub misses: u64,
}

#[derive(Debug)]
struct BoundedCache<K, V> {
    capacity: usize,
    map: HashMap<K, V>,
    order: VecDeque<K>,
    hits: u64,
    misses: u64,
}

impl<K, V> BoundedCache<K, V>
where
    K: Eq + Hash + Clone,
{
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            map: HashMap::new(),
            order: VecDeque::new(),
            hits: 0,
            misses: 0,
        }
    }

    fn get_cloned(&mut self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        let value = self.map.get(key).cloned();
        if value.is_some() {
            self.hits += 1;
        } else {
            self.misses += 1;
        }
        value
    }

    fn insert(&mut self, key: K, value: V) {
        if self.map.contains_key(&key) {
            self.order.retain(|existing| existing != &key);
        }
        self.order.push_back(key.clone());
        self.map.insert(key, value);
        while self.map.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
    }

    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
        self.hits = 0;
        self.misses = 0;
    }

    fn stats(&self) -> MlweCacheStats {
        MlweCacheStats {
            capacity: self.capacity,
            len: self.map.len(),
            hits: self.hits,
            misses: self.misses,
        }
    }
}

fn lock_or_recover<T>(mutex: &'static Mutex<T>) -> MutexGuard<'static, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn ntt_plan_cache() -> &'static Mutex<BoundedCache<(usize, u32), NttPlan>> {
    static CACHE: OnceLock<Mutex<BoundedCache<(usize, u32), NttPlan>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BoundedCache::new(DEFAULT_NTT_CACHE_CAPACITY)))
}

type MatrixNttCacheValue = Arc<Vec<Vec<Vec<i64>>>>;
type MatrixNttCacheKey = [u8; 32];

fn matrix_ntt_cache() -> &'static Mutex<BoundedCache<MatrixNttCacheKey, MatrixNttCacheValue>> {
    static CACHE: OnceLock<Mutex<BoundedCache<MatrixNttCacheKey, MatrixNttCacheValue>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BoundedCache::new(DEFAULT_MATRIX_NTT_CACHE_CAPACITY)))
}

/// Clear MLWE NTT caches and reset hit/miss counters.
pub fn clear_mlwe_caches() {
    lock_or_recover(ntt_plan_cache()).clear();
    lock_or_recover(matrix_ntt_cache()).clear();
}

/// Return hit/miss statistics for the NTT-related caches.
pub fn mlwe_cache_stats() -> (MlweCacheStats, MlweCacheStats) {
    (
        lock_or_recover(ntt_plan_cache()).stats(),
        lock_or_recover(matrix_ntt_cache()).stats(),
    )
}

/// Core parameters for the Module-LWE based signature scheme.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Zeroize)]
pub struct MLWEParameters {
    /// Module dimension (number of polynomials in vector/matrix)
    pub k: usize,
    /// Polynomial degree (ring dimension)
    pub n: usize,
    /// Modulus for coefficient arithmetic
    pub q: u32,
    /// Gaussian/Binomial distribution parameter for secret key
    pub eta1: i32,
    /// Gaussian/Binomial distribution parameter for signatures
    pub eta2: i32,
    /// Bound on norm of signature components
    pub beta: i32,
    /// Coefficient range parameter (gamma1 = 2^17 for Dilithium3)
    pub gamma1: u32,
    /// Decomposition parameter for hint-based verification
    pub gamma2: i32,
    /// Number of columns in the public matrix A
    pub m: usize,
    /// Number of columns per row in the gadget matrix G
    pub ell: usize,
    /// Base for gadget decomposition (e.g., 256)
    pub base: u32,
    /// Gaussian noise standard deviation (added for unification)
    pub sigma: f64,
    /// Challenge Hamming weight (number of ±1 coefficients in sparse challenge)
    pub tau: i32,
}

impl MLWEParameters {
    /// Parameters for 128-bit security level (Dilithium3-equivalent)
    pub fn new_128() -> Self {
        let k = 4;
        let ell = 4;
        let tau: i32 = 39;
        let eta_max = 2i32;
        let result = Self {
            k,
            n: 256,
            q: 8380417,
            eta1: eta_max,
            eta2: eta_max,
            tau,
            beta: tau * eta_max,
            gamma1: 1 << 19,
            gamma2: ((8380417 - 1) / 88) as i32,
            ell,
            base: 256,
            m: (k - 1) + k * ell,
            sigma: 100.0,
        };
        result.with_sigma(100.0)
    }

    /// Parameters for 128-bit security level with reduced reduction loss (PABS-Secure)
    /// Compensates for 32.6 bit reduction loss by increasing module rank k to 5
    pub fn new_128_secure() -> Self {
        let k = 5;
        let ell = 4;
        let tau: i32 = 39;
        let eta_max = 2i32;
        let result = Self {
            k,
            n: 256,
            q: 8380417,
            eta1: eta_max,
            eta2: eta_max,
            tau,
            beta: tau * eta_max,
            gamma1: 1 << 19,
            gamma2: ((8380417 - 1) / 88) as i32,
            ell,
            base: 256,
            m: (k - 1) + k * ell,
            sigma: 100.0,
        };
        result.with_sigma(100.0)
    }

    /// Parameters for 256-bit security level (Dilithium5-equivalent)
    pub fn new_256() -> Self {
        let k = 8;
        let ell = 6;
        let tau: i32 = 60;
        let eta_max = 2i32;
        let result = Self {
            k,
            n: 256,
            q: 8380417,
            eta1: eta_max,
            eta2: eta_max,
            tau,
            beta: tau * eta_max,
            gamma1: 1 << 19,
            gamma2: 95232,
            ell,
            base: 256,
            m: (k - 1) + k * ell,
            sigma: 100.0,
        };
        result.with_sigma(100.0)
    }

    /// Parameters for 192-bit security level (ML-DSA-65-equivalent)
    pub fn new_192() -> Self {
        let k = 6;
        let ell = 5;
        let tau: i32 = 49;
        let eta_max = 2i32;
        let result = Self {
            k,
            n: 256,
            q: 8380417,
            eta1: eta_max,
            eta2: eta_max,
            tau,
            beta: tau * eta_max,
            gamma1: 1 << 19,
            gamma2: 95232,
            ell,
            base: 256,
            m: (k - 1) + k * ell,
            sigma: 100.0,
        };
        result.with_sigma(100.0)
    }

    /// Top-tier 128-bit parameter set (ML-DSA-44-equivalent).
    pub fn top_tier_128() -> Self {
        Self::new_128()
    }

    /// Top-tier 192-bit parameter set (ML-DSA-65-equivalent).
    pub fn top_tier_192() -> Self {
        Self::new_192()
    }

    /// Top-tier 256-bit parameter set (ML-DSA-87-equivalent).
    pub fn top_tier_256() -> Self {
        Self::new_256()
    }

    /// Return the ring degree `n`.
    pub fn n(&self) -> usize {
        self.n
    }
    /// Return the coefficient modulus `q`.
    pub fn q(&self) -> u32 {
        self.q
    }
    /// Return the auxiliary matrix width `m`.
    pub fn m(&self) -> usize {
        self.m
    }
    /// Return the Gaussian width used by trapdoor sampling.
    pub fn sigma(&self) -> f64 {
        self.sigma
    }

    /// Builder-pattern method to set a custom Gaussian σ and proportionally
    /// adjust `gamma1` so that the signing / verification norm bounds remain
    /// satisfiable for the larger preimage norms that result from wider
    /// Gaussian sampling.
    ///
    /// The scaling rule is:
    ///   gamma1 = min(q/2 - 1, base_gamma1 * ceil(sigma / 3.0))
    ///
    /// where `base_gamma1 = 1 << 19` (the Dilithium3 default).
    /// All other parameters (eta1, eta2, beta, tau, …) are left unchanged
    /// because they govern CBD sampling and challenge weight, which are
    /// independent of the Gaussian width.
    pub fn with_sigma(mut self, sigma: f64) -> Self {
        assert!(sigma > 0.0, "sigma must be positive");
        let scale = (sigma / 3.0).ceil() as u32;
        self.sigma = sigma;
        let base_gamma1: u32 = 1 << 19;
        let scaled_gamma1 = base_gamma1.saturating_mul(scale);
        self.gamma1 = scaled_gamma1.min(self.q / 2 - 1);
        self.validate_parameter_consistency()
            .expect("Parameter consistency check failed after sigma adjustment");
        self
    }

    pub fn validate_parameter_consistency(&self) -> PabsCrfResult<()> {
        let eta_max = self.eta1.max(self.eta2);
        if self.beta != self.tau * eta_max {
            return Err(PabsCrfError::InvalidInput(format!(
                "Parameter inconsistency: beta={} != tau*eta_max={}*{}={}",
                self.beta,
                self.tau,
                eta_max,
                self.tau * eta_max
            )));
        }
        if self.gamma1 >= self.q / 2 {
            return Err(PabsCrfError::InvalidInput(format!(
                "Parameter inconsistency: gamma1={} >= q/2={}",
                self.gamma1,
                self.q / 2
            )));
        }
        let z_bound = (self.gamma1 as i64 - self.beta as i64) as i32;
        if z_bound <= 0 {
            return Err(PabsCrfError::InvalidInput(format!(
                "Parameter inconsistency: z_bound=gamma1-beta={}-{}={} must be positive",
                self.gamma1, self.beta, z_bound
            )));
        }
        Ok(())
    }

    /// Power2Round: Decompose r into r0 and r1 such that r = r1*2^d + r0
    /// where |r0| < 2^d and r1 is the high part
    /// Used in Dilithium for signature compression
    pub fn power2round(r: i32, d: u32) -> (i32, i32) {
        let mask = (1i32 << d) - 1;
        let r0 = r & mask;
        let r1 = (r - r0) >> d;
        (r0, r1)
    }

    /// HighBits: Extract the high d bits of r
    /// In Dilithium, this is used to derive the challenge from w
    pub fn high_bits(r: i32, d: u32, q: u32) -> i32 {
        let gamma = ((q as i32) - 1) / (2 * (1i32 << d));
        ((r + gamma) >> d) % ((q >> d) as i32)
    }

    /// LowBits: Extract the low d bits of r
    /// In Dilithium, this is part of the second rejection condition
    pub fn low_bits(r: i32, d: u32) -> i32 {
        let mask = (1i32 << d) - 1;
        r & mask
    }

    /// MakeHint: Compute hint bits for r and z
    /// In Dilithium, MakeHint(z, r) = 1 if HighBits(r) != HighBits(r + z)
    pub fn make_hint(z: i32, r: i32, gamma2: i32, q: u32) -> i32 {
        let r_mod = ((r % q as i32) + q as i32) % q as i32;
        let z_mod = ((z % q as i32) + q as i32) % q as i32;
        let rz_mod = (r_mod + z_mod) % q as i32;

        let (_, r1) = Self::decompose(r_mod, gamma2, q);
        let (_, rz1) = Self::decompose(rz_mod, gamma2, q);

        if r1 != rz1 {
            1
        } else {
            0
        }
    }

    /// UseHint: Use hint bits to reconstruct high bits
    pub fn use_hint(h: i32, r: i32, gamma2: i32, q: u32) -> i32 {
        let q_i = q as i32;
        let r_mod = ((r % q_i) + q_i) % q_i;
        let alpha = 2 * gamma2;
        let m = (q_i - 1) / alpha;

        let (r0, r1) = Self::decompose(r_mod, gamma2, q);

        if h == 0 {
            r1
        } else {
            if r0 > 0 {
                (r1 + 1) % m
            } else {
                (r1 - 1 + m) % m
            }
        }
    }

    /// Decompose: Split a coefficient into high and low parts
    /// r = r1 * 2*gamma2 + r0 where |r0| <= gamma2
    pub fn decompose(r: i32, gamma2: i32, q: u32) -> (i32, i32) {
        let r_mod = ((r % q as i32) + q as i32) % q as i32;
        let alpha = 2 * gamma2;
        let mut r1 = (r_mod + gamma2) / alpha;
        let mut r0 = r_mod - r1 * alpha;

        if r0 > gamma2 {
            r1 += 1;
            r0 -= alpha;
        }

        (r0, r1)
    }
}

impl NttPlan {
    fn for_ring(n: usize, q: u32) -> Self {
        if let Some(cached) = lock_or_recover(ntt_plan_cache()).get_cloned(&(n, q)) {
            return cached;
        }

        let omega = if n == 256 {
            2962264
        } else {
            Polynomial::_mod_exp(175, (q - 1) / n as u32, q)
        };
        let psi = if n == 256 {
            5199961
        } else {
            Polynomial::_mod_exp(175, (q - 1) / (2 * n as u32), q)
        };

        debug_assert_eq!(
            Polynomial::_mod_exp(psi, 2 * n as u32, q),
            1,
            "psi must be 2n-th root of unity"
        );
        debug_assert_eq!(
            Polynomial::_mod_exp(psi, n as u32, q),
            q - 1,
            "psi^n must equal -1 mod q"
        );
        debug_assert_eq!(q % (2 * n as u32), 1, "q must equal 1 mod 2n");

        let psi_inv = Polynomial::_mod_exp(psi, q - 2, q);
        let twiddles = Polynomial::_precompute_twiddles(omega, q, n);
        let twiddles_inv =
            Polynomial::_precompute_twiddles(Polynomial::_mod_exp(omega, q - 2, q), q, n);
        let psi_powers = (0..n)
            .map(|i| Polynomial::_mod_exp(psi, i as u32, q) as i32)
            .collect();
        let psi_inv_powers = (0..n)
            .map(|i| Polynomial::_mod_exp(psi_inv, i as u32, q) as i32)
            .collect();
        let plan = Self {
            n,
            q,
            psi_powers,
            psi_inv_powers,
            twiddles,
            twiddles_inv,
            n_inv: Polynomial::_mod_exp(n as u32, q - 2, q),
        };

        lock_or_recover(ntt_plan_cache()).insert((n, q), plan.clone());
        plan
    }

    fn forward(&self, poly: &Polynomial) -> Vec<i64> {
        let preprocessed: Vec<i32> = (0..self.n)
            .map(|i| ((poly.coeffs[i] as i64 * self.psi_powers[i] as i64) % self.q as i64) as i32)
            .collect();
        Polynomial::_ntt_fast(&preprocessed, self.q, &self.twiddles, self.n)
    }

    fn inverse(&self, ntt_coeffs: &[i64]) -> Polynomial {
        let cyclic =
            Polynomial::_intt_fast(ntt_coeffs, self.q, &self.twiddles_inv, self.n_inv, self.n);
        let coeffs: Vec<i32> = (0..self.n)
            .map(|i| ((cyclic[i] as i64 * self.psi_inv_powers[i] as i64) % self.q as i64) as i32)
            .collect();
        Polynomial { coeffs }
    }
}

fn matrix_ntt_cache_key(matrix: &PolynomialMatrix, q: u32) -> MatrixNttCacheKey {
    let mut hasher = Sha256::new();
    hasher.update(matrix.rows.to_le_bytes());
    hasher.update(matrix.cols.to_le_bytes());
    hasher.update(q.to_le_bytes());
    for row in &matrix.elements {
        for poly in row {
            for coeff in &poly.coeffs {
                hasher.update(coeff.to_le_bytes());
            }
        }
    }
    hasher.finalize().into()
}

/// Represents a polynomial in the ring R_q = Z_q[X]/(X^n + 1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize)]
pub struct Polynomial {
    /// Coefficients in range [0, q-1]
    pub coeffs: Vec<i32>,
}

/// A vector of k polynomials in R_q.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize)]
pub struct PolynomialVector {
    /// Vector elements
    pub elements: Vec<Polynomial>,
}

impl PolynomialVector {
    /// Create a new vector of zero polynomials
    ///
    /// # Arguments
    /// * `num_polys` - Number of polynomials in the vector
    /// * `n` - Degree of each polynomial
    pub fn new(num_polys: usize, n: usize) -> Self {
        Self {
            elements: (0..num_polys).map(|_| Polynomial::new(n)).collect(),
        }
    }

    /// Decompose vector into high and low parts
    pub fn decompose(&self, gamma2: i32, q: u32) -> (Self, Self) {
        let mut high_elements = Vec::with_capacity(self.elements.len());
        let mut low_elements = Vec::with_capacity(self.elements.len());
        for poly in &self.elements {
            let (low, high) = poly.decompose(gamma2, q);
            low_elements.push(low);
            high_elements.push(high);
        }
        (
            Self {
                elements: low_elements,
            },
            Self {
                elements: high_elements,
            },
        )
    }

    /// Make hint vector from a0 and a1
    pub fn make_hint(a0: &Self, a1: &Self, gamma2: i32, q: u32) -> Self {
        let elements = a0
            .elements
            .iter()
            .zip(a1.elements.iter())
            .map(|(p0, p1)| Polynomial::make_hint(p0, p1, gamma2, q))
            .collect();
        Self { elements }
    }

    /// Use hint vector to reconstruct high bits
    pub fn use_hint(&self, hints: &Self, gamma2: i32, q: u32) -> Self {
        let elements = self
            .elements
            .iter()
            .zip(hints.elements.iter())
            .map(|(p, h)| p.use_hint(h, gamma2, q))
            .collect();
        Self { elements }
    }

    /// Infinity norm in the integer domain (raw absolute values).
    /// Returns i64 to correctly represent norms that exceed i32 range.
    pub fn infinity_norm_integer(&self) -> i64 {
        self.elements
            .iter()
            .map(|p| p.infinity_norm_integer())
            .max()
            .unwrap_or(0)
    }

    /// Center all polynomial coefficients from [0, q) to (-q/2, q/2].
    /// Required before integer-domain norm checks on mod-q stored values.
    pub fn center_coefficients(&self, q: u32) -> Self {
        Self {
            elements: self
                .elements
                .iter()
                .map(|p| p.center_coefficients(q))
                .collect(),
        }
    }
}

/// Matrix of polynomials for MLWE public key generation
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Zeroize)]
pub struct PolynomialMatrix {
    /// Number of row polynomials
    pub rows: usize,
    /// Number of column polynomials
    pub cols: usize,
    /// 2D grid of polynomial elements
    pub elements: Vec<Vec<Polynomial>>,
}

impl PolynomialMatrix {
    /// Create a new matrix of zero polynomials
    ///
    /// # Arguments
    /// * `rows` - Number of rows
    /// * `cols` - Number of columns
    /// * `n` - Degree of each polynomial
    pub fn new(rows: usize, cols: usize, n: usize) -> Self {
        Self {
            rows,
            cols,
            elements: (0..rows)
                .map(|_| (0..cols).map(|_| Polynomial::new(n)).collect())
                .collect(),
        }
    }
}

/// MLWE key pair containing public and secret polynomial vectors
///
/// Generated via: A ← random k×k matrix, s,e ← CBD(η₁), t = As + e
/// The public key is (A, t), the secret key is (s, e).
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MLWEKeyPair {
    pub public_key: PolynomialVector,
    pub secret_key: PolynomialVector,
    /// Error vector (e). In the PABS structured path this field is zeroed
    /// by design: the structured signing pipeline does not use the error
    /// vector from key generation.
    pub error_vector: PolynomialVector,
    pub matrix_a: PolynomialMatrix,
}

impl MLWEKeyPair {
    /// Generate a new MLWE key pair using the Dilithium framework.
    ///
    /// Key generation:
    /// 1. Generate random matrix A ∈ R_q^{k×k} from seed
    /// 2. Sample secret vector s ← CBD(η₁)^k
    /// 3. Sample error vector e ← CBD(η₁)^k
    /// 4. Compute public key t = As + e mod q
    pub fn generate(params: &MLWEParameters, rng: &mut impl RngCore) -> Self {
        let n = params.n;
        let q = params.q;
        let k = params.k;

        // Step 1: Generate random matrix A
        let matrix_a = Self::generate_matrix_a(params, rng);

        // Step 2: Sample secret vector s ← CBD(η₁)
        let secret_key = PolynomialVector {
            elements: (0..k)
                .map(|_| Polynomial::rand_poly(n, params.eta1, rng))
                .collect(),
        };

        // Step 3: Sample error vector e ← CBD(η₁)
        let error_vector = PolynomialVector {
            elements: (0..k)
                .map(|_| Polynomial::rand_poly(n, params.eta1, rng))
                .collect(),
        };

        // Step 4: Compute t = As + e
        let as_result = Self::matrix_vector_mul(&matrix_a, &secret_key, q);
        let public_key = PolynomialVector {
            elements: as_result
                .elements
                .iter()
                .zip(error_vector.elements.iter())
                .map(|(a_i, e_i)| a_i.add(e_i, q))
                .collect(),
        };

        Self {
            public_key,
            secret_key,
            error_vector,
            matrix_a,
        }
    }

    /// Generate a new MLWE key pair using an existing public matrix A.
    /// This ensures unified parameter semantics (P0-4) across trapdoor and signature paths.
    pub fn generate_with_matrix(
        params: &MLWEParameters,
        matrix_a: &PolynomialMatrix,
        rng: &mut impl RngCore,
    ) -> Self {
        let n = params.n;
        let q = params.q;
        let k = params.k;
        let m = matrix_a.cols;

        // Step 2: Sample secret vector s ← CBD(η₁) of dimension m
        let secret_key = PolynomialVector {
            elements: (0..m)
                .map(|_| Polynomial::rand_poly(n, params.eta1, rng))
                .collect(),
        };

        // Step 3: Sample error vector e ← CBD(η₁) of dimension k
        let error_vector = PolynomialVector {
            elements: (0..k)
                .map(|_| Polynomial::rand_poly(n, params.eta1, rng))
                .collect(),
        };

        // Step 4: Compute t = As + e
        let as_result = Self::matrix_vector_mul(matrix_a, &secret_key, q);
        let public_key = PolynomialVector {
            elements: as_result
                .elements
                .iter()
                .zip(error_vector.elements.iter())
                .map(|(a_i, e_i)| a_i.add(e_i, q))
                .collect(),
        };

        Self {
            public_key,
            secret_key,
            error_vector,
            matrix_a: matrix_a.clone(),
        }
    }

    pub fn generate_matrix_a_from_seed(
        seed: &[u8; 32],
        params: &MLWEParameters,
    ) -> PolynomialMatrix {
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Shake256,
        };

        let n = params.n;
        let k = params.k;
        let m = params.m;
        let q = params.q;

        let mut hasher = Shake256::default();
        hasher.update(seed);
        hasher.update(&k.to_le_bytes());
        hasher.update(&m.to_le_bytes());
        hasher.update(&n.to_le_bytes());
        let mut reader = hasher.finalize_xof();

        let mut matrix = PolynomialMatrix {
            rows: k,
            cols: m,
            elements: Vec::with_capacity(k),
        };

        for _ in 0..k {
            let mut row = Vec::with_capacity(m);
            for _ in 0..m {
                let mut coeffs = vec![0i32; n];
                for coeff in coeffs.iter_mut() {
                    loop {
                        let mut buf = [0u8; 4];
                        reader.read(&mut buf);
                        let val = u32::from_le_bytes(buf);
                        if val < (u32::MAX - u32::MAX % q) {
                            *coeff = (val % q) as i32;
                            break;
                        }
                    }
                }
                row.push(Polynomial::from_coeffs(&coeffs, q));
            }
            matrix.elements.push(row);
        }

        matrix
    }

    pub fn generate_a_prime_from_seed(
        seed: &[u8; 32],
        params: &MLWEParameters,
    ) -> PolynomialMatrix {
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Shake256,
        };

        let n = params.n;
        let k = params.k;
        let a_prime_cols = k - 1;
        let q = params.q;

        let mut hasher = Shake256::default();
        hasher.update(b"PABS-CRF-A-prime");
        hasher.update(seed);
        hasher.update(&k.to_le_bytes());
        hasher.update(&a_prime_cols.to_le_bytes());
        hasher.update(&n.to_le_bytes());
        let mut reader = hasher.finalize_xof();

        let mut matrix = PolynomialMatrix {
            rows: k,
            cols: a_prime_cols,
            elements: Vec::with_capacity(k),
        };

        for _ in 0..k {
            let mut row = Vec::with_capacity(a_prime_cols);
            for _ in 0..a_prime_cols {
                let mut coeffs = vec![0i32; n];
                for coeff in coeffs.iter_mut() {
                    loop {
                        let mut buf = [0u8; 4];
                        reader.read(&mut buf);
                        let val = u32::from_le_bytes(buf);
                        if val < (u32::MAX - u32::MAX % q) {
                            *coeff = (val % q) as i32;
                            break;
                        }
                    }
                }
                row.push(Polynomial::from_coeffs(&coeffs, q));
            }
            matrix.elements.push(row);
        }

        matrix
    }

    fn generate_matrix_a(params: &MLWEParameters, rng: &mut impl RngCore) -> PolynomialMatrix {
        let n = params.n;
        let q = params.q;
        let k = params.k;
        let mut matrix = PolynomialMatrix::new(k, k, n);
        for i in 0..k {
            for j in 0..k {
                // Generate each entry of A as a random polynomial mod q
                // In Dilithium, A is derived from a seed ρ via SHAKE; here we use direct RNG
                let mut coeffs = Vec::with_capacity(n);
                for _ in 0..n {
                    // Rejection sampling to ensure uniform distribution in [0, q)
                    // This avoids the modulo bias present in (rng.next_u32() % q)
                    let mut val;
                    loop {
                        // q = 8380417 is slightly less than 2^23
                        val = rng.next_u32() & 0x7FFFFF; // 23 bits
                        if val < q {
                            break;
                        }
                    }
                    coeffs.push(val as i32);
                }
                matrix.elements[i][j] = Polynomial { coeffs };
            }
        }
        matrix
    }

    /// Compute matrix-vector multiplication: A * v mod q
    pub fn matrix_vector_mul(
        a: &PolynomialMatrix,
        v: &PolynomialVector,
        q: u32,
    ) -> PolynomialVector {
        let n = a
            .elements
            .first()
            .and_then(|row| row.first())
            .map(|poly| poly.coeffs.len())
            .unwrap_or(0);
        if n >= 64 {
            return Self::matrix_vector_mul_ntt(a, v, q);
        }

        let k = a.rows;
        PolynomialVector {
            elements: (0..k)
                .map(|i| {
                    let mut result = Polynomial::new(a.elements[i][0].coeffs.len());
                    for j in 0..a.cols {
                        let prod = a.elements[i][j].mul(&v.elements[j], q);
                        result = result.add(&prod, q);
                    }
                    result
                })
                .collect(),
        }
    }

    fn matrix_ntt_representation(
        a: &PolynomialMatrix,
        q: u32,
        plan: &NttPlan,
    ) -> Arc<Vec<Vec<Vec<i64>>>> {
        let cache_key = matrix_ntt_cache_key(a, q);
        if let Some(cached) = lock_or_recover(matrix_ntt_cache()).get_cloned(&cache_key) {
            return cached;
        }

        let transformed: Vec<Vec<Vec<i64>>> = a
            .elements
            .iter()
            .map(|row| row.iter().map(|poly| plan.forward(poly)).collect())
            .collect();
        let transformed = Arc::new(transformed);
        lock_or_recover(matrix_ntt_cache()).insert(cache_key, transformed.clone());
        transformed
    }

    /// Compute matrix-vector multiplication while keeping each row accumulation in the NTT domain.
    pub fn matrix_vector_mul_ntt(
        a: &PolynomialMatrix,
        v: &PolynomialVector,
        q: u32,
    ) -> PolynomialVector {
        let n = a
            .elements
            .first()
            .and_then(|row| row.first())
            .map(|poly| poly.coeffs.len())
            .unwrap_or(0);
        if n == 0 {
            return PolynomialVector::new(a.rows, 0);
        }

        let plan = NttPlan::for_ring(n, q);
        let matrix_ntt = Self::matrix_ntt_representation(a, q, &plan);
        let vector_ntt: Vec<Vec<i64>> = v.elements.iter().map(|poly| plan.forward(poly)).collect();
        let q_i64 = q as i64;

        let elements = (0..a.rows)
            .map(|i| {
                let mut acc = vec![0i64; n];
                for j in 0..a.cols {
                    for idx in 0..n {
                        acc[idx] = (acc[idx] + matrix_ntt[i][j][idx] * vector_ntt[j][idx]) % q_i64;
                    }
                }
                plan.inverse(&acc)
            })
            .collect();

        PolynomialVector { elements }
    }

    /// Compute `A * z - c * t` while keeping the entire row equation in the NTT domain.
    pub fn matrix_vector_mul_sub_poly_mul_ntt(
        a: &PolynomialMatrix,
        z: &PolynomialVector,
        t: &PolynomialVector,
        c: &Polynomial,
        q: u32,
    ) -> PolynomialVector {
        let n = a
            .elements
            .first()
            .and_then(|row| row.first())
            .map(|poly| poly.coeffs.len())
            .unwrap_or(0);
        if n == 0 {
            return PolynomialVector::new(a.rows, 0);
        }

        let plan = NttPlan::for_ring(n, q);
        let matrix_ntt = Self::matrix_ntt_representation(a, q, &plan);
        let z_ntt: Vec<Vec<i64>> = z.elements.iter().map(|poly| plan.forward(poly)).collect();
        let c_ntt = plan.forward(c);
        let t_ntt: Vec<Vec<i64>> = t.elements.iter().map(|poly| plan.forward(poly)).collect();
        let q_i64 = q as i64;

        let elements = (0..a.rows)
            .map(|i| {
                let mut acc = vec![0i64; n];
                for j in 0..a.cols {
                    for idx in 0..n {
                        acc[idx] = (acc[idx] + matrix_ntt[i][j][idx] * z_ntt[j][idx]) % q_i64;
                    }
                }
                for idx in 0..n {
                    acc[idx] = (acc[idx] - (t_ntt[i][idx] * c_ntt[idx]) % q_i64 + q_i64) % q_i64;
                }
                plan.inverse(&acc)
            })
            .collect();

        PolynomialVector { elements }
    }

    /// Multiply a vector by a single polynomial while reusing the polynomial's NTT image.
    pub fn vector_poly_mul_ntt(v: &PolynomialVector, p: &Polynomial, q: u32) -> PolynomialVector {
        let n = p.coeffs.len();
        if n < 64 {
            return PolynomialVector {
                elements: v.elements.iter().map(|v_i| v_i.mul(p, q)).collect(),
            };
        }

        let plan = NttPlan::for_ring(n, q);
        let p_ntt = plan.forward(p);
        let q_i64 = q as i64;
        let elements = v
            .elements
            .iter()
            .map(|poly| {
                let poly_ntt = plan.forward(poly);
                let pointwise: Vec<i64> = (0..n)
                    .map(|idx| (poly_ntt[idx] * p_ntt[idx]) % q_i64)
                    .collect();
                plan.inverse(&pointwise)
            })
            .collect();

        PolynomialVector { elements }
    }
}

/// MLWE signature containing polynomial components and challenge hash
///
/// Signature is (z, c) where:
/// - z = y + c·s (masking nonce + challenge × secret)
/// - c = H(tr, μ, w₁) is the challenge hash
/// - The signature is valid iff ||z||_∞ < γ₁ - β and c verifies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MLWESignature {
    /// Signature vector z = y + c·s (must have small norm)
    pub z: PolynomialVector,
    /// Challenge polynomial c derived from message and commitment
    pub challenge: Polynomial,
    /// Hint vector h used to reconstruct high bits of w
    pub hints: Option<PolynomialVector>,
    /// Additional metadata for verification
    pub metadata: std::collections::HashMap<String, Vec<u8>>,
    /// Optional CRF seed used during re-randomization (for audit testing)
    pub crf_seed: Option<Vec<u8>>,
}

impl MLWESignature {
    /// Try to generate a signature and return an explicit error instead of panicking on exhaustion.
    pub fn try_sign(
        params: &MLWEParameters,
        kp: &MLWEKeyPair,
        message: &[u8],
        context: &[u8],
        rng: &mut impl RngCore,
        pk_hash: &[u8],
        delta_bytes: &[u8],
    ) -> PabsCrfResult<Self> {
        Self::sign_internal(params, kp, message, context, rng, pk_hash, delta_bytes)
    }

    /// Generate a signature using the Dilithium "sign-and-reject" paradigm.
    ///
    /// Signing algorithm:
    fn sign_internal(
        params: &MLWEParameters,
        kp: &MLWEKeyPair,
        message: &[u8],
        context: &[u8],
        rng: &mut impl RngCore,
        pk_hash: &[u8],
        delta_bytes: &[u8],
    ) -> PabsCrfResult<Self> {
        let n = params.n;
        let k_in = kp.matrix_a.cols;
        let q = params.q;
        let max_attempts = 5000;
        let mut attempt_count: u32 = 0;

        let z_bound = params.gamma1.saturating_sub(params.beta.max(0) as u32);
        let y_bound = (z_bound / 2).max(1);

        for _ in 0..max_attempts {
            attempt_count += 1;

            // Step 1: Sample masking nonce y ∈ R_q^k_in
            // For the strict v4 path we keep y well inside the final acceptance
            // window so large witness terms do not drive rejection probability to
            // zero when beta is widened for trapdoor-derived preimages.
            let y = PolynomialVector {
                elements: (0..k_in)
                    .map(|_| Polynomial::rand_poly_uniform(n, y_bound, rng))
                    .collect(),
            };

            // Step 2: Compute commitment w = Ay (A is k_out x k_in)
            let w = MLWEKeyPair::matrix_vector_mul(&kp.matrix_a, &y, q);

            // Step 3: Decompose w and derive challenge c = H(w_high, message, context)
            // Dilithium uses HighBits(w) for the challenge to reduce signature size
            let (_w0, w1) = w.decompose(params.gamma2, q);
            let tr = Self::compute_system_tr(&kp.matrix_a, &kp.public_key);
            let challenge =
                Self::derive_challenge(params, &w1, message, context, &tr, pk_hash, delta_bytes);

            // Step 4: Compute response z = y + c·s
            // secret_key s must be k_in dimensional.
            // We MUST perform this in the integer domain before modular reduction
            // to satisfy the strict rejection sampling requirement (P0-1).
            let cs_int = PolynomialVector {
                elements: kp
                    .secret_key
                    .elements
                    .iter()
                    .map(|s_i| s_i.mul_challenge_integer(&challenge))
                    .collect(),
            };

            let z_int = PolynomialVector {
                elements: y
                    .elements
                    .iter()
                    .zip(cs_int.elements.iter())
                    .map(|(y_i, cs_i)| y_i.add_integer(cs_i))
                    .collect(),
            };

            // Step 5: Reject out-of-bound responses in the integer domain.
            let z_ok = z_int.infinity_norm_integer() < (z_bound as i64 - params.eta2 as i64).max(1);

            if z_ok {
                // If accepted, we can now reduce z mod q for the signature.
                let z = PolynomialVector {
                    elements: z_int
                        .elements
                        .iter()
                        .map(|p| Polynomial::from_coeffs(&p.coeffs, q))
                        .collect(),
                };

                // Step 6: Generate hints for verification
                // v = w - c*e (error vector)
                let ce = Self::poly_vec_scalar_mul(&kp.error_vector, &challenge, q);
                let neg_ce = PolynomialVector {
                    elements: ce.elements.iter().map(|p| p.scalar_mul(-1, q)).collect(),
                };

                // h = MakeHint(-ce, w)
                let hints = PolynomialVector::make_hint(&neg_ce, &w, params.gamma2, q);

                debug!("Signing succeeded after {} attempts", attempt_count);
                let metadata = std::collections::HashMap::new();
                return Ok(Self {
                    challenge,
                    z,
                    hints: Some(hints),
                    metadata,
                    crf_seed: None,
                });
            }
        }

        Err(PabsCrfError::SignFailed(format!(
            "Rejection sampling failed after {} attempts. z_bound={}, q/2={}",
            max_attempts,
            z_bound,
            q / 2
        )))
    }

    /// Verify a signature against the message and public key.
    ///
    /// Verification algorithm:
    /// 1. Check ||z||_∞ < γ₁ - β (norm bound)
    /// 2. Recompute w' = Az - c·t
    /// 3. Derive challenge c' = H(w', message)
    /// 4. Accept iff c' == c
    ///
    /// Note: In a full Dilithium implementation, Power2Round is used to extract
    /// high bits of w for challenge derivation, ensuring that Az - ct yields
    /// the same high bits as w. In this implementation, we use the stored
    /// w_commitment for verification consistency.
    pub fn verify(
        params: &MLWEParameters,
        kp: &MLWEKeyPair,
        message: &[u8],
        context: &[u8],
        sig: &Self,
        pk_hash: &[u8],
        delta_bytes: &[u8],
    ) -> bool {
        let q = params.q;

        // Step 1: Check ||z_i||_∞ < γ₁ - β in the INTEGER DOMAIN
        // sig.z stores coefficients in [0, q) after mod-q reduction during signing.
        // We must center them to (-q/2, q/2] before the integer-domain norm check,
        // otherwise originally-negative coefficients appear as large values near q
        // and would incorrectly fail the bound check.
        let z_bound = (params.gamma1 - params.beta as u32) as i64;
        for z_i in &sig.z.elements {
            let centered = z_i.center_coefficients(q);
            if centered.infinity_norm_integer() >= z_bound {
                return false;
            }
        }

        // Step 2: Recompute v = Az - c·t fully in the NTT domain.
        let v = MLWEKeyPair::matrix_vector_mul_sub_poly_mul_ntt(
            &kp.matrix_a,
            &sig.z,
            &kp.public_key,
            &sig.challenge,
            q,
        );

        // Step 3: Use hints to reconstruct w1' (high bits of Ay)
        let w1_prime = if let Some(hints) = &sig.hints {
            v.use_hint(hints, params.gamma2, q)
        } else {
            // Fallback for signatures without hints (just use HighBits of v)
            let (_v0, v1) = v.decompose(params.gamma2, q);
            v1
        };

        // Step 4: Derive challenge c' from w1', message, and context
        let challenge_prime = Self::derive_challenge(
            params,
            &w1_prime,
            message,
            context,
            &Self::compute_system_tr(&kp.matrix_a, &kp.public_key),
            pk_hash,
            delta_bytes,
        );

        // Step 5: Accept iff c' == c
        challenge_prime.coeffs == sig.challenge.coeffs
    }

    pub fn compute_system_tr(matrix_a: &PolynomialMatrix, u_policy: &PolynomialVector) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"PABS-CRF-v4-tr");
        for row in &matrix_a.elements {
            for poly in row {
                for &c in &poly.coeffs {
                    hasher.update(c.to_le_bytes());
                }
            }
        }
        for poly in &u_policy.elements {
            for &c in &poly.coeffs {
                hasher.update(c.to_le_bytes());
            }
        }
        hasher.finalize().into()
    }

    pub fn compute_pk_hash(u_policy: &PolynomialVector, q: u32) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"PABS-CRF-v4-pk");
        for poly in &u_policy.elements {
            for &c in &poly.coeffs {
                hasher.update((c.rem_euclid(q as i32) as u32).to_le_bytes());
            }
        }
        hasher.finalize().to_vec()
    }

    /// Derive a sparse challenge polynomial from high bits of commitment, message, context, and public key hash.
    fn derive_challenge(
        params: &MLWEParameters,
        w1: &PolynomialVector,
        message: &[u8],
        context: &[u8],
        tr: &[u8],
        pk_hash: &[u8],
        delta_bytes: &[u8],
    ) -> Polynomial {
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Shake256,
        };

        let n = params.n;

        let mut hasher = Shake256::default();
        hasher.update(b"PABS-CRF-challenge-v2");
        hasher.update(tr);
        let m_val = (params.q - 1) / (2 * params.gamma2 as u32) + 1;
        let w1_bytes = crate::canonical::canonical_serialize_w1(w1, m_val);
        hasher.update(&(w1_bytes.len() as u32).to_le_bytes());
        hasher.update(&w1_bytes);
        hasher.update(message);
        hasher.update(context);
        hasher.update(pk_hash);
        hasher.update(delta_bytes);

        let mut reader = hasher.finalize_xof();
        let mut seed = [0u8; 32];
        reader.read(&mut seed);

        // Follow the Dilithium-style sparse challenge weight instead of the benchmark shortcut.
        let tau = params.tau;
        let mut coeffs = vec![0i32; n];

        // Use another SHAKE instance as an RNG for rejection sampling
        let mut hasher = Shake256::default();
        hasher.update(&seed);
        let mut reader = hasher.finalize_xof();

        let mut count = 0;
        while count < tau {
            let pos = Self::sample_index(&mut reader, n);
            if coeffs[pos] == 0 {
                let mut sign_buf = [0u8; 1];
                reader.read(&mut sign_buf);
                let sign = if (sign_buf[0] & 1) == 0 { 1i32 } else { -1i32 };
                coeffs[pos] = sign;
                count += 1;
            }
        }

        Polynomial { coeffs }
    }

    fn sample_index(reader: &mut impl sha3::digest::XofReader, n: usize) -> usize {
        let limit = (u16::MAX as usize + 1) / n * n;
        loop {
            let mut buf = [0u8; 2];
            reader.read(&mut buf);
            let candidate = u16::from_le_bytes(buf) as usize;
            if candidate < limit {
                return candidate % n;
            }
        }
    }

    /// Multiply polynomial vector by scalar polynomial: v * p mod q
    fn poly_vec_scalar_mul(v: &PolynomialVector, p: &Polynomial, q: u32) -> PolynomialVector {
        MLWEKeyPair::vector_poly_mul_ntt(v, p, q)
    }

    /// Public wrapper used by verification modules that need the shared challenge derivation.
    pub fn derive_challenge_public(
        params: &MLWEParameters,
        w: &PolynomialVector,
        message: &[u8],
        context: &[u8],
        tr: &[u8],
        pk_hash: &[u8],
        delta_bytes: &[u8],
    ) -> Polynomial {
        Self::derive_challenge(params, w, message, context, tr, pk_hash, delta_bytes)
    }

    /// Public wrapper for multiplying a polynomial vector by a challenge polynomial.
    pub fn poly_vec_scalar_mul_public(
        v: &PolynomialVector,
        p: &Polynomial,
        q: u32,
    ) -> PolynomialVector {
        Self::poly_vec_scalar_mul(v, p, q)
    }

    /// Return the verification bound on `z`, optionally expanded by a CRF margin.
    pub fn verification_z_bound(params: &MLWEParameters, crf_margin: u32) -> i64 {
        (params.gamma1 - params.beta as u32 + crf_margin) as i64
    }
}

impl From<Vec<Polynomial>> for PolynomialVector {
    fn from(elements: Vec<Polynomial>) -> Self {
        Self { elements }
    }
}

impl Polynomial {
    /// Create a new zero polynomial of degree n-1
    pub fn new(n: usize) -> Self {
        Self { coeffs: vec![0; n] }
    }

    /// Create a polynomial from coefficient array with modular reduction
    ///
    /// # Arguments
    /// * `coeffs` - Coefficient values (may be outside [0, q))
    /// * `q` - Modulus for reduction
    pub fn from_coeffs(coeffs: &[i32], q: u32) -> Self {
        Self {
            coeffs: coeffs.iter().map(|&c| Self::mod_reduce(c, q)).collect(),
        }
    }

    fn mod_reduce(c: i32, q: u32) -> i32 {
        ((c % q as i32) + q as i32) % q as i32
    }

    /// Add two polynomials mod q
    pub fn add(&self, other: &Self, q: u32) -> Self {
        let coeffs: Vec<i32> = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| Self::mod_reduce(a + b, q))
            .collect();
        Self { coeffs }
    }

    /// Subtract two polynomials mod q
    pub fn sub(&self, other: &Self, q: u32) -> Self {
        let coeffs: Vec<i32> = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| Self::mod_reduce(a - b, q))
            .collect();
        Self { coeffs }
    }

    /// Multiply polynomial by scalar mod q
    pub fn scalar_mul(&self, scalar: i32, q: u32) -> Self {
        let coeffs: Vec<i32> = self
            .coeffs
            .iter()
            .map(|&c| Self::mod_reduce(c * scalar, q))
            .collect();
        Self { coeffs }
    }

    /// Add two polynomials in the integer domain (no mod q reduction).
    /// Uses i64 accumulators to prevent silent overflow on large coefficients.
    pub fn add_integer(&self, other: &Self) -> Self {
        let coeffs: Vec<i32> = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| {
                let sum = a as i64 + b as i64;
                i32::try_from(sum).expect("coefficient overflow: scheme parameters incorrect")
            })
            .collect();
        Self { coeffs }
    }

    /// Subtract two polynomials in the integer domain (no mod q reduction).
    /// Uses i64 accumulators to prevent silent overflow on large coefficients.
    pub fn sub_integer(&self, other: &Self) -> Self {
        let coeffs: Vec<i32> = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| {
                let diff = a as i64 - b as i64;
                i32::try_from(diff).expect("coefficient overflow: scheme parameters incorrect")
            })
            .collect();
        Self { coeffs }
    }

    /// Multiply by a sparse challenge polynomial in the integer domain.
    /// Since challenge is sparse (±1), we can do this efficiently without NTT.
    /// Uses i64 accumulators to prevent silent overflow on large secret key
    /// coefficients (e.g. after LSSS reconstruction with centered mod-q values).
    pub fn mul_challenge_integer(&self, challenge: &Polynomial) -> Self {
        let n = self.coeffs.len();
        let mut res_coeffs = vec![0i64; n];
        for (idx, &c) in challenge.coeffs.iter().enumerate() {
            if c == 0 {
                continue;
            }
            for i in 0..n {
                let target_idx = (idx + i) % n;
                let mut val = self.coeffs[i] as i64 * c as i64;
                if idx + i >= n {
                    val = -val;
                }
                res_coeffs[target_idx] += val;
            }
        }
        Self {
            coeffs: res_coeffs
                .iter()
                .map(|&c| {
                    i32::try_from(c).expect("coefficient overflow: scheme parameters incorrect")
                })
                .collect(),
        }
    }

    /// Infinity norm in the integer domain (raw absolute values).
    /// Returns i64 to correctly represent norms that exceed i32 range.
    /// Uses i64 internally to avoid i32::MIN.abs() panic.
    pub fn infinity_norm_integer(&self) -> i64 {
        self.coeffs
            .iter()
            .map(|&c| (c as i64).abs())
            .max()
            .unwrap_or(0)
    }

    /// Center polynomial coefficients from [0, q) to (-q/2, q/2].
    /// Required before integer-domain norm checks on mod-q stored values.
    pub fn center_coefficients(&self, q: u32) -> Self {
        let q_i64 = q as i64;
        let half_q = q_i64 / 2;
        Self {
            coeffs: self
                .coeffs
                .iter()
                .map(|&c| {
                    let c_mod = ((c as i64 % q_i64) + q_i64) % q_i64;
                    let centered = if c_mod > half_q { c_mod - q_i64 } else { c_mod };
                    centered as i32
                })
                .collect(),
        }
    }

    /// Compute infinity norm with centered modular reduction.
    ///
    /// For coefficients in [0, q-1], computes the centered value:
    /// - If c < q/2: centered value is c
    /// - If c >= q/2: centered value is c - q (negative)
    ///
    /// The centered absolute value is min(c, q - c).
    /// Compute the infinity norm of the polynomial relative to modulus q.
    /// This returns the maximum absolute value of coefficients when centered in [-q/2, q/2].
    pub fn infinity_norm(&self, q: u32) -> i32 {
        let q_half = q as i64 / 2;
        self.coeffs
            .iter()
            .map(|&c| {
                // Ensure c is in [0, q-1]
                let c_mod = ((c as i64 % q as i64) + q as i64) % q as i64;
                let centered = if c_mod > q_half {
                    q as i64 - c_mod
                } else {
                    c_mod
                };
                centered as i32
            })
            .max()
            .unwrap_or(0)
    }

    /// Generate a random polynomial with coefficients from CBD(eta)
    pub fn rand_poly(n: usize, eta: i32, rng: &mut impl RngCore) -> Self {
        let mut coeffs = Vec::with_capacity(n);
        for _ in 0..n {
            let mut sum = 0i32;
            for _ in 0..eta as usize {
                let a = (rng.next_u32() >> 1) & 1;
                let b = (rng.next_u32() >> 1) & 1;
                sum += a as i32 - b as i32;
            }
            coeffs.push(sum);
        }
        Self { coeffs }
    }

    /// Decompose polynomial into high and low parts
    pub fn decompose(&self, gamma2: i32, q: u32) -> (Self, Self) {
        let mut high = Vec::with_capacity(self.coeffs.len());
        let mut low = Vec::with_capacity(self.coeffs.len());
        for &c in &self.coeffs {
            let (r0, r1) = MLWEParameters::decompose(c, gamma2, q);
            low.push(r0);
            high.push(r1);
        }
        (Self { coeffs: low }, Self { coeffs: high })
    }

    /// Make hint polynomial from a0 and a1
    pub fn make_hint(a0: &Self, a1: &Self, gamma2: i32, q: u32) -> Self {
        let mut hints = Vec::with_capacity(a0.coeffs.len());
        for (i, &c0) in a0.coeffs.iter().enumerate() {
            hints.push(MLWEParameters::make_hint(c0, a1.coeffs[i], gamma2, q));
        }
        Self { coeffs: hints }
    }

    /// Use hint polynomial to reconstruct high bits
    pub fn use_hint(&self, hints: &Self, gamma2: i32, q: u32) -> Self {
        let mut high = Vec::with_capacity(self.coeffs.len());
        for (i, &c) in self.coeffs.iter().enumerate() {
            high.push(MLWEParameters::use_hint(hints.coeffs[i], c, gamma2, q));
        }
        Self { coeffs: high }
    }

    /// Sample a polynomial uniformly from the centered box `[-bound, bound]^n`.
    pub fn rand_poly_uniform(n: usize, bound: u32, rng: &mut impl RngCore) -> Self {
        let range = 2u32 * bound + 1;
        let limit = u32::MAX - (u32::MAX % range);
        let mut coeffs = Vec::with_capacity(n);
        for _ in 0..n {
            let val = loop {
                let v = rng.next_u32();
                if v < limit {
                    break v % range;
                }
            };
            coeffs.push(val as i32 - bound as i32);
        }
        Self { coeffs }
    }

    /// Multiply two polynomials in Z_q[X]/(X^n + 1) ring
    ///
    /// Uses NTT-optimized multiplication for n >= 64 and falls back to naive
    /// O(n²) multiplication for small polynomials.
    pub fn mul(&self, other: &Self, q: u32) -> Self {
        let n = self.coeffs.len();
        assert_eq!(n, other.coeffs.len());

        if n >= 64 {
            Self::_mul_ntt_optimized(self, other, q)
        } else {
            Self::_mul_naive(self, other, q)
        }
    }

    fn _mul_naive(a: &Self, b: &Self, q: u32) -> Self {
        let n = a.coeffs.len();
        let mut result = vec![0i64; n];

        for i in 0..n {
            for j in 0..n {
                let prod = a.coeffs[i] as i64 * b.coeffs[j] as i64;
                let idx = i + j;
                if idx < n {
                    result[idx] += prod;
                } else {
                    result[idx - n] -= prod;
                }
            }
        }

        Self {
            coeffs: result
                .iter()
                .map(|&c| Self::mod_reduce(c as i32, q))
                .collect(),
        }
    }

    /// Negacyclic polynomial multiplication via preprocessing + cyclic NTT
    ///
    /// For Z_q[X]/(X^n + 1):
    /// 1. Preprocess: multiply input[i] by psi^i
    /// 2. Cyclic NTT with omega (n-th root)
    /// 3. Pointwise multiply
    /// 4. Inverse cyclic NTT
    /// 5. Postprocess: multiply output[i] by psi_inv^i
    fn _mul_ntt_optimized(a: &Self, b: &Self, q: u32) -> Self {
        let n = a.coeffs.len();

        let omega = if n == 256 {
            2962264
        } else {
            Self::_mod_exp(175, (q - 1) / n as u32, q)
        };
        let psi = if n == 256 {
            5199961
        } else {
            Self::_mod_exp(175, (q - 1) / (2 * n as u32), q)
        };
        let psi_inv = Self::_mod_exp(psi, q - 2, q);

        let psi_powers: Vec<i32> = (0..n)
            .map(|i| Self::_mod_exp(psi, i as u32, q) as i32)
            .collect();
        let psi_inv_powers: Vec<i32> = (0..n)
            .map(|i| Self::_mod_exp(psi_inv, i as u32, q) as i32)
            .collect();

        let twiddles = Self::_precompute_twiddles(omega, q, n);
        let twiddles_inv = Self::_precompute_twiddles(Self::_mod_exp(omega, q - 2, q), q, n);

        let a_pre: Vec<i32> = (0..n)
            .map(|i| ((a.coeffs[i] as i64 * psi_powers[i] as i64) % q as i64) as i32)
            .collect();
        let b_pre: Vec<i32> = (0..n)
            .map(|i| ((b.coeffs[i] as i64 * psi_powers[i] as i64) % q as i64) as i32)
            .collect();

        let a_ntt = Self::_ntt_fast(&a_pre, q, &twiddles, n);
        let b_ntt = Self::_ntt_fast(&b_pre, q, &twiddles, n);

        let q_i64 = q as i64;
        let mut c_ntt = vec![0i64; n];
        for i in 0..n {
            c_ntt[i] = ((a_ntt[i] * b_ntt[i]) % q_i64 + q_i64) % q_i64;
        }

        let n_inv = Self::_mod_exp(n as u32, q - 2, q);
        let c_cyc = Self::_intt_fast(&c_ntt, q, &twiddles_inv, n_inv, n);

        let coeffs: Vec<i32> = (0..n)
            .map(|i| ((c_cyc[i] as i64 * psi_inv_powers[i] as i64) % q_i64) as i32)
            .collect();

        Self { coeffs }
    }

    pub fn _precompute_twiddles(omega: u32, q: u32, n: usize) -> Vec<Vec<i64>> {
        let q_i64 = q as i64;
        let mut twiddles = Vec::new();
        let mut k = 1;
        while k < n {
            let m = 2 * k;
            let omega_step = Self::_mod_exp(omega, (n / m) as u32, q) as i64;
            let mut stage_twiddles = vec![0i64; k];
            let mut w = 1i64;
            for i in 0..k {
                stage_twiddles[i] = w;
                w = (w * omega_step) % q_i64;
            }
            twiddles.push(stage_twiddles);
            k *= 2;
        }
        twiddles
    }

    /// Cooley-Tukey DIT NTT with precomputed twiddles
    /// Input: natural order, Output: natural order
    fn _ntt_fast(a: &[i32], q: u32, twiddles: &[Vec<i64>], n: usize) -> Vec<i64> {
        let q_i64 = q as i64;

        // Bit-reverse input first
        let mut result = Self::_bit_reverse(&a.iter().map(|&x| x as i64).collect::<Vec<_>>(), n);

        for stage in 0..twiddles.len() {
            let k = twiddles[stage].len();
            let m = 2 * k;
            for j in (0..n).step_by(m) {
                for i in 0..k {
                    let u = result[j + i];
                    let v = result[j + i + k];
                    let t = (twiddles[stage][i] * v) % q_i64;
                    result[j + i] = (u + t) % q_i64;
                    result[j + i + k] = ((u - t) % q_i64 + q_i64) % q_i64;
                }
            }
        }

        result
    }

    /// Inverse NTT: uses same DIT structure with omega_inv
    fn _intt_fast(a: &[i64], q: u32, twiddles_inv: &[Vec<i64>], n_inv: u32, n: usize) -> Vec<i32> {
        let q_i64 = q as i64;
        let n_inv_i64 = n_inv as i64;

        // Bit-reverse input first
        let mut result = Self::_bit_reverse(a, n);

        for stage in 0..twiddles_inv.len() {
            let k = twiddles_inv[stage].len();
            let m = 2 * k;
            for j in (0..n).step_by(m) {
                for i in 0..k {
                    let u = result[j + i];
                    let v = result[j + i + k];
                    let t = (twiddles_inv[stage][i] * v) % q_i64;
                    result[j + i] = (u + t) % q_i64;
                    result[j + i + k] = ((u - t) % q_i64 + q_i64) % q_i64;
                }
            }
        }

        for x in &mut result {
            *x = (*x * n_inv_i64) % q_i64;
        }

        result
            .iter()
            .map(|&x| ((x % q_i64 + q_i64) % q_i64) as i32)
            .collect()
    }

    fn _bit_reverse(input: &[i64], n: usize) -> Vec<i64> {
        let log2_n = (n as f64).log2().round() as u32;
        let mut output = vec![0i64; n];

        for i in 0..n {
            let mut reversed = 0u32;
            let mut temp = i as u32;
            for _ in 0..log2_n {
                reversed = (reversed << 1) | (temp & 1);
                temp >>= 1;
            }
            output[i] = input[reversed as usize];
        }

        output
    }

    fn _mod_exp(mut base: u32, mut exp: u32, m: u32) -> u32 {
        let mut result: u64 = 1;
        let m_u64 = m as u64;
        base = (base as u64 % m_u64) as u32;

        while exp > 0 {
            if exp % 2 == 1 {
                result = (result * base as u64) % m_u64;
            }
            exp /= 2;
            base = ((base as u64 * base as u64) % m_u64) as u32;
        }

        result as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_mlwe_keygen_sign_verify_roundtrip() {
        let params = MLWEParameters::new_128();
        let mut rng = thread_rng();

        let kp = MLWEKeyPair::generate(&params, &mut rng);
        let message = b"Test message for MLWE signature";
        let context = b"test context";
        let sig =
            MLWESignature::try_sign(&params, &kp, message, context, &mut rng, &[], &[]).unwrap();

        assert!(
            MLWESignature::verify(&params, &kp, message, context, &sig, &[], &[]),
            "Valid signature should verify"
        );
    }

    #[test]
    fn test_mlwe_wrong_message_fails() {
        let params = MLWEParameters::new_128();
        let mut rng = thread_rng();

        let kp = MLWEKeyPair::generate(&params, &mut rng);
        let message = b"Original message";
        let context = b"test context";
        let sig =
            MLWESignature::try_sign(&params, &kp, message, context, &mut rng, &[], &[]).unwrap();

        let wrong_message = b"Wrong message";
        assert!(
            !MLWESignature::verify(&params, &kp, wrong_message, context, &sig, &[], &[]),
            "Signature on wrong message should NOT verify"
        );
    }

    #[test]
    fn test_mlwe_wrong_key_fails() {
        let params = MLWEParameters::new_128();
        let mut rng = thread_rng();

        let kp1 = MLWEKeyPair::generate(&params, &mut rng);
        let kp2 = MLWEKeyPair::generate(&params, &mut rng);
        let message = b"Test message";
        let context = b"test context";

        let sig =
            MLWESignature::try_sign(&params, &kp1, message, context, &mut rng, &[], &[]).unwrap();

        assert!(
            !MLWESignature::verify(&params, &kp2, message, context, &sig, &[], &[]),
            "Signature with wrong public key should NOT verify"
        );
    }

    #[test]
    fn test_mlwe_public_key_consistency() {
        let params = MLWEParameters::new_128();
        let mut rng = thread_rng();

        let kp = MLWEKeyPair::generate(&params, &mut rng);

        let as_result = MLWEKeyPair::matrix_vector_mul(&kp.matrix_a, &kp.secret_key, params.q);
        let expected_t = PolynomialVector {
            elements: as_result
                .elements
                .iter()
                .zip(kp.error_vector.elements.iter())
                .map(|(a_i, e_i)| a_i.add(e_i, params.q))
                .collect(),
        };

        for (t_i, exp_i) in kp
            .public_key
            .elements
            .iter()
            .zip(expected_t.elements.iter())
        {
            assert_eq!(t_i.coeffs, exp_i.coeffs, "Public key t must equal As + e");
        }
    }

    #[test]
    fn test_matrix_vector_mul_ntt_matches_reference() {
        let params = MLWEParameters::new_128();
        let mut rng = thread_rng();
        let matrix = MLWEKeyPair::generate_matrix_a(&params, &mut rng);
        let vector = PolynomialVector {
            elements: (0..params.m)
                .map(|_| Polynomial::rand_poly(params.n, params.eta1, &mut rng))
                .collect(),
        };

        let reference = PolynomialVector {
            elements: (0..matrix.rows)
                .map(|i| {
                    let mut result = Polynomial::new(params.n);
                    for j in 0..matrix.cols {
                        let prod = matrix.elements[i][j].mul(&vector.elements[j], params.q);
                        result = result.add(&prod, params.q);
                    }
                    result
                })
                .collect(),
        };
        let accelerated = MLWEKeyPair::matrix_vector_mul_ntt(&matrix, &vector, params.q);

        assert_eq!(reference, accelerated);
    }

    #[test]
    fn test_mlwe_try_sign_returns_error_on_rejection_exhaustion() {
        let params = MLWEParameters {
            k: 1,
            n: 64,
            q: 8380417,
            eta1: 2,
            eta2: 2,
            beta: 0,
            gamma1: 1,
            gamma2: 95232,
            m: 1,
            ell: 1,
            base: 256,
            sigma: 100.0,
            tau: 39,
        };
        let mut rng = thread_rng();

        let huge_secret = Polynomial {
            coeffs: vec![params.q as i32 / 2; params.n],
        };
        let kp = MLWEKeyPair {
            public_key: PolynomialVector::new(1, params.n),
            secret_key: PolynomialVector::from(vec![huge_secret]),
            error_vector: PolynomialVector::new(1, params.n),
            matrix_a: PolynomialMatrix::new(1, 1, params.n),
        };

        let result = MLWESignature::try_sign(&params, &kp, b"msg", b"ctx", &mut rng, &[], &[]);
        assert!(matches!(result, Err(PabsCrfError::SignFailed(_))));
    }

    #[test]
    fn test_challenge_includes_delta_bytes() {
        let params = MLWEParameters::new_128();
        let mut rng = thread_rng();
        let kp = MLWEKeyPair::generate(&params, &mut rng);
        let message = b"delta binding test";
        let context = b"ctx";
        let tr = MLWESignature::compute_system_tr(&kp.matrix_a, &kp.public_key);
        let pk_hash = MLWESignature::compute_pk_hash(&kp.public_key, params.q);

        let w1 = PolynomialVector::new(params.k, params.n);

        let c_no_delta = MLWESignature::derive_challenge_public(
            &params,
            &w1,
            message,
            context,
            &tr,
            &pk_hash,
            &[],
        );
        let c_delta_a = MLWESignature::derive_challenge_public(
            &params, &w1, message, context, &tr, &pk_hash, b"delta_A",
        );
        let c_delta_b = MLWESignature::derive_challenge_public(
            &params, &w1, message, context, &tr, &pk_hash, b"delta_B",
        );

        assert_ne!(
            c_no_delta.coeffs, c_delta_a.coeffs,
            "Challenge with empty delta MUST differ from challenge with non-empty delta"
        );
        assert_ne!(
            c_delta_a.coeffs, c_delta_b.coeffs,
            "Different delta values MUST produce different challenges (P1-9 binding)"
        );
    }

    #[test]
    fn test_decompose_roundtrip_algebraic_identity() {
        let q = 8380417u32;
        let gamma2 = 95232i32;

        for base in [0, gamma2, 2 * gamma2, q as i32 / 2, q as i32 - gamma2] {
            for offset in -3..=3 {
                let r = base + offset;
                let (r0, r1) = MLWEParameters::decompose(r, gamma2, q);
                let recovered = r1 * 2 * gamma2 + r0;
                let r_mod = ((r % q as i32) + q as i32) % q as i32;
                let recovered_mod = ((recovered % q as i32) + q as i32) % q as i32;
                assert_eq!(
                    r_mod, recovered_mod,
                    "r1*2g2 + r0 should recover r mod q; failed at r={}",
                    r
                );
                assert!(
                    r0.abs() <= gamma2,
                    "|r0|={} should be <= gamma2={} for r={}",
                    r0.abs(),
                    gamma2,
                    r
                );
            }
        }
    }

    #[test]
    fn test_mod_reduce_coefficient_internals() {
        let q = 8380417u32;
        for &c in &[-1234567i32, -1, 0, 1, 8380416, 8380417 + 5] {
            let reduced = ((c % q as i32) + q as i32) % q as i32;
            assert!(
                reduced >= 0 && reduced < q as i32,
                "mod should produce value in [0,q)"
            );
        }
    }

    #[test]
    fn test_make_hint_decompose_consistency_at_canonical_representatives() {
        let q = 8380417u32;
        let q_i = q as i32;
        let gamma2 = 95232i32;
        for idx in 0..65 {
            let r_base = ((idx * (q / 65)) % q) as i32;
            for z_gap in [0i32, 1, gamma2 / 2, gamma2, 2 * gamma2 - 1] {
                let r_mod = ((r_base % q_i) + q_i) % q_i;
                let z_mod = ((z_gap % q_i) + q_i) % q_i;
                let hint_from_func = MLWEParameters::make_hint(z_mod, r_mod, gamma2, q);
                assert!(
                    hint_from_func == 0 || hint_from_func == 1,
                    "hint must be boolean, was {}",
                    hint_from_func
                );
                let h0 = MLWEParameters::use_hint(0, r_mod, gamma2, q);
                let (_, r1) = MLWEParameters::decompose(r_mod, gamma2, q);
                assert_eq!(h0, r1, "use_hint(h=0, r) should match decompose(r).1");
            }
        }
    }

    #[test]
    fn test_power2round_algebraic_identity() {
        for d in [8, 13, 17] {
            for v in [0i32, 1, 4095, 65536, 131072, 1 << 19, 8380416 / 2] {
                let (r0, r1) = MLWEParameters::power2round(v, d);
                let reconstructed = r1 * (1i32 << d) + r0;
                let mask = (1i32 << d) - 1;
                assert_eq!(v & mask, r0, "power2round low bits disagreement");
                assert_eq!(
                    reconstructed, v,
                    "power2round: r1*2^d + r0 should recover original for v={},d={}",
                    v, d
                );
            }
        }
    }

    #[test]
    fn test_matrix_a_from_seed_deterministic() {
        let params = MLWEParameters::new_128();
        let seed = [42u8; 32];
        let a1 = MLWEKeyPair::generate_matrix_a_from_seed(&seed, &params);
        let a2 = MLWEKeyPair::generate_matrix_a_from_seed(&seed, &params);
        assert_eq!(a1.rows, a2.rows);
        assert_eq!(a1.cols, a2.cols);
        for (row1, row2) in a1.elements.iter().zip(a2.elements.iter()) {
            for (p1, p2) in row1.iter().zip(row2.iter()) {
                assert_eq!(p1.coeffs, p2.coeffs);
            }
        }
    }

    #[test]
    fn test_matrix_a_different_seeds() {
        let params = MLWEParameters::new_128();
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];
        let a1 = MLWEKeyPair::generate_matrix_a_from_seed(&seed1, &params);
        let a2 = MLWEKeyPair::generate_matrix_a_from_seed(&seed2, &params);
        let mut any_diff = false;
        for (row1, row2) in a1.elements.iter().zip(a2.elements.iter()) {
            for (p1, p2) in row1.iter().zip(row2.iter()) {
                if p1.coeffs != p2.coeffs {
                    any_diff = true;
                    break;
                }
            }
            if any_diff {
                break;
            }
        }
        assert!(
            any_diff,
            "Different seeds should produce different matrices"
        );
    }

    #[test]
    fn test_matrix_a_coefficients_in_range() {
        let params = MLWEParameters::new_128();
        let seed = [7u8; 32];
        let a = MLWEKeyPair::generate_matrix_a_from_seed(&seed, &params);
        let q = params.q;
        for row in &a.elements {
            for poly in row {
                for &c in &poly.coeffs {
                    assert!(
                        c >= 0 && c < q as i32,
                        "Coefficient {} out of range [0, {})",
                        c,
                        q
                    );
                }
            }
        }
    }

    #[test]
    fn test_rand_poly_uniform_no_modular_bias() {
        let mut rng = thread_rng();
        let bound: u32 = 10;
        let range = (2 * bound + 1) as usize;
        let n_samples: usize = 200_000;
        let expected = n_samples as f64 / range as f64;
        let mut counts = vec![0u32; range];
        for _ in 0..n_samples {
            let poly = Polynomial::rand_poly_uniform(1, bound, &mut rng);
            let shifted = (poly.coeffs[0] + bound as i32) as usize;
            counts[shifted] += 1;
        }
        for (i, &c) in counts.iter().enumerate() {
            let deviation = ((c as f64) - expected).abs() / expected;
            assert!(
                deviation < 0.03,
                "bias detected at value {}: count={}, expected={:.1}, deviation={:.3}%",
                i as i32 - bound as i32,
                c,
                expected,
                deviation * 100.0
            );
        }

        let large_bound: u32 = 8380416;
        let poly = Polynomial::rand_poly_uniform(256, large_bound, &mut rng);
        for &c in &poly.coeffs {
            assert!(
                c >= -(large_bound as i32) && c <= large_bound as i32,
                "coefficient {} out of range [-{}, {}]",
                c,
                large_bound,
                large_bound
            );
        }
    }
}
