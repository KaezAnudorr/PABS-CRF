//! LSSS (Linear Secret Sharing Scheme) matrix engine
//!
//! This module implements the LSSS access structure for the PABS-CRF scheme,
//! supporting conversion from boolean trees to LSSS matrices, share generation,
//! and secret reconstruction.
//!
//! # Mathematical Background
//!
//! An LSSS access structure is represented by a sharing matrix M ∈ Z_q^{l×n}
//! and a mapping function ρ: {1,...,l} → U that maps rows to attributes.
//!
//! For a secret s ∈ Z_q, we choose random r_2,...,r_n ∈ Z_q and let
//! v = (s, r_2,...,r_n)^T. The i-th share is λ_i = M_i · v mod q.
//!
//! If attribute set S satisfies the access structure, there exist constants
//! {ω_i} such that Σ_{i∈I} ω_i M_i = (1, 0,..., 0), which implies
//! Σ_{i∈I} ω_i λ_i = s.

use crate::errors::{PabsCrfError, PabsCrfResult};
use crate::mlwe::{MLWEParameters, PolynomialVector};
use rand::{thread_rng, Rng};
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::{Mutex, MutexGuard, OnceLock};

type ReconstructionCacheValue = (Vec<i64>, Vec<usize>);
const DEFAULT_CACHE_CAPACITY: usize = 256;
pub const MAX_RECONSTRUCTION_COEFF_NORM: i64 = 1 << 16;
pub const MAX_POLICY_DEPTH: usize = 8;

/// Statistics for the LSSS reconstruction and policy cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    /// Maximum number of cache entries retained.
    pub capacity: usize,
    /// Number of currently retained entries.
    pub len: usize,
    /// Successful lookups since process start or last clear.
    pub hits: u64,
    /// Missed lookups since process start or last clear.
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

    fn stats(&self) -> CacheStats {
        CacheStats {
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

fn normalize_attributes(attributes: &[String]) -> Vec<String> {
    let mut normalized = attributes.to_vec();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn attribute_cache_key(attributes: &[String]) -> String {
    normalize_attributes(attributes).join("\x1f")
}

fn lsss_cache() -> &'static Mutex<BoundedCache<String, LSSSShareMatrix>> {
    static CACHE: OnceLock<Mutex<BoundedCache<String, LSSSShareMatrix>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BoundedCache::new(DEFAULT_CACHE_CAPACITY)))
}

fn reconstruction_cache() -> &'static Mutex<BoundedCache<String, ReconstructionCacheValue>> {
    static CACHE: OnceLock<Mutex<BoundedCache<String, ReconstructionCacheValue>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BoundedCache::new(DEFAULT_CACHE_CAPACITY)))
}

fn policy_target_cache() -> &'static Mutex<BoundedCache<String, PolynomialVector>> {
    static CACHE: OnceLock<Mutex<BoundedCache<String, PolynomialVector>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BoundedCache::new(DEFAULT_CACHE_CAPACITY)))
}

/// Clear all LSSS-related caches and reset hit/miss counters.
pub fn clear_policy_caches() {
    lock_or_recover(lsss_cache()).clear();
    lock_or_recover(reconstruction_cache()).clear();
    lock_or_recover(policy_target_cache()).clear();
}

/// Return hit/miss statistics for the LSSS caches.
pub fn policy_cache_stats() -> (CacheStats, CacheStats, CacheStats) {
    (
        lock_or_recover(lsss_cache()).stats(),
        lock_or_recover(reconstruction_cache()).stats(),
        lock_or_recover(policy_target_cache()).stats(),
    )
}

/// Return a cached LSSS matrix for a parsed policy.
pub fn lsss_from_policy_cached(policy: &crate::policy::Policy) -> PabsCrfResult<LSSSShareMatrix> {
    let policy_key = policy.to_string();
    if let Some(cached) = lock_or_recover(lsss_cache()).get_cloned(&policy_key) {
        return Ok(cached);
    }

    let lsss = policy.to_lsss()?;
    lock_or_recover(lsss_cache()).insert(policy_key, lsss.clone());
    Ok(lsss)
}

/// Return cached reconstruction constants and the corresponding LSSS row indices.
pub fn reconstruction_data_cached(
    policy: &crate::policy::Policy,
    attributes: &[String],
    q: u32,
) -> PabsCrfResult<(LSSSShareMatrix, Vec<i64>, Vec<usize>)> {
    let lsss = lsss_from_policy_cached(policy)?;
    let cache_key = format!(
        "{}|{}|{}",
        policy.to_string(),
        q,
        attribute_cache_key(attributes)
    );

    if let Some((constants, indices)) =
        lock_or_recover(reconstruction_cache()).get_cloned(&cache_key)
    {
        return Ok((lsss, constants, indices));
    }

    let constants = lsss
        .get_reconstruction_constants(attributes, q)
        .ok_or_else(|| {
            PabsCrfError::PolicyError(
                "Attributes do not satisfy policy for reconstruction".to_string(),
            )
        })?;
    let indices: Vec<usize> = (0..lsss.rows())
        .filter(|i| attributes.contains(&lsss.row_to_attr()[*i]))
        .collect();

    lock_or_recover(reconstruction_cache()).insert(cache_key, (constants.clone(), indices.clone()));

    Ok((lsss, constants, indices))
}

/// Return a cached policy target vector for the supplied satisfying attributes.
pub fn derive_policy_target_cached(
    policy: &crate::policy::Policy,
    attributes: &[String],
    gid: &[u8; 32],
    params: &MLWEParameters,
) -> PabsCrfResult<PolynomialVector> {
    let gid_hex: String = gid.iter().map(|b| format!("{:02x}", b)).collect();
    let cache_key = format!(
        "{}|{}|{}|{}|{}|{}",
        policy.to_string(),
        params.q,
        params.k,
        params.n,
        attribute_cache_key(attributes),
        gid_hex
    );

    if let Some(cached) = lock_or_recover(policy_target_cache()).get_cloned(&cache_key) {
        return Ok(cached);
    }

    let (lsss, constants, indices) = reconstruction_data_cached(policy, attributes, params.q)?;
    let mut target = PolynomialVector::new(params.k, params.n);

    for (i, &coeff) in constants.iter().enumerate() {
        if coeff == 0 {
            continue;
        }
        let attr_name = &lsss.row_to_attr()[indices[i]];
        let u_i = crate::utils::hash_to_target_vector_with_gid(attr_name, gid, params);
        for j in 0..params.k {
            let scaled = u_i.elements[j].scalar_mul(coeff as i32, params.q);
            target.elements[j] = target.elements[j].add(&scaled, params.q);
        }
    }

    lock_or_recover(policy_target_cache()).insert(cache_key, target.clone());

    Ok(target)
}

/// LSSS sharing matrix representation
#[derive(Debug, Clone)]
pub struct LSSSShareMatrix {
    /// Sharing matrix M ∈ Z_q^{l×n}
    matrix: Vec<Vec<i64>>,
    /// Row to attribute mapping ρ: {1,...,l} → attributes
    row_to_attr: Vec<String>,
    /// Matrix dimensions (l, n)
    rows: usize,
    cols: usize,
    /// Original policy string when built from a boolean formula.
    policy_repr: Option<String>,
}

impl LSSSShareMatrix {
    /// Create a new LSSS sharing matrix
    ///
    /// # Arguments
    /// * `matrix` - The sharing matrix M as a 2D vector
    /// * `row_to_attr` - Mapping from row indices to attribute names
    pub fn new(matrix: Vec<Vec<i64>>, row_to_attr: Vec<String>) -> Self {
        let rows = matrix.len();
        let cols = if rows > 0 { matrix[0].len() } else { 0 };
        Self {
            matrix,
            row_to_attr,
            rows,
            cols,
            policy_repr: None,
        }
    }

    /// Create a new LSSS sharing matrix with the source policy attached.
    pub fn new_with_policy(
        matrix: Vec<Vec<i64>>,
        row_to_attr: Vec<String>,
        policy_repr: String,
    ) -> Self {
        let rows = matrix.len();
        let cols = if rows > 0 { matrix[0].len() } else { 0 };
        Self {
            matrix,
            row_to_attr,
            rows,
            cols,
            policy_repr: Some(policy_repr),
        }
    }

    /// Get matrix dimensions (rows)
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Get matrix dimensions (cols)
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// Get row to attribute mapping
    pub fn row_to_attr(&self) -> &[String] {
        &self.row_to_attr
    }

    /// Check if attribute set satisfies the access structure
    ///
    /// This method uses a direct tree-based satisfaction check rather than
    /// the general matrix approach, which is more reliable for simple policies.
    ///
    /// # Arguments
    /// * `attrs` - Set of user attributes
    ///
    /// # Returns
    /// true if attributes satisfy the access structure
    pub fn is_satisfied(&self, attrs: &[String]) -> bool {
        if let Some(policy) = &self.policy_repr {
            let refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();
            return crate::policy::Policy::parse(policy)
                .map(|parsed| parsed.satisfies(&refs))
                .unwrap_or(false);
        }

        // Fallback for matrices created manually in tests.
        let policy = self.reconstruct_policy();
        Self::check_policy_satisfaction(&policy, attrs)
    }

    /// Reconstruct the policy string from the LSSS matrix
    fn reconstruct_policy(&self) -> String {
        panic!("reconstruct_policy is test-only; use get_reconstruction_constants for production");
        // For single attribute policies
        if self.rows == 1 && self.cols == 1 {
            return self.row_to_attr[0].clone();
        }

        // Check if this looks like an AND or OR structure based on the matrix
        if self.rows >= 2 {
            let first_attr = &self.row_to_attr[0];
            let second_attr = &self.row_to_attr[1];

            // Check for OR structure: both rows have same column structure
            if self.cols == 1 && self.rows == 2 {
                return format!("({} OR {})", first_attr, second_attr);
            }

            // Check for AND structure: block diagonal matrix
            if self.cols == 2 && self.rows == 2 {
                if self.matrix[0][1] == 0 && self.matrix[1][0] == 0 {
                    return format!("({} AND {})", first_attr, second_attr);
                }
            }

            // Check for nested (A AND B) OR C: 3 rows, 2 columns
            // Rows 0,1 form AND block, row 2 is the OR branch
            if self.cols == 2 && self.rows == 3 {
                let third_attr = &self.row_to_attr[2];
                // Check if first two rows form a block diagonal (AND structure)
                if self.matrix[0][1] == 0 && self.matrix[1][0] == 0 {
                    return format!("(({} AND {}) OR {})", first_attr, second_attr, third_attr);
                }
            }
        }

        // Fallback: return first attribute
        self.row_to_attr[0].clone()
    }

    /// Check if attributes satisfy a policy string
    fn check_policy_satisfaction(policy: &str, attrs: &[String]) -> bool {
        let policy = policy.trim();

        // Simple attribute
        if !policy.contains(" AND ") && !policy.contains(" OR ") && !policy.starts_with("NOT") {
            return attrs.iter().any(|a| a == policy);
        }

        // NOT policy
        if policy.starts_with("NOT") {
            let inner = &policy[3..].trim();
            // Remove outer parentheses if present
            let inner = inner.strip_prefix('(').unwrap_or(inner);
            let inner = inner.strip_suffix(')').unwrap_or(inner);
            return !Self::check_policy_satisfaction(inner, attrs);
        }

        // Handle parentheses
        if policy.starts_with('(') && policy.ends_with(')') {
            return Self::check_policy_satisfaction(&policy[1..policy.len() - 1], attrs);
        }

        // Find top-level OR
        if let Some(pos) = Self::find_top_level_or_pos(policy) {
            let left = &policy[..pos];
            let right = &policy[pos + 4..]; // skip " OR "
            return Self::check_policy_satisfaction(left, attrs)
                || Self::check_policy_satisfaction(right, attrs);
        }

        // Find top-level AND
        if let Some(pos) = Self::find_top_level_and_pos(policy) {
            let left = &policy[..pos];
            let right = &policy[pos + 5..]; // skip " AND "
            return Self::check_policy_satisfaction(left, attrs)
                && Self::check_policy_satisfaction(right, attrs);
        }

        false
    }

    fn find_top_level_or_pos(s: &str) -> Option<usize> {
        Self::find_top_level_op(s, " OR ")
    }

    fn find_top_level_and_pos(s: &str) -> Option<usize> {
        Self::find_top_level_op(s, " AND ")
    }

    fn find_top_level_op(s: &str, op: &str) -> Option<usize> {
        let mut depth = 0;
        let chars: Vec<char> = s.chars().collect();
        let op_chars: Vec<char> = op.chars().collect();

        for i in 0..chars.len().saturating_sub(op_chars.len() - 1) {
            if chars[i] == '(' {
                depth += 1;
            } else if chars[i] == ')' {
                depth -= 1;
            } else if depth == 0 {
                if i + op_chars.len() <= chars.len() {
                    let matches = (0..op_chars.len()).all(|j| chars[i + j] == op_chars[j]);
                    if matches {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    /// Convert a boolean tree policy string to LSSS matrix
    ///
    /// # Arguments
    /// * `policy_str` - Policy string with AND/OR/NOT operators
    ///   Examples: "A AND B", "A OR B", "(A AND B) OR C"
    ///
    /// # Returns
    /// LSSSShareMatrix representing the policy
    ///
    /// # Conversion Rules
    /// - AND gate: M = [[1,0],[0,1]] (both children required)
    /// - OR gate: M = [[1],[1]] (either child sufficient)
    pub fn from_boolean_tree(policy_str: &str) -> PabsCrfResult<Self> {
        let policy = strip_outer_parens(policy_str.trim());
        if policy.is_empty() {
            return Err(PabsCrfError::PolicyError("Empty policy".to_string()));
        }
        if policy.contains("NOT") {
            return Err(PabsCrfError::PolicyError(
                "NOT is not supported by the monotone LSSS builder".to_string(),
            ));
        }

        let mut rows = Vec::new();
        let mut row_to_attr = Vec::new();
        let mut next_col = 1usize;
        build_msp(policy, vec![1], &mut next_col, &mut rows, &mut row_to_attr)?;

        for row in &mut rows {
            row.resize(next_col, 0);
        }

        Ok(Self::new_with_policy(rows, row_to_attr, policy.to_string()))
    }

    /// Generate shares for a secret value
    pub fn share(&self, secret: i64, q: u32) -> Vec<i64> {
        if self.rows == 0 || self.cols == 0 {
            return vec![];
        }

        let mut rng = thread_rng();
        let mut v = vec![0i64; self.cols];
        v[0] = ((secret % q as i64) + q as i64) % q as i64;
        for i in 1..self.cols {
            v[i] = rng.gen_range(0..q as i64);
        }

        let mut shares = Vec::new();
        for i in 0..self.rows {
            let mut share = 0i64;
            for j in 0..self.cols {
                share = (share + self.matrix[i][j] * v[j]) % q as i64;
            }
            let share_mod = (share + q as i64) % q as i64;
            shares.push(share_mod);
        }

        shares
    }

    /// Reconstruct secret from shares
    pub fn reconstruct(&self, shares: &[(usize, i64)], q: u32) -> PabsCrfResult<i64> {
        if shares.is_empty() {
            return Err(PabsCrfError::PolynomialError(
                "No shares provided".to_string(),
            ));
        }

        let attrs: Vec<String> = shares
            .iter()
            .map(|(idx, _)| self.row_to_attr[*idx].clone())
            .collect();

        let constants = self.get_reconstruction_constants(&attrs, q);
        if constants.is_none() {
            return Err(PabsCrfError::PolynomialError(
                "Cannot reconstruct: attributes don't satisfy access structure".to_string(),
            ));
        }

        let omega = constants.unwrap();
        let mut secret = 0i64;
        for (i, (_, share)) in shares.iter().enumerate() {
            secret += omega[i] * share;
        }

        let secret_mod = ((secret % q as i64) + q as i64) % q as i64;
        Ok(secret_mod)
    }

    /// Get reconstruction constants for satisfying attributes
    pub fn get_reconstruction_constants(&self, attrs: &[String], q: u32) -> Option<Vec<i64>> {
        let indices: Vec<usize> = (0..self.rows)
            .filter(|i| attrs.contains(&self.row_to_attr[*i]))
            .collect();

        if indices.is_empty() {
            return None;
        }

        let m_i: Vec<Vec<i64>> = indices.iter().map(|&i| self.matrix[i].clone()).collect();

        let constants = solve_linear_system(&m_i, q)?;

        let q_i64 = q as i64;
        let mut first_col_sum: i64 = 0;
        for (i, &omega) in constants.iter().enumerate() {
            first_col_sum = (first_col_sum + omega * m_i[i][0]) % q_i64;
        }
        first_col_sum = (first_col_sum % q_i64 + q_i64) % q_i64;
        if first_col_sum != 1 {
            return None;
        }

        let max_norm = constants
            .iter()
            .map(|c| c.unsigned_abs() as i64)
            .max()
            .unwrap_or(0);
        if max_norm > MAX_RECONSTRUCTION_COEFF_NORM {
            return None;
        }

        Some(constants)
    }

    /// Derive a unified policy target vector by aggregating attribute target vectors
    /// using LSSS reconstruction constants.
    ///
    /// This ensures that the policy target u_policy = Σ ω_i * u_i
    /// where u_i = hash_to_target_vector(attr_i).
    pub fn derive_policy_target(
        &self,
        attributes: &[String],
        gid: &[u8; 32],
        params: &MLWEParameters,
    ) -> PolynomialVector {
        let q = params.q;
        let n = params.n;
        let k = params.k;

        let mut target = PolynomialVector::new(k, n);

        if let Some(constants) = self.get_reconstruction_constants(attributes, q) {
            let indices: Vec<usize> = (0..self.rows)
                .filter(|i| attributes.contains(&self.row_to_attr[*i]))
                .collect();

            for (i, &coeff) in constants.iter().enumerate() {
                if coeff != 0 {
                    let attr_name = &self.row_to_attr[indices[i]];
                    let u_i = crate::utils::hash_to_target_vector_with_gid(attr_name, gid, params);
                    for j in 0..k {
                        let scaled = u_i.elements[j].scalar_mul(coeff as i32, q);
                        target.elements[j] = target.elements[j].add(&scaled, q);
                    }
                }
            }
        }
        target
    }

    #[allow(dead_code)]
    fn can_reconstruct(&self, indices: &[usize], q: u32) -> bool {
        if indices.is_empty() {
            return false;
        }

        let m_i: Vec<Vec<i64>> = indices.iter().map(|&i| self.matrix[i].clone()).collect();

        solve_linear_system(&m_i, q).is_some()
    }
}

/// Find top-level OR operator (not inside parentheses)
fn find_top_level_or(s: &str) -> Option<usize> {
    find_top_level_operator(s, " OR ")
}

/// Find top-level AND operator (not inside parentheses)
fn find_top_level_and(s: &str) -> Option<usize> {
    find_top_level_operator(s, " AND ")
}

/// Generic operator finder
fn find_top_level_operator(s: &str, op: &str) -> Option<usize> {
    let mut depth = 0;
    let chars: Vec<char> = s.chars().collect();
    let op_chars: Vec<char> = op.chars().collect();

    for i in 0..chars.len().saturating_sub(op_chars.len() - 1) {
        if chars[i] == '(' {
            depth += 1;
        } else if chars[i] == ')' {
            depth -= 1;
        } else if depth == 0 {
            if i + op_chars.len() <= chars.len() {
                let matches = (0..op_chars.len()).all(|j| chars[i + j] == op_chars[j]);
                if matches {
                    return Some(i);
                }
            }
        }
    }
    None
}

fn build_msp(
    policy: &str,
    current_vec: Vec<i64>,
    next_col: &mut usize,
    rows: &mut Vec<Vec<i64>>,
    row_to_attr: &mut Vec<String>,
) -> PabsCrfResult<()> {
    let policy = strip_outer_parens(policy.trim());

    if let Some(or_pos) = find_top_level_or(policy) {
        let left = policy[..or_pos].trim();
        let right = policy[or_pos + 4..].trim();
        build_msp(left, current_vec.clone(), next_col, rows, row_to_attr)?;
        build_msp(right, current_vec, next_col, rows, row_to_attr)?;
        return Ok(());
    }

    if let Some(and_pos) = find_top_level_and(policy) {
        let left = policy[..and_pos].trim();
        let right = policy[and_pos + 5..].trim();

        let fresh_col = *next_col;
        *next_col += 1;

        let mut left_vec = current_vec;
        left_vec.resize(*next_col, 0);
        left_vec[fresh_col] = 1;

        let mut right_vec = vec![0i64; *next_col];
        right_vec[fresh_col] = -1;

        build_msp(left, left_vec, next_col, rows, row_to_attr)?;
        build_msp(right, right_vec, next_col, rows, row_to_attr)?;
        return Ok(());
    }

    if policy.is_empty() {
        return Err(PabsCrfError::PolicyError(
            "Encountered empty leaf in policy".to_string(),
        ));
    }

    rows.push(current_vec);
    row_to_attr.push(policy.to_string());
    Ok(())
}

fn strip_outer_parens(mut s: &str) -> &str {
    s = s.trim();
    while s.starts_with('(') && s.ends_with(')') && is_wrapped_by_single_paren_group(s) {
        s = s[1..s.len() - 1].trim();
    }
    s
}

fn is_wrapped_by_single_paren_group(s: &str) -> bool {
    let mut depth = 0i32;
    for (idx, ch) in s.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && idx + ch.len_utf8() < s.len() {
            return false;
        }
    }
    depth == 0
}

/// Solve linear system M^T · ω = target using Gaussian elimination over Z_q
fn solve_linear_system(m: &[Vec<i64>], q: u32) -> Option<Vec<i64>> {
    if m.is_empty() || m[0].is_empty() {
        return None;
    }

    let n_rows = m.len();
    let n_cols = m[0].len();

    // Build augmented matrix [M^T | target] where target = (1, 0,..., 0)
    let mut augmented = vec![vec![0i64; n_rows + 1]; n_cols];

    for i in 0..n_cols {
        for j in 0..n_rows {
            augmented[i][j] = ((m[j][i] % q as i64) + q as i64) % q as i64;
        }
        augmented[i][n_rows] = if i == 0 { 1 } else { 0 };
    }

    // Gaussian elimination
    let mut pivot_row = 0;
    for col in 0..n_rows {
        let mut pivot = None;
        for row in pivot_row..n_cols {
            if augmented[row][col] != 0 {
                pivot = Some(row);
                break;
            }
        }

        if let Some(pivot_idx) = pivot {
            augmented.swap(pivot_row, pivot_idx);

            let pivot_val = augmented[pivot_row][col];
            let inv = mod_inverse(pivot_val, q as i64)?;
            for j in 0..=n_rows {
                augmented[pivot_row][j] =
                    ((augmented[pivot_row][j] * inv) % q as i64 + q as i64) % q as i64;
            }

            for row in 0..n_cols {
                if row != pivot_row && augmented[row][col] != 0 {
                    let factor = augmented[row][col];
                    for j in 0..=n_rows {
                        augmented[row][j] =
                            ((augmented[row][j] - factor * augmented[pivot_row][j]) % q as i64
                                + q as i64)
                                % q as i64;
                    }
                }
            }

            pivot_row += 1;
        }
    }

    for row in pivot_row..n_cols {
        if augmented[row][n_rows] != 0 {
            return None;
        }
    }

    let mut omega = vec![0i64; n_rows];
    let q_half = q as i64 / 2;
    for i in 0..n_rows.min(pivot_row) {
        let val_mod_q = augmented[i][n_rows];
        let val_centered = if val_mod_q <= q_half {
            val_mod_q
        } else {
            val_mod_q - q as i64
        };
        omega[i] = val_centered;
    }

    Some(omega)
}

/// Compute modular inverse using extended Euclidean algorithm
fn mod_inverse(a: i64, m: i64) -> Option<i64> {
    let a = ((a % m) + m) % m;
    let mut m0 = m;
    let mut y = 0i64;
    let mut x = 1i64;

    if m == 1 {
        return Some(0);
    }

    let mut a_copy = a;
    while a_copy > 1 {
        let q = a_copy / m0;
        let t = m0;
        m0 = a_copy % m0;
        a_copy = t;
        let temp = y;
        y = x - q * y;
        x = temp;
    }

    if x < 0 {
        x += m;
    }

    Some(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_attribute() {
        let matrix = LSSSShareMatrix::from_boolean_tree("admin").unwrap();
        assert_eq!(matrix.rows, 1);
        assert!(matrix.is_satisfied(&["admin".to_string()]));
        assert!(!matrix.is_satisfied(&["user".to_string()]));
    }

    #[test]
    fn test_and_gate() {
        let matrix = LSSSShareMatrix::from_boolean_tree("A AND B").unwrap();
        assert!(matrix.is_satisfied(&["A".to_string(), "B".to_string()]));
        assert!(!matrix.is_satisfied(&["A".to_string()]));
        assert!(!matrix.is_satisfied(&["B".to_string()]));
    }

    #[test]
    fn test_or_gate() {
        let matrix = LSSSShareMatrix::from_boolean_tree("A OR B").unwrap();
        assert!(matrix.is_satisfied(&["A".to_string()]));
        assert!(matrix.is_satisfied(&["B".to_string()]));
        assert!(matrix.is_satisfied(&["A".to_string(), "B".to_string()]));
        assert!(!matrix.is_satisfied(&["C".to_string()]));
    }

    #[test]
    fn test_nested_policy() {
        let matrix = LSSSShareMatrix::from_boolean_tree("(A AND B) OR C").unwrap();
        assert!(matrix.is_satisfied(&["A".to_string(), "B".to_string()]));
        assert!(matrix.is_satisfied(&["C".to_string()]));
        assert!(!matrix.is_satisfied(&["A".to_string()]));
        assert!(!matrix.is_satisfied(&["B".to_string()]));
    }

    #[test]
    fn test_share_reconstruction() {
        let q = 8380417u32;
        let matrix = LSSSShareMatrix::from_boolean_tree("A AND B").unwrap();
        let secret = 12345i64;

        let shares = matrix.share(secret, q);
        assert_eq!(shares.len(), 2);

        let reconstructed = matrix
            .reconstruct(&[(0, shares[0]), (1, shares[1])], q)
            .unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_reconstruction_constants_satisfy_linear_constraint() {
        let q = 8380417u32;

        let matrix = LSSSShareMatrix::from_boolean_tree("(A AND B) OR C").unwrap();

        let constants_ab = matrix
            .get_reconstruction_constants(&["A".to_string(), "B".to_string()], q)
            .expect("A,B should satisfy (A AND B) OR C");
        let indices_ab: Vec<usize> = (0..matrix.rows)
            .filter(|i| ["A".to_string(), "B".to_string()].contains(&matrix.row_to_attr[*i]))
            .collect();
        let q_i64 = q as i64;
        let mut first_col_sum: i64 = 0;
        for (i, &omega) in constants_ab.iter().enumerate() {
            first_col_sum = (first_col_sum + omega * matrix.matrix[indices_ab[i]][0]) % q_i64;
        }
        first_col_sum = (first_col_sum % q_i64 + q_i64) % q_i64;
        assert_eq!(
            first_col_sum, 1,
            "Σ ω_i · M_i[0] must equal 1 (mod q) for {{A, B}}"
        );

        let constants_c = matrix
            .get_reconstruction_constants(&["C".to_string()], q)
            .expect("C should satisfy (A AND B) OR C");
        let indices_c: Vec<usize> = (0..matrix.rows)
            .filter(|i| matrix.row_to_attr[*i] == "C")
            .collect();
        let mut first_col_sum_c: i64 = 0;
        for (i, &omega) in constants_c.iter().enumerate() {
            first_col_sum_c = (first_col_sum_c + omega * matrix.matrix[indices_c[i]][0]) % q_i64;
        }
        first_col_sum_c = (first_col_sum_c % q_i64 + q_i64) % q_i64;
        assert_eq!(
            first_col_sum_c, 1,
            "Σ ω_i · M_i[0] must equal 1 (mod q) for {{C}}"
        );

        assert!(matrix
            .get_reconstruction_constants(&["A".to_string()], q)
            .is_none());
        assert!(matrix
            .get_reconstruction_constants(&["B".to_string()], q)
            .is_none());
    }
}
