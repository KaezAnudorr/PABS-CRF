/// Internal types and structures for the PABS scheme.
pub mod types;

use crate::errors::{PabsCrfError, PabsCrfResult};
use crate::keygen::UserSecretKey;
use crate::lsss::{
    derive_policy_target_cached, lsss_from_policy_cached, reconstruction_data_cached,
};
use crate::mlwe::{MLWEKeyPair, MLWESignature, PolynomialVector};
use crate::pabs::types::CorePredicateSignature;
use crate::parameter_sets::TopTierParameterModel;
use crate::policy::Policy;
use sha2::{Digest, Sha256};

fn center_mod_q(value: i32, q: u32) -> i64 {
    let q_i64 = q as i64;
    let reduced = ((value as i64 % q_i64) + q_i64) % q_i64;
    if reduced > q_i64 / 2 {
        reduced - q_i64
    } else {
        reduced
    }
}

fn center_reconstruction_coeff(coeff: i64, q: u32) -> i64 {
    let q_i64 = q as i64;
    let reduced = ((coeff % q_i64) + q_i64) % q_i64;
    if reduced > q_i64 / 2 {
        reduced - q_i64
    } else {
        reduced
    }
}

/// Build a stable policy digest used across signing, verification and compression.
pub fn policy_digest(policy: &Policy) -> Vec<u8> {
    Sha256::digest(policy.to_string().as_bytes()).to_vec()
}

fn append_len_prefixed(context: &mut Vec<u8>, label: &[u8], value: &[u8]) {
    context.extend_from_slice(&(label.len() as u32).to_le_bytes());
    context.extend_from_slice(label);
    context.extend_from_slice(&(value.len() as u32).to_le_bytes());
    context.extend_from_slice(value);
}

/// Build the Fiat-Shamir context shared by signing and verification.
pub fn challenge_context(
    policy_digest: &[u8],
    tau: u64,
    gid: &[u8; 32],
    parameter_set_id: &str,
) -> Vec<u8> {
    let mut context = b"PABS-CRF-v4-FS-context".to_vec();
    append_len_prefixed(&mut context, b"policy_digest", policy_digest);
    append_len_prefixed(&mut context, b"tau", &tau.to_le_bytes());
    append_len_prefixed(&mut context, b"gid", gid);
    append_len_prefixed(
        &mut context,
        b"parameter_set_id",
        parameter_set_id.as_bytes(),
    );
    context
}

/// Combine attribute-bound preimages into the signing witness using the LSSS reconstruction constants.
pub fn combine_policy_witness(
    sk: &UserSecretKey,
    policy: &Policy,
) -> PabsCrfResult<(PolynomialVector, Vec<String>, Vec<u16>)> {
    let q = sk.params.q;
    let m = sk.params.m;
    let n = sk.params.n;

    let (lsss, constants, rows_to_use) = reconstruction_data_cached(policy, &sk.attributes, q)?;
    let mut combined_s_i64: Vec<Vec<i64>> = (0..m).map(|_| vec![0i64; n]).collect();
    let mut used_attributes = Vec::new();

    for (i, &row_idx) in rows_to_use.iter().enumerate() {
        let attr_name = &lsss.row_to_attr()[row_idx];
        let attr_pos = sk
            .attributes
            .iter()
            .position(|a| a == attr_name)
            .ok_or_else(|| {
                PabsCrfError::PolicyError(format!(
                    "Policy witness attribute '{}' is missing from the user key",
                    attr_name
                ))
            })?;
        used_attributes.push(attr_name.clone());

        let s_i = &sk.preimages[attr_pos];
        let coeff = center_reconstruction_coeff(constants[i], q);
        for j in 0..m {
            for coeff_idx in 0..n {
                let lifted_preimage = center_mod_q(s_i.elements[j].coeffs[coeff_idx], q);
                combined_s_i64[j][coeff_idx] += coeff * lifted_preimage;
            }
        }
    }

    let mut combined_s = PolynomialVector::new(m, n);
    for j in 0..m {
        for coeff_idx in 0..n {
            let v = combined_s_i64[j][coeff_idx];
            let reduced = ((v % q as i64) + q as i64) % q as i64;
            let centered = if reduced > q as i64 / 2 {
                reduced - q as i64
            } else {
                reduced
            };
            combined_s.elements[j].coeffs[coeff_idx] = i32::try_from(centered).map_err(|_| {
                PabsCrfError::SignFailed(
                    "Combined policy witness coefficient still overflows i32 after mod q reduction"
                        .to_string(),
                )
            })?;
        }
    }

    let witness_rows = rows_to_use.iter().map(|idx| *idx as u16).collect();
    Ok((combined_s, used_attributes, witness_rows))
}

/// Produce the core signature object before firewall transformation.
pub fn core_sign(
    sk: &UserSecretKey,
    message: &[u8],
    policy: &Policy,
    params: &TopTierParameterModel,
    delta_bytes: &[u8],
    tau: u64,
    rng: &mut impl rand::Rng,
) -> PabsCrfResult<(CorePredicateSignature, Vec<u16>, Vec<u8>)> {
    let attr_refs: Vec<&str> = sk.attributes.iter().map(|s| s.as_str()).collect();
    if !policy.satisfies(&attr_refs) {
        return Err(PabsCrfError::PolicyError(
            "User attributes do not satisfy the policy".to_string(),
        ));
    }

    let (combined_s, used_attributes, witness_rows) = combine_policy_witness(sk, policy)?;
    let u_policy = derive_policy_target_cached(policy, &used_attributes, &sk.gid, &sk.params)?;
    let pk_hash = MLWESignature::compute_pk_hash(&u_policy, sk.params.q);
    let kp = MLWEKeyPair {
        public_key: u_policy,
        secret_key: combined_s,
        error_vector: PolynomialVector::new(sk.params.k, sk.params.n),
        matrix_a: sk.matrix_a.clone(),
    };

    let policy_digest = policy_digest(policy);
    let parameter_set_id = params.protocol.security_target.as_str();
    let context = challenge_context(&policy_digest, tau, &sk.gid, parameter_set_id);
    let mlwe_sig = MLWESignature::try_sign(
        &params.protocol.mlwe,
        &kp,
        message,
        &context,
        rng,
        &pk_hash,
        delta_bytes,
    )
    .map_err(|e| PabsCrfError::SignFailed(format!("Core MLWE signing failed: {}", e)))?;

    let core = CorePredicateSignature {
        z: mlwe_sig.z,
        challenge: mlwe_sig.challenge,
        hints: mlwe_sig.hints,
        policy: policy.clone(),
        message_hash: Sha256::digest(message).to_vec(),
        attributes_used: used_attributes,
        policy_digest,
        parameter_set_id: parameter_set_id.to_string(),
        gid: sk.gid,
    };

    Ok((core, witness_rows, pk_hash))
}

/// Resolve witness rows from a final signature using the public policy.
pub fn witness_rows_from_attributes(
    policy: &Policy,
    attributes_used: &[String],
) -> PabsCrfResult<Vec<u16>> {
    let lsss = lsss_from_policy_cached(policy)?;
    Ok((0..lsss.rows())
        .filter(|i| attributes_used.contains(&lsss.row_to_attr()[*i]))
        .map(|i| i as u16)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_context_binds_public_metadata() {
        let digest = vec![7u8; 32];
        let mut gid = [3u8; 32];
        let base = challenge_context(&digest, 42, &gid, "top-tier-128");

        let mut different_digest = digest.clone();
        different_digest[0] ^= 0x01;
        assert_ne!(
            base,
            challenge_context(&different_digest, 42, &gid, "top-tier-128")
        );

        assert_ne!(base, challenge_context(&digest, 43, &gid, "top-tier-128"));

        gid[0] ^= 0x01;
        assert_ne!(base, challenge_context(&digest, 42, &gid, "top-tier-128"));

        assert_ne!(
            base,
            challenge_context(&digest, 42, &[3u8; 32], "top-tier-192")
        );
    }

    #[test]
    fn test_center_mod_q_reduction_range() {
        let q: u32 = 4096;
        let half_q = q as i64 / 2;

        let cases: Vec<i32> = vec![
            0,
            1,
            -1,
            (q / 2) as i32,
            (q / 2 + 1) as i32,
            (q - 1) as i32,
            -(q as i32 / 2),
            -((q / 2 + 1) as i32),
            i32::MIN + 1,
            i32::MAX,
        ];

        for &v in &cases {
            let reduced = ((v as i64 % q as i64) + q as i64) % q as i64;
            let centered = if reduced > half_q {
                reduced - q as i64
            } else {
                reduced
            };
            assert!(
                centered > -half_q && centered <= half_q,
                "centered value {} not in (-q/2, q/2] for input {}, q={}",
                centered,
                v,
                q
            );
        }
    }

    #[test]
    fn test_polynomial_vector_mod_q_reduction() {
        let q: u32 = 4096;
        let n = 4;
        let m = 2;
        let half_q = q as i64 / 2;

        let mut pv = PolynomialVector::new(m, n);
        pv.elements[0].coeffs = vec![5000i32, -5000i32, (q as i32) + 100, -(q as i32) - 100];
        pv.elements[1].coeffs = vec![0, q as i32 - 1, 1, -1];

        for j in 0..m {
            for coeff_idx in 0..n {
                let v = pv.elements[j].coeffs[coeff_idx];
                let reduced = ((v as i64 % q as i64) + q as i64) % q as i64;
                let centered = if reduced > half_q {
                    reduced - q as i64
                } else {
                    reduced
                };
                pv.elements[j].coeffs[coeff_idx] = centered as i32;
            }
        }

        for j in 0..m {
            for coeff_idx in 0..n {
                let c = pv.elements[j].coeffs[coeff_idx] as i64;
                assert!(
                    c > -half_q && c <= half_q,
                    "coefficient {} not in (-q/2, q/2] at poly={}, idx={}",
                    c,
                    j,
                    coeff_idx
                );
            }
        }

        assert_eq!(pv.elements[0].coeffs[0], 5000 - q as i32);
        assert_eq!(pv.elements[0].coeffs[1], -5000 + q as i32);
        assert_eq!(pv.elements[0].coeffs[2], 100);
        assert_eq!(pv.elements[0].coeffs[3], -100);
    }

    #[test]
    fn test_i64_accumulator_no_intermediate_overflow() {
        let q: u32 = 8380417;
        let n = 4;
        let m = 2;

        let mut acc_i64: Vec<Vec<i64>> = (0..m).map(|_| vec![0i64; n]).collect();

        let large_coeff: i64 = (q as i64) / 2 - 1;
        let recon_coeff: i64 = (q as i64) / 2 - 1;

        for _ in 0..3 {
            for j in 0..m {
                for coeff_idx in 0..n {
                    acc_i64[j][coeff_idx] += recon_coeff * large_coeff;
                }
            }
        }

        for j in 0..m {
            for coeff_idx in 0..n {
                let v = acc_i64[j][coeff_idx];
                assert!(
                    v.abs() < i64::MAX / 2,
                    "i64 accumulator should not overflow: got {}",
                    v
                );
                let reduced = ((v % q as i64) + q as i64) % q as i64;
                let centered = if reduced > q as i64 / 2 {
                    reduced - q as i64
                } else {
                    reduced
                };
                assert!(
                    centered.abs() <= q as i64 / 2,
                    "centered value {} should be in (-q/2, q/2]",
                    centered
                );
                let as_i32 = i32::try_from(centered);
                assert!(
                    as_i32.is_ok(),
                    "centered value {} should fit in i32 after mod q reduction",
                    centered
                );
            }
        }
    }
}
