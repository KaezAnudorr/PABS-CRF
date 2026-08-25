use pabs_crf::keygen::keygen_structured;
use pabs_crf::mlwe::{Polynomial, PolynomialVector};
use pabs_crf::setup::try_setup_structured;
use pabs_crf::trapdoor::StrictTrapdoor;
use rand::{thread_rng, RngCore};
use serde_json::json;

fn sample_sparse_challenge(n: usize, tau: usize, rng: &mut impl RngCore) -> Polynomial {
    let mut coefficients = vec![0i32; n];
    let mut selected = 0usize;
    while selected < tau {
        let index = (rng.next_u32() as usize) % n;
        if coefficients[index] == 0 {
            coefficients[index] = if rng.next_u32() & 1 == 0 { 1 } else { -1 };
            selected += 1;
        }
    }
    Polynomial {
        coeffs: coefficients,
    }
}

fn shifted_box_distance(
    first: &PolynomialVector,
    second: &PolynomialVector,
    challenge: &Polynomial,
    y_bound: i64,
) -> (f64, i64, i64) {
    let support_width = (2 * y_bound + 1) as f64;
    let mut log_overlap = 0.0f64;
    let mut max_first_shift = 0i64;
    let mut max_second_shift = 0i64;

    for (first_poly, second_poly) in first.elements.iter().zip(second.elements.iter()) {
        let first_shift = first_poly.mul_challenge_integer(challenge);
        let second_shift = second_poly.mul_challenge_integer(challenge);
        for (&left, &right) in first_shift.coeffs.iter().zip(second_shift.coeffs.iter()) {
            max_first_shift = max_first_shift.max(i64::from(left).abs());
            max_second_shift = max_second_shift.max(i64::from(right).abs());
            let displacement = (i64::from(left) - i64::from(right)).abs() as f64;
            if displacement >= support_width {
                return (1.0, max_first_shift, max_second_shift);
            }
            log_overlap += (-displacement / support_width).ln_1p();
        }
    }

    (1.0 - log_overlap.exp(), max_first_shift, max_second_shift)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut tiers = Vec::new();

    for security_level in [128u32, 192, 256] {
        let (pp, msk) = try_setup_structured(security_level)?;
        let sk = keygen_structured(&pp, &msk, &["role:doctor", "dept:cardiology"])?;

        let witness_norms: Vec<i64> = sk
            .preimages
            .iter()
            .map(|witness| {
                witness
                    .center_coefficients(pp.params.q)
                    .infinity_norm_integer()
            })
            .collect();
        let max_witness_norm = witness_norms.iter().copied().max().unwrap_or(0);
        let required_shift_bound = i64::from(pp.params.tau) * max_witness_norm;
        let configured_beta = i64::from(pp.params.beta);
        let response_window = i64::from(pp.params.gamma1) - configured_beta;
        let y_bound = response_window / 2;

        let target =
            pabs_crf::utils::hash_to_target_vector_with_gid("role:doctor", &sk.gid, &pp.params);
        let mut rng = thread_rng();
        let second_witness = StrictTrapdoor::new(&pp.params).sample_preimage(
            &msk.matrix_a,
            &msk.trapdoor_t,
            &target,
            &mut rng,
        )?;
        let first_witness = sk.preimages[0].center_coefficients(pp.params.q);
        let second_witness = second_witness.center_coefficients(pp.params.q);
        let acceptance_limit = response_window - i64::from(pp.params.eta2);
        let mut sampled_distances = Vec::new();
        let mut all_sampled_supports_accepted = true;
        for _ in 0..64 {
            let challenge = sample_sparse_challenge(pp.params.n, pp.params.tau as usize, &mut rng);
            let (distance, first_shift, second_shift) =
                shifted_box_distance(&first_witness, &second_witness, &challenge, y_bound);
            all_sampled_supports_accepted &= y_bound + first_shift < acceptance_limit
                && y_bound + second_shift < acceptance_limit;
            sampled_distances.push(distance);
        }
        let min_sampled_distance = sampled_distances
            .iter()
            .copied()
            .fold(f64::INFINITY, f64::min);
        let max_sampled_distance = sampled_distances.iter().copied().fold(0.0, f64::max);

        tiers.push(json!({
            "security_level_label": security_level,
            "n": pp.params.n,
            "q": pp.params.q,
            "k": pp.params.k,
            "ell": pp.params.ell,
            "m": pp.params.m,
            "a_prime_columns": pp.params.k - 1,
            "trapdoor_rows": msk.trapdoor_t.rows,
            "trapdoor_columns": msk.trapdoor_t.cols,
            "sigma": pp.params.sigma,
            "tau": pp.params.tau,
            "configured_beta": configured_beta,
            "gamma1": pp.params.gamma1,
            "response_window_gamma1_minus_beta": response_window,
            "sampled_attribute_witness_norms": witness_norms,
            "sampled_max_witness_norm": max_witness_norm,
            "required_beta_for_sampled_witness": required_shift_bound,
            "configured_beta_covers_sampled_witness": configured_beta >= required_shift_bound,
            "required_beta_fits_below_gamma1": required_shift_bound < i64::from(pp.params.gamma1),
            "privacy_audit": {
                "witness_pair_uses_same_target_and_public_gid": true,
                "sampled_sparse_challenges": sampled_distances.len(),
                "all_sampled_shifted_nonce_supports_pass_norm_check": all_sampled_supports_accepted,
                "minimum_exact_conditional_box_distance": min_sampled_distance,
                "maximum_exact_conditional_box_distance": max_sampled_distance,
                "interpretation": "Distances apply to the current bounded-uniform nonce mode for sampled challenges when both shifted supports lie inside the acceptance window."
            },
        }));
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({ "tiers": tiers }))?
    );
    Ok(())
}
