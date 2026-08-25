//! Comprehensive Performance Test for PABS-CRF
//!
//! Tests all security levels, attribute counts, policy types, and optimizations.

use pabs_crf::*;
use rand::thread_rng;
use std::collections::HashMap;
use std::time::Instant;

fn duration_ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn main() {
    println!("=== PABS-CRF Comprehensive Performance Test ===");
    println!("Build Configuration:");
    println!(
        "  - AVX-512: {}",
        if cfg!(feature = "avx512") {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    println!(
        "  - Optimization Level: {}",
        if cfg!(debug_assertions) {
            "DEBUG"
        } else {
            "RELEASE"
        }
    );
    println!();

    let security_levels = vec![
        (128, "L1 (NIST-1)"),
        (192, "L3 (NIST-3)"),
        (256, "L5 (NIST-5)"),
    ];

    let attribute_counts = vec![1, 3, 5, 10, 20];
    let iterations = 100;

    for (security_level, level_name) in &security_levels {
        println!("\n{}", "=".repeat(70));
        println!("Security Level: {} bits - {}", security_level, level_name);
        println!("{}", "=".repeat(70));

        // Setup
        let setup_start = Instant::now();
        let (pp, msk) = setup(*security_level);
        let pp_struct: PublicParameters =
            bincode::deserialize(pp.get("matrix_a_struct").unwrap()).unwrap();
        let setup_duration = setup_start.elapsed();
        println!("Setup: {:.3} ms", duration_ms(setup_duration));

        for &attr_count in &attribute_counts {
            println!("\n--- Testing with {} Attributes ---", attr_count);

            // Generate attributes as &str slices
            let attributes: Vec<&str> = match attr_count {
                1 => vec!["attr_0"],
                3 => vec!["attr_0", "attr_1", "attr_2"],
                5 => vec!["attr_0", "attr_1", "attr_2", "attr_3", "attr_4"],
                10 => vec![
                    "attr_0", "attr_1", "attr_2", "attr_3", "attr_4", "attr_5", "attr_6", "attr_7",
                    "attr_8", "attr_9",
                ],
                20 => vec![
                    "attr_0", "attr_1", "attr_2", "attr_3", "attr_4", "attr_5", "attr_6", "attr_7",
                    "attr_8", "attr_9", "attr_10", "attr_11", "attr_12", "attr_13", "attr_14",
                    "attr_15", "attr_16", "attr_17", "attr_18", "attr_19",
                ],
                _ => vec!["attr_0"],
            };

            // KeyGen
            let keygen_start = Instant::now();
            let mut sk = HashMap::new();
            for _ in 0..iterations {
                sk = keygen(&pp, &msk, &attributes);
            }
            let keygen_duration = keygen_start.elapsed() / iterations as u32;
            println!(
                "  KeyGen: {:.3} ms (avg over {} iterations)",
                duration_ms(keygen_duration),
                iterations
            );

            // Test different policy types
            let test_policies = if attr_count >= 4 {
                vec![
                    (
                        "Simple AND (2 attrs)",
                        format!("{} AND {}", attributes[0], attributes[1]),
                    ),
                    (
                        "Simple OR (2 attrs)",
                        format!("{} OR {}", attributes[0], attributes[1]),
                    ),
                    (
                        "Complex AND (3 attrs)",
                        format!(
                            "{} AND {} AND {}",
                            attributes[0], attributes[1], attributes[2]
                        ),
                    ),
                    (
                        "Nested Policy",
                        format!(
                            "({} AND {}) OR ({} AND {})",
                            attributes[0], attributes[1], attributes[2], attributes[3]
                        ),
                    ),
                ]
            } else if attr_count >= 2 {
                vec![
                    (
                        "Simple AND",
                        format!("{} AND {}", attributes[0], attributes[1]),
                    ),
                    (
                        "Simple OR",
                        format!("{} OR {}", attributes[0], attributes[1]),
                    ),
                ]
            } else {
                vec![("Single Attribute", attributes[0].to_string())]
            };

            for (policy_name, policy_str) in test_policies {
                match Policy::parse(&policy_str) {
                    Ok(policy) => {
                        let message = b"Benchmark message for PABS-CRF performance evaluation";

                        // Sign
                        let sign_start = Instant::now();
                        let mut signature = HashMap::new();
                        let mut sign_errors = 0;
                        for _ in 0..iterations {
                            match sign(&sk, message, &policy, 0) {
                                Ok(sig) => signature = sig,
                                Err(_) => sign_errors += 1,
                            }
                        }
                        let sign_duration = sign_start.elapsed() / iterations as u32;

                        // Verify
                        let verify_start = Instant::now();
                        let mut verify_result = false;
                        let mut verify_errors = 0;
                        for _ in 0..iterations {
                            match verify(&pp, message, &policy, &signature) {
                                Ok(r) => verify_result = r,
                                Err(_) => verify_errors += 1,
                            }
                        }
                        let verify_duration = verify_start.elapsed() / iterations as u32;

                        // Signature sizes
                        let raw_size = bincode::serialize(&signature).unwrap().len();
                        let (struct_size, compressed_size, compression_ratio) =
                            if let Some(sig_struct_bytes) = signature.get("sig_struct") {
                                match bincode::deserialize::<Signature>(sig_struct_bytes) {
                                    Ok(sig_struct) => {
                                        let struct_sz = sig_struct_bytes.len();
                                        match sig_struct.compress(&pp_struct.params) {
                                            Ok(compressed) => match compressed.to_bytes() {
                                                Ok(comp_bytes) => {
                                                    let comp_sz = comp_bytes.len();
                                                    let ratio = struct_sz as f64 / comp_sz as f64;
                                                    (struct_sz, comp_sz, ratio)
                                                }
                                                Err(_) => (struct_sz, 0, 0.0),
                                            },
                                            Err(_) => (struct_sz, 0, 0.0),
                                        }
                                    }
                                    Err(_) => (0, 0, 0.0),
                                }
                            } else {
                                (0, 0, 0.0)
                            };

                        println!("  Policy: {}", policy_name);
                        println!(
                            "    Sign:   {:.3} ms (errors: {})",
                            duration_ms(sign_duration),
                            sign_errors
                        );
                        println!(
                            "    Verify: {:.3} ms (result: {}, errors: {})",
                            duration_ms(verify_duration),
                            verify_result,
                            verify_errors
                        );
                        println!(
                            "    Sizes:  raw={} bytes, struct={} bytes, compressed={} bytes",
                            raw_size, struct_size, compressed_size
                        );
                        if compression_ratio > 0.0 {
                            println!("    Compression Ratio: {:.2}x", compression_ratio);
                        }
                    }
                    Err(e) => {
                        println!("  Policy: {} - PARSE ERROR: {}", policy_name, e);
                    }
                }
            }

            // Puncture operations
            println!("\n  --- Puncture Operations ---");
            let puncture_attrs = vec!["user", "admin"];
            let mut sk_puncture = keygen(&pp, &msk, &puncture_attrs);
            let puncture_rounds = 10.min(50);

            let mut puncture_times = Vec::new();
            for tag in 0..puncture_rounds {
                let puncture_start = Instant::now();
                match puncture(&mut sk_puncture, tag) {
                    Ok(_) => {
                        let puncture_duration = puncture_start.elapsed();
                        puncture_times.push(duration_ms(puncture_duration));
                    }
                    Err(e) => {
                        println!("    Puncture tag={} failed: {}", tag, e);
                        break;
                    }
                }
            }

            if !puncture_times.is_empty() {
                let avg_puncture = puncture_times.iter().sum::<f64>() / puncture_times.len() as f64;
                let min_puncture = puncture_times.iter().cloned().fold(f64::INFINITY, f64::min);
                let max_puncture = puncture_times
                    .iter()
                    .cloned()
                    .fold(f64::NEG_INFINITY, f64::max);
                println!(
                    "    Puncture: {:.3} ms (avg), {:.3} ms (min), {:.3} ms (max), {} successful",
                    avg_puncture,
                    min_puncture,
                    max_puncture,
                    puncture_times.len()
                );
            }
        }

        // MLWE Core Baseline
        println!("\n--- MLWE Core Baseline (No Policy Logic) ---");
        let mut rng = thread_rng();
        let kp = MLWEKeyPair::generate(&pp_struct.params, &mut rng);
        let message = b"Baseline message";

        let mlwe_sign_start = Instant::now();
        let mut mlwe_sig = None;
        for _ in 0..iterations {
            mlwe_sig = Some(
                MLWESignature::try_sign(
                    &pp_struct.params,
                    &kp,
                    message,
                    b"mlwe_baseline",
                    &mut rng,
                    &[],
                    &[],
                )
                .unwrap(),
            );
        }
        let mlwe_sign_duration = mlwe_sign_start.elapsed() / iterations as u32;

        let mlwe_sig = mlwe_sig.unwrap();
        let mlwe_verify_start = Instant::now();
        let mut mlwe_verify_result = false;
        for _ in 0..iterations {
            mlwe_verify_result = MLWESignature::verify(
                &pp_struct.params,
                &kp,
                message,
                b"mlwe_baseline",
                &mlwe_sig,
                &[],
                &[],
            );
        }
        let mlwe_verify_duration = mlwe_verify_start.elapsed() / iterations as u32;
        let mlwe_sig_size = bincode::serialize(&mlwe_sig).unwrap().len();

        println!("  MLWE Sign:   {:.3} ms", duration_ms(mlwe_sign_duration));
        println!(
            "  MLWE Verify: {:.3} ms (result: {})",
            duration_ms(mlwe_verify_duration),
            mlwe_verify_result
        );
        println!("  MLWE Signature Size: {} bytes", mlwe_sig_size);
    }

    println!("\n{}", "=".repeat(70));
    println!("Comprehensive Performance Test Complete");
    println!("{}", "=".repeat(70));
}
