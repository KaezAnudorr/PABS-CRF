use pabs_crf::*;
use rand::thread_rng;
use std::collections::HashMap;
use std::time::Instant;

fn duration_ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn main() {
    println!("=== PABS-CRF Performance Test ===");

    let security_level = 128;
    let iterations = 100;

    // 1. Setup
    let start = Instant::now();
    let (pp, msk) = setup(security_level);
    let pp_struct: PublicParameters =
        bincode::deserialize(pp.get("matrix_a_struct").unwrap()).unwrap();
    let setup_duration = start.elapsed();
    println!(
        "Setup ({} bit): {:.3} ms",
        security_level,
        duration_ms(setup_duration)
    );

    // 2. KeyGen
    let attributes = vec!["user", "admin", "finance", "manager", "staff"];
    let start = Instant::now();
    let mut sk = HashMap::new();
    for _ in 0..iterations {
        sk = keygen(&pp, &msk, &attributes);
    }
    let keygen_duration = start.elapsed() / iterations as u32;
    println!(
        "KeyGen (5 attributes): {:.3} ms",
        duration_ms(keygen_duration)
    );

    // 3. End-to-end PABS signing
    let policy = Policy::parse("admin AND finance").expect("Policy parse failed");
    let message = b"Authentic message for PABS-CRF evaluation";
    let end_to_end = (|| -> PabsCrfResult<_> {
        let start = Instant::now();
        let mut signature = HashMap::new();
        for _ in 0..iterations {
            signature = sign(&sk, message, &policy, 0)?;
        }
        let sign_duration = start.elapsed() / iterations as u32;

        let start = Instant::now();
        let mut result = false;
        for _ in 0..iterations {
            result = verify(&pp, message, &policy, &signature)?;
        }
        let verify_duration = start.elapsed() / iterations as u32;

        let sig_bytes = bincode::serialize(&signature).unwrap();
        let (sig_struct_size, compressed_size) =
            if let Some(sig_struct_bytes) = signature.get("sig_struct") {
                let sig_struct: Signature = bincode::deserialize(sig_struct_bytes).unwrap();
                let compressed = sig_struct.compress(&pp_struct.params).unwrap();
                let compressed_bytes = compressed.to_bytes().unwrap();
                (sig_struct_bytes.len(), compressed_bytes.len())
            } else {
                (0, 0)
            };

        Ok((
            sign_duration,
            verify_duration,
            result,
            sig_bytes.len(),
            sig_struct_size,
            compressed_size,
        ))
    })();

    let mut pabs_sign_ms = None;
    let mut pabs_verify_ms = None;
    let mut pabs_compressed_size = None;

    match end_to_end {
        Ok((
            sign_duration,
            verify_duration,
            result,
            raw_size,
            sig_struct_size,
            compressed_size,
        )) => {
            let sign_ms = duration_ms(sign_duration);
            let verify_ms = duration_ms(verify_duration);
            println!("Sign (Policy = admin AND finance): {:.3} ms", sign_ms);
            println!("Verify: {:.3} ms (Result: {})", verify_ms, result);
            println!("Signature size (raw HashMap): {} bytes", raw_size);
            println!("Signature size (sig_struct): {} bytes", sig_struct_size);
            println!(
                "Signature size (CompressedSignature): {} bytes",
                compressed_size
            );
            if compressed_size > 0 {
                println!(
                    "Compression Ratio: {:.2}x",
                    sig_struct_size as f64 / compressed_size as f64
                );
            }
            pabs_sign_ms = Some(sign_ms);
            pabs_verify_ms = Some(verify_ms);
            pabs_compressed_size = Some(compressed_size);
        }
        Err(err) => {
            println!("Sign (Policy = admin AND finance): N/A");
            println!("Verify: N/A");
            println!("Signature size: N/A");
            println!("End-to-end note: {}", err);
        }
    }

    // 4. Core MLWE signing baseline (lower bound without attribute preimage composition)
    let mut rng = thread_rng();
    let kp = MLWEKeyPair::generate(&pp_struct.params, &mut rng);
    let start = Instant::now();
    let mut mlwe_sig = None;
    for _ in 0..iterations {
        mlwe_sig = Some(
            MLWESignature::try_sign(
                &pp_struct.params,
                &kp,
                message,
                b"benchmark",
                &mut rng,
                &[],
                &[],
            )
            .unwrap(),
        );
    }
    let mlwe_sign_duration = start.elapsed() / iterations as u32;
    let mlwe_sig = mlwe_sig.unwrap();
    let start = Instant::now();
    let mut mlwe_verify_result = false;
    for _ in 0..iterations {
        mlwe_verify_result = MLWESignature::verify(
            &pp_struct.params,
            &kp,
            message,
            b"benchmark",
            &mlwe_sig,
            &[],
            &[],
        );
    }
    let mlwe_verify_duration = start.elapsed() / iterations as u32;
    let mlwe_sig_size = bincode::serialize(&mlwe_sig).unwrap().len();
    println!("MLWE core Sign: {:.3} ms", duration_ms(mlwe_sign_duration));
    println!(
        "MLWE core Verify: {:.3} ms (Result: {})",
        duration_ms(mlwe_verify_duration),
        mlwe_verify_result
    );
    println!("MLWE core Signature size: {} bytes", mlwe_sig_size);

    // 6. Comparison with ML-DSA-44 (Dilithium2 - Security Level 128)
    println!("\n=== Comparison with ML-DSA-44 (Security Level 128) ===");
    println!("Scheme         | Sign Time   | Verify Time | Sig Size");
    println!("---------------|-------------|-------------|----------");

    // Typical ML-DSA-44 numbers on modern CPU
    let mldsa_sign = "0.1 - 0.5 ms";
    let mldsa_verify = "0.05 - 0.1 ms";
    let mldsa_size = "2420 bytes";

    println!(
        "ML-DSA-44      | {:<11} | {:<11} | {}",
        mldsa_sign, mldsa_verify, mldsa_size
    );

    if let (Some(sign_ms), Some(verify_ms), Some(sig_size)) =
        (pabs_sign_ms, pabs_verify_ms, pabs_compressed_size)
    {
        println!(
            "PABS-CRF       | {:>7.3} ms | {:>7.3} ms | {} bytes",
            sign_ms, verify_ms, sig_size
        );
    }

    println!(
        "MLWE-core      | {:>7.3} ms | {:>7.3} ms | {} bytes",
        duration_ms(mlwe_sign_duration),
        duration_ms(mlwe_verify_duration),
        mlwe_sig_size
    );
}
