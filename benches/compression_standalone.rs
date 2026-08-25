//! Standalone performance test for signature compression
//! Does not require criterion, uses simple timing measurements

use pabs_crf::*;
use std::collections::HashMap;
use std::time::Instant;

fn calculate_signature_size(signature: &HashMap<String, Vec<u8>>) -> usize {
    let mut total = 0;
    for (key, value) in signature {
        total += key.len() + value.len();
    }
    total
}

fn calculate_compressed_size(compressed: &CompressedSignature) -> usize {
    compressed.to_bytes().unwrap().len()
}

fn main() {
    println!("=== PABS-CRF Signature Compression Performance Test ===\n");

    // Setup
    println!("1. Setting up system (security level 128)...");
    let (pp, msk) = setup(128);
    println!("   ✓ Setup complete\n");

    // Key generation
    println!("2. Generating keys for attributes: [user, admin, finance]...");
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);
    println!("   ✓ Key generation complete\n");

    // Policy
    let policy = Policy::parse("admin AND finance").expect("Policy parse should succeed");
    let message = b"Hello, World!";

    // Parameters
    let params = MLWEParameters::new_128();

    // Test 1: Sign and measure size
    println!("3. Testing signature generation and size...");
    let iterations = 100;
    let mut total_sign_time = 0.0;
    let mut total_original_size = 0;
    let mut total_compressed_size = 0;

    for i in 0..iterations {
        let start = Instant::now();
        let signature_map = sign(&sk, message, &policy, 0).expect("Sign should succeed");
        let sig_bytes = signature_map.get("sig_struct").unwrap();
        let signature: Signature = bincode::deserialize(sig_bytes).unwrap();
        let sign_time = start.elapsed().as_micros() as f64;
        total_sign_time += sign_time;

        let original_size = calculate_signature_size(&signature_map);
        total_original_size += original_size;

        let compressed = signature
            .compress(&params)
            .expect("Compression should succeed");
        let compressed_size = calculate_compressed_size(&compressed);
        total_compressed_size += compressed_size;

        if i == 0 {
            println!("   First iteration:");
            println!(
                "     Original size: {:.2} KB",
                original_size as f64 / 1024.0
            );
            println!(
                "     Compressed size: {:.2} KB",
                compressed_size as f64 / 1024.0
            );
            println!(
                "     Reduction: {:.1}%",
                (1.0 - compressed_size as f64 / original_size as f64) * 100.0
            );
        }
    }

    let avg_sign_time = total_sign_time / iterations as f64;
    let avg_original_size = total_original_size / iterations;
    let avg_compressed_size = total_compressed_size / iterations;

    println!("\n   Average over {} iterations:", iterations);
    println!(
        "     Sign time: {:.2} μs ({:.2} ms)",
        avg_sign_time,
        avg_sign_time / 1000.0
    );
    println!(
        "     Original size: {:.2} KB",
        avg_original_size as f64 / 1024.0
    );
    println!(
        "     Compressed size: {:.2} KB",
        avg_compressed_size as f64 / 1024.0
    );
    println!(
        "     Size reduction: {:.1}%",
        (1.0 - avg_compressed_size as f64 / avg_original_size as f64) * 100.0
    );

    // Test 2: Compression overhead
    println!("\n4. Testing compression overhead...");
    let signature_map = sign(&sk, message, &policy, 0).expect("Sign should succeed");
    let sig_bytes = signature_map.get("sig_struct").unwrap();
    let signature: Signature = bincode::deserialize(sig_bytes).unwrap();
    let iterations = 1000;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = signature.compress(&params);
    }
    let compress_time = start.elapsed().as_micros() as f64 / iterations as f64;

    let compressed = signature
        .compress(&params)
        .expect("Compression should succeed");
    let start = Instant::now();
    for _ in 0..iterations {
        let blob = compressed
            .to_bytes()
            .expect("blob serialization should succeed");
        let _ = CompressedSignature::from_bytes(&blob).expect("decompression should succeed");
    }
    let decompress_time = start.elapsed().as_micros() as f64 / iterations as f64;

    println!("   Compression time: {:.2} μs", compress_time);
    println!("   Decompression time: {:.2} μs", decompress_time);
    println!(
        "   Total overhead: {:.2} μs ({:.2} ms)",
        compress_time + decompress_time,
        (compress_time + decompress_time) / 1000.0
    );

    // Test 3: Verification with compression
    println!("\n5. Testing verification with compression...");
    let iterations = 100;
    let mut total_verify_original = 0.0;
    let mut total_verify_compressed = 0.0;

    for _ in 0..iterations {
        let signature = sign(&sk, message, &policy, 0).expect("Sign should succeed");

        // Verify original
        let start = Instant::now();
        let result = verify(&pp, message, &policy, &signature).expect("Verify should succeed");
        let verify_time = start.elapsed().as_micros() as f64;
        total_verify_original += verify_time;
        assert!(result, "Original verification should succeed");

        // Verify compressed (compress -> decompress -> verify)
        let compressed_sig_struct: Signature =
            bincode::deserialize(signature.get("sig_struct").unwrap())
                .expect("sig_struct should deserialize");
        let compressed = compressed_sig_struct
            .compress(&params)
            .expect("Compression should succeed");
        let start = Instant::now();
        let blob = compressed
            .to_bytes()
            .expect("blob serialization should succeed");
        let result = Verify::new()
            .verify_compressed(&pp, message, &policy, &blob)
            .expect("Verify should succeed");
        let verify_time = start.elapsed().as_micros() as f64;
        total_verify_compressed += verify_time;
        assert!(result, "Compressed verification should succeed");
    }

    let avg_verify_original = total_verify_original / iterations as f64;
    let avg_verify_compressed = total_verify_compressed / iterations as f64;

    println!(
        "   Verify (original): {:.2} μs ({:.2} ms)",
        avg_verify_original,
        avg_verify_original / 1000.0
    );
    println!(
        "   Verify (compressed): {:.2} μs ({:.2} ms)",
        avg_verify_compressed,
        avg_verify_compressed / 1000.0
    );
    println!(
        "   Overhead: {:.1}%",
        (avg_verify_compressed / avg_verify_original - 1.0) * 100.0
    );

    // Test 4: Different attribute counts
    println!("\n6. Testing with different attribute counts...");
    for attr_count in [3, 5, 10, 20].iter() {
        let attrs: Vec<String> = (0..*attr_count).map(|i| format!("attr_{}", i)).collect();
        let attr_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();
        let sk = keygen(&pp, &msk, &attr_refs);
        let policy_str = (0..*attr_count)
            .map(|i| format!("attr_{}", i))
            .collect::<Vec<_>>()
            .join(" AND ");
        let policy = Policy::parse(&policy_str).expect("Policy parse should succeed");

        let signature = sign(&sk, message, &policy, 0).expect("Sign should succeed");
        let original_size = calculate_signature_size(&signature);
        let sig_struct: Signature = bincode::deserialize(signature.get("sig_struct").unwrap())
            .expect("sig_struct should deserialize");
        let compressed = sig_struct
            .compress(&params)
            .expect("Compression should succeed");
        let compressed_size = calculate_compressed_size(&compressed);

        println!(
            "   {} attributes: {:.2} KB -> {:.2} KB ({:.1}% reduction)",
            attr_count,
            original_size as f64 / 1024.0,
            compressed_size as f64 / 1024.0,
            (1.0 - compressed_size as f64 / original_size as f64) * 100.0
        );
    }

    // Summary
    println!("\n=== Summary ===");
    println!(
        "Signature size (original): {:.2} KB",
        avg_original_size as f64 / 1024.0
    );
    println!(
        "Signature size (compressed): {:.2} KB",
        avg_compressed_size as f64 / 1024.0
    );
    println!(
        "Size reduction: {:.1}%",
        (1.0 - avg_compressed_size as f64 / avg_original_size as f64) * 100.0
    );
    println!("Sign time: {:.2} ms", avg_sign_time / 1000.0);
    println!(
        "Verify time (original): {:.2} ms",
        avg_verify_original / 1000.0
    );
    println!(
        "Verify time (compressed): {:.2} ms",
        avg_verify_compressed / 1000.0
    );
    println!(
        "Compression overhead: {:.2} μs",
        compress_time + decompress_time
    );
    println!("\n✓ All tests passed!");
}
