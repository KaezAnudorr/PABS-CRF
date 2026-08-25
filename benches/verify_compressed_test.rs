use pabs_crf::*;
use std::collections::HashMap;

fn calculate_signature_size(signature: &HashMap<String, Vec<u8>>) -> usize {
    signature.values().map(|v| v.len()).sum()
}

fn calculate_compressed_size(compressed: &CompressedSignature) -> usize {
    compressed.to_bytes().unwrap().len()
}

fn main() {
    println!("=== Compression Correctness Test ===\n");

    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);
    let policy = Policy::parse("admin AND finance").unwrap();
    let message = b"Test message";

    let params = MLWEParameters::new_128();

    println!("1. Generating signature...");
    let signature_map = sign(&sk, message, &policy, 0).unwrap();
    let sig_bytes = signature_map.get("sig_struct").unwrap();
    let signature: Signature = bincode::deserialize(sig_bytes).unwrap();
    let orig_size = calculate_signature_size(&signature_map);
    println!(
        "   Original size: {} bytes ({:.2} KB)",
        orig_size,
        orig_size as f64 / 1024.0
    );

    println!("2. Verifying original signature...");
    let orig_verify = verify(&pp, message, &policy, &signature_map).unwrap();
    println!("   Original verify: {}", orig_verify);

    println!("3. Compressing signature...");
    let compressed = signature
        .compress(&params)
        .expect("compression should succeed");
    let comp_size = calculate_compressed_size(&compressed);
    println!(
        "   Compressed size: {} bytes ({:.2} KB)",
        comp_size,
        comp_size as f64 / 1024.0
    );
    println!(
        "   Reduction: {:.1}%",
        (1.0 - comp_size as f64 / orig_size as f64) * 100.0
    );

    println!("4. Verifying compressed signature blob directly...");
    let compressed_blob = compressed.to_bytes().expect("Should compress to bytes");
    let verify_inst = Verify::new();
    let decomp_verify = verify_inst
        .verify_compressed(&pp, message, &policy, &compressed_blob)
        .unwrap();
    println!("   Compressed verify: {}", decomp_verify);

    println!("\n=== Result ===");
    if orig_verify && decomp_verify {
        println!("PASS: Both original and compressed signatures verify correctly");
    } else {
        println!("FAIL: Verification failed!");
        println!("  Original: {}, Compressed: {}", orig_verify, decomp_verify);
    }
}
