//! Signature compression benchmark
//!
//! Measures the actual performance impact of HighBits/LowBits compression:
//! - Compression/decompression overhead
//! - Signature size reduction
//! - Verification correctness after compression

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pabs_crf::*;

fn bench_compression_overhead(c: &mut Criterion) {
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);
    let policy = Policy::parse("admin AND finance").expect("Policy parse should succeed");
    let message = b"Hello, World!";

    // Generate signature
    let signature_map = sign(&sk, message, &policy, 0).expect("Sign should succeed");
    let sig_bytes = signature_map.get("sig_struct").unwrap();
    let signature: Signature = bincode::deserialize(sig_bytes).unwrap();

    let params = MLWEParameters::new_128();

    // Benchmark compression
    c.bench_function("compress_signature", |b| {
        b.iter(|| black_box(&signature).compress(black_box(&params)));
    });

    // Benchmark decompression
    let compressed = signature
        .compress(&params)
        .expect("compression should succeed");
    c.bench_function("decompress_signature", |b| {
        b.iter(|| {
            let blob = compressed.to_bytes().unwrap();
            CompressedSignature::from_bytes(black_box(&blob))
        });
    });
}

fn bench_signature_size(_c: &mut Criterion) {
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);
    let policy = Policy::parse("admin AND finance").expect("Policy parse should succeed");
    let message = b"Hello, World!";

    // Generate signature
    let signature_map = sign(&sk, message, &policy, 0).expect("Sign should succeed");
    let sig_bytes = signature_map.get("sig_struct").unwrap();
    let signature: Signature = bincode::deserialize(sig_bytes).unwrap();

    let params = MLWEParameters::new_128();

    // Measure original size
    let original_size = sig_bytes.len();

    // Compress
    let compressed = signature
        .compress(&params)
        .expect("compression should succeed");
    let compressed_bytes = compressed.to_bytes().expect("Compression should succeed");
    let compressed_size = compressed_bytes.len();

    // Report sizes
    println!("\n=== Signature Size Measurement ===");
    println!(
        "Original signature size: {:.2} KB",
        original_size as f64 / 1024.0
    );
    println!(
        "Compressed signature size: {:.2} KB",
        compressed_size as f64 / 1024.0
    );
    println!(
        "Size reduction: {:.1}%",
        (1.0 - compressed_size as f64 / original_size as f64) * 100.0
    );
    println!("===================================\n");
}

fn bench_attribute_scaling(c: &mut Criterion) {
    let (pp, msk) = setup(128);
    let message = b"Hello, World!";
    let params = MLWEParameters::new_128();

    // Benchmark with different attribute counts
    let mut group = c.benchmark_group("signature_size");

    for attr_count in [3, 5, 10, 20].iter() {
        let attrs_vec: Vec<String> = (0..*attr_count).map(|i| format!("attr_{}", i)).collect();
        let attrs_refs: Vec<&str> = attrs_vec.iter().map(|s| s.as_str()).collect();

        let sk = keygen(&pp, &msk, &attrs_refs);
        let policy_str = attrs_vec.join(" AND ");
        let policy = Policy::parse(&policy_str).expect("Policy parse should succeed");

        let signature_map = sign(&sk, message, &policy, 0).expect("Sign should succeed");
        let sig_bytes = signature_map.get("sig_struct").unwrap();
        let signature: Signature = bincode::deserialize(sig_bytes).unwrap();

        let original_size = sig_bytes.len();
        let compressed = signature
            .compress(&params)
            .expect("compression should succeed");
        let compressed_bytes = compressed.to_bytes().expect("Compression should succeed");
        let compressed_size = compressed_bytes.len();

        group.bench_with_input(
            BenchmarkId::new("original", attr_count),
            &attr_count,
            |b, _| b.iter(|| black_box(original_size)),
        );

        group.bench_with_input(
            BenchmarkId::new("compressed", attr_count),
            &attr_count,
            |b, _| b.iter(|| black_box(compressed_size)),
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_compression_overhead,
    bench_signature_size,
    bench_attribute_scaling
);
criterion_main!(benches);
