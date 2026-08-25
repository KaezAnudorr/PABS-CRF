//! Performance comparison benchmarks

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pabs_crf::*;
use std::collections::HashMap;

fn bench_security_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("security_levels");

    let security_levels = vec![128, 192, 256];

    for level in security_levels {
        let (pp, msk) = setup(level);
        let attributes = vec!["user", "admin", "finance"];
        let sk = keygen(&pp, &msk, &attributes);
        let policy = Policy::parse("admin AND finance").expect("Policy parse should succeed");
        let message = b"Hello, World!";

        group.bench_function(format!("sign_{}bit", level), |b| {
            b.iter(|| {
                sign(
                    black_box(&sk),
                    black_box(message),
                    black_box(&policy),
                    black_box(0u64),
                )
            });
        });

        let signature = sign(&sk, message, &policy, 0).expect("Sign should succeed");
        group.bench_function(format!("verify_{}bit", level), |b| {
            b.iter(|| {
                verify(
                    black_box(&pp),
                    black_box(message),
                    black_box(&policy),
                    black_box(&signature),
                )
            });
        });
    }

    group.finish();
}

fn bench_attribute_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("attribute_count");

    let attribute_counts = vec![1, 5, 10];
    let (pp, msk) = setup(128);

    for count in attribute_counts {
        let mut attributes: Vec<String> = Vec::new();
        for i in 0..count {
            attributes.push(format!("attr_{}", i));
        }

        let attr_refs: Vec<&str> = attributes.iter().map(|s| s.as_str()).collect();
        let sk = keygen(&pp, &msk, &attr_refs);

        let policy_str = if count > 1 {
            attributes.join(" AND ")
        } else {
            attributes[0].to_string()
        };
        let policy = Policy::parse(&policy_str).expect("Policy parse should succeed");
        let message = b"Hello, World!";

        group.bench_function(format!("keygen_{}attrs", count), |b| {
            b.iter(|| keygen(black_box(&pp), black_box(&msk), black_box(&attr_refs)));
        });

        group.bench_function(format!("sign_{}attrs", count), |b| {
            b.iter(|| {
                sign(
                    black_box(&sk),
                    black_box(message),
                    black_box(&policy),
                    black_box(0u64),
                )
            });
        });

        let signature = sign(&sk, message, &policy, 0).expect("Sign should succeed");
        group.bench_function(format!("verify_{}attrs", count), |b| {
            b.iter(|| {
                verify(
                    black_box(&pp),
                    black_box(message),
                    black_box(&policy),
                    black_box(&signature),
                )
            });
        });
    }

    group.finish();
}

fn bench_policy_complexity(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_complexity");

    let policies = vec![
        ("simple", "admin"),
        ("medium", "admin AND finance"),
        ("complex", "(admin AND finance) OR (user AND manager)"),
    ];

    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance", "manager"];
    let sk = keygen(&pp, &msk, &attributes);
    let message = b"Hello, World!";

    for (name, policy_str) in policies {
        let policy = Policy::parse(policy_str).expect("Policy parse should succeed");

        group.bench_function(format!("sign_{}", name), |b| {
            b.iter(|| {
                sign(
                    black_box(&sk),
                    black_box(message),
                    black_box(&policy),
                    black_box(0u64),
                )
            });
        });

        let signature = sign(&sk, message, &policy, 0).expect("Sign should succeed");
        group.bench_function(format!("verify_{}", name), |b| {
            b.iter(|| {
                verify(
                    black_box(&pp),
                    black_box(message),
                    black_box(&policy),
                    black_box(&signature),
                )
            });
        });
    }

    group.finish();
}

fn bench_message_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_size");

    let message_sizes = vec![10, 100, 1000];

    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attributes);
    let policy = Policy::parse("admin").expect("Policy parse should succeed");

    for size in message_sizes {
        let message = vec![0u8; size];

        group.bench_function(format!("sign_{}B", size), |b| {
            b.iter(|| {
                sign(
                    black_box(&sk),
                    black_box(&message),
                    black_box(&policy),
                    black_box(0u64),
                )
            });
        });

        let signature = sign(&sk, &message, &policy, 0).expect("Sign should succeed");
        group.bench_function(format!("verify_{}B", size), |b| {
            b.iter(|| {
                verify(
                    black_box(&pp),
                    black_box(&message),
                    black_box(&policy),
                    black_box(&signature),
                )
            });
        });
    }

    group.finish();
}

fn bench_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_operations");

    let batch_sizes = vec![1, 5, 10];

    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attributes);
    let policy = Policy::parse("admin").expect("Policy parse should succeed");

    for size in batch_sizes {
        let messages: Vec<&[u8]> = vec![b"Hello, World!"; size];
        let policies: Vec<Policy> = vec![policy.clone(); size];
        let taus: Vec<u64> = vec![0; size];

        let signer = Sign::new();
        group.bench_function(format!("batch_sign_{}", size), |b| {
            b.iter(|| {
                signer.batch_sign(
                    black_box(&sk),
                    black_box(&messages),
                    black_box(&policies),
                    black_box(&taus),
                )
            });
        });

        let signatures: Vec<HashMap<String, Vec<u8>>> = signer
            .batch_sign(&sk, &messages, &policies, &taus)
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .expect("Batch sign should succeed");
        let verifier = Verify::new();
        group.bench_function(format!("batch_verify_{}", size), |b| {
            b.iter(|| {
                verifier.batch_verify(
                    black_box(&pp),
                    black_box(&messages),
                    black_box(&policies),
                    black_box(&signatures),
                )
            });
        });
    }

    group.finish();
}

fn bench_puncture_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("puncture_operations");

    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attributes);

    let tau = 12345;
    group.bench_function("single_puncture", |b| {
        b.iter(|| puncture(black_box(&sk), black_box(tau)));
    });

    let taus = vec![1, 2, 3, 4, 5];
    let puncture = Puncture::new();
    group.bench_function("multiple_puncture", |b| {
        b.iter(|| puncture.puncture_multiple(black_box(&sk), black_box(&taus)));
    });

    let punctured_sk = puncture
        .puncture_multiple(&sk, &taus)
        .expect("Puncture should succeed");
    group.bench_function("puncture_check", |b| {
        b.iter(|| puncture.is_punctured(black_box(&punctured_sk), black_box(tau)));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_security_levels,
    bench_attribute_count,
    bench_policy_complexity,
    bench_message_size,
    bench_batch_operations,
    bench_puncture_operations
);
criterion_main!(benches);
