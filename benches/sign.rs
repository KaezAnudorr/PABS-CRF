//! Release-grade Criterion benchmark suite for the main PABS-CRF hot paths.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pabs_crf::*;
use rand::thread_rng;
use std::time::Duration;

fn configured_criterion() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(8))
        .sample_size(30)
}

fn bench_pabs_end_to_end(c: &mut Criterion) {
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance", "manager", "staff"];
    let sk = keygen(&pp, &msk, &attributes);
    let policy = Policy::parse("admin AND finance").expect("policy should parse");
    let message = b"benchmark message";

    let mut group = c.benchmark_group("pabs_release");
    group.bench_function("keygen_5_attrs", |b| {
        b.iter(|| keygen(black_box(&pp), black_box(&msk), black_box(&attributes)));
    });
    group.bench_function("sign_policy_admin_and_finance", |b| {
        b.iter(|| {
            sign(
                black_box(&sk),
                black_box(message),
                black_box(&policy),
                black_box(0u64),
            )
            .expect("sign should succeed")
        });
    });

    let signature = sign(&sk, message, &policy, 0).expect("sign should succeed");
    group.bench_function("verify_policy_admin_and_finance", |b| {
        b.iter(|| {
            verify(
                black_box(&pp),
                black_box(message),
                black_box(&policy),
                black_box(&signature),
            )
            .expect("verify should succeed")
        });
    });

    let verifier = Verify::new();
    let compressed = Sign::new()
        .sign_compressed(&sk, message, &policy, 0)
        .expect("compressed sign should succeed");
    group.bench_function("verify_compressed_policy_admin_and_finance", |b| {
        b.iter(|| {
            verifier
                .verify_compressed(
                    black_box(&pp),
                    black_box(message),
                    black_box(&policy),
                    black_box(&compressed),
                )
                .expect("compressed verify should succeed")
        });
    });
    group.finish();
}

fn bench_mlwe_core(c: &mut Criterion) {
    let params = MLWEParameters::new_128();
    let mut rng = thread_rng();
    let kp = MLWEKeyPair::generate(&params, &mut rng);
    let message = b"benchmark message";
    let context = b"criterion";

    let mut group = c.benchmark_group("mlwe_core_release");
    group.bench_function("sign", |b| {
        b.iter(|| {
            MLWESignature::try_sign(
                black_box(&params),
                black_box(&kp),
                black_box(message),
                black_box(context),
                black_box(&mut rng),
                black_box(&[]),
                black_box(&[]),
            )
            .unwrap()
        });
    });

    let sig = MLWESignature::try_sign(&params, &kp, message, context, &mut rng, &[], &[]).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| {
            MLWESignature::verify(
                black_box(&params),
                black_box(&kp),
                black_box(message),
                black_box(context),
                black_box(&sig),
                black_box(&[]),
                black_box(&[]),
            )
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = configured_criterion();
    targets = bench_pabs_end_to_end, bench_mlwe_core
}
criterion_main!(benches);
