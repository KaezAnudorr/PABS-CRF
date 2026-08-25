//! Criterion benchmark suite for the σ sweep.
//!
//! Measures keygen / sign / verify latency and signature size for
//! σ ∈ {3.0, 10, 30, 100, 360}.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pabs_crf::keygen::keygen_structured;
use pabs_crf::policy::Policy;
use pabs_crf::setup::setup_structured_with_sigma;
use pabs_crf::sign::sign_structured;
use pabs_crf::verify::verify_signature_struct;
use std::time::Duration;

fn configured_criterion() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(10)
}

fn bench_sigma_sweep(c: &mut Criterion) {
    let sigmas: Vec<f64> = vec![3.0, 10.0, 30.0, 100.0, 360.0];
    let policy = Policy::parse("admin AND finance").expect("policy should parse");
    let message = b"sigma sweep benchmark message";

    let mut group = c.benchmark_group("sigma_sweep");

    for &sigma in &sigmas {
        let (pp, msk) = setup_structured_with_sigma(128, sigma);
        let sk =
            keygen_structured(&pp, &msk, &["admin", "finance"]).expect("keygen should succeed");
        let sig = sign_structured(&sk, message, &policy, 0).expect("sign should succeed");
        let sig_bytes = bincode::serialize(&sig).expect("serialization should succeed");

        println!(
            "[σ={:.1}] gamma1={}, z_bound={}, sig_size={} bytes",
            sigma,
            pp.params.gamma1,
            pp.params.gamma1 - pp.params.beta as u32,
            sig_bytes.len()
        );

        group.bench_with_input(
            BenchmarkId::new("keygen", format!("sigma_{:.0}", sigma)),
            &sigma,
            |b, &_| {
                b.iter(|| {
                    keygen_structured(
                        black_box(&pp),
                        black_box(&msk),
                        black_box(&["admin", "finance"]),
                    )
                    .expect("keygen should succeed")
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("sign", format!("sigma_{:.0}", sigma)),
            &sigma,
            |b, &_| {
                b.iter(|| {
                    sign_structured(
                        black_box(&sk),
                        black_box(message),
                        black_box(&policy),
                        black_box(0u64),
                    )
                    .expect("sign should succeed")
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("verify", format!("sigma_{:.0}", sigma)),
            &sigma,
            |b, &_| {
                b.iter(|| {
                    verify_signature_struct(
                        black_box(&pp),
                        black_box(message),
                        black_box(&policy),
                        black_box(&sig),
                    )
                    .expect("verify should succeed")
                });
            },
        );
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = configured_criterion();
    targets = bench_sigma_sweep
}
criterion_main!(benches);
