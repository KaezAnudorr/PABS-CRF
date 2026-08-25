//! Verification performance benchmark

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pabs_crf::*;

fn bench_verify(c: &mut Criterion) {
    let (pp, msk) = setup(128);
    let attributes = vec!["user", "admin", "finance"];
    let sk = keygen(&pp, &msk, &attributes);
    let policy = Policy::parse("admin AND finance").expect("Policy parse should succeed");
    let message = b"Hello, World!";
    let signature = sign(&sk, message, &policy, 0).expect("Sign should succeed");

    c.bench_function("verify", |b| {
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

criterion_group!(benches, bench_verify);
criterion_main!(benches);
