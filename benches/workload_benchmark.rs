//! Workload benchmarks for PABS-CRF v4 across three application scenarios.
//!
//! Workload 1 — TON_IoT Network Access Control:
//!   Policy: "(role:admin AND department:finance) OR clearance:level3"
//!   Attributes: 5, medium-complexity mixed AND/OR
//!
//! Workload 2 — Healthcare EHR Access:
//!   Policy: "doctor AND department:cardiology AND clearance:level2"
//!   Attributes: 7, deep 3-way AND
//!
//! Workload 3 — Supply Chain Verification:
//!   Policy: "manufacturer OR distributor_cert OR retailer OR auditor_cert"
//!   Attributes: 6, wide 4-way OR
//!
//! NOTE: Attribute names ending in "OR" (e.g. "distributor", "auditor") trigger
//! the policy parser's consecutive-operator guard ("DISTRIBUTOR OR" uppercases to
//! contain "OR OR"). We append "_cert" to avoid this parser limitation.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pabs_crf::*;
use std::time::Duration;

const W1_NAME: &str = "TON_IoT";
const W1_POLICY: &str = "(role:admin AND department:finance) OR clearance:level3";
const W1_ATTRS: &[&str] = &[
    "role:admin",
    "department:finance",
    "clearance:level3",
    "region:us",
    "device:laptop",
];
const W1_MSG: &[u8] = b"TON_IoT network access request";

const W2_NAME: &str = "Healthcare_EHR";
const W2_POLICY: &str = "doctor AND department:cardiology AND clearance:level2";
const W2_ATTRS: &[&str] = &[
    "doctor",
    "nurse",
    "department:cardiology",
    "department:emergency",
    "clearance:level2",
    "clearance:level3",
    "role:attending",
];
const W2_MSG: &[u8] = b"EHR access request for patient record";

const W3_NAME: &str = "Supply_Chain";
const W3_POLICY: &str = "manufacturer OR distributor_cert OR retailer OR auditor_cert";
const W3_ATTRS: &[&str] = &[
    "manufacturer",
    "distributor_cert",
    "retailer",
    "auditor_cert",
    "certified:true",
    "region:eu",
];
const W3_MSG: &[u8] = b"Supply chain provenance verification";

fn configured_criterion() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(8))
        .sample_size(10)
}

struct WorkloadContext {
    name: &'static str,
    policy_str: &'static str,
    attributes: &'static [&'static str],
    pp: PublicParameters,
    msk: MasterSecretKey,
    sk: keygen::UserSecretKey,
    policy: Policy,
    message: &'static [u8],
}

impl WorkloadContext {
    fn build(
        name: &'static str,
        policy_str: &'static str,
        attributes: &'static [&'static str],
        message: &'static [u8],
    ) -> Self {
        let (pp, msk) = setup::setup_structured(128);
        let sk = keygen::keygen_structured(&pp, &msk, attributes)
            .expect("keygen_structured should succeed");
        let policy = Policy::parse(policy_str).expect("policy should parse");
        WorkloadContext {
            name,
            policy_str,
            attributes,
            pp,
            msk,
            sk,
            policy,
            message,
        }
    }
}

fn bench_workload_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("workload_keygen");

    let w1 = WorkloadContext::build(W1_NAME, W1_POLICY, W1_ATTRS, W1_MSG);
    let w2 = WorkloadContext::build(W2_NAME, W2_POLICY, W2_ATTRS, W2_MSG);
    let w3 = WorkloadContext::build(W3_NAME, W3_POLICY, W3_ATTRS, W3_MSG);

    for ctx in [&w1, &w2, &w3] {
        group.bench_with_input(
            BenchmarkId::new(ctx.name, ctx.attributes.len()),
            &ctx,
            |b, ctx| {
                b.iter(|| {
                    keygen::keygen_structured(
                        black_box(&ctx.pp),
                        black_box(&ctx.msk),
                        black_box(ctx.attributes),
                    )
                });
            },
        );
    }
    group.finish();
}

fn bench_workload_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("workload_sign");

    let w1 = WorkloadContext::build(W1_NAME, W1_POLICY, W1_ATTRS, W1_MSG);
    let w2 = WorkloadContext::build(W2_NAME, W2_POLICY, W2_ATTRS, W2_MSG);
    let w3 = WorkloadContext::build(W3_NAME, W3_POLICY, W3_ATTRS, W3_MSG);

    for ctx in [&w1, &w2, &w3] {
        group.bench_with_input(
            BenchmarkId::new(ctx.name, ctx.policy_str.len()),
            &ctx,
            |b, ctx| {
                b.iter(|| {
                    sign::sign_structured(
                        black_box(&ctx.sk),
                        black_box(ctx.message),
                        black_box(&ctx.policy),
                        black_box(0u64),
                    )
                });
            },
        );
    }
    group.finish();
}

fn bench_workload_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("workload_verify");

    let w1 = WorkloadContext::build(W1_NAME, W1_POLICY, W1_ATTRS, W1_MSG);
    let w2 = WorkloadContext::build(W2_NAME, W2_POLICY, W2_ATTRS, W2_MSG);
    let w3 = WorkloadContext::build(W3_NAME, W3_POLICY, W3_ATTRS, W3_MSG);

    for ctx in [&w1, &w2, &w3] {
        let sig = sign::sign_structured(&ctx.sk, ctx.message, &ctx.policy, 0)
            .expect("sign_structured should succeed");
        group.bench_with_input(
            BenchmarkId::new(ctx.name, ctx.policy_str.len()),
            &ctx,
            |b, ctx| {
                b.iter(|| {
                    verify::verify_signature_struct(
                        black_box(&ctx.pp),
                        black_box(ctx.message),
                        black_box(&ctx.policy),
                        black_box(&sig),
                    )
                });
            },
        );
    }
    group.finish();
}

fn bench_workload_signature_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("workload_sig_size");
    group.sample_size(10);

    let workloads: &[(&str, &str, &[&str], &[u8])] = &[
        (W1_NAME, W1_POLICY, W1_ATTRS, W1_MSG),
        (W2_NAME, W2_POLICY, W2_ATTRS, W2_MSG),
        (W3_NAME, W3_POLICY, W3_ATTRS, W3_MSG),
    ];

    for (name, policy_str, attributes, message) in workloads {
        let (pp, msk) = setup::setup_structured(128);
        let sk = keygen::keygen_structured(&pp, &msk, attributes)
            .expect("keygen_structured should succeed");
        let policy = Policy::parse(policy_str).expect("policy should parse");
        let sig = sign::sign_structured(&sk, message, &policy, 0)
            .expect("sign_structured should succeed");

        let raw_bytes = bincode::serialize(&sig).expect("bincode serialize");
        let compressed = sig.compress(&sk.params).expect("compress should succeed");
        let transport_bytes = compressed.to_bytes().expect("to_bytes should succeed");

        println!(
            "\n[{}] attrs={} | raw={} bytes, compressed_transport={} bytes",
            name,
            attributes.len(),
            raw_bytes.len(),
            transport_bytes.len(),
        );

        group.bench_function(BenchmarkId::new("serialize", *name), |b| {
            b.iter(|| {
                let _ = black_box(bincode::serialize(black_box(&sig)));
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = configured_criterion();
    targets = bench_workload_keygen, bench_workload_sign, bench_workload_verify, bench_workload_signature_size
}
criterion_main!(benches);
