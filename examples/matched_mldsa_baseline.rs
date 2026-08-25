use fips204::traits::{Signer, Verifier};
use pabs_crf::{keygen, setup, sign, verify, Policy, PublicParameters, Signature};
use serde::Serialize;
use std::error::Error;
use std::time::Instant;

#[derive(Serialize)]
struct TimingSummary {
    mean_ms: f64,
    median_ms: f64,
    stdev_ms: f64,
    min_ms: f64,
    max_ms: f64,
}

#[derive(Serialize)]
struct BenchmarkRecord {
    scheme: &'static str,
    comparison_scope: &'static str,
    tier_label: String,
    iterations: usize,
    sign: TimingSummary,
    verify: TimingSummary,
    signature_bytes: usize,
    verification_passed: bool,
}

fn summarize(mut samples: Vec<f64>) -> TimingSummary {
    samples.sort_by(|left, right| left.total_cmp(right));
    let count = samples.len() as f64;
    let mean = samples.iter().sum::<f64>() / count;
    let variance = samples
        .iter()
        .map(|sample| (sample - mean).powi(2))
        .sum::<f64>()
        / count;
    TimingSummary {
        mean_ms: mean,
        median_ms: samples[samples.len() / 2],
        stdev_ms: variance.sqrt(),
        min_ms: samples[0],
        max_ms: samples[samples.len() - 1],
    }
}

fn benchmark_pabs(
    security_level: u32,
    iterations: usize,
) -> Result<BenchmarkRecord, Box<dyn Error>> {
    let message = b"matched-platform benchmark message";
    let policy = Policy::parse("role_doctor")?;
    let (pp, msk) = setup(security_level);
    let sk = keygen(&pp, &msk, &["role_doctor", "dept_cardiology"]);
    let pp_struct: PublicParameters = bincode::deserialize(
        pp.get("matrix_a_struct")
            .ok_or("missing structured public parameters")?,
    )?;

    let mut signature = sign(&sk, message, &policy, 0)?;
    for _ in 0..10 {
        signature = sign(&sk, message, &policy, 0)?;
        if !verify(&pp, message, &policy, &signature)? {
            return Err("PABS-CRF warm-up verification failed".into());
        }
    }

    let mut sign_samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        signature = sign(&sk, message, &policy, 0)?;
        sign_samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    let mut verify_samples = Vec::with_capacity(iterations);
    let mut verification_passed = true;
    for _ in 0..iterations {
        let start = Instant::now();
        verification_passed &= verify(&pp, message, &policy, &signature)?;
        verify_samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    let signature_struct: Signature = bincode::deserialize(
        signature
            .get("sig_struct")
            .ok_or("missing structured signature")?,
    )?;
    let signature_bytes = signature_struct
        .compress(&pp_struct.params)?
        .to_bytes()?
        .len();

    Ok(BenchmarkRecord {
        scheme: "PABS-CRF",
        comparison_scope: "full predicate, wrapper, refusal-check, and compact transport path",
        tier_label: format!("nominal-{} (not estimator-validated)", security_level),
        iterations,
        sign: summarize(sign_samples),
        verify: summarize(verify_samples),
        signature_bytes,
        verification_passed,
    })
}

macro_rules! define_mldsa_benchmark {
    ($function_name:ident, $module_name:ident, $label:literal) => {
        fn $function_name(iterations: usize) -> Result<BenchmarkRecord, Box<dyn Error>> {
            use fips204::$module_name;

            let message = b"matched-platform benchmark message";
            let (public_key, secret_key) = $module_name::try_keygen()?;
            let mut signature = secret_key.try_sign(message, &[])?;
            for _ in 0..10 {
                signature = secret_key.try_sign(message, &[])?;
                if !public_key.verify(message, &signature, &[]) {
                    return Err(concat!($label, " warm-up verification failed").into());
                }
            }

            let mut sign_samples = Vec::with_capacity(iterations);
            for _ in 0..iterations {
                let start = Instant::now();
                signature = secret_key.try_sign(message, &[])?;
                sign_samples.push(start.elapsed().as_secs_f64() * 1000.0);
            }

            let mut verify_samples = Vec::with_capacity(iterations);
            let mut verification_passed = true;
            for _ in 0..iterations {
                let start = Instant::now();
                verification_passed &= public_key.verify(message, &signature, &[]);
                verify_samples.push(start.elapsed().as_secs_f64() * 1000.0);
            }

            Ok(BenchmarkRecord {
                scheme: $label,
                comparison_scope: "FIPS 204 signature primitive reference; not an ABS baseline",
                tier_label: $label.to_string(),
                iterations,
                sign: summarize(sign_samples),
                verify: summarize(verify_samples),
                signature_bytes: signature.len(),
                verification_passed,
            })
        }
    };
}

define_mldsa_benchmark!(benchmark_mldsa44, ml_dsa_44, "ML-DSA-44");
define_mldsa_benchmark!(benchmark_mldsa65, ml_dsa_65, "ML-DSA-65");
define_mldsa_benchmark!(benchmark_mldsa87, ml_dsa_87, "ML-DSA-87");

fn main() -> Result<(), Box<dyn Error>> {
    let iterations = std::env::var("PABS_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(100);
    let requested: Vec<String> = std::env::args().skip(1).collect();
    let selected = |name: &str| requested.is_empty() || requested.iter().any(|item| item == name);

    let mut records = Vec::new();
    if selected("pabs-128") {
        records.push(benchmark_pabs(128, iterations)?);
    }
    if selected("mldsa-44") {
        records.push(benchmark_mldsa44(iterations)?);
    }
    if selected("pabs-192") {
        records.push(benchmark_pabs(192, iterations)?);
    }
    if selected("mldsa-65") {
        records.push(benchmark_mldsa65(iterations)?);
    }
    if selected("pabs-256") {
        records.push(benchmark_pabs(256, iterations)?);
    }
    if selected("mldsa-87") {
        records.push(benchmark_mldsa87(iterations)?);
    }

    if records.is_empty() {
        return Err("unknown scheme selector".into());
    }

    let output = serde_json::to_string_pretty(&records)?;
    if let Ok(path) = std::env::var("PABS_BENCH_OUTPUT") {
        std::fs::write(path, format!("{output}\n"))?;
    }
    println!("{output}");
    Ok(())
}
