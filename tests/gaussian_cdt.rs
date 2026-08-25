use pabs_crf::CdtGaussianSampler;
use rand::rngs::OsRng;

#[test]
fn test_cdt_sampler_zero_centered() {
    let sampler = CdtGaussianSampler::new(3.0, 64);
    let mut rng = OsRng;
    let n = 10000;
    let samples: Vec<i32> = (0..n).map(|_| sampler.sample(&mut rng)).collect();
    let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / n as f64;
    assert!(
        mean.abs() < 0.2,
        "CDT sampler should be approximately zero-centered, got mean={}",
        mean
    );
}

#[test]
fn test_cdt_sampler_variance() {
    let sigma = 3.0;
    let sampler = CdtGaussianSampler::new(sigma, 64);
    let mut rng = OsRng;
    let n = 10000;
    let samples: Vec<i32> = (0..n).map(|_| sampler.sample(&mut rng)).collect();
    let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / n as f64;
    let variance: f64 = samples
        .iter()
        .map(|&x| (x as f64 - mean).powi(2))
        .sum::<f64>()
        / n as f64;
    let expected_var = sigma * sigma;
    assert!(
        (variance - expected_var).abs() / expected_var < 0.15,
        "CDT sampler variance should be close to sigma^2={}, got {}",
        expected_var,
        variance
    );
}

#[test]
fn test_cdt_sampler_no_mod_q() {
    let sampler = CdtGaussianSampler::new(3.0, 64);
    let mut rng = OsRng;
    let samples: Vec<i32> = (0..1000).map(|_| sampler.sample(&mut rng)).collect();
    let max_abs = samples.iter().map(|&x| x.unsigned_abs()).max().unwrap();
    assert!(
        (max_abs as f64) < 3.0 * 14.0,
        "CDT samples should be bounded by ~14*sigma, got max={}",
        max_abs
    );
}

#[test]
fn test_cdt_sampler_symmetry() {
    let sampler = CdtGaussianSampler::new(3.0, 64);
    let mut rng = OsRng;
    let n = 10000;
    let samples: Vec<i32> = (0..n).map(|_| sampler.sample(&mut rng)).collect();
    let pos_count = samples.iter().filter(|&&x| x > 0).count();
    let neg_count = samples.iter().filter(|&&x| x < 0).count();
    let ratio = pos_count as f64 / neg_count as f64;
    assert!(
        ratio > 0.85 && ratio < 1.15,
        "CDT sampler should be approximately symmetric, pos/neg ratio={}",
        ratio
    );
}

#[test]
fn test_cdt_sampler_large_sigma() {
    let sigma = 10.0;
    let sampler = CdtGaussianSampler::new(sigma, 64);
    let mut rng = OsRng;
    let n = 10000;
    let samples: Vec<i32> = (0..n).map(|_| sampler.sample(&mut rng)).collect();
    let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / n as f64;
    let variance: f64 = samples
        .iter()
        .map(|&x| (x as f64 - mean).powi(2))
        .sum::<f64>()
        / n as f64;
    let expected_var = sigma * sigma;
    assert!(
        (variance - expected_var).abs() / expected_var < 0.15,
        "CDT sampler with sigma=10 should have variance close to 100, got {}",
        variance
    );
}

#[test]
fn test_cdt_sampler_small_sigma() {
    let sigma = 1.0;
    let sampler = CdtGaussianSampler::new(sigma, 64);
    let mut rng = OsRng;
    let n = 10000;
    let samples: Vec<i32> = (0..n).map(|_| sampler.sample(&mut rng)).collect();
    let zero_count = samples.iter().filter(|&&x| x == 0).count();
    assert!(
        zero_count > n / 4,
        "With sigma=1, zero should be the most frequent value, got {}/{} zeros",
        zero_count,
        n
    );
}

#[test]
fn test_cdt_sampler_poly_dimensions() {
    let sampler = CdtGaussianSampler::new(3.0, 64);
    let mut rng = OsRng;
    let poly = sampler.sample_poly(256, &mut rng);
    assert_eq!(poly.coeffs.len(), 256);
    for &c in &poly.coeffs {
        assert!(
            c.unsigned_abs() < (3.0 * 14.0) as u32,
            "All poly coefficients should be bounded by ~14*sigma, got {}",
            c
        );
    }
}
