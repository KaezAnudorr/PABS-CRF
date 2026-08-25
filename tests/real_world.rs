//! Real-world dataset tests for the PABS-CRF scheme
//!
//! These tests validate the scheme's performance and security in practical scenarios.
//! Includes integration with TON_IoT dataset for realistic IoT device testing.

use pabs_crf::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Instant;
#[derive(Debug, Clone)]
struct IotRecord {
    timestamp: u64,
    _date: String,
    _time: String,
    device_type: String,
    label: u8,
    _attack_type: String,
}

/// Load TON_IoT dataset from CSV file
fn load_ton_iot_dataset(file_name: &str) -> Result<Vec<IotRecord>, String> {
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("datasets")
        .join("TON_IoT")
        .join("Train_Test_IoT_dataset")
        .join(file_name);

    if !base_path.exists() {
        return Err(format!("Dataset file not found: {:?}", base_path));
    }

    let file = File::open(&base_path).map_err(|e| format!("Failed to open file: {}", e))?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    // Skip header line
    for (i, line_result) in reader.lines().enumerate() {
        if i == 0 {
            continue;
        } // Skip header

        let line = line_result.map_err(|e| format!("Failed to read line: {}", e))?;
        let fields: Vec<&str> = line.split(',').collect();

        if fields.len() >= 6 {
            let device_type = file_name
                .replace("Train_Test_IoT_", "")
                .replace(".csv", "")
                .to_lowercase();
            let record = IotRecord {
                timestamp: fields[0].trim().parse().unwrap_or(0),
                _date: fields[1].trim().to_string(),
                _time: fields[2].trim().to_string(),
                device_type,
                label: fields[fields.len() - 2].trim().parse().unwrap_or(0),
                _attack_type: fields[fields.len() - 1].trim().to_string(),
            };
            records.push(record);
        }
    }

    Ok(records)
}

/// Extract IoT device attributes for simple policy matching
fn extract_device_simple_attrs(record: &IotRecord) -> Vec<String> {
    // Device type from filename is lowercase (fridge, gps_tracker, weather)
    // Policy needs to find exact match - use lowercase
    vec![
        record.device_type.to_lowercase(), // e.g., "fridge"
    ]
}

#[test]
fn test_ton_iot_signature_size_and_block_time() {
    // Test signature size and block generation time on TON_IoT dataset
    // This measures real-world performance metrics for paper experiments

    let device_files = vec![
        ("Train_Test_IoT_Fridge.csv", "fridge"),
        ("Train_Test_IoT_GPS_Tracker.csv", "gps_tracker"),
        ("Train_Test_IoT_Weather.csv", "weather"),
    ];

    let (pp, msk) = setup(128);

    println!("\n===== TON_IoT Signature Size & Block Time Analysis =====\n");

    for (file_name, device_type) in device_files {
        let records = match load_ton_iot_dataset(file_name) {
            Ok(r) => r,
            Err(_) => {
                println!("  {} - Dataset not found", device_type);
                continue;
            }
        };

        println!(
            "--- {} Device ({} records) ---",
            device_type.to_uppercase(),
            records.len()
        );

        // Create device key
        let sample_record = &records[0];
        let device_attrs = extract_device_simple_attrs(sample_record);
        let device_attr_refs: Vec<&str> = device_attrs.iter().map(|s| s.as_ref()).collect();
        let sk = keygen(&pp, &msk, &device_attr_refs);

        let policy = Policy::parse(device_type).expect("valid policy");

        // Test 100 records for statistics
        let test_records: Vec<IotRecord> = records
            .iter()
            .step_by(records.len() / 100)
            .take(100)
            .cloned()
            .collect();

        let mut signature_sizes: Vec<usize> = Vec::new();
        let mut sign_times: Vec<u128> = Vec::new();
        let mut verify_times: Vec<u128> = Vec::new();
        let mut block_times: Vec<u128> = Vec::new();

        // Simulate block generation (batch of 10 signatures per block)
        let block_size = 10;
        for chunk in test_records.chunks(block_size) {
            let block_start = Instant::now();
            let mut block_signatures = Vec::new();

            for record in chunk {
                let message = format!(
                    "{}_data_ts_{}_label_{}",
                    device_type, record.timestamp, record.label
                )
                .into_bytes();

                // Sign
                let sign_start = Instant::now();
                let sig = sign(&sk, &message, &policy, 0).expect("sign should succeed");
                let sign_time = sign_start.elapsed().as_micros();
                sign_times.push(sign_time);

                // Measure signature size
                let sig_size = bincode::serialize(&sig).unwrap().len();
                signature_sizes.push(sig_size);

                // Verify
                let verify_start = Instant::now();
                assert!(verify(&pp, &message, &policy, &sig).expect("verify should succeed"));
                let verify_time = verify_start.elapsed().as_micros();
                verify_times.push(verify_time);

                block_signatures.push(sig);
            }

            let block_time = block_start.elapsed().as_millis();
            block_times.push(block_time);
        }

        // Calculate statistics
        let avg_sig_size: f64 =
            signature_sizes.iter().sum::<usize>() as f64 / signature_sizes.len() as f64;
        let avg_sign: f64 = sign_times.iter().sum::<u128>() as f64 / sign_times.len() as f64;
        let avg_verify: f64 = verify_times.iter().sum::<u128>() as f64 / verify_times.len() as f64;
        let avg_block: f64 = block_times.iter().sum::<u128>() as f64 / block_times.len() as f64;

        // Min/Max
        let min_sig_size = *signature_sizes.iter().min().unwrap();
        let max_sig_size = *signature_sizes.iter().max().unwrap();
        let min_sign = *sign_times.iter().min().unwrap();
        let max_sign = *sign_times.iter().max().unwrap();

        println!("  Signature Size:");
        println!(
            "    Average: {:.2} bytes ({:.2} KB)",
            avg_sig_size,
            avg_sig_size / 1024.0
        );
        println!(
            "    Min: {} bytes, Max: {} bytes",
            min_sig_size, max_sig_size
        );
        println!("  Timing (per signature):");
        println!(
            "    Sign: {:.2} μs (min: {} μs, max: {} μs)",
            avg_sign, min_sign, max_sign
        );
        println!("    Verify: {:.2} μs", avg_verify);
        println!(
            "  Block Time ({} signatures): {:.2} ms",
            block_size, avg_block
        );
        println!(
            "  TPS: {:.1} signatures/sec",
            1000.0 / avg_sign * 1_000_000.0 / 1_000_000.0
        );
        println!(
            "  Throughput: {:.2} signatures/sec (block-based)",
            block_size as f64 / (avg_block / 1000.0)
        );
        println!();
    }

    println!("===== Analysis Complete =====\n");
}

#[test]
fn test_ton_iot_fridge_scenario() {
    // Test with TON_IoT fridge dataset
    // This validates the scheme using real IoT sensor data

    // Load dataset
    let records = match load_ton_iot_dataset("Train_Test_IoT_Fridge.csv") {
        Ok(r) => r,
        Err(_) => {
            eprintln!("Skipping test: TON_IoT dataset not found");
            return;
        }
    };

    println!(
        "Loaded {} fridge records from TON_IoT dataset",
        records.len()
    );

    // Setup scheme
    let (pp, msk) = setup(128);

    // Create fridge device key
    let sample_record = &records[0];
    let device_attrs = extract_device_simple_attrs(sample_record);
    let device_attr_refs: Vec<&str> = device_attrs.iter().map(|s| s.as_ref()).collect();
    let sk = keygen(&pp, &msk, &device_attr_refs);

    // Policy: simple attribute name matching
    let policy = Policy::parse("fridge").expect("valid policy");

    // Sample 50 records for testing
    let test_records: Vec<IotRecord> = records
        .iter()
        .step_by(records.len() / 50)
        .take(50)
        .cloned()
        .collect();

    let mut sign_times = Vec::new();
    let mut verify_times = Vec::new();

    for record in &test_records {
        // Create message from real sensor data
        let message = format!(
            "fridge_temp_record_ts_{}_label_{}",
            record.timestamp, record.label
        )
        .into_bytes();

        // Sign
        let start = Instant::now();
        let sig = sign(&sk, &message, &policy, 0).expect("sign should succeed");
        sign_times.push(start.elapsed());

        // Verify
        let start = Instant::now();
        assert!(verify(&pp, &message, &policy, &sig).expect("verify should succeed"));
        verify_times.push(start.elapsed());
    }

    // Calculate statistics
    let avg_sign: u128 =
        sign_times.iter().map(|d| d.as_micros()).sum::<u128>() / sign_times.len() as u128;
    let avg_verify: u128 =
        verify_times.iter().map(|d| d.as_micros()).sum::<u128>() / verify_times.len() as u128;

    println!(
        "TON_IoT Fridge scenario - Records: {}, Avg sign: {} μs, Avg verify: {} μs",
        test_records.len(),
        avg_sign,
        avg_verify
    );

    // IoT devices should be able to sign within reasonable time
    // Academic implementation over WSL mounted FS is slower than native
    // Native Linux would be ~850 μs, WSL adds ~100x overhead
    assert!(avg_sign < 150000); // Under 150ms per signature (WSL bound)
}

#[test]
fn test_ton_iot_multi_device_scenario() {
    // Test with multiple IoT device types from TON_IoT dataset
    // This validates cross-device authentication

    let device_files = vec![
        ("Train_Test_IoT_Fridge.csv", "fridge"),
        ("Train_Test_IoT_GPS_Tracker.csv", "gps_tracker"),
        ("Train_Test_IoT_Weather.csv", "weather"),
    ];

    let (pp, msk) = setup(128);
    let mut total_records = 0;
    let mut success_count = 0;

    for (file_name, device_type) in device_files {
        let records = match load_ton_iot_dataset(file_name) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if records.is_empty() {
            continue;
        }

        println!(
            "Testing {} device with {} records",
            device_type,
            records.len()
        );
        total_records += records.len();

        // Create device key
        let sample_record = &records[0];
        let device_attrs = extract_device_simple_attrs(sample_record);
        let device_attr_refs: Vec<&str> = device_attrs.iter().map(|s| s.as_ref()).collect();
        let sk = keygen(&pp, &msk, &device_attr_refs);

        // Policy for this device type - simple attribute name
        let policy = Policy::parse(device_type).expect("valid policy");

        // Test 20 records per device
        let step = (records.len() / 20).max(1);
        for record in records.iter().step_by(step).take(20) {
            let message = format!(
                "{}_data_ts_{}_label_{}",
                device_type, record.timestamp, record.label
            )
            .into_bytes();

            let sig = sign(&sk, &message, &policy, 0).expect("sign should succeed");
            if verify(&pp, &message, &policy, &sig).expect("verify should succeed") {
                success_count += 1;
            }
        }
    }

    println!(
        "Multi-device test - Total records: {}, Success: {}",
        total_records, success_count
    );
    if total_records == 0 {
        eprintln!("Skipping test: TON_IoT datasets not found");
        return;
    }
    assert!(success_count > 0);
}

#[test]
fn test_ton_iot_attack_detection_scenario() {
    // Test using attack vs normal traffic from TON_IoT dataset
    // This validates the puncture mechanism for attack detection

    let records = match load_ton_iot_dataset("Train_Test_IoT_Weather.csv") {
        Ok(r) => r,
        Err(_) => {
            eprintln!("Skipping test: TON_IoT dataset not found");
            return;
        }
    };

    // Separate normal and attack records
    let normal_records: Vec<_> = records.iter().filter(|r| r.label == 0).collect();
    let attack_records: Vec<_> = records.iter().filter(|r| r.label == 1).collect();

    println!(
        "Weather dataset - Normal: {}, Attack: {}",
        normal_records.len(),
        attack_records.len()
    );

    let (pp, msk) = setup(128);

    // Create weather station key
    let device_attrs = vec!["device_type:weather", "role:sensor", "network:iot_network"];
    let sk = keygen(&pp, &msk, &device_attrs);

    let policy = Policy::parse("device_type:weather AND role:sensor").expect("valid policy");

    // Sign and verify normal records
    for record in normal_records.iter().take(10) {
        let message = format!("weather_normal_ts_{}", record.timestamp).into_bytes();
        let sig = sign(&sk, &message, &policy, 0).expect("sign should succeed");
        assert!(verify(&pp, &message, &policy, &sig).expect("verify should succeed"));
    }

    // Sign and verify attack records (simulating compromised device)
    for record in attack_records.iter().take(10) {
        let message = format!("weather_attack_ts_{}", record.timestamp).into_bytes();
        let sig = sign(&sk, &message, &policy, 0).expect("sign should succeed");
        assert!(verify(&pp, &message, &policy, &sig).expect("verify should succeed"));

        // Puncture the timestamp (revoke access)
        let puncture = Puncture::new();
        let punctured_sk = puncture
            .puncture(&sk, record.timestamp)
            .expect("Puncture should succeed");

        // After puncture, verification with punctured check should fail (return error)
        let verifier = Verify::new();
        let verify_result = verifier.verify_with_local_puncture_state(
            &punctured_sk,
            &pp,
            &message,
            &policy,
            &sig,
            record.timestamp,
        );
        assert!(
            verify_result.is_err(),
            "Punctured tag verification should return error"
        );
    }

    println!("Attack detection test completed successfully");
}

#[test]
fn test_iot_device_scenario() {
    // Simulate IoT device authentication scenario
    // Real-world parameters from NIST IoT security guidelines

    // Setup with minimal parameters for IoT
    let (pp, msk) = setup(128);

    // IoT device attributes
    let device_attrs = vec!["device_type:sensor", "location:factory_a", "org:company_x"];
    let sk = keygen(&pp, &msk, &device_attrs);

    // Simulate 50 IoT messages (reduced from 1000 for WSL performance)
    let messages: Vec<Vec<u8>> = (0..50)
        .map(|i| {
            format!(
                "sensor_data_{}_temp_{}_humidity_{}",
                i,
                20 + (i % 10),
                50 + (i % 20)
            )
            .as_bytes()
            .to_vec()
        })
        .collect();

    let policy = Policy::parse("device_type:sensor").expect("valid policy");

    // Sign and verify all messages
    let mut sign_times = Vec::new();
    let mut verify_times = Vec::new();

    for msg in &messages {
        // Sign
        let start = Instant::now();
        let sig = sign(&sk, msg, &policy, 0).expect("sign should succeed");
        sign_times.push(start.elapsed());

        // Verify
        let start = Instant::now();
        assert!(verify(&pp, msg, &policy, &sig).expect("verify should succeed"));
        verify_times.push(start.elapsed());
    }

    // Calculate statistics
    let avg_sign: u128 =
        sign_times.iter().map(|d| d.as_micros()).sum::<u128>() / sign_times.len() as u128;
    let avg_verify: u128 =
        verify_times.iter().map(|d| d.as_micros()).sum::<u128>() / verify_times.len() as u128;

    // IoT devices should be able to sign within reasonable time
    // WSL mounted FS adds ~100x overhead; native Linux would be ~850 μs
    println!(
        "IoT scenario - Avg sign time: {} μs, Avg verify time: {} μs",
        avg_sign, avg_verify
    );
    assert!(avg_sign < 150000); // Under 150ms per signature (WSL bound)
}

#[test]
fn test_healthcare_data_sharing() {
    // Simulate healthcare data sharing scenario
    // Based on HIPAA requirements for medical data access control

    let (pp, msk) = setup(128);

    // Doctor's attributes
    let doctor_attrs = vec!["doctor", "cardiology", "central_hospital", "level3"];
    let sk = keygen(&pp, &msk, &doctor_attrs);

    // Medical record access policies (without colons to test if colons are the issue)
    let policies = vec![
        Policy::parse("doctor AND cardiology").expect("valid policy"),
        Policy::parse("doctor AND level3").expect("valid policy"),
        Policy::parse("central_hospital AND level3").expect("valid policy"),
    ];

    // Medical records (simulated)
    let medical_records: Vec<Vec<u8>> = vec![
        b"patient_1234_ecg_data_2024".to_vec(),
        b"patient_5678_mri_scan_results".to_vec(),
        b"patient_9012_blood_test_results".to_vec(),
    ];

    // Test that doctor can access records with proper policy
    for (record, policy) in medical_records.iter().zip(policies.iter()) {
        let sig = sign(&sk, record, policy, 0).expect("sign should succeed");
        assert!(verify(&pp, record, policy, &sig).expect("verify should succeed"));
    }

    // Test puncturing after time period expires
    let tau = 20240101; // Time tag for date
    let punctured_sk = puncture(&sk, tau).expect("puncture should succeed");

    // Old signatures should still be valid (if not punctured)
    for (record, policy) in medical_records.iter().take(1).zip(policies.iter().take(1)) {
        let sig = sign(&sk, record, policy, 0).expect("sign should succeed");
        let verifier = Verify::new();
        let verify_result = verifier
            .verify_with_local_puncture_state(&punctured_sk, &pp, record, policy, &sig, tau + 1)
            .expect("verify_punctured should succeed");
        assert!(verify_result);
    }
}

#[test]
fn test_blockchain_transaction_signing() {
    // Simulate blockchain transaction signing scenario
    // Based on Ethereum and Solana requirements

    let (pp, msk) = setup(128);

    // Blockchain validator attributes
    let validator_attrs = vec!["role:validator", "stake:high", "network:mainnet"];
    let sk = keygen(&pp, &msk, &validator_attrs);

    let policy = Policy::parse("role:validator AND network:mainnet").expect("valid policy");

    // Simulate 100 blockchain transactions
    let transactions: Vec<Vec<u8>> = (0..100)
        .map(|i| {
            format!(
                "tx_{}_from_0xABC_to_0xDEF_value_{}_gas_1000",
                i,
                1000 + i * 100
            )
            .as_bytes()
            .to_vec()
        })
        .collect();

    let mut total_sign_time = 0;
    let mut total_verify_time = 0;

    for tx in &transactions {
        // Sign transaction
        let start = Instant::now();
        let sig = sign(&sk, tx, &policy, 0).expect("sign should succeed");
        total_sign_time += start.elapsed().as_micros();

        // Verify transaction
        let start = Instant::now();
        assert!(verify(&pp, tx, &policy, &sig).expect("verify should succeed"));
        total_verify_time += start.elapsed().as_micros();
    }

    let avg_sign = total_sign_time / transactions.len() as u128;
    let avg_verify = total_verify_time / transactions.len() as u128;

    println!(
        "Blockchain scenario - Avg sign: {} μs, Avg verify: {} μs",
        avg_sign, avg_verify
    );

    let verify_threshold = if cfg!(debug_assertions) {
        120_000
    } else {
        10_000
    };
    assert!(
        avg_verify < verify_threshold,
        "avg_verify = {} μs exceeds threshold {} μs",
        avg_verify,
        verify_threshold
    );
}

#[test]
fn test_large_scale_attribute_revocation() {
    // Test large-scale attribute revocation using binary tree puncture

    let (pp, msk) = setup(128);

    // User with many attributes
    let user_attrs: Vec<String> = (0..50).map(|i| format!("attr_{}", i)).collect();
    let user_attrs_refs: Vec<&str> = user_attrs.iter().map(|s| s.as_ref()).collect();
    let sk = keygen(&pp, &msk, &user_attrs_refs);

    // Test puncturing 1000 time tags
    let taus: Vec<u64> = (0..1000).collect();
    let puncture = Puncture::new();
    let punctured_sk = puncture
        .puncture_multiple(&sk, &taus)
        .expect("Puncture multiple should succeed");

    // Verify all punctured tags are marked
    for tau in &taus {
        assert!(puncture
            .is_punctured(&punctured_sk, *tau)
            .expect("is_punctured should succeed"));
    }

    // Verify non-punctured tags are not marked
    assert!(!puncture
        .is_punctured(&punctured_sk, 1001)
        .expect("is_punctured should succeed"));
    assert!(!puncture
        .is_punctured(&punctured_sk, 999999)
        .expect("is_punctured should succeed"));

    // Get puncture statistics
    let punctured_tags = puncture
        .get_punctured_tags(&punctured_sk)
        .expect("get_punctured_tags should succeed");
    assert_eq!(punctured_tags.len(), 1000);
}

#[test]
fn test_puncture_proof_verification() {
    // Test puncture proof generation and verification

    let (pp, msk) = setup(128);
    let attrs = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attrs);

    // Puncture some tags
    let taus = vec![100, 200, 300];
    let puncture = Puncture::new();
    let punctured_sk = puncture
        .puncture_multiple(&sk, &taus)
        .expect("Puncture multiple should succeed");

    // Generate and verify puncture proofs
    for tau in &taus {
        let proof = puncture
            .get_puncture_proof(&punctured_sk, *tau)
            .expect("get_puncture_proof should succeed");
        assert!(proof.is_some());

        let proof = proof.unwrap();
        assert!(!proof.is_empty());

        // Verify proof
        let tree: PunctureTree = bincode::deserialize(&punctured_sk["puncture_tree"]).unwrap();
        assert!(tree.verify_puncture_proof(*tau, &proof).unwrap());
    }
}

#[test]
#[ignore = "run explicitly in a release build on a controlled benchmark host"]
fn test_real_world_performance() {
    // Comprehensive performance test

    // Test different security levels
    let security_levels = vec![128];

    for level in security_levels {
        let (pp, msk) = setup(level);
        let attrs = vec!["user", "admin", "finance"];
        let sk = keygen(&pp, &msk, &attrs);

        let policy = Policy::parse("admin AND finance").expect("valid policy");
        let message = b"Real-world test message with realistic length and content";

        // Run multiple iterations
        let iterations = 5;
        let mut sign_times = Vec::new();
        let mut verify_times = Vec::new();

        for _ in 0..iterations {
            let start = Instant::now();
            let sig = sign(&sk, message, &policy, 0).expect("sign should succeed");
            sign_times.push(start.elapsed());

            let start = Instant::now();
            assert!(verify(&pp, message, &policy, &sig).expect("verify should succeed"));
            verify_times.push(start.elapsed());
        }

        // Calculate and print statistics
        let avg_sign: u128 =
            sign_times.iter().map(|d| d.as_micros()).sum::<u128>() / iterations as u128;
        let avg_verify: u128 =
            verify_times.iter().map(|d| d.as_micros()).sum::<u128>() / iterations as u128;

        println!(
            "Security level {} - Sign: {} μs, Verify: {} μs",
            level, avg_sign, avg_verify
        );

        // WSL mounted filesystem adds ~100x overhead for crypto operations
        // Native Linux would be ~900 μs, WSL is ~90ms
        // These bounds are for WSL verification; native Linux would be much faster
        assert!(avg_sign < 150000); // Under 150ms (WSL bound)
        assert!(avg_verify < 20000); // Under 20ms (WSL bound)
    }
}

#[test]
fn test_signature_size_analysis() {
    use pabs_crf::{Sign, Verify};

    let (pp, msk) = setup(128);
    let attrs = vec!["user", "admin"];
    let sk = keygen(&pp, &msk, &attrs);

    let policy = Policy::parse("admin").expect("valid policy");
    let message = b"Test message for size analysis";

    let sig = sign(&sk, message, &policy, 0).expect("sign should succeed");

    let sig_bytes = bincode::serialize(&sig).unwrap();

    println!("=== Signature Size Analysis ===");
    println!(
        "Bincode (legacy): {} bytes ({:.1} KB)",
        sig_bytes.len(),
        sig_bytes.len() as f64 / 1024.0
    );

    let signer = Sign::new();
    let verifier = Verify::new();

    let compressed_sig = signer
        .sign_compressed(&sk, message, &policy, 0)
        .expect("compressed sign should succeed");
    println!(
        "ZSTD compressed:  {} bytes ({:.1} KB)",
        compressed_sig.len(),
        compressed_sig.len() as f64 / 1024.0
    );
    println!("");

    let csig = pabs_crf::serialization::deserialize_compressed_signature(&compressed_sig)
        .expect("deserialize should succeed");
    let layout = pabs_crf::serialization::measure_layout(&csig).expect("measure should succeed");

    println!(
        "Raw compact layout breakdown (total {} bytes = {:.1} KB):",
        layout.raw_total,
        layout.raw_total as f64 / 1024.0
    );
    println!(
        "  packed_z:      {:>6} bytes  ({:4.1}%)",
        layout.packed_z,
        layout.packed_z as f64 / layout.raw_total as f64 * 100.0
    );
    println!(
        "  packed_delta:  {:>6} bytes  ({:4.1}%)",
        layout.packed_delta,
        layout.packed_delta as f64 / layout.raw_total as f64 * 100.0
    );
    println!(
        "  encoded_c:    {:>6} bytes  ({:4.1}%)",
        layout.encoded_c,
        layout.encoded_c as f64 / layout.raw_total as f64 * 100.0
    );
    println!(
        "  packed_hints:  {:>6} bytes  ({:4.1}%)",
        layout.packed_hints,
        layout.packed_hints as f64 / layout.raw_total as f64 * 100.0
    );
    println!(
        "  pk_hash:      {:>6} bytes  ({:4.1}%)",
        layout.pk_hash,
        layout.pk_hash as f64 / layout.raw_total as f64 * 100.0
    );
    println!(
        "  witness_rows: {:>6} bytes  ({:4.1}%)",
        layout.witness_rows,
        layout.witness_rows as f64 / layout.raw_total as f64 * 100.0
    );
    println!(
        "  param_id:     {:>6} bytes  ({:4.1}%)",
        layout.param_id,
        layout.param_id as f64 / layout.raw_total as f64 * 100.0
    );
    println!(
        "  header+trailer:{:>5} bytes  ({:4.1}%)",
        layout.header + layout.trailer,
        (layout.header + layout.trailer) as f64 / layout.raw_total as f64 * 100.0
    );
    println!("  ───────────────────────────────");
    println!(
        "  ZSTD output:  {:>6} bytes  ({:.1} KB)",
        layout.zstd_compressed,
        layout.zstd_compressed as f64 / 1024.0
    );

    let verify_result = verifier
        .verify_compressed(&pp, message, &policy, &compressed_sig)
        .expect("verify should succeed");
    assert!(verify_result, "Signature verification should succeed");

    assert!(compressed_sig.len() < 100 * 1024);
}

#[test]
#[ignore = "Security audit fix removed the 'attempts' metadata side channel; rejection sampling behavior is no longer exposed via signature metadata, see mlwe.rs:840"]
fn test_rejection_sampling_behavior() {
    use pabs_crf::mlwe::{MLWEKeyPair, MLWEParameters, MLWESignature};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    let params = MLWEParameters::new_128();
    let mut rng = StdRng::from_entropy();

    let kp = MLWEKeyPair::generate(&params, &mut rng);
    let message = b"Test message for rejection sampling analysis";

    let mut total_attempts = 0;
    let num_trials = 100;

    for i in 0..num_trials {
        let sig =
            MLWESignature::try_sign(&params, &kp, message, b"test-context", &mut rng, &[], &[])
                .unwrap();

        if let Some(attempts_bytes) = sig.metadata.get("attempts") {
            let attempts = u32::from_le_bytes(attempts_bytes[0..4].try_into().unwrap());
            total_attempts += attempts;
            println!("Trial {}: {} attempts", i + 1, attempts);
        }
    }

    let average_attempts = total_attempts as f64 / num_trials as f64;
    println!("\nAverage attempts per signature: {:.2}", average_attempts);
    println!("Expected e ≈ 2.718");

    // Check that average is reasonably close to e
    assert!(
        average_attempts >= 1.0 && average_attempts <= 5.0,
        "Average attempts should be between 1 and 5, got {:.2}",
        average_attempts
    );
}
