#!/bin/bash
set -e
export PATH="/root/.cargo/bin:$PATH"
export RUSTFLAGS="-C target-cpu=native"
cd /mnt/e/Code/password/Scheme1_Lattice_PABS_CRF/academic_implementation_v4

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BENCH_DIR="test-results/bench/${TIMESTAMP}"
mkdir -p "${BENCH_DIR}"

echo "=========================================="
echo "  v4 AVX-512 Full Test & Benchmark"
echo "  ${TIMESTAMP}"
echo "=========================================="

echo ""
echo "[1/6] cargo +nightly check --release --features avx512"
cargo +nightly check --release --features avx512 2>&1 | tee "${BENCH_DIR}/check.log"
echo "CHECK: OK"

echo ""
echo "[2/6] cargo +nightly test --release --features avx512 (avx512_benchmark)"
cargo +nightly test --release --features avx512 --test avx512_benchmark -- --nocapture 2>&1 | tee "${BENCH_DIR}/test_avx512.log"
echo "AVX512 TESTS: OK"

echo ""
echo "[3/6] cargo +nightly test --release --features avx512 (all tests, summary)"
cargo +nightly test --release --features avx512 2>&1 | tee "${BENCH_DIR}/test_all.log"
echo "ALL TESTS: OK"

echo ""
echo "[4/6] cargo +nightly bench --bench sign (scalar baseline)"
cargo +nightly bench --bench sign 2>&1 | tee "${BENCH_DIR}/bench_sign_scalar.log"
echo "SCALAR BENCH: OK"

echo ""
echo "[5/6] cargo +nightly bench --bench sign --features avx512 (AVX-512)"
cargo +nightly bench --bench sign --features avx512 2>&1 | tee "${BENCH_DIR}/bench_sign_avx512.log"
echo "AVX512 BENCH: OK"

echo ""
echo "[6/6] cargo +nightly bench --bench workload_benchmark --features avx512"
cargo +nightly bench --bench workload_benchmark --features avx512 2>&1 | tee "${BENCH_DIR}/bench_workload_avx512.log"
echo "WORKLOAD BENCH: OK"

echo ""
echo "=========================================="
echo "  ALL DONE. Results in ${BENCH_DIR}/"
echo "=========================================="
ls -la "${BENCH_DIR}/"
