#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="pabs-crf-v4"
IMAGE_TAG="latest"
CONTAINER_NAME="pabs-crf-v4-bench-$(date +%Y%m%d%H%M%S)"
RESULTS_DIR="$(pwd)/docker-results"
TIMESTAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"

mkdir -p "${RESULTS_DIR}"

echo "=== PABS-CRF v4 Docker Benchmark Runner ==="
echo "Timestamp: ${TIMESTAMP}"
echo ""

echo "[1/5] Building Docker image: ${IMAGE_NAME}:${IMAGE_TAG} ..."
docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" .
echo "Image built successfully."
echo ""

echo "[2/5] Running cargo test --release ..."
TEST_LOG="${RESULTS_DIR}/test-output-${TIMESTAMP}.log"
docker run --rm \
    --name "${CONTAINER_NAME}-test" \
    "${IMAGE_NAME}:${IMAGE_TAG}" \
    cargo test --release 2>&1 | tee "${TEST_LOG}"
echo "Tests completed. Log: ${TEST_LOG}"
echo ""

BENCH_LOG="${RESULTS_DIR}/bench-output-${TIMESTAMP}.log"
BENCH_DIR="/usr/src/pabs-crf/target/criterion"

echo "[3/5] Running cargo bench --no-fail-fast ..."
docker run --rm \
    --name "${CONTAINER_NAME}-bench" \
    "${IMAGE_NAME}:${IMAGE_TAG}" \
    cargo bench --no-fail-fast 2>&1 | tee "${BENCH_LOG}"
echo "Benchmarks completed. Log: ${BENCH_LOG}"
echo ""

echo "[4/5] Copying benchmark results from container ..."
BENCH_CONTAINER="${CONTAINER_NAME}-bench-copy"
docker run --rm -d \
    --name "${BENCH_CONTAINER}" \
    --entrypoint sleep \
    "${IMAGE_NAME}:${IMAGE_TAG}" \
    300 >/dev/null 2>&1 || true

docker cp "${BENCH_CONTAINER}:${BENCH_DIR}" "${RESULTS_DIR}/criterion" 2>/dev/null || {
    echo "Warning: could not copy criterion results (container may have exited)."
    echo "Benchmark data may only be available in the log file."
}
docker stop "${BENCH_CONTAINER}" >/dev/null 2>&1 || true
echo ""

echo "[5/5] Generating JSON summary ..."

RUST_VERSION=$(docker run --rm "${IMAGE_NAME}:${IMAGE_TAG}" rustc --version 2>/dev/null || echo "unknown")
CPU_INFO=$(docker run --rm "${IMAGE_NAME}:${IMAGE_TAG}" cat /proc/cpuinfo 2>/dev/null | head -20 || echo "unavailable")
PLATFORM=$(docker run --rm "${IMAGE_NAME}:${IMAGE_TAG}" uname -a 2>/dev/null || echo "unknown")

TEST_PASS=0
TEST_FAIL=0
if [ -f "${TEST_LOG}" ]; then
    TEST_PASS=$(grep -c "test result: ok" "${TEST_LOG}" 2>/dev/null || echo "0")
    TEST_FAIL=$(grep -c "FAILED" "${TEST_LOG}" 2>/dev/null || echo "0")
fi

BENCH_COUNT=0
if [ -f "${BENCH_LOG}" ]; then
    BENCH_COUNT=$(grep -c "time:" "${BENCH_LOG}" 2>/dev/null || echo "0")
fi

cat > "${RESULTS_DIR}/summary-${TIMESTAMP}.json" <<EOF
{
  "platform": ${PLATFORM@Q},
  "cpu_info": $(echo "${CPU_INFO}" | head -5 | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))" 2>/dev/null || echo '"unavailable"'),
  "rust_version": ${RUST_VERSION@Q},
  "timestamp": "${TIMESTAMP}",
  "image": "${IMAGE_NAME}:${IMAGE_TAG}",
  "test_results": {
    "log_file": "test-output-${TIMESTAMP}.log",
    "passed_suites": "${TEST_PASS}",
    "failed_indicators": "${TEST_FAIL}"
  },
  "bench_results": {
    "log_file": "bench-output-${TIMESTAMP}.log",
    "criterion_dir": "criterion/",
    "bench_count": "${BENCH_COUNT}"
  }
}
EOF

echo ""
echo "=== Summary ==="
echo "Platform:      ${PLATFORM}"
echo "Rust version:  ${RUST_VERSION}"
echo "Test log:      ${TEST_LOG}"
echo "Bench log:     ${BENCH_LOG}"
echo "Results dir:   ${RESULTS_DIR}"
echo "JSON summary:  ${RESULTS_DIR}/summary-${TIMESTAMP}.json"
echo ""
echo "Done."
