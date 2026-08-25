#!/bin/bash
# Quick validation script for comprehensive benchmark suite

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== PABS-CRF Comprehensive Benchmark Validation ==="
echo

# Check files exist
echo "1. Checking required files..."
required_files=(
    "examples/comprehensive_perf_test.rs"
    "scripts/run_comprehensive_benchmark.py"
    "BENCHMARK_GUIDE.md"
)

all_exist=true
for file in "${required_files[@]}"; do
    if [ -f "$PROJECT_ROOT/$file" ]; then
        echo "   ✓ $file"
    else
        echo "   ✗ $file (MISSING)"
        all_exist=false
    fi
done

if [ "$all_exist" = false ]; then
    echo "ERROR: Some required files are missing!"
    exit 1
fi

echo

# Check Rust toolchain
echo "2. Checking Rust toolchain..."
if command -v rustc &> /dev/null; then
    rustc_version=$(rustc --version)
    echo "   ✓ rustc: $rustc_version"
else
    echo "   ✗ rustc not found"
    exit 1
fi

if command -v cargo &> /dev/null; then
    cargo_version=$(cargo --version)
    echo "   ✓ cargo: $cargo_version"
else
    echo "   ✗ cargo not found"
    exit 1
fi

echo

# Check Python
echo "3. Checking Python..."
if command -v python3 &> /dev/null; then
    python_version=$(python3 --version)
    echo "   ✓ python3: $python_version"
else
    echo "   ✗ python3 not found"
    exit 1
fi

echo

# Check CPU features
echo "4. Checking CPU features..."
if [ -f /proc/cpuinfo ]; then
    cpu_model=$(grep -m1 "model name" /proc/cpuinfo | cut -d: -f2 | xargs)
    echo "   CPU: $cpu_model"

    if grep -q "avx512" /proc/cpuinfo; then
        echo "   ✓ AVX-512 supported"
        avx512_support=true
    else
        echo "   ℹ AVX-512 not supported (will test baseline only)"
        avx512_support=false
    fi
else
    echo "   ℹ /proc/cpuinfo not available (non-Linux system?)"
    avx512_support=false
fi

echo

# Check if already built
echo "5. Checking build status..."
if [ -f "$PROJECT_ROOT/target/release/examples/comprehensive_perf_test" ]; then
    echo "   ✓ comprehensive_perf_test already built"
    skip_build="--skip-build"
else
    echo "   ℹ Not yet built, will build during test"
    skip_build=""
fi

echo

# Offer to run quick test
echo "6. Ready to run tests!"
echo
echo "Available test commands:"
echo
echo "a) Quick smoke test (3 rounds, ~10 minutes):"
echo "   python3 scripts/run_comprehensive_benchmark.py --rounds 3 $skip_build"
echo

if [ "$avx512_support" = true ]; then
    echo "b) Full test with AVX-512 (10 rounds, ~60 minutes):"
    echo "   python3 scripts/run_comprehensive_benchmark.py --rounds 10 --test-avx512 $skip_build"
else
    echo "b) Full test baseline (10 rounds, ~30 minutes):"
    echo "   python3 scripts/run_comprehensive_benchmark.py --rounds 10 $skip_build"
fi
echo

echo "c) Manual build and run:"
echo "   cargo build --release --example comprehensive_perf_test"
echo "   cargo run --release --example comprehensive_perf_test"
echo

read -p "Run quick smoke test now? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo
    echo "=== Running Quick Smoke Test ==="
    cd "$PROJECT_ROOT"
    python3 scripts/run_comprehensive_benchmark.py --rounds 3 $skip_build

    echo
    echo "=== Smoke Test Complete ==="
    echo "Check the test-results/comprehensive/ directory for output"
else
    echo
    echo "Skipping test. Run manually when ready."
fi

echo
echo "=== Validation Complete ==="
echo
echo "For more information, see: BENCHMARK_GUIDE.md"
