#!/usr/bin/env bash
set -uo pipefail

PROJECT_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TIMESTAMP="${2:-$(date +%Y%m%d_%H%M%S)}"
OUTDIR="$PROJECT_DIR/test-results/wsl/$TIMESTAMP"
SUMMARY_FILE="$OUTDIR/summary.txt"
ENV_FILE="$OUTDIR/00_environment.log"

mkdir -p "$OUTDIR"

FAILED_STEPS=()

record_summary() {
    printf '%s\n' "$*" | tee -a "$SUMMARY_FILE"
}

run_step() {
    local step_name="$1"
    shift

    local log_file="$OUTDIR/${step_name}.log"

    record_summary ""
    record_summary "[$step_name]"
    record_summary "command: $*"

    if "$@" >"$log_file" 2>&1; then
        record_summary "status: PASS"
    else
        local exit_code=$?
        record_summary "status: FAIL (exit_code=$exit_code)"
        FAILED_STEPS+=("$step_name")
    fi

    record_summary "log: ${step_name}.log"
}

{
    echo "timestamp=$TIMESTAMP"
    echo "project_dir=$PROJECT_DIR"
    echo "pwd=$(pwd)"
    echo "kernel=$(uname -a)"
    echo "user=$(whoami)"
    if command -v rustc >/dev/null 2>&1; then
        echo "rustc=$(rustc --version)"
    else
        echo "rustc=missing"
    fi
    if command -v cargo >/dev/null 2>&1; then
        echo "cargo=$(cargo --version)"
    else
        echo "cargo=missing"
    fi
} | tee "$ENV_FILE"

record_summary "WSL validation v4 summary"
record_summary "timestamp: $TIMESTAMP"
record_summary "output_dir: $OUTDIR"
record_summary "environment_log: 00_environment.log"

if ! command -v cargo >/dev/null 2>&1; then
    record_summary ""
    record_summary "cargo is not available in this WSL distro."
    exit 127
fi

cd "$PROJECT_DIR" || exit 1

run_step "01_cargo_check_all_targets" cargo check --all-targets
run_step "02_cargo_test_top_tier_v4" cargo test --test top_tier_v4
run_step "03_cargo_test_basic" cargo test --test basic
run_step "04_cargo_test_integration" cargo test --test integration
run_step "05_cargo_test_security" cargo test --test security
run_step "06_cargo_test_regression" cargo test --test regression
run_step "07_cargo_test_real_world" cargo test --test real_world
run_step "08_algorithm_validation_v4" bash "$PROJECT_DIR/scripts/run_algorithm_validation_v4.sh" "$PROJECT_DIR" "$TIMESTAMP"

record_summary ""
record_summary "[result]"
if ((${#FAILED_STEPS[@]} == 0)); then
    record_summary "overall_status: PASS"
else
    record_summary "overall_status: FAIL"
    record_summary "failed_steps: ${FAILED_STEPS[*]}"
fi

echo "$OUTDIR"
