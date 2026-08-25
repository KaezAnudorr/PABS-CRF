#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

SAMPLE_SIZE=100
QUICK_MODE=false
BENCH_NAME="sign"
EXTRA_CARGO_ARGS=()

for arg in "$@"; do
    case "$arg" in
        --quick)
            QUICK_MODE=true
            SAMPLE_SIZE=10
            ;;
        --sample-size)
            shift
            SAMPLE_SIZE="${1:-10}"
            ;;
        --bench)
            shift
            BENCH_NAME="${1:-sign}"
            ;;
        --features)
            shift
            EXTRA_CARGO_ARGS+=(--features "${1:-}")
            ;;
        --help|-h)
            echo "Usage: $0 [--quick] [--sample-size N] [--bench NAME] [--features FEAT]"
            echo ""
            echo "  --quick           Use sample-size 10 for fast results"
            echo "  --sample-size N   Set criterion sample size (default: 100)"
            echo "  --bench NAME      Cargo bench target name (default: sign)"
            echo "  --features FEAT   Pass --features to cargo bench (e.g. avx512)"
            exit 0
            ;;
    esac
done

log() { printf '[cross_platform_bench] %s\n' "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

command -v cargo >/dev/null 2>&1 || die "cargo not found in PATH"
command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1 || die "python3/python not found in PATH"
PYTHON_CMD="$(command -v python3 2>/dev/null || command -v python 2>/dev/null)"

detect_os() {
    local os_name
    os_name="$(uname -s)"
    case "$os_name" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "macos" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        FreeBSD*) echo "freebsd" ;;
        *) echo "unknown" ;;
    esac
}

detect_arch() {
    uname -m
}

detect_cpu_model() {
    local os_name
    os_name="$(uname -s)"
    case "$os_name" in
        Linux*)
            if [ -f /proc/cpuinfo ]; then
                grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ *//'
                return
            fi
            ;;
        Darwin*)
            sysctl -n machdep.cpu.brand_string 2>/dev/null && return
            ;;
    esac
    echo "unknown"
}

detect_ram_gb() {
    local os_name
    os_name="$(uname -s)"
    case "$os_name" in
        Linux*)
            if [ -f /proc/meminfo ]; then
                local mem_kb
                mem_kb="$(grep MemTotal /proc/meminfo | awk '{print $2}')"
                echo $((mem_kb / 1024 / 1024))
                return
            fi
            ;;
        Darwin*)
            local mem_bytes
            mem_bytes="$(sysctl -n hw.memsize 2>/dev/null)"
            echo $((mem_bytes / 1024 / 1024 / 1024))
            return
            ;;
    esac
    echo 0
}

detect_cpu_features() {
    local os_name
    os_name="$(uname -s)"
    local features=()

    case "$os_name" in
        Linux*)
            if [ -f /proc/cpuinfo ]; then
                local flags
                flags="$(grep -m1 'flags' /proc/cpuinfo | cut -d: -f2)"
                echo "$flags" | grep -qw avx2 && features+=("avx2")
                echo "$flags" | grep -qw avx512f && features+=("avx512f")
                echo "$flags" | grep -qw avx512dq && features+=("avx512dq")
                echo "$flags" | grep -qw avx512vl && features+=("avx512vl")
                echo "$flags" | grep -qw avx512cd && features+=("avx512cd")
                echo "$flags" | grep -qw avx512bw && features+=("avx512bw")
                echo "$flags" | grep -qw avx512ifma && features+=("avx512ifma")
                echo "$flags" | grep -qw aes && features+=("aes")
                echo "$flags" | grep -qw sse4_2 && features+=("sse4_2")
                echo "$flags" | grep -qw fma && features+=("fma")
            fi
            if command -v lscpu >/dev/null 2>&1; then
                local lscpu_flags
                lscpu_flags="$(lscpu 2>/dev/null | grep -i 'flags' | head -1)"
                if [ -n "$lscpu_flags" ]; then
                    echo "$lscpu_flags" | grep -qw neon && features+=("neon")
                    echo "$lscpu_flags" | grep -qw sve && features+=("sve")
                    echo "$lscpu_flags" | grep -qw sve2 && features+=("sve2")
                fi
            fi
            ;;
        Darwin*)
            local hw_optional
            hw_optional="$(sysctl -n hw.optional.arm64 2>/dev/null)"
            if [ "$hw_optional" = "1" ]; then
                features+=("neon")
            fi
            local hw_cpu_cap
            hw_cpu_cap="$(sysctl -n hw.optional.avx2_0 2>/dev/null)"
            [ "$hw_cpu_cap" = "1" ] && features+=("avx2")
            ;;
    esac

    local IFS=','
    echo "${features[*]}"
}

detect_rust_version() {
    rustc --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1
}

parse_time_unit_to_us() {
    local value="$1"
    local unit="$2"
    case "$unit" in
        ns) echo "$(echo "$value" | awk '{printf "%.1f", $1 / 1000}')" ;;
        us) echo "$(echo "$value" | awk '{printf "%.1f", $1}')" ;;
        ms) echo "$(echo "$value" | awk '{printf "%.1f", $1 * 1000}')" ;;
        s)  echo "$(echo "$value" | awk '{printf "%.1f", $1 * 1000000}')" ;;
        *)  echo "0" ;;
    esac
}

parse_criterion_output() {
    local bench_output="$1"
    local json_results="{}"

    local current_bench=""
    local in_time_line=false

    while IFS= read -r line; do
        if echo "$line" | grep -qP '^\S+/(\S+)\s+time:'; then
            local bench_full
            bench_full="$(echo "$line" | grep -oP '^\S+/(\S+)' | sed 's|.*/||')"
            local time_part
            time_part="$(echo "$line" | grep -oP 'time:\s+\[.*\]' | sed 's/time:\s*\[//;s/\]//')"
            if [ -n "$time_part" ]; then
                local lo_val lo_unit mean_val mean_unit hi_val hi_unit
                lo_val="$(echo "$time_part" | awk '{print $1}')"
                lo_unit="$(echo "$time_part" | awk '{print $2}')"
                mean_val="$(echo "$time_part" | awk '{print $3}')"
                mean_unit="$(echo "$time_part" | awk '{print $4}')"
                hi_val="$(echo "$time_part" | awk '{print $5}')"
                hi_unit="$(echo "$time_part" | awk '{print $6}')"

                local mean_us ci_low_us ci_high_us
                mean_us="$(parse_time_unit_to_us "$mean_val" "$mean_unit")"
                ci_low_us="$(parse_time_unit_to_us "$lo_val" "$lo_unit")"
                ci_high_us="$(parse_time_unit_to_us "$hi_val" "$hi_unit")"

                json_results="$("$PYTHON_CMD" -c "
import json, sys
d = json.loads('''$json_results''')
d['$bench_full'] = {
    'mean_us': $mean_us,
    'ci_low_us': $ci_low_us,
    'ci_high_us': $ci_high_us
}
print(json.dumps(d))
")"
            fi
        fi
    done <<< "$bench_output"

    echo "$json_results"
}

OS="$(detect_os)"
ARCH="$(detect_arch)"
CPU_MODEL="$(detect_cpu_model)"
CPU_FEATURES="$(detect_cpu_features)"
RAM_GB="$(detect_ram_gb)"
RUST_VERSION="$(detect_rust_version)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TIMESTAMP_FILE="$(date +%Y%m%d_%H%M%S)"

log "Platform: os=$OS arch=$ARCH"
log "CPU: $CPU_MODEL"
log "CPU features: $CPU_FEATURES"
log "RAM: ${RAM_GB}GB"
log "Rust: $RUST_VERSION"
log "Sample size: $SAMPLE_SIZE"
log "Bench target: $BENCH_NAME"

cd "$PROJECT_DIR" || die "cannot cd to $PROJECT_DIR"

log "Running cargo bench --bench $BENCH_NAME (sample_size=$SAMPLE_SIZE) ..."

BENCH_OUTPUT="$(cargo bench --bench "$BENCH_NAME" \
    ${EXTRA_CARGO_ARGS[@]+"${EXTRA_CARGO_ARGS[@]}"} \
    -- --sample-size "$SAMPLE_SIZE" 2>&1)" || {
    log "cargo bench failed. Last 40 lines of output:"
    echo "$BENCH_OUTPUT" | tail -40 >&2
    die "benchmark execution failed"
}

log "Parsing criterion output ..."

RESULTS_JSON="$(parse_criterion_output "$BENCH_OUTPUT")"

if [ "$RESULTS_JSON" = "{}" ]; then
    log "WARNING: No benchmark results parsed from criterion output."
    log "Attempting fallback parse from criterion estimate.json files ..."

    RESULTS_JSON="$("$PYTHON_CMD" -c "
import json, os, glob

base = os.path.join('$PROJECT_DIR', 'target', 'criterion')
results = {}

for est_path in glob.glob(os.path.join(base, '**', 'new', 'estimates.json'), recursive=True):
    parts = est_path.split(os.sep)
    idx = parts.index('criterion')
    bench_parts = parts[idx+1:-2]
    bench_name = '/'.join(bench_parts[:-1]) if len(bench_parts) > 1 else bench_parts[0]
    short_name = bench_parts[-1] if bench_parts else 'unknown'

    try:
        with open(est_path) as f:
            est = json.load(f)
        mean_ns = est.get('Mean', {}).get('point_estimate', 0)
        ci_lo_ns = est.get('Mean', {}).get('confidence_interval', {}).get('lower_bound', 0)
        ci_hi_ns = est.get('Mean', {}).get('confidence_interval', {}).get('upper_bound', 0)
        results[short_name] = {
            'mean_us': round(mean_ns / 1000, 1),
            'ci_low_us': round(ci_lo_ns / 1000, 1),
            'ci_high_us': round(ci_hi_ns / 1000, 1)
        }
    except Exception:
        pass

print(json.dumps(results))
")"
fi

FEATURE_SUFFIX=""
for feat in "${EXTRA_CARGO_ARGS[@]}"; do
    case "$feat" in
        --features) ;;
        *) FEATURE_SUFFIX="_${feat}" ;;
    esac
done

OUTPUT_FILE="$PROJECT_DIR/benchmark_results_${ARCH}_${OS}${FEATURE_SUFFIX}_${TIMESTAMP_FILE}.json"

"$PYTHON_CMD" -c "
import json, sys

platform = {
    'os': '$OS',
    'arch': '$ARCH',
    'cpu': '''$CPU_MODEL''',
    'cpu_features': '$CPU_FEATURES'.split(',') if '$CPU_FEATURES' else [],
    'ram_gb': $RAM_GB
}

doc = {
    'platform': platform,
    'rust_version': '$RUST_VERSION',
    'timestamp': '$TIMESTAMP',
    'sample_size': $SAMPLE_SIZE,
    'bench_target': '$BENCH_NAME',
    'results': json.loads('''$RESULTS_JSON''')
}

with open('$OUTPUT_FILE', 'w', encoding='utf-8') as f:
    json.dump(doc, f, indent=2, ensure_ascii=False)

print(json.dumps(doc, indent=2, ensure_ascii=False))
"

log "Results written to: $OUTPUT_FILE"
log "Done."
