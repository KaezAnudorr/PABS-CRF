#!/usr/bin/env bash
set -euo pipefail

scheme="${1:-pabs-128}"
iterations="${2:-100}"
output_dir="${3:-test-results/resource}"

case "$scheme" in
  pabs-128|pabs-192|pabs-256|mldsa-44|mldsa-65|mldsa-87) ;;
  *) echo "unknown scheme selector: $scheme" >&2; exit 2 ;;
esac

mkdir -p "$output_dir"
cargo build --quiet --release --example matched_mldsa_baseline
stamp="$(date -u +%Y%m%d_%H%M%S)"
timing_file="$output_dir/${scheme}_${stamp}_timing.json"
resource_file="$output_dir/${scheme}_${stamp}_resources.txt"

PABS_BENCH_ITERS="$iterations" \
PABS_BENCH_OUTPUT="$timing_file" \
/usr/bin/time -v -o "$resource_file" \
  target/release/examples/matched_mldsa_baseline "$scheme"

{
  printf 'timestamp_utc: %s\n' "$(date -u --iso-8601=seconds)"
  printf 'architecture: %s\n' "$(uname -m)"
  printf 'kernel: %s\n' "$(uname -sr)"
  printf 'rustc: %s\n' "$(rustc --version)"
} >> "$resource_file"

cat "$resource_file"
