#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT_DIR="$(dirname "${PROJECT_DIR}")"
BASE_NAME="$(basename "${PROJECT_DIR}")"
OUT_DIR="${1:-${PROJECT_DIR}/dist}"
STAMP="$(date +%Y%m%d_%H%M%S)"
ARCHIVE_NAME="${2:-pabs-crf-v4-aliyun-${STAMP}.tar.gz}"
ARCHIVE_PATH="${OUT_DIR}/${ARCHIVE_NAME}"

mkdir -p "${OUT_DIR}"

INCLUDES=()

add_path() {
    local rel="$1"
    if [ -e "${PROJECT_DIR}/${rel}" ]; then
        INCLUDES+=("${BASE_NAME}/${rel}")
    fi
}

for rel in \
    Cargo.toml \
    Cargo.lock \
    .cargo \
    src \
    tests \
    benches \
    examples \
    scripts \
    data \
    Dockerfile \
    README.md \
    IMPLEMENTATION_SCOPE.md \
    SECURITY_MODEL.md \
    scheme_v3_rust_implementation.md \
    ALIYUN_RUNBOOK.md
do
    add_path "${rel}"
done

for pattern in "*.py" "*.sh" "*.rs" "*.md" "*.txt"; do
    for path in "${PROJECT_DIR}"/${pattern}; do
        [ -e "${path}" ] || continue
        rel="$(basename "${path}")"
        add_path "${rel}"
    done
done

tar -czf "${ARCHIVE_PATH}" -C "${PARENT_DIR}" "${INCLUDES[@]}"

printf 'Archive written to: %s\n' "${ARCHIVE_PATH}"
printf 'Upload with: scp %s root@<server-ip>:/root/\n' "${ARCHIVE_PATH}"
