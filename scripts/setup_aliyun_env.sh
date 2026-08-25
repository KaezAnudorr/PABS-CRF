#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() {
    printf '[setup_aliyun_env] %s\n' "$*"
}

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

install_system_packages() {
    if command -v apt-get >/dev/null 2>&1; then
        log "Installing Debian/Ubuntu packages ..."
        ${SUDO} apt-get update
        DEBIAN_FRONTEND=noninteractive ${SUDO} apt-get install -y \
            build-essential \
            pkg-config \
            libssl-dev \
            ca-certificates \
            curl \
            git \
            python3 \
            python3-venv \
            tar \
            gzip
    elif command -v dnf >/dev/null 2>&1; then
        log "Installing Fedora/RHEL packages with dnf ..."
        ${SUDO} dnf install -y \
            gcc \
            gcc-c++ \
            make \
            pkgconf-pkg-config \
            openssl-devel \
            ca-certificates \
            curl \
            git \
            python3 \
            tar \
            gzip
    elif command -v yum >/dev/null 2>&1; then
        log "Installing CentOS/RHEL packages with yum ..."
        ${SUDO} yum install -y \
            gcc \
            gcc-c++ \
            make \
            pkgconfig \
            openssl-devel \
            ca-certificates \
            curl \
            git \
            python3 \
            tar \
            gzip
    else
        log "No supported package manager found; please install gcc, make, openssl-devel/libssl-dev, curl, git, python3 manually."
    fi
}

configure_rust_mirrors() {
    log "Configuring Rustup and Cargo mirrors: Tsinghua TUNA"
    export RUSTUP_DIST_SERVER="https://mirrors.tuna.tsinghua.edu.cn/rustup"
    export RUSTUP_UPDATE_ROOT="https://mirrors.tuna.tsinghua.edu.cn/rustup/rustup"

    mkdir -p "${HOME}/.cargo"
    if [ -f "${HOME}/.cargo/config.toml" ]; then
        cp "${HOME}/.cargo/config.toml" "${HOME}/.cargo/config.toml.bak.$(date +%Y%m%d_%H%M%S)"
    fi
    cat > "${HOME}/.cargo/config.toml" <<'EOF'
[source.crates-io]
replace-with = "tuna"

[source.tuna]
registry = "sparse+https://mirrors.tuna.tsinghua.edu.cn/crates.io-index/"

[net]
git-fetch-with-cli = true
EOF

    if ! command -v rustup >/dev/null 2>&1; then
        log "Installing rustup and stable Rust toolchain ..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
            sh -s -- -y --default-toolchain stable
    fi

    # shellcheck disable=SC1091
    [ -f "${HOME}/.cargo/env" ] && . "${HOME}/.cargo/env"

    rustup default stable
    rustup update stable
}

main() {
    install_system_packages
    configure_rust_mirrors

    # shellcheck disable=SC1091
    [ -f "${HOME}/.cargo/env" ] && . "${HOME}/.cargo/env"

    log "Rust version: $(rustc --version)"
    log "Cargo version: $(cargo --version)"

    cd "${PROJECT_DIR}"
    log "Fetching Cargo dependencies ..."
    cargo fetch
    log "Environment is ready."
}

main "$@"
