FROM rust:1.86-slim-bookworm

LABEL org.opencontainers.image.title="pabs-crf-v4"
LABEL org.opencontainers.image.description="Reproducible build environment for PABS-CRF v4 (lattice-based Predicate ABS with CRF)"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.created="2026-05-24"
LABEL pabs-crf.v4.rust-edition="2021"
LABEL pabs-crf.v4.release-profile="opt-level=3,lto=true,codegen-units=1"

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    texlive-latex-base \
    texlive-latex-extra \
    texlive-fonts-recommended \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/pabs-crf

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && echo "fn main() {}" > src/lib.rs \
    && cargo build --release \
    && rm -rf src

COPY .cargo/ .cargo/
COPY src/ src/
COPY tests/ tests/
COPY benches/ benches/
COPY examples/ examples/
COPY data/ data/

ENV RUSTFLAGS="-C target-cpu=native"

RUN cargo build --release

CMD ["cargo", "test", "--release"]
