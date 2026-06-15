# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile — builds ON TOP of the org base image (ghcr.io/mayhemheroes/base), which
# provides debian + clang/llvm + libFuzzer + identities + the build-contract ENV. cargo-deb is a
# RUST cargo subcommand that builds Debian .deb packages; the fuzzed code is its library crate
# `cargo_deb` — the in-process gzip(zopfli)/xz compressors that assemble the .deb data tarball
# (cargo_deb::compress). The base ships NO Rust toolchain, so this installs rustup (a pinned
# nightly — cargo-fuzz needs `-Z` flags; cargo-deb is edition 2024 so the nightly must be recent) +
# cargo-fuzz as root into a SHARED location (/opt/rust) usable by the non-root `mayhem` user, then
# runs build.sh (cargo fuzz build) + test.sh (the compress round-trip oracle).
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) -t cargo-deb-commit:test .

FROM ghcr.io/mayhemheroes/base:2026-06

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG MAYHEM_JOBS=

# Pin the nightly toolchain (cargo-fuzz needs nightly `-Z` flags; cargo-deb is edition 2024, so the
# nightly must be recent enough to accept it — 2025-09-05 does).
ARG RUST_TOOLCHAIN=nightly-2025-09-05
ARG CARGO_FUZZ_VERSION=0.12.0

ENV RUSTUP_HOME=/opt/rust/rustup \
    CARGO_HOME=/opt/rust/cargo \
    PATH=/opt/rust/cargo/bin:$PATH

# Pin EVERY cargo/rustc invocation to the pre-installed nightly. (cargo-deb ships no
# rust-toolchain.toml, but pinning is harmless and keeps the build deterministic.)
ENV RUSTUP_TOOLCHAIN=nightly-2025-09-05

USER root
RUN set -eux; \
    mkdir -p "$RUSTUP_HOME" "$CARGO_HOME"; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "$RUST_TOOLCHAIN"; \
    rustup component add rust-src --toolchain "$RUST_TOOLCHAIN"; \
    cargo install cargo-fuzz --version "$CARGO_FUZZ_VERSION" --locked; \
    chmod -R a+rX /opt/rust; \
    mkdir -p "$CARGO_HOME/registry" "$CARGO_HOME/git" && chmod -R a+rwX "$CARGO_HOME/registry" "$CARGO_HOME/git"; \
    rustc --version; cargo --version; cargo fuzz --version
USER mayhem

WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

# Run the compress round-trip oracle at build time; a failing suite fails the image.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
