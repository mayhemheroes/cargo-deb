#!/usr/bin/env bash
#
# cargo-deb/mayhem/build.sh — build the cargo-deb fuzz targets as sanitized libFuzzer binaries
# (cargo-fuzz + ASan via RUSTFLAGS, the OSS-Fuzz Rust path). The fuzzed code is cargo-deb's library
# crate `cargo_deb` — specifically the in-process compressors (cargo_deb::compress) that build the
# .deb data/control tarball. Our additive cargo-fuzz crate lives at mayhem/fuzz/ and is driven via
# `cargo fuzz build --fuzz-dir mayhem/fuzz`. Purely additive — no upstream file is touched.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
: "${MAYHEM_JOBS:=$(nproc)}"
export MAYHEM_JOBS CARGO_BUILD_JOBS="$MAYHEM_JOBS"
cd "$SRC"

FUZZ_DIR="mayhem/fuzz"
FUZZ_TARGETS=()
for f in "$FUZZ_DIR"/fuzz_targets/*.rs; do FUZZ_TARGETS+=("$(basename "${f%.*}")"); done
[ "${#FUZZ_TARGETS[@]}" -gt 0 ] || { echo "ERROR: no fuzz targets under $FUZZ_DIR/fuzz_targets/" >&2; exit 1; }
TRIPLE="x86_64-unknown-linux-gnu"

export RUSTFLAGS="${RUSTFLAGS:-} --cfg fuzzing -Zsanitizer=address -Cdebuginfo=1 -Cforce-frame-pointers"
echo "=== cargo fuzz build (image-default nightly, ASan via RUSTFLAGS) ==="
echo "targets: ${FUZZ_TARGETS[*]}"
for t in "${FUZZ_TARGETS[@]}"; do
  echo "--- building fuzz target: $t ---"
  cargo fuzz build --fuzz-dir "$FUZZ_DIR" -O --debug-assertions "$t"
  bin="$SRC/$FUZZ_DIR/target/$TRIPLE/release/$t"
  [ -x "$bin" ] || { echo "ERROR: fuzz binary not found at $bin" >&2; exit 1; }
  cp "$bin" "/mayhem/$t"; echo "built /mayhem/$t"
done
echo "build.sh complete:"; ls -la /mayhem/fuzz_process_deep /mayhem/fuzz_process_rand
