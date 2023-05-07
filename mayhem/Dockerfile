# Use the base builder image for Rust projects as the builder stage
FROM gcr.io/oss-fuzz-base/base-builder-rust as builder

# Install build dependencies
RUN apt-get update && \
	apt-get install -y cmake clang curl binutils-dev libbfd-dev libunwind8-dev libblocksruntime-dev
RUN cargo install honggfuzz

# Add source to the build stage
ADD . /cargo-deb
WORKDIR /cargo-deb

# Build the fuzz targets
RUN cd ./fuzz && cargo +nightly hfuzz build

# Use Ubuntu 20.04 as the final image
FROM ubuntu:20.04

# Copy the fuzz targets from the builder stage
COPY --from=builder cargo-deb/fuzz/hfuzz_target/x86_64-unknown-linux-gnu/release/fuzz_process_rand /
COPY --from=builder cargo-deb/fuzz/hfuzz_target/x86_64-unknown-linux-gnu/release/fuzz_process_deep /