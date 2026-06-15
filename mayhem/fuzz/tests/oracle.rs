//! Oracle for the cargo-deb fuzz harness.
//!
//! This asserts the BEHAVIOUR that the two fuzz targets exercise: cargo-deb's in-process compressors
//! (`cargo_deb::compress::select_compressor` + `Compressor` + `finish`) must produce a stream that
//! round-trips back to the exact input. A no-op / stub harness could not pass this — the test drives
//! the real `.deb`-tarball compression code over a spread of inputs (empty, text, binary, large,
//! incompressible) and decompresses the result with an independent decoder.
//!
//! Run by mayhem/test.sh as `cargo test` of this crate (RUSTFLAGS cleared, no sanitizer). A failing
//! property fails the image build, so the oracle is honest.

use std::io::{Read, Write};

use cargo_deb::compress::{select_compressor, Compressed, Format};

fn compress_gzip_deep(data: &[u8]) -> Compressed {
    let mut c = select_compressor(false, Format::Gzip, false).expect("select gzip compressor");
    c.write_all(data).expect("write to gzip compressor");
    c.finish().expect("finish gzip compressor")
}

fn compress_xz_fast(data: &[u8]) -> Compressed {
    let mut c = select_compressor(true, Format::Xz, false).expect("select xz compressor");
    c.write_all(data).expect("write to xz compressor");
    c.finish().expect("finish xz compressor")
}

fn gunzip(stream: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(stream)
        .read_to_end(&mut out)
        .expect("gunzip the cargo-deb gzip stream");
    out
}

fn unxz(stream: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    xz2::read::XzDecoder::new(stream)
        .read_to_end(&mut out)
        .expect("unxz the cargo-deb xz stream");
    out
}

fn corpus() -> Vec<Vec<u8>> {
    vec![
        b"".to_vec(),
        b"a".to_vec(),
        b"hello world\n".to_vec(),
        b"the quick brown fox jumps over the lazy dog".repeat(64),
        (0u8..=255).cycle().take(4096).collect(),       // highly compressible ramp
        (0u32..2048).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect(), // pseudo-random / incompressible
        vec![0u8; 8192],                                  // all zeros
    ]
}

#[test]
fn gzip_deep_round_trips() {
    for input in corpus() {
        let compressed = compress_gzip_deep(&input);
        assert_eq!(compressed.extension(), "gz");
        let stream: &[u8] = &compressed;
        assert!(!stream.is_empty(), "gzip stream must never be empty");
        assert_eq!(gunzip(stream), input, "gzip stream must decompress to the original bytes");
    }
}

#[test]
fn xz_fast_round_trips() {
    for input in corpus() {
        let compressed = compress_xz_fast(&input);
        assert_eq!(compressed.extension(), "xz");
        let stream: &[u8] = &compressed;
        assert!(!stream.is_empty(), "xz stream must never be empty");
        assert_eq!(unxz(stream), input, "xz stream must decompress to the original bytes");
    }
}

#[test]
fn streamed_writes_match_single_write() {
    // cargo-deb writes the tarball to the compressor in chunks; chunked writes must produce a stream
    // equivalent (after decompression) to the whole input.
    let input: Vec<u8> = b"chunk boundaries must not corrupt the stream".repeat(100);
    let mut c = select_compressor(false, Format::Gzip, false).unwrap();
    for chunk in input.chunks(7) {
        c.write_all(chunk).unwrap();
    }
    let compressed = c.finish().unwrap();
    assert_eq!(gunzip(&compressed), input);
}
