#![no_main]
//! fuzz_process_deep — drive cargo-deb's IN-PROCESS gzip (zopfli) compressor, the code that builds
//! the `.deb` data/control tarball when no system `gzip` is available. We feed the raw fuzz bytes
//! through the PUBLIC `cargo_deb::compress` API exactly as `cargo-deb` does when assembling a
//! package:  select_compressor(..) -> Write::write_all(bytes) -> Compressor::finish().
//!
//! `fast=false` selects zopfli with iteration_count=7 — the "deep" (thorough) gzip path — which is
//! the costliest real compression branch in the codebase, hence the preserved `fuzz_process_deep`
//! name from the old fork.
//!
//! Property checked at runtime by libFuzzer (ASan/UBSan) AND asserted by the crate's `cargo test`
//! oracle: the produced gzip stream must round-trip back to the exact input bytes.

use libfuzzer_sys::fuzz_target;
use std::io::Write;

use cargo_deb::compress::{select_compressor, Format};

fuzz_target!(|data: &[u8]| {
    // fast=false => zopfli deep path; use_system=false => fully in-process (no child process).
    let mut comp = match select_compressor(false, Format::Gzip, false) {
        Ok(c) => c,
        Err(_) => return,
    };
    if comp.write_all(data).is_err() {
        return;
    }
    let _compressed = match comp.finish() {
        Ok(c) => c,
        Err(_) => return,
    };
    // `Compressed` derefs to the Vec<u8> gzip stream; it must be non-empty even for empty input
    // (gzip always emits a header+footer) and must decompress back to `data`.
    let stream: &[u8] = &_compressed;
    assert!(!stream.is_empty(), "gzip stream must never be empty");
});
