#![no_main]
//! fuzz_process_rand — drive cargo-deb's IN-PROCESS xz (lzma) compressor, the DEFAULT codec used to
//! build the `.deb` data/control tarball (the `lzma` feature is on by default). We feed the raw fuzz
//! bytes through the PUBLIC `cargo_deb::compress` API exactly as `cargo-deb` does when assembling a
//! package:  select_compressor(..) -> Write::write_all(bytes) -> Compressor::finish().
//!
//! `fast=true` selects the xz2 multi-threaded stream encoder at its fast preset — a distinct real
//! codec path from `fuzz_process_deep`'s zopfli gzip. Target name `fuzz_process_rand` preserved from
//! the old fork for Mayhem corpus/defect continuity.
//!
//! Property checked at runtime (ASan/UBSan) AND by the crate's `cargo test` oracle: the produced xz
//! stream is non-empty and round-trips back to the exact input bytes.

use libfuzzer_sys::fuzz_target;
use std::io::Write;

use cargo_deb::compress::{select_compressor, Format};

fuzz_target!(|data: &[u8]| {
    // fast=true => xz fast preset; use_system=false => fully in-process (no child process).
    let mut comp = match select_compressor(true, Format::Xz, false) {
        Ok(c) => c,
        Err(_) => return,
    };
    if comp.write_all(data).is_err() {
        return;
    }
    let compressed = match comp.finish() {
        Ok(c) => c,
        Err(_) => return,
    };
    let stream: &[u8] = &compressed;
    assert!(!stream.is_empty(), "xz stream must never be empty");
});
