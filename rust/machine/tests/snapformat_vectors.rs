//! The snapshot format against Go's machine/snapformat.go, both ways (machine/snapformat_rustvec_test.go): go-s2.bin
//! is what Go wrote, read here; rust-s2.bin what this port writes, read by the Go test.
//! `GEN_RUST_VECTORS=1 cargo test -p jarvis-machine --test snapformat_vectors` writes rust-s2.bin again.
#![allow(clippy::unwrap_used)]

use sha2::{Digest, Sha256};
use std::io::{Read, Write};

#[path = "../src/snapformat.rs"]
mod snapformat;

fn content() -> Vec<u8> {
    let mut b = Vec::new();
    for i in 0..2000 {
        b.extend_from_slice(
            format!("line {i} of the snapshot vector {}\n", "ab".repeat(i % 37)).as_bytes(),
        );
    }
    let mut x: u32 = 1;
    for _ in 0..65536 {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        b.push((x >> 24) as u8);
    }
    for i in 0..500 {
        b.extend_from_slice(format!("tail {i} {}\n", "xyz".repeat(i % 11)).as_bytes());
    }
    b
}

fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

#[test]
fn go_s2_reads_here() {
    let plain = content();
    let b = std::fs::read(dir().join("go-s2.bin")).unwrap();
    let mut got = Vec::new();
    snapformat::open_snap_reader(&b[..])
        .unwrap()
        .read_to_end(&mut got)
        .unwrap();
    assert_eq!(
        Sha256::digest(&got),
        Sha256::digest(&plain),
        "{} of {}",
        got.len(),
        plain.len()
    );
}

#[test]
fn gzip_reads_here() {
    let plain = content();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&plain).unwrap();
    let b = gz.finish().unwrap();
    let mut got = Vec::new();
    snapformat::open_snap_reader(&b[..])
        .unwrap()
        .read_to_end(&mut got)
        .unwrap();
    assert_eq!(got, plain);
    assert!(snapformat::open_snap_reader(&b"x"[..]).is_err());
    assert!(snapformat::open_snap_reader(&b"neither format"[..]).is_err());
}

#[test]
fn rust_s2_round_trips_and_writes() {
    let plain = content();
    let mut out = Vec::new();
    {
        let mut w = snapformat::SnapWriter::new(&mut out);
        let half = plain.len() / 2;
        w.write_all(&plain[..half]).unwrap();
        w.flush().unwrap();
        w.write_all(&plain[half..]).unwrap();
        w.finish().unwrap();
    }
    let mut got = Vec::new();
    snapformat::open_snap_reader(&out[..])
        .unwrap()
        .read_to_end(&mut got)
        .unwrap();
    assert_eq!(got, plain);
    if std::env::var("GEN_RUST_VECTORS").as_deref() == Ok("1") {
        std::fs::write(dir().join("rust-s2.bin"), &out).unwrap();
    }
}
