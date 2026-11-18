//! Whole snapshots against what the Go machine wrote: go-snapshot.bin (Go's writeSnapshot of the fixture home) restores
//! here, and so does rust-snapshot.bin (what this port writes of the same home), which the Go machine also restored
//! (checked both ways before machine/ was deleted, 2026-11-17: snapshots Go machines stored still restore).
//! `GEN_RUST_VECTORS=1 cargo test -p jarvis-machine snapvectors` writes rust-snapshot.bin again.

use super::testutil::*;
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

fn vec_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// the same home as Go's snapFixture: long names (over 100 bytes, and a 255-byte file name), non-ASCII, an
/// executable, a symlink, an empty directory, a file over several blocks, fixed modification times
fn fixture(home: &Path) {
    let mt = SystemTime::UNIX_EPOCH + Duration::from_secs(1791700000);
    let long = format!(
        "workspace/repo/{}/{}/{}",
        "d".repeat(60),
        "e".repeat(60),
        "f".repeat(255)
    );
    let mut big = vec![0u8; 300 << 10];
    let mut x: u32 = 7;
    for b in big.iter_mut() {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        *b = (x >> 24) as u8;
    }
    let files: [(&str, &[u8], u32); 7] = [
        ("workspace/repo/a.txt", b"hello\n", 0o644),
        ("workspace/repo/tool.bin", b"\x7fELF not really\n", 0o755),
        ("workspace/repo/名前 with space.txt", b"unicode\n", 0o600),
        (&long, b"deep\n", 0o644),
        (
            ".claude/projects/p/c.jsonl",
            b"{\"type\":\"user\"}\n",
            0o600,
        ),
        (".claude.json", b"{}", 0o600),
        ("artifacts/big.bin", &big, 0o644),
    ];
    for (rel, body, mode) in files {
        let p = home.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(mt)
            .unwrap();
    }
    std::fs::create_dir_all(home.join("workspace/empty")).unwrap();
    std::os::unix::fs::symlink("a.txt", home.join("workspace/repo/link")).unwrap();
}

/// every entry under home, one line each, as Go's snapManifest
fn manifest(home: &Path) -> String {
    fn walk(home: &Path, d: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            let rel = p.strip_prefix(home).unwrap().to_string_lossy().into_owned();
            let md = std::fs::symlink_metadata(&p).unwrap();
            if md.file_type().is_symlink() {
                out.push(format!(
                    "{rel} link {}",
                    std::fs::read_link(&p).unwrap().display()
                ));
            } else if md.is_dir() {
                out.push(format!("{rel} dir"));
                walk(home, &p, out);
            } else {
                let s = Sha256::digest(std::fs::read(&p).unwrap());
                let mt = md
                    .modified()
                    .unwrap()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                out.push(format!(
                    "{rel} file {:o} {} {} {mt}",
                    md.permissions().mode() & 0o777,
                    md.len(),
                    hex::encode(&s[..8])
                ));
            }
        }
    }
    let mut v = vec![];
    walk(home, home, &mut v);
    v.sort();
    v.join("\n")
}

#[test]
fn snapshots_restore_both_ways() {
    let e = TestEnv::new();
    let src = e.root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    fixture(&src);
    let want = manifest(&src);
    if std::env::var("GEN_RUST_VECTORS").as_deref() == Ok("1") {
        crate::env::set("HOME", Some(src.to_str().unwrap()));
        let f = std::fs::File::create(vec_dir().join("rust-snapshot.bin")).unwrap();
        crate::snapshot::write_snapshot(f).unwrap();
    }
    for name in ["go-snapshot.bin", "rust-snapshot.bin"] {
        let dst = e.root.join(format!("dst-{name}"));
        std::fs::create_dir_all(&dst).unwrap();
        crate::env::set("HOME", Some(dst.to_str().unwrap()));
        let f = std::fs::File::open(vec_dir().join(name)).unwrap();
        crate::snapshot::unpack_reader(f).unwrap_or_else(|e| panic!("{name}: {e:#}"));
        let got = manifest(&dst);
        assert!(got == want, "{name} restores as\n{got}\nwant\n{want}");
    }
}
