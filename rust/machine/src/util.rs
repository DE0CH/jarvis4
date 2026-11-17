//! Small helpers the Go code had from its standard library.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Go's os.WriteFile: create (with `mode`) or truncate, write
pub fn write_file(p: &Path, b: &[u8], mode: u32) -> std::io::Result<()> {
    let mut f = create_file(p, mode)?;
    f.write_all(b)
}

/// Go's os.OpenFile(p, O_CREATE|O_TRUNC|O_WRONLY, mode)
pub fn create_file(p: &Path, mode: u32) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(mode)
        .open(p)
}

/// The first `n` bytes of `s` (Go's s[:min(n, len(s))]), cut back to a character boundary
pub fn clip_bytes(s: &str, n: usize) -> &str {
    if s.len() <= n {
        return s;
    }
    let mut i = n;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

pub fn file_exists(p: &Path) -> bool {
    std::fs::metadata(p).is_ok()
}

/// Go's time.Now().UTC().Format(time.RFC3339)
pub fn now_rfc3339() -> String {
    let t = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// unix seconds now
pub fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// sleep on a plain thread
pub fn sleep(d: std::time::Duration) {
    std::thread::sleep(d)
}
