//! The snapshot's compression (snapformat.go, DECISIONS 241): S2 (Snappy's successor), whose CPU per byte suits a
//! final snapshot on Fly's shared CPUs. Snapshots made before are gzip: every reader tells the two apart by their
//! first bytes. The files and objects keep their names (snapshot.tar.gz: the role, not the format).

use anyhow::{Result, bail};
use std::io::{BufRead, BufReader, Read, Write};

const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];
/// the stream identifier chunk
const S2_MAGIC: &[u8] = b"\xff\x06\x00\x00S2sTwO";

/// The compressor a snapshot is written through: `flush` sends what it holds as a block of its own; `finish` ends the
/// stream (not the writer under it)
pub struct SnapWriter<W: Write> {
    w: minlz::Writer<W>,
}

impl<W: Write> SnapWriter<W> {
    pub fn new(w: W) -> Self {
        Self {
            w: minlz::Writer::new(w),
        }
    }

    /// the stream ended: what it holds goes out (the writer under it stays open)
    pub fn finish(mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

impl<W: Write> Write for SnapWriter<W> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.w.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

/// A snapshot's tar, from its S2 or (older) gzip bytes
pub fn open_snap_reader<'a, R: Read + 'a>(r: R) -> Result<Box<dyn Read + 'a>> {
    let mut br = BufReader::with_capacity(1 << 20, r);
    let head = br.fill_buf()?.to_vec();
    if head.len() < 2 {
        bail!("not a snapshot: too short");
    }
    if head.starts_with(S2_MAGIC) {
        return Ok(Box::new(minlz::Reader::new(br)));
    }
    if head.starts_with(GZIP_MAGIC) {
        return Ok(Box::new(flate2::read::MultiGzDecoder::new(br)));
    }
    bail!("not a snapshot: neither S2 nor gzip")
}
