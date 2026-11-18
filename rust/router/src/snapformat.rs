//! A snapshot's compression (rust/machine/src/snapformat.rs, DECISIONS 241): S2 from 2026-10-25 on, gzip before; every
//! reader tells them apart by their first bytes. The archive around a snapshot stays gzip.

use anyhow::{Result, bail};
use std::io::{BufReader, Cursor, Read};

const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];
/// the stream identifier chunk
const S2_MAGIC: &[u8] = b"\xff\x06\x00\x00S2sTwO";

/// a snapshot's tar, from its S2 or (older) gzip bytes
pub fn open_snap_reader<'a, R: Read + 'a>(mut r: R) -> Result<Box<dyn Read + 'a>> {
    // the first bytes, waited for as Go's Peek does (one read may bring fewer)
    let mut head = vec![0u8; S2_MAGIC.len()];
    let mut n = 0;
    while n < head.len() {
        match r.read(&mut head[n..])? {
            0 => break,
            k => n += k,
        }
    }
    head.truncate(n);
    if head.len() < 2 {
        bail!("not a snapshot: too short");
    }
    let s2 = head.starts_with(S2_MAGIC);
    let gz = head.starts_with(GZIP_MAGIC);
    let br = BufReader::with_capacity(1 << 20, Cursor::new(head).chain(r));
    if s2 {
        return Ok(Box::new(minlz::Reader::new(br)));
    }
    if gz {
        return Ok(Box::new(flate2::read::MultiGzDecoder::new(br)));
    }
    bail!("not a snapshot: neither S2 nor gzip")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn both_formats() {
        let mut s2 = vec![];
        {
            let mut w = minlz::Writer::new(&mut s2);
            w.write_all(b"tar bytes").unwrap_or_else(|e| panic!("{e}"));
            w.flush().unwrap_or_else(|e| panic!("{e}"));
        }
        let mut out = String::new();
        open_snap_reader(&s2[..])
            .and_then(|mut r| Ok(r.read_to_string(&mut out)?))
            .unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(out, "tar bytes");
        let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::fast());
        gz.write_all(b"old").unwrap_or_else(|e| panic!("{e}"));
        let gz = gz.finish().unwrap_or_default();
        let mut out = String::new();
        open_snap_reader(&gz[..])
            .and_then(|mut r| Ok(r.read_to_string(&mut out)?))
            .unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(out, "old");
        assert!(open_snap_reader(&b"x"[..]).is_err());
    }
}
