//! objstore_resume_test.go: an object's read over S3 that a dropped connection doesn't end
use crate::objstore::{ObjStore, S3Objects, is_no_object};
use crate::testutil::TestServer;
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// one object over S3's GET (Range included); the first `cut` GETs send the headers for the whole body, half of it,
/// and then end, as WARP's resets did (2026-11-21)
fn cutting_bucket(body: Vec<u8>, cut: usize) -> (TestServer, S3Objects, Arc<AtomicUsize>) {
    let gets = Arc::new(AtomicUsize::new(0));
    let g = gets.clone();
    let srv = TestServer::handler(move |w, req| {
        if req.path != "/bucket/snap" {
            w.set_header("Content-Type", "application/xml");
            w.write_header(404);
            w.write_str(r#"<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code><Message>no</Message></Error>"#);
            return;
        }
        let from: usize = req
            .header("Range")
            .strip_prefix("bytes=")
            .and_then(|r| r.trim_end_matches('-').parse().ok())
            .unwrap_or(0);
        let part = &body[from..];
        w.set_header("ETag", "\"e1\"");
        w.set_header("Content-Type", "application/octet-stream");
        w.set_header("Content-Length", &part.len().to_string());
        if from > 0 {
            w.set_header(
                "Content-Range",
                &format!("bytes {from}-{}/{}", body.len() - 1, body.len()),
            );
            w.write_header(206);
        }
        if req.method == "HEAD" {
            return;
        }
        if g.fetch_add(1, Ordering::SeqCst) < cut {
            w.write(&part[..part.len() / 2]);
            return;
        }
        w.write(part);
    });
    let o = S3Objects::new(&srv.url, "fsn1", "bucket", "k", "s");
    (srv, o, gets)
}

#[test]
fn an_object_read_cut_off_goes_on_from_where_it_broke() {
    let body = b"0123456789abcdef".repeat(1 << 14); // 256 KiB
    let (_srv, o, gets) = cutting_bucket(body.clone(), 1);
    let mut rd = o.get("snap").unwrap_or_else(|e| panic!("{e:#}"));
    let mut got = vec![];
    rd.read_to_end(&mut got)
        .unwrap_or_else(|e| panic!("the read failed: {e}"));
    assert!(
        got == body,
        "read {} bytes, not the object's {} as it is",
        got.len(),
        body.len()
    );
    assert!(
        gets.load(Ordering::SeqCst) >= 2,
        "{} GETs: the read was never cut",
        gets.load(Ordering::SeqCst)
    );
}

#[test]
fn a_missing_object_is_still_no_object() {
    let (_srv, o, _) = cutting_bucket(b"x".to_vec(), 0);
    match o.get("other") {
        Err(e) => assert!(is_no_object(&e), "got {e:#}, not NoObject"),
        Ok(_) => panic!("a missing object was read"),
    }
}
