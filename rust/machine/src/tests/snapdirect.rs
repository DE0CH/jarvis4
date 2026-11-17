//! snapdirect_test.go: snapshots straight between the machine and the bucket, in parts and ranges.

use super::testutil::*;
use crate::snapdirect::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Bucket {
    parts: BTreeMap<usize, Vec<u8>>,
    object: Vec<u8>,
    fail_once: BTreeMap<usize, bool>,
    puts: usize,
    direct: bool,
    streamed: Vec<u8>,
    aborted: bool,
    range_gets: usize,
}

/// a bucket's part uploads and ranged reads, with the router's side of snapdirect.go in front of it
fn fake_bucket(key: &str) -> (FakeRouter, Arc<Mutex<Bucket>>) {
    let b = Arc::new(Mutex::new(Bucket {
        direct: true,
        ..Default::default()
    }));
    let b2 = b.clone();
    let url: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let u2 = url.clone();
    let srv = FakeRouter::open(key, move |r| {
        let mut b = b2.lock().unwrap();
        let base = u2.lock().unwrap().clone();
        let signed = r.headers.contains_key("X-Checked");
        let inp: serde_json::Value = serde_json::from_slice(&r.body).unwrap_or_default();
        if (r.path.starts_with("/m/snapshot-upload") || r.path == "/m/snapshot-url") && !b.direct {
            return ans(404, "");
        }
        if r.path.starts_with("/m/") && !signed {
            return ans(401, "");
        }
        match r.path.as_str() {
            "/m/snapshot-upload" => {
                ok_json(serde_json::json!({"upload": "u1", "partSize": 5 << 20}))
            }
            "/m/snapshot-upload/parts" => {
                let (from, count) = (
                    inp["from"].as_u64().unwrap() as usize,
                    inp["count"].as_u64().unwrap() as usize,
                );
                let urls: Vec<String> = (from..from + count)
                    .map(|p| format!("{base}/bucket?partNumber={p}"))
                    .collect();
                ok_json(serde_json::json!({ "urls": urls }))
            }
            "/bucket" if r.method == "PUT" => {
                let p: usize = r
                    .query
                    .strip_prefix("partNumber=")
                    .unwrap()
                    .parse()
                    .unwrap();
                b.puts += 1;
                if b.fail_once.remove(&p).is_some() {
                    return ans(500, "");
                }
                b.parts.insert(p, r.body.clone());
                Ans {
                    status: 200,
                    headers: vec![("ETag".into(), format!("\"e{p}\""))],
                    body: vec![],
                }
            }
            "/bucket" => {
                let rg = r
                    .headers
                    .get("Range")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .strip_prefix("bytes=")
                    .unwrap()
                    .to_string();
                let (from, to) = rg.split_once('-').unwrap();
                let (from, to): (usize, usize) = (from.parse().unwrap(), to.parse().unwrap());
                b.range_gets += 1;
                ans(206, b.object[from..=to].to_vec())
            }
            "/m/snapshot-upload/done" => {
                let mut obj = vec![];
                for (i, p) in inp["parts"].as_array().unwrap().iter().enumerate() {
                    if p["n"].as_u64() != Some(i as u64 + 1)
                        || p["etag"].as_str() != Some(&format!("\"e{}\"", i + 1))
                    {
                        return ans(400, "");
                    }
                    obj.extend_from_slice(&b.parts[&(i + 1)]);
                }
                b.object = obj;
                ok_json(
                    serde_json::json!({"sha256": hex::encode(Sha256::digest(&b.object)), "bytes": b.object.len()}),
                )
            }
            "/m/snapshot-upload/abort" => {
                b.aborted = true;
                ok_json(serde_json::json!({"ok": true}))
            }
            "/m/snapshot-stream" => {
                b.streamed = r.body.clone();
                ok_json(
                    serde_json::json!({"sha256": hex::encode(Sha256::digest(&r.body)), "bytes": r.body.len()}),
                )
            }
            "/m/snapshot-url" => ok_json(
                serde_json::json!({"url": format!("{base}/bucket"), "sha256": "", "bytes": b.object.len(), "sig": "the-sig"}),
            ),
            "/m/snapshot" => Ans {
                status: 200,
                headers: vec![("X-Snapshot-Sig".into(), "the-sig".into())],
                body: b.object.clone(),
            },
            _ => ans(404, ""),
        }
    });
    *url.lock().unwrap() = srv.url.clone();
    (srv, b)
}

/// a home whose snapshot is several parts: a large file that doesn't compress and a few small ones
fn snap_home(e: &TestEnv) {
    let mut big = vec![0u8; 12 << 20];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut big);
    std::fs::create_dir_all(e.home.join("workspace/repo")).unwrap();
    std::fs::write(e.home.join("workspace/repo/big.bin"), &big).unwrap();
    std::fs::write(e.home.join("workspace/repo/a.txt"), "hello").unwrap();
    std::fs::create_dir_all(e.home.join(".claude/projects/p")).unwrap();
    std::fs::write(
        e.home.join(".claude/projects/p/c.jsonl"),
        "{\"type\":\"user\"}\n",
    )
    .unwrap();
}

#[test]
fn direct_snapshot_goes_up_in_parts_and_comes_back() {
    let e = TestEnv::new();
    let key = e.machine_key();
    DIRECT_BACKOFF_MS.store(1, Ordering::SeqCst);
    snap_home(&e);
    let (srv, b) = fake_bucket(&key.sig.public_key());
    b.lock().unwrap().fail_once.insert(2, true); // tried again
    let c = srv.client();
    let (sum, n) = direct_snapshot(&c).unwrap();
    {
        let b = b.lock().unwrap();
        assert!(
            b.parts.len() == 3 && b.puts == 4 && b.object.len() as u64 == n,
            "{} parts, {} puts, {} of {n} bytes",
            b.parts.len(),
            b.puts,
            b.object.len()
        );
        assert!(
            b.object.starts_with(b"\xff\x06\x00\x00S2sTwO"),
            "not an S2 stream"
        );
    }
    // the next machine: ranges of the object into the file, then the hash and the unpack
    RANGE_SIZE.store(4 << 20, Ordering::SeqCst);
    let home2 = e.root.join("home2");
    std::fs::create_dir_all(&home2).unwrap();
    crate::env::set("HOME", Some(home2.to_str().unwrap()));
    let dst = e.root.join("pred");
    let (got, sig) = fetch_snapshot(&c, &dst).unwrap();
    assert_eq!((got.as_str(), sig.as_str()), (sum.as_str(), "the-sig"));
    assert!(b.lock().unwrap().range_gets >= 4, "range reads");
    assert_eq!(crate::snapshot::unpack_file(&dst).unwrap(), 3);
    assert_eq!(
        std::fs::read_to_string(home2.join("workspace/repo/a.txt")).unwrap(),
        "hello"
    );
    assert_eq!(
        std::fs::metadata(home2.join("workspace/repo/big.bin"))
            .unwrap()
            .len(),
        12 << 20
    );
}

#[test]
fn direct_snapshot_fails_and_aborts_when_a_part_never_goes_up() {
    let e = TestEnv::new();
    let key = e.machine_key();
    DIRECT_BACKOFF_MS.store(1, Ordering::SeqCst);
    DIRECT_TRIES.store(1, Ordering::SeqCst);
    snap_home(&e);
    let (srv, b) = fake_bucket(&key.sig.public_key());
    b.lock().unwrap().fail_once.insert(1, true); // its one try fails
    let r = direct_snapshot(&srv.client());
    assert!(
        format!("{:#}", r.as_ref().unwrap_err()).contains("part 1"),
        "{r:?}"
    );
    assert!(b.lock().unwrap().aborted, "the upload wasn't aborted");
}

#[test]
fn no_bucket_urls_means_the_stream_through_the_router() {
    let e = TestEnv::new();
    let key = e.machine_key();
    snap_home(&e);
    let (srv, b) = fake_bucket(&key.sig.public_key());
    b.lock().unwrap().direct = false;
    let c = srv.client();
    let r = direct_snapshot(&c);
    assert!(
        r.as_ref()
            .is_err_and(|e| e.downcast_ref::<NoDirect>().is_some()),
        "{r:?}"
    );
    let (sum, _) = crate::snapstream::stream_snapshot(&c).unwrap();
    {
        let mut b = b.lock().unwrap();
        assert!(!b.streamed.is_empty());
        b.object = b.streamed.clone();
    }
    let (got, sig) = fetch_snapshot(&c, &e.root.join("pred")).unwrap(); // /m/snapshot, through the router
    assert_eq!((got, sig.as_str()), (sum, "the-sig"));
}
