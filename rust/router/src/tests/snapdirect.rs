//! snapdirect_test.go (snapdirect_live_test.go, against the real bucket, is left out: it needs the bucket's
//! credential in the env)
use crate::archive::CHANGES_FILE;
use crate::objstore::{MemObjects, ObjDirect, ObjReader, ObjStore};
use crate::snapdirect::DIRECT_PART_SIZE;
use crate::tails::read_snapshot_facts_from;
use crate::testutil::*;
use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// the memory store with the bucket's direct side, its part and read URLs served by a test server
#[derive(Default)]
struct DirectState {
    mem: MemObjects,
    /// upload → part → bytes
    parts: Mutex<BTreeMap<String, BTreeMap<i64, Vec<u8>>>>,
    done: Mutex<BTreeSet<String>>,
}

struct DirectMem {
    st: Arc<DirectState>,
    srv: TestServer,
}

fn direct_mem() -> Arc<DirectMem> {
    let st: Arc<DirectState> = Arc::default();
    let s2 = st.clone();
    let srv = TestServer::handler(move |w, req| {
        if req.method == "PUT" {
            let p: i64 = req.query("partNumber").parse().unwrap_or(0);
            let up = req.query("uploadId");
            let b = req.read_body(64 << 20);
            let finished = s2
                .done
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&up);
            let mut parts = s2.parts.lock().unwrap_or_else(|e| e.into_inner());
            let Some(m) = parts.get_mut(&up).filter(|_| !finished) else {
                w.write_header(404);
                return;
            };
            m.insert(p, b);
            w.set_header("ETag", &format!("\"{p}\""));
            w.write_header(200);
            return;
        }
        let key = req.path.trim_start_matches('/').to_string();
        match s2.mem.get(&key) {
            Ok(mut rd) => {
                let mut b = vec![];
                let _ = rd.read_to_end(&mut b);
                w.write(&b);
            }
            Err(_) => w.write_header(404),
        }
    });
    Arc::new(DirectMem { st, srv })
}

impl ObjStore for DirectMem {
    fn put(&self, key: &str, r: &mut dyn Read, size: i64) -> Result<()> {
        self.st.mem.put(key, r, size)
    }
    fn get(&self, key: &str) -> Result<ObjReader> {
        self.st.mem.get(key)
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.st.mem.delete(key)
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.st.mem.list(prefix)
    }
    fn direct(&self) -> Option<&dyn ObjDirect> {
        Some(self)
    }
}

impl ObjDirect for DirectMem {
    fn start_upload(&self, _key: &str) -> Result<String> {
        let id = crate::util::rand_id();
        self.st
            .parts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.clone(), BTreeMap::new());
        Ok(id)
    }
    fn part_url(&self, key: &str, upload: &str, part: i64, _: Duration) -> Result<String> {
        Ok(format!(
            "{}/{key}?partNumber={part}&uploadId={upload}",
            self.srv.url
        ))
    }
    fn finish_upload(&self, key: &str, upload: &str, etags: &[String]) -> Result<()> {
        let mut all = vec![];
        {
            let parts = self.st.parts.lock().unwrap_or_else(|e| e.into_inner());
            for (i, e) in etags.iter().enumerate() {
                let n = i64::try_from(i).unwrap_or(0) + 1;
                match parts.get(upload).and_then(|m| m.get(&n)) {
                    Some(b) if *e == format!("\"{n}\"") => all.extend_from_slice(b),
                    _ => return Err(anyhow!("part {n}: no such part")),
                }
            }
        }
        self.st
            .done
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(upload.to_string());
        let n = i64::try_from(all.len()).unwrap_or(0);
        self.st.mem.put(key, &mut all.as_slice(), n)
    }
    fn abort_upload(&self, _key: &str, upload: &str) -> Result<()> {
        self.st
            .done
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(upload.to_string());
        Ok(())
    }
    fn get_url(&self, key: &str, _: Duration) -> Result<String> {
        Ok(format!("{}/{key}", self.srv.url))
    }
}

/// a snapshot holding one transcript and the repos' state, compressed with S2 or gzip
fn test_snap_tar(gz: bool) -> Vec<u8> {
    let mut tb = tar::Builder::new(Vec::new());
    let mut put = |name: &str, body: &[u8]| {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o600);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_mtime(u64::try_from(crate::util::unix_now()).unwrap_or(0));
        h.set_cksum();
        tb.append_data(&mut h, name, body)
            .unwrap_or_else(|e| panic!("{e}"));
    };
    put(
        ".claude/projects/-home-claude-workspace/0b6a2f3e-1111-4222-8333-444455556666.jsonl",
        b"{\"type\":\"user\"}\n",
    );
    put(CHANGES_FILE, b"claude-env 2 0\n");
    put("workspace/x", &vec![b'x'; 6 << 20]);
    let raw = tb.into_inner().unwrap_or_else(|e| panic!("{e}"));
    let mut out = vec![];
    if gz {
        let mut z = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
        z.write_all(&raw).unwrap_or_else(|e| panic!("{e}"));
        z.finish().unwrap_or_else(|e| panic!("{e}"));
    } else {
        let mut z = minlz::Writer::new(&mut out);
        z.write_all(&raw).unwrap_or_else(|e| panic!("{e}"));
        z.flush().unwrap_or_else(|e| panic!("{e}"));
        drop(z);
    }
    out
}

#[test]
fn snapshot_facts_read_both_formats() {
    for gz in [false, true] {
        let f = read_snapshot_facts_from(&mut test_snap_tar(gz).as_slice());
        assert!(
            f.as_ref()
                .is_ok_and(|f| f.transcripts.as_ref().is_some_and(|t| t.len() == 1)
                    && f.changes
                        .as_ref()
                        .is_some_and(|c| c.contains("claude-env 2 0"))),
            "gzip {gz}: {f:?}"
        );
    }
    assert!(
        read_snapshot_facts_from(&mut b"plain text".as_slice()).is_err(),
        "read facts from neither format"
    );
}

#[test]
fn no_direct_bucket_means_no_upload_urls() {
    let rg = Rig::new();
    rg.running_m2(false);
    let m = rg.machine("m2");
    let (code, _) = m.do_(&rg.machine_handler(), "POST", "/m/snapshot-upload", "{}");
    assert_eq!(code, 404, "an upload with no bucket to sign for");
}

fn put_part(url: &str, b: &[u8]) -> (u16, String) {
    let resp = reqwest::blocking::Client::new()
        .put(url)
        .body(b.to_vec())
        .send()
        .unwrap_or_else(|e| panic!("{e}"));
    let etag = resp
        .headers()
        .get("ETag")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (resp.status().as_u16(), etag)
}

fn urls(out: &Value) -> Vec<String> {
    out["urls"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|u| u.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// the machine puts its snapshot to the bucket in parts; the router reads it back, keeps it pending under that hash,
/// the machine's signature commits it, and the successor gets a read URL with the signature
#[test]
fn a_direct_snapshot_is_read_back_committed_and_handed_to_the_successor() {
    let d = direct_mem();
    let rg = Rig::with_objects(d.clone());
    rg.running_m2(false);
    let m = rg.machine("m2");
    let h = rg.machine_handler();
    let body = test_snap_tar(false);
    let (code, out) = m.do_(&h, "POST", "/m/snapshot-upload", "{}");
    assert!(
        code == 200 && out["partSize"] == DIRECT_PART_SIZE,
        "{code} {out}"
    );
    let up = out["upload"].as_str().unwrap_or_default().to_string();
    let parts = |from: i64, count: i64| {
        m.do_(
            &h,
            "POST",
            "/m/snapshot-upload/parts",
            &jarvis_go::marshal(&json!({"upload": up, "from": from, "count": count})),
        )
    };
    assert_eq!(parts(1, 65).0, 400, "65 part URLs at once");
    let (code, out) = parts(1, 2);
    let us = urls(&out);
    assert!(code == 200 && us.len() == 2, "{code} {out}");
    let half = body.len() / 2;
    let mut etags = vec![];
    for (i, chunk) in [&body[..half], &body[half..]].iter().enumerate() {
        let (st, etag) = put_part(&us[i], chunk);
        assert_eq!(st, 200, "part {}", i + 1);
        etags.push(etag);
    }
    let done = |ps: Value| {
        m.do_(
            &h,
            "POST",
            "/m/snapshot-upload/done",
            &jarvis_go::marshal(&json!({"upload": up, "parts": ps})),
        )
    };
    assert_eq!(
        done(json!([{"n": 2, "etag": etags[1]}])).0,
        400,
        "parts out of order"
    );
    let want = hex::encode(sha2::Sha256::digest(&body));
    let (code, out) = done(json!([{"n": 1, "etag": etags[0]}, {"n": 2, "etag": etags[1]}]));
    assert!(
        code == 200 && out["sha256"] == want.as_str() && out["bytes"] == body.len(),
        "{code} {out}"
    );
    let s = rg.snap("m2");
    assert!(
        s.as_ref().is_some_and(|s| s.state == "pending"
            && s.facts
                .as_ref()
                .is_some_and(|f| f.transcripts.as_ref().is_some_and(|t| t.len() == 1))),
        "the pending row: {s:?}"
    );
    let good = rg.mkey.0.sign(want.as_bytes());
    let (code, _) = m.do_(
        &h,
        "POST",
        "/m/snapshot-commit",
        &format!(r#"{{"sha256":"{want}","sig":"{good}"}}"#),
    );
    assert!(code == 200 && rg.have_snap("m2"), "commit: {code}");
    // the finished upload's part URL writes nothing more
    let (_, out) = parts(1, 1);
    let (st, _) = put_part(&urls(&out)[0], b"overwrite");
    assert_ne!(st, 200, "a part URL of the finished upload still writes");

    // the successor m3 (its cert's predecessor is m2)
    let m3 = new_test_machine(&rg, "m3");
    let cert = rg
        .core
        .key
        .doc(&json!({"kind": "succession-cert", "predecessorId": "m2", "line": "m1"}));
    rg.st.do_(|dd| {
        dd.certs.insert("m3".into(), cert.clone());
        dd.machines.insert("m3".into(), "s1".into());
    });
    let (code, out) = m3.do_(&h, "GET", "/m/snapshot-url", "");
    assert!(
        code == 200
            && out["sha256"] == want.as_str()
            && out["sig"] == good.as_str()
            && out["bytes"] == body.len(),
        "{code} {out}"
    );
    let got = reqwest::blocking::get(out["url"].as_str().unwrap_or_default())
        .and_then(|r| r.bytes())
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        got.as_ref() == body.as_slice(),
        "the read URL serves other bytes"
    );
    // a machine with no predecessor gets none
    let m4 = new_test_machine(&rg, "m4");
    let (code, out) = m4.do_(&h, "GET", "/m/snapshot-url", "");
    assert!(
        code == 404 && out["error"] == "no predecessor",
        "{code} {out}"
    );
    let (code, _) = m.do_(
        &h,
        "POST",
        "/m/snapshot-upload/abort",
        &jarvis_go::marshal(&json!({"upload": up})),
    );
    assert_eq!(code, 200);
}
