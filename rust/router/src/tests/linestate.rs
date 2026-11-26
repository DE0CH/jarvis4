//! linestate_test.go
use crate::core::CoreClient;
use crate::linestate::{LINE_SEQ_HEADER, LineKeeper};
use crate::testutil::*;
use jarvis_nethttp::write_json;
use serde_json::json;
use std::sync::{Arc, Mutex};

/// a core that names a line seq in every answer and serves its line state (core/continuity.go)
struct LineCore {
    key: TestKey,
    seq: i64,
    master: String,
}

fn line_core_answer(lc: &LineCore, w: &mut jarvis_nethttp::W, path: &str) {
    if lc.seq > 0 {
        w.set_header(LINE_SEQ_HEADER, &lc.seq.to_string());
    }
    match path {
        "/identity" => write_json(
            w,
            200,
            &json!({"signingKey": lc.key.public(), "state": lc.key.doc(&json!({"kind": "core-state", "master": lc.master}))}),
        ),
        "/line-state" => write_json(
            w,
            200,
            &json!({"head": lc.key.doc(&json!({"kind": "line-state-head", "seq": lc.seq, "sha256": "x"})), "sealed": "c2VhbGVk"}),
        ),
        _ => write_json(w, 200, &lc.key.doc(&json!({"kind": "ok"}))),
    }
}

fn line_core(key: TestKey, seq: i64, master: &str) -> (Arc<Mutex<LineCore>>, TestServer) {
    let lc = Arc::new(Mutex::new(LineCore {
        key,
        seq,
        master: master.into(),
    }));
    let l2 = lc.clone();
    let srv = TestServer::handler(move |w, req| {
        let g = l2.lock().unwrap_or_else(|e| e.into_inner());
        line_core_answer(&g, w, &req.path.clone());
    });
    (lc, srv)
}

fn hook(c: &CoreClient, k: &Arc<LineKeeper>) {
    let k = k.clone();
    *c.on_line_seq.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(move |s| k.seen(s)));
}

#[test]
fn the_router_keeps_the_newest_line_state_before_the_answer_goes_on() {
    let (lc, srv) = line_core(TestKey::new(), 3, "m");
    let cc = Arc::new(CoreClient::new(&srv.url));
    let db = TestDb::new();
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let docs = Arc::new(test_state(&db, dir.path()));
    let k = LineKeeper::new_core(docs.clone(), cc.clone());
    hook(&cc, &k);
    cc.raw("POST", "/certify", Some(b"{}"))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let core_key = lc.lock().unwrap_or_else(|e| e.into_inner()).key.public();
    let x = k.current();
    assert!(
        x.as_ref().is_some_and(|x| x.seq == 3 && x.core == core_key),
        "kept {:?}",
        x.map(|x| (x.seq, x.core))
    );
    lc.lock().unwrap_or_else(|e| e.into_inner()).seq = 7;
    let _ = cc.raw("POST", "/kill", Some(b"{}"));
    assert_eq!(k.current().map(|x| x.seq), Some(7));
    // a router that starts again reads it from its database
    let k2 = LineKeeper::new_core(docs.clone(), cc.clone());
    assert_eq!(k2.current().map(|x| x.seq), Some(7), "after a restart");
    // a head the running core didn't sign isn't kept
    let (bad, _bsrv0) = line_core(TestKey::new(), 9, "m");
    let (l2, b2) = (lc.clone(), bad.clone());
    let bsrv = TestServer::handler(move |w, req| {
        let path = req.path.clone();
        if path == "/identity" {
            let g = l2.lock().unwrap_or_else(|e| e.into_inner());
            return line_core_answer(&g, w, &path); // the identity says lc's key
        }
        let g = b2.lock().unwrap_or_else(|e| e.into_inner());
        line_core_answer(&g, w, &path);
    });
    let bc = Arc::new(CoreClient::new(&bsrv.url));
    let k3 = LineKeeper::new_core(docs.clone(), bc.clone());
    hook(&bc, &k3);
    let _ = bc.raw("POST", "/x", None);
    let cur = k3.current();
    assert_eq!(
        cur.as_ref().map(|x| x.seq),
        Some(7),
        "kept a head another key signed"
    );
    let b = serde_json::to_vec(&cur.map(|x| x.doc)).unwrap_or_default();
    assert!(!b.is_empty(), "no doc");
}

#[test]
fn a_recovered_core_with_the_same_key_keeps_its_sessions() {
    // its own session ids: corechange.rs remembers a tried destroy by session id across routers
    let r = new_test_router();
    r.records_off
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (lc, srv) = line_core(TestKey::new(), 0, "m");
    r.core.set_url(&srv.url);
    let cert = lc
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .key
        .doc(&json!({"kind": "succession-cert", "line": "L1"}));
    r.st.do_(|d| {
        for (id, state, m) in [("ls1", "paused", ""), ("ls2", "started", "lm2")] {
            d.sessions.insert(
                id.into(),
                crate::state::Session {
                    id: id.into(),
                    state: state.into(),
                    machine_id: m.into(),
                    harness: "claude".into(),
                    cert: Some(cert.clone()),
                    ..Default::default()
                },
            );
        }
    });
    r.core_change_tick();
    // the restart: an empty core (its boot key) decides nothing
    let k = {
        let mut g = lc.lock().unwrap_or_else(|e| e.into_inner());
        let k = std::mem::take(&mut g.key);
        g.master = String::new();
        k
    };
    r.core_change_tick();
    // the Recover with the same kit: the same key again
    {
        let mut g = lc.lock().unwrap_or_else(|e| e.into_inner());
        g.key = k;
        g.master = "m".into();
    }
    r.core_change_tick();
    r.st.do_(|d| {
        for id in ["ls1", "ls2"] {
            assert!(
                d.sessions.get(id).is_some_and(|s| !s.old_core),
                "{id} was taken for an earlier core's"
            );
        }
    });
    // a Reset (another key): the sessions are the earlier core's
    lc.lock().unwrap_or_else(|e| e.into_inner()).key = TestKey::new();
    r.core_change_tick();
    assert!(
        r.st.do_(|d| d.sessions.get("ls2").is_some_and(|s| s.old_core)),
        "after a Reset the sessions aren't marked as the earlier core's"
    );
}
