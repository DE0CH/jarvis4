//! content and drain tests

use crate::autopilot::Liveness;
use crate::content::{CONTENT_ROOT, content_name, content_path, invalidate_content};
use crate::drain::DRAINING_MSG;
use crate::state::{Approval, Session};
use crate::testutil::{Rig, TestMachine, call, new_test_machine, signed_headers, wait_for};
use crate::vouch::SessionConfig;
use jarvis_go::GoTime;
use serde_json::json;
use std::time::Duration;

fn raw(
    h: &jarvis_nethttp::Handler,
    method: &str,
    target: &str,
    body: &str,
) -> (u16, serde_json::Value, String) {
    let mut w = jarvis_nethttp::W::recorder();
    let mut req = jarvis_nethttp::Req::new(method, target, body.as_bytes());
    h(&mut w, &mut req);
    let t = w.body_text();
    (w.status(), serde_json::from_str(&t).unwrap_or_default(), t)
}

#[test]
fn content_paths() {
    for ok in ["a.txt", "dir/b.json", "/x/y/", "数据.txt"] {
        content_path(ok).unwrap_or_else(|e| panic!("{ok}: {e:#}"));
    }
    for bad in [
        "", "../x", "a/../b", "a//b", "a\\b", "a/./b", "a\0b", "x\ny",
    ] {
        assert!(content_path(bad).is_err(), "{bad:?} accepted");
    }
    for bad in ["", "A", "-a", "a-", "a_b", "a/b", &"a".repeat(43)] {
        assert!(content_name(bad).is_err(), "name {bad:?} accepted");
    }
}

/// a GET a machine signs (no body), its answer whole: the headers too (sessionops_test.go's mxRaw)
fn mx_raw(
    m: &TestMachine,
    h: &jarvis_nethttp::Handler,
    method: &str,
    target: &str,
) -> jarvis_nethttp::W {
    let path = target.split_once('?').map_or(target, |(p, _)| p);
    let (ts, sig) = signed_headers(&m.key, method, path, b"", crate::util::unix_now());
    let mut req = jarvis_nethttp::Req::new(method, target, b"")
        .with_header("X-Machine", &m.id)
        .with_header("X-Time", &ts)
        .with_header("X-Sig", &sig);
    let mut w = jarvis_nethttp::W::recorder();
    h(&mut w, &mut req);
    w
}

#[test]
fn content_stores_app_and_session() {
    let rg = Rig::with(|c| c.no_access = true);
    invalidate_content();
    let h = rg.handler();
    // Deyao: create, upload (nested), list, download, delete
    let (code, out, _) = raw(&h, "POST", "/api/content", r#"{"name": "notes"}"#);
    assert!(code == 200 && out["ok"] == true, "create: {code} {out}");
    assert_eq!(
        raw(&h, "POST", "/api/content", r#"{"name": "notes"}"#).0,
        200,
        "create twice"
    );
    let _ = raw(&h, "POST", "/api/content", r#"{"name": "other"}"#);
    let (code, out, _) = raw(
        &h,
        "POST",
        "/api/content/notes/file?path=dir/a.txt",
        "hello",
    );
    assert!(code == 200 && out["size"] == 5, "upload: {code} {out}");
    let _ = raw(&h, "POST", "/api/content/notes/file?path=top.md", "# top");
    let (code, out, _) = raw(&h, "GET", "/api/content/notes/files", "");
    assert!(
        code == 200
            && out["files"].as_array().map_or(0, Vec::len) == 2
            && out["files"][0]["path"] == "dir/a.txt",
        "files: {code} {out}"
    );
    let (code, out, _) = raw(&h, "GET", "/api/content?fresh=1", "");
    assert!(
        code == 200
            && out["stores"].as_array().map_or(0, Vec::len) == 2
            && out["stores"][0]["files"] == 2
            && out["stores"][0]["bytes"] == 10,
        "stores: {code} {out}"
    );
    let (code, _, b) = raw(&h, "GET", "/api/content/notes/file?path=dir/a.txt", "");
    assert!(code == 200 && b == "hello", "download: {code} {b:?}");
    assert_eq!(
        raw(&h, "GET", "/api/content/notes/file?path=../x", "").0,
        400,
        "bad path"
    );
    // a session whose cert names "notes": reads and writes it, not "other"
    let cfg = jarvis_go::marshal(&SessionConfig {
        v: 1,
        content: vec!["notes".into()],
        ..Default::default()
    });
    let cert = rg.core.key.doc(&json!({"kind": "succession-cert", "machine": {"id": "mC"}, "options": {"harness": "claude", "config": cfg}}));
    rg.st.do_(|d| {
        d.sessions.insert(
            "sC".into(),
            Session {
                id: "sC".into(),
                state: "started".into(),
                machine_id: "mC".into(),
                harness: "claude".into(),
                ..Default::default()
            },
        );
        d.machines.insert("mC".into(), "sC".into());
        d.certs.insert("mC".into(), cert.clone());
    });
    let m = new_test_machine(&rg, "mC");
    let mh = rg.machine_handler();
    let (code, out) = m.do_(&mh, "GET", "/m/api/sessions/sC/content", "");
    assert!(
        code == 200
            && out["stores"].as_object().map_or(0, |o| o.len()) == 1
            && out["stores"]["notes"].as_array().map_or(0, Vec::len) == 2,
        "session listing: {code} {out}"
    );
    // the file comes with the core's attestation
    let w = mx_raw(
        &m,
        &mh,
        "GET",
        "/m/api/sessions/sC/content/notes/file?path=dir/a.txt",
    );
    let attest = w
        .headers
        .get("X-Jarvis2-Attest")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        w.status() == 200 && w.body_text() == "hello" && !attest.is_empty(),
        "session file: {} {:?}",
        w.status(),
        w.body_text()
    );
    let (code, out) = m.do_(
        &mh,
        "PUT",
        "/m/api/sessions/sC/content/notes/file?path=new/b.txt",
        "pushed",
    );
    assert!(code == 200 && out["size"] == 6, "session put: {code} {out}");
    assert_eq!(
        rg.dav
            .get(&format!("{CONTENT_ROOT}/notes/new/b.txt"))
            .as_deref(),
        Some(&b"pushed"[..]),
        "on the box"
    );
    assert_eq!(
        m.do_(
            &mh,
            "DELETE",
            "/m/api/sessions/sC/content/notes/file?path=new/b.txt",
            ""
        )
        .0,
        200,
        "session delete"
    );
    assert_eq!(
        m.do_(
            &mh,
            "PUT",
            "/m/api/sessions/sC/content/other/file?path=x",
            "no"
        )
        .0,
        403,
        "a store the cert doesn't name"
    );
    assert_eq!(
        m.do_(&mh, "GET", "/m/api/sessions/s1/content", "").0,
        403,
        "another session's path"
    );
    // New session: the content stores go into the signed config; an unknown one is refused
    let e = rg
        .create_session(crate::flows::NewSession {
            label: "x".into(),
            content: vec!["nope".into()],
            ..Default::default()
        })
        .err()
        .unwrap_or_else(|| panic!("an unknown content store was taken"));
    assert!(
        format!("{e:#}").contains("no content store"),
        "unknown store: {e:#}"
    );
    let s = Session {
        label: "x".into(),
        content: Some(vec!["notes".into()]),
        ..Default::default()
    };
    let c = rg.session_config(&s).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(c.contains(r#""content":["notes"]"#), "config: {c}");
    // delete a store
    assert_eq!(
        raw(&h, "DELETE", "/api/content/other", "").0,
        200,
        "delete store"
    );
    assert_eq!(
        raw(&h, "DELETE", "/api/content/other", "").0,
        200,
        "delete again"
    );
}

#[test]
fn parse_multistatus_hetzner() {
    // as the Storage Box (Apache mod_dav) answers, with lp1: prefixes and an absolute href
    let body = r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:ns0="DAV:">
<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/">
<D:href>/claude-records/.content/email/</D:href>
<D:propstat><D:prop><lp1:resourcetype><D:collection/></lp1:resourcetype><lp1:getlastmodified>Fri, 02 Oct 2026 06:07:22 GMT</lp1:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
</D:response>
<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/">
<D:href>/claude-records/.content/email/address%20one.txt</D:href>
<D:propstat><D:prop><lp1:resourcetype/><lp1:getcontentlength>38</lp1:getcontentlength><lp1:getlastmodified>Fri, 02 Oct 2026 06:07:22 GMT</lp1:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>
</D:response>
</D:multistatus>"#;
    let es =
        crate::storagebox::parse_multistatus(body.as_bytes()).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        es.len() == 2
            && es[0].dir
            && es[0].name == "email"
            && !es[1].dir
            && es[1].name == "address one.txt"
            && es[1].size == 38
            && es[1].modified == "2026-10-02T06:07:22Z",
        "{es:?}"
    );
}

fn unsign_snap(rg: &Rig, machine: &str) {
    let _ = rg.st.db().and_then(|db| db.conn().ok()).map(|mut c| {
        c.execute("UPDATE snapshots SET state = 'pending', sig = '', committed_at = NULL WHERE machine_id = $1", &[&machine])
    });
}

/// SIGTERM's drain (drain.rs): a pause in flight finishes (its machine's snapshot still lands), every new lifecycle
/// action is refused with 503 "router updating, try again shortly", reads are served, and the drain ends once the
/// pause is done
#[test]
fn drain_lets_in_flight_finish_and_refuses_new() {
    let rg = Rig::with(|c| {
        c.no_access = true;
        c.snapshot_stall = Duration::from_secs(30);
    });
    unsign_snap(&rg, "m1"); // m1 runs: it hasn't sent its final snapshot yet
    let cert = rg.cert.clone();
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.state = "started".into();
            s.machine_id = "m1".into();
            s.booted = "m1".into();
            s.cert = Some(cert.clone());
            s.live = Some(Liveness {
                last_report: GoTime::now(),
                ..Default::default()
            }); // reporting: the pause waits
        }
        d.sessions.insert(
            "s2".into(),
            Session {
                id: "s2".into(),
                state: "paused".into(),
                cert: Some(cert.clone()),
                ..Default::default()
            },
        );
        d.sessions.insert(
            "s3".into(),
            Session {
                id: "s3".into(),
                state: "started".into(),
                machine_id: "m3".into(),
                cert: Some(cert.clone()),
                ..Default::default()
            },
        );
        d.approvals.insert(
            "a1".into(),
            Approval {
                id: "a1".into(),
                kind: "new-session".into(),
                session: "s2".into(),
                created: GoTime::now().utc(),
                ..Default::default()
            },
        );
    });
    rg.pause("s1").unwrap_or_else(|e| panic!("{e:#}")); // waits for m1's snapshot
    std::thread::scope(|sc| {
        let drained = sc.spawn(|| rg.drain_now(Duration::from_secs(20)));
        wait_for("draining", || rg.draining());
        // new actions: refused, with the text the apps show as is
        for (name, err) in [
            ("pause", rg.pause("s3")),
            ("resume", rg.resume("s2", false)),
            ("destroy", rg.destroy("s3")),
        ] {
            let e = err
                .err()
                .unwrap_or_else(|| panic!("{name} during the drain went through"));
            assert!(
                e.downcast_ref::<crate::drain::Draining>().is_some()
                    && format!("{e}") == DRAINING_MSG,
                "{name}: {e:#}"
            );
        }
        let e = rg
            .respond("a1", "sig")
            .err()
            .unwrap_or_else(|| panic!("an approval answered during the drain"));
        assert!(
            e.downcast_ref::<crate::drain::Draining>().is_some(),
            "approval answer during the drain: {e:#}"
        );
        assert!(
            rg.st.do_(|d| d.approvals.contains_key("a1")),
            "the refused answer used up the approval"
        );
        for c in rg
            .core
            .calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            assert!(
                c != "/approve/by-phone" && c != "/succession",
                "the core was asked {c} during the drain"
            );
        }
        let (code, out) = call(&rg.handler(), "POST", "/api/sessions/s3/pause", "");
        assert!(
            code == 503 && out["error"] == DRAINING_MSG,
            "HTTP pause during the drain: {code} {out}"
        );
        // automatic callers (scheduler, tasks, watches) see a busy session and try again later
        assert!(
            crate::drain::is_busy(&crate::drain::Draining.into()),
            "Draining isn't busy"
        );
        assert_eq!(
            call(&rg.handler(), "GET", "/api/state", "").0,
            200,
            "GET /api/state during the drain"
        );
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            !drained.is_finished(),
            "the drain ended with the pause still waiting for its snapshot"
        );
        rg.snapshot_arrived("m1"); // the machine's report (/m/snapshot) during the drain
        assert!(drained.join().unwrap_or(false), "drain gave up");
    });
    rg.st.do_(|d| {
        assert_eq!(
            d.sessions["s1"].state, "paused",
            "the in-flight pause ended {} ({})",
            d.sessions["s1"].state, d.sessions["s1"].error
        );
        assert_eq!(
            d.sessions["s3"].state, "started",
            "the refused pause touched s3"
        );
    });
}

/// a job that chains actions (restart, upgrade) runs to its end through a drain that began between its steps, and the
/// drain waits for it; a drain past its limit reports so
#[test]
fn drain_waits_for_a_jobs_later_steps() {
    let t = crate::testutil::new_test_router();
    let end_job = t
        .begin_job("s1", "restart")
        .unwrap_or_else(|e| panic!("{e:#}"));
    std::thread::scope(|sc| {
        let drained = sc.spawn(|| t.drain_now(Duration::from_secs(5)));
        wait_for("draining", || t.draining());
        let step = t
            .begin("s1", "starting")
            .unwrap_or_else(|e| panic!("the job's own step was refused: {e:#}")); // the job's resume
        let e = t
            .begin("s2", "pausing")
            .err()
            .unwrap_or_else(|| panic!("another session's action began"));
        assert!(
            e.downcast_ref::<crate::drain::Draining>().is_some(),
            "{e:#}"
        );
        step.call();
        std::thread::sleep(Duration::from_millis(100));
        assert!(!drained.is_finished(), "drained with the job running");
        end_job.call();
        assert!(drained.join().unwrap_or(false), "drain gave up");
    });
    assert!(
        t.begin("s1", "starting")
            .err()
            .is_some_and(|e| e.downcast_ref::<crate::drain::Draining>().is_some()),
        "after the job"
    );
    let t2 = crate::testutil::new_test_router();
    let _done = t2
        .begin("s9", "pausing")
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        !t2.drain_now(Duration::from_millis(50)),
        "a drain past its limit reported success"
    );
}
