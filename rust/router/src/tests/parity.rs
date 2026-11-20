//! router/parity_test.go: the core-not-running answer, the app's search forwarding, the Claude app's title, live
//! transcript sync, and one-shot destroys. (TestLiveTranscriptSync's LIVE_SYNC_SECONDS env check is left out: tests
//! can't set the env.)
use crate::archive::RepoChange;
use crate::archivetar::ARCHIVES_ROOT;
use crate::livearchive::LiveCopy;
use crate::nethttp::{Handler, Req, W};
use crate::oneshot::one_shot_lost_dm;
use crate::searchsvc::ICLOUD_INDEX_BASE;
use crate::testutil::*;
use crate::titles::session_title;
use crate::types::ArchiveInfo;
use serde_json::{Map, Value, json};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

const RIG_ARCHIVE_DAY: &str = "2026-10-01 Fix the router.tar.gz";

#[test]
fn relay_core_not_running() {
    let t = new_test_router();
    t.r.core.set_url("http://127.0.0.1:1");
    let (code, out) = app_do(&t.r, "GET", "/api/core/identity", "", &[]);
    assert!(
        code == 503 && out["error"] == "the core isn't running" && out["coreDown"] == true,
        "{code} {out}"
    );
}

#[derive(Clone, Debug, Default)]
struct Hit {
    method: String,
    uri: String,
    body: String,
    cf_id: String,
}

#[test]
fn app_search_forwards_to_services() {
    let _g = serial(); // ICLOUD_INDEX_BASE
    let t = new_test_router();
    let r = t.r.clone();
    let got: Arc<Mutex<Vec<Hit>>> = Arc::default();
    let g2 = got.clone();
    let icloud = TestServer::handler(move |w, req| {
        let b = String::from_utf8_lossy(&req.read_body(1 << 20)).into_owned();
        let uri = if req.raw_query.is_empty() {
            req.path.clone()
        } else {
            format!("{}?{}", req.path, req.raw_query)
        };
        g2.lock().unwrap_or_else(|e| e.into_inner()).push(Hit {
            method: req.method.clone(),
            uri,
            body: b,
            cf_id: req.header("CF-Access-Client-Id"),
        });
        w.set_header("Content-Type", "application/json");
        w.write_header(202);
        w.write_str(r#"{"hits":[]}"#);
    });
    let saved = std::mem::replace(
        &mut *ICLOUD_INDEX_BASE.write().unwrap_or_else(|e| e.into_inner()),
        format!("{}/", icloud.url),
    );
    struct Restore(String);
    impl Drop for Restore {
        fn drop(&mut self) {
            *ICLOUD_INDEX_BASE.write().unwrap_or_else(|e| e.into_inner()) =
                std::mem::take(&mut self.0);
        }
    }
    let _restore = Restore(saved);
    for (method, target, body, uri) in [
        (
            "GET",
            "/api/icloud/search?q=passport",
            "",
            "/search?q=passport",
        ),
        (
            "GET",
            "/api/icloud/file?path=Documents%2Fa.pdf",
            "",
            "/file?path=Documents%2Fa.pdf",
        ),
        ("GET", "/api/icloud/status", "", "/status"),
        ("POST", "/api/icloud/relist", "{}", "/relist"),
        ("POST", "/api/icloud/retry", "", "/retry"),
    ] {
        let (code, _) = app_do(&r, method, target, body, &[]);
        assert_eq!(code, 202, "{method} {target}");
        let g = got
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last()
            .cloned()
            .unwrap_or_default();
        assert!(
            g.method == method && g.uri == uri && g.body == body && g.cf_id.is_empty(),
            "{method} {target} forwarded as {g:?}"
        );
    }
    // a service that is down: 502 in words
    drop(icloud);
    let (code, out) = app_do(&r, "GET", "/api/icloud/search?q=x", "", &[]);
    assert!(
        code == 502
            && out["error"]
                .as_str()
                .is_some_and(|e| e.contains("the iCloud index unreachable")),
        "{code} {out}"
    );
}

#[test]
fn app_title_from_status_report() {
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sA", "started", "mA", false);
    let m = new_test_machine(&r, "mA");
    let raw = "{\"pid\":1,\"sessionId\":\"c1\",\"name\":\"x\",\"nameSource\":\"derived\",\"status\":\"idle\",\"bridgeSessionId\":\"session_abc\",\"startedAt\":1}\n__TITLES__\n{\"type\":\"ai-title\",\"aiTitle\":\"AI title\",\"sessionId\":\"c1\"}\n__BG__\n__ONESHOT__\n__AUTH__\n__CREDS__\n__REFUSAL__\n";
    let (code, out) = m.do_(
        &t.machine_handler(),
        "POST",
        "/m/status",
        &jarvis_go::marshal(&json!({"raw": raw, "appTitle": "  Renamed\nin   the app "})),
    );
    assert_eq!(code, 200, "{out}");
    let s =
        r.st.read(|d| d.sessions.get("sA").cloned().unwrap_or_default());
    assert!(
        s.app_title == "Renamed in the app" && session_title(&s) == "Renamed in the app",
        "app title {:?}, title {:?}",
        s.app_title,
        session_title(&s)
    );
    // the label gave way; the view carries Jarvis 1's serverTitle
    r.core.set_url("http://127.0.0.1:1");
    let (_, st) = app_do(&r, "GET", "/api/state", "", &[]);
    let v = &st["sessions"][0];
    assert!(
        v["serverTitle"] == "Renamed in the app"
            && v["title"] == "Renamed in the app"
            && v["aiTitle"] == "AI title",
        "view {v}"
    );
    // a report without a title keeps the last one (the machine sends "" when the API can't be read)
    m.do_(
        &t.machine_handler(),
        "POST",
        "/m/status",
        &jarvis_go::marshal(&json!({"raw": raw})),
    );
    let mut s =
        r.st.read(|d| d.sessions.get("sA").cloned().unwrap_or_default());
    assert_eq!(
        s.app_title, "Renamed in the app",
        "an empty report dropped the title"
    );
    // a resume names the new Remote Control entry with it, unless a label is pinned
    s.label = String::new();
    assert_eq!(
        r.machine_env(&s)
            .get("SESSION_RESUME_TITLE")
            .map(String::as_str),
        Some("Renamed in the app"),
        "no SESSION_RESUME_TITLE"
    );
    s.label = "pinned".into();
    assert!(
        !r.machine_env(&s).contains_key("SESSION_RESUME_TITLE"),
        "SESSION_RESUME_TITLE with a pinned label"
    );
}

/// a signed POST with an X-Name header (Go's doReq)
fn put_named(h: &Handler, m: &TestMachine, name: &str, body: &str) -> (u16, Value) {
    let (ts, sig) = signed_headers(
        &m.key,
        "POST",
        "/m/live-transcript",
        body.as_bytes(),
        crate::util::unix_now(),
    );
    let mut req = Req::new("POST", "/m/live-transcript", body.as_bytes())
        .with_header("X-Name", name)
        .with_header("X-Machine", &m.id)
        .with_header("X-Time", &ts)
        .with_header("X-Sig", &sig);
    let mut w = W::recorder();
    h(&mut w, &mut req);
    (
        w.status(),
        serde_json::from_str(&w.body_text()).unwrap_or_default(),
    )
}

fn dav_text(rg: &Rig, p: &str) -> String {
    String::from_utf8_lossy(&rg.dav.get(p).unwrap_or_default()).into_owned()
}

#[test]
fn live_transcript_sync() {
    let rg = Rig::new();
    let r = rg.t.r.clone();
    add_session(&r, "s2", "started", "m2", false);
    let m = new_test_machine(&r, "m2");
    let other = new_test_machine(&r, "m9"); // a machine with no running session
    let h = rg.machine_handler();
    let name = "0b6a2f3e-1111-4222-8333-444455556666.jsonl";
    let (code, out) = put_named(&h, &m, name, "{\"type\":\"user\"}\n");
    assert!(code == 200 && out["stored"] == true, "{code} {out}");
    assert_eq!(
        dav_text(&rg, &format!(".live/s2/{name}")),
        "",
        "written outside claude-records"
    );
    assert_eq!(
        dav_text(&rg, &format!("claude-records/.live/s2/{name}")),
        "{\"type\":\"user\"}\n",
        "on the box"
    );
    // a newer copy replaces it
    put_named(&h, &m, name, "a\nb\n");
    assert_eq!(
        dav_text(&rg, &format!("claude-records/.live/s2/{name}")),
        "a\nb\n",
        "replaced"
    );
    let ls =
        r.st.read(|d| d.sessions.get("s2").and_then(|s| s.live_sync.clone()));
    assert!(
        ls.as_ref()
            .is_some_and(|l| l.stored && l.files.as_ref().and_then(|f| f.get(name)) == Some(&4)),
        "liveSync {ls:?}"
    );
    for bad in ["../x.jsonl", "a/b.jsonl", "x.txt", ".hidden.jsonl"] {
        assert_eq!(put_named(&h, &m, bad, "x").0, 400, "name {bad:?}");
    }
    assert_eq!(
        put_named(&h, &other, name, "x").0,
        403,
        "a machine with no session"
    );
    // records off (the e2e test): received, not written
    r.records_off.store(true, Ordering::Relaxed);
    let (code, out) = put_named(&h, &m, "c.jsonl", "x");
    assert!(code == 200 && out["stored"] == false, "{code} {out}");
    r.records_off.store(false, Ordering::Relaxed);
    // destroy: the copies the archive holds go (livearchive.rs), and only those
    let kept = r.clear_archived_live("s2", None, None);
    assert!(
        !kept.is_empty() && !rg.dav.under("claude-records/.live/s2").is_empty(),
        "live copies with no archive deleted: {kept:?}"
    );
    let listed = rg
        .box_()
        .and_then(|b| b.list("claude-records/.live/s2").ok().flatten())
        .unwrap_or_default();
    let held = ArchiveInfo {
        live: listed
            .iter()
            .map(|(n, size)| LiveCopy {
                name: n.clone(),
                size: *size,
                in_: format!("transcript-{n}"),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let kept = r.clear_archived_live("s2", Some(&held), None);
    assert!(
        kept.is_empty() && rg.dav.under("claude-records/.live/s2").is_empty(),
        "archived live copies kept: {kept:?} {:?}",
        rg.dav.under("claude-records/.live/s2")
    );
}

#[test]
fn one_shot_destroy_dms_lost_work() {
    let rg = Rig::new(); // s1 paused; its snapshot recorded "proj 2 1" and "other 0 -1"
    let dms = capture_dm(&rg);
    rg.finish_one_shot("s1").unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("DM", || {
        !dms.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
    });
    let dm = dms.lock().unwrap_or_else(|e| e.into_inner())[0].clone();
    for want in [
        "one-shot session “Fix the: router”",
        "proj: 2 uncommitted file(s), 1 unpushed commit(s)",
        "other: branch has no upstream",
        &format!("{ARCHIVES_ROOT}/{RIG_ARCHIVE_DAY}"),
    ] {
        assert!(dm.contains(want), "DM lacks {want:?}:\n{dm}");
    }
    assert!(
        rg.record("s1").is_some_and(|x| x.archive.is_some()),
        "not archived"
    );
}

#[test]
fn one_shot_forced_when_archive_fails() {
    let rg = Rig::new();
    rg.dav.set_fail(&format!("{ARCHIVES_ROOT}/2026"));
    let dms = capture_dm(&rg);
    let _ = rg.finish_one_shot("s1");
    wait_for("DM", || {
        !dms.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
    });
    let dm = dms.lock().unwrap_or_else(|e| e.into_inner())[0].clone();
    assert!(
        dm.contains("the archive to the Storage Box failed"),
        "DM {dm}"
    );
    wait_for("the record", || rg.record("s1").is_some());
    let rec = rg.record("s1");
    assert!(
        rec.as_ref().is_some_and(|x| !x.archive_error.is_empty()),
        "a one-shot must be destroyed even when its archive fails: {rec:?}"
    );
}

#[test]
fn one_shot_lost_dm_nothing_lost() {
    let mut changes = Map::new();
    changes.insert("checked".into(), json!(true));
    changes.insert(
        "repos".into(),
        json!([RepoChange {
            name: "a".into(),
            uncommitted: 0,
            unpushed: 0
        }]),
    );
    let s = one_shot_lost_dm(
        "x",
        &changes,
        Some(&ArchiveInfo {
            file: "d".into(),
            ..Default::default()
        }),
        None,
    );
    assert!(s.is_empty(), "DM when nothing was lost: {s}");
    let mut changes = Map::new();
    changes.insert("checked".into(), json!(false));
    changes.insert("reason".into(), json!("no snapshot"));
    let s = one_shot_lost_dm("x", &changes, None, None);
    assert!(
        s.contains("could not check the repos for unsaved work (no snapshot)"),
        "{s}"
    );
}
