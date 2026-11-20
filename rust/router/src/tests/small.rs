//! The small Go test files: flows_r1, peer, healthz, setupservices, lockedstore, flows_legacy, termpage, grants,
//! setupdestroy, inbox_kinds, machinesig, machinetime

use crate::core::CoreError;
use crate::testutil::{
    Rig, TestKey, add_session, new_test_machine, new_test_router, new_test_router_with, rdo,
    wait_for,
};
use jarvis_go::GoTime;
use serde_json::json;

use std::sync::atomic::Ordering;

/// R1 audit: a harness (router policy) can't put the deploy-key token store into a session
#[test]
fn no_harness_brings_the_deploy_key_token() {
    let t = new_test_router();
    assert!(
        t.with_harness_stores(&["default".into()], &["github-deploy-keys".into()])
            .is_err(),
        "github-deploy-keys went to a session"
    );
    t.with_harness_stores(&["default".into()], &["tunnel".into()])
        .unwrap_or_else(|e| panic!("{e:#}"));
}

#[test]
fn is_grant_refusal() {
    for m in [
        "the machine refused or failed: no grant, and the holder isn't on this session's allow list",
        "the machine refused or failed: this session holds a sensitive store: only a phone grant opens a shell",
    ] {
        assert!(
            crate::peer::is_grant_refusal(Some(&anyhow::anyhow!("{m}"))),
            "{m} is a refusal"
        );
    }
    for m in [
        "no answer from the machine",
        "peer message not delivered: x",
    ] {
        assert!(
            !crate::peer::is_grant_refusal(Some(&anyhow::anyhow!("{m}"))),
            "{m} isn't"
        );
    }
}

/// /healthz refuses without the probe's Access service token (no audience configured = 503, never open)
#[test]
fn healthz_needs_its_access_app() {
    let t = new_test_router();
    let (code, _) = crate::testutil::call(&t.handler(), "GET", "/healthz", "");
    assert_eq!(code, 503, "no ACCESS_HEALTH_AUD");
}

/// GET /setup/services: a check on the watch runner; only for the setup key
#[test]
fn setup_services() {
    let _g = crate::testutil::serial();
    let old = *crate::watches::RUN_CHECK_HOOK
        .read()
        .unwrap_or_else(|e| e.into_inner());
    *crate::watches::RUN_CHECK_HOOK
        .write()
        .unwrap_or_else(|e| e.into_inner()) = |_| {
        Ok(crate::watches::CheckResult {
            exit: 0,
            stdout: "watch runner ok\n".into(),
            ..Default::default()
        })
    };
    let setup = TestKey::new();
    let pk = setup.public();
    let t = new_test_router_with(|c| c.setup_key = pk, None, Default::default());
    let h = t.handler();
    let (c, _) = rdo(&h, "GET", "/setup/services", None, None);
    assert_eq!(c, 401, "unsigned");
    let (c, out) = rdo(&h, "GET", "/setup/services", None, Some(&setup));
    *crate::watches::RUN_CHECK_HOOK
        .write()
        .unwrap_or_else(|e| e.into_inner()) = old;
    assert!(c == 200 && out.get("search").is_none(), "{c} {out}");
    let w = &out["watch"]["run"];
    assert!(
        w["exit"] == 0 && w["stdout"] == "watch runner ok",
        "watch: {w}"
    );
}

/// a machine waiting on a locked store: the session says which until a pull goes through
#[test]
fn locked_store_shown_until_the_pull_goes_through() {
    let rg = Rig::new();
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.state = "initialising".into();
            s.machine_id = "m1".into();
        }
        d.machines.insert("m1".into(), "s1".into());
    });
    let get = || rg.session("s1").locked_store;
    let locked = |s: &str| -> anyhow::Error {
        CoreError {
            status: 423,
            body: vec![],
            msg: format!("core: store {s} is locked"),
        }
        .into()
    };
    rg.note_secrets_pull("m1", Some(&locked("claude")));
    assert_eq!(get(), "claude");
    rg.note_secrets_pull(
        "m1",
        Some(&anyhow::anyhow!("core /pull-secrets: connection refused")),
    ); // another failure: kept
    assert_eq!(get(), "claude");
    rg.note_secrets_pull("m1", None);
    assert_eq!(get(), "");
    rg.note_secrets_pull("m2", Some(&locked("x"))); // not this session's machine
    assert_eq!(get(), "", "another machine's pull touched s1");
}

#[test]
fn legacy_login_images() {
    let order: Vec<String> = [
        "ghcr.io/de0ch/jarvis4-session:sha-f07bfc204790@sha256:085b",
        "ghcr.io/de0ch/jarvis4-session:sha-828a6521769c@sha256:449a",
        "ghcr.io/de0ch/jarvis4-session:sha-c5427052a542@sha256:b578",
        "ghcr.io/de0ch/jarvis4-session:sha-bc727daca489@sha256:56bb",
    ]
    .map(String::from)
    .to_vec();
    for (img, want) in [
        ("ghcr.io/de0ch/jarvis4-session@sha256:085b", true), // no tag, an early pin
        (
            "ghcr.io/de0ch/jarvis4-session:sha-828a6521769c@sha256:449a",
            true,
        ),
        (
            "ghcr.io/de0ch/jarvis4-session:sha-c5427052a542@sha256:b578",
            false,
        ),
        (
            "ghcr.io/de0ch/jarvis4-session:sha-bc727daca489@sha256:56bb",
            false,
        ),
        ("ghcr.io/de0ch/jarvis4-session@sha256:0000", true), // before the list began
        ("", false),
    ] {
        assert_eq!(crate::flows::legacy_login_image(img, &order), want, "{img}");
    }
    assert!(
        !crate::flows::legacy_login_image("x@sha256:085b", &order[..2])
            && !crate::flows::legacy_login_image("x@sha256:085b", &[]),
        "no marker in the order: never legacy"
    );
}

#[test]
fn pinned_images() {
    let order: Vec<String> = [
        "ghcr.io/de0ch/jarvis4-session:sha-f07bfc204790@sha256:085b",
        "ghcr.io/de0ch/jarvis4-session:sha-828a6521769c@sha256:449a",
    ]
    .map(String::from)
    .to_vec();
    let cur = "ghcr.io/de0ch/jarvis4-session:sha-c5427052a542@sha256:b578";
    for (img, want) in [
        (
            "ghcr.io/de0ch/jarvis4-session@sha256:449a",
            order[1].as_str(),
        ), // the machine's bare form: the signed pin
        ("ghcr.io/de0ch/jarvis4-session@sha256:b578", cur),
        (order[0].as_str(), order[0].as_str()),
        (
            "ghcr.io/de0ch/jarvis4-session@sha256:0000",
            "ghcr.io/de0ch/jarvis4-session@sha256:0000",
        ), // never pinned
        ("", ""),
    ] {
        assert_eq!(crate::flows::pinned_image(img, cur, &order), want, "{img}");
    }
}

/// GET /term/{id}: the terminal page the iPhone app shows in a web view — self-contained, no script from anywhere else
#[test]
fn term_page() {
    let t = new_test_router();
    let h = t.handler();
    let get = |path: &str| {
        let mut w = crate::nethttp::W::recorder();
        let mut req = crate::nethttp::Req::new("GET", path, b"");
        h(&mut w, &mut req);
        w
    };
    let w = get("/term/abc-123");
    assert_eq!(w.status(), 200);
    let hd = |k: &str| {
        w.headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    assert!(hd("Content-Type").starts_with("text/html"), "content type");
    for k in [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Cache-Control",
    ] {
        assert!(!hd(k).is_empty(), "no {k} header");
    }
    let page = w.body_text();
    for want in [
        "Terminal input",
        "Terminal status",
        "Allow terminal for 10 minutes",
        r#"const SID = "abc-123""#,
        "jarvis2Refresh",
    ] {
        assert!(page.contains(want), "page lacks {want}");
    }
    assert!(
        !page.contains("__SESSION_ID__"),
        "session id placeholder left in the page"
    );
    let src = regex::Regex::new(r"(?i)<script[^>]*\bsrc=").unwrap_or_else(|_| unreachable!());
    let link = regex::Regex::new(r"(?i)<link[^>]*\bhref=").unwrap_or_else(|_| unreachable!());
    assert!(
        !src.is_match(&page) && !link.is_match(&page),
        "the page loads something from elsewhere"
    );
    for bad in [
        "/term/a%22b",
        "/term/a.b",
        "/term/a%3Cscript%3E",
        &format!("/term/{}", "a".repeat(81)),
    ] {
        assert_eq!(get(bad).status(), 404, "{bad}");
    }
}

/// A grant the phone signs for a feature the machine turned away is used at the next tick: the back-off from the
/// refusal and the callout go (2026-10-11: the 10-minute back-off outlasted a 10-minute grant)
#[test]
fn add_grant_clears_the_refusal_backoff() {
    let t = new_test_router();
    let phone = TestKey::new();
    let cert = jarvis_go::marshal(&json!({"line": "LsA", "phone": phone.public()}));
    t.st.do_(|d| {
        d.sessions.insert(
            "sA".into(),
            crate::state::Session {
                id: "sA".into(),
                state: "started".into(),
                machine_id: "mA".into(),
                harness: "claude".into(),
                cert: Some(crate::core::Doc {
                    payload: cert.clone(),
                    sig: String::new(),
                }),
                live: Some(Default::default()),
                ..Default::default()
            },
        );
        d.machines.insert("mA".into(), "sA".into());
    });
    t.note_refusal(
        "sA",
        "archive",
        &anyhow::anyhow!("the machine refused or failed: no grant"),
    );
    let now = GoTime::now();
    let l =
        t.st.do_(|d| d.sessions["sA"].live.clone().unwrap_or_default());
    assert!(
        l.needs_grant == "archive" && !l.may_exec("archive", &now),
        "the refusal isn't recorded: {l:?}"
    );
    let pubk = t.holder_public_keys().unwrap_or_else(|e| panic!("{e:#}"));
    let text = jarvis_go::marshal(
        &json!({"kind": "grant", "holder": pubk["archive"], "session": "LsA", "scope": "shell",
        "issued": now.utc().rfc3339(), "expires": GoTime::from_unix(now.unix() + 600).utc().rfc3339()}),
    );
    let sig = phone.0.sign(text.as_bytes());
    t.add_grant("sA", Some(&crate::core::Doc { payload: text, sig }))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let l =
        t.st.do_(|d| d.sessions["sA"].live.clone().unwrap_or_default());
    assert!(
        l.needs_grant.is_empty() && l.may_exec("archive", &now),
        "the grant left the back-off in place: {l:?}"
    );
}

/// POST /setup/sessions/{id}/destroy: setup-signed, the app's destroy (archive, then the record); a failed archive
/// leaves the session paused unless force
#[test]
fn setup_destroy() {
    let setup = TestKey::new();
    let pk = setup.public();
    let rg = Rig::with(|c| {
        c.setup_key = pk;
        c.no_access = true;
    });
    let h = rg.handler();
    assert_eq!(
        rdo(
            &h,
            "POST",
            "/setup/sessions/s1/destroy",
            Some(&json!({})),
            None
        )
        .0,
        401,
        "unsigned"
    );
    let (code, out) = rdo(
        &h,
        "POST",
        "/setup/sessions/nope/destroy",
        Some(&json!({})),
        Some(&setup),
    );
    assert_eq!(code, 400, "no such session: {out}");
    // the archive fails (the Storage Box refuses): paused with the error, no record
    rg.dav
        .set_fail(&format!("{}/2026", crate::archivetar::ARCHIVES_ROOT));
    let (code, out) = rdo(
        &h,
        "POST",
        "/setup/sessions/s1/destroy",
        Some(&json!({})),
        Some(&setup),
    );
    assert!(code == 202 && out["ok"] == true, "{code} {out}");
    wait_for("paused with the archive error", || {
        let s = rg.session("s1");
        s.state == "paused" && !s.error.is_empty()
    });
    assert!(rg.record("s1").is_none(), "a record without force");
    // force in the signed body: destroyed anyway
    wait_for("the forced destroy", || {
        rdo(
            &h,
            "POST",
            "/setup/sessions/s1/destroy",
            Some(&json!({"force": true})),
            Some(&setup),
        )
        .0 == 202
    });
    wait_for("the record", || rg.record("s1").is_some());
    let rec = rg.record("s1").unwrap_or_default();
    assert!(
        rec.archive.is_none() && !rec.archive_error.is_empty(),
        "forced record {rec:?}"
    );
}

/// with the Storage Box answering, the setup destroy archives the session and leaves its record
#[test]
fn setup_destroy_archives() {
    let setup = TestKey::new();
    let pk = setup.public();
    let rg = Rig::with(|c| {
        c.setup_key = pk;
        c.no_access = true;
    });
    let (code, out) = rdo(
        &rg.handler(),
        "POST",
        "/setup/sessions/s1/destroy",
        None,
        Some(&setup),
    );
    assert_eq!(code, 202, "{out}");
    wait_for("the archived record", || {
        rg.record("s1").is_some_and(|r| r.archive.is_some())
    });
    rg.dav.archive(
        &rg.record("s1")
            .and_then(|r| r.archive)
            .map(|a| a.file)
            .unwrap_or_default(),
    ); // one .tar.gz that opens
}

/// The iPhone app and the web page each name every Inbox kind the router files (Deyao, 2026-10-21: an Inbox outcome
/// waiting as a "message" showed in an older app build as "New session"). Their fallback for an unknown kind says so.
#[test]
fn every_inbox_kind_is_known_to_the_apps() {
    use crate::inbox::*;
    let kinds = [
        REQUEST_KIND_REPO,
        REQUEST_KIND_GRANT,
        REQUEST_KIND_UNLOCK,
        crate::storerestore::REQUEST_KIND_RESTORE,
        crate::peermsg::REQUEST_KIND_PEER,
        crate::apicalls::REQUEST_KIND_CALL,
        crate::messages::REQUEST_KIND_MSG,
    ];
    let read = |p: &str| {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(p),
        )
        .unwrap_or_else(|e| panic!("{p}: {e}"))
    };
    let ios_title = read("ios/Jarvis4/Review/BatchReviewView.swift");
    let ios_pill = read("ios/Jarvis4/Inbox/InboxView.swift");
    let web_title = read("app/src/lib/inbox.ts");
    let web_pill = read("app/src/views/Inbox.tsx");
    for k in kinds {
        let q = regex::escape(k);
        let re = |p: String| regex::Regex::new(&p).unwrap_or_else(|_| unreachable!());
        assert!(
            re(format!(r#"case "{q}""#)).is_match(&ios_title),
            "{k}: iOS list title"
        );
        assert!(
            re(format!(r#""{q}": ""#)).is_match(&ios_pill),
            "{k}: iOS kind pill"
        );
        assert!(
            re(format!(r#"case "{q}""#)).is_match(&web_title),
            "{k}: web title"
        );
        assert!(
            re(format!(r#"(?:"{q}"|\b{q}): ""#)).is_match(&web_pill),
            "{k}: web kind pill"
        );
    }
    assert!(
        ios_title.contains(r#"default: return "Unknown request"#),
        "the iOS app's fallback must say so"
    );
    assert!(
        web_title.contains("return `Unknown request"),
        "the web page's fallback must say so"
    );
}

#[test]
fn machine_signature_for_another_service() {
    let t = new_test_router();
    add_session(&t, "sA", "started", "mA", false);
    t.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sA") {
            s.harness = "aviary".into();
        }
    });
    let m = new_test_machine(&t, "mA");
    let now = GoTime::now();
    let body = br#"{"session":"sA"}"#;
    let sign = |method: &str, path: &str, at: i64| {
        use sha2::Digest;
        let sum = hex::encode(sha2::Sha256::digest(body));
        let (ts, sig) = crate::testutil::signed_headers(&m.key, method, path, body, at);
        crate::machinesig::MachineSigRequest {
            machine: "mA".into(),
            method: method.into(),
            path: path.into(),
            time: ts,
            body_sha256: sum,
            sig,
        }
    };
    let o = t
        .check_machine_signature(&sign("POST", "/jarvis/boot", now.unix()), now)
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        o.session == "sA" && o.harness == "aviary" && o.state == "started",
        "{o:?}"
    );
    // the signed path is part of it: another path does not verify
    let mut bad = sign("POST", "/jarvis/boot", now.unix());
    bad.path = "/jarvis/other".into();
    assert!(
        t.check_machine_signature(&bad, now).is_err(),
        "a signature over another path verified"
    );
    // a body other than the signed one
    let mut bad = sign("POST", "/jarvis/boot", now.unix());
    bad.body_sha256 = hex::encode([0u8; 32]);
    assert!(
        t.check_machine_signature(&bad, now).is_err(),
        "a signature over another body verified"
    );
    // too old
    assert_eq!(
        t.check_machine_signature(&sign("POST", "/jarvis/boot", now.unix() - 180), now)
            .err()
            .as_deref(),
        Some("time too far off")
    );
    // a router path is never checked for someone else
    assert!(
        t.check_machine_signature(&sign("POST", "/m/status", now.unix()), now)
            .is_err(),
        "a signature for /m was checked"
    );
    // a machine the router does not know
    let mut unknown = sign("POST", "/jarvis/boot", now.unix());
    unknown.machine = "mZ".into();
    assert!(
        t.check_machine_signature(&unknown, now).is_err(),
        "an unknown machine verified"
    );
}

/// a body that takes d to arrive (a large upload over a slow link)
struct SlowBody {
    r: std::io::Cursor<Vec<u8>>,
    d: std::time::Duration,
}

impl std::io::Read for SlowBody {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        if !self.d.is_zero() {
            std::thread::sleep(self.d);
            self.d = std::time::Duration::ZERO;
        }
        self.r.read(b)
    }
}

/// the machine's X-Time is checked as the request arrives, not after its body (2026-10-21: a 20 MB live transcript
/// took over 2 min to arrive and every sync was refused "X-Time too far off")
#[test]
fn a_slow_body_is_not_refused_as_too_old() {
    let _g = crate::testutil::serial();
    let rg = Rig::new();
    rg.running_m2(false);
    let skew = crate::http::MACHINE_TIME_SKEW.swap(2, Ordering::SeqCst);
    let m = rg.machine("m2");
    let h = rg.machine_handler();
    let send = |at: i64, delay: std::time::Duration| {
        let body = r#"{"phase":"uploading","done":1,"total":2,"sent":1,"elapsedMs":1}"#;
        let (ts, sig) = crate::testutil::signed_headers(
            &m.key,
            "POST",
            "/m/snapshot-progress",
            body.as_bytes(),
            at,
        );
        let mut req = crate::nethttp::Req::new("POST", "/m/snapshot-progress", b"")
            .with_header("X-Machine", "m2")
            .with_header("X-Time", &ts)
            .with_header("X-Sig", &sig);
        req.body = Box::new(SlowBody {
            r: std::io::Cursor::new(body.as_bytes().to_vec()),
            d: delay,
        });
        let mut w = crate::nethttp::W::recorder();
        h(&mut w, &mut req);
        w.status()
    };
    let slow = send(crate::util::unix_now(), std::time::Duration::from_secs(4));
    let stale = send(crate::util::unix_now() - 10, std::time::Duration::ZERO);
    crate::http::MACHINE_TIME_SKEW.store(skew, Ordering::SeqCst);
    assert_eq!(slow, 200, "a slow body");
    assert_eq!(stale, 401, "a stale X-Time");
}

/// a role the serving roster lacks (the preloader's first release) neither hands over nor is waited for in a flip; with
/// no serving roster recorded every role moves (kernelflip.go TestServingRolesSkipsARoleTheServingCopyLacks)
#[test]
fn serving_roles_skips_a_role_the_serving_copy_lacks() {
    let members = ["notary", "spawner", "secrets"]
        .iter()
        .map(|r| jarvis_sig::Component::new(r).identity)
        .collect();
    let ro = jarvis_sig::Roster {
        copy: "blue".into(),
        members,
        ..Default::default()
    };
    let cur = crate::roster::RosterCurrent {
        copy: "blue".into(),
        payload: ro.payload().expect("payload"),
        sig: String::new(),
        at: GoTime::default(),
        results: Default::default(),
        stale: Default::default(),
    };
    let moves = crate::kernelflip::serving_roles(Some(&cur));
    assert!(moves("spawner") && moves("secrets") && !moves("preloader"));
    assert!(crate::kernelflip::serving_roles(None)("preloader"));
}

/// the golden volumes asked for: none without PRELOAD_SESSION_IMAGE; the router's region and 20 GB by default; the
/// configured regions and size otherwise (preload_test.go); the preloader's signed answer read
#[test]
fn preload_asks_for_a_golden_per_region() {
    use crate::preload::{golden_state, preload_config, preload_steps};
    let env = |m: Vec<(&'static str, &'static str)>| {
        move |k: &str| {
            m.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_string())
                .unwrap_or_default()
        }
    };
    assert!(preload_config(env(vec![]), "lhr").is_none());
    let img = "ghcr.io/de0ch/jarvis4-session@sha256:a1b2";
    let c = preload_config(env(vec![("PRELOAD_SESSION_IMAGE", img)]), "lhr").expect("config");
    assert_eq!(
        preload_steps(&c),
        vec![json!({"region": "lhr", "image": img, "diskGb": 20})]
    );
    let c = preload_config(
        env(vec![
            ("PRELOAD_SESSION_IMAGE", img),
            ("PRELOAD_REGIONS", "lhr, sin,"),
            ("PRELOAD_DISK_GB", "40"),
        ]),
        "lhr",
    )
    .expect("config");
    assert_eq!(
        preload_steps(&c),
        vec![
            json!({"region": "lhr", "image": img, "diskGb": 40}),
            json!({"region": "sin", "image": img, "diskGb": 40})
        ]
    );
    let d =
        json!({"payload": json!({"state": "ready", "volume": "vol_1"}).to_string(), "sig": "x"});
    assert_eq!(golden_state(d.to_string().as_bytes()), "ready vol_1");
    assert_eq!(golden_state(b"x"), "an answer that isn't the preloader's");
}

/// an aviary session that asks for no disk gets room for aviary's sandbox image; the others keep the default
#[test]
fn an_aviary_sessions_default_disk_holds_the_sandbox_image() {
    use crate::disk::{AVIARY_DISK, DEFAULT_DISK, default_disk_for};
    const { assert!(AVIARY_DISK >= 20) };
    assert_eq!(default_disk_for("aviary"), AVIARY_DISK);
    assert_eq!(default_disk_for("claude"), DEFAULT_DISK);
    assert_eq!(default_disk_for(""), DEFAULT_DISK);
}
