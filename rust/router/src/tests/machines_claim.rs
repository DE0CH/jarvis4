//! machines and claimdevice tests

use crate::budget::FlyGuest;
use crate::claimdevice::MasterCert;
use crate::core::Doc;
use crate::inbox::Origin;
use crate::machines::{FlyMachineDetail, LIST_FLY_MACHINES, ORPHAN_KILL};
use crate::state::{Approval, Started};
use crate::testutil::{
    TestKey, TestServer, add_session, call, new_test_router, new_test_router_with,
};
use jarvis_go::GoTime;
use serde_json::json;
use std::sync::{Arc, Mutex};

fn fly_m(id: &str, state: &str, created: &str, router_url: &str) -> FlyMachineDetail {
    let mut m = FlyMachineDetail {
        id: id.into(),
        state: state.into(),
        created_at: created.into(),
        region: "lhr".into(),
        ..Default::default()
    };
    m.config.image = "ghcr.io/de0ch/jarvis4-session@sha256:abc".into();
    m.config.guest = Some(FlyGuest {
        cpu_kind: "shared".into(),
        cpus: 4,
        memory_mb: 4096,
    });
    m.config.env.insert("JARVIS2_URL".into(), router_url.into());
    m
}

const PROD_URL: &str = "http://jarvis4-box._peer.internal:8081";

#[test]
fn machines_view() {
    let t = new_test_router();
    add_session(&t, "s1", "running", "m-cur", false);
    t.st.do_(|d| {
        d.machines.insert("m-old".into(), "s1".into()); // an earlier machine of s1 Fly still lists
    });
    let now = GoTime::parse("2026-10-11T12:00:00Z").unwrap_or_default();
    let (old, fresh) = (
        GoTime::from_unix(now.unix() - 7200).rfc3339(),
        GoTime::from_unix(now.unix() - 60).rfc3339(),
    );
    let vs = t.machines_view(
        &[
            fly_m("m-cur", "started", &old, PROD_URL),
            fly_m("m-old", "stopped", &old, PROD_URL),
            fly_m("m-orphan", "stopped", &old, PROD_URL),
            fly_m(
                "m-test",
                "started",
                &old,
                "http://e2e-peer-1._peer.internal:8081",
            ),
            fly_m("m-new", "started", &fresh, PROD_URL),
            fly_m("m-gone", "destroyed", &old, PROD_URL),
        ],
        now,
    );
    assert!(vs.len() == 5 && vs[0].id == "m-new", "list {vs:?}");
    let by = |id: &str| vs.iter().find(|v| v.id == id).cloned().unwrap_or_default();
    let v = by("m-cur");
    assert!(
        v.session_id == "s1"
            && v.current
            && !v.test
            && !v.no_destroy.is_empty()
            && v.size == "medium"
            && v.guest == "4×shared · 4 GB",
        "session machine {v:?}"
    );
    let v = by("m-old");
    assert!(
        v.session_id == "s1" && !v.current && !v.no_destroy.is_empty(),
        "earlier machine {v:?}"
    );
    let v = by("m-orphan");
    assert!(
        v.session_id.is_empty() && v.no_destroy.is_empty() && !v.test,
        "orphan {v:?}"
    );
    let v = by("m-test");
    assert!(v.test && v.no_destroy.is_empty(), "test machine {v:?}");
    assert!(
        !by("m-new").no_destroy.is_empty(),
        "a machine minutes old (a Start in flight) offered Destroy"
    );
}

static FLEET: Mutex<Vec<FlyMachineDetail>> = Mutex::new(vec![]);
static KILLED: Mutex<Vec<String>> = Mutex::new(vec![]);

#[test]
fn destroy_orphan_only_kills_machines_with_no_session() {
    let _g = crate::testutil::serial();
    let t = new_test_router();
    add_session(&t, "s1", "running", "m-cur", false);
    t.st.do_(|d| {
        d.started.insert("m-started".into(), Started::default());
    });
    let old = GoTime::from_unix(GoTime::now().unix() - 3600)
        .utc()
        .rfc3339();
    *FLEET.lock().unwrap_or_else(|e| e.into_inner()) = vec![
        fly_m("m-cur", "started", &old, PROD_URL),
        fly_m("m-started", "started", &old, PROD_URL),
        fly_m("m-orphan", "stopped", &old, PROD_URL),
        fly_m("m-new", "started", &GoTime::now().utc().rfc3339(), PROD_URL),
    ];
    KILLED.lock().unwrap_or_else(|e| e.into_inner()).clear();
    let (ol, ok) = (
        *LIST_FLY_MACHINES.read().unwrap_or_else(|e| e.into_inner()),
        *ORPHAN_KILL.read().unwrap_or_else(|e| e.into_inner()),
    );
    *LIST_FLY_MACHINES.write().unwrap_or_else(|e| e.into_inner()) =
        || Ok(FLEET.lock().unwrap_or_else(|e| e.into_inner()).clone());
    *ORPHAN_KILL.write().unwrap_or_else(|e| e.into_inner()) = |_, id| {
        KILLED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(id.into());
        Ok(())
    };
    let killed = || KILLED.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for id in ["m-cur", "m-new"] {
            let e = t
                .destroy_orphan(id)
                .err()
                .unwrap_or_else(|| panic!("{id} destroyed"));
            assert!(crate::drain::is_busy(&e), "{id}: {e:#}");
        }
        assert!(
            t.destroy_orphan("m-nope").is_err(),
            "destroyed a machine Fly doesn't list"
        );
        assert!(killed().is_empty(), "killed {:?}", killed());
        assert!(
            t.destroy_orphan("m-orphan").is_ok() && killed() == ["m-orphan"],
            "orphan {:?}",
            killed()
        );
        // one the router started that no session names (Started and Machines are set together at a start, so this is
        // a destroyed session's machine left behind): an orphan too
        assert!(
            t.destroy_orphan("m-started").is_ok() && killed().len() == 2,
            "left behind {:?}",
            killed()
        );
    }));
    *LIST_FLY_MACHINES.write().unwrap_or_else(|e| e.into_inner()) = ol;
    *ORPHAN_KILL.write().unwrap_or_else(|e| e.into_inner()) = ok;
    if let Err(p) = res {
        std::panic::resume_unwind(p);
    }
}

#[test]
fn the_claims_device_signature_is_kept_for_the_setup_session() {
    let t = new_test_router();
    t.keep_claim_device(
        br#"{"statement":"{\"kind\":\"claim\"}","masterSig":"m","deviceKey":"k","deviceSig":"s"}"#,
    );
    t.keep_claim_device(br#"{"statement":"x"}"#); // no countersignature: nothing kept
    let got = t.claim_devices();
    assert!(
        got.len() == 1 && got[0].device_key == "k" && got[0].statement == r#"{"kind":"claim"}"#,
        "{got:?}"
    );
}

/// R1 audit: an approval for a CI build this router was given carries CI's signature; one for any other image none
#[test]
fn only_ci_builds_carry_their_signature() {
    let ch = |img: &str| Doc {
        payload: format!(r#"{{"kind":"challenge","request":{{"image":"{img}"}}}}"#),
        sig: String::new(),
    };
    let approve = |r: &Arc<crate::router::Router>, img: &str| {
        let id = r.add_approval(Approval {
            challenge: Some(ch(img)),
            origin: Some(Origin::default()),
            ..Default::default()
        });
        r.st.do_(|d| {
            d.approvals
                .get(&id)
                .map(|a| a.image_sig.clone())
                .unwrap_or_default()
        })
    };
    let t = new_test_router_with(
        |c| {
            c.session_image = "ghcr.io/de0ch/jarvis4-session:sha-1@sha256:aa".into();
            c.session_image_sig = "c2ln".into();
        },
        None,
        Default::default(),
    );
    assert_eq!(
        approve(&t, "ghcr.io/de0ch/jarvis4-session:sha-1@sha256:aa"),
        "c2ln"
    );
    assert_eq!(approve(&t, "ghcr.io/de0ch/jarvis4-session:x@sha256:bb"), "");
    // a newer image is pinned: a resume on the old image gets the old signature from the list (the file images.yml keeps)
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let f = dir.path().join("sigs.txt");
    let _ = std::fs::write(&f, "ghcr.io/de0ch/jarvis4-session:sha-1@sha256:aa c2ln\n");
    let sigs = crate::flows::load_image_sigs(&f.display().to_string());
    let t2 = new_test_router_with(
        |c| {
            c.session_image = "ghcr.io/de0ch/jarvis4-session:sha-2@sha256:cc".into();
            c.session_image_sig = "bmV3".into();
            c.image_sigs = sigs;
        },
        None,
        Default::default(),
    );
    assert_eq!(
        approve(&t2, "ghcr.io/de0ch/jarvis4-session:sha-1@sha256:aa"),
        "c2ln"
    );
    assert_eq!(
        approve(&t2, "ghcr.io/de0ch/jarvis4-session:sha-2@sha256:cc"),
        "bmV3"
    );
    assert_eq!(
        approve(&t2, "ghcr.io/de0ch/jarvis4-session:x@sha256:bb"),
        ""
    );
}

/// R2: the master's signature on the core is kept by the router from the claim the core accepted, and served for the
/// running core only; a core claimed before (no kept claim) is asked for its own
#[test]
fn the_router_keeps_the_claim_for_the_running_core() {
    let status = Arc::new(std::sync::atomic::AtomicU16::new(200));
    let ck = Arc::new(TestKey::new());
    let (s2, k2) = (status.clone(), ck.clone());
    let core = TestServer::handler(move |w, req| match req.path.as_str() {
        "/identity" => crate::nethttp::write_json(
            w,
            200,
            &json!({"signingKey": k2.public(), "agreementKey": "a"}),
        ),
        "/claim" => crate::nethttp::write_json(
            w,
            s2.load(std::sync::atomic::Ordering::SeqCst),
            &json!({"payload": "{}", "sig": "x"}),
        ),
        _ => crate::nethttp::write_json(w, 404, &json!({"error": "no such route"})),
    });
    let t = new_test_router_with(|_| {}, Some(&core.url), Default::default());
    assert!(t.core_cert().is_none(), "a cert before any claim");
    let stmt =
        |key: &str| jarvis_go::marshal(&json!({"kind": "claim", "core": {"signingKey": key}}));
    let body = |key: &str| jarvis_go::marshal(&json!({"statement": stmt(key), "masterSig": "ms"}));
    let h = t.handler();
    status.store(403, std::sync::atomic::Ordering::SeqCst);
    let _ = call(&h, "POST", "/api/core/claim", &body(&ck.public()));
    assert!(t.core_cert().is_none(), "kept a claim the core refused");
    status.store(200, std::sync::atomic::Ordering::SeqCst);
    let _ = call(&h, "POST", "/api/core/claim", &body("another-core"));
    let _ = call(&h, "POST", "/api/core/claim", &body(&ck.public()));
    let mc: MasterCert =
        serde_json::from_slice(&t.core_cert().unwrap_or_default()).unwrap_or_default();
    assert!(
        mc.statement == stmt(&ck.public()) && mc.master_sig == "ms",
        "{mc:?}"
    );
}
