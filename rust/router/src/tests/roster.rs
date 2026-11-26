//! roster_test.go: the root key's roster through the router, on the whole kernel in-process
use crate::kernel::{KernelClient, is_no_roster};
use crate::roster::{KERNEL_ROLES, roster_targets};
use crate::testutil::*;
use jarvis_kernel::kerneltest::Kernel;
use jarvis_nethttp::write_json;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// a router (Access off, a setup key) on the real kernel, every Deployment of it at the kernel's front (copy blue
/// serving; green idle until a test releases onto it)
struct RosterRig {
    k: Kernel,
    t: TestRouter,
    h: crate::http::AppFn,
    setup: TestKey,
    _serial: std::sync::MutexGuard<'static, ()>,
}

fn roster_rig() -> RosterRig {
    let serial = serial();
    let setup = TestKey::new();
    let k = Kernel::start(BTreeMap::from([(
        "JARVIS2_URL".to_string(),
        "http://router".to_string(),
    )]));
    let (front, sk) = (k.front.clone(), setup.public());
    let t = new_test_router_with(
        move |c| {
            c.no_access = true;
            c.setup_key = sk;
            c.kernel_url = format!("{front}/%s");
        },
        None,
        Default::default(),
    );
    t.r.wire_kernel();
    crate::roster::ROSTER_DMED.store(false, Ordering::SeqCst);
    let h = t.r.handler();
    RosterRig {
        k,
        t,
        h,
        setup,
        _serial: serial,
    }
}

/// a copy's roster as the setup session files it (the kernel's: the components' identities, the retired keys)
fn roster_of(k: &Kernel, copy: &str) -> String {
    k.roster_for(copy)
        .unwrap_or_else(|e| panic!("{e:#}"))
        .payload
}

fn state_of(out: &Value) -> String {
    out["roster"]["state"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// the roster's way: the app registers its root key, the setup session reads it and files the components' identities,
/// the app fetches the filing and signs it with the root key, the router posts it to every component and keeps it
#[test]
fn roster_flow() {
    let mut rr = roster_rig();
    let h = rr.h.clone();
    let (c, out) = rdo(&h, "GET", "/api/kernel", None, None);
    assert!(c == 200 && state_of(&out) == "none", "before: {c} {out}");
    let (c, _) = rdo(
        &h,
        "POST",
        "/api/kernel/root-key",
        Some(&json!({"rootKey": "AAAA"})),
        None,
    );
    assert_eq!(c, 400, "a bad root key");
    assert_eq!(
        rdo(&h, "GET", "/setup/kernel/root-key", None, Some(&rr.setup)).0,
        404,
        "no root key yet"
    );
    let root = rr.k.root.public_key();
    assert_eq!(
        rdo(
            &h,
            "POST",
            "/api/kernel/root-key",
            Some(&json!({"rootKey": root})),
            None
        )
        .0,
        200,
        "root key"
    );
    assert_eq!(
        rdo(&h, "GET", "/setup/kernel/root-key", None, None).0,
        401,
        "unsigned setup call"
    );
    // (the test's setup key signs deterministically: the same call in the same second would be a replay)
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let (c, out) = rdo(&h, "GET", "/setup/kernel/root-key", None, Some(&rr.setup));
    assert!(
        c == 200 && out["rootKey"] == root.as_str(),
        "setup root key: {c} {out}"
    );

    let payload = roster_of(&rr.k, "blue");
    let ss = rr.setup.0.sign(payload.as_bytes());
    let bad = TestKey::new().0.sign(payload.as_bytes());
    let (c, _) = rdo(
        &h,
        "POST",
        "/setup/kernel/roster",
        Some(&json!({"copy": "blue", "payload": payload, "setupSig": bad})),
        Some(&rr.setup),
    );
    assert_eq!(c, 403, "a roster signed by another key");
    let spaced = payload.replacen(r#","copy""#, r#", "copy""#, 1);
    let (c, _) = rdo(
        &h,
        "POST",
        "/setup/kernel/roster",
        Some(&json!({"copy": "blue", "payload": spaced, "setupSig": ss})),
        Some(&rr.setup),
    );
    assert_eq!(c, 400, "a payload not in Roster::payload's form");
    let (c, out) = rdo(
        &h,
        "POST",
        "/setup/kernel/roster",
        Some(&json!({"copy": "blue", "payload": payload, "setupSig": ss})),
        Some(&rr.setup),
    );
    assert_eq!(c, 200, "filing: {out}");
    assert_eq!(
        state_of(&rdo(&h, "GET", "/api/kernel", None, None).1),
        "pending",
        "after the filing"
    );
    let (c, out) = rdo(&h, "GET", "/api/kernel/roster/pending", None, None);
    assert!(
        c == 200
            && out["payload"] == payload.as_str()
            && out["setupSig"] == ss.as_str()
            && out["copy"] == "blue",
        "pending: {c} {out}"
    );

    // a signature by another key is refused before anything is posted
    assert_eq!(
        rdo(
            &h,
            "POST",
            "/api/kernel/roster",
            Some(&json!({"payload": payload, "rootSig": bad})),
            None
        )
        .0,
        403,
        "not the root key"
    );
    let rs = rr.k.root.sign(payload.as_bytes());
    let (c, out) = rdo(
        &h,
        "POST",
        "/api/kernel/roster",
        Some(&json!({"payload": payload, "rootSig": rs})),
        None,
    );
    assert_eq!(c, 200, "roster: {out}");
    let res = out["results"].as_object().cloned().unwrap_or_default();
    for dep in roster_targets("blue") {
        assert_eq!(
            res.get(&dep).and_then(Value::as_str),
            Some("taken"),
            "{dep}: {res:?}"
        );
    }
    assert_eq!(
        res.len(),
        KERNEL_ROLES.len(),
        "the roster went beyond its copy: {res:?}"
    );
    let (c, out) = rdo(&h, "GET", "/api/kernel/roster", None, None);
    assert!(
        c == 200 && out["payload"] == payload.as_str() && out["sig"] == rs.as_str(),
        "current: {c} {out}"
    );
    assert_eq!(
        state_of(&rdo(&h, "GET", "/api/kernel", None, None).1),
        "current",
        "after the roster"
    );
    assert_eq!(
        rdo(&h, "GET", "/api/kernel/roster/pending", None, None).0,
        404,
        "the filing stays after it was signed"
    );

    // a component restarts: new keys, no roster; the router posts the roster again, the component refuses it, and the
    // roster is stale until a new one is signed (one DM)
    let dms = Arc::new(AtomicI32::new(0));
    let d2 = dms.clone();
    *crate::discord::DM_HOOK
        .write()
        .unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(move |_: &str| {
        d2.fetch_add(1, Ordering::SeqCst);
    }));
    rr.k.restart("mover");
    rr.t.r.roster_check();
    rr.t.r.roster_check();
    let (_, out) = rdo(&h, "GET", "/api/kernel", None, None);
    let stale: Vec<String> = out["roster"]["stale"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| x.as_str().map(String::from))
        .collect();
    assert!(
        state_of(&out) == "stale"
            && stale.len() == 1
            && stale[0].starts_with("roster stale: component mover-blue restarted"),
        "after mover's restart: {}",
        out["roster"]
    );
    assert_eq!(dms.load(Ordering::SeqCst), 1, "DMs");
    *crate::discord::DM_HOOK
        .write()
        .unwrap_or_else(|e| e.into_inner()) = None;

    // the setup session files a new roster (the old mover's keys retired) and the app signs it: current again, mover
    // holds it
    let payload2 = roster_of(&rr.k, "blue");
    assert!(
        payload2.contains(r#""retired":[{"role":"mover""#),
        "the restarted mover's old keys aren't retired: {payload2}"
    );
    let ss2 = rr.setup.0.sign(payload2.as_bytes());
    let (c, _) = rdo(
        &h,
        "POST",
        "/setup/kernel/roster",
        Some(&json!({"copy": "blue", "payload": payload2, "setupSig": ss2})),
        Some(&rr.setup),
    );
    assert_eq!(c, 200, "second filing");
    let rs2 = rr.k.root.sign(payload2.as_bytes());
    let (c, out) = rdo(
        &h,
        "POST",
        "/api/kernel/roster",
        Some(&json!({"payload": payload2, "rootSig": rs2})),
        None,
    );
    assert!(
        c == 200 && out["results"]["mover-blue"] == "taken",
        "second roster: {c} {out}"
    );
    assert_eq!(
        state_of(&rdo(&h, "GET", "/api/kernel", None, None).1),
        "current",
        "after the new roster"
    );
    let (c, out) = rdo(&h, "GET", "/setup/kernel/roster", None, Some(&rr.setup));
    assert!(
        c == 200 && out["serving"] == "blue" && !out["current"].is_null(),
        "setup roster: {c} {out}"
    );
}

/// a component that answers it has no roster gets the current one posted, and the call is made again
#[test]
fn kernel_call_reposts_the_roster() {
    let held = Arc::new(AtomicBool::new(false));
    let posts = Arc::new(AtomicI32::new(0));
    let (h2, p2) = (held.clone(), posts.clone());
    let srv = TestServer::handler(move |w, req| {
        if req.path.ends_with("/roster") {
            p2.fetch_add(1, Ordering::SeqCst);
            h2.store(true, Ordering::SeqCst);
            write_json(w, 200, &json!({"kind": "roster-taken"}));
        } else if !h2.load(Ordering::SeqCst) {
            write_json(
                w,
                503,
                &json!({"kind": "error", "error": jarvis_sig::IdentityError::NoRoster.to_string()}),
            );
        } else {
            write_json(w, 200, &json!({"ok": "yes"}));
        }
    });
    let k = KernelClient::new(&format!("{}/%s", srv.url)).unwrap_or_else(|| panic!("no client"));
    let e = k
        .call("mover", "POST", "/move", Some(&json!({})))
        .err()
        .unwrap_or_else(|| panic!("no error"));
    assert!(is_no_roster(&e), "no roster to post yet: {e:#}");
    *k.roster.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(|| {
        Some(jarvis_sig::Doc {
            payload: "{}".into(),
            sig: "x".into(),
        })
    }));
    let b = k
        .call("mover", "POST", "/move", Some(&json!({})))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        String::from_utf8_lossy(&b).contains("yes") && posts.load(Ordering::SeqCst) == 1,
        "after the re-post: posts={}",
        posts.load(Ordering::SeqCst)
    );

    // a component that refuses it (restarted: new keys) makes the roster stale, and the call fails saying so
    let refuse = TestServer::handler(|w, req| {
        if req.path.ends_with("/roster") {
            return write_json(
                w,
                403,
                &json!({"error": "the roster doesn't name this notary's keys"}),
            );
        }
        write_json(
            w,
            503,
            &json!({"error": jarvis_sig::IdentityError::NoRoster.to_string()}),
        );
    });
    let k2 =
        KernelClient::new(&format!("{}/%s", refuse.url)).unwrap_or_else(|| panic!("no client"));
    *k2.roster.write().unwrap_or_else(|e| e.into_inner()) =
        k.roster.read().unwrap_or_else(|e| e.into_inner()).clone();
    let stale = Arc::new(std::sync::Mutex::new(String::new()));
    let s2 = stale.clone();
    *k2.on_stale.write().unwrap_or_else(|e| e.into_inner()) =
        Some(Arc::new(move |_: &str, msg: &str| {
            *s2.lock().unwrap_or_else(|e| e.into_inner()) = msg.into();
        }));
    let e = k2
        .call("notary", "POST", "/challenge", Some(&json!({})))
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(
        e.contains("roster stale: component notary-blue restarted"),
        "refused: {e}"
    );
    let st = stale.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        st.starts_with("roster stale: component notary-blue restarted"),
        "stale: {st:?}"
    );
}
