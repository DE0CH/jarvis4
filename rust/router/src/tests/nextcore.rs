//! nextcore_test.go
use crate::nethttp::{Req, write_error, write_json};
use crate::nextcore::{DRAIN_WATCH_EVERY_MS, FLIP_AUTO_FORCE, HttpHandoff};
use crate::router::Router;
use crate::testutil::*;
use crate::types::Doc;
use serde_json::{Value, json};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// a core as the handoff contract describes it (core continuity): serving | standby | handed-off
#[derive(Default)]
struct HState {
    /// "" = empty
    serving: String,
    /// its signing key ("K" unless a test sets another)
    key: String,
    seq: i64,
    handoffs: usize,
    takeovers: Vec<String>,
}

struct HandoffCore {
    st: Arc<Mutex<HState>>,
    srv: TestServer,
}

impl HandoffCore {
    fn new(serving: &str, seq: i64) -> HandoffCore {
        let st = Arc::new(Mutex::new(HState {
            serving: serving.into(),
            key: "K".into(),
            seq,
            ..Default::default()
        }));
        let s2 = st.clone();
        let srv = TestServer::handler(move |w, req| {
            let b = req.read_body(1 << 20);
            let mut f = s2.lock().unwrap_or_else(|e| e.into_inner());
            match format!("{} {}", req.method, req.path).as_str() {
                "GET /identity" => {
                    let mut st = json!({"kind": "core-state", "master": null});
                    if !f.serving.is_empty() {
                        st["master"] = json!("M");
                        st["serving"] = json!(f.serving);
                        st["lineSeq"] = json!(f.seq);
                    }
                    let state = Doc {
                        payload: jarvis_go::marshal(&st),
                        sig: "s".into(),
                    };
                    write_json(w, 200, &json!({"signingKey": f.key, "state": state}));
                }
                "POST /handoff" => {
                    if f.serving != "serving" && f.serving != "handed-off" {
                        return write_error(w, 409, "not serving");
                    }
                    f.serving = "handed-off".into();
                    f.handoffs += 1;
                    let head = Doc {
                        payload: jarvis_go::marshal(
                            &json!({"kind": "line-state-head", "seq": f.seq, "final": true}),
                        ),
                        sig: "s".into(),
                    };
                    write_json(w, 200, &json!({"head": head, "sealed": "SEALED"}));
                }
                "POST /takeover" => {
                    let input: Value = serde_json::from_slice(&b).unwrap_or_default();
                    let ls = &input["lineState"];
                    let h: Value =
                        serde_json::from_str(ls["head"]["payload"].as_str().unwrap_or_default())
                            .unwrap_or_default();
                    let seq = h["seq"].as_i64().unwrap_or(0);
                    if f.serving != "standby"
                        || h["final"] != true
                        || seq < f.seq
                        || ls["sealed"] != "SEALED"
                    {
                        return write_error(w, 403, "refused");
                    }
                    f.serving = "serving".into();
                    f.seq = seq;
                    f.takeovers.push(String::from_utf8_lossy(&b).into_owned());
                    write_json(
                        w,
                        200,
                        &Doc {
                            payload: r#"{"kind":"took-over"}"#.into(),
                            sig: "s".into(),
                        },
                    );
                }
                _ => {
                    if f.serving == "handed-off" {
                        return write_error(w, 409, "this core is handed-off");
                    }
                    w.write_str(r#"{"payload":"{}","sig":"s"}"#);
                }
            }
        });
        HandoffCore { st, srv }
    }

    fn set(&self, f: impl FnOnce(&mut HState)) {
        f(&mut self.st.lock().unwrap_or_else(|e| e.into_inner()));
    }

    fn get<R>(&self, f: impl FnOnce(&HState) -> R) -> R {
        f(&self.st.lock().unwrap_or_else(|e| e.into_inner()))
    }

    fn state(&self) -> String {
        self.get(|s| s.serving.clone())
    }

    fn url(&self) -> String {
        self.srv.url.clone()
    }
}

/// r on cur, with next as its next core (the HTTP handoff)
fn on_cores(r: &Router, cur: &HandoffCore, next: &HandoffCore) {
    r.core.set_url(&cur.url());
    r.set_next_core(&next.url(), Some(Arc::new(HttpHandoff)));
}

fn next_url(r: &Router) -> String {
    r.next.client().map(|c| c.url()).unwrap_or_default()
}

/// a router restarted with the same env (CORE_URL = the old one, NEXT_CORE_URL = the new one)
fn restarted(r: &Router, cur: &HandoffCore, next: &HandoffCore) -> Arc<Router> {
    let core = Arc::new(crate::core::CoreClient::new(&cur.url()));
    let r2 = Router::new(r.cfg.clone(), r.st.clone(), core, Default::default());
    r2.set_next_core(&next.url(), None);
    r2.apply_active_core();
    r2
}

#[test]
fn flip_to_standby_core() {
    let t = new_test_router();
    let r = t.r.clone();
    let (cur, next) = (HandoffCore::new("serving", 7), HandoffCore::new("", 0));
    on_cores(&r, &cur, &next);
    let err = r.flip_core(Duration::from_secs(1)).err();
    assert!(
        err.as_ref()
            .is_some_and(|e| format!("{e:#}").contains("empty")),
        "an empty next core can't take over: {err:?}"
    );
    assert_eq!(
        cur.state(),
        "serving",
        "a refused flip must not hand the serving core off"
    );
    next.set(|f| {
        f.serving = "standby".into(); // Deyao Recovered it alongside
        f.seq = 5;
    });
    r.flip_core(Duration::from_secs(1))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        cur.state() == "handed-off" && next.state() == "serving",
        "after the flip: old {}, next {}",
        cur.state(),
        next.state()
    );
    assert!(
        r.core.url() == next.url() && next_url(&r) == cur.url(),
        "the router must talk to the new core now"
    );
    assert!(!r.draining(), "the flip must end its drain");
    assert_eq!(
        r.st.read(|d| d.active_core.clone()),
        next.url(),
        "activeCore"
    );
    // a restarted router talks to the active one
    let r2 = restarted(&r, &cur, &next);
    assert_eq!(
        r2.core.url(),
        next.url(),
        "a restart must keep the flipped core"
    );
    let st = r.next_core_status();
    assert!(
        st["current"]["serving"] == "serving" && st["next"]["serving"] == "handed-off",
        "status {st}"
    );
    // the handed-off core is never flipped back to
    assert!(
        r.flip_core(Duration::from_secs(1)).is_err(),
        "a handed-off core can't take over"
    );
}

/// A takeover refused after the handoff: no core serves; the final state is kept and a retry goes through.
#[test]
fn flip_retry_after_refused_takeover() {
    let t = new_test_router();
    let r = t.r.clone();
    // recovered NEWER than the final: refused
    let (cur, next) = (
        HandoffCore::new("serving", 7),
        HandoffCore::new("standby", 9),
    );
    on_cores(&r, &cur, &next);
    let _dms = capture_dm(&r);
    assert!(
        r.flip_core(Duration::from_secs(1)).is_err(),
        "a takeover of an older state must be refused"
    );
    assert!(
        cur.state() == "handed-off" && r.core.url() == cur.url(),
        "the old core is handed off and the router still points at it"
    );
    next.set(|f| f.seq = 7);
    r.flip_core(Duration::from_secs(1))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        next.state() == "serving" && cur.get(|f| f.handoffs) == 1,
        "retry: next {}, handoffs {} (the kept final state is reused)",
        next.state(),
        cur.get(|f| f.handoffs)
    );
}

#[test]
fn core_for_next() {
    let t = new_test_router();
    let r = t.r.clone();
    r.core.set_url("http://cur");
    let req = Req::new("GET", "/api/core/identity?core=next", b"");
    assert!(r.core_for(&req).is_none(), "no next core configured: None");
    r.set_next_core("http://next", None);
    assert_eq!(
        r.core_for(&req).map(|c| c.url()).as_deref(),
        Some("http://next"),
        "?core=next"
    );
    let req = Req::new("GET", "/api/core/identity", b"").with_header("X-Jarvis2-Core", "next");
    assert_eq!(
        r.core_for(&req).map(|c| c.url()).as_deref(),
        Some("http://next"),
        "header"
    );
    let req = Req::new("GET", "/api/core/identity", b"");
    assert_eq!(
        r.core_for(&req).map(|c| c.url()).as_deref(),
        Some("http://cur"),
        "default"
    );
}

/// The outage of 2026-10-22: a core release restarted the standby (empty) while the flip drained. The drain ends
/// early and nothing is handed off: the serving core goes on, and Deyao hears why.
#[test]
fn flip_aborts_when_the_standby_goes_during_the_drain() {
    let _g = serial();
    let _every = set_u64(&DRAIN_WATCH_EVERY_MS, 20);
    let t = new_test_router();
    let r = t.r.clone();
    let dms = capture_dm(&r);
    let (cur, next) = (
        HandoffCore::new("serving", 7),
        HandoffCore::new("standby", 7),
    );
    on_cores(&r, &cur, &next);
    let done = r.begin("s1", "pause").unwrap_or_else(|e| panic!("{e:#}")); // a lifecycle action that outlasts the drain
    let (r2, st2) = (r.clone(), next.st.clone());
    let th = std::thread::spawn(move || {
        // once the drain has begun (a fixed wait raced the flip's first look at the standby on a loaded box)
        while !r2.draining() {
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut f = st2.lock().unwrap_or_else(|e| e.into_inner());
        f.serving = String::new(); // CI pinned a new core into it: empty
        f.seq = 0;
    });
    let start = Instant::now();
    let err = r.flip_core(Duration::from_secs(60)).err();
    let _ = th.join();
    assert!(
        err.as_ref()
            .is_some_and(|e| format!("{e:#}").contains("empty")),
        "the flip must abort: {err:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "the drain must end as soon as the standby goes, not at its maximum"
    );
    assert!(
        cur.state() == "serving" && cur.get(|f| f.handoffs) == 0 && r.core.url() == cur.url(),
        "the serving core must go on: {}, {} handoffs",
        cur.state(),
        cur.get(|f| f.handoffs)
    );
    assert!(!r.draining(), "an aborted flip must undrain");
    let d = dms.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(d.len() == 1 && d[0].contains("aborted"), "DMs {d:?}");
    done.call();
}

/// The standby changes in a way the watch doesn't see in time (here: Recovered again with another kit just before
/// the drain ends): the check after the drain still refuses the handoff.
#[test]
fn flip_rechecks_the_standby_after_the_drain() {
    let _g = serial();
    let _every = set_u64(&DRAIN_WATCH_EVERY_MS, 3_600_000);
    let t = new_test_router();
    let r = t.r.clone();
    let dms = capture_dm(&r);
    let (cur, next) = (
        HandoffCore::new("serving", 7),
        HandoffCore::new("standby", 7),
    );
    on_cores(&r, &cur, &next);
    let done = r.begin("s1", "pause").unwrap_or_else(|e| panic!("{e:#}"));
    let (r2, st2) = (r.clone(), next.st.clone());
    let th = std::thread::spawn(move || {
        // once the drain has begun (the standby was checked before it), the standby changes, then the pause ends
        while !r2.draining() {
            std::thread::sleep(Duration::from_millis(1));
        }
        st2.lock().unwrap_or_else(|e| e.into_inner()).key = "OTHER".into();
        done.call();
    });
    let err = r.flip_core(Duration::from_secs(60)).err();
    let _ = th.join();
    assert!(
        err.as_ref()
            .is_some_and(|e| format!("{e:#}").contains("signing key")),
        "the flip must abort: {err:?}"
    );
    assert!(
        cur.state() == "serving" && cur.get(|f| f.handoffs) == 0 && next.state() == "standby",
        "nothing may be handed off: current {}, next {}",
        cur.state(),
        next.state()
    );
    let n = dms.lock().unwrap_or_else(|e| e.into_inner()).len();
    assert!(
        !r.draining() && n == 1,
        "draining {}, DMs {n}",
        r.draining()
    );
    // the same standby once more: the flip goes through
    next.set(|f| f.key = "K".into());
    r.flip_core(Duration::from_secs(60))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        next.state() == "serving" && r.core.url() == next.url(),
        "the flip after it must go through"
    );
}

struct FlipAuto;

impl Drop for FlipAuto {
    fn drop(&mut self) {
        FLIP_AUTO_FORCE.store(false, Ordering::SeqCst);
    }
}

fn flip_auto_on() -> FlipAuto {
    FLIP_AUTO_FORCE.store(true, Ordering::SeqCst);
    FlipAuto
}

/// The takeover happened by the next core's own Recover (its bundle carried the final state): the router finishes the
/// flip (the automatic tick and POST /setup/core/flip alike) and keeps it over a restart.
#[test]
fn finish_a_flip_the_next_core_took_over_by_recover() {
    let _g = serial(); // FLIP_AUTO_FORCE
    let t = new_test_router();
    let r = t.r.clone();
    // refused: older than its Recover
    let (cur, next) = (
        HandoffCore::new("serving", 7),
        HandoffCore::new("standby", 9),
    );
    on_cores(&r, &cur, &next);
    let _dms = capture_dm(&r);
    assert!(
        r.flip_core(Duration::from_secs(1)).is_err(),
        "the takeover must be refused"
    );
    assert!(
        r.st.read_doc("core-final.json").is_some(),
        "the final state is kept"
    );
    // another kit's core serving there: not switched to
    next.set(|f| {
        f.serving = "serving".into();
        f.seq = 7;
        f.key = "OTHER".into();
    });
    let err = r.flip_core(Duration::from_secs(1)).err();
    assert!(
        err.is_some() && r.core.url() == cur.url(),
        "another kit's core must not be switched to: {err:?}"
    );
    // an older line state than the final one: not switched to
    next.set(|f| {
        f.seq = 6;
        f.key = "K".into();
    });
    let err = r.flip_core(Duration::from_secs(1)).err();
    assert!(
        err.is_some() && r.core.url() == cur.url(),
        "an older line state must not be switched to: {err:?}"
    );
    // Recovered (restarted empty, then Recover with the kit: the bundle had the final state) → it serves
    next.set(|f| f.seq = 7);
    let _auto = flip_auto_on();
    r.next_core_tick(Duration::from_secs(1));
    assert!(
        r.core.url() == next.url() && next_url(&r) == cur.url(),
        "the automatic tick must finish the flip"
    );
    assert!(
        next.get(|f| f.takeovers.is_empty()),
        "no takeover call: it already serves"
    );
    assert_eq!(
        r.st.read(|d| d.active_core.clone()),
        next.url(),
        "activeCore"
    );
    assert!(
        r.st.read_doc("core-final.json").is_none(),
        "core-final.json must go"
    );
    assert_eq!(
        r.next_core_status()["activeCore"],
        next.url().as_str(),
        "the status shows activeCore"
    );
    // a restarted router with the env unchanged talks to the new core
    let r2 = restarted(&r, &cur, &next);
    assert_eq!(
        r2.core.url(),
        next.url(),
        "a restart must keep the finished flip"
    );
    // nothing more to finish: the tick leaves it alone (the handed-off core is next now)
    r.next_core_tick(Duration::from_secs(1));
    assert_eq!(
        r.core.url(),
        next.url(),
        "a second tick must change nothing"
    );
}

/// Both cores serving (the next one Recovered on its own while the current one never handed off): no switch.
#[test]
fn no_finish_while_the_current_core_serves() {
    let _g = serial();
    let t = new_test_router();
    let r = t.r.clone();
    let (cur, next) = (
        HandoffCore::new("serving", 7),
        HandoffCore::new("serving", 7),
    );
    on_cores(&r, &cur, &next);
    let _auto = flip_auto_on();
    r.next_core_tick(Duration::from_secs(1));
    let err = r.flip_core(Duration::from_secs(1)).err();
    assert!(
        err.as_ref()
            .is_some_and(|e| format!("{e:#}").contains("both cores")),
        "{err:?}"
    );
    assert_eq!(
        r.core.url(),
        cur.url(),
        "no switch while the current core serves"
    );
}
