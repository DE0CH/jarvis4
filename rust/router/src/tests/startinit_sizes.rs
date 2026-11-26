//! startinit (the core's start, init and kill, Fly's machine limit) and sizes tests

use crate::flows::{
    INIT_MAX_MS, INIT_STEP_MS, KILL_STEP_MS, MACHINE_LIMIT_STEP_MS, MACHINE_LIMIT_WAIT_MS,
};
use crate::memory::{MemAlert, mem_message};
use crate::sizes::{next_size, note_core_sizes, size_guest, size_label, size_mem_gb, size_text};
use crate::testutil::{FakeCore, Rig, TestKey, TestServer, new_test_router_with, wait_for};
use serde_json::{Value, json};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

/// a core whose start is one Fly create and whose init and kill answer 409 until Fly is ready (R2); old answers like
/// the core from before R2 (start waits and returns "started", kill waits)
#[derive(Default)]
pub struct SplitState {
    pub old: bool,
    pub init_wait: i64,
    pub kill_wait: i64,
    pub init_fail: bool,
    /// /start answers Fly's machine-limit refusal this many times first
    pub limit: i64,
    pub calls: Vec<String>,
    pub bodies: std::collections::BTreeMap<String, Value>,
}

pub struct SplitCore {
    pub st: Arc<Mutex<SplitState>>,
    pub srv: TestServer,
}

impl SplitCore {
    pub fn new(f: impl FnOnce(&mut SplitState)) -> SplitCore {
        let mut s = SplitState::default();
        f(&mut s);
        let st = Arc::new(Mutex::new(s));
        let key = Arc::new(TestKey::new());
        let s2 = st.clone();
        let srv = TestServer::handler(move |w, req| {
            use jarvis_nethttp::write_json;
            let b: Value = serde_json::from_slice(&req.read_body(1 << 20)).unwrap_or(Value::Null);
            let mut c = s2.lock().unwrap_or_else(|e| e.into_inner());
            c.calls.push(req.path.clone());
            c.bodies.insert(req.path.clone(), b);
            let started = json!({"kind": "started", "machine": {"id": "m7", "requested": "img", "image": "img"}});
            let err = |m: &str| key.doc(&json!({"kind": "error", "error": m}));
            match req.path.as_str() {
                "/start" if c.limit > 0 => {
                    c.limit -= 1;
                    write_json(
                        w,
                        502,
                        &err(
                            "fly create: 422 Your organization has reached its machine limit. Please contact billing@fly.io",
                        ),
                    );
                }
                "/start" if c.old => write_json(w, 200, &key.doc(&started)),
                "/start" => write_json(
                    w,
                    200,
                    &key.doc(&json!({"kind": "created", "id": "m7", "image": "img"})),
                ),
                "/init" if c.init_fail => write_json(
                    w,
                    409,
                    &err("machine m7 isn't one this core created and hasn't initialised"),
                ),
                "/init" if c.init_wait > 0 => {
                    c.init_wait -= 1;
                    write_json(w, 409, &err("machine m7 is starting, not started"));
                }
                "/init" => write_json(w, 200, &key.doc(&started)),
                "/kill" if c.kill_wait > 0 => {
                    c.kill_wait -= 1;
                    write_json(w, 409, &err("machine m7 is destroying, not destroyed yet"));
                }
                "/kill" => write_json(w, 200, &key.doc(&json!({"kind": "killed", "id": "m7"}))),
                _ => write_json(w, 404, &json!({"error": "no"})),
            }
        });
        SplitCore { st, srv }
    }

    pub fn count(&self, path: &str) -> usize {
        self.st
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .calls
            .iter()
            .filter(|p| *p == path)
            .count()
    }

    pub fn calls(&self) -> Vec<String> {
        self.st
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .calls
            .clone()
    }
}

/// the start's waits shortened (process-wide: the caller holds the serial lock)
fn short_steps() {
    INIT_STEP_MS.store(1, Ordering::SeqCst);
    KILL_STEP_MS.store(1, Ordering::SeqCst);
}

fn restore_steps() {
    INIT_STEP_MS.store(5_000, Ordering::SeqCst);
    KILL_STEP_MS.store(1_000, Ordering::SeqCst);
    INIT_MAX_MS.store(12 * 60_000, Ordering::SeqCst);
    MACHINE_LIMIT_STEP_MS.store(60_000, Ordering::SeqCst);
    MACHINE_LIMIT_WAIT_MS.store(3 * 3_600_000, Ordering::SeqCst);
}

fn with_steps(f: impl FnOnce() + std::panic::UnwindSafe) {
    let _g = crate::testutil::serial();
    short_steps();
    let res = std::panic::catch_unwind(f);
    restore_steps();
    if let Err(p) = res {
        std::panic::resume_unwind(p);
    }
}

fn kind(d: &crate::core::Doc) -> String {
    d.decode::<Value>()
        .map(|v| v["kind"].as_str().unwrap_or("").to_string())
        .unwrap_or_default()
}

#[test]
fn start_retries_init_until_the_machine_is_up() {
    with_steps(|| {
        let c = SplitCore::new(|s| s.init_wait = 3);
        let t = new_test_router_with(|_| {}, Some(&c.srv.url), Default::default());
        let d = t
            .start_machine("img", "")
            .unwrap_or_else(|e| panic!("{e:#}"));
        assert!(
            kind(&d) == "started" && c.count("/init") == 4 && c.count("/kill") == 0,
            "{:?}",
            c.calls()
        );
        let b =
            c.st.lock()
                .unwrap_or_else(|e| e.into_inner())
                .bodies
                .get("/start")
                .cloned()
                .unwrap_or_default();
        assert!(
            b["size"] == "medium" && b.get("env").is_none_or(Value::is_null),
            "start body {b} (size defaults in the router; no env)"
        );
    });
}

#[test]
fn start_kills_a_machine_that_never_comes_up() {
    with_steps(|| {
        let c = SplitCore::new(|s| {
            s.init_fail = true;
            s.kill_wait = 2;
        });
        let t = new_test_router_with(|_| {}, Some(&c.srv.url), Default::default());
        assert!(t.start_machine("img", "small").is_err(), "started");
        // a permanent refusal isn't retried; the kill is, until destroyed
        assert!(
            c.count("/init") == 1 && c.count("/kill") == 3,
            "{:?}",
            c.calls()
        );
        {
            let mut s = c.st.lock().unwrap_or_else(|e| e.into_inner());
            s.init_fail = false;
            s.init_wait = 1 << 30;
        }
        INIT_MAX_MS.store(20, Ordering::SeqCst);
        assert!(t.start_machine("img", "small").is_err(), "started");
        assert_eq!(
            c.calls().last().map(String::as_str),
            Some("/kill"),
            "a machine that never came up wasn't killed"
        );
    });
}

#[test]
fn start_with_a_core_from_before_r2() {
    with_steps(|| {
        let c = SplitCore::new(|s| s.old = true);
        let t = new_test_router_with(|_| {}, Some(&c.srv.url), Default::default());
        let d = t
            .start_machine("img", "large")
            .unwrap_or_else(|e| panic!("{e:#}"));
        assert!(
            c.count("/init") == 0 && kind(&d) == "started",
            "{:?}",
            c.calls()
        );
        assert!(
            t.kill_until_destroyed(&json!({"machine": "m7"})).is_ok() && c.count("/kill") == 1,
            "{:?}",
            c.calls()
        );
    });
}

#[test]
fn start_waits_out_flys_machine_limit() {
    with_steps(|| {
        let c = SplitCore::new(|s| s.limit = 2);
        let t = new_test_router_with(|_| {}, Some(&c.srv.url), Default::default());
        MACHINE_LIMIT_STEP_MS.store(1, Ordering::SeqCst);
        t.start_machine("img", "")
            .unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(c.count("/start"), 3, "{:?}", c.calls());
        c.st.lock().unwrap_or_else(|e| e.into_inner()).limit = 1 << 30;
        MACHINE_LIMIT_WAIT_MS.store(5, Ordering::SeqCst);
        let e = t
            .start_machine("img", "")
            .err()
            .unwrap_or_else(|| panic!("started past the limit"));
        assert!(
            crate::flows::fly_machine_limit(&e),
            "gave up without the limit's error: {e:#}"
        );
    });
}

/// a start waiting out Fly's machine limit doesn't hold a drain for hours: it ends at once
#[test]
fn drain_ends_a_machine_limit_wait() {
    with_steps(|| {
        let c = SplitCore::new(|s| s.limit = 1 << 30);
        let t = new_test_router_with(|_| {}, Some(&c.srv.url), Default::default());
        std::thread::scope(|sc| {
            let res = sc.spawn(|| t.start_machine("img", ""));
            wait_for("the limit wait", || c.count("/start") >= 1);
            sc.spawn(|| t.drain_now(std::time::Duration::from_secs(1)));
            let e = res
                .join()
                .ok()
                .and_then(|r| r.err())
                .unwrap_or_else(|| panic!("the machine-limit wait went on through the drain"));
            assert!(format!("{e:#}").contains("start it again"), "{e:#}");
            let e = t
                .start_machine("img", "")
                .err()
                .unwrap_or_else(|| panic!("a wait began during the drain"));
            assert!(
                format!("{e:#}").contains("start it again"),
                "a wait began during the drain: {e:#}"
            );
        });
    });
}

/// Upgrade keeps going: every step doubles the memory, and each guest is one Fly takes (machine-sizing rules)
#[test]
fn the_ladder_keeps_going() {
    let want = [
        ("small", "shared", 2, 2),
        ("medium", "shared", 4, 4),
        ("large", "shared", 8, 8),
        ("16gb", "shared", 8, 16),
        ("32gb", "performance", 8, 32),
        ("64gb", "performance", 8, 64),
        ("128gb", "performance", 16, 128),
        ("256gb", "performance", 32, 256),
        ("512gb", "performance", 64, 512),
    ];
    let mut size = "small".to_string();
    for (i, (wsize, wkind, wcpus, wgb)) in want.into_iter().enumerate() {
        assert_eq!(size, wsize, "step {i}");
        let (k, cpus, mb) = size_guest(&size);
        assert!(
            k == wkind && cpus == wcpus && mb == wgb * 1024 && size_mem_gb(&size) == wgb,
            "{size}: {k} {cpus} {mb}"
        );
        // Fly: ≤ 2 GB per shared CPU; 2–8 GB per performance CPU, in steps of 2048 MB
        assert!(
            !((k == "shared" && mb > 2048 * cpus)
                || (k == "performance"
                    && (mb > 8192 * cpus || mb < 2048 * cpus || mb % 2048 != 0))),
            "{size}: {k} {cpus}×{mb} MB breaks Fly's sizing rules"
        );
        let g = crate::budget::FlyGuest {
            cpu_kind: k.into(),
            cpus,
            memory_mb: mb,
        };
        assert_eq!(
            crate::machines::size_of(Some(&g)),
            size,
            "size_of({size} guest)"
        );
        let next = next_size(&size);
        assert_eq!(size_mem_gb(&next), 2 * wgb, "after {size} comes {next}");
        size = next;
    }
    assert!(
        next_size("") == "large" && next_size("medium") == "large",
        "a session with no size runs medium: its next is large"
    );
    for bad in [
        "", "8gb", "17gb", "24gb", "016gb", "gb", "16GB", "16", "xlarge", "-16gb",
    ] {
        assert_eq!(size_mem_gb(bad), 0, "{bad:?} is a size");
    }
    assert_eq!(
        crate::machines::size_of(Some(&crate::budget::FlyGuest {
            cpu_kind: "shared".into(),
            cpus: 4,
            memory_mb: 8192
        })),
        ""
    );
    assert!(
        size_label("16gb") == "8×shared · 16 GB"
            && size_label("32gb") == "8×performance · 32 GB"
            && size_text("16gb") == "16 GB"
            && size_text("large") == "large (8 GB)",
        "{} {} {}",
        size_label("16gb"),
        size_label("32gb"),
        size_text("16gb")
    );
    let _g = crate::testutil::serial();
    note_core_sizes(true);
    let m = mem_message(
        "x",
        "large",
        &MemAlert {
            reason: "r".into(),
            ..Default::default()
        },
    );
    note_core_sizes(false);
    assert!(m.contains("moves it to 16 GB"), "{m}");
}

/// a size Fly refuses: Upgrade reports Fly's own error and the session goes back to its old size
#[test]
fn upgrade_a_fly_refusal_goes_back_to_the_old_size() {
    let rg = Rig::with(|c| c.no_access = true);
    let fc = FakeCore::new();
    let sizes: Arc<Mutex<Vec<String>>> = Arc::default();
    let (s2, furl, key) = (sizes.clone(), fc.srv.url.clone(), fc.key.clone());
    let core = TestServer::handler(move |w, req| {
        let b = req.read_body(1 << 20);
        if req.path == "/start" {
            let v: Value = serde_json::from_slice(&b).unwrap_or_default();
            let size = v["size"].as_str().unwrap_or("").to_string();
            s2.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(size.clone());
            let msg = if size == "256gb" {
                r#"fly create: POST /machines: HTTP 422 {"error":"invalid guest"}"#
            } else {
                "no Fly in tests"
            };
            return jarvis_nethttp::write_json(
                w,
                502,
                &key.doc(&json!({"kind": "error", "error": msg})),
            );
        }
        let resp = reqwest::blocking::Client::new()
            .post(format!("{furl}{}", req.path))
            .body(b)
            .send();
        match resp {
            Ok(r) => {
                let st = r.status().as_u16();
                let body = r.bytes().unwrap_or_default();
                w.set_header("Content-Type", "application/json");
                w.write_header(st);
                w.write(&body);
            }
            Err(_) => w.write_header(502),
        }
    });
    rg.t.r.core.set_url(&core.url);
    let cert = rg.cert.clone();
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.cert = Some(cert.clone());
            s.size = "128gb".into();
        }
    });
    let e = rg
        .resume_bigger("s1", "128gb", "256gb")
        .err()
        .unwrap_or_else(|| panic!("the refused size started"));
    let m = format!("{e:#}");
    assert!(
        m.contains(
            r#"256gb: core: fly create: POST /machines: HTTP 422 {"error":"invalid guest"}"#
        ),
        "{m}"
    );
    assert!(
        m.contains("resuming it on 128gb failed too: core: no Fly in tests"),
        "the way back: {m}"
    );
    assert_eq!(
        *sizes.lock().unwrap_or_else(|e| e.into_inner()),
        ["256gb", "128gb"],
        "starts"
    );
    assert_eq!(rg.session("s1").size, "128gb");
    wait_for("idle", || rg.lock("s1", "test-end").is_ok());
}
