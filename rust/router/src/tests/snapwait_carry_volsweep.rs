//! snapwait, carry and volsweep tests

use crate::budget::FlyVolume;
use crate::core::Doc;
use crate::state::{Session, Started};
use crate::testutil::{
    Rig, TestServer, add_session, capture_dm, new_test_router, new_test_router_with, wait_for,
};
use crate::types::Volume;
use crate::volsweep::{
    SweepConfig, SweepMachine, SweepMount, VOL_SWEEP_MAX_PER_GO, VOL_SWEEP_READER, VOLUME_DELETE,
    sweep_select,
};
use jarvis_go::GoTime;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn progress(i: i64) -> String {
    jarvis_go::marshal(
        &json!({"phase": "uploading", "done": i * 1000, "total": 100000, "sent": i * 500, "elapsedMs": i * 100}),
    )
}

/// the wait has no overall limit (DECISIONS 214): a snapshot whose progress reports keep moving is waited for well past
/// the stall window, and arrives
#[test]
fn a_snapshot_making_progress_is_waited_for() {
    let rg = Rig::with(|c| c.snapshot_stall = Duration::from_secs(1)); // ten report intervals
    rg.running_m2(false);
    rg.pause("s1").unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("asked", || rg.snapshot_awaited("m2"));
    let m = rg.machine("m2");
    let h = rg.machine_handler();
    for i in 1..=30 {
        // 3 s, three stall windows
        let (code, _) = m.do_(&h, "POST", "/m/snapshot-progress", &progress(i));
        assert_eq!(code, 200);
        std::thread::sleep(Duration::from_millis(100));
        let s = rg.session("s1");
        assert_eq!(
            s.state, "pausing",
            "after {i} reports: {}",
            s.snapshot_failed
        );
    }
    rg.write_snapshot("m2", &rg.files.clone());
    rg.snapshot_arrived("m2");
    rg.wait_action_end("s1", "paused")
        .unwrap_or_else(|e| panic!("{e:#}"));
}

/// a live machine repeating the same numbers makes no progress: the wait ends after the stall window
#[test]
fn repeated_progress_numbers_stall() {
    // the stall window well above what a loaded machine does between two reports: the test is the repeated
    // number, not the scheduler
    let rg = Rig::with(|c| c.snapshot_stall = Duration::from_millis(1500));
    let _dms = capture_dm(&rg);
    rg.running_m2(false);
    rg.pause("s1").unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("asked", || rg.snapshot_awaited("m2"));
    let m = rg.machine("m2");
    let h = rg.machine_handler();
    let t0 = Instant::now();
    for _ in 0..30 {
        if rg.session("s1").state != "pausing" {
            break;
        }
        let _ = m.do_(&h, "POST", "/m/snapshot-progress", &progress(1));
        std::thread::sleep(Duration::from_millis(50));
    }
    rg.wait_action_end("s1", "failed")
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        t0.elapsed() <= Duration::from_secs(5),
        "the stall took {:?}",
        t0.elapsed()
    );
    let s = rg.session("s1");
    assert!(
        s.snapshot_failed.contains("made no progress") && s.machine_id == "m2",
        "{s:?}"
    );
    assert!(
        !rg.snapshot_awaited("m2"),
        "still awaited after the wait ended"
    );
}

/// the snapshot's bytes arriving at the router are progress (a machine with no progress reports, or a slow network)
#[test]
fn streamed_bytes_keep_the_wait_going() {
    let rg = Rig::new();
    let done = rg.await_snapshot("m9");
    let (pr, mut pw) = std::io::pipe().unwrap_or_else(|e| panic!("{e}"));
    std::thread::spawn(move || {
        for _ in 0..20 {
            let _ = std::io::Write::write_all(&mut pw, b"x");
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let r2 = rg.t.r.clone();
    std::thread::spawn(move || {
        let mut rd = crate::snapwait::MovedReader::new(pr, r2, "m9");
        let _ = std::io::copy(&mut rd, &mut std::io::sink());
    });
    // a loaded machine can take a few hundred ms to schedule the writer; the stall window is 1 s, so anything
    // under that still shows the bytes resetting the quiet
    let mut quiet_max = time::Duration::ZERO;
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(50));
        quiet_max = quiet_max.max(rg.snapshot_quiet("m9"));
    }
    assert!(
        quiet_max <= time::Duration::milliseconds(750),
        "quiet for {quiet_max} while bytes arrived"
    );
    rg.snapshot_arrived("m9");
    rg.wait_snapshot("m9", done)
        .unwrap_or_else(|e| panic!("{e:#}"));
}

/// a machine that stops reporting during its snapshot (gone) ends the wait after SILENT_AFTER, not the stall window
#[test]
fn a_machine_gone_silent_during_its_snapshot() {
    let rg = Rig::with(|c| c.snapshot_stall = Duration::from_secs(60));
    let _dms = capture_dm(&rg);
    rg.running_m2(false); // its last report is fresh: it is asked
    rg.silent_after_secs
        .store(0, std::sync::atomic::Ordering::SeqCst);
    let t0 = Instant::now();
    rg.pause("s1")
        .and_then(|()| rg.wait_action_end("s1", "failed"))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        t0.elapsed() <= Duration::from_secs(5),
        "took {:?}",
        t0.elapsed()
    );
    let s = rg.session("s1");
    assert!(
        s.snapshot_failed
            .contains("went silent during its snapshot"),
        "{s:?}"
    );
}

// ---- carry ---------------------------------------------------------------------------------------------------

/// a core that answers pulls and forwards with carry blobs (old = a core that predates them: no carry in its answers,
/// 404 on /carry/forward)
fn carry_core(old: bool) -> (TestServer, Arc<Mutex<Vec<Value>>>) {
    let calls: Arc<Mutex<Vec<Value>>> = Arc::default();
    let c = calls.clone();
    let srv = TestServer::handler(move |w, req| {
        let mut input: Value = serde_json::from_slice(&req.read_body(1 << 20)).unwrap_or(json!({}));
        input["path"] = json!(req.path);
        c.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(input.clone());
        let doc = |w: &mut crate::nethttp::W, v: Value| {
            crate::nethttp::write_json(
                w,
                200,
                &json!({"payload": jarvis_go::marshal(&v), "sig": "s"}),
            );
        };
        let carry = input["carry"].as_str().unwrap_or("").to_string();
        match (req.path.as_str(), old) {
            ("/pull-secrets", true) => doc(w, json!({"kind": "secrets"})),
            ("/pull-secrets", false) => doc(
                w,
                json!({"kind": "secrets", "carry": format!("blob-after-pull-{carry}")}),
            ),
            ("/carry/forward", false) => doc(
                w,
                json!({"kind": "carry", "carry": format!("forwarded-{carry}")}),
            ),
            _ => crate::nethttp::not_found(w),
        }
    });
    (srv, calls)
}

fn cert_doc(machine: &str, pred: &str) -> Doc {
    Doc {
        payload: jarvis_go::marshal(
            &json!({"kind": "succession-cert", "predecessorId": pred, "machine": {"id": machine}}),
        ),
        sig: "s".into(),
    }
}

#[test]
fn the_router_keeps_and_forwards_the_carried_secrets() {
    let (core, calls) = carry_core(false);
    let t = new_test_router_with(|_| {}, Some(&core.url), Default::default());
    // m1's first pull: no blob yet; the answer's blob is kept for m1
    assert_eq!(
        t.carry_for_pull("m1", &cert_doc("m1", "")),
        "",
        "a blob before any pull"
    );
    let d = t
        .core
        .call(
            "/pull-secrets",
            &json!({"cert": cert_doc("m1", ""), "carry": ""}),
        )
        .unwrap_or_else(|e| panic!("{e:#}"));
    t.pulled("m1", &cert_doc("m1", ""), &d);
    assert_eq!(t.read_carry("m1"), "blob-after-pull-");
    // a resume: m2 certified as m1's successor → forwarded to m2, m1's dropped
    t.forward_carry("m1", &cert_doc("m2", "m1"), "m2");
    let f = calls
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .last()
        .cloned()
        .unwrap_or_default();
    assert!(
        f["path"] == "/carry/forward" && f["carry"] == "blob-after-pull-",
        "forward: {f}"
    );
    assert!(t.read_carry("m2") == "forwarded-blob-after-pull-" && t.read_carry("m1").is_empty());
    // m2's pull sends its own blob
    assert_eq!(
        t.carry_for_pull("m2", &cert_doc("m2", "m1")),
        "forwarded-blob-after-pull-"
    );
    // a successor whose forward didn't happen sends its predecessor's
    t.save_carry("m3", "m3-blob");
    assert_eq!(t.carry_for_pull("m4", &cert_doc("m4", "m3")), "m3-blob");
    // destroy: finish drops the blobs with the snapshots
    add_session(&t, "s1", "paused", "", false);
    t.st.do_(|d| {
        d.machines.insert("m2".into(), "s1".into());
    });
    t.finish("s1", |_| {});
    assert_eq!(t.read_carry("m2"), "", "the blob outlived the session");
}

#[test]
fn a_core_without_carried_secrets_changes_nothing() {
    let (core, _) = carry_core(true);
    let t = new_test_router_with(|_| {}, Some(&core.url), Default::default());
    let d = t
        .core
        .call(
            "/pull-secrets",
            &json!({"cert": cert_doc("m1", ""), "carry": ""}),
        )
        .unwrap_or_else(|e| panic!("{e:#}"));
    t.pulled("m1", &cert_doc("m1", ""), &d);
    assert_eq!(
        t.read_carry("m1"),
        "",
        "kept a blob from a core that has none"
    );
    t.save_carry("m1", "x");
    t.forward_carry("m1", &cert_doc("m2", "m1"), "m2"); // 404: ignored
    assert!(
        t.read_carry("m2").is_empty() && t.read_carry("m1") == "x",
        "a failed forward moved or dropped a blob"
    );
}

// ---- volsweep ------------------------------------------------------------------------------------------------

fn sweep_now() -> GoTime {
    GoTime::parse("2026-10-20T12:00:00Z").unwrap_or_default()
}

fn vol(id: &str, name: &str, state: &str, attached: &str, age_s: i64) -> FlyVolume {
    FlyVolume {
        id: id.into(),
        name: name.into(),
        state: state.into(),
        attached_machine_id: attached.into(),
        created_at: GoTime::from_unix(sweep_now().unix() - age_s)
            .utc()
            .rfc3339(),
        ..Default::default()
    }
}

fn mounting(id: &str, state: &str, vols: &[&str]) -> SweepMachine {
    SweepMachine {
        id: id.into(),
        state: state.into(),
        config: SweepConfig {
            mounts: vols
                .iter()
                .map(|v| SweepMount {
                    volume: (*v).into(),
                })
                .collect(),
        },
    }
}

#[test]
fn sweep_selects() {
    let vols = vec![
        vol("vol_leftover", "jarvis4_state", "created", "", 7200),
        vol("vol_young", "jarvis4_state", "created", "", 14 * 60),
        vol("vol_attached", "jarvis4_state", "created", "m1", 7200),
        vol("vol_mounted", "jarvis4_state", "created", "", 7200),
        vol("vol_named", "jarvis4_state", "created", "", 7200),
        vol("vol_other", "data", "created", "", 7200),
        vol(
            "vol_destroying",
            "jarvis4_state",
            "pending_destroy",
            "",
            7200,
        ),
        vol("vol_deadmount", "jarvis4_state", "created", "", 7200),
        FlyVolume {
            id: "vol_notime".into(),
            name: "jarvis4_state".into(),
            state: "created".into(),
            created_at: "yesterday".into(),
            ..Default::default()
        },
    ];
    let ms = vec![
        mounting("m2", "stopped", &["vol_mounted"]),
        mounting("m3", "destroyed", &["vol_deadmount"]),
    ];
    let named = [(
        "vol_named".to_string(),
        "session s1's machine m9".to_string(),
    )]
    .into_iter()
    .collect();
    let ch = sweep_select(&vols, &ms, &named, sweep_now());
    assert_eq!(ch.delete, ["vol_deadmount", "vol_leftover"]);
    for (id, cat) in [
        ("vol_young", "young"),
        ("vol_attached", "attached"),
        ("vol_mounted", "mounted"),
        ("vol_named", "named"),
        ("vol_other", "other name"),
        ("vol_destroying", "state"),
        ("vol_notime", "no creation time"),
    ] {
        let kept = ch.kept.get(id).cloned().unwrap_or_default();
        assert_eq!(
            jarvis_go::fmt::cut(&kept, ":").0,
            cat,
            "{id} kept as {kept}"
        );
    }
}

#[test]
fn sweep_select_boundary_and_limit() {
    let ch = sweep_select(
        &[vol("vol_15", "jarvis4_state", "created", "", 15 * 60)],
        &[],
        &Default::default(),
        sweep_now(),
    );
    assert_eq!(
        ch.delete.len(),
        1,
        "a volume exactly 15 minutes old is a leftover: {ch:?}"
    );
    let vols: Vec<FlyVolume> = (0..VOL_SWEEP_MAX_PER_GO + 5)
        .map(|i| vol(&format!("vol_{i:02}"), "jarvis4_state", "created", "", 3600))
        .collect();
    let ch = sweep_select(&vols, &[], &Default::default(), sweep_now());
    assert!(
        ch.delete.len() == VOL_SWEEP_MAX_PER_GO && ch.kept.len() == 5,
        "limit: {} deleted, {} kept",
        ch.delete.len(),
        ch.kept.len()
    );
}

fn cert_with_volume(v: &str) -> Doc {
    Doc {
        payload: jarvis_go::marshal(
            &json!({"machine": {"volume": {"id": v, "sizeGb": 10, "path": "/data"}}}),
        ),
        sig: String::new(),
    }
}

#[test]
fn sweep_named() {
    let t = new_test_router();
    t.st.do_(|d| {
        d.sessions.insert(
            "s1".into(),
            Session {
                id: "s1".into(),
                state: "running".into(),
                machine_id: "m1".into(),
                booted: "m0".into(),
                ..Default::default()
            },
        );
        d.certs
            .insert("m1".into(), cert_with_volume("vol_current_cert"));
        d.started.insert(
            "m0".into(),
            Started {
                id: "m0".into(),
                volume: Some(Volume {
                    id: "vol_booted_started".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        // an earlier machine of the same session: its volume is no longer named (the leak the sweep exists for)
        d.started.insert(
            "m_old".into(),
            Started {
                id: "m_old".into(),
                volume: Some(Volume {
                    id: "vol_old_machine".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        d.certs
            .insert("m_old".into(), cert_with_volume("vol_old_machine"));
        d.machines.insert("m_old".into(), "s1".into());
    });
    let named = t.sweep_named();
    for v in ["vol_current_cert", "vol_booted_started"] {
        assert!(
            named.get(v).is_some_and(|n| !n.is_empty()),
            "{v} not named: {named:?}"
        );
    }
    assert!(
        !named.contains_key("vol_old_machine"),
        "vol_old_machine named"
    );
}

static DELETE_CALLS: Mutex<Vec<String>> = Mutex::new(vec![]);

#[test]
fn volume_sweep_deletes_and_retries() {
    let _g = crate::testutil::serial();
    let t = new_test_router();
    t.st.do_(|d| {
        d.sessions.insert(
            "s1".into(),
            Session {
                id: "s1".into(),
                state: "running".into(),
                machine_id: "m1".into(),
                ..Default::default()
            },
        );
        d.started.insert(
            "m1".into(),
            Started {
                id: "m1".into(),
                volume: Some(Volume {
                    id: "vol_live".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    });
    let (or, od) = (
        *VOL_SWEEP_READER.read().unwrap_or_else(|e| e.into_inner()),
        *VOLUME_DELETE.read().unwrap_or_else(|e| e.into_inner()),
    );
    *VOL_SWEEP_READER.write().unwrap_or_else(|e| e.into_inner()) = || {
        Ok((
            vec![
                vol("vol_live", "jarvis4_state", "created", "", 3600),
                vol("vol_a", "jarvis4_state", "created", "", 3600),
                vol("vol_b", "jarvis4_state", "created", "", 3600),
            ],
            vec![],
        ))
    };
    DELETE_CALLS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    *VOLUME_DELETE.write().unwrap_or_else(|e| e.into_inner()) = |token, id| {
        DELETE_CALLS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(format!("{token}:{id}"));
        if id == "vol_b" {
            Err(anyhow::anyhow!("HTTP 500"))
        } else {
            Ok(())
        }
    };
    let got = t.volume_sweep("tok", sweep_now());
    let calls = DELETE_CALLS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let st = crate::volsweep::volume_sweep_status();
    *VOL_SWEEP_READER.write().unwrap_or_else(|e| e.into_inner()) =
        || Err(anyhow::anyhow!("HTTP 503"));
    DELETE_CALLS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    let failed_list = t.volume_sweep("tok", sweep_now());
    let calls2 = DELETE_CALLS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    *VOL_SWEEP_READER.write().unwrap_or_else(|e| e.into_inner()) = or;
    *VOLUME_DELETE.write().unwrap_or_else(|e| e.into_inner()) = od;
    assert!(
        got.as_ref().is_ok_and(|g| g == &["vol_a"]) && calls == ["tok:vol_a", "tok:vol_b"],
        "deleted {got:?} (calls {calls:?})"
    );
    assert!(
        st["failed"]["vol_b"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "status {st}"
    );
    // a failed list deletes nothing
    assert!(
        failed_list.is_err() && calls2.is_empty(),
        "list failure: {failed_list:?}, calls {calls2:?}"
    );
}
