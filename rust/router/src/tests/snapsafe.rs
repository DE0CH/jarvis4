//! snapsafe_test.go
use crate::router::Router;
use crate::testutil::*;
use jarvis_nethttp::{Req, W, write_json};
use serde_json::{Value, json};
use sha2::Digest;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// a core that kills like a core with volumes: the record names the backup
#[derive(Default)]
struct VolState {
    kills: usize,
    extends: Vec<Value>,
    restart: bool,
    /// the kill record names a volume backup, as an earlier core's did: read without acting on it
    old_kill: bool,
}

type Vol = Arc<Mutex<VolState>>;

fn vs<R>(v: &Vol, f: impl FnOnce(&mut VolState) -> R) -> R {
    f(&mut v.lock().unwrap_or_else(|e| e.into_inner()))
}

/// the rig on the volume core (its fake core's key), and the core's state
fn vol_rig() -> (Rig, Vol, FakeCore) {
    let rg = Rig::new();
    let v: Vol = Arc::default();
    let v2 = v.clone();
    let core = FakeCore::hooked(
        rg.core.key.clone(),
        Arc::new(move |w: &mut W, k: &TestKey, path: &str, b: &[u8]| {
            let input: Value = serde_json::from_slice(b).unwrap_or_default();
            match path {
                "/kill" => {
                    let m = input["machine"].as_str().unwrap_or_default().to_string();
                    let sum = input["snapshot"]["sha256"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    let old = vs(&v2, |x| {
                        x.kills += 1;
                        x.old_kill
                    });
                    let mut rec = json!({"kind": "killed", "id": m, "snapshot": sum});
                    if old {
                        rec["backup"] = json!({"volume": format!("vol_{m}"), "snapshot": format!("vs_{m}"),
                            "at": "2026-10-15T05:00:00Z", "retentionDays": 60, "signedSnapshot": !sum.is_empty()});
                    }
                    write_json(w, 200, &k.doc(&rec));
                    true
                }
                "/extend" => {
                    let restart = vs(&v2, |x| {
                        x.extends.push(input.clone());
                        x.restart
                    });
                    write_json(
                        w,
                        200,
                        &k.doc(&json!({"kind": "extended", "id": input["machine"],
                        "sizeGb": input["sizeGb"], "needsRestart": restart})),
                    );
                    true
                }
                _ => false,
            }
        }),
    );
    rg.core().set_url(&core.srv.url);
    (rg, v, core)
}

/// a router on the rig's state and core with another snapshot stall (Go's tests change r.cfg.SnapshotStall)
fn with_stall(rg: &Rig, stall: Duration) -> Arc<Router> {
    let mut cfg = rg.cfg.clone();
    cfg.snapshot_stall = stall;
    let r = Router::new(cfg, rg.st.clone(), rg.core().clone(), Default::default());
    *r.box_override.write().unwrap_or_else(|e| e.into_inner()) =
        Some(Some(Arc::new(rg.dav.storage_box())));
    r
}

fn dms_of(d: &Mutex<Vec<String>>) -> Vec<String> {
    d.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// the incident (2026-10-15): the final snapshot failed and the machine was destroyed anyway. Now a machine without
/// a volume whose snapshot fails is kept, the session says why, and Deyao gets a "needs you" DM; nothing is killed
#[test]
fn a_failed_final_snapshot_keeps_the_machine() {
    let rg = Rig::new();
    let r = with_stall(&rg, Duration::from_millis(200));
    let dms = capture_dm(&r);
    rg.running_m2(false);
    r.pause("s1").unwrap_or_else(|e| panic!("{e:#}"));
    r.wait_state("s1", "failed", Duration::from_secs(5))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let s = rg.session("s1");
    assert!(
        s.machine_id == "m2"
            && s.snapshot_failed.contains("made no progress for")
            && s.error.contains("is kept"),
        "session {s:?}"
    );
    assert!(
        !rg.core
            .calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|c| c == "/kill"),
        "the machine was killed"
    );
    wait_for("DM", || dms_of(&dms).len() == 1);
    let d = dms_of(&dms);
    assert!(
        d[0].contains("needs you") && d[0].contains("kept instead of destroyed"),
        "{d:?}"
    );
    // the machine reports its failure: the next pause stops waiting at once (no stall wait)
    let r60 = with_stall(&rg, Duration::from_secs(60));
    let _dms60 = capture_dm(&r60);
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.state = "started".into();
        }
    });
    let t0 = Instant::now();
    r60.pause("s1").unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("asked", || !rg.session("s1").waiting.is_empty());
    let m = rg.machine("m2");
    let (code, _) = m.do_(
        &r60.machine_handler(),
        "POST",
        "/m/snapshot-failed",
        r#"{"error":"no space left on device"}"#,
    );
    assert_eq!(code, 200);
    r60.wait_state("s1", "failed", Duration::from_secs(5))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        t0.elapsed() < Duration::from_secs(10),
        "waited for the stall"
    );
    let s = rg.session("s1");
    assert!(
        s.snapshot_failed.contains("no space left on device") && s.machine_id == "m2",
        "{s:?}"
    );
    // Destroy anyway goes on past it
    r.destroy_with("s1", true)
        .unwrap_or_else(|e| panic!("{e:#}")); // wait_state saw the pause end, its lock gone too
    wait_for("destroyed", || {
        rg.st.read(|d| !d.sessions.contains_key("s1"))
    });
}

/// a machine with a volume whose snapshot fails is kept too (2026-10-21: the YYC session's was killed after its
/// snapshot failed): no kill, a "needs you" DM
#[test]
fn a_failed_final_snapshot_keeps_a_machine_with_a_volume() {
    let (rg, vc, _core) = vol_rig();
    let r = with_stall(&rg, Duration::from_millis(200));
    let dms = capture_dm(&r);
    rg.running_m2(true);
    r.pause("s1").unwrap_or_else(|e| panic!("{e:#}"));
    r.wait_state("s1", "failed", Duration::from_secs(5))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let s = rg.session("s1");
    let kills = vs(&vc, |x| x.kills);
    assert!(
        kills == 0
            && s.machine_id == "m2"
            && s.error.contains("is kept")
            && !s.snapshot_failed.is_empty(),
        "kills {kills}, session {s:?}"
    );
    wait_for("DM", || dms_of(&dms).len() == 1);
    assert!(
        dms_of(&dms)[0].contains("kept instead of destroyed"),
        "{:?}",
        dms_of(&dms)
    );
}

/// a kill that goes on past a failed snapshot (force) of a machine with a volume: a line whose last machine left no
/// snapshot won't resume (it would start empty): the session and a DM say so. A kill record that still names a
/// volume backup (an earlier core's) is read without acting on it.
#[test]
fn no_snapshot_stops_the_resume() {
    let (rg, vc, _core) = vol_rig();
    vs(&vc, |x| x.old_kill = true);
    let r = with_stall(&rg, Duration::from_millis(200));
    let dms = capture_dm(&r);
    rg.running_m2(true);
    assert!(
        r.final_snapshot_and_kill("s1", "m2", true),
        "the forced kill didn't finish"
    );
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.state = "paused".into(); // as a pause leaves it
            s.machine_id = String::new();
        }
    });
    let s = rg.session("s1");
    let kills = vs(&vc, |x| x.kills);
    assert!(
        kills == 1 && s.no_snapshot.contains("machine m2 left no snapshot"),
        "kills {kills}, noSnapshot {:?}",
        s.no_snapshot
    );
    wait_for("DM", || dms_of(&dms).len() == 1);
    let d = dms_of(&dms);
    assert!(
        d[0].contains("won't resume") && !d[0].contains("vs_m2") && !d[0].contains("backup"),
        "{d:?}"
    );
    let err = r
        .resume("s1", false)
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(
        err.contains("would start empty") && err.contains("machine m1's"),
        "resume: {err:?}"
    );
    let _ = r.resume("s1", false);
    assert_eq!(
        dms_of(&dms).len(),
        1,
        "the refusal DMed again: {:?}",
        dms_of(&dms)
    );
    rg.st.do_(|d| {
        let snapshot = d.clone();
        let s = d.sessions.get("s1").cloned().unwrap_or_default();
        let v = crate::http::session_view(&s, &snapshot);
        assert!(
            v.get("backups").is_none() && v.get("noSnapshot").is_some_and(|x| !x.is_null()),
            "view {v:?}"
        );
    });
}

/// a pause whose machine did send its snapshot: no noSnapshot
#[test]
fn a_signed_snapshot_pauses_normally() {
    let (rg, _vc, _core) = vol_rig();
    rg.running_m2(true);
    rg.write_snapshot("m2", &rg.files);
    rg.pause("s1").unwrap_or_else(|e| panic!("{e:#}"));
    rg.wait_state("s1", "paused", Duration::from_secs(5))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let s = rg.session("s1");
    assert!(s.no_snapshot.is_empty(), "{s:?}");
}

fn hex_sum(b: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(b))
}

/// the snapshot streams in (no disk on the machine), then the machine's signature over the router's hash commits it
#[test]
fn the_streamed_snapshot_is_committed_only_with_the_machines_signature() {
    let rg = Rig::new();
    rg.running_m2(false);
    let h = rg.machine_handler();
    let body = "snapshot bytes ".repeat(1000);
    let stream = |sig: &str| {
        let ts = crate::util::unix_now().to_string();
        let sig = if sig.is_empty() {
            rg.mkey
                .0
                .sign(format!("POST /m/snapshot-stream {ts} stream").as_bytes())
        } else {
            sig.to_string()
        };
        let mut req = Req::new("POST", "/m/snapshot-stream", body.as_bytes())
            .with_header("X-Machine", "m2")
            .with_header("X-Time", &ts)
            .with_header("X-Sig", &sig);
        let mut w = W::recorder();
        h(&mut w, &mut req);
        (
            w.status(),
            serde_json::from_str::<Value>(&w.body_text()).unwrap_or_default(),
        )
    };
    assert_eq!(stream("bm90IGEgc2ln").0, 401, "an unsigned stream");
    let (code, out) = stream("");
    let want = hex_sum(body.as_bytes());
    assert!(
        code == 200 && out["sha256"] == want.as_str() && out["bytes"] == body.len(),
        "{code} {out}"
    );
    let m = rg.machine("m2");
    let other = TestKey::new();
    let bad = other.0.sign(want.as_bytes());
    let commit = |sum: &str, sig: &str| {
        m.do_(
            &h,
            "POST",
            "/m/snapshot-commit",
            &format!(r#"{{"sha256":"{sum}","sig":"{sig}"}}"#),
        )
        .0
    };
    assert_eq!(
        commit(&want, &bad),
        403,
        "committed with another key's signature"
    );
    let good = rg.mkey.0.sign(want.as_bytes());
    assert_eq!(
        commit(&"0".repeat(64), &good),
        409,
        "committed another hash"
    );
    assert_eq!(commit(&want, &good), 200, "commit");
    assert!(
        snap_bytes(&rg, "m2").as_deref() == Some(body.as_bytes()) && rg.have_snap("m2"),
        "the snapshot isn't in place"
    );
    let kd = rg.kill_machine("m2", false);
    assert!(
        kd.as_ref()
            .is_ok_and(|d| d.as_ref().is_some_and(|d| d.payload.contains(&want))),
        "the kill doesn't name it: {kd:?}"
    );
}

/// a machine paused while still booting carries its predecessor's snapshot over: the line keeps its state
#[test]
fn a_booting_machine_carries_the_predecessors_snapshot() {
    let rg = Rig::new();
    let m1 = snap_bytes(&rg, "m1").unwrap_or_default();
    let sum = hex_sum(&m1);
    let cert = rg.core.key.doc(
        &json!({"kind": "succession-cert", "predecessorId": "m1", "snapshot": sum,
        "machine": {"id": "m2", "signingKey": rg.mkey.public()}}),
    );
    let started = crate::state::Started {
        id: "m2".into(),
        signing_key: rg.mkey.public(),
        ..Default::default()
    };
    rg.st.do_(|d| {
        d.machines.insert("m2".into(), "s1".into());
        d.certs.insert("m2".into(), cert.clone());
        d.started.insert("m2".into(), started.clone());
    });
    let m = rg.machine("m2");
    let h = rg.machine_handler();
    let wrong = "1".repeat(64);
    let ws = rg.mkey.0.sign(wrong.as_bytes());
    let (code, _) = m.do_(
        &h,
        "POST",
        "/m/snapshot-carry",
        &format!(r#"{{"sha256":"{wrong}","sig":"{ws}"}}"#),
    );
    assert_eq!(code, 409, "carried a hash the cert doesn't name");
    let sig = rg.mkey.0.sign(sum.as_bytes());
    let (code, _) = m.do_(
        &h,
        "POST",
        "/m/snapshot-carry",
        &format!(r#"{{"sha256":"{sum}","sig":"{sig}"}}"#),
    );
    assert_eq!(code, 200, "carry");
    let s = rg.snap("m2");
    assert!(
        s.is_some_and(|s| s.sha256 == sum)
            && rg.have_snap("m2")
            && snap_bytes(&rg, "m2") == Some(m1),
        "the predecessor's snapshot isn't m2's"
    );
}

/// disk reports: shown like memory; a low disk is DMed once with the size More disk gives; More disk extends the
/// volume through the core (and needs a volume)
#[test]
fn disk_reports_warn_and_more_disk_extends() {
    let (rg, vc, _core) = vol_rig();
    let dms = capture_dm(&rg);
    rg.running_m2(false);
    let h = rg.machine_handler();
    let m = rg.machine("m2");
    let disk = |b: &str| m.do_(&h, "POST", "/m/disk", b).0;
    assert_eq!(
        disk(r#"{"root":{"totalKb":8000000,"availKb":4000000}}"#),
        200
    );
    assert_eq!(disk(r#"{"root":{"totalKb":0,"availKb":4}}"#), 400);
    // a machine without a volume: the next start gets the bigger disk
    let out = rg.more_disk("s1");
    assert!(
        out.as_ref().is_ok_and(|o| o["nextStart"] == true),
        "more disk without a volume: {out:?}"
    );
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.disk_gb = 0;
        }
    });
    disk(r#"{"root":{"totalKb":8000000,"availKb":200000}}"#);
    disk(r#"{"root":{"totalKb":8000000,"availKb":100000}}"#); // the same episode: no second DM
    let d = dms_of(&dms);
    assert!(
        d.len() == 1
            && d[0].contains("running out of disk: 0.2 GB free of 7.6 GB on its machine's disk")
            && d[0].contains("no volume"),
        "{d:?}"
    );
    rg.st.do_(|d| {
        let snapshot = d.clone();
        let s = d.sessions.get("s1").cloned().unwrap_or_default();
        let v = crate::http::session_view(&s, &snapshot);
        assert!(
            v.get("disk").is_some_and(|dk| dk["availMb"] == 97)
                && v.get("diskAlert").is_some_and(|a| a["canGrow"] == false),
            "view {:?} {:?}",
            v.get("disk"),
            v.get("diskAlert")
        );
    });
    // with a volume: the volume is the disk that counts, and More disk doubles it
    rg.running_m2(true);
    disk(
        r#"{"root":{"totalKb":8000000,"availKb":4000000},"data":{"totalKb":10485760,"availKb":300000}}"#,
    );
    let d = dms_of(&dms);
    assert!(
        d.len() == 2 && d[1].contains("on its volume") && d[1].contains("gives it 20 GB"),
        "{d:?}"
    );
    let out = rg.more_disk("s1");
    assert!(out.as_ref().is_ok_and(|o| o["toGb"] == 20), "{out:?}");
    wait_for("extended", || rg.session("s1").disk_gb == 20);
    let ext = vs(&vc, |x| x.extends.clone());
    assert!(
        ext.len() == 1 && ext[0]["machine"] == "m2" && ext[0]["sizeGb"] == 20,
        "extend {ext:?}"
    );
    // recovered: the episode ends
    disk(
        r#"{"root":{"totalKb":8000000,"availKb":4000000},"data":{"totalKb":20971520,"availKb":10000000}}"#,
    );
    rg.st.do_(|d| {
        let snapshot = d.clone();
        let s = d.sessions.get("s1").cloned().unwrap_or_default();
        let v = crate::http::session_view(&s, &snapshot);
        assert!(
            v.get("diskAlert").is_none_or(Value::is_null),
            "still alerted: {:?}",
            v.get("diskAlert")
        );
    });
}
