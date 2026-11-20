//! router/failedsession_test.go: a failed session comes back with one tap and can always be destroyed (Deyao,
//! 2026-10-15; DECISIONS 181): Resume of a failed session that still has a machine finishes its pause first; a kill
//! that failed on the way is tried again; a destroy goes past a snapshot the core refuses, a machine Fly no longer
//! has, and (Destroy anyway) any kill failure; the core calls that wait inside the running core outlast its own worst
//! case.
use crate::archive::{
    DESTROY_ANYWAY_HINT, FLY_MACHINE_GONE, SNAPSHOT_FROM_EARLIER_CORE, refused_snapshot,
};
use crate::core::core_call_timeout;
use crate::flows::{KILL_TRANSIENT_STEP_MS, KILL_TRANSIENT_TRIES};
use crate::machines::{FlyMachineDetail, orphan_refusal};
use crate::testutil::*;
use crate::types::Doc;
use jarvis_go::GoTime;
use serde_json::json;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// short kill retries (the step is global: the guard holds serial())
struct Fast {
    _step: U64Set,
    _s: std::sync::MutexGuard<'static, ()>,
}

fn fast_kills() -> Fast {
    let s = serial();
    Fast {
        _step: set_u64(&KILL_TRANSIENT_STEP_MS, 1),
        _s: s,
    }
}

fn call_order(vc: &V2Core) -> Vec<String> {
    vc.st
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .order
        .clone()
}

fn kill_errs(vc: &V2Core, errs: &[(u16, &str)]) {
    vc.st.lock().unwrap_or_else(|e| e.into_inner()).kill_errs =
        errs.iter().map(|(c, m)| (*c, m.to_string())).collect();
}

fn wait_idle(rg: &Rig) {
    wait_for("idle", || match rg.lock("s1", "test-end") {
        Ok(u) => {
            u.call();
            true
        }
        Err(_) => false,
    });
}

/// "Draft reply to image" (2026-10-15): its pause's kill timed out at Fly. One tap: the kill again, then the resume.
#[test]
fn resume_of_a_failed_session_with_a_machine_finishes_the_pause_first() {
    let _f = fast_kills();
    let (rg, vc) = Rig::v2();
    rg.failed_with_machine(
        r#"kill: core: fly destroy: Delete "…?force=true": context deadline exceeded"#,
    );
    kill_errs(
        &vc,
        &[(
            502,
            "fly destroy: context deadline exceeded (Client.Timeout exceeded while awaiting headers)",
        )],
    );
    rg.resume("s1", false).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the resume asked the core", || {
        vc.last("/approve/by-dead-machine").is_some()
    });
    let calls = call_order(&vc);
    let kills = calls.iter().filter(|c| *c == "/kill").count();
    let (succ, kill) = (
        calls.iter().position(|c| c == "/succession"),
        calls.iter().position(|c| c == "/kill"),
    );
    assert!(
        kills == 2 && succ > kill,
        "the kill (tried again) before the resume's challenge: {calls:?}"
    );
    let k = vc.last("/kill").unwrap_or_default();
    assert_eq!(
        k["snapshot"]["required"], true,
        "the finished pause's kill names the snapshot and keeps the machine without it: {k}"
    );
    let input = vc.last("/succession").unwrap_or_default();
    assert!(
        !input["predecessor"].is_null(),
        "the resume continues the line: {input}"
    );
    wait_idle(&rg);
    let s = rg.session("s1");
    assert_ne!(
        s.machine_id, "m1",
        "the killed machine is still the session's"
    );
}

/// a kill the core refuses (not a failure on the way) leaves the session failed with the error: nothing resumes
#[test]
fn resume_of_a_failed_session_whose_kill_is_refused_stays_failed() {
    let _f = fast_kills();
    let (rg, vc) = Rig::v2();
    rg.failed_with_machine("kill: core: the snapshot isn't signed by machine m1's current key");
    kill_errs(
        &vc,
        &[(403, "the snapshot isn't signed by machine m1's current key")],
    );
    rg.resume("s1", false).unwrap_or_else(|e| panic!("{e:#}"));
    wait_idle(&rg);
    let s = rg.session("s1");
    assert!(
        s.state == "failed"
            && s.error.contains("current key")
            && s.machine_id == "m1"
            && vc.last("/succession").is_none(),
        "{} {:?} {}, succession {:?}",
        s.state,
        s.error,
        s.machine_id,
        vc.last("/succession")
    );
    assert!(
        !s.error.contains("Destroy anyway"),
        "a resume's error offers Destroy anyway: {:?}",
        s.error
    );
}

#[test]
fn a_kill_that_failed_on_the_way_is_tried_again() {
    let _f = fast_kills();
    let (rg, vc) = Rig::v2();
    let input = json!({"machine": "m1"});
    kill_errs(
        &vc,
        &[
            (502, "fly destroy: timeout"),
            (502, "fly did not confirm m1 destroyed"),
        ],
    );
    rg.kill_until_destroyed(&input)
        .unwrap_or_else(|e| panic!("{e:#}"));
    // a refusal is final
    kill_errs(
        &vc,
        &[
            (403, "the snapshot isn't signed by machine m1's current key"),
            (502, "x"),
        ],
    );
    let err = rg.kill_until_destroyed(&input).err();
    assert!(
        err.as_ref().is_some_and(refused_snapshot),
        "a refusal tried again: {err:?}"
    );
    // and the tries end
    kill_errs(
        &vc,
        &[
            (502, "a"),
            (502, "b"),
            (502, "c"),
            (502, "d"),
            (502, "e"),
            (502, "f"),
        ],
    );
    assert!(
        rg.kill_until_destroyed(&input).is_err(),
        "killed after every try failed"
    );
}

fn destroyed(rg: &Rig) -> bool {
    rg.st.read(|d| {
        !d.sessions.contains_key("s1") && d.records.first().is_some_and(|x| x.session.id == "s1")
    })
}

/// Fly's answer about a machine, for this test (put back when dropped)
struct Gone;

impl Drop for Gone {
    fn drop(&mut self) {
        *FLY_MACHINE_GONE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

fn gone(f: fn(&str) -> anyhow::Result<bool>) -> Gone {
    *FLY_MACHINE_GONE.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
    Gone
}

fn fly_unreadable(_: &str) -> anyhow::Result<bool> {
    Err(anyhow::anyhow!("no Fly reader"))
}

fn fly_has_it(_: &str) -> anyhow::Result<bool> {
    Ok(false)
}

fn fly_lost_it(_: &str) -> anyhow::Result<bool> {
    Ok(true)
}

/// "Powerpoint generator" (2026-10-15): the core refuses the snapshot; a destroy restores nothing, so it kills without
/// it
#[test]
fn a_destroy_goes_past_a_refused_snapshot() {
    let _f = fast_kills();
    let _g = gone(fly_unreadable);
    let (rg, vc) = Rig::v2();
    rg.failed_with_machine("kill: core: the snapshot isn't signed by machine m1's current key");
    kill_errs(
        &vc,
        &[(403, "the snapshot isn't signed by machine m1's current key")],
    );
    let body = snap_bytes(&rg, "m1").unwrap_or_default();
    rg.destroy("s1").unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("destroyed", || destroyed(&rg));
    let kills = vc
        .st
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .bodies
        .get("/kill")
        .cloned()
        .unwrap_or_default();
    assert!(
        kills.len() == 2 && !kills[0]["snapshot"].is_null() && kills[1]["snapshot"].is_null(),
        "kills {kills:?}"
    );
    // the router's snapshot is archived as is, marked; a restore of it is refused for now
    let rec = rg
        .st
        .read(|d| d.records.first().cloned().unwrap_or_default());
    let arch = rec.archive.clone().unwrap_or_default();
    assert!(
        arch.unverified == SNAPSHOT_FROM_EARLIER_CORE
            && rec.session.snapshot_note == SNAPSHOT_FROM_EARLIER_CORE,
        "record {rec:?}"
    );
    let (files, _) = rg.dav.archive(&arch.file);
    let got = files
        .get("jarvis2/snapshot.tar.gz")
        .cloned()
        .unwrap_or_default();
    assert!(
        !body.is_empty() && got == body,
        "the snapshot isn't archived whole ({} of {} bytes)",
        got.len(),
        body.len()
    );
    let sj = String::from_utf8_lossy(files.get("session.json").map_or(&[][..], |v| v)).into_owned();
    assert!(
        sj.contains(&format!(
            r#""snapshotUnverified": "{SNAPSHOT_FROM_EARLIER_CORE}"#
        )),
        "session.json: {sj}"
    );
    // restorable like any archive: checked by the restore's own checks, not refused for its mark
    if let Err(e) = rg.restore_record("s1", "") {
        assert!(
            !format!("{e:#}").contains("waits for the core release"),
            "restore: {e:#}"
        );
    }
}

fn kills_keep_failing(vc: &V2Core) {
    let n = 2 * (usize::try_from(KILL_TRANSIENT_TRIES.load(Ordering::Relaxed)).unwrap_or(4) + 1);
    let errs: Vec<(u16, &str)> = (0..n)
        .map(|_| (502, "fly destroy: context deadline exceeded"))
        .collect();
    kill_errs(vc, &errs);
}

fn old_detail(id: &str, state: &str) -> FlyMachineDetail {
    FlyMachineDetail {
        id: id.into(),
        state: state.into(),
        created_at: GoTime::now().add(-time::Duration::hours(1)).utc().rfc3339(),
        ..Default::default()
    }
}

/// a destroy whose kill keeps failing: failed with the hint (the apps offer Destroy anyway), unless Fly says the
/// machine is gone; Destroy anyway destroys it and leaves the machine to the Machines tab
#[test]
fn a_destroy_whose_kill_keeps_failing() {
    let _f = fast_kills();
    {
        let _g = gone(fly_has_it);
        let (rg, vc) = Rig::v2();
        rg.failed_with_machine("kill: core: fly destroy: timeout");
        kills_keep_failing(&vc);
        let _ = rg.destroy("s1");
        wait_idle(&rg);
        let s = rg.session("s1");
        assert!(
            s.state == "failed"
                && s.error.starts_with("kill: ")
                && s.error.ends_with(DESTROY_ANYWAY_HINT),
            "{} {:?}",
            s.state,
            s.error
        );

        let (rg2, vc2) = Rig::v2();
        rg2.failed_with_machine("kill: …");
        kills_keep_failing(&vc2);
        rg2.destroy_with("s1", true)
            .unwrap_or_else(|e| panic!("{e:#}"));
        wait_for("destroyed anyway", || destroyed(&rg2));
        rg2.st.read(|d| {
            assert!(
                !d.started.contains_key("m1"),
                "the router still takes the abandoned machine's calls"
            );
            let why = orphan_refusal(d, &old_detail("m1", "stopped"), GoTime::now());
            assert!(
                why.is_empty(),
                "the abandoned machine can't be destroyed from the Machines tab: {why}"
            );
        });
    }
    let _g = gone(fly_lost_it);
    let (rg3, vc3) = Rig::v2();
    rg3.failed_with_machine("kill: …");
    kills_keep_failing(&vc3);
    let _ = rg3.destroy("s1");
    wait_for("destroyed: Fly has no such machine", || destroyed(&rg3));
}

/// a live session's machine is never an orphan; a paused one's destroyed machine isn't listed at all
#[test]
fn a_machine_of_a_live_session_is_no_orphan() {
    let (rg, _vc) = Rig::v2();
    rg.failed_with_machine("kill: …");
    rg.st.read(|d| {
        let why = orphan_refusal(d, &old_detail("m1", "started"), GoTime::now());
        assert!(why.contains("belongs to session s1"), "{why:?}");
    });
}

/// a machine the router started that no session names any more (its cert still kept) is an orphan Deyao may destroy
#[test]
fn an_unnamed_started_machine_is_an_orphan() {
    let (rg, _vc) = Rig::v2();
    rg.st.do_(|d| {
        d.certs.insert(
            "m-left".into(),
            Doc {
                payload: "{}".into(),
                sig: String::new(),
            },
        );
    });
    rg.st.read(|d| {
        let why = orphan_refusal(d, &old_detail("m-left", "stopped"), GoTime::now());
        assert!(why.is_empty(), "{why:?}");
    });
}

/// 2026-10-15 "start: core /start: … Client.Timeout exceeded": the running core waits inside /start and /kill for up
/// to ≈ 34 min; the router waits longer, so it always hears the core's answer
#[test]
fn the_router_outwaits_the_running_cores_start_and_kill() {
    let s = |n: u64| Duration::from_secs(n);
    let live_core_start = s(90) + s(10 * 90) + s(90) + s(10 * (90 + 3));
    let live_core_kill = s(90) + s(20 * (90 + 1));
    assert!(
        core_call_timeout("/start") > live_core_start
            && core_call_timeout("/kill") > live_core_kill,
        "start {:?} (core up to {live_core_start:?}), kill {:?} (core up to {live_core_kill:?})",
        core_call_timeout("/start"),
        core_call_timeout("/kill")
    );
    assert_eq!(
        core_call_timeout("/succession"),
        s(15 * 60),
        "other calls keep the default"
    );
}
