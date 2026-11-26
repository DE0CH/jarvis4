//! lostmachine_test.go: a machine that stopped without Jarvis doing it, on a kernel line (the whole kernel in-process)
use super::kernelline::{kdo, kernel_session, lost_rig, lost_rig_with};
use crate::testutil::*;
use std::collections::BTreeMap;

fn events_text(r: &crate::router::Router, sid: &str) -> String {
    r.session_events(sid, true, 0, 0, crate::sessionevents::EVENTS_READ_MAX)
        .events
        .iter()
        .map(|e| format!("{}\n", e.text))
        .collect()
}

/// a machine stopped outside Jarvis (fly machine stop): on the second look the session says so — when, Fly's event,
/// that the machine isn't started again, which snapshot Resume starts from and that work since it is lost — in its
/// error, its lost record, its events and /setup/sessions; Resume kills it into the line's next source (never starts it
/// again) and a new machine restores the newest signed snapshot. ✱ A machine gone from Fly the same way.
#[test]
fn a_machine_stopped_outside_jarvis_resumes_from_the_newest_snapshot() {
    use sha2::Digest;
    for destroyed in [false, true] {
        let (kr, sid, m1) = lost_rig_with(|c| c.no_access = true);
        let tarball = make_tar(&kr.files);
        let sum = hex::encode(sha2::Sha256::digest(&tarball));
        put_snap(&kr.t.r, &m1.id, &tarball, &m1.sig.sign(sum.as_bytes()));
        let mut seen = BTreeMap::new();
        kr.lost_tick(&mut seen);
        assert_eq!(
            kernel_session(&kr, &sid).state,
            "started",
            "a running machine was taken for lost"
        );
        if destroyed {
            jarvis_kernel::spawner::fly::Fly::destroy(&*kr.k.fly, &m1.id).unwrap_or_default(); // listed no more: "gone"
        } else {
            kr.k.fly.stop(&m1.id);
        }
        kr.lost_tick(&mut seen);
        assert_eq!(
            kernel_session(&kr, &sid).state,
            "started",
            "lost on one look"
        );
        kr.lost_tick(&mut seen);
        let s = kernel_session(&kr, &sid);
        let state = if destroyed { "gone" } else { "stopped" };
        assert!(
            s.state == "failed"
                && s.lost.as_ref().is_some_and(|l| l.fly_state == state)
                && s.failed_at.is_some(),
            "{} {:?}",
            s.state,
            s.lost
        );
        let what = if destroyed {
            "is gone from Fly outside Jarvis"
        } else {
            "stopped outside Jarvis at 2026-10-22 09:30:00 UTC"
        };
        for want in [
            format!("Its machine {} {what}", m1.id),
            "Fly: machine exit → stopped (user)".into(),
            "isn't started again (its keys were in its memory only)".into(),
            format!(
                "Resume starts a new machine from the newest signed snapshot (machine {}'s, from ",
                m1.id
            ),
            "what the session did after that snapshot is lost".into(),
        ] {
            assert!(s.error.contains(&want), "{:?} lacks {want:?}", s.error);
        }
        assert!(
            !s.error.contains("Nothing is lost") && !s.error.contains("volume"),
            "{}",
            s.error
        );
        wait_for("the event", || {
            let t = events_text(&kr, &sid);
            t.contains("Machine lost failed")
                && t.contains(&format!(": Its machine {} {what}", m1.id))
        });
        assert!(
            !events_text(&kr, &sid).contains("Session failed"),
            "the failure was written twice"
        );
        let (code, out) = inbox_do(&kr, "GET", "/setup/sessions", "", false);
        let row = out["sessions"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|x| x["id"] == sid.as_str())
            .cloned()
            .unwrap_or_default();
        let lost = &row["lost"];
        assert!(
            code == 200
                && row["error"] == s.error.as_str()
                && !row["failedAt"].is_null()
                && lost["resume"]
                    == s.lost
                        .as_ref()
                        .map(|l| l.resume.clone())
                        .unwrap_or_default()
                        .as_str()
                && lost["inPlace"].is_null()
                && lost["volume"].is_null(),
            "{code} {row}"
        );
        kr.lost_tick(&mut seen); // ✱ the next look leaves it alone
        kr.resume(&sid, false).unwrap_or_else(|e| panic!("{e:#}"));
        wait_for("a new machine", || {
            let s = kernel_session(&kr, &sid);
            !s.machine_id.is_empty()
                && s.machine_id != m1.id
                && s.kernel.as_ref().is_some_and(|k| k.machine_cert.is_some())
        });
        assert_eq!(
            kr.k.fly
                .machine(&m1.id)
                .map(|m| m.state)
                .unwrap_or_default(),
            "destroyed",
            "the lost machine wasn't killed"
        );
        let s = kernel_session(&kr, &sid);
        assert!(s.lost.is_none() && s.error.is_empty(), "{s:?}");
        let m2 =
            kr.k.fly
                .machine(&s.machine_id)
                .unwrap_or_else(|| panic!("no machine"));
        let (code, body) = kdo(&kr.machine_handler(), &m2, "GET", "/m/snapshot", "");
        assert!(
            code == 200 && body == tarball,
            "the newest snapshot: {code}"
        );
    }
}

/// ✱ a lost machine and no signed snapshot at all: the session says Resume refuses, and Resume does (it would start
/// empty)
#[test]
fn a_lost_machine_without_a_snapshot_is_refused() {
    let (kr, sid, m1) = lost_rig();
    kr.k.fly.stop(&m1.id);
    let mut seen = BTreeMap::new();
    kr.lost_tick(&mut seen);
    kr.lost_tick(&mut seen);
    let s = kernel_session(&kr, &sid);
    assert!(
        s.lost.is_some()
            && s.error.contains("There is no signed snapshot of the session, so Resume would start it empty and refuses"),
        "{:?} {}",
        s.lost,
        s.error
    );
    kr.resume(&sid, false).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the refusal", || {
        let s = kernel_session(&kr, &sid);
        s.state == "failed" && !s.no_snapshot.is_empty() && s.error.contains("it would start empty")
    });
    assert!(
        kr.k.fly
            .machine(&m1.id)
            .is_some_and(|m| m.state == "destroyed")
            && kernel_session(&kr, &sid).machine_id.is_empty(),
        "the lost machine wasn't killed, or a new one started"
    );
}

/// ✱ a machine Jarvis is pausing (its job holds the session) isn't lost; nor is one that is only stopping
#[test]
fn jarvis_own_stop_is_not_lost() {
    let (kr, sid, m1) = lost_rig();
    kr.k.fly.stop(&m1.id);
    let done = kr.lock(&sid, "pausing").unwrap_or_else(|e| panic!("{e:#}"));
    let mut seen = BTreeMap::new();
    kr.lost_tick(&mut seen);
    kr.lost_tick(&mut seen);
    done.call();
    let s = kernel_session(&kr, &sid);
    assert!(
        s.lost.is_none() && s.state != "failed",
        "Jarvis's own action taken for a lost machine"
    );
    use crate::lostmachine::machine_down;
    assert!(
        machine_down("gone") && !machine_down("stopping") && !machine_down("started"),
        "machine_down"
    );
}
