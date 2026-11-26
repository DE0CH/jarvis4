//! resumefallback_test.go: a resume the core won't answer by itself becomes the resume-upgrade approval in the
//! Inbox (Deyao, 2026-10-15), and an approved API call's review sheet follows the core requests the call brings about
//! (apicalls.rs follow-ups).
use crate::router::Config;
use crate::state::Approval;
use crate::testutil::*;
use serde_json::Value;
use std::time::Duration;

const REFUSED_SAME: &str =
    "store set, image or options differ from the predecessor's (or a one-time input is asked for)";

fn bare_image() -> String {
    format!("ghcr.io/de0ch/jarvis4-session@sha256:{}", "1".repeat(64))
}

fn pinned_of_it() -> String {
    format!(
        "ghcr.io/de0ch/jarvis4-session:sha-0123456789ab@sha256:{}",
        "1".repeat(64)
    )
}

fn newest_image() -> String {
    format!(
        "ghcr.io/de0ch/jarvis4-session:sha-ba9876543210@sha256:{}",
        "2".repeat(64)
    )
}

fn succession_images(vc: &V2Core) -> Vec<String> {
    vc.st
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .bodies
        .get("/succession")
        .map(|b| {
            b.iter()
                .map(|x| x["image"].as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn set_refuse(vc: &V2Core, why: &str) {
    vc.st.lock().unwrap_or_else(|e| e.into_inner()).refuse = why.into();
}

/// the rig on a v2 core whose session image is the newest and whose order knows CI's pin; with f's config too
fn pin_rig(f: impl FnOnce(&mut Config)) -> (Rig, V2Core) {
    Rig::v2_with(|c| {
        c.session_image = newest_image();
        c.image_order = vec![pinned_of_it(), newest_image()];
        f(c);
    })
}

/// s1 paused on CI's pin: the session row names the pin; the cert names what Fly reported (repo@digest), the core
/// compares the cert's
fn paused_on_a_pin(rg: &Rig) {
    let cert = rg.v2_cert("m1", r#"{"v":1}"#);
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.cert = Some(cert.clone());
            s.image = pinned_of_it();
        }
    });
}

fn approval_of(rg: &Rig, sid: &str) -> Option<Approval> {
    rg.st
        .read(|d| d.approvals.values().find(|a| a.session == sid).cloned())
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

/// the root cause of 2026-10-15: an unattended resume must name the cert's own image string, not CI's pinned ref
#[test]
fn an_unattended_resume_names_the_certs_own_image() {
    let (rg, vc) = pin_rig(|_| {});
    paused_on_a_pin(&rg);
    rg.resume("s1", false).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("dead-machine asked", || {
        vc.last("/approve/by-dead-machine").is_some()
    });
    let imgs = succession_images(&vc);
    assert_eq!(
        imgs,
        [bare_image()],
        "the unattended resume named {imgs:?}, not the cert's"
    );
    assert!(
        approval_of(&rg, "s1").is_none(),
        "an approval for an unattended resume"
    );
    wait_idle(&rg);
}

#[test]
fn a_refused_resume_becomes_the_resume_upgrade_approval() {
    let (rg, vc) = pin_rig(|_| {});
    paused_on_a_pin(&rg);
    set_refuse(&vc, REFUSED_SAME);
    rg.resume("s1", false).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("approval", || approval_of(&rg, "s1").is_some());
    let a = approval_of(&rg, "s1").unwrap_or_default();
    assert_eq!(a.kind, "resume-upgrade", "{a:?}");
    // the phone's challenge names the same image, as CI pinned (and signed) it
    let imgs = succession_images(&vc);
    assert_eq!(imgs, [bare_image(), pinned_of_it()], "challenges");
    let s = rg.session("s1");
    assert!(
        s.state == "approval" && s.error.is_empty(),
        "session {} {:?}",
        s.state,
        s.error
    );
    // any other refusal stays an error on the paused session (nothing the phone should be asked)
    let (rg2, vc2) = pin_rig(|_| {});
    paused_on_a_pin(&rg2);
    set_refuse(&vc2, "predecessor is not a killed, unused machine");
    let _ = rg2.resume("s1", false);
    wait_for("paused with the error", || {
        let s = rg2.session("s1");
        s.state == "paused" && s.error.contains("killed, unused")
    });
    assert!(
        approval_of(&rg2, "s1").is_none(),
        "an approval for another refusal"
    );
}

fn call(rg: &Rig, m: &TestMachine, explanation: &str) -> String {
    let (code, out) = m.do_(
        &rg.machine_handler(),
        "POST",
        "/m/api/actions/requests/call",
        &format!(r#"{{"method": "POST", "path": "/api/sessions/s1/resume", "explanation": "{explanation}"}}"#),
    );
    assert_eq!(code, 200, "{out}");
    out["id"].as_str().unwrap_or_default().to_string()
}

/// the session actions' resume (and the app's) reach the same fallback; a resume through an approved API call links
/// its approval to the call, so the call's review sheet shows it
#[test]
fn an_approved_resume_call_follows_its_approval() {
    let (rg, vc) = pin_rig(|c| c.no_access = true);
    let r = rg.t.r.clone();
    paused_on_a_pin(&rg);
    set_refuse(&vc, REFUSED_SAME);
    add_session(&r, "sR", "started", "mR", false);
    let m = new_test_machine(&r, "mR");
    let id = call(&rg, &m, "carry on with s1");
    let (code, out) = inbox_do(&r, "POST", &format!("/api/requests/{id}/approve"), "", true);
    assert!(
        code == 200 && out["state"] == "done",
        "approve: {code} {out}"
    );
    // right after Approve the sheet knows either the approval or that one may still come, and until when
    let fs = out["followups"].as_array().map_or(0, Vec::len);
    assert!(
        fs > 0 || !out["awaiting"].is_null(),
        "approve answered neither follow-ups nor awaiting: {out}"
    );
    wait_for("the follow-up", || {
        r.call_followups_of(&id)
            .is_some_and(|f| f.followups.len() == 1)
    });
    let f = r.call_followups_of(&id).unwrap_or_default();
    let fu = &f.followups[0];
    assert!(
        fu.open
            && fu
                .item
                .as_ref()
                .is_some_and(|it| it.kind == "resume-upgrade"
                    && it.session == "s1"
                    && it.via_call == id)
            && f.awaiting.is_none(),
        "{f:?}"
    );
    let (code, out) = inbox_do(&r, "GET", &format!("/api/requests/calls/{id}"), "", true);
    assert!(
        code == 200 && out["followups"].as_array().map_or(0, Vec::len) == 1,
        "{code} {out}"
    );
    // answered (here: denied) → the sheet sees it gone
    r.reject(&fu.id).unwrap_or_else(|e| panic!("{e:#}"));
    let f = r.call_followups_of(&id).unwrap_or_default();
    assert!(!f.followups[0].open, "{f:?}");
    assert_eq!(
        inbox_do(&r, "GET", "/api/requests/calls/nope", "", true).0,
        404,
        "unknown call"
    );
}

/// a resume the core answers by itself brings nothing about: the call's wait ends without a follow-up
#[test]
fn an_approved_resume_call_with_nothing_to_follow() {
    let (rg, _vc) = pin_rig(|c| c.no_access = true);
    let r = rg.t.r.clone();
    paused_on_a_pin(&rg);
    add_session(&r, "sR", "started", "mR", false);
    let m = new_test_machine(&r, "mR");
    let id = call(&rg, &m, "carry on");
    let (code, out) = inbox_do(&r, "POST", &format!("/api/requests/{id}/approve"), "", true);
    assert!(code == 200 && out["state"] == "done", "{code} {out}");
    wait_for("settled", || {
        r.call_followups_of(&id)
            .is_some_and(|f| f.awaiting.is_none())
    });
    let f = r.call_followups_of(&id).unwrap_or_default();
    assert!(f.followups.is_empty(), "{f:?}");
    wait_idle(&rg);
}

/// a call that fails waits for nothing
#[test]
fn a_failed_call_awaits_nothing() {
    let (rg, _vc) = Rig::v2_with(|c| c.no_access = true);
    let r = rg.t.r.clone();
    add_session(&r, "sR", "started", "mR", false);
    let m = new_test_machine(&r, "mR");
    // s1 is being destroyed: the resume is refused at once
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.state = "destroying".into();
        }
    });
    let id = call(&rg, &m, "x");
    let (code, out) = inbox_do(&r, "POST", &format!("/api/requests/{id}/approve"), "", true);
    assert!(
        code == 200 && out["status"].as_i64().unwrap_or(0) >= 400 && out["awaiting"].is_null(),
        "{code} {out}"
    );
}

/// a failed session with no machine comes back with Resume: a failed start of a resume (the line is intact) like a
/// paused one, and a refusal of it reaches the phone
#[test]
fn a_failed_start_resumes() {
    let (rg, vc) = pin_rig(|_| {});
    paused_on_a_pin(&rg);
    set_refuse(&vc, REFUSED_SAME);
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.state = "failed".into();
            s.error = "start: core /start: context deadline exceeded".into();
        }
    });
    rg.resume("s1", false).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("approval", || approval_of(&rg, "s1").is_some());
    let a = approval_of(&rg, "s1").unwrap_or_default();
    assert_eq!(a.kind, "resume-upgrade", "{a:?}");
    // (a failed session that still has a machine finishes its pause first: failedsession.rs)
}

/// a new line whose first start failed gets its new-session approval again; Deny leaves it failed
#[test]
fn a_failed_new_line_starts_again() {
    let (rg, vc) = Rig::v2_with(|c| c.session_image = newest_image());
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.cert = None;
            s.state = "failed".into();
            s.error = "the start was cut off by a router crash: start it again".into();
            s.prompt = "do the thing".into();
            s.label = "Jarvis 4".into();
        }
    });
    rg.resume("s1", false).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("approval", || approval_of(&rg, "s1").is_some());
    let a = approval_of(&rg, "s1").unwrap_or_default();
    assert!(a.kind == "new-session" && a.again, "{a:?}");
    let input = vc.last("/succession").unwrap_or_default();
    assert!(
        input["predecessor"].is_null() && input["image"] == newest_image().as_str(),
        "challenge {input}"
    );
    assert!(
        input["options"]["config"]
            .as_str()
            .is_some_and(|c| c.contains("do the thing")),
        "config {}",
        input["options"]
    );
    rg.reject(&a.id).unwrap_or_else(|e| panic!("{e:#}"));
    // failed, and the start's thread ended (else it still writes into the test's dir as it is removed)
    rg.wait_state("s1", "failed", Duration::from_secs(5))
        .unwrap_or_else(|e| panic!("after Deny: {e:#}"));
}

/// Restart {upgrade: true}: the resume after the pause goes on the newest image, through its resume-upgrade approval
/// (how a fixed supervisor reaches a running session in one Inbox ask)
#[test]
fn restart_with_upgrade_asks_for_the_newest_image() {
    let (rg, _vc) = pin_rig(|c| c.no_access = true);
    paused_on_a_pin(&rg);
    let (code, out) = app_do(
        &rg,
        "POST",
        "/api/sessions/s1/restart",
        r#"{"upgrade":true}"#,
        &[],
    );
    assert!(code == 202 && out["upgrade"] == true, "{code} {out}");
    wait_for("approval", || approval_of(&rg, "s1").is_some());
    let a = approval_of(&rg, "s1").unwrap_or_default();
    assert_eq!(a.kind, "resume-upgrade", "{a:?}");
    wait_for("job finished", || {
        rg.ops
            .job_view("s1")
            .is_some_and(|j| !j.get("finishedAt").unwrap_or(&Value::Null).is_null())
    });
}
