//! leases_test.go
use crate::leases::{
    LEASE_DEFAULT_TTL, LEASE_MIN_TTL, LeaseError, LeaseOpts, LeaseState, lease_granted_text,
    signed_prompt,
};
use crate::testutil::*;
use crate::vouch::{Delivery, attested};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const LT0: i64 = 1_790_000_000_000;

fn sp(s: &str) -> Option<String> {
    Some(s.to_string())
}

fn opts() -> LeaseOpts {
    LeaseOpts::default()
}

#[test]
fn lease_grant_renew_queue() {
    let mut st = LeaseState::default();
    let a = st
        .acquire(
            "wechat-phone",
            "A",
            &LeaseOpts {
                purpose: sp("map"),
                ..opts()
            },
            LT0,
        )
        .unwrap_or_else(|e| panic!("{e:#}"));
    let exp = |st: &LeaseState, n: &str| {
        st.resources
            .get(n)
            .and_then(|r| r.holder.as_ref())
            .map(|h| h.expires_at)
    };
    assert!(
        a.status == "granted" && exp(&st, "wechat-phone") == Some(LT0 + LEASE_DEFAULT_TTL * 1000),
        "{a:?}"
    );
    let again = st
        .acquire("wechat-phone", "A", &opts(), LT0 + 100_000)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        again.status == "renewed"
            && exp(&st, "wechat-phone") == Some(LT0 + 100_000 + LEASE_DEFAULT_TTL * 1000),
        "{again:?}"
    );
    let _ = st.acquire("p", "A", &opts(), LT0);
    let o = st
        .acquire(
            "p",
            "B",
            &LeaseOpts {
                prompt: "go B".into(),
                ..opts()
            },
            LT0,
        )
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(o.status == "queued" && o.position == 1, "{o:?}");
    let o = st
        .acquire("p", "C", &opts(), LT0)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(o.position, 2);
    let o = st
        .acquire("p", "B", &opts(), LT0)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(o.position, 1, "re-queueing keeps the place");
    let o = st
        .acquire(
            "p",
            "W",
            &LeaseOpts {
                low_priority: true,
                ..opts()
            },
            LT0,
        )
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(o.status, "busy", "low priority is never queued");
    let q: Vec<String> = st.resources["p"]
        .queue
        .iter()
        .map(|e| e.sid.clone())
        .collect();
    assert_eq!(q, vec!["B", "C"]);
    assert!(
        st.acquire("Bad Name", "A", &opts(), LT0).is_err(),
        "bad name"
    );
    // only the holder renews; a renew pushes the expiry by the lease's own ttl
    let _ = st.acquire(
        "q",
        "A",
        &LeaseOpts {
            ttl: Some(json!(120)),
            ..opts()
        },
        LT0,
    );
    let e = st
        .renew("q", "B", LT0)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(e.contains("does not hold"), "{e}");
    let o = st
        .renew("q", "A", LT0 + 100_000)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(
        o.lease["holder"]["expiresAt"],
        json!(LT0 + 220_000),
        "{}",
        o.lease
    );
    // ttl is clamped
    let _ = st.acquire(
        "r",
        "A",
        &LeaseOpts {
            ttl: Some(json!(5)),
            ..opts()
        },
        LT0,
    );
    assert_eq!(
        st.resources["r"].holder.as_ref().map(|h| h.ttl),
        Some(LEASE_MIN_TTL),
        "ttl clamp"
    );
}

#[test]
fn lease_return_promotes_and_notifies_once() {
    let mut st = LeaseState::default();
    let _ = st.acquire("p", "A", &opts(), LT0);
    let _ = st.acquire(
        "p",
        "B",
        &LeaseOpts {
            prompt: "carry on with the map".into(),
            ttl: Some(json!(600)),
            ..opts()
        },
        LT0,
    );
    assert!(
        st.give_back("p", "B", LT0, false).is_err(),
        "a waiter can't return it"
    );
    let out = st
        .give_back("p", "A", LT0 + 5000, false)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(
        out.promoted.as_ref().map(|p| p.sid.as_str()),
        Some("B"),
        "{out:?}"
    );
    let h = st.resources["p"].holder.clone().unwrap_or_default();
    assert!(
        h.sid == "B" && h.expires_at == LT0 + 5000 + 600_000 && h.prompt == "carry on with the map",
        "{h:?}"
    );
    let p = st.pending_notifications();
    assert!(
        p.len() == 1 && p[0].sid == "B" && p[0].since == LT0 + 5000 && p[0].ttl == 600,
        "{p:?}"
    );
    st.mark_notified("p", "B", LT0 + 5000);
    assert!(st.pending_notifications().is_empty(), "notified once");
    let _ = st.give_back("p", "B", LT0 + 10_000, false);
    assert!(st.resources["p"].holder.is_none(), "free");
    // leave the queue; force return
    for s in ["A", "B", "C"] {
        let _ = st.acquire("x", s, &opts(), LT0);
    }
    assert!(st.leave("x", "B").unwrap_or(false), "leave");
    let f = st
        .give_back("x", "", LT0, true)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        f.previous == "A" && f.promoted.as_ref().is_some_and(|p| p.sid == "C"),
        "{f:?}"
    );
}

#[test]
fn lease_sweep() {
    let mut st = LeaseState::default();
    let _ = st.acquire(
        "p",
        "A",
        &LeaseOpts {
            ttl: Some(json!(60)),
            ..opts()
        },
        LT0,
    );
    let _ = st.acquire("p", "GONE", &opts(), LT0);
    let _ = st.acquire("p", "B", &opts(), LT0);
    assert!(st.sweep(LT0 + 30_000, &|_| true).is_empty());
    let ch = st.sweep(LT0 + 61_000, &|s| s != "GONE");
    assert!(
        ch.len() == 1
            && ch[0].expired == "A"
            && ch[0].promoted.as_ref().is_some_and(|p| p.sid == "B"),
        "the gone waiter is skipped: {ch:?}"
    );
    let ch = st.sweep(LT0 + 62_000, &|s| s != "B");
    assert!(
        ch.len() == 1
            && ch[0].expired == "B"
            && ch[0].promoted.is_none()
            && st.resources["p"].holder.is_none(),
        "a gone holder is freed before expiry: {ch:?}"
    );
    assert!(st.resources.contains_key("p"), "kept: its log is the trail");
    // the known devices are always listed
    let l = st.list(LT0);
    assert!(
        l.len() >= 3
            && l[0]["name"] == "wechat-phone"
            && l[1]["name"] == "iphone"
            && l[2]["name"] == "mac",
        "{l:?}"
    );
}

#[test]
fn lease_take_over_hand_back() {
    let mut st = LeaseState::default();
    let _ = st.acquire(
        "iphone",
        "A",
        &LeaseOpts {
            purpose: sp("pay"),
            prompt: "finish paying".into(),
            ..opts()
        },
        LT0,
    );
    let _ = st.acquire("iphone", "B", &opts(), LT0);
    let out = st
        .take_over("iphone", Some("need it myself"), LT0 + 1000)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(out.taken && out.interrupted == "A", "{out:?}");
    {
        let r = &st.resources["iphone"];
        let h = r.holder.clone().unwrap_or_default();
        assert!(
            h.human
                && h.expires_at == 0
                && r.queue[0].sid == "A"
                && r.queue[0].interrupted
                && r.queue[0].prompt == "finish paying"
                && r.queue[1].sid == "B",
            "{h:?} {:?}",
            r.queue
        );
    }
    // he never expires
    assert!(
        st.sweep(LT0 + 100 * 3600 * 1000, &|_| true).is_empty(),
        "Deyao's hold doesn't expire"
    );
    // an agent's renew is refused with his note, and it is recorded to be told
    let err = st
        .renew("iphone", "C", LT0 + 2000)
        .err()
        .unwrap_or_else(|| anyhow::anyhow!("none"));
    let le = err.downcast_ref::<LeaseError>();
    assert!(
        le.is_some_and(|le| le.taken_over && le.msg.contains("need it myself")),
        "{err:#}"
    );
    let again = st
        .take_over("iphone", Some("long term"), LT0 + 3000)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        again.note_updated
            && st.resources["iphone"]
                .holder
                .as_ref()
                .is_some_and(|h| h.note == "long term"),
        "a take-over while he has it only updates the note"
    );
    let hb = st
        .hand_back("iphone", "left WeChat open", LT0 + 4000)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        hb.handed_back
            && hb.promoted.as_ref().is_some_and(|p| p.sid == "A")
            && hb.notify == vec!["C"],
        "{hb:?}"
    );
    let p = st.pending_notifications();
    assert!(p.len() == 1 && p[0].handover && p[0].interrupted, "{p:?}");
}

#[test]
fn lease_texts_match_the_machine() {
    // rust/machine/src/tests/vouch.rs checks the same strings
    let got = lease_granted_text("mac", 60, false, false, "go on");
    let want = r#"[lease "mac" granted] This session now holds the shared device "mac" (you were queued for it). It is yours for 60 min, renewed automatically by the device helpers on every action; return it when done (scripts/lease.py return mac). The previous holder may have left it in any state: inspect it first. Your note: go on"#;
    assert_eq!(got, want);
}

#[test]
fn lease_api() {
    let r = new_test_router();
    add_session(&r, "sA", "started", "mA", false);
    add_session(&r, "sB", "paused", "", false);
    add_session(&r, "sC", "started", "mC", false);
    let (ma, mc) = (new_test_machine(&r, "mA"), new_test_machine(&r, "mC"));
    let h = r.machine_handler();
    let got: Arc<Mutex<Vec<Delivery>>> = Arc::default();
    {
        let g = got.clone();
        *r.deliver_hook.write().unwrap_or_else(|e| e.into_inner()) =
            Some(Arc::new(move |_, sid, mut d| {
                d.id = sid.to_string();
                g.lock().unwrap_or_else(|e| e.into_inner()).push(d);
                Ok(())
            }));
    }
    let n_got = || got.lock().unwrap_or_else(|e| e.into_inner()).len();

    let (code, out) = ma.do_(
        &h,
        "POST",
        "/m/api/sessions/sA/leases/mac",
        r#"{"purpose":"screen","description":"step 1"}"#,
    );
    assert!(code == 200 && out["status"] == "granted", "{code} {out}");
    let (code, _) = ma.do_(&h, "POST", "/m/api/sessions/sC/leases/mac", "{}");
    assert_eq!(code, 403, "another session's path");
    let (code, out) = mc.do_(
        &h,
        "POST",
        "/m/api/sessions/sC/leases/mac",
        r#"{"purpose":"wait","prompt":"continue the  build"}"#,
    );
    assert!(
        code == 200 && out["status"] == "queued" && out["position"] == 1,
        "{code} {out}"
    );
    let (code, out) = mc.do_(
        &h,
        "POST",
        "/m/api/sessions/sC/leases/iphone",
        r#"{"lowPriority":true}"#,
    );
    assert!(code == 200 && out["status"] == "granted", "{code} {out}");
    let (code, out) = ma.do_(
        &h,
        "POST",
        "/m/api/sessions/sA/leases/iphone",
        r#"{"lowPriority":true}"#,
    );
    assert!(code == 409 && out["status"] == "busy", "{code} {out}");
    let (code, _) = mc.do_(&h, "PUT", "/m/api/sessions/sC/leases/mac", "");
    assert_eq!(code, 409, "a waiter can't renew");
    let (code, out) = ma.do_(
        &h,
        "PATCH",
        "/m/api/sessions/sA/leases/mac",
        r#"{"description":"step 2"}"#,
    );
    assert!(code == 200 && out["status"] == "holder", "{code} {out}");
    let (code, out) = ma.do_(&h, "GET", "/m/api/leases/mac", "");
    let l = &out["lease"];
    assert!(
        code == 200
            && l["holder"]["description"] == "step 2"
            && l["queue"].as_array().is_some_and(|q| q.len() == 1),
        "{code} {out}"
    );
    // returning promotes C and wakes it with its own signed acquire
    let (code, out) = ma.do_(&h, "DELETE", "/m/api/sessions/sA/leases/mac", "");
    assert!(
        code == 200 && out["returned"] == true && out["next"] == "sC",
        "{code} {out}"
    );
    r.lease_tick();
    wait_for("leases", || n_got() == 1);
    let d = got.lock().unwrap_or_else(|e| e.into_inner())[0].clone();
    assert!(
        d.id == "sC"
            && d.kind == "lease-granted"
            && d.device == "mac"
            && d.minutes == 60
            && d.request.is_some()
            && signed_prompt(d.request.as_ref()) == "continue the build",
        "{d:?}"
    );
    wait_for("leases", || {
        !r.lease_list().is_empty()
            && r.lease_tx(|st| Ok(st.pending_notifications().len()))
                .unwrap_or(1)
                == 0
    });
    // the attestation's input is the text the machine builds
    let (inp, origin) = attested(&d).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        origin == "session-signed:mC"
            && String::from_utf8_lossy(&inp).ends_with("Your note: continue the build"),
        "{} {origin}",
        String::from_utf8_lossy(&inp)
    );

    // the app: take over (C is told), hand back (A, who looked meanwhile, is told), force return
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/leases/mac/take-over",
        r#"{"note":"mine"}"#,
        &[],
    );
    assert!(code == 200 && out["interrupted"] == "sC", "{code} {out}");
    let (code, out) = ma.do_(&h, "POST", "/m/api/sessions/sA/leases/mac/seen", "{}");
    assert!(code == 200 && out["takenOver"] == true, "{code} {out}");
    let (code, out) = app_do(
        &r,
        "POST",
        "/api/leases/mac/hand-back",
        r#"{"note":"done"}"#,
        &[],
    );
    assert!(
        code == 200
            && out["next"] == "sC"
            && out["notified"].as_array().is_some_and(|n| n.len() == 1),
        "{code} {out}"
    );
    r.lease_tick();
    wait_for("leases", || n_got() >= 4);
    let all = got.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut kinds = std::collections::BTreeSet::new();
    for d in &all[1..] {
        kinds.insert(format!("{} {}", d.id, d.kind));
        if d.kind == "lease-granted" {
            assert!(d.handover && d.interrupted, "{d:?}");
        }
    }
    assert!(
        kinds.contains("sC lease-taken")
            && kinds.contains("sA lease-back")
            && kinds.contains("sC lease-granted"),
        "{kinds:?}"
    );
    let (code, out) = app_do(&r, "POST", "/api/leases/mac/force-return", "", &[]);
    assert!(code == 200 && out["previous"] == "sC", "{code} {out}");
    // the setup session can take over and hand back for Deyao
    let (code, out) = app_do(
        &r,
        "POST",
        "/setup/leases/iphone/take-over",
        r#"{"note":"long term"}"#,
        &[],
    );
    assert!(code == 200 && out["taken"] == true, "{code} {out}");
    let (code, out) = app_do(&r, "GET", "/api/leases/iphone", "", &[]);
    assert!(
        code == 200 && out["lease"]["holder"]["note"] == "long term",
        "{code} {out}"
    );
    // /api/state lists them; a destroyed session's queue place goes at the next tick
    let _ = ma.do_(&h, "POST", "/m/api/sessions/sA/leases/wechat-phone", "{}");
    let _ = mc.do_(&h, "POST", "/m/api/sessions/sC/leases/wechat-phone", "{}");
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sC") {
            s.state = "destroyed".into();
        }
    });
    r.lease_tick();
    let (code, out) = app_do(&r, "GET", "/api/leases/wechat-phone", "", &[]);
    assert!(
        code == 200 && out["lease"]["queue"].as_array().is_some_and(Vec::is_empty),
        "{code} {out}"
    );
    let _: Value = out;
}

/// describing a lease the session neither holds nor waits for changes nothing and isn't refused
#[test]
fn lease_describe_with_nothing_held() {
    let mut st = LeaseState::default();
    let _ = st.acquire(
        "p",
        "A",
        &LeaseOpts {
            purpose: sp("map"),
            ..opts()
        },
        LT0,
    );
    let o = st
        .describe(
            "p",
            "B",
            &LeaseOpts {
                purpose: sp("other"),
                ..opts()
            },
            LT0,
        )
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        o.status == "none"
            && st.resources["p"]
                .holder
                .as_ref()
                .is_some_and(|h| h.sid == "A"),
        "{o:?}"
    );
}
