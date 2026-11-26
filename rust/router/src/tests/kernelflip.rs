//! kernelflip_test.go: a kernel release (a copy flip) through the router and the whole kernel in-process
use super::kernelline::{KRig, kdo, kernel_rig, kernel_session};
use crate::kernelflip::KernelFlip;
use crate::roster::{KERNEL_ROLES, RosterCurrent};
use crate::testutil::*;
use jarvis_doc::gv;
use jarvis_sig::{Identity, Roster};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// the copy's roster as the setup session files it and Deyao signs it, taken by the router
fn sign_roster(kr: &KRig, copy: &str) -> Value {
    let d = kr.k.roster_for(copy).unwrap_or_else(|e| panic!("{e:#}"));
    kr.take_roster(&d.payload, &d.sig)
        .unwrap_or_else(|(code, e)| panic!("{code} {e:#}"))
}

fn start(kr: &KRig, label: &str) -> String {
    let sid = kr
        .create_session(crate::flows::NewSession {
            label: label.into(),
            harness: "claude".into(),
            ..Default::default()
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    let a = super::kernelline::approval_of(kr, &sid);
    let sig = kr.k.phone.sign(super::kernelline::challenge(&a).as_bytes());
    kr.respond(&a.id, &sig).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the machine", || {
        let s = kernel_session(kr, &sid);
        !s.machine_id.is_empty() && s.kernel.as_ref().is_some_and(|k| k.machine_cert.is_some())
    });
    sid
}

fn pause(kr: &KRig, sid: &str) {
    kr.pause(sid).unwrap_or_else(|e| panic!("{e:#}"));
    kr.wait_action_end(sid, "paused")
        .unwrap_or_else(|e| panic!("{e:#} {}", kernel_session(kr, sid).error));
}

/// a kernel release never interrupts anything: a live session on blue; a release onto green; green's roster signed
/// (one Face ID) and the router flips by itself — every blue component hands over and freezes, green's notarizer,
/// spawner and secrets take over, every call goes to green; the session's machine, booted on blue, reads its documents
/// (blue's grant, certs and notarizations under green's roster) and pulls its secrets; it pauses (green's spawner kills
/// the machine blue's made), resumes onto a new machine and pulls; a new session starts; and a router that restarted
/// mid-flip carries the flip on from where it was kept
#[test]
fn a_kernel_release_flips_without_interruption() {
    use sha2::Digest;
    let mut kr = kernel_rig();
    let sid = start(&kr, "lives through a release");
    let m1 =
        kr.k.fly
            .machine(&kernel_session(&kr, &sid).machine_id)
            .unwrap_or_else(|| panic!("no machine"));
    let h = kr.machine_handler();
    let (code, body) = kdo(&h, &m1, "POST", "/m/pull-secrets", "{}");
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let blue_grant = kernel_session(&kr, &sid)
        .kernel
        .and_then(|k| k.grant)
        .unwrap_or_else(|| panic!("no grant"));

    kr.k.release();
    let out = sign_roster(&kr, "green");
    assert_eq!(
        out["flip"], "green",
        "the green roster didn't start the flip: {out}"
    );
    wait_for("the flip", || kr.serving_copy() == "green");
    kr.k.serve("green"); // (kerneltest's view follows the router's)
    let (rest, cur) = kr
        .st
        .do_(|p| (p.kernel_flip.clone(), p.kernel_roster.clone()));
    let cur = cur.unwrap_or_else(|| panic!("no roster"));
    assert!(
        rest.is_none() && cur.copy == "green",
        "after the flip: {rest:?} {cur:?}"
    );
    for (dep, path) in [
        ("notarizer-blue", "/notarize"),
        ("spawner-blue", "/init"),
        ("mover-blue", "/move"),
    ] {
        let e =
            kr.k.post(dep, path, &json!({}))
                .err()
                .map(|e| format!("{e:#}"))
                .unwrap_or_default();
        assert!(e.contains("handed over"), "{dep} after the flip: {e}");
    }

    // the live machine: its documents check against green's roster, and it pulls
    let (code, body) = kdo(&h, &m1, "GET", "/m/kernel/boot", "");
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let boot: Value = serde_json::from_slice(&body).unwrap_or_default();
    let notary: Identity = serde_json::from_value(boot["notary"].clone()).unwrap_or_default();
    assert!(
        boot["roster"]["payload"] == cur.payload.as_str() && notary == kr.k.identity("notary"),
        "{boot}"
    );
    let g: gv::Signed =
        serde_json::from_value(boot["grant"].clone()).unwrap_or_else(|e| panic!("{e}"));
    let g = gv::open(&g, &kr.k.trust())
        .unwrap_or_else(|e| panic!("blue's grant under green's roster: {e}"));
    assert_eq!(g.machine.0, format!("fly-{}", m1.id));
    let (code, body) = kdo(&h, &m1, "POST", "/m/pull-secrets", "{}");
    assert_eq!(
        code,
        200,
        "a pull after the flip: {}",
        String::from_utf8_lossy(&body)
    );

    // pause and resume on green
    let tarball = make_tar(&kr.files);
    let sum = hex::encode(sha2::Sha256::digest(&tarball));
    put_snap(&kr.t.r, &m1.id, &tarball, &m1.sig.sign(sum.as_bytes()));
    pause(&kr, &sid);
    assert_eq!(
        kr.k.fly
            .machine(&m1.id)
            .map(|m| m.state)
            .unwrap_or_default(),
        "destroyed",
        "blue's machine wasn't killed by green's spawner"
    );
    let g = kernel_session(&kr, &sid).kernel.and_then(|k| k.grant);
    assert!(
        g.as_ref()
            .and_then(|g| g.signer.as_ref())
            .map(|s| s.signing_key.clone())
            != blue_grant.signer.as_ref().map(|s| s.signing_key.clone()),
        "the paused line's grant isn't green's mover's"
    );
    kr.resume(&sid, false).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the second machine", || {
        let s = kernel_session(&kr, &sid);
        !s.machine_id.is_empty()
            && s.machine_id != m1.id
            && s.kernel.as_ref().is_some_and(|k| k.machine_cert.is_some())
    });
    let m2 =
        kr.k.fly
            .machine(&kernel_session(&kr, &sid).machine_id)
            .unwrap_or_else(|| panic!("no machine"));
    let (code, body) = kdo(&h, &m2, "GET", "/m/snapshot", "");
    assert!(
        code == 200 && body == tarball,
        "the predecessor's snapshot: {code}"
    );
    let (code, body) = kdo(&h, &m2, "POST", "/m/pull-secrets", "{}");
    assert_eq!(
        code,
        200,
        "the resumed machine's pull: {}",
        String::from_utf8_lossy(&body)
    );

    // a new session starts on green
    start(&kr, "after the release");

    // the next release lands on blue. The router died mid-flip: green's notarizer and spawner had handed over and blue's
    // notarizer had taken over, but only the two handoffs were kept. The kept flip carries on: a try that can't reach
    // secrets-blue keeps what it did; the next finishes (blue's notarizer answers the same handoff again)
    kr.k.release();
    let d = kr.k.roster_for("blue").unwrap_or_else(|e| panic!("{e:#}"));
    let ro: Roster = serde_json::from_str(&d.payload).unwrap_or_default();
    assert!(
        ro.retired.len() >= 2 * 8,
        "blue's roster retires green's members and the keys green still needs: {}",
        ro.retired.len()
    );
    let results = kr.distribute_roster(&d, "blue");
    kr.st.do_(|p| {
        p.kernel_roster_next = Some(RosterCurrent {
            copy: "blue".into(),
            payload: d.payload.clone(),
            sig: d.sig.clone(),
            results: results.clone(),
            ..Default::default()
        });
    });
    let hn =
        kr.k.post("notarizer-green", "/handoff", &json!({"roster": d}))
            .unwrap_or_else(|e| panic!("{e:#}"));
    let hs =
        kr.k.post("spawner-green", "/handoff", &json!({"roster": d}))
            .unwrap_or_else(|e| panic!("{e:#}"));
    kr.k.post("notarizer-blue", "/takeover", &json!({"handoff": hn}))
        .unwrap_or_else(|e| panic!("{e:#}"));
    kr.st.do_(|p| {
        p.kernel_flip = Some(KernelFlip {
            to: "blue".into(),
            roster: d.id(),
            handoffs: BTreeMap::from([
                ("notarizer".to_string(), hn.clone()),
                ("spawner".to_string(), hs.clone()),
            ]),
            taken: BTreeMap::new(),
            ..Default::default()
        });
    });
    kr.k.down
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert("secrets-blue".into());
    let e = kr
        .kernel_flip_run()
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(
        e.contains("secrets-blue"),
        "the flip went through without secrets-blue: {e}"
    );
    let kept = kr.st.do_(|p| p.kernel_flip.clone()).unwrap_or_default();
    assert!(
        kept.handoffs.len() == KERNEL_ROLES.len()
            && kept.taken.get("notarizer") == Some(&true)
            && kept.taken.get("spawner") == Some(&true)
            && kept.taken.get("secrets") != Some(&true)
            && kr.serving_copy() == "green"
            && !kept.waiting.is_empty(),
        "the failed try: {kept:?}"
    );
    kr.k.down.lock().unwrap_or_else(|e| e.into_inner()).clear();
    kr.kernel_flip_run()
        .unwrap_or_else(|e| panic!("the flip carried on: {e:#}"));
    assert_eq!(kr.serving_copy(), "blue", "blue doesn't serve");
    kr.k.serve("blue");
    let (code, body) = kdo(&h, &m2, "POST", "/m/pull-secrets", "{}");
    assert_eq!(
        code,
        200,
        "a pull after the second flip: {}",
        String::from_utf8_lossy(&body)
    );
    put_snap(&kr.t.r, &m2.id, &tarball, &m2.sig.sign(sum.as_bytes()));
    pause(&kr, &sid);
    let _ = &mut kr;
}

/// ✱ a roster of the copy that doesn't serve that doesn't retire the serving copy's members, or names no empty secrets
/// to take over, starts nothing; a serving component that restarted after the roster was read stops the flip before
/// anything froze
#[test]
fn a_flip_refuses_a_roster_that_cant_take_over() {
    let mut kr = kernel_rig();
    let keep = kr.k.release().retired.clone();
    kr.k.copies
        .get_mut("green")
        .unwrap_or_else(|| panic!("no green"))
        .retired = vec![];
    let d = kr.k.roster_for("green").unwrap_or_else(|e| panic!("{e:#}"));
    let (code, e) = kr
        .take_roster(&d.payload, &d.sig)
        .err()
        .unwrap_or_else(|| panic!("taken"));
    assert!(
        code == 403 && format!("{e:#}").contains("retires every serving member"),
        "{code} {e:#}"
    );
    kr.k.restart("merger"); // blue's merger restarts after green's roster was read
    kr.k.copies
        .get_mut("green")
        .unwrap_or_else(|| panic!("no green"))
        .retired = keep;
    let d = kr.k.roster_for("green").unwrap_or_else(|e| panic!("{e:#}"));
    kr.take_roster(&d.payload, &d.sig)
        .unwrap_or_else(|(c, e)| panic!("{c} {e:#}"));
    wait_for("the flip's wait", || {
        kr.st.do_(|p| {
            p.kernel_flip
                .as_ref()
                .is_some_and(|f| f.waiting.contains("merger-blue restarted"))
        })
    });
    let f = kr.st.do_(|p| p.kernel_flip.clone()).unwrap_or_default();
    assert!(
        f.handoffs.is_empty() && kr.serving_copy() == "blue",
        "something froze: {f:?}"
    );
}
