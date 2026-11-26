//! kernel/kerneltest/flip_test.go: the copy flip on the kernel alone

use jarvis_doc::gv::{self, Signed};
use jarvis_doc::{Grant, Kind, now};
use jarvis_kernel::kerneltest::{Kernel, post_roster};
use jarvis_sig::{Doc, Identity, Signer};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const TEST_IMAGE: &str = "ghcr.io/de0ch/jarvis4-session:sha-aaaaaaaaaaaa@sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn start() -> Kernel {
    Kernel::start(BTreeMap::from([(
        "JARVIS2_URL".to_string(),
        "http://router".to_string(),
    )]))
}

fn err_of(r: anyhow::Result<Doc>) -> String {
    r.err().map(|e| format!("{e:#}")).unwrap_or_default()
}

/// the secrets' answer to a pull with g
fn pull(k: &Kernel, g: &Signed) -> anyhow::Result<Doc> {
    k.post_role("secrets", "/pull", &json!(g))
}

fn payload(d: &Doc) -> Value {
    serde_json::from_str(&d.payload).unwrap_or_default()
}

/// the copy flip, end to end on the kernel alone: a live line on blue; a release onto green; green's roster retires
/// blue; every blue component hands over and freezes, green's notarizer, spawner and secrets take over; the line's
/// grant (blue's mover signed it) still pulls, its machine is killed by green's spawner (which has blue's record of it)
/// into a source green's notarizer defines, the grant moves on and a new machine starts from it; and a second release
/// flips back to blue the same way, the grant then signed by green's mover
#[test]
fn a_copy_flip_keeps_a_live_line() {
    let mut k = start();
    let (boot, mut m1) = k.line("s1", TEST_IMAGE, r#"{"v":1}"#, &[]);
    let mut g = boot.grant;
    pull(&k, &g).unwrap_or_else(|e| panic!("{e:#}"));
    for back in ["green", "blue"] {
        let from = k.active.clone();
        k.release();
        k.sign_roster(back).unwrap_or_else(|e| panic!("{e:#}"));
        // the standby serves nothing before it takes over
        assert!(
            k.post(&format!("notarizer-{back}"), "/notarize", &json!({}))
                .is_err(),
            "the standby notarizer answered"
        );
        k.flip();
        assert_eq!(k.active, back);
        // ✱ the frozen source: every component of the old copy refuses work
        for (role, path) in [
            ("notarizer", "/notarize"),
            ("mover", "/move"),
            ("spawner", "/init"),
            ("notary", "/challenge"),
        ] {
            let e = err_of(k.post(&format!("{role}-{from}"), path, &json!({})));
            assert!(
                e.contains("handed over"),
                "{role}-{from} after its handoff: {e}"
            );
        }
        assert!(
            k.post(&format!("secrets-{from}"), "/keys", &json!({}))
                .is_err(),
            "the old secrets answered"
        );
        // the live line: its grant pulls through the new copy's secrets
        pull(&k, &g).unwrap_or_else(|e| panic!("the grant after the flip to {back}: {e:#}"));
        // a pause: the new spawner kills the machine its predecessor made, the kill cert is notarized, the grant moves
        let kd = k
            .post_role("spawner", "/kill", &json!({"id": m1.id}))
            .unwrap_or_else(|e| panic!("{e:#}"));
        let kc: Doc =
            serde_json::from_value(payload(&kd)["cert"].clone()).unwrap_or_else(|e| panic!("{e}"));
        let knz = k.notarize(&kc);
        g = k.mv(&g, &kc, &knz);
        // a resume from that source
        let id = k.spawn(&kc, &knz).unwrap_or_else(|e| panic!("{e:#}"));
        let mc = k
            .post_role("spawner", "/init", &json!({"id": id}))
            .unwrap_or_else(|e| panic!("{e:#}"));
        let mnz = k.notarize(&mc);
        g = k.mv(&g, &mc, &mnz);
        pull(&k, &g).unwrap_or_else(|e| panic!("{e:#}"));
        m1 = k
            .fly
            .machine(&id)
            .unwrap_or_else(|| panic!("no machine {id}"));
        // the new notarizer holds the old one's sources: the paused source's second successor is refused
        let id2 = k.spawn(&kc, &knz).unwrap_or_else(|e| panic!("{e:#}"));
        let second = k
            .post_role("spawner", "/init", &json!({"id": id2}))
            .unwrap_or_else(|e| panic!("{e:#}"));
        let ch = k.challenge(&second.id(), "cert");
        let e = err_of(k.post_role(
            "notarizer",
            "/notarize",
            &json!({"cert": second, "challenge": ch, "notary": k.identity("notary"), "signer": k.identity("spawner")}),
        ));
        assert!(
            e.contains("already has a successor"),
            "a second machine from the paused source: {e}"
        );
        // a new line starts on the new copy
        k.line(&format!("s-{back}"), TEST_IMAGE, r#"{"v":1}"#, &[]);
    }
}

/// ✱ the handoff's refusals: to a roster of the same copy, to one that doesn't retire the component (a newer roster
/// of the other copy gets the same frozen state); the takeover's: a handoff of another role, for another roster than
/// the one held (a replay), signed by a key the roster doesn't retire, any handoff once it serves; the same handoff
/// again is answered the same
#[test]
fn the_handoff_refusals() {
    let mut k = start();
    let blue = k.roster().unwrap_or_else(|e| panic!("{e:#}"));
    let e = err_of(k.post_role("notarizer", "/handoff", &json!({"roster": blue})));
    assert!(
        e.contains("other kernel copy"),
        "a handoff to the same copy: {e}"
    );
    let keep = k.release().retired.clone();
    k.copies
        .get_mut("green")
        .unwrap_or_else(|| panic!("no green"))
        .retired = vec![];
    let unretired = k.roster_for("green").unwrap_or_else(|e| panic!("{e:#}"));
    let e = err_of(k.post_role("notarizer", "/handoff", &json!({"roster": unretired})));
    assert!(
        e.contains("doesn't retire"),
        "a handoff to a roster that doesn't retire it: {e}"
    );
    let set_retired = |k: &mut Kernel, r: Vec<Identity>| {
        k.copies
            .get_mut("green")
            .unwrap_or_else(|| panic!("no green"))
            .retired = r;
    };
    set_retired(&mut k, keep.clone());
    k.sign_roster("green").unwrap_or_else(|e| panic!("{e:#}"));
    let gd = k.roster_for("green").unwrap_or_else(|e| panic!("{e:#}"));
    let h = k
        .post_role("notarizer", "/handoff", &json!({"roster": gd}))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let e = err_of(k.post_role("notarizer", "/notarize", &json!({})));
    assert!(
        e.contains("handed over"),
        "the frozen notarizer answered: {e}"
    );
    // a second roster for green (as if one of its components restarted before taking over; here: the minter's keys
    // not retired): the frozen notarizer hands the same state to it
    set_retired(&mut k, keep[..keep.len() - 1].to_vec());
    let gd2 = k.roster_for("green").unwrap_or_else(|e| panic!("{e:#}"));
    set_retired(&mut k, keep.clone());
    let h2 = k
        .post_role("notarizer", "/handoff", &json!({"roster": gd2}))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_ne!(
        h2.payload, h.payload,
        "a frozen notarizer's handoff to a newer roster"
    );
    let sh = k
        .post_role("spawner", "/handoff", &json!({"roster": gd}))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let e = err_of(k.post("notarizer-green", "/takeover", &json!({"handoff": sh})));
    assert!(
        e.contains("a handoff of a spawner"),
        "the notarizer took the spawner's handoff: {e}"
    );
    let forged = Doc {
        payload: h.payload.clone(),
        sig: Signer::generate().sign(h.payload.as_bytes()),
    };
    let e = err_of(k.post("notarizer-green", "/takeover", &json!({"handoff": forged})));
    assert!(
        e.contains("isn't signed by the notarizer this roster retires"),
        "a handoff signed by another key: {e}"
    );
    // the replay: green's notarizer holding another roster than the one the handoff names
    let green_nz = k.copies["green"].url["notarizer"].clone();
    post_roster(&green_nz, &gd2).unwrap_or_else(|e| panic!("{e:#}"));
    let e = err_of(k.post("notarizer-green", "/takeover", &json!({"handoff": h})));
    assert!(
        e.contains("another roster"),
        "a handoff for another roster: {e}"
    );
    post_roster(&green_nz, &gd).unwrap_or_else(|e| panic!("{e:#}"));
    let a = k
        .post("notarizer-green", "/takeover", &json!({"handoff": h}))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let b = k
        .post("notarizer-green", "/takeover", &json!({"handoff": h}))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(a.payload, b.payload, "the same handoff again");
    // ✱ once it took one it serves: the frozen state handed again (to the newer roster) never replaces what it went on
    // with
    post_roster(&green_nz, &gd2).unwrap_or_else(|e| panic!("{e:#}"));
    let e = err_of(k.post("notarizer-green", "/takeover", &json!({"handoff": h2})));
    assert!(
        e.contains("serves"),
        "a serving notarizer took a second handoff: {e}"
    );
    // a stateless component takes no handoff
    assert!(
        k.post("mover-green", "/takeover", &json!({"handoff": h}))
            .is_err(),
        "the mover took a handoff"
    );
}

/// a crash restart (not a release): the mover comes back with new keys; its copy's re-signed roster names the old
/// keys as retired, so a live line's grant (the old mover signed it) still opens and moves; the retired mover's keys
/// sign nothing new (its process is gone)
#[test]
fn a_crash_restart_keeps_the_grants() {
    let mut k = start();
    let (boot, m) = k.line("s1", TEST_IMAGE, r#"{"v":1}"#, &[]);
    let g = boot.grant;
    k.restart("mover");
    k.post_roster("").unwrap_or_else(|e| panic!("{e:#}"));
    gv::open(&g, &k.trust())
        .unwrap_or_else(|e| panic!("the old mover's grant no longer opens: {e}"));
    pull(&k, &g).unwrap_or_else(|e| panic!("{e:#}"));
    let kd = k
        .post_role("spawner", "/kill", &json!({"id": m.id}))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let kc: Doc =
        serde_json::from_value(payload(&kd)["cert"].clone()).unwrap_or_else(|e| panic!("{e}"));
    let g2 = k.mv(&g, &kc, &k.notarize(&kc));
    assert_ne!(
        g2.signer.as_ref().map(|s| s.signing_key.clone()),
        g.signer.as_ref().map(|s| s.signing_key.clone()),
        "the move wasn't the new mover's"
    );
    let gg = gv::open(&g2, &k.trust()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(gg.machine.kind(), Some(Kind::Source), "{gg:?}");
    // a grant on the sink signed by a key the roster never named is refused as before
    let x = Signer::generate();
    let d = x
        .sign_json(&Grant {
            kind: "grant".into(),
            machine: gg.machine.clone(),
            keys: gg.keys.clone(),
            pair: gg.pair.clone(),
            from: Some(vec![]),
            at: now(),
        })
        .unwrap_or_else(|e| panic!("{e}"));
    let id = Identity {
        role: "mover".into(),
        signing_key: x.public_key(),
        agreement_key: x.public_key(),
    };
    let s = Signed {
        grant: d,
        by: "mover".into(),
        signer: Some(id),
        keys: None,
        secrets: None,
    };
    assert!(
        gv::open(&s, &k.trust()).is_err(),
        "a grant by a mover the roster never named"
    );
}
