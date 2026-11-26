//! fabricrunner_test.go
use crate::awsrunner::{session_runners, valid_runner};
use crate::fabricrunner::{
    FABRIC_ENV, FABRIC_MACHINE_STATE, FabricLine, HermitKeys, fabric_machine_state,
    parse_hermit_keys, verify_hst,
};
use crate::kernelline::kernel_object;
use crate::machines::{FlyMachineDetail, LIST_FLY_MACHINES};
use crate::nethttp::{Req, W};
use crate::state::Session;
use crate::testutil::*;
use jarvis_go::GoTime;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// A token hermit's own code signed (aviary crates/hermit-api src/token.rs: key(1, 7) and its test claims), with the
/// key hermit publishes for it
const HST_VECTOR: &str = "hst1.1.AQGQ9sIAAHAAgAAAAAAAAAEBkPbCAABwAIAAAAAAAAACwAACBwAAAABrSdIAc3RhZmZAZXhhbXBsZS5vcmc.BshwBoZfSVF4vOt5b_NYB4A4SfZg0n8_WcFTMZ49NdtMjJA09IOVy6j6Enpa8MdylPirxw7DNv7sj8ioCrHLCg";
const HST_VECTOR_KEY: &str = r#"{"keys":[{"kid":1,"alg":"Ed25519","publicKey":"p-Rs6z8KcdQsdkKo5b22-NQxDMOV-A1W1PEv19s0IRQ"}]}"#;

/// the fabric's settings for one test, put back when dropped (the caller holds serial())
struct FabricEnv;

impl Drop for FabricEnv {
    fn drop(&mut self) {
        *FABRIC_ENV.write().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

fn fabric_env(kv: &[(&str, &str)]) -> FabricEnv {
    *FABRIC_ENV.write().unwrap_or_else(|e| e.into_inner()) = Some(
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    );
    FabricEnv
}

#[test]
fn verify_hermit_sandbox_token() {
    let keys = parse_hermit_keys(HST_VECTOR_KEY.as_bytes()).unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(keys.len(), 1);
    let c = verify_hst(HST_VECTOR, &keys, GoTime::from_unix(1_700_000_000))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        c.sandbox == "0190f6c2-0000-7000-8000-000000000001"
            && c.conversation == "0190f6c2-0000-7000-8000-000000000002"
            && c.expires.unix() == 1_800_000_000,
        "{c:?}"
    );
    assert!(
        verify_hst(HST_VECTOR, &keys, GoTime::from_unix(1_800_000_000)).is_err(),
        "an expired token"
    );
    let mut bad = HST_VECTOR.as_bytes().to_vec();
    let n = bad.len();
    bad[n - 3] ^= 1;
    for tok in [
        String::from_utf8_lossy(&bad).into_owned(),
        HST_VECTOR.replacen("hst1.1.", "hst1.2.", 1),
        "hst1.1.AA.AA".into(),
        "x".into(),
        "a".repeat(700),
    ] {
        assert!(
            verify_hst(&tok, &keys, GoTime::from_unix(1_700_000_000)).is_err(),
            "taken: {:.40}",
            tok
        );
    }
}

/// GET /fabric/env answers the env of the session whose machine is the token's sandbox and whose conversation is
/// the token's, with the runner's names; nothing to anyone else
#[test]
fn fabric_env_endpoint() {
    let _g = serial(); // the fabric's settings
    let _env = fabric_env(&[("FABRIC_HERMIT_URL", "http://hermit")]);
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sF", "starting", "", false);
    let ks = parse_hermit_keys(HST_VECTOR_KEY.as_bytes()).unwrap_or_else(|e| panic!("{e:#}"));
    let fetches = Arc::new(AtomicUsize::new(0));
    let f2 = fetches.clone();
    let keys = Arc::new(HermitKeys::new(Box::new(move || {
        f2.fetch_add(1, Ordering::SeqCst);
        Ok(ks.clone())
    })));
    let h = r.fabric_machine_handler(keys);
    let get = |auth: &str| {
        let mut req = Req::new("GET", "/fabric/env", b"");
        if !auth.is_empty() {
            req = req.with_header("Authorization", auth);
        }
        let mut w = W::recorder();
        h(&mut w, &mut req);
        (w.status(), w.body_text())
    };
    let bearer = format!("Bearer {HST_VECTOR}");
    // the token is good but no session's machine is its sandbox yet
    assert_eq!(get(&bearer).0, 404, "no machine");
    let fl = r.fabric_line("sF").unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(fl.conversation.len(), 36, "{fl:?}");
    let again = r.fabric_line("sF").unwrap_or_default();
    assert_eq!(
        again.conversation, fl.conversation,
        "a session's conversation changed"
    );
    // another conversation than the token's: refused
    r.set_fabric_machine(
        "sF",
        "x0190f6c2000070008000000000000001",
        BTreeMap::from([
            ("JARVIS2_SOURCE".to_string(), "source-a".to_string()),
            (
                "JARVIS2_URL".to_string(),
                "http://10.202.1.1:3128".to_string(),
            ),
        ]),
    );
    assert_eq!(get(&bearer).0, 404, "another conversation");
    r.st.do_(|d| {
        if let Some(f) = d.sessions.get_mut("sF").and_then(|s| s.fabric.as_mut()) {
            f.conversation = "0190f6c2-0000-7000-8000-000000000002".into();
        }
    });
    let (code, out) = get(&bearer);
    assert!(
        code == 200
            && out.contains(r#""JARVIS2_SOURCE":"source-a""#)
            && out.contains(r#""JARVIS2_RUNNER":"fabric""#)
            && out.contains(r#""JARVIS2_MACHINE_ID":"x0190f6c2000070008000000000000001""#),
        "{code} {out}"
    );
    for auth in ["", "Basic x", "Bearer hst1.1.AA.AA"] {
        assert_eq!(get(auth).0, 401, "{auth:?}");
    }
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        1,
        "hermit's keys fetched more than once"
    );
    // the runner is offered only with a fabric hermit, and fabric objects are named as the kernel names them
    let fabric = Session {
        runner: "fabric".into(),
        ..Default::default()
    };
    assert!(
        valid_runner("fabric")
            && kernel_object(Some(&fabric), "x0190f6c2000070008000000000000001", "fly").0
                == "fabric-x0190f6c2000070008000000000000001",
        "the fabric runner"
    );
    // a fabric session's sources name the fabric image; the others the session image
    let img = format!(
        "ghcr.io/de0ch/jarvis4-session-fabric@sha256:{}",
        "c".repeat(64)
    );
    {
        let _env = fabric_env(&[
            ("FABRIC_HERMIT_URL", "http://hermit"),
            ("FABRIC_SESSION_IMAGE", &img),
        ]);
        let fly = Session {
            runner: "fly".into(),
            ..Default::default()
        };
        assert!(
            r.source_image(&fabric) == img && r.source_image(&fly) == r.cfg.session_image,
            "the source image by runner"
        );
        // offered on the New session page with a fabric hermit
        assert!(
            session_runners().iter().any(|g| g.id == "fabric"),
            "New session does not offer the fabric with a fabric hermit"
        );
    }
    let _none = fabric_env(&[]);
    assert!(
        !valid_runner("fabric") && session_runners().len() == 2,
        "the fabric offered without a hermit"
    );
}

/// a destroyed fabric session's files: DELETE /v1/workspaces/{conversation} at hermit as caller magpie
#[test]
fn delete_fabric_files() {
    let _g = serial();
    let got: Arc<Mutex<Vec<String>>> = Arc::default();
    let g2 = got.clone();
    let srv = TestServer::handler(move |w, req| {
        g2.lock().unwrap_or_else(|e| e.into_inner()).push(format!(
            "{} {} {} {}",
            req.method,
            req.path,
            req.header("Authorization"),
            req.header("Aviary-Protocol")
        ));
        w.write_header(if req.path.ends_with("/bad") { 503 } else { 204 });
    });
    let url = format!("{}/", srv.url);
    let _env = fabric_env(&[
        ("FABRIC_HERMIT_URL", &url),
        ("FABRIC_HERMIT_MAGPIE_TOKEN", "mt"),
    ]);
    let t = new_test_router();
    t.r.delete_fabric_files("0190f6c2-0000-7000-8000-000000000002")
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        t.r.delete_fabric_files("bad").is_err(),
        "a 503 taken as deleted"
    );
    let first = got
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .first()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        first,
        "DELETE /v1/workspaces/0190f6c2-0000-7000-8000-000000000002 Bearer mt hermit-core=1"
    );
}

static HERMIT_ANSWER: Mutex<(String, String)> = Mutex::new((String::new(), String::new()));

fn fake_state(conversation: &str, machine: &str) -> anyhow::Result<String> {
    let mut g = HERMIT_ANSWER.lock().unwrap_or_else(|e| e.into_inner());
    g.1 = format!("{conversation} {machine}");
    Ok(g.0.clone())
}

fn no_fly() -> anyhow::Result<Vec<FlyMachineDetail>> {
    Ok(vec![])
}

struct LostSeams(crate::machines::ListFn, crate::fabricrunner::MachineStateFn);

impl Drop for LostSeams {
    fn drop(&mut self) {
        *LIST_FLY_MACHINES.write().unwrap_or_else(|e| e.into_inner()) = self.0;
        *FABRIC_MACHINE_STATE
            .write()
            .unwrap_or_else(|e| e.into_inner()) = self.1;
    }
}

/// a fabric machine's state is hermit's word, not Fly's: the lost-machine check marked a fabric session lost 30 s
/// after it booted, its machine being in neither Fly's nor AWS's list (2026-11-18)
#[test]
fn the_lost_check_asks_hermit_for_a_fabric_machine() {
    let _g = serial();
    let _env = fabric_env(&[("FABRIC_HERMIT_URL", "http://hermit.invalid")]);
    let t = new_test_router();
    let r = t.r.clone();
    let m = "x01a1ec41c22f71e49e50601a78aeffde";
    add_session(&r, "s1", "started", m, false);
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.runner = "fabric".into();
            s.fabric = Some(FabricLine {
                conversation: "6bd76dff-094c-425f-b971-c9b531254b1e".into(),
                machine: m.into(),
                ..Default::default()
            });
        }
    });
    let _seams = LostSeams(
        std::mem::replace(
            &mut *LIST_FLY_MACHINES.write().unwrap_or_else(|e| e.into_inner()),
            no_fly,
        ),
        std::mem::replace(
            &mut *FABRIC_MACHINE_STATE
                .write()
                .unwrap_or_else(|e| e.into_inner()),
            fake_state,
        ),
    );
    *HERMIT_ANSWER.lock().unwrap_or_else(|e| e.into_inner()) = ("started".into(), String::new());
    let mut seen = BTreeMap::new();
    r.lost_tick(&mut seen);
    r.lost_tick(&mut seen);
    let s =
        r.st.read(|d| d.sessions.get("s1").cloned().unwrap_or_default());
    assert!(
        s.lost.is_none() && s.state == "started",
        "a running fabric machine was marked lost: {} {:?}",
        s.state,
        s.error
    );
    let asked = HERMIT_ANSWER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .1
        .clone();
    assert_eq!(
        asked,
        format!("6bd76dff-094c-425f-b971-c9b531254b1e {m}"),
        "asked hermit about"
    );
    // hermit no longer has it: lost, said as the fabric's
    HERMIT_ANSWER.lock().unwrap_or_else(|e| e.into_inner()).0 = "released".into();
    r.lost_tick(&mut seen);
    r.lost_tick(&mut seen);
    let s =
        r.st.read(|d| d.sessions.get("s1").cloned().unwrap_or_default());
    assert!(
        s.lost.is_some() && s.state == "failed" && s.error.contains("was released on the fabric"),
        "a released fabric machine: {} {:?}",
        s.state,
        s.error
    );
}

/// hermit's answer in the lost check's words: this machine's sandbox starting or ready is running; another sandbox of
/// the conversation, none, or a gone one is released; one being released is destroying
#[test]
fn fabric_machine_states() {
    let _g = serial();
    let answer: Arc<Mutex<(u16, String)>> = Arc::new(Mutex::new((200, String::new())));
    let a2 = answer.clone();
    let srv = TestServer::handler(move |w, req| {
        if req.path != "/v1/conversations/c1/sandbox"
            || req.header("Authorization") != "Bearer mt"
            || req.header("Aviary-Protocol") != "hermit-core=1"
        {
            w.write_header(400);
            return;
        }
        let (code, body) = a2.lock().unwrap_or_else(|e| e.into_inner()).clone();
        w.write_header(code);
        w.write_str(&body);
    });
    let url = format!("{}/", srv.url);
    let _env = fabric_env(&[
        ("FABRIC_HERMIT_URL", &url),
        ("FABRIC_HERMIT_MAGPIE_TOKEN", "mt"),
    ]);
    let m = "x01a1ec41c22f71e49e50601a78aeffde";
    for (code, body, want) in [
        (
            200,
            r#"{"id":"01a1ec41-c22f-71e4-9e50-601a78aeffde","state":"ready"}"#,
            "started",
        ),
        (
            202,
            r#"{"id":"01a1ec41-c22f-71e4-9e50-601a78aeffde","state":"starting"}"#,
            "started",
        ),
        (
            200,
            r#"{"id":"01a1ec41-c22f-71e4-9e50-601a78aeffde","state":"releasing"}"#,
            "destroying",
        ),
        (
            200,
            r#"{"id":"01a1ec41-c22f-71e4-9e50-601a78aeffde","state":"gone"}"#,
            "released",
        ),
        (
            200,
            r#"{"id":"01a1ffff-c22f-71e4-9e50-601a78aeffde","state":"ready"}"#,
            "released",
        ),
        (404, r#"{"code":"no_sandbox"}"#, "released"),
    ] {
        *answer.lock().unwrap_or_else(|e| e.into_inner()) = (code, body.into());
        let got = fabric_machine_state("c1", m);
        assert!(
            got.as_deref().is_ok_and(|g| g == want),
            "{code} {body}: {got:?}, want {want:?}"
        );
    }
    *answer.lock().unwrap_or_else(|e| e.into_inner()) = (503, "{}".into());
    assert!(
        fabric_machine_state("c1", m).is_err(),
        "hermit unavailable: an error (the machine is not taken for lost)"
    );
}

/// Where a session's machine runs is the session's runner, never read from the machine's id (Deyao, 2026-11-20:
/// "there are more than 2 types"): its log names that runner, and its card shows the fabric's sandbox and hosts.
#[test]
fn the_runner_is_the_sessions() {
    let _g = serial();
    let _env = fabric_env(&[("FABRIC_HERMIT_URL", "http://hermit")]);
    let t = new_test_router();
    let r = t.arc();
    r.st.do_(|d| {
        // ids of every shape on every runner: the id says nothing
        for (sid, runner, m) in [
            ("sA", "aws", "683dde7ea60478"),
            ("sB", "fabric", "i-0123456789abcdef0"),
            ("sC", "fly", "x01a1f71ecb6d71d6b5be4c4e404255df"),
        ] {
            d.sessions.insert(
                sid.into(),
                Session {
                    id: sid.into(),
                    runner: runner.into(),
                    machine_id: m.into(),
                    ..Default::default()
                },
            );
            d.machines.insert(m.into(), sid.into());
        }
    });
    for (sid, want) in [
        ("sA", "AWS"),
        ("sB", "the fabric"),
        ("sC", "Fly"),
        ("nope", "its runner"),
    ] {
        assert_eq!(
            crate::awsrunner::runner_label(&r.runner_of_session(sid)),
            want,
            "session {sid}"
        );
    }
    assert!(
        r.runner_of_machine("683dde7ea60478") == "aws"
            && r.runner_of_machine("i-0123456789abcdef0") == "fabric"
            && r.runner_of_machine("unknown").is_empty(),
        "a machine's runner is its session's"
    );
    let d = crate::state::Persisted::default();
    let s = |id: &str, runner: &str| Session {
        id: id.into(),
        runner: runner.into(),
        size: "small".into(),
        region: "lhr".into(),
        ..Default::default()
    };
    let v = crate::http::session_view(&s("s1", "fabric"), &d);
    assert!(
        v.get("runner") == Some(&serde_json::json!("fabric"))
            && v.get("region") == Some(&serde_json::json!(crate::fabricrunner::FABRIC_REGION))
            && v.get("guest") == Some(&serde_json::json!(crate::fabricrunner::FABRIC_GUEST)),
        "fabric session view: {:?} {:?} {:?}",
        v.get("runner"),
        v.get("region"),
        v.get("guest")
    );
    let v = crate::http::session_view(&s("s2", "fly"), &d);
    assert!(
        v.get("runner") == Some(&serde_json::json!("fly"))
            && v.get("region") == Some(&serde_json::json!("lhr"))
            && v.get("guest") == Some(&serde_json::json!(crate::sizes::size_label("small"))),
        "fly session view: {:?} {:?} {:?}",
        v.get("runner"),
        v.get("region"),
        v.get("guest")
    );
}
