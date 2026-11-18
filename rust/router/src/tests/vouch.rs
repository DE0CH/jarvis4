use crate::schedule::{Wakeup, sched};
use crate::sessionops::{RollbackMark, SessionOps};
use crate::state::Approval;
use crate::testutil::{
    Rig, TestServer, call, mq_wait_kind, new_test_machine, snap_bytes, wait_for,
};
use crate::vouch::{
    AttachmentRef, Delivery, DeliveryResult, OnceInputs, SessionConfig, SignedRequest,
};
use base64::Engine;
use serde_json::{Value, json};
use sha2::Digest;
use std::time::Duration;

fn img() -> String {
    format!("ghcr.io/de0ch/jarvis4-session@sha256:{}", "1".repeat(64))
}

fn config_of(v: &Option<Value>, key: &str) -> String {
    v.as_ref()
        .and_then(|b| b["options"][key].as_str())
        .unwrap_or("")
        .to_string()
}

fn approval_of(rg: &Rig, sid: &str) -> Option<Approval> {
    rg.st
        .do_(|d| d.approvals.values().rfind(|a| a.session == sid).cloned())
}

#[test]
fn the_settings_go_into_the_challenge() {
    let (rg, vc) = Rig::v2();
    let sid = rg
        .create_session(crate::flows::NewSession {
            label: "Refactor".into(),
            prompt: "please refactor".into(),
            harness: "claude".into(),
            repos: "https://github.com/DE0CH/claude-env.git".into(),
            one_shot: true,
            ..Default::default()
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
    let c: SessionConfig = serde_json::from_str(&config_of(&vc.last("/succession"), "config"))
        .unwrap_or_else(|e| panic!("no config: {e}"));
    assert!(
        c.prompt == "please refactor"
            && c.label == "Refactor"
            && c.one_shot
            && c.repos == ["https://github.com/DE0CH/claude-env.git"],
        "config {c:?}"
    );
    wait_for("approval", || approval_of(&rg, &sid).is_some());
}

#[test]
fn an_unattended_resume_carries_the_certs_config_and_only_that() {
    let (rg, vc) = Rig::v2();
    let conf = r#"{"v":1,"label":"x"}"#;
    let cert = rg.v2_cert("m1", conf);
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.cert = Some(cert.clone());
            s.image = img();
            s.prompt = "a new prompt".into();
            s.label = "a new label".into();
        }
    });
    rg.resume("s1", false).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("dead-machine asked", || {
        vc.last("/approve/by-dead-machine").is_some()
    });
    let opts = vc
        .last("/succession")
        .map(|b| b["options"].clone())
        .unwrap_or_default();
    assert!(
        opts["config"] == conf && opts.get("once").is_none_or(Value::is_null),
        "resume options {opts}"
    );
    wait_for("idle", || rg.lock("s1", "test-end").is_ok());
}

#[test]
fn a_resume_prompt_or_rollback_needs_the_phone() {
    let (rg, vc) = Rig::v2();
    let cert = rg.v2_cert("m1", r#"{"v":1}"#);
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.cert = Some(cert.clone());
            s.ops = Some(SessionOps {
                rollback: Some(RollbackMark {
                    marker: "uuid-1234".into(),
                    pred: "m1".into(),
                }),
                ..Default::default()
            });
        }
    });
    rg.set_resume_prompt("s1", "carry on with the report");
    rg.resume("s1", false).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("approval", || approval_of(&rg, "s1").is_some());
    let a = approval_of(&rg, "s1").unwrap_or_default();
    assert!(
        a.kind == "resume-upgrade" && vc.last("/approve/by-dead-machine").is_none(),
        "a one-time input went unattended: {a:?}"
    );
    let once: OnceInputs =
        serde_json::from_str(&config_of(&vc.last("/succession"), "once")).unwrap_or_default();
    assert!(
        once.prompt == "carry on with the report" && once.rollback == "uuid-1234",
        "once {once:?}"
    );
    rg.st.do_(|d| {
        assert!(
            d.schedules
                .get("s1")
                .is_none_or(|s| s.resume_prompt.is_empty())
                && d.sessions["s1"]
                    .ops
                    .as_ref()
                    .is_none_or(|o| o.rollback.is_none()),
            "the prompt or rollback would be delivered again another way"
        );
    });
}

#[test]
fn a_kill_names_the_machines_snapshot() {
    let (rg, vc) = Rig::v2();
    rg.kill_machine("m1", false)
        .unwrap_or_else(|e| panic!("{e:#}"));
    let k = vc.last("/kill").unwrap_or_default();
    let body = snap_bytes(&rg, "m1").unwrap_or_default();
    let sig = rg.snap("m1").map(|s| s.sig).unwrap_or_default();
    let sum = hex::encode(sha2::Sha256::digest(&body));
    let snap = &k["snapshot"];
    assert!(
        snap["sha256"] == json!(sum) && snap["sig"] == json!(sig) && snap["required"] == false,
        "kill {k}"
    );
    // a pause asks the core to keep the machine rather than kill it without that snapshot
    let _ = rg.kill_machine("m1", true);
    assert_eq!(
        vc.last("/kill").unwrap_or_default()["snapshot"]["required"],
        true
    );
}

#[test]
fn deliveries_to_a_vouching_machine() {
    let (rg, vc) = Rig::v2();
    let cert = rg.v2_cert("m1", r#"{"v":1}"#);
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.state = "started".into();
            s.machine_id = "m1".into();
            s.cert = Some(cert.clone());
        }
        // a wakeup made outside the session: nothing vouches for it (the router has no free-text delivery at all)
        sched(d, "s1").wakeups.insert(
            "w".into(),
            Wakeup {
                name: "w".into(),
                at: 1,
                prompt: "x".into(),
                armed_at: 7,
                ..Default::default()
            },
        );
    });
    let e = rg
        .fire_wakeup("s1", "w", 7)
        .err()
        .unwrap_or_else(|| panic!("an app-made wakeup was delivered"));
    assert!(
        format!("{e:#}").contains(crate::vouch::NOT_VOUCHED),
        "an app-made wakeup: {e:#}"
    );
    // the session's own: handed over with the core's attestation of exactly its body
    let body = br#"{"name":"w","prompt":"check CI","delaySeconds":60}"#;
    let signed = SignedRequest {
        machine: "m1".into(),
        method: "POST".into(),
        path: "/m/api/sessions/s1/wakeup".into(),
        at: "1".into(),
        body: base64::engine::general_purpose::STANDARD.encode(body),
        sig: "s".into(),
    };
    rg.st.do_(|d| {
        if let Some(w) = sched(d, "s1").wakeups.get_mut("w") {
            w.signed = Some(signed.clone());
        }
    });
    let d = std::thread::scope(|s| {
        let h = s.spawn(|| {
            let b =
                mq_wait_kind(&rg, "m1", "delivery", Duration::from_secs(10)).unwrap_or_default();
            let d: Delivery = serde_json::from_str(&b).unwrap_or_default();
            let _ = rg.mq_answer(
                &d.id,
                &json!(DeliveryResult {
                    id: d.id.clone(),
                    ok: true,
                    ..Default::default()
                }),
            );
            d
        });
        rg.fire_wakeup("s1", "w", 7)
            .unwrap_or_else(|e| panic!("{e:#}"));
        h.join().unwrap_or_default()
    });
    let sum = hex::encode(sha2::Sha256::digest(body));
    let at = vc.last("/attest").unwrap_or_default();
    assert!(
        d.kind == "wakeup"
            && d.request.as_ref().is_some_and(|r| r.body == signed.body)
            && d.attest.is_some()
            && at["machine"] == "m1"
            && at["input"] == "wakeup"
            && at["sha256"] == json!(sum),
        "delivery {d:?} attest {at}"
    );
}

#[test]
fn machine_config_is_only_format_exceptions() {
    let (rg, _vc) = Rig::v2();
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.state = "started".into();
            s.machine_id = "m1".into();
            s.prompt = "secret instructions".into();
            s.label = "title".into();
        }
    });
    let out = rg.machine_config("m1").unwrap_or_else(|e| panic!("{e:#}"));
    let allowed = [
        "sessionId",
        "discordChannel",
        "liveSyncSeconds",
        "taskRun",
        "taskTrigger",
        "tunnelProof",
    ];
    for k in out
        .as_object()
        .map(|m| m.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default()
    {
        assert!(allowed.contains(&k.as_str()), "/m/config carries {k}");
    }
}

/// the app's resume with a prompt: the prompt is queued before the resume starts, so the resume always carries it to
/// the phone
#[test]
fn resume_with_prompt_always_reaches_the_phone() {
    let (rg, vc) = Rig::v2();
    let cert = rg.v2_cert("m1", r#"{"v":1}"#);
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.cert = Some(cert.clone());
        }
    });
    rg.resume_with_prompt("s1", false, "carry on")
        .unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("approval", || approval_of(&rg, "s1").is_some());
    let a = approval_of(&rg, "s1").unwrap_or_default();
    let once: OnceInputs =
        serde_json::from_str(&config_of(&vc.last("/succession"), "once")).unwrap_or_default();
    assert!(
        a.kind == "resume-upgrade" && once.prompt == "carry on",
        "approval {a:?} once {once:?}"
    );
    // a refused resume (the session isn't paused now) leaves the earlier queued prompt as it was
    rg.set_resume_prompt("s1", "earlier");
    assert!(
        rg.resume_with_prompt("s1", false, "later").is_err(),
        "resumed a session that isn't paused"
    );
    assert_eq!(
        rg.st.do_(|d| d
            .schedules
            .get("s1")
            .map(|s| s.resume_prompt.clone())
            .unwrap_or_default()),
        "earlier"
    );
}

/// An image attached on New session: its sha256 and size go into the signed config, the app can read the staged bytes
/// back, and the machine's listing carries the core's attestation of each file as it is now (the input log)
#[test]
fn an_attachment_is_signed_by_hash_and_attested_into_the_input_log() {
    let (rg, vc) = Rig::v2_with(|c| c.no_access = true);
    // a core after R2: no /input-log, so the router keeps the entries itself
    let vurl = vc.srv.url.clone();
    let proxy = TestServer::handler(move |w, req| {
        if req.path == "/input-log" {
            return crate::nethttp::write_json(w, 404, &json!({"error": "no such route"}));
        }
        let b = req.read_body(16 << 20);
        let resp = reqwest::blocking::Client::new()
            .request(
                reqwest::Method::from_bytes(req.method.as_bytes()).unwrap_or(reqwest::Method::POST),
                format!("{vurl}{}", req.path),
            )
            .body(b)
            .send();
        match resp {
            Ok(r) => {
                let st = r.status().as_u16();
                let b = r.bytes().unwrap_or_default();
                w.set_header("Content-Type", "application/json");
                w.write_header(st);
                w.write(&b);
            }
            Err(_) => w.write_header(502),
        }
    });
    rg.t.r.core.set_url(&proxy.url);
    let h = rg.handler();
    let photo = "\u{89}PNG the photo";
    let mut req = crate::nethttp::Req::new("POST", "/api/uploads", photo.as_bytes())
        .with_header("x-upload-id", "upA")
        .with_header("x-upload-name", "IMG 1.png");
    let mut w = crate::nethttp::W::recorder();
    h(&mut w, &mut req);
    assert_eq!(w.status(), 200, "{}", w.body_text());
    let (code, out) = call(
        &h,
        "POST",
        "/api/sessions",
        r#"{"requestId":"rA","label":"look","prompt":"what is this?","harness":"claude","attachments":{"uploadId":"upA","files":[{"name":"IMG 1.png"}]}}"#,
    );
    assert_eq!(code, 200, "{out}");
    let sid = out["id"].as_str().unwrap_or("").to_string();
    wait_for("succession", || vc.last("/succession").is_some());
    let c: SessionConfig =
        serde_json::from_str(&config_of(&vc.last("/succession"), "config")).unwrap_or_default();
    let want = hex::encode(sha2::Sha256::digest(photo.as_bytes()));
    assert!(
        c.attachments
            == [AttachmentRef {
                name: "IMG_1.png".into(),
                sha256: want.clone(),
                size: photo.len() as i64
            }]
            && c.prompt == "what is this?",
        "signed config {c:?}"
    );
    let get = |target: &str| {
        let mut w = crate::nethttp::W::recorder();
        let mut req = crate::nethttp::Req::new("GET", target, b"");
        h(&mut w, &mut req);
        w
    };
    let w = get(&format!("/api/sessions/{sid}/attachments/IMG_1.png"));
    assert!(
        w.status() == 200 && w.body_text() == photo,
        "app read: {}",
        w.status()
    );
    assert_eq!(
        get(&format!("/api/sessions/{sid}/attachments/other.png")).status(),
        404
    );
    assert_eq!(get("/api/sessions/s1/attachments/IMG_1.png").status(), 404);
    // the session's machine lists them with the core's attestation; the attestation is in the router's input log
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut(&sid) {
            s.machine_id = "mA".into();
            s.state = "initialising".into();
        }
        d.machines.insert("mA".into(), sid.clone());
    });
    let mx = new_test_machine(&rg, "mA");
    let mh = rg.machine_handler();
    let listing = || {
        let (code, out) = mx.do_(&mh, "GET", "/m/attachments", "");
        assert_eq!(code, 200, "{out}");
        out
    };
    let attested = |out: &Value| -> Value {
        let p = out["attest"]["IMG_1.png"]["payload"]
            .as_str()
            .unwrap_or_else(|| panic!("no attestation in {out}"));
        serde_json::from_str(p).unwrap_or_default()
    };
    let e = attested(&listing());
    assert!(
        e["machine"] == "mA" && e["input"] == "attachment" && e["sha256"] == json!(want),
        "attestation {e}"
    );
    let at = vc.last("/attest").unwrap_or_default();
    assert!(
        at["origin"] == "cert" && at["sha256"] == json!(want),
        "attest asked {at}"
    );
    let il: Vec<String> = rg
        .st
        .read_log("", crate::sessionlog::LOG_INPUT)
        .unwrap_or_default()
        .iter()
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect();
    let b = il.join("\n");
    assert!(
        b.contains(r#"\"input\":\"attachment\""#) && b.contains(&want),
        "input log {b}"
    );
    // swapped in the bucket after the phone signed: attested under the new bytes' hash, never the signed one
    let up = rg.st.do_(|d| {
        d.sessions[&sid]
            .ops
            .as_ref()
            .map(|o| o.upload.clone())
            .unwrap_or_default()
    });
    rg.obj_put_bytes(
        &crate::uploads::upload_key(&up, "IMG_1.png"),
        b"another picture",
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    assert_ne!(
        attested(&listing())["sha256"],
        json!(want),
        "a swapped file was attested under the signed hash"
    );
    // 2026-11-17: only a line's first machine uses them, so a later line's config carries none
    let (code, out) = mx.do_(&mh, "DELETE", "/m/attachments", "");
    assert_eq!(code, 200, "drop: {out}");
    let s = rg.session(&sid);
    let cfg = rg
        .session_config(&s)
        .unwrap_or_else(|e| panic!("a later line's config: {e:#}"));
    let later: SessionConfig = serde_json::from_str(&cfg).unwrap_or_default();
    assert!(
        later.attachments.is_empty() && later.prompt == "what is this?",
        "later line's config {later:?}"
    );
}
