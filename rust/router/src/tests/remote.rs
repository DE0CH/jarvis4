//! router/remote_test.go
use crate::autopilot::Liveness;
use crate::grants::ExecResult;
use crate::harness::{default_model, proxy_login_harness, session_model};
use crate::nethttp::{Req, W};
use crate::policy::{HarnessPolicy, Policy};
use crate::registry::Registry;
use crate::remote::{CHAT_URL, TUNNEL_KEY, parse_remote, tunnel_proof};
use crate::router::Router;
use crate::testutil::*;
use jarvis_go::GoTime;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn session_models() {
    for (harness, input, want) in [
        ("claude", "", "claude-opus-5-5"),
        ("claude", "claude-opus-5-5", "claude-opus-5-5"),
        ("opencode", "", "openrouter/z-ai/glm-5.3"),
        (
            "opencode",
            "openrouter/moonshotai/kimi-k3",
            "openrouter/moonshotai/kimi-k3",
        ),
        ("opencode", "claude-opus-5-5", "openrouter/z-ai/glm-5.3"), // the shell picked another harness than the form's model
        ("openclaw", "claude-opus-5-5", "openclaw/claude-opus-5-5"),
        (
            "openclaw",
            "openclaw/claude-opus-5-5",
            "openclaw/claude-opus-5-5",
        ),
        ("paseo-claude", "", "paseo/claude-opus-5-5"),
        (
            "paseo-claude",
            "paseo/claude-opus-5-5",
            "paseo/claude-opus-5-5",
        ),
        ("paseo-claude", "claude-opus-5-5", "paseo/claude-opus-5-5"),
        ("aviary", "", "aviary/claude-opus-5-5"),
        ("aviary", "aviary/z-ai/glm-5.3", "aviary/z-ai/glm-5.3"), // GLM 5.3 beside the Claude models (Deyao, 2026-11-12)
    ] {
        let got = session_model(harness, input);
        assert!(
            got.as_deref().is_ok_and(|g| g == want),
            "{harness} {input:?}: {got:?}, want {want:?}"
        );
    }
    assert!(
        session_model("claude", "claude-opus-typo").is_err(),
        "an unknown model must be refused"
    );
}

fn policy_of(hs: &[&str]) -> Policy {
    Policy {
        harnesses: hs
            .iter()
            .map(|h| (h.to_string(), HarnessPolicy::default()))
            .collect(),
        ..Default::default()
    }
}

#[test]
fn models_list() {
    let t = new_test_router_with(|_| {}, None, policy_of(&["claude", "opencode"]));
    let r = t.r.clone();
    let get = |r: &Router, q: &str| app_do(r, "GET", &format!("/api/models{q}"), "", &[]).1;
    let all = get(&r, "");
    for m in all["models"].as_array().cloned().unwrap_or_default() {
        assert_ne!(
            m["harness"], "openclaw",
            "a harness outside the policy is listed"
        );
    }
    assert!(
        all["harnesses"].get("openclaw").is_none() && all["default"] == "claude-opus-5-5",
        "{all}"
    );
    // a new session starts on aviary when the policy offers it (Deyao, 2026-11-13), else on Claude Code
    assert_eq!(all["defaultHarness"], "claude", "no aviary in the policy");
    let ta = new_test_router_with(|_| {}, None, policy_of(&["claude", "opencode", "aviary"]));
    let av = get(&ta.r, "");
    assert!(
        av["defaultHarness"] == "aviary" && av["default"] == "aviary/claude-opus-5-5",
        "{} {}",
        av["defaultHarness"],
        av["default"]
    );
    let oc = get(&r, "?harness=opencode");
    let ms = oc["models"].as_array().cloned().unwrap_or_default();
    assert!(
        ms.len() == 6 && oc["default"] == "openrouter/z-ai/glm-5.3",
        "{oc}"
    );
    for m in ms {
        assert!(
            m["id"]
                .as_str()
                .is_some_and(|i| i.starts_with("openrouter/")),
            "{m}"
        );
    }
}

fn raw_get(r: &Arc<Router>, path: &str) -> W {
    let h = r.handler();
    let mut req = Req::new("GET", path, b"");
    let mut w = W::recorder();
    h(&mut w, &mut req);
    w
}

fn cache_control(w: &W) -> String {
    w.headers
        .get("Cache-Control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// The web page is never served from a browser's cache without asking, and names its build so an open tab can tell
/// a new one (Deyao, 2026-11-13: a tab from before a fix showed the old page for a day).
#[test]
fn web_page_build() {
    let web = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let wd = web.path().display().to_string();
    let write = |p: &str, b: &str| {
        let f = web.path().join(p);
        if let Some(d) = f.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        std::fs::write(f, b).unwrap_or_else(|e| panic!("{e}"));
    };
    write(
        "index.html",
        "<!doctype html><script src=/_expo/a1.js></script>",
    );
    write("_expo/a1.js", "1");
    let wd1 = wd.clone();
    let t = new_test_router_with(
        move |c| {
            c.no_access = true;
            c.web_dir = wd1;
        },
        None,
        Default::default(),
    );
    let r = t.r.clone();
    for page in ["/", "/new"] {
        let w = raw_get(&r, page);
        assert!(
            w.status() == 200 && cache_control(&w) == "no-cache",
            "{page}: {} cache-control {:?}",
            w.status(),
            cache_control(&w)
        );
    }
    let w = raw_get(&r, "/_expo/a1.js");
    assert!(
        w.status() == 200 && cache_control(&w) != "no-cache",
        "a hashed file: {} {:?}",
        w.status(),
        cache_control(&w)
    );
    let build = |r: &Router| {
        app_do(r, "GET", "/api/build", "", &[]).1["build"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    let b1 = build(&r);
    assert!(b1.len() == 12 && b1 == build(&r), "build {b1:?}");
    write(
        "index.html",
        "<!doctype html><script src=/_expo/b2.js></script>",
    );
    let r2 = Router::new(
        r.cfg.clone(),
        r.st.clone(),
        r.core.clone(),
        Default::default(),
    );
    let b2 = build(&r2);
    assert!(
        b2 != b1 && b2.len() == 12,
        "another page, the same build: {b2:?}"
    );
}

#[test]
fn parse_remotes() {
    let i = parse_remote(
        "opencode",
        "s0123456789abcdef",
        "starting…\n{\"url\":\"https://app.paseo.sh/#offer=x\",\"relayEnabled\":true}\n",
    );
    assert!(
        i.pair_url == "https://app.paseo.sh/#offer=x"
            && i.relay
            && i.web_url == "https://s0123456789abcdef-s.deyaochen.com/"
            && i.error.is_empty(),
        "{i:?}"
    );
    let i = parse_remote("opencode", "s1", "daemon not running");
    assert!(!i.error.is_empty() && i.pair_url.is_empty(), "{i:?}");
    let i = parse_remote("openclaw", "s1", r#"{"token":"a/b+c"}"#);
    assert!(
        i.token == "a/b+c"
            && i.url == "wss://s1-s.deyaochen.com"
            && i.web_url == "https://s1-s.deyaochen.com/#token=a%2Fb%2Bc",
        "{i:?}"
    );
    let i = parse_remote("openclaw", "s1", "");
    assert!(!i.error.is_empty() && i.token.is_empty(), "{i:?}");
}

fn add_harness_session(r: &Router, id: &str, harness: &str, state: &str, machine: &str) {
    add_session(r, id, state, machine, false);
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut(id) {
            s.harness = harness.into();
            s.model = default_model(harness).into();
            s.created = GoTime::now();
        }
    });
}

fn err_result(e: String) -> ExecResult {
    ExecResult {
        error: e,
        ..Default::default()
    }
}

fn by_id(out: &Value) -> BTreeMap<String, Value> {
    out["sessions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|s| (s["id"].as_str().unwrap_or_default().to_string(), s))
        .collect()
}

const OPENCLAW_REMOTE: &str = r#"cat "$HOME/.openclaw/jarvis-remote.json""#;
const PASEO_PAIR_CMD: &str = r#"export PATH="$HOME/.local/bin:/usr/local/bin:$PATH" PASEO_HOME="$HOME/.paseo"; paseo daemon pair --json"#;

#[test]
fn remote_page() {
    let t = new_test_router();
    let r = t.r.clone();
    add_harness_session(&r, "sOC", "openclaw", "started", "mOC");
    add_harness_session(&r, "sOP", "opencode", "started", "mOP");
    add_harness_session(&r, "sCL", "claude", "started", "mCL");
    add_harness_session(&r, "sPA", "opencode", "paused", "");
    add_harness_session(&r, "sPC", "paseo-claude", "started", "mPC");
    let calls = Arc::new(AtomicUsize::new(0));
    let c2 = calls.clone();
    let _oc = answer_execs_with(&r, "mOC", move |holder, cmd| {
        c2.fetch_add(1, Ordering::SeqCst);
        if holder != "remote" || cmd != OPENCLAW_REMOTE {
            return err_result(format!("unexpected {holder}: {cmd}"));
        }
        ExecResult {
            stdout: r#"{"token":"tok123"}"#.into(),
            ..Default::default()
        }
    });
    let _op = answer_execs_with(&r, "mOP", |_, _| {
        err_result(
            "the remote holder is not on this session's allow list and no phone grant is given"
                .into(),
        )
    });
    let _pc = answer_execs_with(&r, "mPC", |holder, cmd| {
        if holder != "remote" || cmd != PASEO_PAIR_CMD {
            return err_result(format!("unexpected {holder}: {cmd}"));
        }
        ExecResult {
            stdout: r#"{"url":"https://app.paseo.sh/#offer=pc","relayEnabled":true}"#.into(),
            ..Default::default()
        }
    });
    let get = |p: &str| app_do(&r, "GET", p, "", &[]);
    let (code, out) = get("/api/sessions/sOC/remote");
    assert!(
        code == 200
            && out["token"] == "tok123"
            && out["url"] == "wss://sOC-s.deyaochen.com"
            && out["webUrl"] == "https://sOC-s.deyaochen.com/#token=tok123",
        "{code} {out}"
    );
    get("/api/sessions/sOC/remote");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "not cached");
    let (code, out) = get("/api/sessions/sOP/remote");
    assert!(code == 403 && out["needsGrant"] == "remote", "{code} {out}");
    assert_eq!(get("/api/sessions/sCL/remote").0, 400, "claude");
    assert_eq!(get("/api/sessions/sPA/remote").0, 409, "paused");
    assert_eq!(get("/api/sessions/nope/remote").0, 404, "missing");

    let (code, out) = get("/api/remotes?harness=opencode");
    let ss = by_id(&out);
    assert!(code == 200 && ss.len() == 2, "{code} {out}");
    let p = &ss["sPA"];
    assert!(
        p["state"] == "paused" && p["error"].is_null() && p["model"] == "openrouter/z-ai/glm-5.3",
        "{p}"
    );
    let o = &ss["sOP"];
    assert!(o["needsGrant"] == "remote" && !o["error"].is_null(), "{o}");
    let (code, out) = get("/api/remotes?harness=openclaw");
    let s = &out["sessions"][0];
    assert!(
        code == 200 && s["token"] == "tok123" && s["title"] == "label sOC",
        "{code} {out}"
    );
    // Claude Code · Paseo: the Paseo pairing offer; listed on its own and with every Paseo session (harness=paseo)
    let (code, out) = get("/api/sessions/sPC/remote");
    assert!(
        code == 200
            && out["pairUrl"] == "https://app.paseo.sh/#offer=pc"
            && out["webUrl"] == "https://sPC-s.deyaochen.com/",
        "{code} {out}"
    );
    let (code, out) = get("/api/remotes?harness=paseo-claude");
    assert!(code == 200 && by_id(&out).len() == 1, "{code} {out}");
    let (code, out) = get("/api/remotes?harness=paseo");
    let got: BTreeMap<String, String> = by_id(&out)
        .into_iter()
        .map(|(k, v)| (k, v["harness"].as_str().unwrap_or_default().to_string()))
        .collect();
    assert!(
        code == 200
            && got.len() == 3
            && got.get("sPC").map(String::as_str) == Some("paseo-claude")
            && got.get("sOP").map(String::as_str) == Some("opencode")
            && got.get("sPA").map(String::as_str) == Some("opencode"),
        "{code} {out}"
    );
    assert_eq!(get("/api/remotes?harness=claude").0, 400, "claude remotes");
}

/// Claude Code · aviary: its remote is Jarvis 4's chat web app, read from nothing on the machine; hermit-jarvis lists
/// the sessions (paused ones too) with harness=aviary
#[test]
fn aviary_remote() {
    let t = new_test_router();
    let r = t.r.clone();
    add_harness_session(&r, "sAV", "aviary", "started", "mAV");
    add_harness_session(&r, "sAP", "aviary", "paused", "");
    add_harness_session(&r, "sPC", "paseo-claude", "started", "mPC");
    // a paused session whose resume waits for Deyao's approval (a restart onto a newer image) is still a session:
    // hermit-jarvis takes one missing from this list for destroyed and removes its conversation from the chat
    // (2026-11-16). A new session not yet approved is listed as "approval": hermit-jarvis holds a new conversation's
    // first message until the session it proposed is up, and would take it for denied if the list left it out
    // (2026-11-18).
    add_harness_session(&r, "sAR", "aviary", "approval", "");
    add_harness_session(&r, "sAN", "aviary", "approval", "");
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("sAR") {
            s.paused_at = Some(GoTime::now());
        }
    });
    let _m = answer_execs_with(&r, "mAV", |holder, cmd| {
        err_result(format!(
            "the router ran {holder}: {cmd} on an aviary session"
        ))
    });
    let get = |p: &str| app_do(&r, "GET", p, "", &[]);
    // before the machine names its conversation: the chat's front page
    let (code, out) = get("/api/sessions/sAV/remote");
    assert!(
        code == 200
            && out["webUrl"] == CHAT_URL
            && out["harness"] == "aviary"
            && out["token"].is_null()
            && out["pairUrl"].is_null(),
        "{code} {out}"
    );
    // once it does (the gateway's conversationId, the registry's sessionId): that conversation's page in the chat
    let conv = "0b6f1c2e-6c1d-4c84-9a57-3f1e2d4c5b6a";
    let conv_url = format!("{CHAT_URL}h/srv_conversations/workspace/wks_{conv}");
    let set_sid = |sid: &str| {
        r.st.do_(|d| {
            if let Some(s) = d.sessions.get_mut("sAV") {
                s.live = Some(Liveness {
                    reg: Some(Registry {
                        session_id: sid.into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                });
            }
        })
    };
    set_sid(conv);
    let (code, out) = get("/api/sessions/sAV/remote");
    assert!(
        code == 200 && out["webUrl"] == conv_url.as_str(),
        "the remote opens the session's own conversation: {code} {out}"
    );
    // the placeholder before the gateway knows its conversation ("aviary") is no conversation
    set_sid("aviary");
    assert_eq!(get("/api/sessions/sAV/remote").1["webUrl"], CHAT_URL);
    set_sid(conv);
    let (code, out) = get("/api/remotes?harness=aviary");
    let ss = by_id(&out);
    assert!(code == 200 && ss.len() == 4, "{code} {out}");
    let s = &ss["sAR"];
    assert!(
        s["state"] == "paused" && s["webUrl"].is_null(),
        "a session waiting for its resume approval is listed as paused: {s}"
    );
    let s = ss.get("sAN").cloned().unwrap_or_default();
    assert!(
        s["state"] == "approval" && s["webUrl"].is_null(),
        "a new session not yet approved is listed as approval: {s}"
    );
    let s = &ss["sAV"];
    assert!(
        s["webUrl"] == conv_url.as_str()
            && s["model"] == "aviary/claude-opus-5-5"
            && s["error"].is_null(),
        "{s}"
    );
    let s = &ss["sAP"];
    assert!(s["state"] == "paused" && s["webUrl"].is_null(), "{s}");
    assert!(
        proxy_login_harness("aviary")
            && crate::peer::harness_send("aviary")
            && crate::devices::device_scheme("hermit").is_empty(),
        "aviary: an account switch through its gateway, harness-send and hermit-jarvis's pairing"
    );
    assert!(
        crate::devices::device_scheme("jarvis4chat").is_empty() && !proxy_login_harness("cloudcli"),
        "cloudcli and the Jarvis 4 Chat app are gone"
    );
}

/// DeepSeek Harness: its remote is the persistent dsh web UI's page for it, nothing read from the machine; it takes
/// prompts through harness-send
#[test]
fn dsh_remote() {
    let t = new_test_router();
    let r = t.r.clone();
    add_harness_session(&r, "sDS", "dsh", "started", "mDS");
    let _m = answer_execs_with(&r, "mDS", |holder, cmd| {
        err_result(format!("the router ran {holder}: {cmd} on a dsh session"))
    });
    let (code, out) = app_do(&r, "GET", "/api/sessions/sDS/remote", "", &[]);
    assert!(
        code == 200
            && out["webUrl"] == "https://dsh.deyaochen.com/s/sDS/"
            && out["harness"] == "dsh"
            && out["token"].is_null(),
        "{code} {out}"
    );
    let m = session_model("dsh", "");
    assert!(
        m.as_deref()
            .is_ok_and(|m| m == "dsh/deepseek/deepseek-v4-pro-0813")
            && crate::peer::harness_send("dsh"),
        "default model {m:?}"
    );
}

#[test]
fn tunnel_proofs() {
    let _g = serial(); // TUNNEL_KEY
    let (a, b) = (
        tunnel_proof("k", "s0000000000000001"),
        tunnel_proof("k", "s0000000000000002"),
    );
    assert!(
        a.len() == 64
            && a != b
            && a == tunnel_proof("k", "s0000000000000001")
            && tunnel_proof("", "s1").is_empty(),
        "proof"
    );
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sA", "started", "mA", false);
    let m = new_test_machine(&r, "mA");
    let other = new_test_machine(&r, "mX"); // started by the core, but no running session
    let h = t.machine_handler();
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            *TUNNEL_KEY.write().unwrap_or_else(|e| e.into_inner()) = None;
        }
    }
    let _restore = Restore;
    *TUNNEL_KEY.write().unwrap_or_else(|e| e.into_inner()) = Some(String::new());
    assert_eq!(m.do_(&h, "GET", "/m/tunnel-proof", "").0, 404, "no key");
    *TUNNEL_KEY.write().unwrap_or_else(|e| e.into_inner()) = Some("k".into());
    let (code, out) = m.do_(&h, "GET", "/m/tunnel-proof", "");
    assert!(
        code == 200 && out["proof"] == tunnel_proof("k", "sA").as_str() && out["id"] == "sA",
        "{code} {out}"
    );
    assert_eq!(
        other.do_(&h, "GET", "/m/tunnel-proof", "").0,
        403,
        "a machine without a session got a proof"
    );
}

#[test]
fn remote_holder_exists() {
    let t = new_test_router();
    let pubs = t.r.holder_public_keys().unwrap_or_default();
    let remote = pubs.get("remote").cloned().unwrap_or_default();
    assert!(
        !remote.is_empty() && Some(&remote) != pubs.get("terminal"),
        "holder remote"
    );
}
