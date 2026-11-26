//! repokernel_test.go: on a box with no core adding a repo goes to the kernel's serving secrets (the same calls
//! and signed answers): begin and finish are relayed there, never to the core; the signed deploy-key-added puts the
//! repo on the list; secrets' refusals come back with their status, a GitHub 403 explained.
use crate::nethttp::write_json;
use crate::testutil::*;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

fn core_calls(rg: &Rig) -> usize {
    rg.core
        .calls
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|c| c.starts_with("/deploy-keys"))
        .count()
}

fn err_of(v: &Value) -> String {
    v["error"].as_str().unwrap_or_default().to_string()
}

#[test]
fn deploy_keys_on_the_kernel() {
    let sk = Arc::new(TestKey::new());
    let calls: Arc<Mutex<Vec<String>>> = Arc::default();
    let finish = Arc::new(AtomicU16::new(200));
    let (k2, c2, f2) = (sk.clone(), calls.clone(), finish.clone());
    let secrets = TestServer::handler(move |w, req| {
        let b = String::from_utf8_lossy(&req.read_body(1 << 20)).into_owned();
        // the kernel's URL template names the component in the path: /secrets-blue/deploy-keys/…
        let path = req
            .path
            .split_once("/deploy-keys/")
            .map(|(_, p)| format!("/deploy-keys/{p}"))
            .unwrap_or_default();
        c2.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(format!("{path} {b}"));
        match path.as_str() {
            "/deploy-keys/begin" => write_json(
                w,
                200,
                &k2.doc(&json!({"kind": "deploy-key-begin", "pending": "p1",
                "repo": "DE0CH/jarvis4", "store": "github-jarvis4"})),
            ),
            "/deploy-keys/finish" => {
                if f2.load(Ordering::SeqCst) == 502 {
                    return write_json(w, 502, &k2.doc(&json!({"kind": "error", "error": "github: HTTP 403: Resource not accessible"})));
                }
                write_json(w, 200, &k2.doc(&json!({"kind": "deploy-key-added", "pending": "p1", "repo": "DE0CH/jarvis4",
                    "store": "github-jarvis4", "sensitive": true,
                    "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGQ2e3Hn7m0YkqNn3b0yQ1Bq0nqQ0P1n8n8n8n8n8n8n"})));
            }
            _ => w.write_header(404),
        }
    });
    let url = secrets.url.clone();
    let rg = Rig::with(move |c| {
        c.no_access = true;
        c.no_core = true;
        c.kernel_url = format!("{url}/%s");
    });
    let root: crate::types::GvSigned =
        serde_json::from_value(json!({"grant": {"payload": "{}", "sig": ""}, "by": "root"}))
            .unwrap_or_else(|e| panic!("{e}"));
    rg.st.do_(|d| d.kernel_root = Some(root.clone()));
    let n_calls = || calls.lock().unwrap_or_else(|e| e.into_inner()).len();

    // Jarvis 2's title would make secrets delete Jarvis 2's key for the repo: refused before anything is asked
    let (code, out) = app_do(
        &rg,
        "POST",
        "/api/repos/key/begin",
        r#"{"action": "add", "repo": "DE0CH/jarvis4", "store": "github-jarvis4", "title": "jarvis2 github-jarvis4"}"#,
        &[],
    );
    assert!(
        code == 400 && n_calls() == 0,
        "Jarvis 2's title: {code} {out}"
    );
    let (code, out) = app_do(
        &rg,
        "POST",
        "/api/repos/key/begin",
        r#"{"action": "add", "repo": "https://github.com/DE0CH/jarvis4", "sensitive": true, "store": "github-jarvis4", "title": "jarvis4 github-jarvis4"}"#,
        &[],
    );
    assert!(
        code == 200 && !out["payload"].is_null(),
        "begin: {code} {out}"
    );
    let (code, out) = app_do(
        &rg,
        "POST",
        "/api/repos/key/finish",
        r#"{"pending": "p1", "signature": "s", "share": {}}"#,
        &[],
    );
    assert!(
        code == 200 && !out["payload"].is_null(),
        "finish: {code} {out}"
    );
    assert_eq!(core_calls(&rg), 0, "the core was asked");
    let cs = calls.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        cs.len() == 2
            && cs[0].contains(r#""repo":"DE0CH/jarvis4""#)
            && cs[0].contains(r#""title":"jarvis4 github-jarvis4""#)
            && cs[1].starts_with("/deploy-keys/finish"),
        "secrets got {cs:?}"
    );
    let repos = rg.repos();
    assert!(
        repos.len() == 1 && repos[0].repo == "DE0CH/jarvis4" && repos[0].sensitive,
        "repos {repos:?}"
    );
    // GitHub refused the token: secrets' 502, explained
    finish.store(502, Ordering::SeqCst);
    let (code, out) = app_do(
        &rg,
        "POST",
        "/api/repos/key/finish",
        r#"{"pending": "p1"}"#,
        &[],
    );
    assert!(
        code == 502 && err_of(&out).contains("Administration: read and write"),
        "502: {code} {out}"
    );

    // a box with a core: the core keeps the deploy keys
    let rg2 = Rig::with(|c| c.no_access = true);
    app_do(
        &rg2,
        "POST",
        "/api/repos/key/begin",
        r#"{"action": "remove", "repo": "DE0CH/jarvis4"}"#,
        &[],
    );
    assert_eq!(
        core_calls(&rg2),
        1,
        "the core wasn't asked before the kernel serves"
    );
}
