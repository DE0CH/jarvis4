//! apiproxy_test.go: the session API proxy, $JARVIS_URL for the session's scripts.

use super::testutil::*;
use super::vouch::attest_for;
use crate::apiproxy::*;
use crate::cert::Cert;
use crate::client::Client;
use crate::crypto::SignedDoc;
use crate::rt;
use std::sync::{Arc, Mutex};

/// the proxy on 127.0.0.1, forwarding to c's router → its base URL
fn proxy(c: &Client) -> (String, tokio::task::JoinHandle<()>) {
    let app = api_proxy_router(c.clone());
    rt::block_on(async move {
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", ln.local_addr().unwrap());
        let h = tokio::spawn(async move {
            let _ = axum::serve(ln, app).await;
        });
        (url, h)
    })
}

fn call(method: &str, url: &str, body: &str, headers: &[(&str, &str)]) -> (u16, String) {
    let (method, url, body) = (
        reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
        url.to_string(),
        body.to_string(),
    );
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    rt::block_on(async move {
        let mut r = reqwest::Client::new().request(method, &url).body(body);
        for (k, v) in headers {
            r = r.header(k, v);
        }
        let resp = r.send().await.unwrap();
        let st = resp.status().as_u16();
        (st, resp.text().await.unwrap())
    })
}

#[test]
fn proxy_forwards_signed() {
    let e = TestEnv::new();
    let key = e.machine_key();
    let got: Arc<Mutex<Option<Req>>> = Arc::new(Mutex::new(None));
    let g2 = got.clone();
    let srv = FakeRouter::new(&key.sig.public_key(), move |r| {
        *g2.lock().unwrap() = Some(r);
        Ans {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: br#"{"hits":[]}"#.to_vec(),
        }
    });
    let (p, h) = proxy(&srv.client());
    let (st, _) = call(
        "PUT",
        &format!("{p}/api/sessions/s1/content/my%20store/file?path=a%2Fb.txt"),
        "data",
        &[
            ("CF-Access-Client-Id", "placeholder"),
            ("Authorization", "Bearer placeholder"),
            ("Content-Type", "application/octet-stream"),
        ],
    );
    assert_eq!(st, 200);
    let r = got.lock().unwrap().clone().unwrap();
    assert_eq!(r.path, "/m/api/sessions/s1/content/my store/file");
    assert_eq!(r.query, "path=a%2Fb.txt");
    assert_eq!(r.body, b"data");
    assert!(
        r.headers.get("Authorization").is_none() && r.headers.get("CF-Access-Client-Id").is_none()
    );
    assert_eq!(
        r.headers.get("Content-Type").and_then(|v| v.to_str().ok()),
        Some("application/octet-stream")
    );
    // secrets and changes for another session are refused locally
    assert_eq!(
        call("GET", &format!("{p}/api/sessions/sX/secrets"), "", &[]).0,
        403
    );
    h.abort();
}

#[test]
fn proxy_arming_gives_no_shell() {
    let e = TestEnv::new();
    let key = e.machine_key();
    *crate::grants::TEST_CERT.lock().unwrap() = Some(Cert {
        line: "m1".into(),
        sensitive: true,
        ..Default::default()
    });
    let at = (crate::util::unix_now() + 7200) * 1000;
    let srv = FakeRouter::new(&key.sig.public_key(), move |r| match r.path.as_str() {
        "/m/api/sessions/s1/wakeup" => {
            ok_json(serde_json::json!({"ok": true, "wakeup": {"name": "default", "at": at}}))
        }
        _ => ans(404, ""),
    });
    let (p, h) = proxy(&srv.client());
    let (st, b) = call(
        "POST",
        &format!("{p}/api/sessions/s1/wakeup"),
        r#"{"delaySeconds":7200,"prompt":"x"}"#,
        &[("Content-Type", "application/json")],
    );
    assert!(
        st == 200
            && b.contains(r#""ok":true"#)
            && b.contains("no shell access granted")
            && b.contains("approves or denies that message on the phone"),
        "{st} {b}"
    );
    assert!(
        crate::grants::read_allow().is_empty(),
        "something was put on the allow list"
    );
    h.abort();
}

#[test]
fn repo_changes_counts() {
    let e = TestEnv::new();
    let ws = e.root.join("ws");
    let d = ws.join("r");
    std::fs::create_dir_all(&d).unwrap();
    let mut c = std::process::Command::new("git");
    c.args(["-C", d.to_str().unwrap(), "init", "-q"]);
    crate::env::apply(&mut c);
    assert!(c.status().unwrap().success());
    std::fs::write(d.join("a"), "x").unwrap();
    let got = repo_changes(&ws);
    assert!(
        got.len() == 1 && got[0].name == "r" && got[0].uncommitted == 1 && got[0].unpushed == -1,
        "{got:?}"
    );
}

#[test]
fn proxy_takes_a_content_file_only_attested() {
    let e = TestEnv::new();
    let key = e.machine_key();
    let core = new_key();
    *TEST_CORE_KEY.lock().unwrap() = Some(core.public());
    let attest: Arc<Mutex<Option<SignedDoc>>> = Arc::new(Mutex::new(None));
    let a2 = attest.clone();
    let srv = FakeRouter::new(&key.sig.public_key(), move |r| {
        if r.path != "/m/api/sessions/m1/content/notes/file" || r.query != "path=a.txt" {
            return ans(404, "");
        }
        let mut headers = vec![];
        if let Some(a) = a2.lock().unwrap().as_ref() {
            headers.push(("X-Jarvis2-Attest".to_string(), crate::gojson::marshal(a)));
        }
        Ans {
            status: 200,
            headers,
            body: b"hello".to_vec(),
        }
    });
    let (p, h) = proxy(&srv.client());
    let get = || {
        call(
            "GET",
            &format!("{p}/api/sessions/m1/content/notes/file?path=a.txt"),
            "",
            &[],
        )
    };
    for a in [
        None,
        Some(attest_for(&core, "m2", "content", b"hello")),
        Some(attest_for(&core, "m1", "attachment", b"hello")),
        Some(attest_for(&core, "m1", "content", b"other")),
        Some(attest_for(&new_key(), "m1", "content", b"hello")),
    ] {
        *attest.lock().unwrap() = a.clone();
        assert_eq!(get().0, 502, "taken without a matching attestation ({a:?})");
    }
    *attest.lock().unwrap() = Some(attest_for(&core, "m1", "content", b"hello"));
    assert_eq!(get(), (200, "hello".to_string()));
    assert_eq!(
        call(
            "GET",
            &format!("{p}/api/sessions/sX/content/notes/file?path=a.txt"),
            "",
            &[]
        )
        .0,
        403,
        "another session"
    );
    h.abort();
}

/// jarvis-request batch: the batch reaches the router as /m/api/requests/batch, signed, body unchanged
#[test]
fn proxy_forwards_a_batch() {
    let e = TestEnv::new();
    let key = e.machine_key();
    let got: Arc<Mutex<(String, Vec<u8>)>> = Arc::new(Mutex::new(Default::default()));
    let g2 = got.clone();
    let srv = FakeRouter::new(&key.sig.public_key(), move |r| {
        *g2.lock().unwrap() = (r.path.clone(), r.body.clone());
        Ans {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: br#"{"id":"b1","items":[]}"#.to_vec(),
        }
    });
    let (p, h) = proxy(&srv.client());
    let inp = r#"{"summary":"two grants","items":[{"intent":"grant","holder":"status","minutes":5},{"intent":"grant","holder":"remote"}]}"#;
    let (st, b) = call(
        "POST",
        &format!("{p}/api/requests/batch"),
        inp,
        &[("Content-Type", "application/json")],
    );
    assert_eq!(st, 200);
    let out: serde_json::Value = serde_json::from_str(&b).unwrap();
    let (path, body) = got.lock().unwrap().clone();
    assert!(
        path == "/m/api/requests/batch" && body == inp.as_bytes() && out["id"] == "b1",
        "forwarded {path} {body:?} {out}"
    );
    h.abort();
}
