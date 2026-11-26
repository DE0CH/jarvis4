//! fabricops_test.go
use crate::fabricrunner::FABRIC_ENV;
use crate::testutil::{TestServer, new_test_router, serial};
use jarvis_nethttp::{Req, W};
use std::sync::{Arc, Mutex};

/// the fabric's settings put back when dropped
struct Undo;

impl Drop for Undo {
    fn drop(&mut self) {
        *FABRIC_ENV.write().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

fn set_env(url: &str, token: &str) {
    *FABRIC_ENV.write().unwrap_or_else(|e| e.into_inner()) = Some(
        [
            ("FABRIC_HERMIT_URL", url),
            ("FABRIC_HERMIT_ADMIN_TOKEN", token),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
    );
}

/// the fabric's operator page: the fabric hermit's /ops/ and its snapshot, asked with hermit's admin token, the page's
/// own headers passed on; no token, no page
#[test]
fn fabric_ops_page() {
    let _g = serial();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let s2 = seen.clone();
    let hermit = TestServer::handler(move |w, req| {
        let uri = if req.raw_query.is_empty() {
            req.path.clone()
        } else {
            format!("{}?{}", req.path, req.raw_query)
        };
        s2.lock().unwrap_or_else(|e| e.into_inner()).push(format!(
            "{} {uri} {} {}",
            req.method,
            req.header("Authorization"),
            req.header("Aviary-Protocol")
        ));
        match req.path.as_str() {
            "/ops/" => {
                w.set_header("Content-Type", "text/html; charset=utf-8");
                w.set_header("Content-Security-Policy", "default-src 'none'");
                w.write_str("<title>Jarvis 4 fabric Ops</title>");
            }
            "/ops/snapshot" => {
                w.set_header("Content-Type", "application/json");
                w.write_str(r#"{"hosts":[]}"#);
            }
            _ => w.write_header(404),
        }
    });
    let _undo = Undo;
    set_env(&hermit.url, "adm");
    let t = new_test_router();
    let h = t.handler();
    let get = |path: &str| {
        let mut w = W::recorder();
        let mut req = Req::new("GET", path, b"");
        h(&mut w, &mut req);
        w
    };
    let w = get("/api/fabric/ops/");
    let csp = w
        .headers
        .get("Content-Security-Policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        w.status() == 200 && w.body_text().contains("fabric Ops") && csp == "default-src 'none'",
        "{} {:?} {:?}",
        w.status(),
        w.body_text(),
        w.headers
    );
    let w = get("/api/fabric/ops/snapshot?tz=Asia%2FHong_Kong");
    assert!(
        w.status() == 200 && w.body_text() == r#"{"hosts":[]}"#,
        "{} {}",
        w.status(),
        w.body_text()
    );
    assert_eq!(
        seen.lock().unwrap_or_else(|e| e.into_inner()).join("|"),
        "GET /ops/ Bearer adm hermit-core=1|GET /ops/snapshot?tz=Asia%2FHong_Kong Bearer adm hermit-core=1"
    );
    set_env(&hermit.url, "");
    assert_eq!(get("/api/fabric/ops/").status(), 503, "no token");
}
