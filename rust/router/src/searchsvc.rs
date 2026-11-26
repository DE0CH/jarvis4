//! The iCloud index: its own pods (services/icloud-index; k8s/cluster/services/icloud-index, off since 2026-10-22). The
//! router forwards to it, for the app's Search tab (/api/...) and for sessions (/m/api/..., the machine's local proxy).
//! It is identity-level (Deyao, 2026-10-13): its paths, OCR'd text and downloads act as Deyao's own files, so a session
//! reaches it only while its cert holds the `identity` store (where the iCloud login lives); any other session gets
//! 403. It has no login of its own: only the router can reach it (its NetworkPolicy), and the router is behind
//! Cloudflare Access (the app) or the machine signature (sessions). Shapes: docs/API.md "iCloud index". Transcript
//! search is not Jarvis's: DE0CH/deyao-ai, at search.deyaochen.com behind its own Access app.
//!
//! router env: ICLOUD_INDEX_URL (default http://10.77.0.3:30091).

use crate::http::Registrar;
use crate::router::Router;
use anyhow::{Result, anyhow};
use jarvis_nethttp::{Req, W, write_error, write_json};
use serde_json::json;
use std::sync::LazyLock;
use std::time::Duration;

/// the store a session's cert must hold to reach the iCloud index
pub const ICLOUD_STORE: &str = "identity";

#[derive(Clone, Copy)]
struct SvcRoute {
    pattern: &'static str,
    svc: &'static str,
    path: &'static str,
}

/// method + path under /api (the app; sessions get the same under /m/api) → service + its own path
const SEARCH_ROUTES: &[SvcRoute] = &[
    SvcRoute {
        pattern: "GET /api/icloud/search",
        svc: "icloud",
        path: "/search",
    },
    SvcRoute {
        pattern: "GET /api/icloud/file",
        svc: "icloud",
        path: "/file",
    },
    SvcRoute {
        pattern: "GET /api/icloud/status",
        svc: "icloud",
        path: "/status",
    },
    SvcRoute {
        pattern: "POST /api/icloud/relist",
        svc: "icloud",
        path: "/relist",
    },
    SvcRoute {
        pattern: "POST /api/icloud/retry",
        svc: "icloud",
        path: "/retry",
    },
];

/// a search may take its time, but the service answers a connect at once inside the cluster; one that doesn't (the box
/// down, or no services box at all, as in CI) is an error in seconds, not after two minutes
static SEARCH_CLIENT: LazyLock<reqwest::blocking::Client> = LazyLock::new(|| {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(4)
        .build()
        .unwrap_or_default()
});

/// the iCloud index (ICLOUD_INDEX_URL; a test's fake)
pub static ICLOUD_INDEX_BASE: LazyLock<std::sync::RwLock<String>> = LazyLock::new(|| {
    std::sync::RwLock::new(crate::router::env(
        "ICLOUD_INDEX_URL",
        "http://10.77.0.3:30091",
    ))
});

fn service_base(_svc: &str) -> (String, &'static str) {
    (
        ICLOUD_INDEX_BASE
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .trim_end_matches('/')
            .to_string(),
        "the iCloud index",
    )
}

pub fn register_search_services(reg: &mut Registrar) {
    for &rt in SEARCH_ROUTES {
        reg.app(rt.pattern, move |_, w, req| {
            let b = req.read_body(1 << 20);
            forward_service(w, req, rt, b);
        });
        reg.m(&rt.pattern.replacen(" /api/", " /m/api/", 1), move |r, w, req, machine, body| {
            let stores = match r.machine_session_stores(machine) {
                Ok(s) => s,
                Err(e) => return write_error(w, 403, &format!("{e:#}")),
            };
            if rt.svc == "icloud" && !stores.iter().any(|s| s == ICLOUD_STORE) {
                return write_json(
                    w,
                    403,
                    &json!({"error": format!("the iCloud index needs the {ICLOUD_STORE} store in this session: jarvis-request add-store {ICLOUD_STORE} --why \"…\""), "needsStore": ICLOUD_STORE}),
                );
            }
            forward_service(w, req, rt, body.to_vec());
        });
    }
}

impl Router {
    /// the stores in the cert of the machine's running session (the cert's own list: it follows add-store and
    /// downgrade)
    pub fn machine_session_stores(&self, machine: &str) -> Result<Vec<String>> {
        self.st
            .do_(|d| {
                let sid = d.machines.get(machine)?;
                let s = d.sessions.get(sid).filter(|s| s.machine_id == machine)?;
                Some(s.stores.clone().unwrap_or_default())
            })
            .ok_or_else(|| anyhow!("this machine isn't a running session"))
    }
}

/// method, the service's path, the query and body unchanged; the service's status and JSON back
fn forward_service(w: &mut W, req: &Req, rt: SvcRoute, body: Vec<u8>) {
    let (base, name) = service_base(rt.svc);
    let mut u = format!("{base}{}", rt.path);
    if !req.raw_query.is_empty() {
        u = format!("{u}?{}", req.raw_query);
    }
    let method = reqwest::Method::from_bytes(req.method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut out = SEARCH_CLIENT.request(method, &u).body(body);
    let ct = req.header("Content-Type");
    if !ct.is_empty() {
        out = out.header("Content-Type", ct);
    }
    let mut resp = match out.send() {
        Err(e) => return write_error(w, 502, &format!("{name} unreachable: {e}")),
        Ok(r) => r,
    };
    if let Some(ct) = resp
        .headers()
        .get("Content-Type")
        .and_then(|v| v.to_str().ok())
    {
        w.set_header("Content-Type", ct);
    }
    w.write_header(resp.status().as_u16());
    if let Err(e) = std::io::copy(&mut resp, w) {
        crate::logf!("[search] {} {u}: {e}", req.method);
    }
}
