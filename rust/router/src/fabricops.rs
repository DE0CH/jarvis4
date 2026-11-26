//! The fabric's operator page (Deyao, 2026-11-20: "I should be able to see the machines and scaler view just like that
//! in YYC AI"): the fabric hermit's own /ops/ page and its snapshot, the page YYC AI's admins open on their hermit (the
//! same build: status, hosts and their slots, live and frozen sandboxes, the scaler, errors). YYC AI reaches it through
//! pigeon as an admin of its catalogue; the fabric hermit has no pigeon, so the router asks it with hermit's admin
//! token, behind Deyao's Access login like every app route. Read only: GET of the page and of the snapshot it polls
//! (its script fetches "snapshot?tz=…" relative to the page, so both live under one prefix).
//!
//! router env: FABRIC_HERMIT_URL, FABRIC_HERMIT_ADMIN_TOKEN (Secret router-secrets-fabric; fabricrunner.rs FABRIC_ENV
//! in tests).

use crate::fabricrunner::env;
use crate::http::Registrar;
use jarvis_nethttp::{Req, W, write_json};
use serde_json::json;
use std::io::Read;
use std::sync::LazyLock;
use std::time::Duration;

/// the app's paths and the fabric hermit's (hermit-api routes OPS_PAGE, OPS_SNAPSHOT)
const FABRIC_OPS_PATHS: &[(&str, &str)] = &[
    ("GET /api/fabric/ops/", "/ops/"),
    ("GET /api/fabric/ops/snapshot", "/ops/snapshot"),
];

/// the page's own headers that come through (its CSP and referrer policy; hermit ops.rs page_headers)
const FABRIC_OPS_HEADERS: &[&str] = &[
    "Content-Type",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Cache-Control",
];

static FABRIC_OPS_CLIENT: LazyLock<reqwest::blocking::Client> = LazyLock::new(|| {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_default()
});

pub fn register_fabric_ops(reg: &mut Registrar) {
    for &(pattern, path) in FABRIC_OPS_PATHS {
        reg.app(pattern, move |_, w, req| fabric_ops(w, req, path));
    }
}

fn fabric_ops(w: &mut W, req: &Req, path: &str) {
    let base = env("FABRIC_HERMIT_URL");
    let (base, token) = (base.trim_end_matches('/'), env("FABRIC_HERMIT_ADMIN_TOKEN"));
    if base.is_empty() || token.is_empty() {
        return write_json(
            w,
            503,
            &json!({"error": "this router has no fabric operator page (FABRIC_HERMIT_URL, FABRIC_HERMIT_ADMIN_TOKEN)"}),
        );
    }
    let mut u = format!("{base}{path}");
    if !req.raw_query.is_empty() {
        u = format!("{u}?{}", req.raw_query);
    }
    let resp = FABRIC_OPS_CLIENT
        .get(&u)
        .header("Authorization", format!("Bearer {token}"))
        .header("Aviary-Protocol", "hermit-core=1")
        .send();
    let resp = match resp {
        Err(e) => {
            return write_json(
                w,
                502,
                &json!({"error": format!("the fabric hermit did not answer: {e}")}),
            );
        }
        Ok(r) => r,
    };
    for h in FABRIC_OPS_HEADERS {
        if let Some(v) = resp.headers().get(*h).and_then(|v| v.to_str().ok()) {
            w.set_header(h, v);
        }
    }
    w.write_header(resp.status().as_u16());
    if let Err(e) = std::io::copy(&mut resp.take(16 << 20), w) {
        crate::logf!("[fabric-ops] GET {path}: {e}");
    }
}
