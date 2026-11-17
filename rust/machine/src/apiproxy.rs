//! The session-facing API, machine side. Jarvis 1's session scripts (schedule-wakeup, schedule-cron, lease.py,
//! transcript-search.py, content-sync, …) call `$JARVIS_URL/api/...` with Cloudflare Access headers and the session's
//! SESSION_API_TOKEN. In a Jarvis 4 session JARVIS_URL is this proxy (127.0.0.1:7171, served by supervisor-normal): it
//! drops those headers and forwards each request to the router as /m/api/<rest>, signed with the machine key like every
//! other /m call.
//!
//! Two calls never leave the machine: GET …/secrets (refused: the supervisor serves the secrets on its own socket) and
//! GET …/changes (the repos' uncommitted/unpushed work).
//!
//! A wakeup, cron or watch the session arms comes back as a delivery of its own signed request (deliver.rs): no router
//! feature gets a shell for it.

use crate::client::{Client, Resp};
use crate::crypto::SignedDoc;
use crate::session::session_command;
use crate::{gojson, logf, rt, util};
use anyhow::{Result, anyhow, bail};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{any, get, post};
use serde::Serialize;
use std::sync::Mutex;

pub const API_PROXY_ADDR: &str = "127.0.0.1:7171";
const API_MAX_BODY: usize = 64 << 20;

/// serve_api_proxy: runs for the supervisor's life
pub fn serve_api_proxy(c: &Client) {
    let addr = std::env::var("JARVIS_API_ADDR")
        .ok()
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| API_PROXY_ADDR.to_string());
    logf!("session API on http://{addr} (→ router /m/api)");
    let app = api_proxy_router(c.clone());
    let r = rt::block_on(async move {
        let ln = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(ln, app).await
    });
    if let Err(e) = r {
        logf!("session API stopped: {e}");
    }
}

fn json_resp<T: Serialize>(status: u16, v: &T) -> Response {
    let mut r = Response::new(Body::from(format!("{}\n", gojson::marshal(v))));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    r.headers_mut()
        .insert("Content-Type", HeaderValue::from_static("application/json"));
    r
}

fn err_resp(status: u16, msg: &str) -> Response {
    json_resp(status, &std::collections::BTreeMap::from([("error", msg)]))
}

fn copy_resp(r: Resp) -> Response {
    let mut out = Response::new(Body::from(r.body));
    *out.status_mut() = StatusCode::from_u16(r.status).unwrap_or(StatusCode::BAD_GATEWAY);
    for h in ["Content-Type", "Content-Range", "Content-Disposition"] {
        if let Some(v) = r.headers.get(h)
            && let Ok(v) = HeaderValue::from_bytes(v.as_bytes())
        {
            out.headers_mut().insert(h, v);
        }
    }
    out
}

pub fn api_proxy_router(c: Client) -> Router {
    Router::new()
        .route("/api/sessions/{id}/secrets", get(secrets).fallback(forward))
        .route("/api/sessions/{id}/changes", get(changes).fallback(forward))
        .route(
            "/api/sessions/{id}/content/{name}/file",
            get(content_file).fallback(forward),
        )
        .route("/api/sessions/{id}/wakeup", post(armed).fallback(forward))
        .route("/api/sessions/{id}/wakeups", post(armed).fallback(forward))
        .route("/api/sessions/{id}/crons", post(armed).fallback(forward))
        .route("/api/{*rest}", any(forward))
        .route("/api/", any(forward))
        .fallback(|| async { err_resp(404, "only /api/… is served here") })
        .with_state(c)
}

/// Jarvis 1's scripts name the session by SESSION_ID (the router's id) or FLY_MACHINE_ID
fn own_session(c: &Client, id: &str) -> Option<Response> {
    let sid = crate::vouch::session_id(&c.me);
    if id == sid || id == c.me {
        return None;
    }
    Some(err_resp(403, &format!("this is session {sid}, not {id}")))
}

/// run blocking work (the signed client) off the runtime's workers
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    match tokio::task::spawn_blocking(f).await {
        Ok(v) => v,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}

async fn secrets(State(c): State<Client>, Path(id): Path<String>) -> Response {
    if let Some(r) = own_session(&c, &id) {
        return r;
    }
    // the secrets don't travel over HTTP: the supervisor serves them on its own socket (secrets.rs, session-secret)
    err_resp(
        410,
        "the session's secrets come from the supervisor: session-secret --names | --keys K1,K2 --exec CMD",
    )
}

async fn changes(State(c): State<Client>, Path(id): Path<String>) -> Response {
    if let Some(r) = own_session(&c, &id) {
        return r;
    }
    let repos = blocking(|| repo_changes(&crate::paths::home().join("workspace"))).await;
    json_resp(
        200,
        &serde_json::json!({"checked": true, "repos": repos, "status": ""}),
    )
}

/// the request forwarded as /m/api/<rest>; the signature covers the decoded path, as the router checks it
async fn forward_req(c: &Client, req: Request) -> Result<Resp> {
    let method = req.method().as_str().to_string();
    let uri = req.uri().clone();
    let ct = req
        .headers()
        .get("Content-Type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body: Bytes = axum::body::to_bytes(req.into_body(), API_MAX_BODY + 1)
        .await
        .map_err(|_| anyhow!("request body too large"))?;
    if body.len() > API_MAX_BODY {
        bail!("request body too large");
    }
    let escaped = format!("/m{}", uri.path());
    let path = format!("/m{}", util::path_unescape(uri.path()));
    let query = uri.query().unwrap_or("").to_string();
    let c = c.clone();
    blocking(move || c.signed_do(&method, &path, &escaped, &query, &body, &ct)).await
}

async fn forward(State(c): State<Client>, req: Request) -> Response {
    match forward_req(&c, req).await {
        Ok(r) => copy_resp(r),
        Err(e) => err_resp(502, &format!("Jarvis 4 router unreachable: {e:#}")),
    }
}

/// a content file (content-sync, a task's script): taken only with the core's attestation of exactly these bytes
async fn content_file(
    State(c): State<Client>,
    Path((id, _name)): Path<(String, String)>,
    req: Request,
) -> Response {
    if let Some(r) = own_session(&c, &id) {
        return r;
    }
    let qpath = req
        .uri()
        .query()
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("path=")))
        .map(util::path_unescape)
        .unwrap_or_default();
    let r = match forward_req(&c, req).await {
        Ok(r) => r,
        Err(e) => return err_resp(502, &format!("Jarvis 4 router unreachable: {e:#}")),
    };
    if r.status == 200 {
        let hdr = r
            .headers
            .get("X-Jarvis2-Attest")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let (me, body) = (c.me.clone(), r.body.clone());
        if let Err(e) = blocking(move || check_content_attest(&me, &hdr, &body)).await {
            logf!("content: refused {qpath}: {e:#}");
            return err_resp(502, &format!("content file refused: {e:#}"));
        }
    }
    copy_resp(r)
}

/// arming: the answer says how it will be delivered
async fn armed(State(c): State<Client>, req: Request) -> Response {
    let r = match forward_req(&c, req).await {
        Ok(r) => r,
        Err(e) => return err_resp(502, &format!("Jarvis 4 router unreachable: {e:#}")),
    };
    let ans: Option<serde_json::Map<String, serde_json::Value>> =
        serde_json::from_slice(&r.body).ok();
    let Some(mut ans) =
        ans.filter(|a| r.status == 200 && a.get("ok") == Some(&serde_json::Value::Bool(true)))
    else {
        return copy_resp(r);
    };
    // the wakeup comes back as a delivery of this very request (deliver.rs), checked against this line's keys and
    // attested by the core; nobody needs a shell for it
    ans.insert(
        "delivery".into(),
        "delivered as this session's own signed request; no shell access granted".into(),
    );
    if blocking(|| {
        crate::grants::current_cert()
            .map(|c| c.sensitive)
            .unwrap_or(false)
    })
    .await
    {
        ans.insert("note".into(), "this session holds a sensitive store: when it is due, Deyao approves or denies that message on the phone (or a standing rule he signed for its kind delivers it); a denial comes back as an Inbox outcome".into());
    }
    json_resp(200, &ans)
}

// ---- changes (Jarvis 1's GET /api/sessions/:id/changes) ----------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize)]
pub struct RepoChange {
    pub name: String,
    pub uncommitted: i64,
    /// -1: the branch has no upstream
    pub unpushed: i64,
}

pub fn repo_changes(workspace: &std::path::Path) -> Vec<RepoChange> {
    let mut dirs: Vec<std::path::PathBuf> = std::fs::read_dir(workspace)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join(".git").exists())
        .collect();
    dirs.sort();
    dirs.iter()
        .map(|d| {
            let ds = d.to_string_lossy().into_owned();
            let mut rc = RepoChange {
                name: d
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                ..Default::default()
            };
            if let Ok(o) = session_command("git", &["-C", &ds, "status", "--porcelain"]).output()
                && o.status.success()
            {
                rc.uncommitted = String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .count() as i64;
            }
            let up = session_command("git", &["-C", &ds, "rev-parse", "--abbrev-ref", "@{u}"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            if !up.is_ok_and(|s| s.success()) {
                rc.unpushed = -1;
            } else if let Ok(o) =
                session_command("git", &["-C", &ds, "rev-list", "@{u}..HEAD", "--count"]).output()
                && o.status.success()
            {
                rc.unpushed = String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse()
                    .unwrap_or(0);
            }
            rc
        })
        .collect()
}

/// tests give their own core key here
pub static TEST_CORE_KEY: Mutex<Option<String>> = Mutex::new(None);

pub fn test_core_key() -> Option<String> {
    TEST_CORE_KEY.lock().ok().and_then(|g| g.clone())
}

/// the core's input-log entry (machine, "content", sha256 of the bytes) the router sent with a content file
pub fn check_content_attest(me: &str, header: &str, body: &[u8]) -> Result<()> {
    let core_key =
        crate::kernelboot::attest_key().map_err(|_| anyhow!("no core key on this machine"))?;
    let d: SignedDoc = match (
        header.is_empty(),
        gojson::unmarshal::<SignedDoc>(header.as_bytes()),
    ) {
        (false, Ok(d)) => d,
        _ => bail!("no core attestation (the input isn't in the core's log)"),
    };
    crate::deliver::check_attest(&core_key, me, "content", body, Some(&d))
}
