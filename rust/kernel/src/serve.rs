//! What every kernel component's server shares. A component makes fresh keys at start (RAM
//! only) and answers them at GET /identity; the root key vouches for them in the kernel's roster, which the router
//! brings with POST /roster and every component checks against KERNEL_ROOT (keys/root.pub). Every answer leaves
//! signed, errors too, so the untrusted router can't put words in a component's mouth.

use jarvis_nethttp::{HandlerFn, Mux, Req, W};
use jarvis_sig::{Component, IdentityError as IdError, Trust};
use jarvis_sig::{Doc, go_json, strict_json};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io::Write as _;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

pub use crate::flip::{
    Continuity, HANDOFF_INFO, Handoff, MODE_HANDED_OFF, MODE_SERVING, MODE_STANDBY,
    REASON_HANDED_OFF, REASON_STANDBY, Stateful,
};

/// an error with the HTTP status it answers and, for an answer the router acts on, a stable reason (the error answer's
/// "reason": a short kebab-case word the router matches instead of the message's words)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fail {
    pub code: u16,
    pub msg: String,
    pub reason: String,
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Fail {}

/// an error answered with code
pub fn fail(code: u16, msg: impl Into<String>) -> anyhow::Error {
    Fail {
        code,
        msg: msg.into(),
        reason: String::new(),
    }
    .into()
}

/// an error answered with code and the stable reason
pub fn fail_because(code: u16, reason: &str, msg: impl Into<String>) -> anyhow::Error {
    Fail {
        code,
        msg: msg.into(),
        reason: reason.into(),
    }
    .into()
}

/// "no roster yet", as Go's sig.ErrNoRoster
pub fn no_roster() -> String {
    IdError::NoRoster.to_string()
}

/// what a handler answers: a document signed already, or a value the component signs
pub enum Answer {
    Doc(Doc),
    /// the value as Go's json.Marshal writes it
    Payload(String),
}

impl Answer {
    pub fn of<T: Serialize + ?Sized>(v: &T) -> anyhow::Result<Answer> {
        Ok(Answer::Payload(go_json(v)?))
    }
}

/// a component's routes and keys; `handle` wraps a JSON handler
pub struct Server {
    pub c: Component,
    /// the root key's roster (to check the other components' identities)
    pub trust: Arc<Trust>,
    /// written only while the routes are set up; read by every request at once
    mux: RwLock<Mux>,
    /// a stateful component's handoff and takeover (flip.rs); unset for the stateless ones
    pub state: OnceLock<Arc<dyn Stateful>>,
    /// the roster this component handed over to ("" = it serves); held while a handoff or takeover runs
    pub(crate) frozen_to: Mutex<String>,
}

/// the root key's roster, as the router posts it
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterIn {
    pub roster: Doc,
}

impl Server {
    pub fn new(c: Component, t: Arc<Trust>) -> Arc<Server> {
        let s = Arc::new(Server {
            c,
            trust: t,
            mux: RwLock::new(Mux::new()),
            state: OnceLock::new(),
            frozen_to: Mutex::new(String::new()),
        });
        {
            let s2 = s.clone();
            s.route(
                "GET /identity",
                Arc::new(move |w: &mut W, _: &mut Req| {
                    s2.reply(w, 200, &Answer::of(&s2.c.identity).ok())
                }),
            );
        }
        {
            let s2 = s.clone();
            s.route(
                "GET /roster",
                Arc::new(move |w: &mut W, _: &mut Req| match s2.trust.doc() {
                    Some(d) => write_doc(w, 200, &d),
                    None => {
                        let e = serde_json::json!({"kind": "error", "error": no_roster()});
                        s2.reply(w, 404, &Answer::of(&e).ok());
                    }
                }),
            );
        }
        let s2 = s.clone();
        handle(&s, "POST /roster", move |inp: RosterIn| {
            s2.trust
                .set(inp.roster.clone(), Some(&s2.c.identity))
                .map_err(|e| fail(403, e.to_string()))?;
            if let Some(st) = s2.state.get()
                && let Some(r) = s2.trust.roster()
            {
                st.decide(&r)?;
            }
            log(&format!("{}: the root key's roster taken", s2.c.role));
            Answer::of(&serde_json::json!({"kind": "roster-taken", "roster": inp.roster.id()}))
        });
        crate::flip::register_flip(&s);
        s
    }

    /// a route as it is
    pub fn route(&self, pattern: &str, h: HandlerFn) {
        self.mux
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .handle(pattern, h);
    }

    /// the component's handler (its mux)
    pub fn handler(self: &Arc<Self>) -> HandlerFn {
        let s = self.clone();
        Arc::new(move |w: &mut W, req: &mut Req| {
            let m = s.mux.read().unwrap_or_else(|e| e.into_inner());
            m.serve(w, req);
        })
    }

    /// the handoff this component made ("" = none)
    pub fn frozen(&self) -> String {
        self.frozen_to
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// v signed by the component (None: it couldn't be marshalled, answered as "signing failed")
    pub fn reply(&self, w: &mut W, code: u16, a: &Option<Answer>) {
        match a {
            Some(Answer::Doc(d)) => write_doc(w, code, d),
            Some(Answer::Payload(p)) => {
                let d = Doc {
                    payload: p.clone(),
                    sig: self.c.signer.sign(p.as_bytes()),
                };
                write_doc(w, code, &d)
            }
            None => {
                w.set_header("Content-Type", "text/plain; charset=utf-8");
                w.write_header(500);
                w.write_str("signing failed\n");
            }
        }
    }
}

/// a document as Go's json.NewEncoder writes it (the line ends with "\n")
fn write_doc(w: &mut W, code: u16, d: &Doc) {
    w.set_header("Content-Type", "application/json");
    w.write_header(code);
    let mut s = go_json(d).unwrap_or_default();
    s.push('\n');
    w.write_str(&s);
}

/// what a component that handed over still answers
pub fn frozen_allowed(pattern: &str) -> bool {
    matches!(
        pattern,
        "GET /identity" | "GET /roster" | "POST /roster" | "POST /handoff" | "POST /takeover"
    )
}

/// POST pattern with a strict JSON body; the handler's answer is signed
pub fn handle<In: DeserializeOwned + 'static>(
    s: &Arc<Server>,
    pattern: &str,
    f: impl Fn(In) -> anyhow::Result<Answer> + Send + Sync + 'static,
) {
    let s2 = s.clone();
    let pat = pattern.to_string();
    s.route(
        pattern,
        Arc::new(move |w: &mut W, req: &mut Req| {
            if !s2.frozen().is_empty() && !frozen_allowed(&pat) {
                let e = serde_json::json!({"kind": "error", "reason": REASON_HANDED_OFF,
                    "error": format!("this {} handed over to the other kernel copy: it serves nothing", s2.c.role)});
                return s2.reply(w, 409, &Answer::of(&e).ok());
            }
            let body = req.read_body(8 << 20);
            let inp: In = match strict_json(&body) {
                Ok(v) => v,
                Err(e) => {
                    let e = serde_json::json!({"kind": "error", "error": format!("bad request: {e}")});
                    return s2.reply(w, 400, &Answer::of(&e).ok());
                }
            };
            match f(inp) {
                Ok(a) => s2.reply(w, 200, &Some(a)),
                Err(e) => {
                    let (code, reason) = match e.downcast_ref::<Fail>() {
                        Some(f) => (f.code, f.reason.clone()),
                        None if e.downcast_ref::<IdError>() == Some(&IdError::NoRoster) => {
                            (503, String::new())
                        }
                        None => (500, String::new()),
                    };
                    if code >= 500 {
                        log(&format!("{pat}: {e:#}"));
                    }
                    let mut out = serde_json::Map::new();
                    out.insert("kind".into(), "error".into());
                    out.insert("error".into(), format!("{e:#}").into());
                    if !reason.is_empty() {
                        out.insert("reason".into(), reason.into());
                    }
                    s2.reply(w, code, &Answer::of(&out).ok());
                }
            }
        }),
    );
}

static LOG_MU: Mutex<()> = Mutex::new(());

/// a line in the component's log, as Go's log.Printf ("2006/01/02 15:04:05 " first)
pub fn log(line: &str) {
    let t = jarvis_go::GoTime::now()
        .utc()
        .0
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let _g = LOG_MU.lock().unwrap_or_else(|e| e.into_inner());
    let _ = writeln!(
        std::io::stderr().lock(),
        "{:04}/{:02}/{:02} {:02}:{:02}:{:02} {}",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        line.trim_end_matches('\n')
    );
}

/// the component's process: its keys, its routes (setup adds them), then serve on KERNEL_ADDR (default :8080)
pub fn main(role: &str, setup: impl FnOnce(&Arc<Server>) -> anyhow::Result<()>) {
    let root = std::env::var("KERNEL_ROOT").unwrap_or_default();
    if root.is_empty() {
        fatal("KERNEL_ROOT (the root key's public half, keys/root.pub) isn't set");
    }
    let s = Server::new(Component::new(role), Arc::new(Trust::new(&root)));
    if let Err(e) = setup(&s) {
        fatal(&format!("{e:#}"));
    }
    let addr = std::env::var("KERNEL_ADDR")
        .ok()
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| ":8080".into());
    log(&format!(
        "{role}: serving on {addr} (signing key {})",
        s.c.identity.signing_key
    ));
    let rt = tokio::runtime::Runtime::new().unwrap_or_else(|e| fatal(&e.to_string()));
    let stop = tokio_util::sync::CancellationToken::new();
    if let Err(e) = rt.block_on(jarvis_nethttp::serve(&addr, s.handler(), stop)) {
        fatal(&format!("{e:#}"));
    }
}

pub fn fatal(msg: &str) -> ! {
    log(msg);
    std::process::exit(1);
}
