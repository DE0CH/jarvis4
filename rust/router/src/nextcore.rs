//! The next core (blue/green; Deyao, 2026-10-15; docs/DESIGN.md "Core continuity", DECISIONS). A core release no longer
//! empties the core the sessions use: the new core runs NEXT to the serving one (NEXT_CORE_URL), Deyao Recovers it
//! ahead of time with the same kit as a STANDBY ("Recover alongside" in the app's Reset-or-Recover page, every core
//! call with ?core=next or "X-Jarvis2-Core: next"), and the router then FLIPS: drain → POST /handoff to the serving core
//! (it answers its FINAL line state and from then on refuses every call) → POST /takeover with that state to the
//! standby (it serves nothing before, and takes only a final state at least as new as the one it was Recovered with) →
//! every later core call goes to it. The cores themselves guarantee that at most one of them serves; the router only
//! chooses when.
//!
//! The flip is POST /setup/core/flip (setup-signed), or by itself with FLIP_AUTO=1 once the next core is a standby
//! (Recovered alongside). Which core serves is kept in the state (active_core), so a restarted router talks to the
//! same one.

use crate::core::{CoreClient, Doc};
use crate::ctx::Ctx;
use crate::http::Registrar;
use crate::nethttp::{Req, W, write_error, write_json};
use crate::router::Router;
use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// what the router asks of the cores for a flip (core continuity's contract)
pub trait CoreHandoff: Send + Sync {
    /// the serving core seals a FINAL line state and refuses every call from then on
    fn finalize(&self, c: &CoreClient) -> Result<Vec<u8>>;
    /// a next core (Recovered with the same kit) takes that final state and serves from then on
    fn adopt(&self, c: &CoreClient, final_state: &[u8]) -> Result<()>;
}

/// the core's endpoints (core continuity, DESIGN "Core continuity", DECISIONS 173):
///
///     POST /handoff  (no body) to the serving core → the FINAL line state {head, sealed}; head is core-signed
///                    {"kind": "line-state-head", seq, final: true, sha256, at}. From then on that core answers 409
///                    "this core is handed-off" to everything but GET /identity, GET /line-state and POST /handoff
///                    (which repeats the same final state).
///     POST /takeover {lineState: {head, sealed}} to a standby core (Recovered with "standby": true, same kit) → it
///                    takes the lines and the stores over and serves: signed {"kind": "took-over", lineSeq, stores};
///                    403 for a state that isn't final, from other keys, or older than the one it was Recovered with.
pub struct HttpHandoff;

fn trim_body(b: &[u8]) -> String {
    String::from_utf8_lossy(&b[..b.len().min(300)]).into_owned()
}

impl CoreHandoff for HttpHandoff {
    fn finalize(&self, c: &CoreClient) -> Result<Vec<u8>> {
        let (status, b) = c.raw("POST", "/handoff", None)?;
        if status != 200 {
            bail!("core POST /handoff: HTTP {status} {}", trim_body(&b));
        }
        Ok(b)
    }

    fn adopt(&self, c: &CoreClient, final_state: &[u8]) -> Result<()> {
        let fs: Value = serde_json::from_slice(final_state)?;
        let body = jarvis_go::marshal(&json!({"lineState": fs}));
        let (status, b) = c.raw("POST", "/takeover", Some(body.as_bytes()))?;
        if status != 200 {
            bail!("core POST /takeover: HTTP {status} {}", trim_body(&b));
        }
        Ok(())
    }
}

/// the router's side (one per router)
pub struct NextCores {
    /// None without NEXT_CORE_URL
    pub next: RwLock<Option<Arc<CoreClient>>>,
    pub handoff: RwLock<Arc<dyn CoreHandoff>>,
    flip_mu: Mutex<()>,
    final_state: Mutex<Option<Vec<u8>>>,
}

impl NextCores {
    pub fn from_env() -> NextCores {
        let u = std::env::var("NEXT_CORE_URL").unwrap_or_default();
        NextCores {
            next: RwLock::new((!u.is_empty()).then(|| Arc::new(CoreClient::new(&u)))),
            handoff: RwLock::new(Arc::new(HttpHandoff)),
            flip_mu: Mutex::new(()),
            final_state: Mutex::new(None),
        }
    }

    pub fn client(&self) -> Option<Arc<CoreClient>> {
        self.next.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn final_state(&self) -> Option<Vec<u8>> {
        self.final_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn set_final(&self, f: Option<Vec<u8>>) {
        *self.final_state.lock().unwrap_or_else(|e| e.into_inner()) = f;
    }
}

/// a core's identity as the flip reads it
#[derive(Debug, Clone, Default)]
pub struct CoreInfo {
    /// serving | standby | handed-off | "" (empty)
    pub serving: String,
    /// its signing key: the same for every Recover with the same kit
    pub key: String,
    /// its newest line state's number
    pub line_seq: i64,
}

pub fn core_view(c: &CoreClient) -> Result<CoreInfo> {
    let (status, b) = c.raw("GET", "/identity", None)?;
    if status != 200 {
        bail!("core /identity: HTTP {status}");
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Id {
        #[serde(rename = "signingKey")]
        signing_key: String,
        state: Doc,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct St {
        master: Value,
        serving: String,
        #[serde(rename = "lineSeq")]
        line_seq: i64,
    }
    let id: Id = jarvis_go::unmarshal(&b)?;
    let st: St = id.state.decode().unwrap_or_default();
    if st.master.as_str().unwrap_or("").is_empty() {
        return Ok(CoreInfo {
            key: id.signing_key,
            ..Default::default()
        });
    }
    let serving = if st.serving.is_empty() {
        "serving".into()
    } else {
        st.serving
    }; // a core from before continuity
    Ok(CoreInfo {
        serving,
        key: id.signing_key,
        line_seq: st.line_seq,
    })
}

/// what c's signed state says it does — "serving", "standby" (Recovered alongside, waiting for a takeover),
/// "handed-off" ("" for an empty core) — and its signing key
pub fn core_serving(c: &CoreClient) -> Result<(String, String)> {
    let v = core_view(c)?;
    Ok((v.serving, v.key))
}

/// how often the flip's drain looks at the next core again (ms; tests shorten it)
pub static DRAIN_WATCH_EVERY_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(30_000);

/// why the next core is no longer the standby it was before the drain ("" = it still is). A core release restarts it
/// empty (the outage of 2026-10-22: CI pinned a new core into the standby while the flip drained), a wipe or a Recover
/// with another kit gives it another key.
pub fn standby_gone(c: &CoreClient, key: &str) -> String {
    match core_view(c) {
        Err(e) => format!("the next core doesn't answer: {e:#}"),
        Ok(v) if v.serving != "standby" => format!(
            "the next core is {} now, no longer a standby",
            or_empty_core(&v.serving)
        ),
        Ok(v) if v.key != key => {
            "the next core has another signing key now (Recovered again, with another kit?)".into()
        }
        Ok(_) => String::new(),
    }
}

pub fn or_empty_core(s: &str) -> String {
    if s.is_empty() {
        "empty".into()
    } else {
        s.into()
    }
}

impl Router {
    /// tests and main (the URL and the handoff)
    pub fn set_next_core(&self, url: &str, h: Option<Arc<dyn CoreHandoff>>) {
        if !url.is_empty() {
            *self.next.next.write().unwrap_or_else(|e| e.into_inner()) =
                Some(Arc::new(CoreClient::new(url)));
        }
        if let Some(h) = h {
            *self.next.handoff.write().unwrap_or_else(|e| e.into_inner()) = h;
        }
    }

    /// at start, talk to the core the state says serves (a flip before a restart)
    pub fn apply_active_core(&self) {
        let Some(next) = self.next.client() else {
            return;
        };
        let active = self.st.do_(|d| d.active_core.clone());
        if !active.is_empty() && active == next.url() {
            let cur = self.core.url();
            self.core.set_url(&active);
            next.set_url(&cur);
            crate::logf!("core: {active} serves (flipped before), next is {cur}");
        }
    }

    /// the core a request names (?core=next or X-Jarvis2-Core: next), None when it names a next core there isn't
    pub fn core_for(&self, req: &Req) -> Option<Arc<CoreClient>> {
        if req.query("core") == "next" || req.header("X-Jarvis2-Core") == "next" {
            return self.next.client();
        }
        Some(self.core.clone())
    }

    /// relay to the core the request names
    pub fn relay_for(&self, w: &mut W, req: &Req, method: &str, path: &str, body: Option<&[u8]>) {
        let Some(c) = self.core_for(req) else {
            return write_error(w, 404, "there is no next core");
        };
        if Arc::ptr_eq(&c, &self.core) {
            return self.relay(w, method, path, body);
        }
        match c.raw(method, path, body) {
            Err(_) => write_json(
                w,
                503,
                &json!({"error": "the next core isn't running", "coreDown": true}),
            ),
            Ok((status, b)) => {
                w.set_header("Content-Type", "application/json");
                w.write_header(status);
                w.write(&b);
            }
        }
    }

    /// where a request's store call goes — the next core when it names one, else the stores' keeper (store_core: the
    /// kernel's serving secrets on a box with no core); None when it names a next core there isn't
    pub fn stores_for(&self, req: &Req) -> Option<Arc<CoreClient>> {
        let c = self.core_for(req)?;
        if !Arc::ptr_eq(&c, &self.core) {
            return Some(c);
        }
        Some(self.store_core())
    }

    /// a store call relayed to stores_for
    pub fn relay_stores(&self, w: &mut W, req: &Req, method: &str, path: &str, body: &[u8]) {
        let body = if method == "GET" { None } else { Some(body) };
        if self.secrets_stores.get().is_none() {
            return self.relay_for(w, req, method, path, body);
        }
        match self.stores_for(req) {
            None => write_error(w, 404, "there is no next core"),
            Some(c) => self.relay_to(w, &c, method, path, body),
        }
    }

    /// the next core serves from now on (see the top of the file). A flip whose takeover already happened (the next
    /// core serves and the current one is handed off) is finished instead (finish_flip).
    pub fn flip_core(&self, drain_max: Duration) -> Result<()> {
        let n = &self.next;
        let _g = n.flip_mu.lock().unwrap_or_else(|e| e.into_inner());
        let next = n
            .client()
            .ok_or_else(|| anyhow!("there is no next core (NEXT_CORE_URL)"))?;
        let nv = core_view(&next).map_err(|e| anyhow!("the next core: {e:#}"))?;
        if nv.serving == "serving" {
            return self.finish_flip(&next, &nv);
        }
        if nv.serving != "standby" {
            bail!(
                "the next core is {}, not a standby: Recover it alongside first (the app's Reset-or-Recover page, next core)",
                jarvis_go::fmt::go_quote(&or_empty_core(&nv.serving))
            );
        }
        crate::logf!("[flip] draining before the core flip");
        // the drain can take up to drain_max (29 minutes): it ends early once the next core stops being this standby
        let abort = Ctx::background();
        let stop = Ctx::background();
        let gone: Arc<Mutex<String>> = Arc::default();
        let watcher = {
            let (abort, stop, gone, next, key) = (
                abort.clone(),
                stop.clone(),
                gone.clone(),
                next.clone(),
                nv.key.clone(),
            );
            std::thread::spawn(move || {
                loop {
                    let every = Duration::from_millis(
                        DRAIN_WATCH_EVERY_MS.load(std::sync::atomic::Ordering::Relaxed),
                    );
                    if !stop.sleep(every) {
                        return;
                    }
                    let w = standby_gone(&next, &key);
                    if !w.is_empty() {
                        *gone.lock().unwrap_or_else(|e| e.into_inner()) = w;
                        abort.cancel();
                        return;
                    }
                }
            })
        };
        self.drain_until(drain_max, &abort);
        stop.cancel();
        let _ = watcher.join();
        let _undrain = crate::flows::scopeguard(|| self.undrain());
        // and once more after it: the serving core is handed off only to the standby that was checked before the drain
        let mut why = gone.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if why.is_empty() {
            why = standby_gone(&next, &nv.key);
        }
        if !why.is_empty() && n.final_state().is_none() {
            crate::logf!("[flip] aborted, the serving core goes on: {why}");
            self.dm(&format!("Jarvis 4: the core flip was aborted after its drain, nothing was handed off and the serving core goes on: {why}. Recover the next core alongside again for a new flip."));
            bail!("flip aborted, the serving core goes on: {why}");
        }
        let handoff = n.handoff.read().unwrap_or_else(|e| e.into_inner()).clone();
        let final_state = match n.final_state() {
            Some(f) => f,
            None => {
                let f = handoff
                    .finalize(&self.core)
                    .map_err(|e| anyhow!("finalizing the serving core: {e:#}"))?;
                n.set_final(Some(f.clone()));
                let _ = self.st.write_doc("core-final.json", &f); // kept beside the records (statedb.rs), for a retry
                f
            }
        };
        if let Err(e) = handoff.adopt(&next, &final_state) {
            // the old core is handed-off for good and can't serve: nothing serves until a takeover goes through (the
            // final state is kept for the retry; POST /handoff on the old core repeats it too)
            crate::logf!(
                "[flip] THE NEXT CORE REFUSED THE TAKEOVER: NO CORE SERVES (retry the flip): {e:#}"
            );
            self.dm(&format!("Jarvis 4: the core flip failed half way — the old core is handed off and the next one refused the takeover, so no core serves. Retry: POST /setup/core/flip. {e:#}"));
            bail!(
                "the next core refused the takeover (the old one is handed off: retry the flip): {e:#}"
            );
        }
        self.switch_cores(&next);
        Ok(())
    }

    /// the next core serves while the current one is handed off — a takeover went through the next core's own Recover
    /// (its bundle carried the final state the current core sealed) rather than the flip's POST /takeover. The router
    /// switches to it only if it has the handed-off core's signing key (the same kit) and a line state at least as new
    /// as the final state the router kept.
    fn finish_flip(&self, next: &Arc<CoreClient>, nv: &CoreInfo) -> Result<()> {
        let cv = core_view(&self.core)
            .map_err(|e| anyhow!("the next core serves, but the current core doesn't answer (is it handed off?): {e:#}"))?;
        if cv.serving != "handed-off" {
            bail!(
                "both cores say they serve (current {}, next serving): nothing changed, look at both before anything else",
                or_empty_core(&cv.serving)
            );
        }
        if nv.key != cv.key {
            bail!(
                "the next core serves with another signing key than the handed-off one (another kit): nothing changed"
            );
        }
        if let Some(f) = self.next.final_state() {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct Fs {
                head: Doc,
            }
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct H {
                seq: i64,
            }
            let fs: Fs = jarvis_go::unmarshal(&f).unwrap_or_default();
            let h: H = fs.head.decode().unwrap_or_default();
            if nv.line_seq < h.seq {
                bail!(
                    "the next core serves line state {}, older than the final state {} the current core handed off: nothing changed",
                    nv.line_seq,
                    h.seq
                );
            }
        }
        crate::logf!(
            "[flip] the next core took the final state over by its own Recover: finishing the flip"
        );
        self.switch_cores(next);
        Ok(())
    }

    /// every later core call goes to the next core, and the state says so (active_core), so a restarted router talks
    /// to it too. The final state is no longer needed.
    fn switch_cores(&self, next: &CoreClient) {
        let (cur, nxt) = (self.core.url(), next.url());
        self.core.set_url(&nxt);
        next.set_url(&cur);
        self.next.set_final(None);
        self.st.delete_doc("core-final.json");
        self.st.do_(|d| d.active_core = nxt.clone());
        crate::logf!("[flip] {nxt} serves now; {cur} is final (the next release goes there)");
    }

    /// FLIP_AUTO=1 flips once the next core is a standby, and finishes a flip whose takeover already happened
    pub fn next_core_loop(self: &Arc<Self>, every: Duration, drain_max: Duration) {
        loop {
            crate::leaderlease::await_lead();
            self.next_core_tick(drain_max);
            std::thread::sleep(every);
        }
    }

    pub fn next_core_tick(&self, drain_max: Duration) {
        let Some(next) = self.next.client() else {
            return;
        };
        if std::env::var("FLIP_AUTO").unwrap_or_default() != "1" {
            return;
        }
        let Ok((serving, _)) = core_serving(&next) else {
            return;
        };
        if serving == "serving" {
            // a takeover by the next core's own Recover: finished only while the current core is handed off
            match core_serving(&self.core) {
                Ok((cur, _)) if cur == "handed-off" => {}
                _ => return,
            }
        } else if serving != "standby" {
            return;
        }
        if let Err(e) = self.flip_core(drain_max) {
            crate::logf!("[flip] automatic flip: {e:#}");
        }
    }

    /// for the setup status: each core's URL, serving value and identity
    pub fn next_core_status(&self) -> Value {
        let view = |c: &CoreClient| {
            let mut v = Map::new();
            v.insert("url".into(), json!(c.url()));
            match core_serving(c) {
                Err(e) => {
                    v.insert("error".into(), json!(format!("{e:#}")));
                }
                Ok((serving, key)) => {
                    v.insert("serving".into(), json!(or_empty_core(&serving)));
                    v.insert("identity".into(), json!(key));
                }
            }
            v
        };
        let mut out = Map::new();
        out.insert("current".into(), Value::Object(view(&self.core)));
        out.insert(
            "activeCore".into(),
            json!(self.st.do_(|d| d.active_core.clone())),
        );
        if let Some(n) = self.next.client() {
            let mut nx = view(&n);
            nx.insert(
                "finalPending".into(),
                json!(self.next.final_state().is_some()),
            );
            out.insert("next".into(), Value::Object(nx));
        }
        Value::Object(out)
    }
}

/// GET /api/state's core.next: the app learns there is a next core (and what it is) and offers Recover alongside for
/// it, every call for it with X-Jarvis2-Core: next
pub fn nextcore_state_hook(r: &Arc<Router>, out: &mut Map<String, Value>) {
    let Some(n) = r.next.client() else { return };
    let Some(core) = out.get_mut("core").and_then(Value::as_object_mut) else {
        return;
    };
    let mut nx = Map::new();
    nx.insert("up".into(), json!(false));
    if let Ok((serving, key)) = core_serving(&n) {
        nx.insert("up".into(), json!(true));
        nx.insert("serving".into(), json!(or_empty_core(&serving)));
        nx.insert("signingKey".into(), json!(key));
    }
    core.insert("next".into(), Value::Object(nx));
}

/// the flip route
pub fn register_next_core(reg: &mut Registrar) {
    reg.setup_signed("POST /setup/core/flip", 1 << 16, |r, w, _, _| {
        let max: u64 = crate::router::env("DRAIN_SECONDS", "1740")
            .parse()
            .unwrap_or(0);
        if let Err(e) = r.flip_core(Duration::from_secs(max)) {
            return write_error(w, 409, &format!("{e:#}"));
        }
        write_json(w, 200, &r.next_core_status());
    });
}
