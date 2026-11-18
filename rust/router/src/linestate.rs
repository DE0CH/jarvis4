//! The core's line state (core/continuity.go, docs/DESIGN.md "Core continuity"): a core set up with the seed from the
//! master key seals what it must remember about lines (newest certs, killed/used, spent approvals, the input log's
//! head, the deploy-key stores) after every call that changes it, and names the newest number in every answer
//! (X-Line-Seq). The router keeps the newest one: in its database at once (line-state.json, before the call's answer
//! goes on), and in the backup bucket at most every few minutes and when it drains (keys/_jarvis2/line-state.json, for
//! a router or box that comes back without its database). At a Recover the app reads it (GET /api/core/line-state),
//! checks it and hands it back to the new core in the claim bundle. The router can't read or forge it (sealed and
//! signed by the core); it can withhold it (the lines then end, as before continuity) or serve an older one, which the
//! app refuses below the newest number it has seen itself.

use crate::backups::BackupBucket;
use crate::core::{CoreClient, Doc};
use crate::http::Registrar;
use crate::kernel::{KernelClient, KernelError};
use crate::nethttp::write_json;
use crate::state::State;
use anyhow::Result;
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub const LINE_SEQ_HEADER: &str = "X-Line-Seq";
/// the bucket's copy (the router may only add versions under keys/)
pub const LINE_STATE_OBJECT: &str = "keys/_jarvis2/line-state.json";
const LINE_BUCKET_PERIOD: Duration = Duration::from_secs(5 * 60);

/// as the core answers GET /line-state
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LineStateDoc {
    pub head: Doc,
    pub sealed: String,
}

/// what the router keeps — the core's doc and the core key that signed its head
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct KeptLineState {
    pub core: String,
    pub seq: i64,
    pub doc: LineStateDoc,
    pub at: GoTime,
}

pub type FetchFn = Box<dyn Fn() -> Result<(u16, Vec<u8>)> + Send + Sync>;
pub type KeyFn = Box<dyn Fn() -> String + Send + Sync>;
pub type BucketFn = fn() -> Option<BackupBucket>;

#[derive(Default)]
struct Kept {
    kept: Option<KeptLineState>,
    bucket_seq: i64,
    bucket_at: Option<Instant>,
    bucket_busy: bool,
}

pub struct LineKeeper {
    mu: Mutex<Kept>,
    /// where the kept line state is (router_docs: name)
    docs: Arc<State>,
    name: String,
    /// its copy in the bucket
    object: String,
    pub bucket: BucketFn,
    /// GET /line-state, raw
    fetch: FetchFn,
    /// the core's signing key (its identity)
    core_key: KeyFn,
}

impl LineKeeper {
    fn lock(&self) -> MutexGuard<'_, Kept> {
        self.mu.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn with(
        docs: Arc<State>,
        name: &str,
        object: &str,
        fetch: FetchFn,
        core_key: KeyFn,
    ) -> Arc<LineKeeper> {
        let kept = docs
            .read_doc(name)
            .and_then(|b| jarvis_go::unmarshal::<KeptLineState>(&b).ok())
            .filter(|x| !x.core.is_empty());
        Arc::new(LineKeeper {
            mu: Mutex::new(Kept {
                kept,
                ..Default::default()
            }),
            docs,
            name: name.into(),
            object: object.into(),
            bucket: crate::backups::backup_bucket_from_env,
            fetch,
            core_key,
        })
    }

    /// the router's keeper, wired to its core client
    pub fn new_core(docs: Arc<State>, c: Arc<CoreClient>) -> Arc<LineKeeper> {
        let c2 = c.clone();
        LineKeeper::with(
            docs,
            "line-state.json",
            LINE_STATE_OBJECT,
            Box::new(move || c.raw_no_hook("GET", "/line-state", None)),
            Box::new(move || match c2.raw_no_hook("GET", "/identity", None) {
                Ok((200, b)) => serde_json::from_slice::<serde_json::Value>(&b)
                    .ok()
                    .and_then(|v| {
                        v.get("signingKey")
                            .and_then(|s| s.as_str())
                            .map(String::from)
                    })
                    .unwrap_or_default(),
                _ => String::new(),
            }),
        )
    }

    /// the same for the kernel's secrets (kernel/secrets/continuity.go: its stores and the deploy-key stores, which
    /// have no backup), kept beside the core's (kernel-line-state.json; keys/_jarvis2/kernel-line-state.json)
    pub fn new_kernel(docs: Arc<State>, k: Arc<KernelClient>) -> Arc<LineKeeper> {
        let k2 = k.clone();
        LineKeeper::with(
            docs,
            "kernel-line-state.json",
            "keys/_jarvis2/kernel-line-state.json",
            Box::new(
                move || match k.call_no_hook("secrets", "GET", "/line-state", None) {
                    Ok(b) => Ok((200, b)),
                    Err(e) => match e.downcast_ref::<KernelError>() {
                        Some(ke) => Ok((ke.status, vec![])),
                        None => Err(e),
                    },
                },
            ),
            Box::new(move || {
                k2.forget("secrets"); // a restarted secrets has other keys
                k2.identity("secrets")
                    .map(|id| id.signing_key)
                    .unwrap_or_default()
            }),
        )
    }

    /// an answer named seq n — fetch and keep the core's line state when it isn't the kept one (a newer one, or
    /// another core's after a Reset). Synchronous, so the answer that moved it goes on only once it is kept.
    pub fn seen(self: &Arc<Self>, n: i64) {
        if n <= 0 {
            return;
        }
        let mut g = self.lock();
        if g.kept.as_ref().is_some_and(|k| k.seq == n) {
            return; // already kept (a lower number is another core, or one Recovered from an older state: the running core's word goes)
        }
        let b = match (self.fetch)() {
            Ok((200, b)) => b,
            Ok((st, _)) => {
                crate::logf!("line state {n}: GET /line-state: {st} <nil>");
                return;
            }
            Err(e) => {
                crate::logf!("line state {n}: GET /line-state: 0 {e:#}");
                return;
            }
        };
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Head {
            kind: String,
            seq: i64,
        }
        let parsed = jarvis_go::unmarshal::<LineStateDoc>(&b)
            .ok()
            .and_then(|d| Some((d.head.decode::<Head>().ok()?, d)));
        let Some((h, d)) = parsed.filter(|(h, _)| h.kind == "line-state-head") else {
            crate::logf!("line state {n}: not a line state");
            return;
        };
        let key = (self.core_key)();
        if key.is_empty() || !crate::http::verify_p256(&key, d.head.payload.as_bytes(), &d.head.sig)
        {
            crate::logf!(
                "line state {}: its head isn't signed by the running core",
                h.seq
            );
            return;
        }
        if g.kept
            .as_ref()
            .is_some_and(|k| k.core == key && k.seq == h.seq)
        {
            return;
        }
        let x = KeptLineState {
            core: key,
            seq: h.seq,
            doc: d,
            at: GoTime::now(),
        };
        if let Err(e) = self
            .docs
            .write_doc(&self.name, jarvis_go::marshal(&x).as_bytes())
        {
            crate::logf!("line state {}: can't write {}: {e:#}", h.seq, self.name);
            return;
        }
        g.kept = Some(x);
        if g.bucket_at
            .is_none_or(|t| t.elapsed() >= LINE_BUCKET_PERIOD)
            && !g.bucket_busy
        {
            g.bucket_busy = true;
            let k = self.clone();
            std::thread::spawn(move || k.to_bucket());
        }
    }

    /// the kept state into the bucket (a new version; never deletes one)
    fn to_bucket(&self) {
        let (x, bseq) = {
            let g = self.lock();
            (g.kept.clone(), g.bucket_seq)
        };
        (|| {
            let Some(x) = x.filter(|x| x.seq != bseq) else {
                return;
            };
            let Some(b) = (self.bucket)() else { return };
            if let Err(e) = b.put(&self.object, jarvis_go::marshal(&x).as_bytes()) {
                crate::logf!("line state {}: bucket: {e:#}", x.seq);
                return;
            }
            let mut g = self.lock();
            g.bucket_seq = x.seq;
            g.bucket_at = Some(Instant::now());
        })();
        self.lock().bucket_busy = false;
    }

    /// the newest into the bucket now (the router's drain)
    pub fn flush(&self) {
        let busy = {
            let mut g = self.lock();
            let b = g.bucket_busy;
            g.bucket_busy = true;
            b
        };
        if !busy {
            self.to_bucket();
        }
    }

    /// the kept state; without one (a router that lost its database), the bucket's copy
    pub fn current(&self) -> Option<KeptLineState> {
        if let Some(x) = self.lock().kept.clone() {
            return Some(x);
        }
        let b = (self.bucket)()?;
        let raw = b.get(&self.object, &BTreeMap::new()).ok()?;
        jarvis_go::unmarshal::<KeptLineState>(&raw)
            .ok()
            .filter(|y| !y.core.is_empty())
    }
}

pub fn register_line_state(reg: &mut Registrar) {
    // the kernel's secrets, the same way (KernelSetupView's Recover)
    reg.app("GET /api/kernel/line-state", |r, w, _| {
        match r.kernel_lines.get().and_then(|k| k.current()) {
            None => write_json(
                w,
                404,
                &json!({"error": "the router keeps no line state of the kernel's secrets"}),
            ),
            Some(x) => {
                w.set_header(LINE_SEQ_HEADER, &x.seq.to_string());
                write_json(w, 200, &x.doc);
            }
        }
    });
    // the app's Recover: the newest line state the router holds (the app checks the head against the derived key and
    // against the newest number it has seen; the router's word decides nothing)
    reg.app("GET /api/core/line-state", |r, w, _| {
        match r.lines().and_then(|k| k.current()) {
            None => write_json(w, 404, &json!({"error": "the router keeps no line state"})),
            Some(x) => {
                w.set_header(LINE_SEQ_HEADER, &x.seq.to_string());
                write_json(w, 200, &x.doc);
            }
        }
    });
}

/// the router's own object under keys/, which isn't a key backup (backups.rs leaves it out)
pub fn is_line_state_object(key: &str) -> bool {
    key.starts_with("keys/_jarvis2/")
}
