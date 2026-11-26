//! The final snapshot without free disk on the machine (snapsafe.rs): the machine streams its tar straight into the
//! request body as it makes it (rust/machine/src/snapstream.rs upload_snapshot), so it needs no room for a local copy.
//!
//! ```text
//! POST /m/snapshot-stream   the body, streamed into the bucket (snapstore.rs) and hashed on the way. The request is
//!                           signed over the constant body marker "stream" (the hash isn't known before the bytes), so
//!                           the router checks the machine before it takes a byte. → {sha256, bytes}: the hash the router
//!                           computed, kept as the machine's pending snapshot.
//! POST /m/snapshot-commit   {sha256, sig}: the machine compares the router's hash with its own, signs it with its
//!                           current key (the one signature of its life, as before) and commits; the router checks the
//!                           signature and that the pending file has that hash, then puts it in place: the snapshot.
//! POST /m/snapshot-failed   {error}: the machine couldn't take it; the waiting pause stops waiting at once.
//! POST /m/snapshot-carry    {sha256, sig}: a machine asked while it is still booting has no state of its own: its state
//!                           is its predecessor's snapshot, the one its cert names (a kernel machine: the one its source
//!                           names). It signs that hash; the router links the predecessor's file as this machine's
//!                           snapshot, so the line goes on from it instead of losing it (and the machine stops booting).
//! ```
//!
//! POST /m/snapshot (a whole file signed over its hash) stays for older images.

use crate::http::{Registrar, verify_p256, write_err};
use crate::router::Router;
use crate::snapwait::MovedReader;
use anyhow::{Result, anyhow};
use jarvis_nethttp::write_json;
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, LazyLock};

pub const STREAM_MARKER: &str = "stream";

static HEX64: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[0-9a-f]{64}$").unwrap_or_else(|_| unreachable!()));

#[derive(Deserialize, Default)]
#[serde(default)]
struct SumSig {
    #[serde(alias = "Sha256")]
    sha256: String,
    #[serde(alias = "Sig")]
    sig: String,
}

fn sum_sig(body: &[u8]) -> Option<SumSig> {
    jarvis_go::unmarshal::<SumSig>(body)
        .ok()
        .filter(|x| HEX64.is_match(&x.sha256) && !x.sig.is_empty())
}

impl Router {
    /// the failure the machine reported for its snapshot, kept on its wait (snapwait.rs) for the waiter
    pub fn set_snapshot_error(&self, machine: &str, msg: &str) {
        let _ = self.sw_exec(
            "INSERT INTO snapshot_waits (machine_id, token, moved_at, error) VALUES ($1, '', now(), $2)
             ON CONFLICT (machine_id) DO UPDATE SET error = $2",
            &[&machine, &msg],
        );
    }

    /// the failure the machine reported for its snapshot (taken: read once)
    pub fn snapshot_error(&self, machine: &str) -> Option<anyhow::Error> {
        let db = self.st.db()?;
        let row = db
            .conn()
            .ok()?
            .query_opt(
                "UPDATE snapshot_waits w SET error = '' FROM (SELECT error FROM snapshot_waits WHERE machine_id = $1 FOR UPDATE) old WHERE w.machine_id = $1 RETURNING old.error",
                &[&machine],
            )
            .ok()??;
        let msg: String = row.get(0);
        (!msg.is_empty()).then(|| anyhow!("the machine's snapshot failed: {msg}"))
    }

    pub fn machine_key(&self, machine: &str) -> String {
        self.st.do_(|d| {
            d.started
                .get(machine)
                .map(|s| s.signing_key.clone())
                .unwrap_or_default()
        })
    }

    /// POST /m/snapshot-stream: checked before a byte is taken, then straight into the bucket
    fn snapshot_stream(
        self: &Arc<Self>,
        w: &mut jarvis_nethttp::W,
        req: &mut jarvis_nethttp::Req,
    ) -> Result<()> {
        let (machine, t, sig) = (
            req.header("X-Machine"),
            req.header("X-Time"),
            req.header("X-Sig"),
        );
        let ts: i64 = t.parse().unwrap_or(0);
        let skew = crate::http::MACHINE_TIME_SKEW.load(std::sync::atomic::Ordering::Relaxed);
        let d = crate::util::unix_now() - ts;
        if d > skew || d < -skew {
            write_json(w, 401, &json!({"error": "X-Time too far off"}));
            return Ok(());
        }
        let key = self.machine_key(&machine);
        let payload = format!("{} {} {t} {STREAM_MARKER}", req.method, req.path);
        if key.is_empty() || !verify_p256(&key, payload.as_bytes(), &sig) {
            write_json(
                w,
                401,
                &json!({"error": "not signed by a machine the core started"}),
            );
            return Ok(());
        }
        // snapstore.rs: straight into the bucket, hashed on the way (snapwait.rs: every read is progress)
        let mut body = MovedReader::new(&mut req.body, self.clone(), &machine);
        match self.snap_stream(&machine, &mut body) {
            Err((e, _)) => {
                crate::logf!("machine {machine}: snapshot stream: {e:#}");
                write_err(w, &e);
            }
            Ok((sum, n)) => write_json(w, 200, &json!({"sha256": sum, "bytes": n})),
        }
        Ok(())
    }
}

pub fn register_snap_stream(reg: &mut Registrar) {
    let r = reg.r.clone();
    reg.machine.handle(
        "POST /m/snapshot-stream",
        Arc::new(move |w, req| {
            let _ = r.snapshot_stream(w, req);
        }),
    );
    reg.m("POST /m/snapshot-commit", |r, w, _, machine, body| {
        let Some(i) = sum_sig(body) else {
            return write_json(w, 400, &json!({"error": "{sha256, sig}"}));
        };
        if r.snap(machine).is_none_or(|s| s.sha256 != i.sha256) {
            return write_json(
                w,
                409,
                &json!({"error": "no streamed snapshot with that sha256"}),
            );
        }
        if !verify_p256(&r.machine_key(machine), i.sha256.as_bytes(), &i.sig) {
            return write_json(
                w,
                403,
                &json!({"error": "the snapshot isn't signed by the machine's current key"}),
            );
        }
        if let Err(e) = r.snap_commit(machine, &i.sha256, &i.sig) {
            return write_err(w, &e);
        }
        crate::logf!(
            "machine {machine}: snapshot committed ({})",
            &i.sha256[..12]
        );
        r.snapshot_arrived(machine);
        write_json(w, 200, &json!({"ok": true}));
    });
    reg.m("POST /m/snapshot-failed", |r, w, _, machine, body| {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            #[serde(alias = "Error")]
            error: String,
        }
        let i: In = jarvis_go::unmarshal(body).unwrap_or_default();
        let mut msg = jarvis_go::fmt::clip_bytes(&i.error, 500).to_string();
        if msg.is_empty() {
            msg = "no reason given".into();
        }
        crate::logf!("machine {machine}: its snapshot failed: {msg}");
        r.set_snapshot_error(machine, &msg);
        r.snapshot_arrived(machine);
        write_json(w, 200, &json!({"ok": true}));
    });
    reg.m("POST /m/snapshot-carry", |r, w, _, machine, body| {
        let Some(i) = sum_sig(body) else {
            return write_json(w, 400, &json!({"error": "{sha256, sig}"}));
        };
        let (pred, named) = r.st.do_(|d| {
            if let Some(c) = d.certs.get(machine) {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct X {
                    #[serde(rename = "predecessorId")]
                    pred_id: String,
                    snapshot: String,
                }
                let x = c.decode::<X>().unwrap_or_default();
                return (x.pred_id, x.snapshot);
            }
            // a kernel machine has no cert of the old core: the hash is the one its source names, the predecessor the
            // machine that left that snapshot (kernelline.rs kernel_pred)
            let st = d.started.get(machine);
            let s = d.machines.get(machine).and_then(|sid| d.sessions.get(sid));
            match (st, s) {
                (Some(st), Some(s)) if s.machine_id == machine => {
                    let named = s
                        .kernel
                        .as_ref()
                        .and_then(|k| k.source_cert.as_ref())
                        .and_then(|c| jarvis_doc::peek_cert(c).ok())
                        .and_then(|c| c.source)
                        .map(|x| x.snapshot);
                    match named {
                        Some(n) => (st.kernel_pred.clone(), n),
                        None => (String::new(), String::new()),
                    }
                }
                _ => (String::new(), String::new()),
            }
        });
        if pred.is_empty() || named.is_empty() || named != i.sha256 {
            return write_json(
                w,
                409,
                &json!({"error": "the cert names no predecessor snapshot with that sha256"}),
            );
        }
        if !verify_p256(&r.machine_key(machine), i.sha256.as_bytes(), &i.sig) {
            return write_json(
                w,
                403,
                &json!({"error": "the snapshot isn't signed by the machine's current key"}),
            );
        }
        if let Err(e) = r.snap_carry(machine, &pred, &i.sha256, &i.sig) {
            return write_json(
                w,
                409,
                &json!({"error": format!("the predecessor's snapshot: {e:#}")}),
            );
        }
        crate::logf!(
            "machine {machine}: still booting; its predecessor {pred}'s snapshot carried over"
        );
        r.snapshot_arrived(machine);
        write_json(w, 200, &json!({"ok": true}));
    });
}
