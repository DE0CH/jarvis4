//! Snapshots straight between the machines and the bucket (rust/machine/src/snapdirect.rs, DECISIONS 241). The
//! machines' way to the router, Fly's WireGuard peer into m-gateway, carries about 6 MB/s per connection and 15 MB/s in
//! all (measured 2026-10-25), while the bucket answers a Fly machine at 86 MB/s on one stream. So the router only signs
//! the way and checks what arrived:
//!
//! ```text
//! POST /m/snapshot-upload         {} → {upload, partSize}: a multipart upload of the machine's own object
//!                                 snapshots/<machine>.tar.gz (an earlier unfinished one of it is aborted)
//! POST /m/snapshot-upload/parts   {upload, from, count ≤ 64} → {urls}: part URLs for parts from … from+count-1, one
//!                                 hour
//! POST /m/snapshot-upload/done    {upload, parts: [{n, etag}], sha256, bytes} → {sha256, bytes}: the upload finished,
//!                                 then the object read back through the router, hashed, counted and read for its facts
//!                                 (every read is the awaited snapshot's progress), and kept as the machine's pending
//!                                 snapshot, exactly as a streamed one (snapstream.rs); the machine commits it with its
//!                                 signature only when that hash is its own
//! POST /m/snapshot-upload/abort   {upload}
//! GET  /m/snapshot-url            → {url, sha256, bytes, sig?}: a one-hour read URL of the snapshot GET /m/snapshot
//!                                 sends (the predecessor's, or a restoring line's first), sig when it has one
//! ```
//!
//! 404 when the router has no bucket it can sign for (the memory stand-in): the machine streams through the router.
//! What a machine can do with these is what it could already do through the router: write its own object, read its own
//! predecessor's; a part URL is dead once its upload is finished or aborted, and the hash the machine signs is the one
//! the router read back.

use crate::http::{Registrar, write_err};
use crate::nethttp::{W, write_json};
use crate::objstore::ObjDirect;
use crate::router::Router;
use crate::snapstore::{Snap, snap_ingest, snap_key};
use crate::snapwait::MovedReader;
use serde::Deserialize;
use serde_json::json;
use std::time::{Duration, Instant};

pub const DIRECT_PART_SIZE: i64 = 16 << 20;
pub const DIRECT_URL_TTL: Duration = Duration::from_secs(3600);
/// S3's
pub const DIRECT_MAX_PARTS: i64 = 10000;

fn direct<'a>(r: &'a Router, w: &mut W) -> Option<&'a dyn ObjDirect> {
    let d = r.objects.direct();
    if d.is_none() {
        write_json(w, 404, &json!({"error": "no bucket the machines can reach: stream the snapshot through the router"}));
    }
    d
}

impl Router {
    /// the snapshot a machine's boot takes (GET /m/snapshot): its predecessor's committed one (signed: its signature
    /// goes with it; a kernel machine's predecessor is the machine that left the snapshot its source names,
    /// kernelline.rs kernel_pred), or, for a restoring line's first machine, the archived one (checked by the cert's
    /// hash) → (it, signed) or why there is none
    pub fn snapshot_for(&self, machine: &str) -> std::result::Result<(Snap, bool), String> {
        let pred = self.st.do_(|d| {
            if let Some(st) = d.started.get(machine) {
                if !st.kernel_pred.is_empty() {
                    return st.kernel_pred.clone(); // kernelline.rs kernel_pred
                }
                if st.kernel_cert.is_some() {
                    return "restore".into(); // a kernel line's first machine: the archived snapshot its source names
                }
            }
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct C {
                #[serde(rename = "predecessorId")]
                pred_id: String,
            }
            d.certs
                .get(machine)
                .and_then(|c| c.decode::<C>().ok())
                .map(|c| c.pred_id)
                .unwrap_or_default()
        });
        match pred.as_str() {
            "restore" => match self.restore_files_for(machine) {
                // restore.rs: only a restoring line's first machine
                Some(s) => Ok((s, false)),
                None => Err("no predecessor".into()),
            },
            "" => Err("no predecessor".into()),
            p => match self.snap(p) {
                Some(s) if s.state == "committed" => Ok((s, true)),
                _ => Err("no snapshot".into()),
            },
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct UploadIn {
    #[serde(alias = "Upload")]
    upload: String,
    #[serde(alias = "From")]
    from: i64,
    #[serde(alias = "Count")]
    count: i64,
    #[serde(alias = "Parts")]
    parts: Vec<PartIn>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PartIn {
    #[serde(alias = "N")]
    n: i64,
    #[serde(alias = "ETag", alias = "Etag")]
    etag: String,
}

pub fn register_snap_direct(reg: &mut Registrar) {
    reg.m("POST /m/snapshot-upload", |r, w, _, machine, _| {
        let Some(d) = direct(r, w) else { return };
        match d.start_upload(&snap_key(machine)) {
            Err(e) => write_err(w, &e),
            Ok(up) => {
                crate::logf!(
                    "machine {machine}: snapshot upload {}… started (straight to the bucket)",
                    jarvis_go::fmt::clip_bytes(&up, 12)
                );
                write_json(w, 200, &json!({"upload": up, "partSize": DIRECT_PART_SIZE}));
            }
        }
    });
    reg.m("POST /m/snapshot-upload/parts", |r, w, _, machine, body| {
        let i = match jarvis_go::unmarshal::<UploadIn>(body) {
            Ok(i) if !i.upload.is_empty() && i.from >= 1 && (1..=64).contains(&i.count) && i.from + i.count - 1 <= DIRECT_MAX_PARTS => i,
            _ => {
                return write_json(w, 400, &json!({"error": "{upload, from ≥ 1, count 1..64}, parts up to 10000"}));
            }
        };
        let Some(d) = direct(r, w) else { return };
        let mut urls = vec![];
        for p in i.from..i.from + i.count {
            match d.part_url(&snap_key(machine), &i.upload, p, DIRECT_URL_TTL) {
                Err(e) => return write_err(w, &e),
                Ok(u) => urls.push(u),
            }
        }
        r.snapshot_moved(machine);
        write_json(w, 200, &json!({"urls": urls}));
    });
    reg.m("POST /m/snapshot-upload/done", |r, w, _, machine, body| {
        let i = match jarvis_go::unmarshal::<UploadIn>(body) {
            Ok(i) if !i.upload.is_empty() && !i.parts.is_empty() && i.parts.len() as i64 <= DIRECT_MAX_PARTS => i,
            _ => return write_json(w, 400, &json!({"error": "{upload, parts: [{n, etag}]}"})),
        };
        let mut etags = vec![];
        for (k, p) in i.parts.iter().enumerate() {
            if p.n != k as i64 + 1 || p.etag.is_empty() {
                return write_json(
                    w,
                    400,
                    &json!({"error": format!("part {}: the parts go 1, 2, … each with its etag", k + 1)}),
                );
            }
            etags.push(p.etag.clone());
        }
        let Some(d) = direct(r, w) else { return };
        let key = snap_key(machine);
        if let Err(e) = d.finish_upload(&key, &i.upload, &etags) {
            crate::logf!("machine {machine}: snapshot upload: finishing: {e:#}");
            return write_err(w, &e);
        }
        r.snapshot_moved(machine);
        let t0 = Instant::now();
        let rd = match r.objects.get(&key) {
            Err(e) => return write_err(w, &e),
            Ok(rd) => rd,
        };
        let mut moved = MovedReader::new(rd, r.clone(), machine);
        let res = snap_ingest(&mut moved, |b| {
            std::io::copy(b, &mut std::io::sink())?;
            Ok(())
        })
        .map_err(|(e, _)| e)
        .and_then(|(sum, n, facts)| r.snap_pending(machine, &key, &sum, n, facts.as_ref()).map(|()| (sum, n)));
        match res {
            Err(e) => {
                crate::logf!("machine {machine}: snapshot upload: reading it back: {e:#}");
                write_err(w, &e);
            }
            Ok((sum, n)) => {
                crate::logf!(
                    "machine {machine}: snapshot upload of {} parts done, {n} bytes read back in {:.1} s ({}…)",
                    etags.len(),
                    t0.elapsed().as_secs_f64(),
                    &sum[..12]
                );
                write_json(w, 200, &json!({"sha256": sum, "bytes": n}));
            }
        }
    });
    reg.m("POST /m/snapshot-upload/abort", |r, w, _, machine, body| {
        let Some(i) = jarvis_go::unmarshal::<UploadIn>(body).ok().filter(|i| !i.upload.is_empty()) else {
            return write_json(w, 400, &json!({"error": "{upload}"}));
        };
        let Some(d) = direct(r, w) else { return };
        match d.abort_upload(&snap_key(machine), &i.upload) {
            Err(e) => write_err(w, &e),
            Ok(()) => write_json(w, 200, &json!({"ok": true})),
        }
    });
    reg.m("GET /m/snapshot-url", |r, w, _, machine, _| {
        let (s, signed) = match r.snapshot_for(machine) {
            Err(why) => return write_json(w, 404, &json!({"error": why})),
            Ok(x) => x,
        };
        let Some(d) = direct(r, w) else { return };
        match d.get_url(&s.key, DIRECT_URL_TTL) {
            Err(e) => write_err(w, &e),
            Ok(u) => {
                let mut out = json!({"url": u, "sha256": s.sha256, "bytes": s.bytes});
                if signed {
                    out["sig"] = json!(s.sig);
                }
                write_json(w, 200, &out);
            }
        }
    });
}
