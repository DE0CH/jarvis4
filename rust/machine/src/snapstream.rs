//! The final snapshot without free disk (rust/router/src/snapstream.rs): the tar is made straight into the request body (POST
//! /m/snapshot-stream, signed over the marker "stream" because the hash isn't known before the bytes), the router
//! answers the hash it stored, the machine checks it against its own, signs it and commits (POST /m/snapshot-commit).
//! The R1 rule stands: the machine signs exactly one snapshot in its life, after stopping the session; a later snapshot
//! command commits that same one again (or, if the first commit never reached the router, streams the frozen files
//! again and commits only when they hash the same). A router without streaming (404) gets the old whole-file upload.
//!
//! A failure is reported (POST /m/snapshot-failed), so the pause stops waiting and keeps the machine; when nothing was
//! signed yet, the session is let go on (SIGCONT) so it can be fixed (space freed) and the pause tried again.
//!
//! A machine asked while still booting has no state of its own: its state is the predecessor's snapshot, the one its
//! cert names. It signs that hash (its one signature) and the router links the predecessor's file as its snapshot (POST
//! /m/snapshot-carry), then the machine never finishes booting (hold_if_carried). The first machine of a line, with no
//! predecessor snapshot, still answers "nothing to snapshot".

use crate::cert::Cert;
use crate::client::{Body, Client};
use crate::crypto::SignedDoc;
use crate::snapshot::{
    FROZEN, final_snapshot_sum, keep_signed, no_snapshot, snapshot_key, start_progress,
};
use crate::{gojson, logf, paths, util};
use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// the one snapshot this machine signed (also in the final-snapshot.sig files, best effort), and whether the router
/// took it
#[derive(Default)]
pub struct Signed {
    pub sum: String,
    pub sig: String,
    pub committed: bool,
}

pub static SIGNED: Mutex<Signed> = Mutex::new(Signed {
    sum: String::new(),
    sig: String::new(),
    committed: false,
});

fn signed() -> std::sync::MutexGuard<'static, Signed> {
    SIGNED.lock().unwrap_or_else(|e| e.into_inner())
}

/// the router has no snapshot streaming
#[derive(Debug, thiserror::Error)]
#[error("the router has no snapshot streaming")]
pub struct NoStreaming;

pub fn upload_snapshot(c: &Client) -> Result<()> {
    let mut s = signed();
    if s.sum.is_empty()
        && let Ok((sum, sig)) = final_snapshot_sum()
    {
        // an earlier supervisor-core of this machine signed one
        s.sum = sum;
        s.sig = sig;
    }
    if !s.sum.is_empty() && s.committed {
        return commit_snapshot(c, &s.sum, &s.sig);
    }
    if s.sum.is_empty() {
        FROZEN.store(true, Ordering::SeqCst);
        crate::supervisor::freeze_session();
        crate::restore::write_changes(); // the repos' state, for the router's uncommitted-work check
        crate::volume::mirror_volume_files();
    }
    let prog = start_progress(c); // measured, then counted as it streams
    prog.set_phase("uploading");
    let mut r = crate::snapdirect::direct_snapshot(c); // straight to the bucket
    if r.as_ref()
        .is_err_and(|e| e.downcast_ref::<crate::snapdirect::NoDirect>().is_some())
    {
        r = stream_snapshot(c);
    }
    prog.end(r.as_ref().err());
    let (sum, n) = match r {
        Err(e) if e.downcast_ref::<NoStreaming>().is_some() => {
            drop(s);
            return crate::snapshot::upload_snapshot_file(c);
        }
        Err(e) => {
            if s.sum.is_empty() {
                // nothing signed: the session may go on and the pause be tried again
                FROZEN.store(false, Ordering::SeqCst);
                crate::supervisor::thaw_session();
            }
            return Err(e);
        }
        Ok(x) => x,
    };
    if s.sum.is_empty() {
        let sig = snapshot_key()?.sign(sum.as_bytes());
        s.sum = sum;
        s.sig = sig;
        // best effort: a full disk can't stop the snapshot (the signature lives in memory)
        let _ = keep_signed(&s.sum, &s.sig);
    } else if sum != s.sum {
        bail!(
            "the files changed since the snapshot this machine signed ({}…): it signs no second one",
            util::clip_bytes(&s.sum, 12)
        );
    }
    commit_snapshot(c, &s.sum, &s.sig)?;
    s.committed = true;
    logf!("snapshot streamed and committed ({n} bytes)");
    Ok(())
}

/// the snapshot made into the request body → the hash both sides agree on
pub fn stream_snapshot(c: &Client) -> Result<(String, u64)> {
    let hdr = c.signed("POST", "/m/snapshot-stream", "stream")?;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(8);
    struct ChanW(tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>);
    impl Write for ChanW {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0
                .blocking_send(Ok(Bytes::copy_from_slice(b)))
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "request over"))?;
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let writer = std::thread::spawn(move || {
        let mut w = std::io::BufWriter::with_capacity(256 << 10, ChanW(tx.clone()));
        let r = crate::snapshot::write_snapshot(&mut w).and_then(|x| {
            w.flush()?;
            Ok(x)
        });
        if let Err(e) = &r {
            let _ = tx.blocking_send(Err(std::io::Error::other(format!("{e:#}"))));
        }
        r
    });
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|x| (x.map(Frame::data), rx))
    });
    let body: Body = BodyExt::boxed(StreamBody::new(stream));
    let resp = c.post_stream("/m/snapshot-stream", hdr, body);
    let made = writer
        .join()
        .map_err(|_| anyhow!("the snapshot writer panicked"))?;
    let resp = resp?;
    if resp.status == 404 || resp.status == 405 {
        return Err(NoStreaming.into());
    }
    let (sum, n) = made.map_err(|e| anyhow!("making the snapshot: {e:#}"))?;
    let b = &resp.body[..resp.body.len().min(4096)];
    if resp.status != 200 {
        bail!(
            "snapshot stream: HTTP {} {}",
            resp.status,
            String::from_utf8_lossy(b).trim()
        );
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Got {
        sha256: String,
        bytes: u64,
    }
    match gojson::unmarshal::<Got>(b) {
        Ok(g) if g.sha256 == sum && g.bytes == n => Ok((sum, n)),
        g => {
            let g = g.unwrap_or_default();
            bail!(
                "the router stored other bytes ({}, {}) than were sent ({sum}, {n})",
                g.sha256,
                g.bytes
            )
        }
    }
}

pub fn commit_snapshot(c: &Client, sum: &str, sig: &str) -> Result<()> {
    c.json_ok(
        "POST",
        "/m/snapshot-commit",
        Some(&BTreeMap::from([("sha256", sum), ("sig", sig)])),
    )
}

/// tell the router at once (it stops waiting and keeps the machine)
pub fn report_snapshot_failed(c: &Client, err: &anyhow::Error) {
    let e = format!("{err:#}");
    if let Err(re) = c.json_ok(
        "POST",
        "/m/snapshot-failed",
        Some(&BTreeMap::from([("error", e.as_str())])),
    ) {
        logf!("reporting the failed snapshot: {re:#}");
    }
}

/// tests move the cert file
pub static TEST_CERT_FILE: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

/// a snapshot command while booting: the predecessor's snapshot, carried over as this machine's, when its cert names
/// one; else (the line's first machine) "nothing to snapshot"
pub fn booting_snapshot(c: &Client) -> Result<()> {
    let p = TEST_CERT_FILE
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_else(paths::cert_path);
    let cert: Cert = std::fs::read(p)
        .ok()
        .and_then(|raw| gojson::unmarshal::<SignedDoc>(&raw).ok())
        .and_then(|d| gojson::unmarshal::<Cert>(d.payload.as_bytes()).ok()) // the boot verified it before writing it
        .unwrap_or_default();
    if cert.snapshot.is_empty() || cert.pred_id.is_empty() || cert.pred_id == c.me {
        return no_snapshot(c);
    }
    let mut s = signed();
    if !s.sum.is_empty() && s.sum != cert.snapshot {
        bail!("this machine signed another snapshot already");
    }
    if s.sum.is_empty() {
        let sig = snapshot_key()?.sign(cert.snapshot.as_bytes());
        s.sum = cert.snapshot.clone();
        s.sig = sig;
        let _ = util::write_file(&paths::carried_run(), cert.snapshot.as_bytes(), 0o600); // the boot stops before the harness
    }
    let body = gojson::marshal(&BTreeMap::from([
        ("sha256", s.sum.as_str()),
        ("sig", s.sig.as_str()),
    ]));
    let r = c.raw("POST", "/m/snapshot-carry", body.as_bytes(), &[])?;
    if r.status == 404 || r.status == 405 {
        // an older router: what it knew before
        drop(s);
        return no_snapshot(c);
    }
    if r.status != 200 {
        bail!(
            "snapshot carry: HTTP {} {}",
            r.status,
            String::from_utf8_lossy(&r.body).trim()
        );
    }
    s.committed = true;
    logf!(
        "snapshot asked while booting: the predecessor's snapshot carried over as this machine's"
    );
    Ok(())
}

/// the boot goes no further once a pause took the predecessor's snapshot as this machine's
pub fn hold_if_carried() {
    if !paths::carried_run().exists() {
        return;
    }
    logf!(
        "paused while booting: this machine's snapshot is its predecessor's; not starting the harness"
    );
    loop {
        util::sleep(Duration::from_secs(3600));
    }
}

/// the router took this machine's final snapshot
pub fn snapshot_committed() -> bool {
    signed().committed
}
