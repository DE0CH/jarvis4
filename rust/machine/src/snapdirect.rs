//! Snapshots straight between the machine and the bucket (rust/router/src/snapdirect.rs, DECISIONS 241). The machines' way to the
//! router carries about 6 MB/s per connection and 15 MB/s in all, while the bucket answers a Fly machine at 86 MB/s on
//! one stream and 380 MB/s on eight. So the bytes go to the bucket and only the asking goes to the router:
//!
//!   upload    POST /m/snapshot-upload → a multipart upload of this machine's own object; the tar is cut into parts as
//!             it is made and 4 of them go up at once through part URLs the router signs (POST
//!             /m/snapshot-upload/parts); POST /m/snapshot-upload/done ends it and the router reads the object back for
//!             its hash, which must be this machine's.
//!   download  GET /m/snapshot-url → a read URL of the snapshot /m/snapshot would send, its sha256, size and signature;
//!             4 ranges at once into the file, then the hash is checked as before.
//!
//! A router without these routes, or a bucket it can't sign for, answers 404: the stream through the router, as before.

use crate::client::Client;
use crate::{gojson, logf, rt, util};
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

/// the router signs no bucket URLs
#[derive(Debug, thiserror::Error)]
#[error("the router signs no bucket URLs")]
pub struct NoDirect;

pub const DIRECT_WORKERS: usize = 4;
/// tries per part or range (tests lower it)
pub static DIRECT_TRIES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(4);
/// the backoff between tries (ms; tests shorten it)
pub static DIRECT_BACKOFF_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(2000);
/// the range size of a download (tests shorten it)
pub static RANGE_SIZE: AtomicI64 = AtomicI64::new(16 << 20);

/// the machine's own way to the bucket (the internet, not the router's gateway). HTTP/1.1, so the parts and ranges in
/// flight each have a connection of their own.
static BUCKET: LazyLock<reqwest::Client> = LazyLock::new(|| {
    // building a client needs no runtime (first used inside an async block: no block_on here)
    reqwest::Client::builder()
        .http1_only()
        .pool_max_idle_per_host(16)
        .build()
        .unwrap_or_default()
});

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct UploadedPart {
    pub n: usize,
    pub etag: String,
}

fn backoff(tr: u32) {
    util::sleep(Duration::from_millis(
        DIRECT_BACKOFF_MS.load(Ordering::Relaxed) * tr as u64,
    ));
}

/// the snapshot made and sent to the bucket in parts → the hash the router read back
pub fn direct_snapshot(c: &Client) -> Result<(String, u64)> {
    let r = c.raw("POST", "/m/snapshot-upload", b"{}", &[])?;
    if r.status == 404 || r.status == 405 {
        return Err(NoDirect.into());
    }
    if r.status != 200 {
        bail!(
            "snapshot upload: HTTP {} {}",
            r.status,
            String::from_utf8_lossy(&r.body).trim()
        );
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Up {
        upload: String,
        #[serde(rename = "partSize")]
        part_size: i64,
    }
    let up: Up = match gojson::unmarshal::<Up>(&r.body) {
        Ok(u) if !u.upload.is_empty() && u.part_size >= 5 << 20 && u.part_size <= 1 << 30 => u,
        _ => bail!(
            "snapshot upload: a bad answer {}",
            util::clip_bytes(&String::from_utf8_lossy(&r.body), 200)
        ),
    };
    let (pw, pr) = crate::chanpipe::pipe();
    let writer = std::thread::spawn(move || {
        let mut pw = pw;
        let r = crate::snapshot::write_snapshot(&mut pw);
        pw.close(r.as_ref().err().map(|e| format!("{e:#}")));
        r
    });
    let parts = upload_parts(c, &up.upload, up.part_size as usize, pr);
    // a failed upload stops the writer too (the reader went away with upload_parts)
    let made = writer
        .join()
        .map_err(|_| anyhow!("the snapshot writer panicked"))?;
    let res = match (parts, made) {
        (Ok(p), Ok(m)) => Ok((p, m)),
        (Err(e), _) => Err(e),
        (Ok(_), Err(e)) => Err(anyhow!("making the snapshot: {e:#}")),
    };
    let (parts, (sum, n)) = match res {
        Ok(x) => x,
        Err(e) => {
            let body = serde_json::json!({"upload": up.upload});
            if let Err(ae) = c.json_ok("POST", "/m/snapshot-upload/abort", Some(&body)) {
                logf!("snapshot upload: abort: {ae:#}");
            }
            return Err(e);
        }
    };
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Got {
        sha256: String,
        bytes: u64,
    }
    let got: Got = c.json(
        "POST",
        "/m/snapshot-upload/done",
        Some(&serde_json::json!({"upload": up.upload, "parts": parts, "sha256": sum, "bytes": n})),
    )?;
    if got.sha256 != sum || got.bytes != n {
        bail!(
            "the bucket holds other bytes ({}, {}) than were sent ({sum}, {n})",
            got.sha256,
            got.bytes
        );
    }
    Ok((sum, n))
}

/// r cut into parts of size, 4 of them on their way at once → the parts in order
pub fn upload_parts<R: Read>(
    c: &Client,
    upload: &str,
    size: usize,
    mut r: R,
) -> Result<Vec<UploadedPart>> {
    let failed: Arc<Mutex<Option<anyhow::Error>>> = Arc::new(Mutex::new(None));
    let etags: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let (free_tx, free_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(DIRECT_WORKERS + 1);
    for _ in 0..=DIRECT_WORKERS {
        let _ = free_tx.send(vec![0u8; size]);
    }
    let (work_tx, work_rx) = std::sync::mpsc::sync_channel::<(usize, String, Vec<u8>, usize)>(0);
    let work_rx = Arc::new(Mutex::new(work_rx));
    let mut workers = vec![];
    for _ in 0..DIRECT_WORKERS {
        let (work_rx, free_tx, failed, etags) = (
            work_rx.clone(),
            free_tx.clone(),
            failed.clone(),
            etags.clone(),
        );
        workers.push(std::thread::spawn(move || {
            loop {
                let job = work_rx.lock().map(|rx| rx.recv());
                let Ok(Ok((n, url, buf, k))) = job else {
                    return;
                };
                match put_part(&url, &buf[..k]) {
                    Err(e) => {
                        let mut f = failed.lock().unwrap_or_else(|e| e.into_inner());
                        if f.is_none() {
                            *f = Some(anyhow!("part {n}: {e:#}"));
                        }
                    }
                    Ok(etag) => {
                        let mut t = etags.lock().unwrap_or_else(|e| e.into_inner());
                        while t.len() < n {
                            t.push(String::new());
                        }
                        t[n - 1] = etag;
                    }
                }
                let _ = free_tx.send(buf);
            }
        }));
    }
    let is_failed = || failed.lock().map(|f| f.is_some()).unwrap_or(true);
    let fail = |e: anyhow::Error| {
        let mut f = failed.lock().unwrap_or_else(|e| e.into_inner());
        if f.is_none() {
            *f = Some(e);
        }
    };
    let mut urls: Vec<String> = vec![];
    let mut n = 1;
    while !is_failed() {
        let Ok(mut buf) = free_rx.recv() else { break };
        // io.ReadFull
        let mut k = 0;
        let mut eof = false;
        while k < buf.len() {
            match r.read(&mut buf[k..]) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(m) => k += m,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    fail(e.into());
                    break;
                }
            }
        }
        if is_failed() || (k == 0 && eof) {
            break;
        }
        if urls.is_empty() {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct U {
                urls: Vec<String>,
            }
            match c.json::<_, U>(
                "POST",
                "/m/snapshot-upload/parts",
                Some(&serde_json::json!({"upload": upload, "from": n, "count": 16})),
            ) {
                Ok(u) if !u.urls.is_empty() => urls = u.urls,
                Ok(_) => {
                    fail(anyhow!("part URLs: <nil>"));
                    break;
                }
                Err(e) => {
                    fail(anyhow!("part URLs: {e:#}"));
                    break;
                }
            }
        }
        let url = urls.remove(0);
        if work_tx.send((n, url, buf, k)).is_err() {
            break;
        }
        n += 1;
        if eof {
            break;
        }
    }
    drop(work_tx);
    drop(r); // the writer's next write fails if it is still making the snapshot
    for w in workers {
        let _ = w.join();
    }
    if let Some(e) = failed.lock().ok().and_then(|mut f| f.take()) {
        return Err(e);
    }
    let t = etags.lock().map(|t| t.clone()).unwrap_or_default();
    Ok(t.into_iter()
        .enumerate()
        .map(|(i, etag)| UploadedPart { n: i + 1, etag })
        .collect())
}

/// one part to its URL, tried again on a failure → its ETag
pub fn put_part(url: &str, body: &[u8]) -> Result<String> {
    let mut last = anyhow!("no try");
    for tr in 1..=DIRECT_TRIES.load(Ordering::Relaxed) {
        let body = body.to_vec();
        let r = rt::block_on(async {
            let resp =
                tokio::time::timeout(Duration::from_secs(120), BUCKET.put(url).body(body).send())
                    .await
                    .map_err(|_| anyhow!("no response within 2 minutes"))??;
            let status = resp.status().as_u16();
            let etag = resp
                .headers()
                .get("ETag")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let b = resp.bytes().await.unwrap_or_default();
            Ok::<_, anyhow::Error>((status, etag, b))
        });
        match r {
            Ok((200, etag, _)) if !etag.is_empty() => return Ok(etag),
            Ok((st, _, b)) => {
                last = anyhow!(
                    "HTTP {st} {}",
                    String::from_utf8_lossy(&b[..b.len().min(512)]).trim()
                )
            }
            Err(e) => last = e,
        }
        backoff(tr);
    }
    Err(last)
}

/// The snapshot /m/snapshot would send, into dst (from the bucket, else through the router) → its sha256 and the
/// signature the router keeps with it ("" when it has none: a restore's)
pub fn fetch_snapshot(c: &Client, dst: &Path) -> Result<(String, String)> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct In {
        url: String,
        sha256: String,
        bytes: i64,
        sig: String,
    }
    let got = c
        .raw("GET", "/m/snapshot-url", b"", &[])
        .ok()
        .filter(|r| r.status == 200)
        .and_then(|r| gojson::unmarshal::<In>(&r.body).ok())
        .filter(|i| !i.url.is_empty() && i.bytes > 0);
    let Some(i) = got else {
        // an older router, a bucket it can't sign for, or no snapshot: /m/snapshot says which
        let prog = RestoreLog::start("downloading", 0);
        let r = c.download_to("/m/snapshot", |r| {
            let mut f = util::create_file(dst, 0o600)?;
            let mut cr = Counting { r, n: &prog.done };
            std::io::copy(&mut cr, &mut f)?;
            Ok(())
        });
        prog.stop();
        let (sum, hdr, _) = r?;
        let sig = hdr
            .get("X-Snapshot-Sig")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        return Ok((sum, sig));
    };
    let prog = RestoreLog::start("downloading", i.bytes);
    let r = get_ranges(&i.url, i.bytes, dst, &prog.done);
    prog.stop();
    r?;
    Ok((file_sha256(dst)?, i.sig))
}

struct Counting<'a, R: Read + ?Sized> {
    r: &'a mut R,
    n: &'a AtomicI64,
}

impl<R: Read + ?Sized> Read for Counting<'_, R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.r.read(b)?;
        self.n.fetch_add(n as i64, Ordering::Relaxed);
        Ok(n)
    }
}

/// size bytes of url into dst, 4 ranges at once
pub fn get_ranges(url: &str, size: i64, dst: &Path, done: &AtomicI64) -> Result<()> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(dst)?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o600));
    f.set_len(size as u64)?;
    let next = AtomicI64::new(0);
    let ferr: Mutex<Option<anyhow::Error>> = Mutex::new(None);
    let rs = RANGE_SIZE.load(Ordering::Relaxed);
    std::thread::scope(|s| {
        for _ in 0..DIRECT_WORKERS {
            s.spawn(|| {
                loop {
                    let off = next.fetch_add(rs, Ordering::SeqCst);
                    let stop = ferr.lock().map(|e| e.is_some()).unwrap_or(true);
                    if off >= size || stop {
                        return;
                    }
                    let end = (off + rs).min(size);
                    if let Err(e) = get_range(url, &f, off, end, done) {
                        let mut g = ferr.lock().unwrap_or_else(|e| e.into_inner());
                        if g.is_none() {
                            *g = Some(anyhow!("bytes {off}-{}: {e:#}", end - 1));
                        }
                        return;
                    }
                }
            });
        }
    });
    if let Some(e) = ferr.into_inner().unwrap_or(None) {
        return Err(e);
    }
    f.sync_all()?;
    Ok(())
}

fn get_range(url: &str, f: &std::fs::File, off: i64, end: i64, done: &AtomicI64) -> Result<()> {
    let mut last = anyhow!("no try");
    for tr in 1..=DIRECT_TRIES.load(Ordering::Relaxed) {
        let r = rt::block_on(async {
            let resp = tokio::time::timeout(
                Duration::from_secs(120),
                BUCKET
                    .get(url)
                    .header("Range", format!("bytes={off}-{}", end - 1))
                    .send(),
            )
            .await
            .map_err(|_| anyhow!("no response within 2 minutes"))??;
            Ok::<_, anyhow::Error>(resp)
        });
        let res: Result<()> = match r {
            Err(e) => Err(e),
            Ok(resp) if resp.status().as_u16() == 206 => {
                let mut n: i64 = 0;
                let mut resp = resp;
                let mut err = None;
                // pwrite each chunk at its offset (the file is shared by the workers)
                loop {
                    match rt::block_on(resp.chunk()) {
                        Ok(Some(b)) => {
                            let take = (b.len() as i64).min(end - off - n).max(0) as usize;
                            use std::os::unix::fs::FileExt;
                            if let Err(e) = f.write_all_at(&b[..take], (off + n) as u64) {
                                err = Some(anyhow!("{e}"));
                                break;
                            }
                            n += take as i64;
                            done.fetch_add(take as i64, Ordering::Relaxed);
                        }
                        Ok(None) => break,
                        Err(e) => {
                            err = Some(anyhow!("{e}"));
                            break;
                        }
                    }
                }
                if err.is_none() && n == end - off {
                    return Ok(());
                }
                done.fetch_sub(n, Ordering::Relaxed);
                Err(err.unwrap_or_else(|| anyhow!("{n} of {} bytes", end - off)))
            }
            Ok(resp) => {
                let st = resp.status().as_u16();
                let b = rt::block_on(resp.bytes()).unwrap_or_default();
                Err(anyhow!(
                    "HTTP {st} {}",
                    String::from_utf8_lossy(&b[..b.len().min(512)]).trim()
                ))
            }
        };
        match res {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
        backoff(tr);
    }
    Err(last)
}

pub fn file_sha256(p: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(hex::encode(h.finalize()))
}

/// A restore's progress in the supervisor's log every 10 s (the Lifecycle shows it), so a machine that is downloading
/// or unpacking a large snapshot is seen doing so
pub struct RestoreLog {
    what: String,
    total: i64,
    pub done: Arc<AtomicI64>,
    started: Instant,
    quit: Arc<AtomicBool>,
    h: Option<std::thread::JoinHandle<()>>,
}

impl RestoreLog {
    pub fn start(what: &str, total: i64) -> RestoreLog {
        let done = Arc::new(AtomicI64::new(0));
        let quit = Arc::new(AtomicBool::new(false));
        let started = Instant::now();
        let (d, q, w) = (done.clone(), quit.clone(), what.to_string());
        let h = std::thread::spawn(move || {
            let mut last = Instant::now();
            while !q.load(Ordering::SeqCst) {
                util::sleep(Duration::from_millis(200));
                if last.elapsed() >= crate::snapshot::PROGRESS_LOG_EVERY {
                    last = Instant::now();
                    logf!("{}", line(&w, total, d.load(Ordering::Relaxed), started));
                }
            }
        });
        RestoreLog {
            what: what.into(),
            total,
            done,
            started,
            quit,
            h: Some(h),
        }
    }

    pub fn stop(mut self) {
        self.quit.store(true, Ordering::SeqCst);
        if let Some(h) = self.h.take() {
            let _ = h.join();
        }
        let el = self.started.elapsed().as_secs_f64();
        let d = self.done.load(Ordering::Relaxed);
        logf!(
            "restore: {} done, {} in {el:.0} s ({:.0} MB/s)",
            self.what,
            crate::snapshot::gb(d),
            d as f64 / el.max(0.001) / 1e6
        );
        let _ = self.total;
    }
}

fn line(what: &str, total: i64, done: i64, started: Instant) -> String {
    let mut s = format!("restore: {what} {}", crate::snapshot::gb(done));
    if total > 0 {
        s += &format!("/{} ({}%)", crate::snapshot::gb(total), done * 100 / total);
    }
    let el = started.elapsed().as_secs_f64();
    if el >= 1.0 {
        s += &format!(", {:.0} MB/s", done as f64 / el / 1e6);
        if total > done && done > 0 {
            s += &format!(", {:.0} s left", (total - done) as f64 / (done as f64 / el));
        }
    }
    s
}
