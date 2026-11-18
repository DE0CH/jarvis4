//! Small helpers the router's files share (Go's standard library calls they replaced: io.ReadAll(io.LimitReader),
//! crypto/rand, path.Clean, http.ServeContent, http.Redirect, http.FileServer, os.MkdirAll and friends).

use crate::nethttp::{Req, W};
use anyhow::Result;
use jarvis_go::GoTime;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// log.Printf: one line on stderr with the time, as Go's log package writes it
#[macro_export]
macro_rules! logf {
    ($($arg:tt)*) => {
        $crate::util::log_line(&format!($($arg)*))
    };
}

static LOG_MU: Mutex<()> = Mutex::new(());

pub fn log_line(s: &str) {
    let t = GoTime::now().utc().0.unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let _g = LOG_MU.lock().unwrap_or_else(|e| e.into_inner());
    let mut e = std::io::stderr().lock();
    let _ = writeln!(
        e,
        "{:04}/{:02}/{:02} {:02}:{:02}:{:02} {}",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        s.trim_end_matches('\n')
    );
}

/// at most n bytes of a body (Go's io.ReadAll(io.LimitReader(r, n)))
pub fn read_limited(r: impl Read, n: u64) -> Result<Vec<u8>> {
    let mut b = vec![];
    r.take(n).read_to_end(&mut b)?;
    Ok(b)
}

pub fn rand_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    rand_core::OsRng.fill_bytes(&mut b);
    b
}

use rand_core::RngCore;

/// 16 random hex characters (Go's randID: 8 bytes of crypto/rand)
pub fn rand_id() -> String {
    hex::encode(rand_bytes(8))
}

pub fn unix_now() -> i64 {
    GoTime::now().unix()
}

/// s trimmed of spaces, cut to at most n bytes (on a character boundary)
pub fn trim_to(s: &str, n: usize) -> String {
    let s = s.trim();
    let mut i = n.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    s[..i].to_string()
}

/// Go's path.Clean
pub fn path_clean(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let rooted = p.starts_with('/');
    let mut out: Vec<&str> = vec![];
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|l| *l != "..") {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            x => out.push(x),
        }
    }
    let s = out.join("/");
    match (rooted, s.is_empty()) {
        (true, _) => format!("/{s}"),
        (false, true) => ".".into(),
        (false, false) => s,
    }
}

/// "2006-01-02 15:04 UTC"
pub fn fmt_utc_minute(t: &GoTime) -> String {
    match t.utc().0 {
        Some(t) => format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", t.year(), t.month() as u8, t.day(), t.hour(), t.minute()),
        None => "0001-01-01 00:00 UTC".into(),
    }
}

/// "12.3 MB"
pub fn mb(n: i64) -> String {
    format!("{:.1} MB", n as f64 / 1e6)
}

/// an error as the API answers it (Go's err.Error())
pub fn err_text(err: &anyhow::Error) -> String {
    format!("{err:#}")
}

/// a float as Go's encoding/json writes a float64 (5 as 5, 0.1 as 0.1)
pub fn go_f64(f: f64) -> serde_json::Value {
    if f.fract() == 0.0 && f.abs() < 1e15 {
        serde_json::json!(f as i64)
    } else {
        serde_json::json!(f)
    }
}

#[cfg(unix)]
fn mode(p: &Path, m: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(m))
}

/// os.MkdirAll(p, 0o700)
pub fn mkdir_all_0700(p: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(p)?;
    }
    Ok(())
}

/// os.Create with mode 0600
pub fn create_0600(p: &Path) -> Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        return Ok(std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(p)?);
    }
    #[allow(unreachable_code)]
    Ok(std::fs::File::create(p)?)
}

/// os.WriteFile(p, b, 0o600)
pub fn write_file_0600(p: &Path, b: &[u8]) -> Result<()> {
    let mut f = create_0600(p)?;
    f.write_all(b)?;
    #[cfg(unix)]
    mode(p, 0o600)?;
    Ok(())
}

/// every regular file under dir (recursive)
pub fn walk_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let t = e.file_type()?;
        if t.is_dir() {
            walk_files(&e.path(), out)?;
        } else if t.is_file() {
            out.push(e.path());
        }
    }
    Ok(())
}

const HTTP_TIME: &[time::format_description::BorrowedFormatItem<'static>] =
    time::macros::format_description!("[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT");

/// an HTTP date (RFC 1123, as WebDAV's getlastmodified and Last-Modified write it)
pub fn parse_http_time(s: &str) -> Option<GoTime> {
    let t = time::PrimitiveDateTime::parse(s, HTTP_TIME).ok()?;
    Some(GoTime(Some(t.assume_utc())))
}

fn http_time(t: &GoTime) -> String {
    t.utc().0.and_then(|t| t.format(HTTP_TIME).ok()).unwrap_or_default()
}

/// Go's http.Redirect
pub fn redirect(w: &mut W, req: &Req, loc: &str, code: u16) {
    w.set_header("Location", loc);
    if req.method == "GET" || req.method == "HEAD" {
        w.set_header("Content-Type", "text/html; charset=utf-8");
    }
    w.write_header(code);
    if req.method == "GET" {
        let text = match code {
            301 => "Moved Permanently",
            303 => "See Other",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            _ => "Found",
        };
        let esc = loc.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&#34;").replace('\'', "&#39;");
        w.write(format!("<a href=\"{esc}\">{text}</a>.\n\n").as_bytes());
    }
}

/// one "bytes=a-b" range of a body of size n → (start, length); None: none or not one this serves
fn one_range(h: &str, n: i64) -> Option<(i64, i64)> {
    let spec = h.strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (a, b) = spec.trim().split_once('-')?;
    let (start, end) = if a.is_empty() {
        let k: i64 = b.parse().ok()?;
        ((n - k).max(0), n - 1)
    } else {
        let s: i64 = a.parse().ok()?;
        let e: i64 = if b.is_empty() { n - 1 } else { b.parse::<i64>().ok()?.min(n - 1) };
        (s, e)
    };
    (start <= end && start < n).then_some((start, end - start + 1))
}

/// Go's http.ServeContent for a body read once: Last-Modified and If-Modified-Since (modtime), one byte range, the
/// length; the caller set the Content-Type
pub fn serve_content(w: &mut W, req: &Req, modtime: GoTime, mut rd: impl Read, size: i64) {
    if !modtime.is_zero() {
        w.set_header("Last-Modified", &http_time(&modtime));
        if let Some(since) = parse_http_time(&req.header("If-Modified-Since"))
            && modtime.unix() <= since.unix()
            && req.header("Range").is_empty()
        {
            w.write_header(304);
            return;
        }
    }
    w.set_header("Accept-Ranges", "bytes");
    let range = req.header("Range");
    let (start, len, status) = match (range.is_empty(), one_range(&range, size)) {
        (true, _) | (false, None) => (0, size, 200),
        (false, Some((s, l))) => (s, l, 206),
    };
    if status == 206 {
        w.set_header("Content-Range", &format!("bytes {start}-{}/{size}", start + len - 1));
        if std::io::copy(&mut (&mut rd).take(start as u64), &mut std::io::sink()).is_err() {
            return crate::nethttp::write_error(w, 500, "reading the body");
        }
    }
    if size >= 0 {
        w.set_header("Content-Length", &len.to_string());
    }
    w.write_header(status);
    if req.method == "HEAD" {
        return;
    }
    let mut lim = rd.take(if size >= 0 { len as u64 } else { u64::MAX });
    let _ = std::io::copy(&mut lim, w);
}

/// a content type by the file's extension (Go's mime.TypeByExtension, the web page's kinds)
fn content_type(p: &Path) -> &'static str {
    match p.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/vnd.microsoft.icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "txt" => "text/plain; charset=utf-8",
        "wasm" => "application/wasm",
        "xml" => "text/xml; charset=utf-8",
        "webmanifest" => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

/// the web page (expo export) at /: a file, else <path>.html, else a directory's index.html, else the app's own route
/// (index.html at /). A page is asked for again every time (its hashed files are not): without no-cache a browser keeps
/// an old index.html, and with it the whole old page, for as long as it likes.
pub fn serve_web(w: &mut W, req: &mut Req, dir: &str) {
    let clean = path_clean(&format!("/{}", req.path));
    let root = Path::new(dir);
    let mut url_path = clean.clone();
    let p = root.join(clean.trim_start_matches('/'));
    if !p.is_file() {
        let html = PathBuf::from(format!("{}.html", p.display()));
        if html.is_file() {
            url_path = format!("{clean}.html");
        } else if !p.join("index.html").is_file() {
            url_path = "/".into(); // a client-side route
        }
    }
    if url_path.ends_with('/') || url_path.ends_with(".html") {
        w.set_header("Cache-Control", "no-cache");
    }
    let mut f = root.join(url_path.trim_start_matches('/'));
    if f.is_dir() {
        f = f.join("index.html");
    }
    let Ok(file) = std::fs::File::open(&f) else { return crate::nethttp::not_found(w) };
    let meta = file.metadata().ok();
    let size = meta.as_ref().map_or(-1, |m| m.len() as i64);
    let modtime = meta
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(GoTime::default(), |d| GoTime::from_unix(d.as_secs() as i64));
    w.set_header("Content-Type", content_type(&f));
    serve_content(w, req, modtime, file, size);
}

/// what drops once (Go's sync.OnceFunc): called by hand or on drop
pub struct OnceFn(Option<Box<dyn FnOnce() + Send>>);

impl OnceFn {
    pub fn new(f: impl FnOnce() + Send + 'static) -> OnceFn {
        OnceFn(Some(Box::new(f)))
    }

    pub fn call(mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

impl Drop for OnceFn {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_clean_as_go() {
        for (i, o) in [("", "."), ("/a/../b", "/b"), ("a/./b/", "a/b"), ("../x", "../x"), ("/..", "/"), ("a/..", ".")] {
            assert_eq!(path_clean(i), o, "{i}");
        }
    }

    #[test]
    fn ranges() {
        assert_eq!(one_range("bytes=0-9", 100), Some((0, 10)));
        assert_eq!(one_range("bytes=90-", 100), Some((90, 10)));
        assert_eq!(one_range("bytes=-5", 100), Some((95, 5)));
        assert_eq!(one_range("bytes=200-", 100), None);
    }

    #[test]
    fn http_times() {
        let s = "Wed, 18 Nov 2026 10:00:00 GMT";
        let t = parse_http_time(s);
        assert!(t.is_some());
        assert_eq!(http_time(&t.unwrap_or_default()), s);
    }
}
