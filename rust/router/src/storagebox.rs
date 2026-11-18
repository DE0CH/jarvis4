//! The Storage Box (Hetzner, WebDAV over https on 443) with the router's own credentials: router env STORAGEBOX_HOST,
//! STORAGEBOX_USER, STORAGEBOX_PASSWORD. The archives of destroyed sessions live there, one .tar.gz each in Jarvis 4's
//! own folder (archivetar.rs); the content stores too (content.rs).

use anyhow::{Result, anyhow};
use reqwest::blocking::{Body, Client, Response};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

pub struct StorageBox {
    base: String,
    user: String,
    pass: String,
    http: Client,
}

/// the wait before a PUT is retried (times the attempt), in milliseconds; tests shorten it
pub static PUT_BACKOFF_MS: AtomicU64 = AtomicU64::new(1000);

pub fn put_backoff() -> Duration {
    Duration::from_millis(PUT_BACKOFF_MS.load(Ordering::Relaxed))
}

pub fn no_storage_box() -> anyhow::Error {
    anyhow!("the router has no STORAGEBOX_HOST/USER/PASSWORD")
}

/// no overall time limit: a multi-GB archive or workspace outlasts any fixed one
static STREAM_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .timeout(None)
        .connect_timeout(Duration::from_secs(120))
        .build()
        .unwrap_or_default()
});

/// None when any of the three is missing
pub fn records_box_from_env() -> Option<StorageBox> {
    let get = |k: &str| std::env::var(k).unwrap_or_default();
    let (h, u, p) = (get("STORAGEBOX_HOST"), get("STORAGEBOX_USER"), get("STORAGEBOX_PASSWORD"));
    if h.is_empty() || u.is_empty() || p.is_empty() {
        return None;
    }
    Some(StorageBox::new(&format!("https://{h}"), &u, &p))
}

pub fn dav_url(base: &str, p: &str) -> String {
    let segs: Vec<String> = p
        .trim_matches('/')
        .split('/')
        .map(jarvis_go::fmt::path_escape)
        .collect();
    format!("{base}{}", segs.join("/"))
}

/// one directory entry of a PROPFIND
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DavEntry {
    pub href: String,
    pub name: String,
    pub dir: bool,
    pub size: i64,
    pub modified: String,
}

impl StorageBox {
    pub fn new(base: &str, user: &str, pass: &str) -> StorageBox {
        // its own pool: enough idle connections for the live copies' and content stores' calls in parallel
        let http = Client::builder()
            .timeout(Duration::from_secs(30 * 60))
            .pool_max_idle_per_host(8)
            .build()
            .unwrap_or_default();
        StorageBox {
            base: format!("{}/", base.trim_end_matches('/')),
            user: user.to_string(),
            pass: pass.to_string(),
            http,
        }
    }

    fn request(&self, c: &Client, method: &str, u: &str) -> Result<reqwest::blocking::RequestBuilder> {
        let m = reqwest::Method::from_bytes(method.as_bytes())?;
        let mut rb = c.request(m, u);
        if !self.user.is_empty() {
            rb = rb.basic_auth(&self.user, Some(&self.pass));
        }
        Ok(rb)
    }

    pub fn do_(&self, method: &str, p: &str, body: Option<Body>, hdr: &BTreeMap<&str, String>) -> Result<Response> {
        let mut u = dav_url(&self.base, p);
        // a directory keeps its trailing "/": Apache answers a collection without it with a 301, which a client follows
        // as a GET (an HTML listing instead of a multistatus)
        if ((method == "DELETE" || method == "PROPFIND") && p.ends_with('/')) || method == "MKCOL" {
            u.push('/');
        }
        let mut rb = self.request(&self.http, method, &u)?;
        for (k, v) in hdr {
            rb = rb.header(*k, v);
        }
        if let Some(b) = body {
            rb = rb.body(b);
        }
        Ok(rb.send()?)
    }

    fn simple(&self, method: &str, p: &str) -> Result<u16> {
        let resp = self.do_(method, p, None, &BTreeMap::new())?;
        Ok(resp.status().as_u16())
    }

    /// every segment of a directory path (an existing one answers 405, which is fine)
    pub fn mkcols(&self, dir: &str) -> Result<()> {
        let mut cur = String::new();
        for s in dir.trim_matches('/').split('/').filter(|s| !s.is_empty()) {
            cur += s;
            self.mkcol(&cur)?;
            cur.push('/');
        }
        Ok(())
    }

    /// one directory whose parent exists (an existing one answers 405, which is fine)
    pub fn mkcol(&self, dir: &str) -> Result<()> {
        let d = dir.trim_matches('/');
        let st = self.simple("MKCOL", d)?;
        if st >= 300 && st != 405 {
            return Err(anyhow!("MKCOL {d}/: HTTP {st}"));
        }
        Ok(())
    }

    /// a local file, three tries
    pub fn put_file(&self, p: &str, local: &std::path::Path) -> Result<()> {
        let mut last = anyhow!("no try");
        for i in 0..3u32 {
            let f = std::fs::File::open(local)?;
            let size = f.metadata()?.len();
            match self.put(p, Body::sized(f, size)) {
                Ok(()) => return Ok(()),
                Err(e) => last = e,
            }
            std::thread::sleep(put_backoff() * (i + 1));
        }
        Err(last)
    }

    pub fn put_bytes(&self, p: &str, data: &[u8]) -> Result<()> {
        let mut last = anyhow!("no try");
        for i in 0..3u32 {
            match self.put(p, Body::from(data.to_vec())) {
                Ok(()) => return Ok(()),
                Err(e) => last = e,
            }
            std::thread::sleep(put_backoff() * (i + 1));
        }
        Err(last)
    }

    fn put(&self, p: &str, body: Body) -> Result<()> {
        let resp = self.do_("PUT", p, Some(body), &BTreeMap::new())?;
        let st = resp.status().as_u16();
        if st >= 300 {
            return Err(anyhow!("PUT {p}: HTTP {st}"));
        }
        Ok(())
    }

    /// None when the file is missing
    pub fn get(&self, p: &str) -> Result<Option<Vec<u8>>> {
        self.get_with(p, &BTreeMap::new())
    }

    /// the file's last n bytes (a server that ignores Range sends it whole; the caller copes)
    pub fn get_tail(&self, p: &str, n: usize) -> Result<Option<Vec<u8>>> {
        self.get_with(p, &BTreeMap::from([("Range", format!("bytes=-{n}"))]))
    }

    fn get_with(&self, p: &str, hdr: &BTreeMap<&str, String>) -> Result<Option<Vec<u8>>> {
        let mut resp = self.do_("GET", p, None, hdr)?;
        let st = resp.status().as_u16();
        if st == 404 {
            return Ok(None);
        }
        if st >= 300 {
            return Err(anyhow!("GET {p}: HTTP {st}"));
        }
        let mut b = vec![];
        resp.read_to_end(&mut b)?;
        Ok(Some(b))
    }

    /// a file to a local path (streamed); false when it is missing
    pub fn download(&self, p: &str, local: &std::path::Path) -> Result<bool> {
        let mut resp = self.do_("GET", p, None, &BTreeMap::new())?;
        let st = resp.status().as_u16();
        if st == 404 {
            return Ok(false);
        }
        if st >= 300 {
            return Err(anyhow!("GET {p}: HTTP {st}"));
        }
        let mut f = crate::util::create_0600(local)?;
        std::io::copy(&mut resp, &mut f)?;
        f.sync_all().ok();
        Ok(true)
    }

    pub fn exists(&self, p: &str) -> Result<bool> {
        match self.simple("HEAD", p)? {
            404 => Ok(false),
            st if st < 300 => Ok(true),
            st => Err(anyhow!("HEAD {p}: HTTP {st}")),
        }
    }

    /// a file, or a directory with a trailing "/" (whole); a missing one is fine
    pub fn delete(&self, p: &str) -> Result<()> {
        let st = self.simple("DELETE", p)?;
        if st >= 300 && st != 404 {
            return Err(anyhow!("DELETE {p}: HTTP {st}"));
        }
        Ok(())
    }

    /// a body of unknown length, sent chunked (an archive written while it uploads, archivetar.rs); one try, since a
    /// stream can't be sent again (the caller makes it again)
    pub fn put_stream(&self, p: &str, body: impl Read + Send + 'static) -> Result<()> {
        let u = dav_url(&self.base, p);
        let mut resp = self.request(&STREAM_CLIENT, "PUT", &u)?.body(Body::new(body)).send()?;
        std::io::copy(&mut resp, &mut std::io::sink()).ok();
        let st = resp.status().as_u16();
        if st >= 300 {
            return Err(anyhow!("PUT {p}: HTTP {st}"));
        }
        Ok(())
    }

    /// a file to a new name (WebDAV MOVE, server side), replacing what is there
    pub fn move_(&self, from: &str, to: &str) -> Result<()> {
        let hdr = BTreeMap::from([("Destination", dav_url(&self.base, to)), ("Overwrite", "T".to_string())]);
        let st = self.do_("MOVE", from, None, &hdr)?.status().as_u16();
        if st >= 300 {
            return Err(anyhow!("MOVE {from} → {to}: HTTP {st}"));
        }
        Ok(())
    }

    /// a file's size (-1 when it is missing)
    pub fn size(&self, p: &str) -> Result<i64> {
        let resp = self.do_("HEAD", p, None, &BTreeMap::new())?;
        match resp.status().as_u16() {
            404 => Ok(-1),
            st if st < 300 => Ok(resp
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .unwrap_or(-1)),
            st => Err(anyhow!("HEAD {p}: HTTP {st}")),
        }
    }

    /// a file streamed; None when it is missing → (body, its length or -1)
    pub fn open(&self, p: &str) -> Result<Option<(Box<dyn Read + Send>, i64)>> {
        let u = dav_url(&self.base, p);
        let resp = self.request(&STREAM_CLIENT, "GET", &u)?.send()?;
        let st = resp.status().as_u16();
        if st == 404 {
            return Ok(None);
        }
        if st >= 300 {
            return Err(anyhow!("GET {p}: HTTP {st}"));
        }
        let n = resp.content_length().map_or(-1, |n| n as i64);
        Ok(Some((Box::new(resp), n)))
    }

    /// the direct children of a directory (relative to the box root); None when it doesn't exist
    pub fn children(&self, dir: &str) -> Result<Option<Vec<DavEntry>>> {
        let d = format!("{}/", dir.trim_end_matches('/'));
        let resp = self.do_("PROPFIND", &d, None, &BTreeMap::from([("Depth", "1".to_string())]))?;
        let st = resp.status().as_u16();
        if st == 404 {
            return Ok(None);
        }
        if st != 207 && st >= 300 {
            return Err(anyhow!("PROPFIND {dir}: HTTP {st}"));
        }
        let body = crate::util::read_limited(resp, 16 << 20);
        let all = parse_multistatus(&body).map_err(|e| anyhow!("PROPFIND {dir}: {e:#}"))?;
        let me = format!("/{}/", dir.trim_matches('/'));
        Ok(Some(
            all.into_iter()
                .filter(|e| format!("{}/", e.href.trim_end_matches('/')) != me && !e.name.is_empty())
                .collect(),
        ))
    }

    /// the names (and sizes) of the files directly in a directory; None when it is missing
    pub fn list(&self, dir: &str) -> Result<Option<BTreeMap<String, i64>>> {
        Ok(self.children(dir)?.map(|ents| {
            ents.into_iter()
                .filter(|e| !e.dir)
                .map(|e| (e.name, e.size))
                .collect()
        }))
    }
}

/// a Depth 1 PROPFIND body → its entries (namespace prefixes don't matter)
pub fn parse_multistatus(body: &[u8]) -> Result<Vec<DavEntry>> {
    use quick_xml::events::Event;
    let mut rd = quick_xml::Reader::from_reader(body);
    rd.config_mut().trim_text(true);
    let mut out = vec![];
    let mut cur: Option<DavEntry> = None;
    let mut path: Vec<String> = vec![];
    let mut buf = vec![];
    let mut text = String::new();
    loop {
        match rd.read_event_into(&mut buf)? {
            Event::Eof => break,
            Event::Start(e) => {
                let n = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if n == "response" {
                    cur = Some(DavEntry::default());
                }
                path.push(n);
                text.clear();
            }
            Event::Empty(e) => {
                let n = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if n == "collection"
                    && path.iter().any(|p| p == "resourcetype")
                    && let Some(c) = cur.as_mut()
                {
                    c.dir = true;
                }
            }
            Event::Text(t) => text.push_str(&t.unescape().map(|c| c.into_owned()).unwrap_or_default()),
            Event::CData(t) => text.push_str(&String::from_utf8_lossy(&t)),
            Event::End(_) => {
                let n = path.pop().unwrap_or_default();
                let in_prop = path.iter().any(|p| p == "prop");
                if let Some(c) = cur.as_mut() {
                    match n.as_str() {
                        "href" if !in_prop && c.href.is_empty() => c.href = text.clone(),
                        "collection" if path.iter().any(|p| p == "resourcetype") => c.dir = true,
                        "getcontentlength" if in_prop => {
                            if let Ok(x) = text.trim().parse::<i64>() {
                                c.size = x;
                            }
                        }
                        "getlastmodified" if in_prop => {
                            if let Some(t) = crate::util::parse_http_time(text.trim()) {
                                c.modified = t.utc().rfc3339();
                            }
                        }
                        "response" => {
                            if let Some(mut e) = cur.take() {
                                let mut href = jarvis_go::fmt::path_unescape(&e.href);
                                if let Ok(u) = url::Url::parse(&href)
                                    && u.host_str().is_some_and(|h| !h.is_empty())
                                {
                                    href = jarvis_go::fmt::path_unescape(u.path());
                                }
                                let trimmed = href.trim_end_matches('/');
                                let name = trimmed.rsplit('/').next().unwrap_or_default();
                                e.name = name.to_string();
                                e.href = href;
                                out.push(e);
                            }
                        }
                        _ => {}
                    }
                }
                text.clear();
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multistatus_entries() {
        let body = br#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
<D:response><D:href>/claude-records/.content/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat></D:response>
<D:response><D:href>/claude-records/.content/a%20b/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype><D:getlastmodified>Mon, 02 Jan 2006 15:04:05 GMT</D:getlastmodified></D:prop></D:propstat></D:response>
<D:response><D:href>https://u.example/claude-records/.content/x.txt</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>12</D:getcontentlength></D:prop></D:propstat></D:response>
</D:multistatus>"#;
        let es = parse_multistatus(body).unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(es.len(), 3);
        assert!(es[0].dir);
        assert_eq!(es[1].name, "a b");
        assert!(es[1].dir);
        assert_eq!(es[1].modified, "2006-01-02T15:04:05Z");
        assert_eq!(es[2].href, "/claude-records/.content/x.txt");
        assert_eq!(es[2].name, "x.txt");
        assert_eq!(es[2].size, 12);
        assert!(!es[2].dir);
    }
}
