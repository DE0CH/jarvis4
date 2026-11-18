//! What the router's handlers were written against, Go's net/http, over hyper: a ServeMux with Go 1.22's patterns
//! ("GET /api/sessions/{id}/pause", "{rest...}", a trailing "/" for a subtree; the most specific pattern wins; a path
//! that matches only under another method is 405 with Allow), a request whose body is read as a plain std::io::Read,
//! and a ResponseWriter whose headers go when the first byte is written (or the handler ends), every write after that
//! streamed, so a handler that writes progressively (a long poll, a log stream) behaves as it did in Go. Each request
//! runs on a blocking thread (tokio's blocking pool), as a goroutine did.

use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

pub type HandlerFn = Arc<dyn Fn(&mut W, &mut Req) + Send + Sync>;

/// a request as a handler sees it
pub struct Req {
    pub method: String,
    /// the path, decoded (Go's URL.Path)
    pub path: String,
    /// the raw query (Go's URL.RawQuery)
    pub raw_query: String,
    pub headers: HeaderMap,
    pub remote_addr: String,
    pub body: Box<dyn Read + Send>,
    /// the pattern's {name} values (Go's PathValue)
    pub params: BTreeMap<String, String>,
    /// values a wrapping handler set for the one it calls (Go's request context)
    pub ctx: BTreeMap<String, String>,
}

impl Req {
    pub fn path_value(&self, k: &str) -> String {
        self.params.get(k).cloned().unwrap_or_default()
    }

    pub fn header(&self, k: &str) -> String {
        self.headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }

    /// Go's URL.Query().Get(k)
    pub fn query(&self, k: &str) -> String {
        url::form_urlencoded::parse(self.raw_query.as_bytes())
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    }

    pub fn query_has(&self, k: &str) -> bool {
        url::form_urlencoded::parse(self.raw_query.as_bytes()).any(|(n, _)| n == k)
    }

    /// the body, at most n bytes (Go's io.ReadAll(io.LimitReader(req.Body, n)))
    pub fn read_body(&mut self, n: u64) -> Vec<u8> {
        let mut b = vec![];
        let _ = (&mut self.body).take(n).read_to_end(&mut b);
        b
    }

    /// a test's request
    pub fn new(method: &str, target: &str, body: &[u8]) -> Req {
        let (path, q) = target.split_once('?').unwrap_or((target, ""));
        Req {
            method: method.into(),
            path: percent_encoding::percent_decode_str(path)
                .decode_utf8_lossy()
                .into_owned(),
            raw_query: q.into(),
            headers: HeaderMap::new(),
            remote_addr: "127.0.0.1:1".into(),
            body: Box::new(std::io::Cursor::new(body.to_vec())),
            params: BTreeMap::new(),
            ctx: BTreeMap::new(),
        }
    }

    pub fn with_header(mut self, k: &str, v: &str) -> Req {
        if let (Ok(n), Ok(v)) = (HeaderName::try_from(k), HeaderValue::from_str(v)) {
            self.headers.insert(n, v);
        }
        self
    }
}

type Head = (u16, HeaderMap);

/// Go's http.ResponseWriter
pub struct W {
    pub headers: HeaderMap,
    head: Option<oneshot::Sender<(Head, mpsc::Receiver<Bytes>)>>,
    tx: Option<mpsc::Sender<Bytes>>,
    status: u16,
    /// tests: what was written (no server)
    pub recorded: Option<Vec<u8>>,
    buf: Vec<u8>,
}

impl W {
    /// a ResponseWriter that only records (tests, and handlers calling handlers)
    pub fn recorder() -> W {
        W {
            headers: HeaderMap::new(),
            head: None,
            tx: None,
            status: 0,
            recorded: Some(vec![]),
            buf: vec![],
        }
    }

    pub fn status(&self) -> u16 {
        if self.status == 0 { 200 } else { self.status }
    }

    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(self.recorded.as_deref().unwrap_or(&[])).into_owned()
    }

    pub fn set_header(&mut self, k: &str, v: &str) {
        if let (Ok(n), Ok(v)) = (HeaderName::try_from(k), HeaderValue::from_str(v)) {
            self.headers.insert(n, v);
        }
    }

    pub fn add_header(&mut self, k: &str, v: &str) {
        if let (Ok(n), Ok(v)) = (HeaderName::try_from(k), HeaderValue::from_str(v)) {
            self.headers.append(n, v);
        }
    }

    pub fn wrote_header(&self) -> bool {
        self.status != 0
    }

    /// Go's WriteHeader: the status and the headers set so far go (once)
    pub fn write_header(&mut self, status: u16) {
        if self.status != 0 {
            return;
        }
        self.status = status;
        if let Some(h) = self.head.take() {
            let (tx, rx) = mpsc::channel(16);
            self.tx = Some(tx);
            let _ = h.send(((status, self.headers.clone()), rx));
        }
    }

    /// Go's Write: the header first (200) if it hasn't gone
    pub fn write(&mut self, b: &[u8]) -> usize {
        if self.status == 0 {
            self.write_header(200);
        }
        if let Some(r) = &mut self.recorded {
            r.extend_from_slice(b);
            return b.len();
        }
        self.buf.extend_from_slice(b);
        if self.buf.len() >= 32 << 10 {
            self.flush();
        }
        b.len()
    }

    /// Go's Flusher: what was written goes now
    pub fn flush(&mut self) {
        if self.status == 0 {
            self.write_header(200);
        }
        if self.buf.is_empty() {
            return;
        }
        let b = Bytes::from(std::mem::take(&mut self.buf));
        if let Some(tx) = &self.tx
            && tx.blocking_send(b).is_err()
        {
            self.tx = None; // the client went: later writes go nowhere
        }
    }

    /// whether the client is still there (a long poll's check)
    pub fn gone(&self) -> bool {
        self.tx.as_ref().is_some_and(|t| t.is_closed())
    }

    pub fn write_str(&mut self, s: &str) -> usize {
        self.write(s.as_bytes())
    }

    fn finish(&mut self) {
        self.flush();
        self.tx = None;
    }
}

impl std::io::Write for W {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.gone() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the client went",
            ));
        }
        Ok(W::write(self, b))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        W::flush(self);
        Ok(())
    }
}

/// Go's writeJSON: Content-Type, the status, v as json.Encoder writes it (with a newline)
pub fn write_json<T: Serialize + ?Sized>(w: &mut W, status: u16, v: &T) {
    w.set_header("Content-Type", "application/json");
    w.write_header(status);
    let mut s = jarvis_go::marshal(v);
    s.push('\n');
    w.write_str(&s);
}

/// Go's http.NotFound
pub fn not_found(w: &mut W) {
    w.set_header("Content-Type", "text/plain; charset=utf-8");
    w.set_header("X-Content-Type-Options", "nosniff");
    w.write_header(404);
    w.write_str("404 page not found\n");
}

/// write_json of {"error": msg}
pub fn write_error(w: &mut W, status: u16, msg: &str) {
    write_json(w, status, &serde_json::json!({"error": msg}));
}

// ---- the mux ---------------------------------------------------------------------------------------------------

#[derive(Clone)]
enum Seg {
    Lit(String),
    Param(String),
    /// {name...}: the rest
    Rest(String),
}

#[derive(Clone)]
struct Pattern {
    method: String,
    segs: Vec<Seg>,
    /// ends in "/": the subtree
    subtree: bool,
    /// ends in "/{$}": exactly this path with its trailing slash
    exact_slash: bool,
    raw: String,
}

fn parse_pattern(p: &str) -> Pattern {
    let (method, path) = match p.split_once(' ') {
        Some((m, rest)) if !m.starts_with('/') => (m.to_string(), rest.trim().to_string()),
        _ => (String::new(), p.to_string()),
    };
    let subtree = path.ends_with('/');
    let mut segs = vec![];
    for s in path.trim_start_matches('/').split('/') {
        if s.is_empty() {
            continue;
        }
        if let Some(n) = s.strip_prefix('{').and_then(|x| x.strip_suffix('}')) {
            if let Some(n) = n.strip_suffix("...") {
                segs.push(Seg::Rest(n.to_string()));
            } else if n == "$" {
                // "{$}": exactly this path, no subtree
            } else {
                segs.push(Seg::Param(n.to_string()));
            }
        } else {
            segs.push(Seg::Lit(s.to_string()));
        }
    }
    let exact_end = path.ends_with("{$}");
    Pattern {
        method,
        segs,
        subtree: subtree && !exact_end,
        exact_slash: exact_end,
        raw: p.to_string(),
    }
}

impl Pattern {
    /// the {name} values when path matches
    fn matches(&self, path: &str) -> Option<BTreeMap<String, String>> {
        let parts: Vec<&str> = if path == "/" {
            vec![]
        } else {
            path.trim_start_matches('/').split('/').collect()
        };
        let trailing = path.ends_with('/') && path != "/";
        let parts: Vec<&str> = if trailing {
            parts[..parts.len() - 1].to_vec()
        } else {
            parts
        };
        let mut out = BTreeMap::new();
        let mut i = 0;
        for s in &self.segs {
            match s {
                Seg::Lit(l) => {
                    if parts.get(i) != Some(&l.as_str()) {
                        return None;
                    }
                }
                Seg::Param(n) => {
                    let v = parts.get(i)?;
                    if v.is_empty() {
                        return None;
                    }
                    out.insert(n.clone(), (*v).to_string());
                }
                Seg::Rest(n) => {
                    let mut rest = parts[i.min(parts.len())..].join("/");
                    if trailing {
                        rest.push('/');
                    }
                    out.insert(n.clone(), rest);
                    return Some(out);
                }
            }
            i += 1;
        }
        if self.exact_slash {
            return (i == parts.len() && trailing).then_some(out);
        }
        if i == parts.len() && (!trailing || self.subtree) {
            return Some(out);
        }
        if self.subtree && i <= parts.len() {
            return Some(out);
        }
        None
    }

    /// Go's precedence, near enough: more literal segments first, then fewer wildcards, then a method over none, an
    /// exact path over a subtree
    fn rank(&self) -> (usize, usize, bool, bool) {
        let lits = self
            .segs
            .iter()
            .filter(|s| matches!(s, Seg::Lit(_)))
            .count();
        let rests = self
            .segs
            .iter()
            .filter(|s| matches!(s, Seg::Rest(_)))
            .count();
        (
            lits,
            self.segs.len() - rests,
            !self.method.is_empty(),
            !self.subtree,
        )
    }
}

#[derive(Clone, Default)]
pub struct Mux {
    routes: Vec<(Pattern, HandlerFn)>,
}

impl Mux {
    pub fn new() -> Mux {
        Mux::default()
    }

    pub fn handle(&mut self, pattern: &str, h: HandlerFn) {
        self.routes.push((parse_pattern(pattern), h));
    }

    pub fn handle_fn(
        &mut self,
        pattern: &str,
        h: impl Fn(&mut W, &mut Req) + Send + Sync + 'static,
    ) {
        self.handle(pattern, Arc::new(h));
    }

    /// the pattern that serves req (Go's mux.Handler), its values
    fn find(
        &self,
        method: &str,
        path: &str,
    ) -> Result<(HandlerFn, BTreeMap<String, String>, String), Vec<String>> {
        let mut best: Option<(&Pattern, &HandlerFn, BTreeMap<String, String>)> = None;
        let mut allowed = vec![];
        for (p, h) in &self.routes {
            let Some(vals) = p.matches(path) else {
                continue;
            };
            let method_ok = p.method.is_empty()
                || p.method == method
                || (p.method == "GET" && method == "HEAD");
            if !method_ok {
                allowed.push(p.method.clone());
                continue;
            }
            if best.as_ref().is_none_or(|(b, _, _)| p.rank() > b.rank()) {
                best = Some((p, h, vals));
            }
        }
        match best {
            Some((p, h, v)) => Ok((h.clone(), v, p.raw.clone())),
            None => Err(allowed),
        }
    }

    pub fn serve(&self, w: &mut W, req: &mut Req) {
        match self.find(&req.method, &req.path) {
            Ok((h, vals, _)) => {
                req.params = vals;
                h(w, req);
            }
            Err(allowed) if !allowed.is_empty() => {
                let mut a = allowed;
                a.sort();
                a.dedup();
                w.set_header("Allow", &a.join(", "));
                w.set_header("Content-Type", "text/plain; charset=utf-8");
                w.write_header(405);
                w.write_str("Method Not Allowed\n");
            }
            Err(_) => {
                w.set_header("Content-Type", "text/plain; charset=utf-8");
                w.write_header(404);
                w.write_str("404 page not found\n");
            }
        }
    }

    /// the pattern a request would be served by ("" = none): tests, apicalls.rs
    pub fn pattern_for(&self, method: &str, path: &str) -> String {
        self.find(method, path)
            .map(|(_, _, p)| p)
            .unwrap_or_default()
    }
}

// ---- serving -----------------------------------------------------------------------------------------------------

/// a request body (hyper's, async) read on the handler's blocking thread
struct BodyReader {
    rx: mpsc::Receiver<Bytes>,
    cur: Bytes,
}

impl Read for BodyReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.cur.is_empty() {
            match self.rx.blocking_recv() {
                Some(b) => self.cur = b,
                None => return Ok(0),
            }
        }
        let n = out.len().min(self.cur.len());
        out[..n].copy_from_slice(&self.cur[..n]);
        self.cur = self.cur.slice(n..);
        Ok(n)
    }
}

pub type Handler = Arc<dyn Fn(&mut W, &mut Req) + Send + Sync>;

/// serve h on addr until the token says stop (Go's ListenAndServe and Shutdown)
pub async fn serve(
    addr: &str,
    h: Handler,
    stop: tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    let addr = if addr.starts_with(':') {
        format!("0.0.0.0{addr}")
    } else {
        addr.to_string()
    };
    let ln = tokio::net::TcpListener::bind(&addr).await?;
    loop {
        let (conn, peer) = tokio::select! {
            r = ln.accept() => r?,
            _ = stop.cancelled() => return Ok(()),
        };
        let h = h.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                let h = h.clone();
                async move { Ok::<_, std::convert::Infallible>(handle(h, req, peer.to_string()).await) }
            });
            let c = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(conn), svc);
            tokio::pin!(c);
            tokio::select! {
                _ = c.as_mut() => {}
                _ = stop.cancelled() => {
                    c.as_mut().graceful_shutdown();
                    let _ = c.await;
                }
            }
        });
    }
}

type RespBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

async fn handle(
    h: Handler,
    req: hyper::Request<Incoming>,
    peer: String,
) -> hyper::Response<RespBody> {
    let (parts, body) = req.into_parts();
    let (btx, brx) = mpsc::channel::<Bytes>(8);
    tokio::spawn(async move {
        let mut body = body;
        while let Some(f) = body.frame().await {
            let Ok(f) = f else { break };
            if let Ok(d) = f.into_data()
                && btx.send(d).await.is_err()
            {
                break;
            }
        }
    });
    let (htx, hrx) = oneshot::channel();
    let path = percent_encoding::percent_decode_str(parts.uri.path())
        .decode_utf8_lossy()
        .into_owned();
    let mut r = Req {
        method: parts.method.as_str().to_string(),
        path,
        raw_query: parts.uri.query().unwrap_or("").to_string(),
        headers: parts.headers,
        remote_addr: peer,
        body: Box::new(BodyReader {
            rx: brx,
            cur: Bytes::new(),
        }),
        params: BTreeMap::new(),
        ctx: BTreeMap::new(),
    };
    tokio::task::spawn_blocking(move || {
        let mut w = W {
            headers: HeaderMap::new(),
            head: Some(htx),
            tx: None,
            status: 0,
            recorded: None,
            buf: vec![],
        };
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h(&mut w, &mut r)));
        if res.is_err() && !w.wrote_header() {
            w.write_header(500);
        }
        if !w.wrote_header() {
            w.write_header(200);
        }
        w.finish();
    });
    match hrx.await {
        Ok(((status, headers), rx)) => {
            let stream = tokio_stream::wrappers::ReceiverStream::new(rx)
                .map(|b| Ok::<_, std::convert::Infallible>(Frame::data(b)));
            let mut resp = hyper::Response::new(StreamBody::new(stream).boxed());
            *resp.status_mut() =
                hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::OK);
            *resp.headers_mut() = headers;
            resp
        }
        Err(_) => {
            let mut resp = hyper::Response::new(
                http_body_util::Full::new(Bytes::new())
                    .map_err(|e| match e {})
                    .boxed(),
            );
            *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
            resp
        }
    }
}

use tokio_stream::StreamExt as _;

#[cfg(test)]
mod tests {
    use super::*;

    fn mux(ps: &[&str]) -> Mux {
        let mut m = Mux::new();
        for p in ps {
            let p2 = p.to_string();
            m.handle_fn(p, move |w, r| {
                let vals: Vec<String> = r.params.iter().map(|(k, v)| format!("{k}={v}")).collect();
                w.write_str(&format!("{p2} {}", vals.join(",")));
            });
        }
        m
    }

    fn get(m: &Mux, method: &str, path: &str) -> (u16, String) {
        let mut w = W::recorder();
        let mut r = Req::new(method, path, b"");
        m.serve(&mut w, &mut r);
        (w.status(), w.body_text())
    }

    #[test]
    fn go_patterns() {
        let m = mux(&[
            "GET /api/sessions/{id}",
            "POST /api/sessions/{id}/pause",
            "GET /api/sessions/new",
            "/",
            "GET /files/{rest...}",
            "GET /m/{$}",
        ]);
        assert_eq!(
            get(&m, "GET", "/api/sessions/s1").1,
            "GET /api/sessions/{id} id=s1"
        );
        assert_eq!(
            get(&m, "GET", "/api/sessions/new").1,
            "GET /api/sessions/new "
        );
        assert_eq!(
            get(&m, "POST", "/api/sessions/s1/pause").1,
            "POST /api/sessions/{id}/pause id=s1"
        );
        // another method's pattern: "/" (any method) serves it, as Go's mux does
        assert_eq!(get(&m, "GET", "/api/sessions/s1/pause").1, "/ ");
        assert_eq!(get(&mux(&["POST /api/x/{id}"]), "GET", "/api/x/1").0, 405);
        assert_eq!(
            get(&m, "GET", "/files/a/b.txt").1,
            "GET /files/{rest...} rest=a/b.txt"
        );
        assert_eq!(get(&m, "GET", "/web/index.html").1, "/ ");
        assert_eq!(get(&m, "GET", "/m/").1, "GET /m/{$} ");
        let m2 = mux(&["GET /api/x"]);
        assert_eq!(get(&m2, "GET", "/api/y").0, 404);
    }
}
