//! The router client (main.go `client`): over Fly's private network, every request signed by this machine's key
//! ("METHOD PATH UNIXTIME SHA256(body)" in X-Sig, with X-Machine and X-Time).

use crate::crypto::{load_private, sha256_hex};
use crate::routerdial::{Connector, router_transport};
use crate::{gojson, machine_id, paths, rt};
use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::Frame;
use hyper::{HeaderMap, Request};
use hyper_util::client::legacy::Client as HClient;
use hyper_util::rt::TokioExecutor;
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::Duration;

pub type Body = BoxBody<Bytes, std::io::Error>;

#[derive(Clone)]
pub struct Client {
    pub base: String,
    pub me: String,
    http: HClient<Connector, Body>,
    /// the overall limit of a plain request (Go's http.Client.Timeout, 10 min); None: none (tests' streaming)
    pub timeout: Option<Duration>,
}

#[derive(Serialize, serde::Deserialize, Default)]
#[serde(default)]
struct ClientConf {
    #[serde(rename = "URL")]
    url: String,
    #[serde(rename = "Machine")]
    machine: String,
}

pub fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|never| match never {}).boxed()
}

/// A response: status, headers, body
pub struct Resp {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Client {
    /// From the machine's env at boot (saved to client.json, mode 600), from that file later
    pub fn new() -> Result<Client> {
        load_private()?;
        let mut conf = ClientConf {
            url: crate::env::get("JARVIS2_URL"),
            machine: machine_id(),
        };
        if !conf.url.is_empty() && !conf.machine.is_empty() {
            let _ = crate::util::write_file(
                &paths::client_path(),
                gojson::marshal(&conf).as_bytes(),
                0o600,
            );
        } else if let Ok(b) = std::fs::read(paths::client_path())
            && let Ok(c) = gojson::unmarshal::<ClientConf>(&b)
        {
            conf = c;
        }
        if conf.url.is_empty() {
            bail!("no router URL (JARVIS2_URL)");
        }
        Ok(Self::with_url(&conf.url, &conf.machine))
    }

    /// A client of the router at `url` (one address, or the gateways comma-separated) as machine `me`
    pub fn with_url(url: &str, me: &str) -> Client {
        let (base, d) = router_transport(url);
        // building a client needs no runtime context (a with_url inside an async block must not block_on)
        let http = HClient::builder(TokioExecutor::new())
            .pool_max_idle_per_host(8)
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_timer(hyper_util::rt::TokioTimer::new())
            .build(Connector(d));
        Client {
            base,
            me: me.to_string(),
            http,
            timeout: Some(Duration::from_secs(600)),
        }
    }

    /// The signing headers for a request whose body hashes to `body_sum` (the keys are re-read per call: a downgrade
    /// changes them under a running process)
    pub fn signed(
        &self,
        method: &str,
        path: &str,
        body_sum: &str,
    ) -> Result<Vec<(String, String)>> {
        let k = load_private()?;
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .to_string();
        let sig = k
            .sig
            .sign(format!("{method} {path} {t} {body_sum}").as_bytes());
        Ok(vec![
            ("X-Machine".into(), self.me.clone()),
            ("X-Time".into(), t),
            ("X-Sig".into(), sig),
        ])
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        hdr: Vec<(String, String)>,
        body: Body,
        len: Option<u64>,
    ) -> Result<hyper::Response<hyper::body::Incoming>> {
        let mut b = Request::builder()
            .method(method)
            .uri(format!("{}{}", self.base, path));
        for (k, v) in &hdr {
            b = b.header(k.as_str(), v.as_str());
        }
        if let Some(n) = len {
            b = b.header("Content-Length", n.to_string());
        }
        let req = b.body(body)?;
        Ok(self.http.request(req).await?)
    }

    /// A signed request with `body`, the whole response read (the overall limit applies)
    pub fn raw(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        extra: &[(&str, &str)],
    ) -> Result<Resp> {
        let mut hdr = self.signed(method, path, &sha256_hex(body))?;
        hdr.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        let body = Bytes::copy_from_slice(body);
        let fut = async {
            let resp = self
                .send(
                    method,
                    path,
                    hdr,
                    full(body.clone()),
                    Some(body.len() as u64),
                )
                .await?;
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            let body = resp.into_body().collect().await?.to_bytes().to_vec();
            Ok::<_, anyhow::Error>(Resp {
                status,
                headers,
                body,
            })
        };
        rt::block_on(async {
            match self.timeout {
                Some(t) => tokio::time::timeout(t, fut)
                    .await
                    .map_err(|_| anyhow!("{method} {path}: timeout"))?,
                None => fut.await,
            }
        })
    }

    /// Like raw, with a query string (unsigned: the router signs the path only) and the path sent escaped
    /// (`path` decoded, as the router checks the signature)
    pub fn signed_do(
        &self,
        method: &str,
        path: &str,
        escaped: &str,
        query: &str,
        body: &[u8],
        content_type: &str,
    ) -> Result<Resp> {
        let mut hdr = self.signed(method, path, &sha256_hex(body))?;
        if !content_type.is_empty() {
            hdr.push(("Content-Type".into(), content_type.into()));
        }
        let mut url_path = escaped.to_string();
        if !query.is_empty() {
            url_path = format!("{url_path}?{query}");
        }
        let body = Bytes::copy_from_slice(body);
        let fut = async {
            let resp = self
                .send(
                    method,
                    &url_path,
                    hdr,
                    full(body.clone()),
                    Some(body.len() as u64),
                )
                .await?;
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            let body = resp.into_body().collect().await?.to_bytes().to_vec();
            Ok::<_, anyhow::Error>(Resp {
                status,
                headers,
                body,
            })
        };
        rt::block_on(async {
            match self.timeout {
                Some(t) => tokio::time::timeout(t, fut)
                    .await
                    .map_err(|_| anyhow!("{method} {path}: timeout"))?,
                None => fut.await,
            }
        })
    }

    /// A JSON request: `input` marshalled (None: no body), a 200's body decoded into `T` (as Go's json.Unmarshal)
    pub fn json<I: Serialize, T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        input: Option<&I>,
    ) -> Result<T> {
        let b = self.json_raw(method, path, input)?;
        Ok(gojson::unmarshal(&b)?)
    }

    /// A JSON request whose 200 answer isn't read
    pub fn json_ok<I: Serialize>(&self, method: &str, path: &str, input: Option<&I>) -> Result<()> {
        self.json_raw(method, path, input).map(|_| ())
    }

    fn json_raw<I: Serialize>(
        &self,
        method: &str,
        path: &str,
        input: Option<&I>,
    ) -> Result<Vec<u8>> {
        let body = input.map(|i| gojson::marshal(i)).unwrap_or_default();
        let r = self.raw(method, path, body.as_bytes(), &[])?;
        if r.status != 200 {
            let t = String::from_utf8_lossy(&r.body);
            let t = t.trim();
            bail!(
                "{method} {path}: HTTP {} {}",
                r.status,
                crate::util::clip_bytes(t, 200)
            );
        }
        Ok(r.body)
    }

    /// A signed GET streamed into `dst` → the body's sha256 and the response headers (non-200 is an error)
    pub fn download(&self, path: &str, dst: &std::path::Path) -> Result<(String, HeaderMap)> {
        let (sum, hdr, _) = self.download_to(path, |r| {
            let mut f = crate::util::create_file(dst, 0o600)?;
            std::io::copy(r, &mut f)?;
            f.sync_all().ok();
            Ok(())
        })?;
        Ok((sum, hdr))
    }

    /// A signed GET whose body `f` consumes as a stream → the sha256 and size of everything read (what `f` leaves
    /// is read here too, so the hash always covers the whole body). No overall time limit; 5 minutes for the headers.
    pub fn download_to<F>(&self, path: &str, f: F) -> Result<(String, HeaderMap, u64)>
    where
        F: FnOnce(&mut dyn Read) -> Result<()>,
    {
        let hdr = self.signed("GET", path, &sha256_hex(b""))?;
        let resp = rt::block_on(async {
            tokio::time::timeout(
                Duration::from_secs(300),
                self.send("GET", path, hdr, full(Bytes::new()), None),
            )
            .await
            .map_err(|_| anyhow!("GET {path}: no response headers within 5 minutes"))?
        })?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let mut r = BodyReader::new(resp.into_body());
        if status != 200 {
            let mut b = Vec::new();
            let _ = (&mut r).take(300).read_to_end(&mut b);
            bail!(
                "GET {path}: HTTP {status} {}",
                String::from_utf8_lossy(&b).trim()
            );
        }
        let mut h = HashingReader {
            r,
            h: Sha256::new(),
            n: 0,
        };
        f(&mut h)?;
        std::io::copy(&mut h, &mut std::io::sink())?;
        Ok((hex::encode(h.h.finalize()), headers, h.n))
    }

    /// A file as a signed POST body, streamed (`sum` = the file's sha256, which the signature covers) → status, size
    pub fn upload(
        &self,
        path: &str,
        file: &std::path::Path,
        sum: &str,
        extra: &[(&str, &str)],
    ) -> Result<(u16, u64)> {
        let size = std::fs::metadata(file)?.len();
        let mut hdr = self.signed("POST", path, sum)?;
        hdr.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        let file = file.to_path_buf();
        rt::block_on(async {
            let f = tokio::fs::File::open(&file).await?;
            let s = tokio_util::io::ReaderStream::with_capacity(f, 256 << 10).map_ok(Frame::data);
            let body = BodyExt::boxed(StreamBody::new(s));
            let resp = self.send("POST", path, hdr, body, Some(size)).await?;
            let status = resp.status().as_u16();
            let _ = resp.into_body().collect().await;
            Ok((status, size))
        })
    }

    /// A signed POST whose body streams from `r` (the bytes hash to `sum`, which the signature covers)
    pub fn post_stream(
        &self,
        path: &str,
        sum_header: Vec<(String, String)>,
        body: Body,
    ) -> Result<Resp> {
        rt::block_on(async {
            let resp = self.send("POST", path, sum_header, body, None).await?;
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            let body = resp.into_body().collect().await?.to_bytes().to_vec();
            Ok(Resp {
                status,
                headers,
                body,
            })
        })
    }
}

/// A response body read as a std::io::Read from a plain thread
pub struct BodyReader {
    body: hyper::body::Incoming,
    buf: Bytes,
    done: bool,
}

impl BodyReader {
    pub fn new(body: hyper::body::Incoming) -> Self {
        Self {
            body,
            buf: Bytes::new(),
            done: false,
        }
    }
}

impl Read for BodyReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.buf.is_empty() && !self.done {
            match rt::block_on(self.body.frame()) {
                None => self.done = true,
                Some(Err(e)) => return Err(std::io::Error::other(e)),
                Some(Ok(f)) => {
                    if let Ok(d) = f.into_data() {
                        self.buf = d;
                    }
                }
            }
        }
        let n = out.len().min(self.buf.len());
        out[..n].copy_from_slice(&self.buf[..n]);
        let _ = self.buf.split_to(n);
        Ok(n)
    }
}

/// A reader that hashes and counts what passes through it
pub struct HashingReader<R: Read> {
    pub r: R,
    pub h: Sha256,
    pub n: u64,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = self.r.read(out)?;
        self.h.update(&out[..n]);
        self.n += n as u64;
        Ok(n)
    }
}
