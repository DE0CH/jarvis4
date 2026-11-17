//! The machine's way to the router (routerdial.go): JARVIS2_URL names one address, or the gateways comma-separated
//! (each a WireGuard peer of the Fly org running `router m-gateway`). Every request goes to the first URL's host; the
//! dial behind it tries the gateways in turn, starting with the last one that answered, so a gateway being replaced
//! costs one failed dial, not a failed request. A connection already open stays where it is until it closes.

use hyper::Uri;
use hyper_util::rt::TokioIo;
use regex::Regex;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpStream;

pub static ROUTER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^http://[A-Za-z0-9][A-Za-z0-9._-]{0,200}(:[0-9]{1,5})?/?$")
        .unwrap_or_else(|e| panic!("{e}"))
});

/// how long one gateway gets to answer a dial before the next is tried (ms; tests shorten it)
pub static DIAL_TIMEOUT_MS: AtomicU64 = AtomicU64::new(5000);

pub fn router_urls_ok(v: &str) -> bool {
    !v.is_empty() && v.split(',').all(|u| ROUTER_RE.is_match(u.trim()))
}

#[derive(Debug, Default)]
pub struct RouterDialer {
    /// host:port every request names (the first URL's)
    pub front: String,
    /// every gateway's host:port, in order
    pub hosts: Vec<String>,
    /// the one that answered last
    pub cur: AtomicUsize,
}

fn host_port(raw: &str) -> Option<String> {
    let u: Uri = raw.parse().ok()?;
    let host = u.host()?;
    if host.is_empty() {
        return None;
    }
    let port = u.port_u16().unwrap_or(80);
    Some(if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

/// The base URL requests are made to, and the dialer behind them
pub fn router_transport(v: &str) -> (String, Arc<RouterDialer>) {
    let mut d = RouterDialer::default();
    let mut base = String::new();
    for (i, raw) in v.split(',').enumerate() {
        let raw = raw.trim();
        let raw = raw.strip_suffix('/').unwrap_or(raw);
        let Some(host) = host_port(raw) else { continue };
        if i == 0 || base.is_empty() {
            base = raw.to_string();
            d.front = host.clone();
        }
        d.hosts.push(host);
    }
    (base, Arc::new(d))
}

async fn dial(addr: &str) -> std::io::Result<TcpStream> {
    let t = Duration::from_millis(DIAL_TIMEOUT_MS.load(Ordering::Relaxed));
    match tokio::time::timeout(t, TcpStream::connect(addr)).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("dial {addr}: timeout"),
        )),
    }
}

impl RouterDialer {
    pub async fn connect(&self, addr: &str) -> std::io::Result<TcpStream> {
        if addr != self.front || self.hosts.len() < 2 {
            return dial(addr).await;
        }
        let start = self.cur.load(Ordering::Relaxed);
        let mut last = None;
        for i in 0..self.hosts.len() {
            let n = (start + i) % self.hosts.len();
            match dial(&self.hosts[n]).await {
                Ok(c) => {
                    self.cur.store(n, Ordering::Relaxed);
                    return Ok(c);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| std::io::Error::other("no gateway")))
    }
}

/// The hyper connector over a [`RouterDialer`]
#[derive(Clone)]
pub struct Connector(pub Arc<RouterDialer>);

impl tower_service::Service<Uri> for Connector {
    type Response = TokioIo<TcpStream>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let d = self.0.clone();
        Box::pin(async move {
            let addr = host_port(&uri.to_string())
                .ok_or_else(|| std::io::Error::other(format!("no host in {uri}")))?;
            let s = d.connect(&addr).await?;
            let _ = s.set_nodelay(true);
            Ok(TokioIo::new(s))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// two gateways: requests name the first; when it doesn't answer a dial, the second takes them, and stays chosen
    #[test]
    fn router_dial_fails_over() {
        DIAL_TIMEOUT_MS.store(300, Ordering::Relaxed);
        crate::rt::block_on(async {
            let live = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            let live_addr = live
                .local_addr()
                .unwrap_or_else(|e| panic!("{e}"))
                .to_string();
            let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
            let dead_addr = dead
                .local_addr()
                .unwrap_or_else(|e| panic!("{e}"))
                .to_string();
            drop(dead);
            tokio::spawn(async move {
                while let Ok((s, _)) = live.accept().await {
                    drop(s);
                }
            });
            let (base, d) = router_transport(&format!("http://{dead_addr},http://{live_addr}"));
            assert_eq!(base, format!("http://{dead_addr}"));
            assert_eq!(d.hosts.len(), 2);
            for _ in 0..2 {
                d.connect(&dead_addr)
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
            }
            assert_eq!(
                d.cur.load(Ordering::Relaxed),
                1,
                "the answering gateway isn't kept"
            );
        });
        assert!(router_urls_ok(
            "http://a._peer.internal:8081,http://b._peer.internal:8081"
        ));
        assert!(!router_urls_ok("http://a:1,http://x/$(evil)"));
        assert!(!router_urls_ok(""));
        let (_, one) = router_transport("http://only:8081");
        assert_eq!(one.hosts.len(), 1);
        assert!(one.front.ends_with(":8081"));
    }
}
