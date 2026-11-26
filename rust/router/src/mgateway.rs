//! The machines' gateway (docs/STATE.md 5, step 9; mgateway.rs): `router m-gateway` runs the Fly org's
//! WireGuard peer (the address the machines know: KERNEL_MACHINE_URL / MACHINE_URL, http://<peer>._peer.internal:8081)
//! and passes every request it takes there to the router's machines' port (M_GATEWAY_TO, the router Service's :8081),
//! streamed both ways (snapshot uploads, long polls). It holds no state and checks nothing: every /m request is signed
//! by the machine's key and the router checks it, on whichever replica the Service picks. The router's rollouts never
//! touch the peer.
//!
//!   WG_CONFIGS     the peers' wg.conf files, comma-separated; the pod's ordinal (POD_NAME m-gateway-<n>, a StatefulSet)
//!                  picks the n-th: two gateways, two peers, replaced one at a time
//!   M_GATEWAY_TO   e.g. http://router.jarvis4-router.svc.cluster.local:8081
//!   WG_AWS_KEYS    the AWS machines' device keys by ordinal (its address: WG_AWS_GATEWAYS); its peers are the machines
//!                  the router lists at /gw/aws-peers, read every 10 s
//!   HEALTH_ADDR    :8080 by default: GET /healthz answers once the peer is up (the pod's readiness)
//!
//! SIGTERM: no new connection (the machines' dials go to the other gateway, rust/machine/src/routerdial.rs), the
//! requests it carries end (up to M_GATEWAY_GRACE_SECONDS), then the peer goes. A rollout replaces one gateway at a
//! time (OrderedReady), so the machines always have one. The WireGuard is userspace (wgserve.rs): no privileges.

use crate::wgserve::{
    ConnHandler, PeerConf, WgServer, parse_cidr, parse_wg_conf, serve_wg, wg_key,
};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// the Fly peer's MTU (wgserve.rs) and the AWS machines' (lesson 89: WireGuard through WARP)
const FLY_MTU: usize = 1420;
const AWS_MTU: usize = 1200;
const PORT: u16 = 8081;

type Body = BoxBody<Bytes, hyper::Error>;

/// the peer of this pod: the ordinal of POD_NAME (…-<n>) picks the n-th of configs
pub fn gateway_config(configs: &str, pod: &str) -> Result<String> {
    if configs.is_empty() {
        return Err(anyhow!("WG_CONFIGS: the peers' wg.conf files"));
    }
    let list: Vec<&str> = configs.split(',').collect();
    let n = pod
        .rsplit_once('-')
        .and_then(|(_, n)| n.parse::<usize>().ok())
        .filter(|n| *n < list.len())
        .ok_or_else(|| {
            anyhow!(
                "POD_NAME {}: no ordinal within the {} peers of WG_CONFIGS",
                jarvis_go::fmt::go_quote(pod),
                list.len()
            )
        })?;
    Ok(list[n].trim().to_string())
}

/// the gateways' own calls (/gw/…, awsrunner.rs) are never a machine's
pub fn refused_path(path: &str) -> bool {
    crate::util::path_clean(&format!("/{path}")).starts_with("/gw/")
}

const HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
];

fn full(status: u16, b: &str) -> Response<Body> {
    let mut r = Response::new(
        Full::new(Bytes::from(b.to_string()))
            .map_err(|e| match e {})
            .boxed(),
    );
    *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::BAD_GATEWAY);
    r.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/json"),
    );
    r
}

/// one request passed on to the router as it is (its headers, its streamed body), the router's answer back
async fn pass_on(
    to: Arc<(String, u16)>,
    mut req: Request<Incoming>,
    close: bool,
) -> Response<Body> {
    if refused_path(req.uri().path()) {
        return full(404, "404 page not found\n");
    }
    let fail = |e: String| {
        crate::logf!("m-gateway: {e}");
        full(
            502,
            r#"{"error":"the router can't be reached from the gateway: try again"}"#,
        )
    };
    let tcp = match tokio::net::TcpStream::connect((to.0.as_str(), to.1)).await {
        Ok(t) => t,
        Err(e) => return fail(format!("{} {}: {e}", req.method(), req.uri().path())),
    };
    let (mut send, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await {
        Ok(x) => x,
        Err(e) => return fail(format!("{} {}: {e}", req.method(), req.uri().path())),
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    for h in HOP {
        req.headers_mut().remove(h);
    }
    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    if let Ok(u) = pq.parse() {
        *req.uri_mut() = u;
    }
    let (method, path) = (req.method().clone(), req.uri().path().to_string());
    match send.send_request(req).await {
        Err(e) => fail(format!("{method} {path}: {e}")),
        Ok(resp) => {
            let (mut parts, body) = resp.into_parts();
            for h in HOP {
                parts.headers.remove(h);
            }
            if close {
                parts.headers.insert(
                    "connection",
                    hyper::header::HeaderValue::from_static("close"),
                );
            }
            Response::from_parts(parts, body.boxed())
        }
    }
}

/// the handler of each connection a peer opens: HTTP/1 passed on to the router
pub fn proxy_handler(to: (String, u16)) -> ConnHandler {
    let to = Arc::new(to);
    Arc::new(move |stream, one_shot: Arc<AtomicBool>| {
        let to = to.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                let (to, close) = (to.clone(), one_shot.load(Ordering::SeqCst));
                async move { Ok::<_, std::convert::Infallible>(pass_on(to, req, close).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .with_upgrades()
                .await;
        });
    })
}

/// M_GATEWAY_TO → (host, port)
pub fn parse_to(u: &str) -> Result<(String, u16)> {
    let rest = u
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("M_GATEWAY_TO: the router's machines' URL, e.g. http://router.jarvis4-router.svc.cluster.local:8081"))?;
    let host = rest.split('/').next().unwrap_or_default();
    let (h, p) = match host.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (h, p.parse::<u16>().ok()),
        _ => (host, Some(80)),
    };
    let p = p.ok_or_else(|| anyhow!("M_GATEWAY_TO: bad port in {u}"))?;
    if h.is_empty() {
        return Err(anyhow!("M_GATEWAY_TO: no host in {u}"));
    }
    Ok((
        h.trim_start_matches('[').trim_end_matches(']').to_string(),
        p,
    ))
}

/// the Fly peer of wg.conf at path
async fn fly_peer(path: &str, handler: ConnHandler) -> Result<WgServer> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow!("{path}: {e}"))?;
    let c = parse_wg_conf(&text, path)?;
    let addr = parse_cidr(&c.address).map_err(|e| anyhow!("Address: {e:#}"))?;
    let ep = tokio::net::lookup_host(&c.endpoint)
        .await
        .map_err(|e| anyhow!("endpoint {}: {e}", c.endpoint))?
        .next()
        .ok_or_else(|| anyhow!("endpoint {}: no address", c.endpoint))?;
    let allowed = c
        .allowed_ips
        .split(',')
        .filter(|a| !a.trim().is_empty())
        .map(parse_cidr)
        .collect::<Result<Vec<_>>>()?;
    let ka = c
        .keepalive
        .parse::<u16>()
        .ok()
        .filter(|k| *k > 0)
        .unwrap_or(25);
    serve_wg(
        addr,
        FLY_MTU,
        wg_key(&c.private_key)?,
        vec![PeerConf {
            public_key: c.public_key.clone(),
            endpoint: Some(ep),
            allowed,
            keepalive: Some(ka),
        }],
        PORT,
        handler,
        "wg",
    )
    .await
}

/// the router's list of AWS machines as the device's peers
fn aws_peers(peers_url: &str) -> Result<Vec<PeerConf>> {
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct Out {
        peers: Vec<crate::awsrunner::AwsPeer>,
    }
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?
        .get(peers_url)
        .send()?;
    if resp.status().as_u16() != 200 {
        return Err(anyhow!("HTTP {}", resp.status().as_u16()));
    }
    let out: Out = resp.json()?;
    Ok(out
        .peers
        .into_iter()
        .filter_map(|p| {
            let ip: IpAddr = p.address.parse().ok()?;
            Some(PeerConf {
                public_key: p.public_key,
                endpoint: p.endpoint.parse().ok(),
                allowed: vec![(ip, if ip.is_ipv4() { 32 } else { 128 })],
                keepalive: Some(25),
            })
        })
        .collect())
}

async fn aws_device(
    key: &str,
    addr: &str,
    handler: ConnHandler,
    peers_url: String,
) -> Result<WgServer> {
    let ip: IpAddr = addr.parse().map_err(|_| anyhow!("address {addr:?}"))?;
    let s = serve_wg(
        (ip, if ip.is_ipv4() { 32 } else { 128 }),
        AWS_MTU,
        wg_key(key)?,
        vec![],
        PORT,
        handler,
        "wg-aws",
    )
    .await?;
    let tx = s.peers.clone();
    tokio::spawn(async move {
        loop {
            let u = peers_url.clone();
            match tokio::task::spawn_blocking(move || aws_peers(&u)).await {
                Ok(Ok(p)) => {
                    let _ = tx.send(p);
                }
                Ok(Err(e)) => crate::logf!("wg-aws: peers: {e:#}"),
                Err(e) => crate::logf!("wg-aws: peers: {e}"),
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
    Ok(s)
}

/// `router m-gateway`
pub async fn command() -> Result<()> {
    let to_url = std::env::var("M_GATEWAY_TO").unwrap_or_default();
    let to = parse_to(&to_url)?;
    let pod = std::env::var("POD_NAME").unwrap_or_default();
    let path = gateway_config(&std::env::var("WG_CONFIGS").unwrap_or_default(), &pod)
        .map_err(|e| anyhow!("m-gateway: {e:#}"))?;
    let handler = proxy_handler(to.clone());
    let peer = fly_peer(&path, handler.clone())
        .await
        .map_err(|e| anyhow!("m-gateway: {e:#}"))?;
    crate::logf!(
        "m-gateway: the WireGuard peer from {path} serves port {PORT}, passed on to {to_url}"
    );
    let mut aws = None;
    let keys = std::env::var("WG_AWS_KEYS").unwrap_or_default();
    if !keys.is_empty() {
        let key =
            gateway_config(&keys, &pod).map_err(|e| anyhow!("m-gateway: WG_AWS_KEYS: {e:#}"))?;
        let gws = crate::awsrunner::aws_gateways().map_err(|e| anyhow!("m-gateway: {e:#}"))?;
        let n: usize = pod
            .rsplit_once('-')
            .and_then(|(_, n)| n.parse().ok())
            .unwrap_or(0);
        let gw = gws
            .get(n)
            .ok_or_else(|| anyhow!("m-gateway: WG_AWS_GATEWAYS has no address for gateway {n}"))?;
        let s = aws_device(
            &key,
            &gw.address,
            handler.clone(),
            format!("{}/gw/aws-peers", to_url.trim_end_matches('/')),
        )
        .await
        .map_err(|e| anyhow!("m-gateway: AWS WireGuard: {e:#}"))?;
        crate::logf!(
            "m-gateway: the AWS machines' WireGuard serves {}:{PORT}",
            gw.address
        );
        aws = Some(s);
    }
    let health = crate::router::env("HEALTH_ADDR", ":8080");
    let bind = if health.starts_with(':') {
        format!("0.0.0.0{health}")
    } else {
        health
    };
    let ln = tokio::net::TcpListener::bind(&bind).await?;
    let stop = tokio_util::sync::CancellationToken::new();
    let h: crate::nethttp::Handler = Arc::new(|w, req| {
        if req.method == "GET" && req.path == "/healthz" {
            w.write_str("ok\n");
        } else {
            crate::nethttp::not_found(w);
        }
    });
    tokio::spawn(crate::nethttp::serve_listener(ln, h, stop.clone()));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    let grace: u64 = crate::router::env("M_GATEWAY_GRACE_SECONDS", "1740")
        .parse()
        .unwrap_or(1740);
    crate::logf!(
        "m-gateway: stopping: no new connections, waiting up to {grace} s for the requests in flight"
    );
    let g = Duration::from_secs(grace);
    match &aws {
        Some(a) => {
            tokio::join!(peer.shutdown(g), a.shutdown(g));
        }
        None => peer.shutdown(g).await,
    }
    stop.cancel();
    crate::logf!("m-gateway: stopped");
    Ok(())
}
