//! warp-watch: on every node (k8s/cluster/nodes/warp-watch.yaml, host network), every [`EVERY`] it times a TLS
//! handshake over IPv4 to each of [`TARGETS`], bounded by [`BOUND`], logs the round as one JSON line (Loki), and when
//! [`Watch::after_round`] says so, reconnects the host's WARP client (`warp-cli disconnect`, then `connect`, in the
//! host's namespaces through busybox's nsenter). Its rule is in lib.rs.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde_json::{Value, json};
use warp_watch::{BOUND, EVERY, TARGETS, Watch};

fn main() {
    let tls = Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map(|b| {
                b.with_root_certificates(RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                })
                .with_no_client_auth()
            })
            .unwrap_or_else(|e| {
                log(json!({"level": "error", "msg": "no TLS config", "error": e.to_string()}));
                std::process::exit(1)
            }),
    );
    let node = std::env::var("NODE_NAME").unwrap_or_default();
    let mut watch = Watch::default();
    loop {
        let started = Instant::now();
        let mut ms = serde_json::Map::new();
        let mut answered = false;
        for host in TARGETS {
            let took = handshake(&tls, host);
            answered |= took.is_ok();
            ms.insert(
                (*host).to_owned(),
                match took {
                    Ok(d) => json!(u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
                    Err(e) => json!(e),
                },
            );
        }
        let reconnect = watch.after_round(answered, Instant::now());
        log(
            json!({"level": if answered { "info" } else { "warn" }, "msg": "round", "node": node,
                   "answered": answered, "ms": ms}),
        );
        if reconnect {
            let out = reconnect_warp();
            log(
                json!({"level": "warn", "msg": "WARP reconnected: no IPv4 origin answered two rounds in a row",
                       "node": node, "result": out}),
            );
        }
        std::thread::sleep(EVERY.saturating_sub(started.elapsed()));
    }
}

/// The time a TCP connect plus TLS handshake to `host`:443 over IPv4 took, within [`BOUND`]; else what failed.
fn handshake(tls: &Arc<ClientConfig>, host: &str) -> Result<Duration, String> {
    let start = Instant::now();
    let left = || {
        BOUND
            .checked_sub(start.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or("timeout")
    };
    let addr: SocketAddr = (host, 443)
        .to_socket_addrs()
        .map_err(|e| format!("resolve: {e}"))?
        .find(SocketAddr::is_ipv4)
        .ok_or("no IPv4 address")?;
    let mut sock =
        TcpStream::connect_timeout(&addr, left()?).map_err(|e| format!("connect: {e}"))?;
    let name = ServerName::try_from(host.to_owned()).map_err(|e| e.to_string())?;
    let mut conn = ClientConnection::new(tls.clone(), name).map_err(|e| e.to_string())?;
    while conn.is_handshaking() {
        let d = left()?;
        sock.set_read_timeout(Some(d)).map_err(|e| e.to_string())?;
        sock.set_write_timeout(Some(d)).map_err(|e| e.to_string())?;
        conn.complete_io(&mut IoStream(&mut sock))
            .map_err(|e| format!("tls: {e}"))?;
    }
    Ok(start.elapsed())
}

/// The socket as rustls's `complete_io` wants it.
struct IoStream<'a>(&'a mut TcpStream);

impl Read for IoStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for IoStream<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// `warp-cli disconnect` then `connect` on the host (its namespaces, PID 1's); each step's exit and output.
fn reconnect_warp() -> Value {
    let step = |what: &str| {
        let out = Command::new("nsenter")
            .args([
                "-t",
                "1",
                "-m",
                "-u",
                "-i",
                "-n",
                "--",
                "warp-cli",
                "--accept-tos",
                what,
            ])
            .output();
        match out {
            Ok(o) => json!({"step": what, "ok": o.status.success(),
                            "out": String::from_utf8_lossy(&o.stdout).trim().chars().take(200).collect::<String>(),
                            "err": String::from_utf8_lossy(&o.stderr).trim().chars().take(200).collect::<String>()}),
            Err(e) => json!({"step": what, "ok": false, "err": e.to_string()}),
        }
    };
    let first = step("disconnect");
    std::thread::sleep(Duration::from_secs(1));
    json!([first, step("connect")])
}

fn log(mut line: Value) {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    if let Some(o) = line.as_object_mut() {
        o.insert("t_ms".into(), json!(u64::try_from(t).unwrap_or(u64::MAX)));
        o.insert("svc".into(), json!("warp-watch"));
    }
    println!("{line}");
}
