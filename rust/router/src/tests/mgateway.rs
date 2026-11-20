//! router/mgateway_test.go, and a machine's request through the gateway's WireGuard peer (the machine played with
//! boringtun and smoltcp, as rust/machine dials it)
use crate::mgateway::{gateway_config, parse_to, proxy_handler, refused_path};
use crate::testutil::*;
use crate::wgserve::{PeerConf, Queues, is_syn_to, now_s, parse_cidr, parse_wg_conf, serve_wg};
use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default, Clone, Debug)]
struct Got {
    path: String,
    sig: String,
    body: usize,
}

/// the router's machines' port: records what it got, answers "answer" with a header of its own
fn fake_router() -> (TestServer, Arc<Mutex<Got>>) {
    let got: Arc<Mutex<Got>> = Arc::default();
    let g2 = got.clone();
    let srv = TestServer::handler(move |w, req| {
        let b = req.read_body(16 << 20);
        *g2.lock().unwrap_or_else(|e| e.into_inner()) = Got {
            path: format!("{}?{}", req.path, req.raw_query),
            sig: req.header("X-Sig"),
            body: b.len(),
        };
        w.set_header("X-Snapshot-Sig", "s");
        w.write_str("answer");
    });
    (srv, got)
}

fn to_of(srv: &TestServer) -> (String, u16) {
    parse_to(&srv.url).unwrap_or_else(|e| panic!("{e:#}"))
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("{e}"))
}

/// an HTTP/1.1 exchange over a stream: the raw answer, until the server closes
async fn exchange(
    mut s: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    req: &[u8],
) -> String {
    s.write_all(req).await.unwrap_or_else(|e| panic!("{e}"));
    let mut out = vec![];
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

/// the gateway passes a machine's signed request on as it is (its headers, its streamed body) and the router's
/// answer back; a router out of reach is a 502 the machine retries
#[test]
fn m_gateway_passes_requests_on() {
    let (router, got) = fake_router();
    let to = to_of(&router);
    rt().block_on(async {
        let h = proxy_handler(to.clone());
        let (ours, theirs) = tokio::io::duplex(1 << 20);
        h(theirs, Arc::new(AtomicBool::new(true)));
        let body = "b".repeat(1 << 20);
        let req = format!(
            "POST /m/snapshot-stream?x=1 HTTP/1.1\r\nHost: g\r\nX-Sig: machine-sig\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let out = exchange(ours, req.as_bytes()).await;
        let g = got.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            out.starts_with("HTTP/1.1 200")
                && out.to_lowercase().contains("x-snapshot-sig: s")
                && out.contains("\r\nanswer\r\n") // chunked: the router's length isn't known ahead
                && g.path == "/m/snapshot-stream?x=1"
                && g.sig == "machine-sig"
                && g.body == 1 << 20,
            "{:.300} {g:?}",
            out
        );
        // the gateways' own calls are never a machine's
        let (ours, theirs) = tokio::io::duplex(1 << 16);
        h(theirs, Arc::new(AtomicBool::new(true)));
        let out = exchange(ours, b"GET /gw/aws-peers HTTP/1.1\r\nHost: g\r\nConnection: close\r\n\r\n").await;
        assert!(out.starts_with("HTTP/1.1 404"), "{out:.200}");
    });
    drop(router);
    rt().block_on(async {
        let h = proxy_handler(to);
        let (ours, theirs) = tokio::io::duplex(1 << 16);
        h(theirs, Arc::new(AtomicBool::new(true)));
        let out = exchange(
            ours,
            b"GET /m/commands HTTP/1.1\r\nHost: g\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 502"), "router gone: {out:.200}");
    });
}

#[test]
fn gateway_config_by_ordinal() {
    let p = gateway_config("/wg-a/wg.conf,/wg-b/wg.conf", "m-gateway-1");
    assert_eq!(p.ok().as_deref(), Some("/wg-b/wg.conf"));
    assert!(
        gateway_config("/wg-a/wg.conf", "m-gateway-1").is_err(),
        "an ordinal past the peers"
    );
    assert!(gateway_config("", "m-gateway-0").is_err(), "no configs");
    assert!(
        refused_path("/gw/aws-peers") && refused_path("/m/../gw/x") && !refused_path("/m/status")
    );
    assert_eq!(
        parse_to("http://router.jarvis4-router.svc.cluster.local:8081").ok(),
        Some(("router.jarvis4-router.svc.cluster.local".to_string(), 8081))
    );
    let c = parse_wg_conf(
        "[Interface]\nAddress = fdaa:0:1::2/120\nPrivateKey = a\n[Peer]\nPublicKey = b\nEndpoint = x:51820\nAllowedIPs = fdaa::/16\nPersistentKeepalive = 15\n",
        "wg.conf",
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        c.address == "fdaa:0:1::2/120" && c.allowed_ips == "fdaa::/16" && c.keepalive == "15",
        "{c:?}"
    );
    assert!(
        parse_wg_conf("Address = x\n", "w").is_err(),
        "a conf without keys"
    );
    assert_eq!(
        parse_cidr("10.0.0.1/24").ok(),
        Some((IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24))
    );
}

/// a TCP SYN to the port (not a SYN-ACK, nor another port)
#[test]
fn syns_to_the_port() {
    let mut p = vec![0u8; 40];
    p[0] = 0x45;
    p[9] = 6;
    p[22] = (8081u16 >> 8) as u8;
    p[23] = (8081u16 & 0xff) as u8;
    p[33] = 0x02;
    assert!(is_syn_to(&p, 8081));
    p[33] = 0x12;
    assert!(!is_syn_to(&p, 8081), "a SYN-ACK");
    p[33] = 0x02;
    assert!(!is_syn_to(&p, 443), "another port");
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// a fresh local port each connection (a reused one meets the last connection's TIME-WAIT on the gateway)
fn next_port() -> u16 {
    static NEXT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(40000);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// a machine on the tunnel: boringtun to the gateway, smoltcp's TCP to its address; one HTTP request, its answer
async fn machine_request(
    sk: x25519::StaticSecret,
    gw_pub: x25519::PublicKey,
    udp: tokio::net::UdpSocket,
    gw_udp: SocketAddr,
    req: &[u8],
) -> String {
    let mut tunn = Tunn::new(sk, gw_pub, None, None, 7, None);
    let start = Instant::now();
    let mut q = Queues {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
        mtu: 1420,
    };
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut q, now_s(start));
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::v4(10, 7, 0, 2), 24));
    });
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(10, 7, 0, 2));
    let mut sockets = SocketSet::new(vec![]);
    let h = sockets.add(tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 1 << 16]),
        tcp::SocketBuffer::new(vec![0; 1 << 16]),
    ));
    let cx = iface.context();
    sockets
        .get_mut::<tcp::Socket>(h)
        .connect(cx, (IpAddress::v4(10, 7, 0, 1), 8081), next_port())
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut sent = 0usize;
    let mut answer = vec![];
    let mut buf = vec![0u8; 65536];
    let mut out = vec![0u8; 65536];
    let end = Instant::now() + Duration::from_secs(20);
    while Instant::now() < end {
        iface.poll(now_s(start), &mut q, &mut sockets);
        {
            let s = sockets.get_mut::<tcp::Socket>(h);
            if s.may_send()
                && sent < req.len()
                && let Ok(n) = s.send_slice(&req[sent..])
            {
                sent += n;
            }
            while s.can_recv() {
                let mut b = vec![0u8; 16 << 10];
                match s.recv_slice(&mut b) {
                    Ok(n) if n > 0 => answer.extend_from_slice(&b[..n]),
                    _ => break,
                }
            }
            if sent > 0 && !s.may_recv() && s.state() != tcp::State::SynSent {
                break;
            }
        }
        iface.poll(now_s(start), &mut q, &mut sockets);
        while let Some(p) = q.tx.pop_front() {
            if let TunnResult::WriteToNetwork(w) = tunn.encapsulate(&p, &mut out) {
                let _ = udp.send_to(w, gw_udp).await;
            }
        }
        if let TunnResult::WriteToNetwork(w) = tunn.update_timers(&mut out) {
            let _ = udp.send_to(w, gw_udp).await;
        }
        if let Ok(Ok((n, from))) =
            tokio::time::timeout(Duration::from_millis(5), udp.recv_from(&mut buf)).await
        {
            let mut first = true;
            loop {
                let r = if first {
                    tunn.decapsulate(Some(from.ip()), &buf[..n], &mut out)
                } else {
                    tunn.decapsulate(None, &[], &mut out)
                };
                first = false;
                match r {
                    TunnResult::WriteToNetwork(w) => {
                        let _ = udp.send_to(w, from).await;
                    }
                    TunnResult::WriteToTunnelV4(w, _) | TunnResult::WriteToTunnelV6(w, _) => {
                        q.rx.push_back(w.to_vec());
                        break;
                    }
                    _ => break,
                }
            }
        }
    }
    String::from_utf8_lossy(&answer).into_owned()
}

/// a machine's request through the gateway's WireGuard peer reaches the router and its answer comes back; a peer the
/// gateway doesn't know gets nothing
#[test]
fn a_machine_reaches_the_router_through_the_wireguard_peer() {
    let (router, got) = fake_router();
    let to = to_of(&router);
    rt().block_on(async {
        let gw_sk = x25519::StaticSecret::from([3u8; 32]);
        let m_sk = x25519::StaticSecret::from([5u8; 32]);
        let (gw_pub, m_pub) = (x25519::PublicKey::from(&gw_sk), x25519::PublicKey::from(&m_sk));
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap_or_else(|e| panic!("{e}"));
        let m_addr = udp.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let gw = serve_wg(
            (IpAddr::V4(Ipv4Addr::new(10, 7, 0, 1)), 24),
            1420,
            [3u8; 32],
            vec![PeerConf {
                public_key: b64(m_pub.as_bytes()),
                endpoint: Some(m_addr),
                allowed: vec![(IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2)), 32)],
                keepalive: Some(25),
            }],
            8081,
            proxy_handler(to),
            "wg-test",
        )
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
        let gw_udp = SocketAddr::from(([127, 0, 0, 1], gw.local_addr.port()));
        let out = machine_request(
            m_sk,
            gw_pub,
            udp,
            gw_udp,
            b"GET /m/commands?wait=1 HTTP/1.1\r\nHost: m-gateway\r\nX-Sig: sig-of-the-machine\r\nConnection: close\r\n\r\n",
        )
        .await;
        let g = got.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            out.starts_with("HTTP/1.1 200") && out.contains("\r\nanswer\r\n") && g.path == "/m/commands?wait=1" && g.sig == "sig-of-the-machine",
            "{out:.300} {g:?}"
        );
        // a snapshot upload: 2 MiB through the tunnel's TCP and the gateway's buffers
        let body = "u".repeat(2 << 20);
        let udp2 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap_or_else(|e| panic!("{e}"));
        let _ = gw.peers.send(vec![PeerConf {
            public_key: b64(m_pub.as_bytes()),
            endpoint: Some(udp2.local_addr().unwrap_or_else(|e| panic!("{e}"))),
            allowed: vec![(IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2)), 32)],
            keepalive: Some(25),
        }]);
        let req = format!(
            "POST /m/snapshot-stream HTTP/1.1\r\nHost: g\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let out = machine_request(x25519::StaticSecret::from([5u8; 32]), gw_pub, udp2, gw_udp, req.as_bytes()).await;
        let g = got.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(out.starts_with("HTTP/1.1 200") && g.body == 2 << 20, "{out:.200} {g:?}");
        // a stranger's key: no session, no answer
        let other = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap_or_else(|e| panic!("{e}"));
        let out = machine_request(
            x25519::StaticSecret::from([9u8; 32]),
            gw_pub,
            other,
            gw_udp,
            b"GET /m/x HTTP/1.1\r\nHost: g\r\nConnection: close\r\n\r\n",
        );
        let out = tokio::time::timeout(Duration::from_secs(3), out).await.unwrap_or_default();
        assert!(out.is_empty(), "a peer the gateway doesn't know got {out:.100}");
        // stopping: a new connection's SYN is dropped (the machine dials the other gateway)
        gw.quiesce();
        let udp3 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap_or_else(|e| panic!("{e}"));
        let _ = gw.peers.send(vec![PeerConf {
            public_key: b64(m_pub.as_bytes()),
            endpoint: Some(udp3.local_addr().unwrap_or_else(|e| panic!("{e}"))),
            allowed: vec![(IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2)), 32)],
            keepalive: Some(25),
        }]);
        let out = machine_request(
            x25519::StaticSecret::from([5u8; 32]),
            gw_pub,
            udp3,
            gw_udp,
            b"GET /m/x HTTP/1.1\r\nHost: g\r\nConnection: close\r\n\r\n",
        );
        let out = tokio::time::timeout(Duration::from_secs(3), out).await.unwrap_or_default();
        assert!(out.is_empty(), "a stopping gateway took a new connection: {out:.100}");
        gw.shutdown(Duration::from_millis(100)).await;
    });
}
