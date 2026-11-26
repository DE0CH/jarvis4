//! A WireGuard device in userspace that serves HTTP on one TCP port of its tunnel address (wgserve.rs and
//! awsgw.go's serveWG/serveAWSWG): boringtun does WireGuard, smoltcp the tunnel's TCP/IP, and every connection a
//! peer opens is handed to an HTTP handler (hyper) as a stream. No kernel interface, no privileges: the pod only
//! sends and receives UDP.
//!
//! One task owns the device: its peers (a Tunn each), the smoltcp interface and the listening sockets. A connection
//! is bridged to its own task through two channels; the device task wakes on a datagram, on a connection's bytes or
//! on smoltcp's next timer.
//!
//! Stopping: quiesce drops new connections' SYNs (the machines dial the other gateway) and asks the handler to close
//! kept-alive connections after their current request; the connections in flight end by themselves.

use anyhow::{Result, anyhow};
use base64::Engine;
use boringtun::noise::{Packet, Tunn, TunnResult, handshake::parse_handshake_anon};
use boringtun::x25519;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc};

/// a peer of the device
#[derive(Debug, Clone, PartialEq)]
pub struct PeerConf {
    /// base64, as in wg.conf
    pub public_key: String,
    /// where its datagrams go until it sends from elsewhere (None: wait for it)
    pub endpoint: Option<SocketAddr>,
    /// the addresses it may send from and is sent to
    pub allowed: Vec<(IpAddr, u8)>,
    pub keepalive: Option<u16>,
}

/// what a wg.conf says (wgserve.rs parseWG)
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WgConf {
    pub address: String,
    pub private_key: String,
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: String,
    pub keepalive: String,
}

pub fn parse_wg_conf(text: &str, what: &str) -> Result<WgConf> {
    let mut c = WgConf::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim().to_string();
        match k.trim() {
            "Address" => c.address = v,
            "PrivateKey" => c.private_key = v,
            "PublicKey" => c.public_key = v,
            "Endpoint" => c.endpoint = v,
            "AllowedIPs" => c.allowed_ips = v,
            "PersistentKeepalive" => c.keepalive = v,
            _ => {}
        }
    }
    if c.address.is_empty()
        || c.private_key.is_empty()
        || c.public_key.is_empty()
        || c.endpoint.is_empty()
    {
        return Err(anyhow!(
            "{what}: missing Address/PrivateKey/PublicKey/Endpoint"
        ));
    }
    Ok(c)
}

/// a WireGuard key (32 bytes, base64)
pub fn wg_key(b64: &str) -> Result<[u8; 32]> {
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| anyhow!("bad WireGuard key"))
}

/// "10.0.0.1/24" or "fdaa::1" → (address, prefix length)
pub fn parse_cidr(s: &str) -> Result<(IpAddr, u8)> {
    let (a, p) = match s.trim().split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s.trim(), None),
    };
    let ip: IpAddr = a.parse().map_err(|_| anyhow!("bad address {s:?}"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = match p {
        Some(p) => p
            .parse::<u8>()
            .ok()
            .filter(|n| *n <= max)
            .ok_or_else(|| anyhow!("bad prefix {s:?}"))?,
        None => max,
    };
    Ok((ip, len))
}

fn in_prefix(ip: IpAddr, (net, len): (IpAddr, u8)) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let m = if len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(len))
            };
            u32::from(a) & m == u32::from(n) & m
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let m = if len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(len))
            };
            u128::from(a) & m == u128::from(n) & m
        }
        _ => false,
    }
}

/// a TCP SYN (not a SYN-ACK) to port, in an IPv4 or IPv6 packet (wgserve.rs isSynTo)
pub fn is_syn_to(p: &[u8], port: u16) -> bool {
    let tcp = match p.first().map(|b| b >> 4) {
        Some(6) if p.len() >= 40 && p[6] == 6 => &p[40..],
        Some(4) if p.len() >= 20 && p[9] == 6 => {
            let ihl = usize::from(p[0] & 0x0f) * 4;
            if p.len() < ihl {
                return false;
            }
            &p[ihl..]
        }
        _ => return false,
    };
    if tcp.len() < 14 {
        return false;
    }
    let dst = u16::from_be_bytes([tcp[2], tcp[3]]);
    let flags = tcp[13];
    dst == port && flags & 0x02 != 0 && flags & 0x10 == 0
}

/// the source address of an IP packet
fn src_of(p: &[u8]) -> Option<IpAddr> {
    match p.first().map(|b| b >> 4) {
        Some(4) if p.len() >= 20 => Some(IpAddr::from(<[u8; 4]>::try_from(&p[12..16]).ok()?)),
        Some(6) if p.len() >= 40 => Some(IpAddr::from(<[u8; 16]>::try_from(&p[8..24]).ok()?)),
        _ => None,
    }
}

/// the destination address of an IP packet
fn dst_of(p: &[u8]) -> Option<IpAddr> {
    match p.first().map(|b| b >> 4) {
        Some(4) if p.len() >= 20 => Some(IpAddr::from(<[u8; 4]>::try_from(&p[16..20]).ok()?)),
        Some(6) if p.len() >= 40 => Some(IpAddr::from(<[u8; 16]>::try_from(&p[24..40]).ok()?)),
        _ => None,
    }
}

// ---- the smoltcp side: IP packets in and out of queues -----------------------------------------------------------

pub(crate) struct Queues {
    pub(crate) rx: VecDeque<Vec<u8>>,
    pub(crate) tx: VecDeque<Vec<u8>>,
    pub(crate) mtu: usize,
}

pub(crate) struct QRx(Vec<u8>);
pub(crate) struct QTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for QRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for QTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push_back(b);
        r
    }
}

impl Device for Queues {
    type RxToken<'a> = QRx;
    type TxToken<'a> = QTx<'a>;

    fn receive(&mut self, _: SInstant) -> Option<(QRx, QTx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((QRx(p), QTx(&mut self.tx)))
    }

    fn transmit(&mut self, _: SInstant) -> Option<QTx<'_>> {
        Some(QTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

// ---- the device -----------------------------------------------------------------------------------------------------

/// what an HTTP handler is given: the connection's stream, and whether the device is stopping (close after this
/// request)
pub type ConnHandler = Arc<dyn Fn(DuplexStream, Arc<AtomicBool>) + Send + Sync>;

/// a running device: its controls
pub struct WgServer {
    /// drop new connections' SYNs
    pub drop_syn: Arc<AtomicBool>,
    /// close kept-alive connections after their current request
    pub one_shot: Arc<AtomicBool>,
    /// the connections it carries
    pub active: Arc<AtomicUsize>,
    /// a peer set to replace the current one with (the AWS machines)
    pub peers: mpsc::UnboundedSender<Vec<PeerConf>>,
    /// the UDP address its datagrams leave from (IPv4)
    pub local_addr: SocketAddr,
    stop: Arc<Notify>,
    stopped: Arc<AtomicBool>,
}

impl WgServer {
    /// no new connections; the ones in flight end after their current request
    pub fn quiesce(&self) {
        self.one_shot.store(true, Ordering::SeqCst);
        self.drop_syn.store(true, Ordering::SeqCst);
    }

    /// quiesce, wait (up to grace) for the connections in flight to end, then stop the device
    pub async fn shutdown(&self, grace: Duration) {
        self.quiesce();
        let end = Instant::now() + grace;
        while self.active.load(Ordering::SeqCst) > 0 && Instant::now() < end {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        self.stopped.store(true, Ordering::SeqCst);
        self.stop.notify_one();
    }
}

struct Peer {
    key: [u8; 32],
    /// the index its Tunn was made with (the session indices it hands out are index << 8 + n)
    index: u32,
    tunn: Tunn,
    endpoint: Option<SocketAddr>,
    allowed: Vec<(IpAddr, u8)>,
}

/// a connection's two halves on the device task's side
struct Conn {
    handle: SocketHandle,
    /// bytes from the peer → the handler (None once the peer closed its side)
    to_handler: Option<mpsc::Sender<Vec<u8>>>,
    /// bytes from the handler → the peer
    from_handler: mpsc::Receiver<Vec<u8>>,
    /// a chunk taken from from_handler that the socket hasn't taken all of yet
    pending: Vec<u8>,
    /// the handler closed its side
    handler_done: bool,
    /// bytes read from the socket that to_handler had no room for yet
    held: Option<Vec<u8>>,
}

/// the listening sockets kept ready at once (each takes one connection)
const LISTENERS: usize = 4;
const TCP_BUF: usize = 256 << 10;

/// a device with address addr/prefix (mtu), its private key and peers, serving port with handler. The UDP socket is
/// bound to an ephemeral port: the gateway dials its peers (their endpoints), and learns a peer's new endpoint from
/// where its datagrams come from.
pub async fn serve_wg(
    addr: (IpAddr, u8),
    mtu: usize,
    private_key: [u8; 32],
    peers: Vec<PeerConf>,
    port: u16,
    handler: ConnHandler,
    what: &'static str,
) -> Result<WgServer> {
    let v4 = UdpSocket::bind("0.0.0.0:0").await?;
    let v6 = UdpSocket::bind("[::]:0").await.ok();
    let (ptx, prx) = mpsc::unbounded_channel();
    let s = WgServer {
        drop_syn: Arc::new(AtomicBool::new(false)),
        one_shot: Arc::new(AtomicBool::new(false)),
        active: Arc::new(AtomicUsize::new(0)),
        peers: ptx,
        local_addr: v4.local_addr()?,
        stop: Arc::new(Notify::new()),
        stopped: Arc::new(AtomicBool::new(false)),
    };
    let dev = DevTask {
        what,
        addr,
        port,
        secret: x25519::StaticSecret::from(private_key),
        peers: vec![],
        v4,
        v6,
        queues: Queues {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        },
        conns: vec![],
        listeners: vec![],
        handler,
        wake: Arc::new(Notify::new()),
        drop_syn: s.drop_syn.clone(),
        one_shot: s.one_shot.clone(),
        active: s.active.clone(),
        stop: s.stop.clone(),
        stopped: s.stopped.clone(),
        next_index: 1,
    };
    let mut dev = dev;
    dev.set_peers(peers);
    tokio::spawn(dev.run(prx));
    Ok(s)
}

struct DevTask {
    what: &'static str,
    addr: (IpAddr, u8),
    port: u16,
    secret: x25519::StaticSecret,
    peers: Vec<Option<Peer>>,
    v4: UdpSocket,
    v6: Option<UdpSocket>,
    queues: Queues,
    conns: Vec<Conn>,
    listeners: Vec<SocketHandle>,
    handler: ConnHandler,
    wake: Arc<Notify>,
    drop_syn: Arc<AtomicBool>,
    one_shot: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    stop: Arc<Notify>,
    stopped: Arc<AtomicBool>,
    next_index: u32,
}

pub(crate) fn now_s(start: Instant) -> SInstant {
    SInstant::from_millis(i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX))
}

impl DevTask {
    /// the peers become exactly these: a known key keeps its session (its allowed IPs and endpoint follow), a new one
    /// gets a Tunn, a missing one goes
    fn set_peers(&mut self, want: Vec<PeerConf>) {
        let mut keep: Vec<Option<Peer>> = std::mem::take(&mut self.peers);
        let mut next: Vec<Option<Peer>> = vec![];
        for p in want {
            let Ok(key) = wg_key(&p.public_key) else {
                crate::logf!("{}: peer {}: bad key", self.what, p.public_key);
                continue;
            };
            if let Some(i) = keep
                .iter()
                .position(|x| x.as_ref().is_some_and(|x| x.key == key))
                && let Some(mut old) = keep[i].take()
            {
                old.allowed = p.allowed.clone();
                if p.endpoint.is_some() {
                    old.endpoint = p.endpoint;
                }
                next.push(Some(old));
                continue;
            }
            let index = self.next_index;
            self.next_index = self.next_index.wrapping_add(1) & 0x00ff_ffff;
            next.push(Some(Peer {
                key,
                index,
                tunn: Tunn::new(
                    self.secret.clone(),
                    x25519::PublicKey::from(key),
                    None,
                    p.keepalive,
                    index,
                    None,
                ),
                endpoint: p.endpoint,
                allowed: p.allowed,
            }));
        }
        self.peers = next;
    }

    fn peer_for_dst(&mut self, dst: IpAddr) -> Option<&mut Peer> {
        self.peers
            .iter_mut()
            .flatten()
            .filter_map(|p| {
                let best = p
                    .allowed
                    .iter()
                    .filter(|a| in_prefix(dst, **a))
                    .map(|a| a.1)
                    .max()?;
                Some((best, p))
            })
            .max_by_key(|(len, _)| *len)
            .map(|(_, p)| p)
    }

    async fn send_to(&self, to: SocketAddr, b: &[u8]) {
        let sock = match (to, &self.v6) {
            (SocketAddr::V6(_), Some(s)) => s,
            _ => &self.v4,
        };
        if let Err(e) = sock.send_to(b, to).await {
            crate::logf!("{}: send to {to}: {e}", self.what);
        }
    }

    /// a datagram from from
    async fn datagram(&mut self, from: SocketAddr, b: &[u8]) {
        let mut out = vec![0u8; 65536];
        let pkt = match Tunn::parse_incoming_packet(b) {
            Ok(p) => p,
            Err(_) => return,
        };
        let pk = x25519::PublicKey::from(&self.secret);
        let i = match &pkt {
            Packet::HandshakeInit(h) => {
                let Ok(half) = parse_handshake_anon(&self.secret, &pk, h) else {
                    return;
                };
                let Some(i) = self
                    .peers
                    .iter()
                    .position(|p| p.as_ref().is_some_and(|p| p.key == half.peer_static_public))
                else {
                    return;
                };
                i
            }
            Packet::HandshakeResponse(h) => match self.index_of(h.receiver_idx) {
                Some(i) => i,
                None => return,
            },
            Packet::PacketCookieReply(c) => match self.index_of(c.receiver_idx) {
                Some(i) => i,
                None => return,
            },
            Packet::PacketData(d) => match self.index_of(d.receiver_idx) {
                Some(i) => i,
                None => return,
            },
        };
        let mut sends: Vec<Vec<u8>> = vec![];
        let mut ins: Vec<Vec<u8>> = vec![];
        let allowed;
        {
            let Some(p) = self.peers.get_mut(i).and_then(Option::as_mut) else {
                return;
            };
            p.endpoint = Some(from);
            allowed = p.allowed.clone();
            let mut first = true;
            loop {
                let r = if first {
                    p.tunn.decapsulate(Some(from.ip()), b, &mut out)
                } else {
                    p.tunn.decapsulate(None, &[], &mut out)
                };
                first = false;
                match r {
                    TunnResult::WriteToNetwork(w) => sends.push(w.to_vec()),
                    TunnResult::WriteToTunnelV4(w, _) | TunnResult::WriteToTunnelV6(w, _) => {
                        ins.push(w.to_vec());
                        break;
                    }
                    TunnResult::Done | TunnResult::Err(_) => break,
                }
            }
        }
        for s in sends {
            self.send_to(from, &s).await;
        }
        for p in ins {
            // only from an address the peer may send from (wireguard-go's allowed-IPs check)
            if src_of(&p).is_some_and(|src| allowed.iter().any(|a| in_prefix(src, *a))) {
                if self.drop_syn.load(Ordering::SeqCst) && is_syn_to(&p, self.port) {
                    continue;
                }
                self.queues.rx.push_back(p);
            }
        }
    }

    fn index_of(&self, receiver_idx: u32) -> Option<usize> {
        let want = receiver_idx >> 8;
        self.peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.index == want))
    }

    /// smoltcp's outgoing packets to their peers
    async fn flush_tx(&mut self) {
        let mut out = vec![0u8; 65536];
        while let Some(p) = self.queues.tx.pop_front() {
            let Some(dst) = dst_of(&p) else { continue };
            let send = {
                let Some(peer) = self.peer_for_dst(dst) else {
                    continue;
                };
                let ep = peer.endpoint;
                match peer.tunn.encapsulate(&p, &mut out) {
                    TunnResult::WriteToNetwork(w) => ep.map(|e| (e, w.to_vec())),
                    _ => None,
                }
            };
            if let Some((e, w)) = send {
                self.send_to(e, &w).await;
            }
        }
    }

    /// every peer's timers: handshakes, keepalives
    async fn timers(&mut self) {
        let mut out = vec![0u8; 65536];
        let mut sends = vec![];
        for p in self.peers.iter_mut().flatten() {
            if let TunnResult::WriteToNetwork(w) = p.tunn.update_timers(&mut out)
                && let Some(e) = p.endpoint
            {
                sends.push((e, w.to_vec()));
            }
        }
        for (e, w) in sends {
            self.send_to(e, &w).await;
        }
    }

    async fn run(mut self, mut peer_updates: mpsc::UnboundedReceiver<Vec<PeerConf>>) {
        let start = Instant::now();
        let mut cfg = Config::new(HardwareAddress::Ip);
        cfg.random_seed = rand::random();
        let mut iface = Interface::new(cfg, &mut self.queues, now_s(start));
        let ip = IpAddress::from(self.addr.0);
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(ip, self.addr.1));
        });
        match self.addr.0 {
            IpAddr::V4(v) => {
                let _ = iface.routes_mut().add_default_ipv4_route(v);
            }
            IpAddr::V6(v) => {
                let _ = iface.routes_mut().add_default_ipv6_route(v);
            }
        }
        let mut sockets = SocketSet::new(vec![]);
        let mut udp_buf = vec![0u8; 65536];
        let mut udp6_buf = vec![0u8; 65536];
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        loop {
            if self.stopped.load(Ordering::SeqCst) {
                return;
            }
            // listening sockets: LISTENERS ready while not stopping
            self.listeners
                .retain(|h| sockets.get::<tcp::Socket>(*h).state() == tcp::State::Listen);
            while !self.drop_syn.load(Ordering::SeqCst) && self.listeners.len() < LISTENERS {
                let mut sock = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; TCP_BUF]),
                    tcp::SocketBuffer::new(vec![0; TCP_BUF]),
                );
                if sock.listen(self.port).is_err() {
                    break;
                }
                self.listeners.push(sockets.add(sock));
            }
            iface.poll(now_s(start), &mut self.queues, &mut sockets);
            self.pump(&mut sockets);
            iface.poll(now_s(start), &mut self.queues, &mut sockets);
            self.flush_tx().await;
            let delay = iface
                .poll_delay(now_s(start), &sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(Duration::from_millis(250))
                .min(Duration::from_millis(250));
            let wake = self.wake.clone();
            let stop = self.stop.clone();
            tokio::select! {
                r = self.v4.recv_from(&mut udp_buf) => {
                    if let Ok((n, from)) = r {
                        let b = udp_buf[..n].to_vec();
                        self.datagram(from, &b).await;
                    }
                }
                r = async {
                    match &self.v6 {
                        Some(s) => s.recv_from(&mut udp6_buf).await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Ok((n, from)) = r {
                        let b = udp6_buf[..n].to_vec();
                        self.datagram(from, &b).await;
                    }
                }
                _ = tick.tick() => self.timers().await,
                Some(p) = peer_updates.recv() => self.set_peers(p),
                _ = wake.notified() => {}
                _ = stop.notified() => {}
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    /// accepted connections handed to the handler; bytes moved both ways; closed ones dropped
    fn pump(&mut self, sockets: &mut SocketSet<'_>) {
        // newly established: a connection each
        let mut taken = vec![];
        for h in &self.listeners {
            let st = sockets.get::<tcp::Socket>(*h).state();
            if st != tcp::State::Listen {
                taken.push(*h);
            }
        }
        for h in taken {
            self.listeners.retain(|x| *x != h);
            let (to_h_tx, mut to_h_rx) = mpsc::channel::<Vec<u8>>(16);
            let (from_h_tx, from_h_rx) = mpsc::channel::<Vec<u8>>(16);
            let (ours, theirs) = tokio::io::duplex(64 << 10);
            let wake = self.wake.clone();
            self.active.fetch_add(1, Ordering::SeqCst);
            // the bridge: the duplex's end ↔ the channels
            tokio::spawn(async move {
                let (mut rd, mut wr) = tokio::io::split(ours);
                let w = wake.clone();
                let reader = tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 << 10];
                    loop {
                        match rd.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if from_h_tx.send(buf[..n].to_vec()).await.is_err() {
                                    break;
                                }
                                w.notify_one();
                            }
                        }
                    }
                    drop(from_h_tx);
                    w.notify_one();
                });
                while let Some(b) = to_h_rx.recv().await {
                    if wr.write_all(&b).await.is_err() {
                        break;
                    }
                    wake.notify_one();
                }
                let _ = wr.shutdown().await;
                let _ = reader.await;
            });
            (self.handler)(theirs, self.one_shot.clone());
            self.conns.push(Conn {
                handle: h,
                to_handler: Some(to_h_tx),
                from_handler: from_h_rx,
                pending: vec![],
                handler_done: false,
                held: None,
            });
        }
        let mut gone = vec![];
        for (i, c) in self.conns.iter_mut().enumerate() {
            let sock = sockets.get_mut::<tcp::Socket>(c.handle);
            // peer → handler
            let mut handler_gone = false;
            if let Some(tx) = &c.to_handler {
                if let Some(b) = c.held.take() {
                    match tx.try_send(b) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(b)) => c.held = Some(b),
                        Err(mpsc::error::TrySendError::Closed(_)) => handler_gone = true,
                    }
                }
                while !handler_gone && c.held.is_none() && sock.can_recv() {
                    let mut b = vec![0u8; 16 << 10];
                    match sock.recv_slice(&mut b) {
                        Ok(n) if n > 0 => {
                            b.truncate(n);
                            match tx.try_send(b) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(b)) => c.held = Some(b),
                                Err(mpsc::error::TrySendError::Closed(_)) => handler_gone = true,
                            }
                        }
                        _ => break,
                    }
                }
                // the peer closed its side (its FIN came: not SYN-RECEIVED, where may_recv is false too): EOF to
                // the handler
                let fin = matches!(
                    sock.state(),
                    tcp::State::CloseWait
                        | tcp::State::LastAck
                        | tcp::State::Closing
                        | tcp::State::TimeWait
                        | tcp::State::Closed
                );
                handler_gone |= c.held.is_none() && fin && !sock.can_recv();
            }
            if handler_gone {
                c.to_handler = None;
                c.held = None;
            }
            // handler → peer
            loop {
                if !c.pending.is_empty() {
                    match sock.send_slice(&c.pending) {
                        Ok(n) => {
                            c.pending.drain(..n);
                        }
                        Err(_) => break,
                    }
                    if !c.pending.is_empty() {
                        break;
                    }
                }
                match c.from_handler.try_recv() {
                    Ok(b) => c.pending = b,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        c.handler_done = true;
                        break;
                    }
                }
            }
            if c.handler_done && c.pending.is_empty() && sock.may_send() {
                sock.close();
            }
            match sock.state() {
                tcp::State::Closed | tcp::State::TimeWait => gone.push(i),
                _ => {}
            }
        }
        for i in gone.into_iter().rev() {
            let c = self.conns.remove(i);
            sockets.remove(c.handle);
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
