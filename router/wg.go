package main

// The machines' listener on Fly's private network: the box is a WireGuard peer of the Fly org (a peer made
// with `fly wireguard create`), and the router runs that peer itself in userspace (wireguard-go + netstack),
// so the pod needs no privileges and /m is reachable from the org's machines and nowhere else.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// wgConf: the parts of a wg-quick file that `fly wireguard create` writes
type wgConf struct {
	Address, PrivateKey, PublicKey, Endpoint, AllowedIPs, Keepalive string
}

func parseWG(path string) (wgConf, error) {
	f, err := os.Open(path)
	if err != nil {
		return wgConf{}, err
	}
	defer f.Close()
	var c wgConf
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "Address":
			c.Address = v
		case "PrivateKey":
			c.PrivateKey = v
		case "PublicKey":
			c.PublicKey = v
		case "Endpoint":
			c.Endpoint = v
		case "AllowedIPs":
			c.AllowedIPs = v
		case "PersistentKeepalive":
			c.Keepalive = v
		}
	}
	if c.Address == "" || c.PrivateKey == "" || c.PublicKey == "" || c.Endpoint == "" {
		return c, fmt.Errorf("%s: missing Address/PrivateKey/PublicKey/Endpoint", path)
	}
	return c, sc.Err()
}

func b64hex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("bad WireGuard key")
	}
	return hex.EncodeToString(b), nil
}

// wgServer: the peer and the machines' listener on it
type wgServer struct {
	srv     *http.Server
	dev     *device.Device
	dropSyn *atomic.Bool
	oneShot *atomic.Bool
	once    sync.Once
}

// Prepare (a handover is coming: the drain begins): every answer from now on closes its connection, while this peer
// still serves. By the freeze the machines hold no pooled connection a request could race a FIN on (a POST on a
// connection the server just closed fails, and the machine's proxy doesn't retry it).
func (w *wgServer) Prepare() { w.oneShot.Store(true) }

// Quiesce (a handover, movegate.go): no new connection opens here — a machine's SYN is dropped, so its dial waits in
// TCP's retries for the next peer instead of reaching a router that no longer serves — and the idle connections are
// closed (a FIN, so no machine sends its next call down a dead one); every answer from now on closes its connection.
func (w *wgServer) Quiesce() {
	w.oneShot.Store(true)
	w.dropSyn.Store(true)
	w.srv.SetKeepAlivesEnabled(false)
}

// Stop: quiesce, let the last answers and FINs reach the machines, then the peer goes
func (w *wgServer) Stop() {
	w.once.Do(func() {
		w.Quiesce()
		time.Sleep(200 * time.Millisecond)
		w.dev.Close()
		w.srv.Close()
	})
}

// Shutdown: no new connection (Quiesce: a machine's dial goes to the other gateway), the requests in flight end (a
// snapshot upload, a long poll), then the peer goes; ctx bounds the wait
func (w *wgServer) Shutdown(ctx context.Context) {
	w.Quiesce()
	w.oneShot.Store(true) // kept-alive connections close after their current request
	w.srv.Shutdown(ctx)
	w.Stop()
}

// synFilter: the TUN between WireGuard and the netstack; drops incoming TCP SYNs once the peer is quiesced
type synFilter struct {
	tun.Device
	drop *atomic.Bool
	port uint16
}

func (f *synFilter) Write(bufs [][]byte, offset int) (int, error) {
	if !f.drop.Load() {
		return f.Device.Write(bufs, offset)
	}
	keep := bufs[:0:0]
	for _, b := range bufs {
		if !isSynTo(b[offset:], f.port) {
			keep = append(keep, b)
		}
	}
	if len(keep) > 0 {
		if _, err := f.Device.Write(keep, offset); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}

// isSynTo: an IPv4 or IPv6 (no extension headers) TCP segment opening a connection to port
func isSynTo(p []byte, port uint16) bool {
	var tcp []byte
	switch {
	case len(p) >= 40 && p[0]>>4 == 6 && p[6] == 6:
		tcp = p[40:]
	case len(p) >= 20 && p[0]>>4 == 4 && p[9] == 6:
		ihl := int(p[0]&0x0f) * 4
		if len(p) < ihl {
			return false
		}
		tcp = p[ihl:]
	default:
		return false
	}
	if len(tcp) < 14 {
		return false
	}
	dst := uint16(tcp[2])<<8 | uint16(tcp[3])
	flags := tcp[13]
	return dst == port && flags&0x02 != 0 && flags&0x10 == 0
}

// serveWG brings the box's WireGuard peer up and serves h on it; Stop takes the peer down (the leader's handover,
// leader.go; a move, move.go) and ends the serve. err reports a failure to come up.
func serveWG(path string, port int, h http.Handler) (*wgServer, error) {
	c, err := parseWG(path)
	if err != nil {
		return nil, err
	}
	pfx, err := netip.ParsePrefix(c.Address)
	if err != nil {
		return nil, fmt.Errorf("Address: %w", err)
	}
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{pfx.Addr()}, nil, 1420)
	if err != nil {
		return nil, err
	}
	ep, err := net.ResolveUDPAddr("udp", c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("endpoint %s: %w", c.Endpoint, err)
	}
	priv, err := b64hex(c.PrivateKey)
	if err != nil {
		return nil, err
	}
	pub, err := b64hex(c.PublicKey)
	if err != nil {
		return nil, err
	}
	ipc := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\n", priv, pub, ep.String())
	for _, a := range strings.Split(c.AllowedIPs, ",") {
		if a = strings.TrimSpace(a); a != "" {
			ipc += "allowed_ip=" + a + "\n"
		}
	}

	drop := &atomic.Bool{}
	dev := device.NewDevice(&synFilter{Device: tdev, drop: drop, port: uint16(port)}, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg: "))
	if err := dev.IpcSet(ipc); err != nil {
		return nil, err
	}
	if err := dev.Up(); err != nil {
		return nil, err
	}
	// the keepalive set only now, on a device that is up, makes wireguard-go send one at once: the handshake starts
	// now, not at the first packet or keepalive interval, so Fly's gateway routes the peer's address here at once (a
	// handover's gap). Without a keepalive in the config, one anyway, once.
	ka := c.Keepalive
	if ka == "" || ka == "0" {
		ka = "25"
	}
	if err := dev.IpcSet(fmt.Sprintf("public_key=%s\npersistent_keepalive_interval=%s\n", pub, ka)); err != nil {
		log.Printf("wg: keepalive: %v", err)
	}
	l, err := tnet.ListenTCP(&net.TCPAddr{IP: pfx.Addr().AsSlice(), Port: port})
	if err != nil {
		return nil, err
	}
	oneShot := &atomic.Bool{}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if oneShot.Load() {
			w.Header().Set("Connection", "close")
		}
		h.ServeHTTP(w, r)
	})}
	go func() {
		if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
			log.Printf("wg: serve: %v", err)
		}
	}()
	return &wgServer{srv: srv, dev: dev, dropSyn: drop, oneShot: oneShot}, nil
}
