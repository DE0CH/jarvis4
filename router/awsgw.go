package main

// The m-gateway's second WireGuard device: the AWS machines' (awsrunner.go). It listens on no fixed port: it starts
// every handshake itself, to each instance's public IPv4, as GET /gw/aws-peers on the router lists them every 10 s,
// so the box takes nothing inbound. It serves the same proxy on its tunnel address's port 8081.
//
//	WG_AWS_KEYS      the gateways' WireGuard private keys, comma-separated; the pod's ordinal picks its own
//	WG_AWS_GATEWAYS  "<public key>@<tunnel address>,…" in the same order (the router's, too): this pod's address

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// serveAWSWG: the AWS machines' device with privKey (base64) at addr, serving h on port; peers from peersURL
func serveAWSWG(privKey, addr string, port int, h http.Handler, peersURL string) (*wgServer, error) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("address %q: %w", addr, err)
	}
	priv, err := b64hex(privKey)
	if err != nil {
		return nil, err
	}
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{a}, nil, 1420)
	if err != nil {
		return nil, err
	}
	drop := &atomic.Bool{}
	dev := device.NewDevice(&synFilter{Device: tdev, drop: drop, port: uint16(port)}, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg-aws: "))
	if err := dev.IpcSet("private_key=" + priv + "\n"); err != nil {
		return nil, err
	}
	if err := dev.Up(); err != nil {
		return nil, err
	}
	l, err := tnet.ListenTCP(&net.TCPAddr{IP: a.AsSlice(), Port: port})
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
			log.Printf("wg-aws: serve: %v", err)
		}
	}()
	go awsPeerLoop(dev, peersURL)
	return &wgServer{srv: srv, dev: dev, dropSyn: drop, oneShot: oneShot}, nil
}

// awsPeerLoop: the device's peers kept to the router's list: a new machine added (keepalive 25 s, so the handshake
// starts at once and NAT-free state stays), a gone one removed, an existing one left alone (its session goes on)
func awsPeerLoop(dev *device.Device, peersURL string) {
	have := map[string]string{} // hex public key → endpoint
	client := &http.Client{Timeout: 10 * time.Second}
	for ; ; time.Sleep(10 * time.Second) {
		resp, err := client.Get(peersURL)
		if err != nil {
			log.Printf("wg-aws: peers: %v", err)
			continue
		}
		var out struct {
			Peers []AWSPeer `json:"peers"`
		}
		err = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			log.Printf("wg-aws: peers: HTTP %d %v", resp.StatusCode, err)
			continue
		}
		want := map[string]AWSPeer{}
		for _, p := range out.Peers {
			if k, err := b64hex(p.PublicKey); err == nil {
				want[k] = p
			}
		}
		ipc := ""
		for k, p := range want {
			if have[k] == p.Endpoint {
				continue
			}
			ipc += fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\nendpoint=%s\npersistent_keepalive_interval=25\n", k, p.Address, p.Endpoint)
		}
		for k := range have {
			if _, ok := want[k]; !ok {
				ipc += "public_key=" + k + "\nremove=true\n"
			}
		}
		if ipc == "" {
			continue
		}
		if err := dev.IpcSet(ipc); err != nil {
			log.Printf("wg-aws: set peers: %v", err)
			continue
		}
		clear(have)
		for k, p := range want {
			have[k] = p.Endpoint
		}
		log.Printf("wg-aws: %d AWS machines", len(want))
	}
}
