package main

// The machine's way to the router: JARVIS2_URL names one address, or the gateways comma-separated
// (http://jarvis4-box._peer.internal:8081,http://jarvis4-gw-b._peer.internal:8081: each a WireGuard peer of the Fly org
// running `router m-gateway`, which passes every request on to the router). Every request goes to the first URL's host;
// the dial behind it tries the gateways in turn, starting with the last one that answered, so a gateway that is being
// replaced (its peer gone, or refusing new connections while it finishes what it carries) costs one failed dial, not
// a failed request. A connection already open stays where it is until it closes.

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// routerDialTimeout: how long one gateway gets to answer a dial before the next is tried (a var: tests)
var routerDialTimeout = 5 * time.Second

func routerURLsOK(v string) bool {
	if v == "" {
		return false
	}
	for _, u := range strings.Split(v, ",") {
		if !routerRE.MatchString(strings.TrimSpace(u)) {
			return false
		}
	}
	return true
}

type routerDialer struct {
	mu    sync.Mutex
	front string   // host:port every request names (the first URL's)
	hosts []string // every gateway's host:port, in order
	cur   int      // the one that answered last
}

// routerTransport: the base URL requests are made to, and the dialer behind them
func routerTransport(v string) (string, *routerDialer) {
	d := &routerDialer{}
	base := ""
	for i, raw := range strings.Split(v, ",") {
		raw = strings.TrimSuffix(strings.TrimSpace(raw), "/")
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		host := u.Host
		if u.Port() == "" {
			host = net.JoinHostPort(u.Hostname(), "80")
		}
		if i == 0 || base == "" {
			base, d.front = raw, host
		}
		d.hosts = append(d.hosts, host)
	}
	return base, d
}

func (d *routerDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr != d.front || len(d.hosts) < 2 {
		return (&net.Dialer{Timeout: routerDialTimeout}).DialContext(ctx, network, addr)
	}
	d.mu.Lock()
	start := d.cur
	d.mu.Unlock()
	var last error
	for i := 0; i < len(d.hosts); i++ {
		n := (start + i) % len(d.hosts)
		c, err := (&net.Dialer{Timeout: routerDialTimeout}).DialContext(ctx, network, d.hosts[n])
		if err == nil {
			d.mu.Lock()
			d.cur = n
			d.mu.Unlock()
			return c, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

func (d *routerDialer) plain() *http.Transport {
	return &http.Transport{DialContext: d.DialContext, MaxIdleConnsPerHost: 8, IdleConnTimeout: 90 * time.Second}
}

// streaming: for the multi-GB transfers (snapshots, an import's tarballs): no overall time limit
func (d *routerDialer) streaming() *http.Transport {
	t := d.plain()
	t.ResponseHeaderTimeout = 5 * time.Minute
	return t
}
