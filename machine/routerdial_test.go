package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// two gateways: requests name the first; when it doesn't answer a dial, the second takes them, and stays chosen
func TestRouterDialFailsOver(t *testing.T) {
	old := routerDialTimeout
	routerDialTimeout = 300 * time.Millisecond
	t.Cleanup(func() { routerDialTimeout = old })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("router")) }))
	defer srv.Close()
	dead, _ := net.Listen("tcp", "127.0.0.1:0") // a gateway whose port answers nothing: closed at once
	deadAddr := dead.Addr().String()
	dead.Close()
	base, d := routerTransport("http://" + deadAddr + "," + srv.URL)
	if base != "http://"+deadAddr || len(d.hosts) != 2 {
		t.Fatalf("%s %v", base, d.hosts)
	}
	c := &http.Client{Transport: d.plain()}
	for i := 0; i < 2; i++ {
		resp, err := c.Get(base + "/m/commands")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "router" {
			t.Fatal(string(b))
		}
	}
	if d.cur != 1 {
		t.Fatalf("the answering gateway isn't kept: %d", d.cur)
	}
	if !routerURLsOK("http://a._peer.internal:8081,http://b._peer.internal:8081") || routerURLsOK("http://a:1,http://x/$(evil)") || routerURLsOK("") {
		t.Fatal("the URL list check")
	}
	_, one := routerTransport("http://only:8081")
	if len(one.hosts) != 1 || !strings.HasSuffix(one.front, ":8081") {
		t.Fatal(one.hosts)
	}
}
