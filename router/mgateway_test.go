package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// the gateway passes a machine's signed request on as it is (its headers, its streamed body) and the router's answer
// back; a router out of reach is a 502 the machine retries
func TestMGatewayPassesRequestsOn(t *testing.T) {
	var got struct{ path, sig, body string }
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		got.path, got.sig, got.body = req.URL.Path+"?"+req.URL.RawQuery, req.Header.Get("X-Sig"), string(b)
		w.Header().Set("X-Snapshot-Sig", "s")
		w.Write([]byte("answer"))
	}))
	defer router.Close()
	to, _ := url.Parse(router.URL)
	gw := httptest.NewServer(mGatewayProxy(to))
	defer gw.Close()
	req, _ := http.NewRequest("POST", gw.URL+"/m/snapshot-stream?x=1", strings.NewReader(strings.Repeat("b", 1<<20)))
	req.Header.Set("X-Sig", "machine-sig")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "answer" || resp.Header.Get("X-Snapshot-Sig") != "s" || got.path != "/m/snapshot-stream?x=1" || got.sig != "machine-sig" || len(got.body) != 1<<20 {
		t.Fatalf("%q %+v", b, got.path)
	}
	router.Close()
	resp, err = http.Get(gw.URL + "/m/commands")
	if err != nil || resp.StatusCode != 502 {
		t.Fatalf("router gone: %v %v", err, resp)
	}
}
