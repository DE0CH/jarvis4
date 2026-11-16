package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// a machine that refuses to start tells the router why (2026-11-16: "REFUSING TO START: snapshot: write …: no space
// left on device" stayed in the machine's log and its session showed "initialising" for good): the reason, signed as
// every machine request; told again when the router didn't take it; an older router (404) is asked once
func TestARefusedStartIsToldToTheRouter(t *testing.T) {
	bootReportWait = time.Millisecond
	defer func() { bootReportWait = 2 * time.Second }()
	key := newKey()
	var mu sync.Mutex
	var got []string
	calls, down, status := 0, 0, 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		b, _ := io.ReadAll(req.Body)
		sum := sha256.Sum256(b)
		if req.Method != "POST" || req.URL.Path != "/m/boot-failed" || req.Header.Get("X-Machine") != "m1" ||
			!verify(key.pub(), []byte("POST /m/boot-failed "+req.Header.Get("X-Time")+" "+hex.EncodeToString(sum[:])), req.Header.Get("X-Sig")) {
			w.WriteHeader(401)
			return
		}
		if down > 0 {
			down--
			w.WriteHeader(503)
			return
		}
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		var in map[string]string
		json.Unmarshal(b, &in)
		got = append(got, in["error"])
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := &client{base: srv.URL, me: "m1", sig: key.k, http: srv.Client()}
	why := errors.New("snapshot: write /data/x: no space left on device")
	// report: one refused start told to a router that fails the first `failing` tries → what it took, in how many calls
	report := func(failing, answer int) ([]string, int) {
		mu.Lock()
		got, calls, down, status = nil, 0, failing, answer
		mu.Unlock()
		reportBootFailed(c, why)
		mu.Lock()
		defer mu.Unlock()
		return got, calls
	}
	if got, calls := report(0, 200); len(got) != 1 || got[0] != why.Error() || calls != 1 {
		t.Fatalf("the router got %q in %d calls", got, calls)
	}
	// a router that doesn't take it at first is told again
	if got, calls := report(2, 200); len(got) != 1 || calls != 3 {
		t.Fatalf("after two failed tries: %q in %d calls", got, calls)
	}
	// it gives up after bootReportTries; an older router is asked once
	if got, calls := report(10, 200); len(got) != 0 || calls != bootReportTries {
		t.Fatalf("a router that stays down: %q in %d calls", got, calls)
	}
	if _, calls := report(0, 404); calls != 1 {
		t.Fatalf("an older router was asked %d times", calls)
	}
}
