package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
)

// lineCore: a core that names a line seq in every answer and serves its line state (core/continuity.go)
type lineCore struct {
	mu     sync.Mutex
	key    key
	seq    int
	master string
}

func (c *lineCore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seq > 0 {
		w.Header().Set(lineSeqHeader, strconv.Itoa(c.seq))
	}
	switch req.URL.Path {
	case "/identity":
		writeJSON(w, 200, map[string]any{"signingKey": c.key.pub(), "state": c.key.doc(map[string]any{"kind": "core-state", "master": c.master})})
	case "/line-state":
		writeJSON(w, 200, map[string]any{"head": c.key.doc(map[string]any{"kind": "line-state-head", "seq": c.seq, "sha256": "x"}), "sealed": "c2VhbGVk"})
	default:
		writeJSON(w, 200, c.key.doc(map[string]string{"kind": "ok"}))
	}
}

func TestTheRouterKeepsTheNewestLineStateBeforeTheAnswerGoesOn(t *testing.T) {
	t.Setenv("BACKUP_READ_ACCESS_KEY", "")
	lc := &lineCore{key: newTestKey(), seq: 3, master: "m"}
	srv := httptest.NewServer(lc)
	defer srv.Close()
	cc := &CoreClient{base: srv.URL, http: http.DefaultClient}
	path, err := testState(t, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	k := newLineKeeper(path, cc)
	cc.onLineSeq = k.seen
	if _, _, err := cc.Raw("POST", "/certify", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if x := k.current(); x == nil || x.Seq != 3 || x.Core != lc.key.pub() {
		t.Fatalf("kept %+v", x)
	}
	lc.mu.Lock()
	lc.seq = 7
	lc.mu.Unlock()
	cc.Raw("POST", "/kill", []byte("{}"))
	if x := k.current(); x.Seq != 7 {
		t.Fatalf("kept %d", x.Seq)
	}
	// a router that starts again reads it from its database
	k2 := newLineKeeper(path, cc)
	if x := k2.current(); x == nil || x.Seq != 7 {
		t.Fatalf("after a restart: %+v", x)
	}
	// a head the running core didn't sign isn't kept
	other := newTestKey()
	bad := &lineCore{key: other, seq: 9, master: "m"}
	bsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/identity" {
			lc.ServeHTTP(w, req) // the identity says lc's key
			return
		}
		bad.ServeHTTP(w, req)
	}))
	defer bsrv.Close()
	bc := &CoreClient{base: bsrv.URL, http: http.DefaultClient}
	k3 := newLineKeeper(path, bc)
	bc.onLineSeq = k3.seen
	bc.Raw("POST", "/x", nil)
	if x := k3.current(); x.Seq != 7 {
		t.Fatalf("kept a head another key signed: %d", x.Seq)
	}
	b, _ := json.Marshal(k3.current().Doc)
	if len(b) == 0 {
		t.Fatal("no doc")
	}
}

func TestARecoveredCoreWithTheSameKeyKeepsItsSessions(t *testing.T) {
	t.Setenv("RECORDS_OFF", "1")
	r := newTestRouter(t)
	k := newTestKey()
	lc := &lineCore{key: k, master: "m"}
	srv := httptest.NewServer(lc)
	t.Cleanup(srv.Close)
	r.core = &CoreClient{base: srv.URL, http: http.DefaultClient}
	cert := k.doc(map[string]any{"kind": "succession-cert", "line": "L1"})
	r.st.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", State: "paused", Harness: "claude", Cert: cert}
		d.Sessions["s2"] = &Session{ID: "s2", State: "started", MachineID: "m2", Harness: "claude", Cert: cert}
	})
	r.coreChangeTick()
	// the restart: an empty core (its boot key) decides nothing
	lc.mu.Lock()
	lc.key, lc.master = newTestKey(), ""
	lc.mu.Unlock()
	r.coreChangeTick()
	// the Recover with the same kit: the same key again
	lc.mu.Lock()
	lc.key, lc.master = k, "m"
	lc.mu.Unlock()
	r.coreChangeTick()
	r.st.Do(func(d *persisted) {
		for _, id := range []string{"s1", "s2"} {
			if d.Sessions[id] == nil || d.Sessions[id].OldCore {
				t.Fatalf("%s was taken for an earlier core's", id)
			}
		}
	})
	// a Reset (another key): the sessions are the earlier core's
	lc.mu.Lock()
	lc.key = newTestKey()
	lc.mu.Unlock()
	r.coreChangeTick()
	r.st.Do(func(d *persisted) {
		if s := d.Sessions["s2"]; s == nil || !s.OldCore {
			t.Fatal("after a Reset the sessions aren't marked as the earlier core's")
		}
	})
}
