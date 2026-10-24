package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// the read-only terminal: the machine pushes its pane, and the terminal shows it with no grant and no exec
func TestPushedScreenNeedsNoGrant(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	if code, out := m.do(t, r.MachineHandler(), "POST", "/m/screen", jsonString(map[string]string{"screen": "\x1b[1mhello\x1b[0m", "cursor": "0,1,80,24,1"})); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	code, v := appDo(t, r, "GET", "/api/sessions/sA/terminal", "")
	if code != 200 || !strings.Contains(v["screen"].(string), "hello") || v["cursor"] != "0,1,80,24,1" || v["at"] == "" {
		t.Fatalf("%d %v", code, v)
	}
	// typing still needs the terminal grant
	if code, _ := appDo(t, r, "POST", "/api/sessions/sA/terminal", `{"text":"x"}`); code == 200 {
		t.Fatal("typing went through without a grant")
	}
	// a stale push (no heartbeat) isn't fresh for the autopilot, but the terminal still shows it, with its time and
	// without running anything in the machine; another machine's push doesn't land on this session
	r.st.sdb.db.pool.Exec(context.Background(), "UPDATE session_screens SET at = now() - interval '46 seconds' WHERE session_id = 'sA'")
	if _, ok := r.pushedScreen("sA"); ok {
		t.Fatal("a stale screen was used")
	}
	if code, v := appDo(t, r, "GET", "/api/sessions/sA/terminal", ""); code != 200 || !strings.Contains(v["screen"].(string), "hello") || v["at"] == "" {
		t.Fatalf("the terminal didn't show the last screen: %d %v", code, v)
	}
	// no screen at all: an error, no exec
	addSession(r, "sC", "started", "mC", false)
	if code, v := appDo(t, r, "GET", "/api/sessions/sC/terminal", ""); code == 200 || !strings.Contains(fmt.Sprint(v["error"]), "no screen") {
		t.Fatalf("%d %v", code, v)
	}
	// any replica sees it: another router on the same database
	r2 := newTestRouterOn(t, r)
	r.st.PutScreen("sA", "mA", TermSnap{Screen: "fresh"})
	if s, ok := r2.pushedScreen("sA"); !ok || s.Screen != "fresh" {
		t.Fatalf("the other replica doesn't see the push: %v %v", s, ok)
	}
	addSession(r, "sB", "started", "mB", false)
	other := newTestMachine(r, "mB")
	other.do(t, r.MachineHandler(), "POST", "/m/screen", jsonString(map[string]string{"screen": "other", "cursor": "0,0,80,24,1"}))
	if s, ok := r.pushedScreen("sA"); ok && strings.Contains(s.Screen, "other") {
		t.Fatal("another machine's screen")
	}
	// a paused session drops it
	r.st.Do(func(d *persisted) { d.Sessions["sB"].State, d.Sessions["sB"].MachineID = "paused", "" })
	if _, ok := r.pushedScreen("sB"); ok {
		t.Fatal("a paused session's screen")
	}
}

// newTestRouterOn: a second router replica on the same database as r
func newTestRouterOn(t *testing.T, r *Router) *Router {
	t.Helper()
	st, err := OpenState(context.Background(), r.st.sdb.db, t.TempDir(), randomSealer())
	if err != nil {
		t.Fatal(err)
	}
	return NewRouter(Config{NoAccess: true, DataDir: st.dir, WebDir: t.TempDir()}, st, nil, Policy{})
}
