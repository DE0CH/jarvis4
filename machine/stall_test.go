package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// the supervisor's stall watch: idle with background jobs and no turn for 15 min → a nudge, again every 15 min; a new
// turn, no jobs, or a running turn on the pane resets it; a busy host with no pane keeps the clock as it is
func TestStallStep(t *testing.T) {
	t0 := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	idle := hostStatus{ok: true, status: "idle", statusAt: 1, jobs: 2}
	var c stallClock
	if n, _ := stallStep(&c, idle, "", false, at(0)); n {
		t.Fatal("nudged at once")
	}
	if n, _ := stallStep(&c, idle, "", false, at(14)); n {
		t.Fatal("nudged before 15 min")
	}
	if n, m := stallStep(&c, idle, "", false, at(15)); !n || m != 15 {
		t.Fatalf("no nudge at 15 min: %v %d", n, m)
	}
	if n, _ := stallStep(&c, idle, "", false, at(20)); n {
		t.Fatal("nudged again within 15 min")
	}
	if n, m := stallStep(&c, idle, "", false, at(30)); !n || m != 15 {
		t.Fatalf("not repeated after 15 more min: %v %d", n, m)
	}
	// a new turn starts the clock again
	turn := idle
	turn.statusAt = 2
	stallStep(&c, turn, "", false, at(31))
	if n, _ := stallStep(&c, turn, "", false, at(45)); n {
		t.Fatal("the new turn's clock didn't restart")
	}
	// no jobs: nothing
	var c2 stallClock
	for m := 0; m <= 30; m += 5 {
		if n, _ := stallStep(&c2, hostStatus{ok: true, status: "idle", statusAt: 1}, "", false, at(m)); n {
			t.Fatal("nudged with no background jobs")
		}
	}
	// busy with jobs: a pane without a spinner counts as waiting on the jobs; with one, a turn runs
	busy := hostStatus{ok: true, status: "busy", statusAt: 3, jobs: 1}
	var c3 stallClock
	stallStep(&c3, busy, "❯ ", true, at(0))
	if n, _ := stallStep(&c3, busy, "❯ ", true, at(15)); !n {
		t.Fatal("a busy host waiting on its jobs wasn't nudged")
	}
	spin := "\x1b[33m✻\x1b[0m Thinking… (12s · esc to interrupt)\n"
	if n, _ := stallStep(&c3, busy, spin, true, at(40)); n || !c3.since.IsZero() {
		t.Fatal("a running turn didn't reset the clock")
	}
	// busy with no pane: the clock stays as it is (neither starts nor resets)
	var c4 stallClock
	if n, _ := stallStep(&c4, busy, "", false, at(0)); n || !c4.since.IsZero() {
		t.Fatal("a busy host with no pane started the clock")
	}
	if !strings.HasPrefix(stallText(1, 15), "Jarvis watchdog: this session has been idle for 15 min while 1 background job has") {
		t.Fatal(stallText(1, 15))
	}
}

// readHost: the Remote Control host's entry, its jobs the larger of the shells and the hook-fed count
func TestReadHost(t *testing.T) {
	d := t.TempDir()
	old, oldShell := claudeSessions, shellJobs
	claudeSessions, shellJobs = d, func(int64) int { return 1 }
	t.Cleanup(func() { claudeSessions, shellJobs = old, oldShell })
	write := func(name, body string) {
		if err := os.WriteFile(d+"/"+name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.json", `{"pid":10,"sessionId":"c1","status":"busy","statusUpdatedAt":5,"startedAt":1}`)
	write("b.json", `{"pid":11,"sessionId":"c2","status":"idle","statusUpdatedAt":7,"startedAt":2,"bridgeSessionId":"session_x"}`)
	if h := readHost(); !h.ok || h.status != "idle" || h.statusAt != 7 || h.jobs != 1 {
		t.Fatalf("%+v", h)
	}
	tasks := []hookTask{{ID: "j1", Type: "shell"}, {ID: "j2", Type: "monitor"}}
	workers.apply(workerEvent{Event: "Stop", SessionID: "c2", Tasks: &tasks}, time.Now())
	if h := readHost(); h.jobs != 2 {
		t.Fatalf("the hook-fed count wasn't used: %+v", h)
	}
}

// TestLiveSentAcrossProcesses: supervisor-normal's live sync keeps what it sent in a file, so supervisor-core's
// teardown sends only what changed since
func TestLiveSentAcrossProcesses(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "a.jsonl")
	os.WriteFile(f, []byte("{}\n"), 0o644)
	state := filepath.Join(d, "live-sent.json")
	var sent []string
	send := func(name string, body []byte) error { sent = append(sent, name); return nil }
	normal := &liveSyncer{sent: map[string]time.Time{}, send: send, state: state}
	if n := normal.pass([]string{f}); n != 1 {
		t.Fatalf("normal sent %d", n)
	}
	core := &liveSyncer{sent: map[string]time.Time{}, send: send, state: state}
	b, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(b, &core.sent)
	if n := core.pass([]string{f}); n != 0 {
		t.Fatalf("the teardown sent %d unchanged transcripts again", n)
	}
	later := time.Now().Add(time.Minute)
	os.Chtimes(f, later, later)
	if n := core.pass([]string{f}); n != 1 {
		t.Fatalf("the teardown sent %d changed transcripts, want 1", n)
	}
}
