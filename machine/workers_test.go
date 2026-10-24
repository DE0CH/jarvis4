package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// the event order Claude Code 2.1.300 sent for: a background Bash, a background subagent, a foreground subagent
// (recorded with a logging hook, 2026-10-15)
func TestWorkersHookSequence(t *testing.T) {
	state := filepath.Join(t.TempDir(), "workers.json")
	w := newWorkerCount(state)
	now := time.Now()
	ev := func(s string) {
		if e, ok := workerEventOf([]byte(s)); ok {
			w.apply(e, now)
		}
	}
	want := func(step string, sub int, jobs map[string]int) {
		t.Helper()
		f := w.get("s1")
		if f == nil {
			t.Fatalf("%s: no count", step)
		}
		if f.Subagents != sub || len(f.Jobs) != len(jobs) {
			t.Fatalf("%s: %d subagents, jobs %v; want %d, %v", step, f.Subagents, f.Jobs, sub, jobs)
		}
		for k, n := range jobs {
			if f.Jobs[k] != n {
				t.Fatalf("%s: jobs %v, want %v", step, f.Jobs, jobs)
			}
		}
	}
	ev(`{"session_id":"s1","hook_event_name":"SessionStart","source":"startup"}`)
	want("start", 0, nil)
	ev(`{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"abg","agent_type":"general-purpose"}`)
	want("bg agent started", 1, nil)
	ev(`{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Agent","tool_response":{"isAsync":true,"status":"async_launched","agentId":"abg"}}`)
	ev(`{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"","backgroundTaskId":"b1"}}`)
	want("bash", 1, map[string]int{"shell": 1})
	ev(`{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"x"}}`) // foreground: nothing
	ev(`{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"afg","agent_type":"Explore"}`)
	ev(`{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"internal","agent_type":""}`) // prompt suggestion
	want("fg agent", 2, map[string]int{"shell": 1})
	// the foreground agent stops: the list names the other two (and never a foreground agent)
	ev(`{"session_id":"s1","hook_event_name":"SubagentStop","agent_id":"afg","agent_type":"Explore","background_tasks":[{"id":"abg","type":"subagent","status":"running"},{"id":"b1","type":"shell","status":"running"}]}`)
	want("fg stopped", 1, map[string]int{"shell": 1})
	ev(`{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"afg2","agent_type":"Explore"}`)
	// the background agent stops after the shell ended: its own entry is still listed as running
	ev(`{"session_id":"s1","hook_event_name":"SubagentStop","agent_id":"abg","agent_type":"general-purpose","background_tasks":[{"id":"abg","type":"subagent","status":"running"},{"id":"m1","type":"monitor","status":"running"}]}`)
	want("bg stopped", 1, map[string]int{"monitor": 1}) // afg2 (foreground) stays
	ev(`{"session_id":"s1","hook_event_name":"Stop","background_tasks":[{"id":"w1","type":"workflow","status":"running"},{"id":"x","type":"shell","status":"completed"}]}`)
	want("turn end", 0, map[string]int{"workflow": 1})
	ev(`{"session_id":"s1","hook_event_name":"Stop"}`) // no registry: unchanged
	want("no list", 0, map[string]int{"workflow": 1})
	ev(`{"session_id":"s1","hook_event_name":"SessionStart","source":"compact"}`)
	want("compact", 0, map[string]int{"workflow": 1})
	ev(`{"session_id":"s1","hook_event_name":"SessionStart","source":"resume"}`)
	want("restart", 0, nil)
	ev(`{"session_id":"../x","hook_event_name":"Stop","background_tasks":[]}`)
	if w.get("../x") != nil {
		t.Fatal("unsafe session id kept")
	}
	ev(`not json`)
	// a restarted supervisor-normal starts from the kept count
	if again := newWorkerCount(state).get("s1"); again == nil || again.Jobs != nil && len(again.Jobs) != 0 {
		t.Fatalf("kept count %+v", again)
	}
	if r := w.report(); !strings.Contains(r, `"workersOf":"s1"`) || strings.Count(r, "\n") != 1 {
		t.Fatalf("report %q", r)
	}
}

// the hook only notifies: its event reaches the supervisor's count over the socket, and with no supervisor
// listening it still exits quietly
func TestWorkersHookNotifiesTheSupervisor(t *testing.T) {
	old := workersSock
	defer func() { workersSock = old }()
	workersSock = filepath.Join(t.TempDir(), "w.sock")
	send := func(s string) {
		r, wr, _ := os.Pipe()
		wr.WriteString(s)
		wr.Close()
		stdin := os.Stdin
		os.Stdin = r
		workersHook()
		os.Stdin = stdin
	}
	send(`{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"a1","agent_type":"Explore"}`) // nobody listens
	w := newWorkerCount("")
	go serveWorkerCount(w)
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(workersSock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	send(`{"session_id":"s1","hook_event_name":"SubagentStart","agent_id":"a1","agent_type":"Explore","prompt":"secret text"}`)
	for i := 0; i < 100 && w.get("s1") == nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if f := w.get("s1"); f == nil || f.Subagents != 1 {
		t.Fatalf("count %+v", f)
	}
	b, _ := json.Marshal(workerEvent{})
	if e, _ := workerEventOf([]byte(`{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"echo hunter2"},"tool_response":{"stdout":"hunter2","backgroundTaskId":"b1"}}`)); strings.Contains(string(mustJSON(e)), "hunter2") || len(b) == 0 {
		t.Fatal("the notification carries a command or its output")
	}
}

func TestInstallWorkerHooks(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".claude", "settings.json")
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte(`{"remoteControlAtStartup":true,"hooks":{"Stop":[{"hooks":[{"type":"command","command":"mine"}]}]}}`), 0o644)
	for i := 0; i < 2; i++ { // idempotent
		if err := installWorkerHooks(home); err != nil {
			t.Fatal(err)
		}
	}
	var s struct {
		RC    bool                        `json:"remoteControlAtStartup"`
		Hooks map[string][]map[string]any `json:"hooks"`
	}
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if !s.RC || len(s.Hooks["Stop"]) != 2 || len(s.Hooks["SubagentStart"]) != 1 || s.Hooks["PostToolUse"][0]["matcher"] != "Bash|Monitor|Agent" {
		t.Fatalf("settings %s", b)
	}
	os.WriteFile(p, []byte(`{broken`), 0o644)
	if installWorkerHooks(home) == nil {
		t.Fatal("overwrote an unreadable settings file")
	}
}
