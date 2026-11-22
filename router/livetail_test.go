package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTranscriptWithTools(t *testing.T) {
	text := line(map[string]any{"type": "user", "timestamp": "2026-11-20T10:00:00Z", "message": map[string]any{"content": "find the bug"}}) +
		line(map[string]any{"type": "assistant", "timestamp": "2026-11-20T10:00:01Z", "message": map[string]any{"content": []map[string]any{
			{"type": "text", "text": "Looking."},
			{"type": "tool_use", "name": "Bash", "input": map[string]string{"command": "grep -rn bug ."}}}}}) +
		line(map[string]any{"type": "user", "timestamp": "2026-11-20T10:00:02Z", "message": map[string]any{"content": []map[string]any{
			{"type": "tool_result", "content": "a.go:3: bug " + strings.Repeat("x", 900)}}}}) +
		line(map[string]any{"type": "user", "timestamp": "2026-11-20T10:00:03Z", "message": map[string]any{"content": []map[string]any{
			{"type": "tool_result", "is_error": true, "content": []map[string]string{{"type": "text", "text": "exit 1"}}}}}})
	said := parseTranscript(text, false, 40, 4000)
	if len(said.Messages) != 2 || said.Messages[1].Text != "Looking." {
		t.Fatalf("said only: %+v", said.Messages)
	}
	all := parseTranscriptWith(text, false, 40, 4000, true)
	var roles []string
	for _, m := range all.Messages {
		roles = append(roles, m.Role)
	}
	if strings.Join(roles, ",") != "user,assistant,tool,result,result" {
		t.Fatalf("roles %v", roles)
	}
	if all.Messages[2].Text != `Bash {"command":"grep -rn bug ."}` {
		t.Fatalf("tool call %q", all.Messages[2].Text)
	}
	if r := []rune(all.Messages[3].Text); len(r) != toolClip+2 || !strings.HasSuffix(all.Messages[3].Text, " …") {
		t.Fatalf("result not clipped: %d", len(r))
	}
	if all.Messages[4].Text != "error: exit 1" {
		t.Fatalf("error result %q", all.Messages[4].Text)
	}
}

func TestLiveTail(t *testing.T) {
	rg := newRig(t)
	r := rg.r
	h := r.MachineHandler()
	t.Cleanup(func() { liveDirs.Delete("s2"); liveTailWait = 45 * time.Second }) // the next test's box has no .live/s2
	addSession(r, "s2", "started", "m2", false)
	m := newTestMachine(r, "m2")
	reader := newTestMachine(r, "m3")
	addSession(r, "s3", "started", "m3", false)
	put := func(name, body string) {
		t.Helper()
		req := httptest.NewRequest("POST", "/m/live-transcript", strings.NewReader(body))
		req.Header.Set("X-Name", name)
		if code, out := m.doReq(t, h, req, body); code != 200 {
			t.Fatalf("%d %v", code, out)
		}
	}
	old := line(map[string]any{"type": "user", "timestamp": "2026-11-20T09:00:00Z", "message": map[string]any{"content": "an older conversation"}})
	put("aaaa.jsonl", old)
	put("agent-zzzz.jsonl", line(map[string]any{"type": "user", "timestamp": "2026-11-20T23:00:00Z", "isSidechain": true, "message": map[string]any{"content": "a subagent"}}))

	// the machine answers the round: the newer conversation arrives, then live-synced
	liveTailWait = 5 * time.Second
	go func() {
		if c, ok := waitCmd(r, "m2", 5*time.Second); !ok || c != "live-sync" {
			t.Errorf("command %q %v", c, ok)
			return
		}
		put("bbbb.jsonl", line(map[string]any{"type": "user", "timestamp": "2026-11-20T10:00:00Z", "message": map[string]any{"content": "now"}})+
			line(map[string]any{"type": "assistant", "timestamp": "2026-11-20T10:00:01Z", "message": map[string]any{"content": []map[string]any{
				{"type": "tool_use", "name": "Bash", "input": map[string]string{"command": "ls"}}}}}))
		if code, out := m.do(t, h, "POST", "/m/live-synced", "{}"); code != 200 {
			t.Errorf("live-synced %d %v", code, out)
		}
	}()
	code, out := reader.do(t, h, "GET", "/m/api/tail/s2", "")
	if code != 200 || out["file"] != "bbbb.jsonl" || out["stale"] != nil || out["lastAt"] != "2026-11-20T10:00:01Z" {
		t.Fatalf("%d %v", code, out)
	}
	msgs := out["messages"].([]any)
	if len(msgs) != 2 || msgs[1].(map[string]any)["role"] != "tool" {
		t.Fatalf("messages %v", msgs)
	}
	// by its title too, said only
	code, out = reader.do(t, h, "GET", "/m/api/tail/label%20s2?said=1", "")
	if code != 200 || len(out["messages"].([]any)) != 1 {
		t.Fatalf("said only, by title: %d %v", code, out)
	}

	// a machine that never answers (an older image): its last copy, stale
	liveTailWait = 300 * time.Millisecond
	tl, code, err := r.LiveTailOf("s2", true, 0)
	if err != nil || !tl.Stale || !strings.Contains(tl.Why, "did not answer") || tl.File != "bbbb.jsonl" {
		t.Fatalf("%d %v %+v", code, err, tl)
	}

	// a paused session isn't asked
	r.st.Do(func(d *persisted) { d.Sessions["s2"].State, d.Sessions["s2"].MachineID = "paused", "" })
	for {
		if _, ok := takeCmd(r, "m2"); !ok {
			break
		}
	}
	tl, _, err = r.LiveTailOf("s2", true, 0)
	if err != nil || !tl.Stale || !strings.Contains(tl.Why, "it is paused") {
		t.Fatalf("%v %+v", err, tl)
	}
	if c, ok := takeCmd(r, "m2"); ok {
		t.Fatalf("a paused session's machine was sent %q", c)
	}

	// no copy yet; no such session
	if _, code, _ := r.LiveTailOf("s3", true, 0); code != 404 {
		t.Fatalf("no copy: %d", code)
	}
	if code, out := reader.do(t, h, "GET", "/m/api/tail/nope", ""); code != 404 || !strings.Contains(out["error"].(string), "transcript search") {
		t.Fatalf("no such session: %d %v", code, out)
	}
}
