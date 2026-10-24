package main

// The worker count: a component of the supervisor (supervisor.go), like the guard. It knows how many subagents and
// background jobs the session's Claude Code harness has running now, for the session's card (router/registry.go
// Workers, docs/DECISIONS.md "Workers"); the status report carries it.
//
// Claude Code documents no live list of its tasks, so the count comes from its documented hooks
// (code.claude.com/docs/en/hooks): boot installs `jarvis-machine workers-hook` in ~/.claude/settings.json for
// SessionStart, SubagentStart, SubagentStop, Stop and PostToolUse (Bash|Monitor|Agent). The hook only NOTIFIES the
// supervisor: it boils the event down to ids, types and the event name (never a command, a description or a tool's
// output) and sends that over the supervisor's local socket (workersSock); it never fails a turn (any error, or no
// supervisor listening, exits 0 silently). A hook message only updates a count and carries no command, so the guard
// doesn't check it. The supervisor holds the count per conversation, in memory and in workersState (tmpfs, kept across
// a worker restart, new on every machine):
//   - Stop and SubagentStop carry `background_tasks`, the harness's own list of what is in flight (types
//     shell, subagent, monitor, workflow, teammate, …): each one replaces the conversation's list. A SubagentStop's
//     list still names the agent that is stopping, so that one is left out.
//   - between two of those, SubagentStart adds the agent (a foreground subagent never appears in the list, so
//     it stays until its own SubagentStop or the turn's Stop), and a PostToolUse whose result has a
//     backgroundTaskId (a background Bash, a Monitor) adds that job until the next list.
//   - SessionStart (startup, resume) empties it: a restarted host has nothing running.

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

const workersHookCmd = "/usr/local/bin/jarvis-machine workers-hook"

var (
	workersSock  = dir + "/workers.sock"
	workersState = dir + "/workers.json"
)

// workerHookEvents: the hook events the count needs (with PostToolUse's matcher)
var workerHookEvents = []struct{ event, matcher string }{
	{"SessionStart", ""}, {"SubagentStart", ""}, {"SubagentStop", ""}, {"Stop", ""}, {"PostToolUse", "Bash|Monitor|Agent"},
}

// workerFile: one conversation's count; Subagents and Jobs are what the router reads
type workerFile struct {
	SessionID string            `json:"workersOf"`
	At        int64             `json:"at"` // ms, the last change
	Subagents int               `json:"subagents"`
	Jobs      map[string]int    `json:"jobs"`   // every other in-flight task by the harness's type label
	Listed    map[string]string `json:"listed"` // id → type, from the last background_tasks
	Added     map[string]string `json:"added"`  // id → type, seen since it ("subagent-fg" until known as background)
}

type hookTask struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

// hookInput: what Claude Code gives the hook on stdin (the parts the count reads)
type hookInput struct {
	SessionID string          `json:"session_id"`
	Event     string          `json:"hook_event_name"`
	Source    string          `json:"source"`
	AgentID   string          `json:"agent_id"`
	AgentType string          `json:"agent_type"`
	ToolName  string          `json:"tool_name"`
	Tasks     *[]hookTask     `json:"background_tasks"`
	Response  json.RawMessage `json:"tool_response"`
}

// workerEvent: the notification the hook sends the supervisor (ids, types and names only)
type workerEvent struct {
	SessionID string      `json:"session"`
	Event     string      `json:"event"`
	Source    string      `json:"source,omitempty"`
	AgentID   string      `json:"agentId,omitempty"`
	AgentType string      `json:"agentType,omitempty"`
	ToolName  string      `json:"tool,omitempty"`
	Tasks     *[]hookTask `json:"tasks,omitempty"`
	IsAsync   bool        `json:"isAsync,omitempty"`  // PostToolUse: the tool result's isAsync
	RAgentID  string      `json:"rAgentId,omitempty"` // PostToolUse: the tool result's agentId
	TaskID    string      `json:"taskId,omitempty"`   // PostToolUse: the tool result's backgroundTaskId
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

// workerEventOf: the hook's stdin boiled down to the notification (ok=false: nothing to tell)
func workerEventOf(raw []byte) (workerEvent, bool) {
	var in hookInput
	if json.Unmarshal(raw, &in) != nil || !safeID.MatchString(in.SessionID) {
		return workerEvent{}, false
	}
	ev := workerEvent{SessionID: in.SessionID, Event: in.Event, Source: in.Source, AgentID: in.AgentID, AgentType: in.AgentType, ToolName: in.ToolName, Tasks: in.Tasks}
	if in.Tasks != nil {
		ts := make([]hookTask, 0, len(*in.Tasks))
		for _, t := range *in.Tasks {
			ts = append(ts, hookTask{ID: t.ID, Type: t.Type, Status: t.Status})
		}
		ev.Tasks = &ts
	}
	if in.Event == "PostToolUse" {
		var r struct {
			IsAsync bool   `json:"isAsync"`
			AgentID string `json:"agentId"`
			TaskID  string `json:"backgroundTaskId"`
		}
		if json.Unmarshal(in.Response, &r) != nil {
			return workerEvent{}, false
		}
		ev.IsAsync, ev.RAgentID, ev.TaskID = r.IsAsync, r.AgentID, r.TaskID
	}
	return ev, true
}

// workersHook: the hook command (stdin = the event's JSON): the notification to the supervisor. Always exits 0 with
// no output.
func workersHook() {
	defer func() { recover() }()
	b, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	if err != nil {
		return
	}
	ev, ok := workerEventOf(b)
	if !ok {
		return
	}
	conn, err := net.DialTimeout("unix", workersSock, time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	json.NewEncoder(conn).Encode(ev)
	io.Copy(io.Discard, io.LimitReader(conn, 16)) // the supervisor closes once it has applied it
}

// workerCount: the supervisor's count, per conversation
type workerCount struct {
	mu    sync.Mutex
	files map[string]*workerFile
	path  string // where it is kept across a worker restart ("" = memory only)
}

func newWorkerCount(path string) *workerCount {
	w := &workerCount{files: map[string]*workerFile{}, path: path}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			json.Unmarshal(b, &w.files)
		}
	}
	return w
}

// workers: the supervisor's worker count (supervise starts it)
var workers = newWorkerCount("")

// serveWorkerCount: the socket the hook notifies (the supervisor's component; started by supervise)
func serveWorkerCount(w *workerCount) {
	os.Remove(workersSock)
	ln, err := net.Listen("unix", workersSock)
	if err != nil {
		log.Printf("worker count: %v", err)
		return
	}
	os.Chmod(workersSock, 0o600)
	for {
		conn, err := ln.Accept()
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			var ev workerEvent
			if json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&ev) == nil {
				w.apply(ev, time.Now())
			}
		}()
	}
}

// apply: one notification
func (w *workerCount) apply(in workerEvent, now time.Time) {
	if !safeID.MatchString(in.SessionID) {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	f := w.files[in.SessionID]
	if f == nil {
		f = &workerFile{}
	}
	if f.Listed == nil {
		f.Listed = map[string]string{}
	}
	if f.Added == nil {
		f.Added = map[string]string{}
	}
	switch in.Event {
	case "SessionStart":
		if in.Source != "startup" && in.Source != "resume" {
			return
		}
		f.Listed, f.Added = map[string]string{}, map[string]string{}
	case "SubagentStart":
		if in.AgentType == "" || !safeID.MatchString(in.AgentID) { // the harness's own internal agents
			return
		}
		if _, ok := f.Listed[in.AgentID]; !ok {
			f.Added[in.AgentID] = "subagent-fg"
		}
	case "PostToolUse":
		switch {
		case in.ToolName == "Agent" && in.IsAsync && f.Added[in.RAgentID] == "subagent-fg":
			f.Added[in.RAgentID] = "subagent" // a background one: the next list says when it ends
		case in.TaskID != "" && safeID.MatchString(in.TaskID):
			if _, ok := f.Listed[in.TaskID]; !ok {
				f.Added[in.TaskID] = map[string]string{"Bash": "shell", "Monitor": "monitor"}[in.ToolName]
				if f.Added[in.TaskID] == "" {
					f.Added[in.TaskID] = "other"
				}
			}
		default:
			return
		}
	case "SubagentStop", "Stop":
		if in.Event == "SubagentStop" {
			delete(f.Added, in.AgentID)
		}
		if in.Tasks == nil { // no registry reachable: keep what we had
			break
		}
		f.Listed = map[string]string{}
		for _, t := range *in.Tasks {
			if t.ID == "" || t.ID == in.AgentID || (t.Status != "" && t.Status != "running" && t.Status != "pending") {
				continue
			}
			f.Listed[t.ID] = t.Type
		}
		for id, ty := range f.Added { // background ones the list no longer names have ended
			if _, ok := f.Listed[id]; ok || ty != "subagent-fg" || in.Event == "Stop" {
				delete(f.Added, id) // and at the turn's end no foreground subagent is left
			}
		}
	default:
		return
	}
	f.SessionID, f.At = in.SessionID, now.UnixMilli()
	f.Subagents, f.Jobs = 0, map[string]int{}
	all := map[string]string{}
	for id, ty := range f.Listed {
		all[id] = ty
	}
	for id, ty := range f.Added {
		all[id] = ty
	}
	for _, ty := range all {
		switch ty {
		case "subagent", "subagent-fg":
			f.Subagents++
		case "":
			f.Jobs["other"]++
		default:
			f.Jobs[ty]++
		}
	}
	w.files[in.SessionID] = f
	if w.path != "" {
		b, _ := json.Marshal(w.files)
		tmp := w.path + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			os.Rename(tmp, w.path)
		}
	}
}

// get: one conversation's count (nil when it has none)
func (w *workerCount) get(sid string) *workerFile {
	w.mu.Lock()
	defer w.mu.Unlock()
	if f := w.files[sid]; f != nil {
		c := *f
		return &c
	}
	return nil
}

// report: the status report's __WORKERS__ section, one JSON object per conversation (router/registry.go)
func (w *workerCount) report() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	ids := make([]string, 0, len(w.files))
	for id := range w.files {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b bytes.Buffer
	for _, id := range ids {
		j, _ := json.Marshal(w.files[id])
		b.Write(j)
		b.WriteByte('\n')
	}
	return b.String()
}

// installWorkerHooks: the hook entries in ~/.claude/settings.json (boot, before the harness starts), replacing
// any earlier copy of ours and keeping everything else in the file
func installWorkerHooks(home string) error {
	p := filepath.Join(home, ".claude", "settings.json")
	s := map[string]any{}
	if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
		if err := json.Unmarshal(b, &s); err != nil {
			return err // never overwrite a file we can't read
		}
	}
	hooks, _ := s["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	for _, e := range workerHookEvents {
		var keep []any
		groups, _ := hooks[e.event].([]any)
		for _, g := range groups {
			if !isWorkersGroup(g) {
				keep = append(keep, g)
			}
		}
		g := map[string]any{"hooks": []any{map[string]any{"type": "command", "command": workersHookCmd, "timeout": 10}}}
		if e.matcher != "" {
			g["matcher"] = e.matcher
		}
		hooks[e.event] = append(keep, g)
	}
	s["hooks"] = hooks
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(p), 0o755)
	return os.WriteFile(p, b, 0o600)
}

func isWorkersGroup(g any) bool {
	m, _ := g.(map[string]any)
	hs, _ := m["hooks"].([]any)
	for _, h := range hs {
		if hm, _ := h.(map[string]any); hm != nil && hm["command"] == workersHookCmd {
			return true
		}
	}
	return false
}
