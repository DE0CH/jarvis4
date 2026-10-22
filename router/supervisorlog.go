package main

// The supervisor's log (Deyao, 2026-10-16): each session machine's supervisor (machine/supervisor.go) pushes its own
// log lines here (POST /m/supervisor-log), from its first second (also while it boots, before its first status
// report). The router keeps them per session in its database (session_log, sessionlog.go), for the session's life;
// the app and web page read them in the session's one event stream with the lifecycle log (sessionevents.go,
// GET /api/sessions/{id}/events). On Destroy both go into the session's Storage Box archive
// (jarvis2/supervisor-log.jsonl), then off the volume.
//
// The lines are the machine's own words: the supervisor writes no secret into them (machine side), and the router
// shows them only to Deyao's login.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

const (
	supLogMaxLines = 500  // per push
	supLogMaxLine  = 2000 // bytes per line (clipped)
	supLogReadMax  = 2000 // lines per read
)

// supLogMaxFile: a session's file is cut to its newer half past this (a var: tests shrink it)
var supLogMaxFile int64 = 20 << 20

type SupLine struct {
	Seq     int64  `json:"seq"`
	At      string `json:"at"`
	Machine string `json:"machine"`
	Text    string `json:"text"`
}

type supLogs struct {
	mu   sync.Mutex
	next map[string]int64 // session → the next seq (read from its file on first use)
}

// safeName: a session id as a file name (ids are [a-z0-9-]; anything else is replaced)
func logFileName(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			b[i] = '_'
		}
	}
	if len(b) == 0 {
		return "_"
	}
	return string(b)
}

// readSupLog: every line of a session's supervisor log, in order
func (r *Router) readSupLog(session string) []SupLine {
	r.sup.mu.Lock()
	defer r.sup.mu.Unlock()
	return r.readSupLogLocked(session)
}

func (r *Router) readSupLogLocked(session string) []SupLine {
	raw, err := r.st.ReadLog(session, logSupervisor)
	if err != nil {
		log.Printf("[supervisor-log] reading %s: %v", session, err)
	}
	var out []SupLine
	for _, b := range raw {
		var l SupLine
		if json.Unmarshal(b, &l) == nil {
			out = append(out, l)
		}
	}
	return out
}

// appendSupLog: lines of one machine onto its session's log, numbered; cut to the newer half past supLogMaxFile
func (r *Router) appendSupLog(session, machine string, lines []SupLine) error {
	r.sup.mu.Lock()
	defer r.sup.mu.Unlock()
	if r.lc.dropped(session) {
		return nil
	}
	next, ok := r.sup.next[session]
	if !ok {
		next = 1
		if all := r.readSupLogLocked(session); len(all) > 0 {
			next = all[len(all)-1].Seq + 1
		}
	}
	rows := make([][]byte, 0, len(lines))
	for _, l := range lines {
		l.Seq, l.Machine = next, machine
		next++
		b, _ := json.Marshal(l)
		rows = append(rows, b)
	}
	if err := r.st.AppendLog(session, logSupervisor, rows...); err != nil {
		return err
	}
	r.sup.next[session] = next
	if r.st.LogBytes(session, logSupervisor) > supLogMaxFile {
		all := r.readSupLogLocked(session)
		keep := all[len(all)/2:]
		note := SupLine{Seq: keep[0].Seq - 1 /* a dropped line's: the seqs stay in order */, At: time.Now().UTC().Format(time.RFC3339Nano), Machine: "",
			Text: fmt.Sprintf("[router] the supervisor log passed %d MB: its %d oldest lines were dropped", supLogMaxFile>>20, len(all)-len(keep))}
		out := [][]byte{}
		for _, l := range append([]SupLine{note}, keep...) {
			b, _ := json.Marshal(l)
			out = append(out, b)
		}
		return r.st.ReplaceLog(session, logSupervisor, out)
	}
	return nil
}

// dropSupLog: the session is gone (a record now, its archive holds the log)
func (r *Router) dropSupLog(session string) {
	r.sup.mu.Lock()
	defer r.sup.mu.Unlock()
	r.st.DropLog(session, logSupervisor)
	delete(r.sup.next, session)
}

func (r *Router) registerSupervisorLog(m machineRoute) {
	m("POST /m/supervisor-log", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct {
			Lines []struct {
				At   string `json:"at"`
				Text string `json:"text"`
			} `json:"lines"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "not JSON: " + err.Error()})
			return
		}
		if len(in.Lines) > supLogMaxLines {
			writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("at most %d lines per push", supLogMaxLines)})
			return
		}
		var session string
		r.st.Do(func(d *persisted) { session = d.Machines[machine] })
		if session == "" {
			writeJSON(w, 404, map[string]string{"error": "this machine belongs to no session"})
			return
		}
		lines := make([]SupLine, 0, len(in.Lines))
		now := time.Now().UTC()
		for _, l := range in.Lines {
			at, err := time.Parse(time.RFC3339Nano, l.At)
			if err != nil || at.After(now.Add(time.Minute)) || at.Before(now.Add(-24*time.Hour)) {
				at = now // a machine clock off by a lot: the router's time
			}
			text := l.Text
			if len(text) > supLogMaxLine {
				text = text[:supLogMaxLine] + "…"
			}
			lines = append(lines, SupLine{At: at.UTC().Format(time.RFC3339Nano), Text: text})
		}
		if err := r.appendSupLog(session, machine, lines); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
}
