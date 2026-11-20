package main

// A session's tail, now (Deyao, 2026-11-20: "in addition to the transcript search that lags current by some time,
// have a function to get the tail of a session in a timely manner"). Transcript search sees a running session through
// its .live copies (livesync.go), up to LIVE_SYNC_SECONDS (5 min) old, then indexed by a crawl every 5 min.
//
// GET /m/api/tail/{session} (`jarvis-tail SESSION`): for a running session the router sends its machine the
// "live-sync" command; the machine sends every transcript that changed since its last copy (POST /m/live-transcript,
// as its own sync does) and then POST /m/live-synced. The router waits for that (up to liveTailWait), then reads the
// end of the session's conversation from its .live copy and parses it as the app's tails are (transcript.go), with
// the tool calls and their results unless ?said=1. The conversation is the copy whose last entry is newest: one rule
// that also picks right for an image that never answers the command. A session that isn't running (paused, frozen)
// or a machine that doesn't answer gets its last copy, marked stale with why.
//
// Any session may read any session's tail, as transcript search already gives every session every transcript, only
// later (Deyao, 2026-11-20). The machine sends only its own transcripts, so no router feature runs anything in it.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	liveTailWait = 45 * time.Second       // a machine sends a 50 MB transcript in seconds; an old image never answers
	liveTailPoll = 300 * time.Millisecond // the round's answer may reach another replica: read the state again
)

// liveScanBytes: how much of each .live copy's end is read for its last entry's time
const liveScanBytes = 256 << 10

// LiveTail: GET /m/api/tail/{session}
type LiveTail struct {
	Tail
	Session string `json:"session"` // the router's id (s…)
	State   string `json:"state"`
	File    string `json:"file"`          // the conversation's .live copy (<uuid>.jsonl)
	Bytes   int64  `json:"bytes"`         // its size when the router last received it
	LastAt  string `json:"lastAt"`        // its last entry's time
	Why     string `json:"why,omitempty"` // why it is stale
}

func (r *Router) registerLiveTail(m machineRoute) {
	m("POST /m/live-synced", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		sid, err := r.machineSession(machine)
		if err != nil {
			writeJSON(w, 403, map[string]string{"error": err.Error()})
			return
		}
		now := time.Now().UTC()
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[sid]; s != nil && s.MachineID == machine {
				if s.LiveSync == nil {
					s.LiveSync = &LiveSync{}
				}
				s.LiveSync.RoundAt = &now
			}
		})
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	m("GET /m/api/tail/{session}", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		if _, err := r.machineSession(machine); err != nil {
			writeJSON(w, 403, map[string]string{"error": err.Error()})
			return
		}
		q := req.URL.Query()
		n, _ := strconv.Atoi(q.Get("n"))
		t, code, err := r.LiveTailOf(req.PathValue("session"), q.Get("said") != "1", n)
		if err != nil {
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, t)
	})
}

// LiveTailOf: target = a session id or its exact title; tools: the tool calls and results too; n messages (default 40,
// at most 500)
func (r *Router) LiveTailOf(target string, tools bool, n int) (*LiveTail, int, error) {
	if n <= 0 {
		n = 40
	}
	n = min(n, 500)
	var s Session
	var rerr error
	r.st.Read(func(d *persisted) {
		x, err := resolvePeer(d, target)
		if err != nil {
			rerr = err
			return
		}
		s = *x
	})
	if rerr != nil {
		return nil, 404, fmt.Errorf("%v (a destroyed session's transcript is in transcript search, whole)", rerr)
	}
	out := &LiveTail{Session: s.ID, State: s.State}
	if s.State == "started" && s.MachineID != "" {
		if !r.liveRound(s.ID, s.MachineID) {
			out.Stale = true
			out.Why = fmt.Sprintf("its machine did not answer the live sync within %s (an image from before 2026-11-20 never does): its last copy", liveTailWait)
		}
	} else {
		out.Stale = true
		out.Why = "it is " + s.State + ": its last copy, taken before that"
	}
	box := r.box()
	if box == nil {
		return nil, 500, errNoStorageBox
	}
	var files map[string]int64
	r.st.Read(func(d *persisted) {
		if x := d.Sessions[s.ID]; x != nil && x.LiveSync != nil {
			files = make(map[string]int64, len(x.LiveSync.Files))
			for k, v := range x.LiveSync.Files {
				files[k] = v
			}
		}
	})
	name, last, err := newestConversation(box, liveDir(s.ID), files)
	if err != nil {
		return nil, 502, err
	}
	if name == "" {
		return nil, 404, errors.New("no copy of its conversation has reached the router yet")
	}
	text, err := box.GetTail(liveDir(s.ID)+"/"+name, tailBytes)
	if err != nil {
		return nil, 502, err
	}
	if len(text) > tailBytes {
		text = text[len(text)-tailBytes:]
	}
	tl := parseTranscriptWith(string(text), len(text) >= tailBytes, n, 4000, tools)
	tl.Stale = out.Stale
	out.Tail, out.File, out.Bytes, out.LastAt = tl, name, files[name], last
	return out, 200, nil
}

// liveRound: ask the machine for a sync round now and wait for its answer; false when none came in time
func (r *Router) liveRound(sid, machine string) bool {
	asked := time.Now().UTC()
	r.send(machine, "live-sync")
	deadline := asked.Add(liveTailWait)
	for {
		var done bool
		r.st.Read(func(d *persisted) {
			if s := d.Sessions[sid]; s != nil && s.LiveSync != nil && s.LiveSync.RoundAt != nil {
				done = !s.LiveSync.RoundAt.Before(asked)
			}
		})
		if done {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(liveTailPoll)
	}
}

// newestConversation: of a session's .live copies (name → size), the conversation whose last entry is newest, and
// that entry's time. Subagents' copies (agent-*.jsonl) are not conversations.
func newestConversation(box *StorageBox, dir string, files map[string]int64) (string, string, error) {
	var names []string
	for n := range files {
		if !strings.HasPrefix(n, "agent-") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var best, bestAt string
	var bestT time.Time
	for _, n := range names {
		b, err := box.GetTail(dir+"/"+n, liveScanBytes)
		if err != nil {
			return "", "", err
		}
		if b == nil {
			continue // gone from the box (a purge)
		}
		at := lastEntryTime(b)
		t, _ := time.Parse(time.RFC3339Nano, at)
		if best == "" || t.After(bestT) {
			best, bestAt, bestT = n, at, t
		}
	}
	return best, bestAt, nil
}

// lastEntryTime: the timestamp of the last whole line that has one ("" when none does)
func lastEntryTime(b []byte) string {
	lines := strings.Split(string(b), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var j struct {
			Timestamp string `json:"timestamp"`
		}
		if json.Unmarshal([]byte(lines[i]), &j) == nil && j.Timestamp != "" {
			return j.Timestamp
		}
	}
	return ""
}
