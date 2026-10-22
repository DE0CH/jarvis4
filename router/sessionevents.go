package main

// A session's events (Deyao, 2026-10-16: "it should be one stream which i can see all events"): ONE time-ordered stream
// of everything the router keeps about a session's machines, which the app and the web page show as the session's Log:
//
//   - the supervisor's lines (source "supervisor", supervisorlog.go), all of them, from every machine the session had;
//   - each operation of the lifecycle log (lifecycle.go): its start and its end (source "router", mark "start" / "end",
//     with the operation's kind and, at the end, its state and error), and its router steps and Fly entries (sources
//     "router" and "fly") in between.
//
// GET /api/sessions/{id}/events → the newest `limit` events (default and max 2000), oldest first, and a cursor;
// GET …/events?after=<cursor> → only what was written since (the client adds them and keeps its list in time order:
// a Fly event is read a few seconds after it happened, so a new event can sort before one already shown). The cursor
// is "<supervisor seq>.<lifecycle record>": both files only grow (the supervisor log's cut keeps its seqs), so it is
// exact; an event's key ("s<seq>", "l<record>") is stable across reads.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const eventsReadMax = 2000

// SessionEvent: one entry of a session's stream
type SessionEvent struct {
	Key     string `json:"key"`
	At      string `json:"at"`
	Source  string `json:"source"` // supervisor | router | fly
	Machine string `json:"machine,omitempty"`
	Op      string `json:"op,omitempty"`    // the operation it belongs to: its kind (pause, resume, …)
	OpID    string `json:"opId,omitempty"`  //   …and id
	Mark    string `json:"mark,omitempty"`  // start | end: the operation began / ended here
	State   string `json:"state,omitempty"` // an end's state: done | failed | cut off
	Text    string `json:"text"`
}

// lcRecords: every record of a session's lifecycle file, in file order
func (r *Router) lcRecords(session string) []lcRec {
	var out []lcRec
	for _, raw := range r.lcLines(session) {
		var rec lcRec
		json.Unmarshal(raw, &rec) // a bad line stays a record (an empty one): the record numbers stay the log's
		out = append(out, rec)
	}
	return out
}

func opTitle(kind string) string {
	k := strings.ReplaceAll(orStr(kind, "operation"), "-", " ")
	return strings.ToUpper(k[:1]) + k[1:]
}

func durText(from, to string) string {
	a, b := parseAt(from), parseAt(to)
	if a.IsZero() || b.IsZero() {
		return ""
	}
	d := b.Sub(a)
	if d < time.Minute {
		return fmt.Sprintf("%d s", int(d/time.Second))
	}
	return waitText(d)
}

// lcEvents: the lifecycle file's records as events (from record `from` on), and the operation still running (nil if none)
func lcEvents(recs []lcRec, from int) ([]SessionEvent, *LcOp) {
	ops := map[string]LcOp{}   // id → as it now is
	ended := map[string]bool{} // an end already given
	var out []SessionEvent
	var latest string
	for i, rec := range recs {
		key := "l" + strconv.Itoa(i)
		switch {
		case rec.Op != nil:
			op := *rec.Op
			_, seen := ops[op.ID]
			ops[op.ID] = op
			if !seen {
				latest = op.ID
				if i >= from {
					out = append(out, SessionEvent{Key: key, At: op.Started, Source: "router", Op: op.Kind, OpID: op.ID, Mark: "start",
						State: "running", Text: opTitle(op.Kind) + " started"})
				}
			}
			if op.State != "running" && !ended[op.ID] {
				ended[op.ID] = true
				if i >= from {
					t := opTitle(op.Kind) + " " + op.State
					if d := durText(op.Started, op.Ended); d != "" {
						t += " after " + d
					}
					if op.Error != "" {
						t += ": " + op.Error
					}
					out = append(out, SessionEvent{Key: key, At: orStr(op.Ended, op.Started), Source: "router", Op: op.Kind, OpID: op.ID,
						Mark: "end", State: op.State, Text: t})
				}
			}
		case rec.Entry != nil && i >= from:
			e := rec.Entry
			out = append(out, SessionEvent{Key: key, At: e.At, Source: orStr(e.Source, "router"), Machine: e.Machine, Op: ops[rec.OpID].Kind,
				OpID: rec.OpID, Text: e.Text})
		}
	}
	if op, ok := ops[latest]; ok && op.State == "running" {
		return out, &op
	}
	return out, nil
}

func sortEvents(es []SessionEvent) {
	sort.SliceStable(es, func(i, j int) bool { return parseAt(es[i].At).Before(parseAt(es[j].At)) })
}

// sessionEvents: the session's stream. tail (no cursor): the newest limit events. Otherwise what came after the
// cursor (supervisor lines: at most limit, oldest first, so the cursor walks through a long backlog).
func (r *Router) sessionEvents(session string, tail bool, afterSup int64, afterLc, limit int) (out []SessionEvent, next string, running *LcOp, more bool) {
	recs := r.lcRecords(session)
	from := afterLc
	if tail {
		from = 0
	}
	out, running = lcEvents(recs, from)
	sup := r.readSupLog(session)
	nextSup := afterSup
	if tail {
		nextSup = 0
	}
	taken := 0
	for _, l := range sup {
		if l.Seq <= afterSup && !tail {
			continue
		}
		if !tail && taken >= limit {
			more = true
			break
		}
		out = append(out, SessionEvent{Key: "s" + strconv.FormatInt(l.Seq, 10), At: l.At, Source: "supervisor", Machine: l.Machine, Text: l.Text})
		nextSup, taken = l.Seq, taken+1
	}
	sortEvents(out)
	if tail && len(out) > limit {
		out, more = out[len(out)-limit:], true
	}
	if out == nil {
		out = []SessionEvent{}
	}
	return out, fmt.Sprintf("%d.%d", nextSup, len(recs)), running, more
}

// parseCursor: "<supervisor seq>.<lifecycle record>"
func parseCursor(s string) (int64, int, bool) {
	a, b, ok := strings.Cut(s, ".")
	if !ok {
		return 0, 0, false
	}
	sup, err1 := strconv.ParseInt(a, 10, 64)
	lc, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil || sup < 0 || lc < 0 {
		return 0, 0, false
	}
	return sup, lc, true
}

func (r *Router) registerSessionEvents(app appRoute) {
	app("GET /api/sessions/{id}/events", func(w http.ResponseWriter, req *http.Request) {
		id := req.PathValue("id")
		found, machine := false, ""
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[id]; s != nil {
				found, machine = true, s.MachineID
			}
		})
		if !found {
			writeJSON(w, 404, map[string]string{"error": "no session " + id})
			return
		}
		limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))
		if limit <= 0 || limit > eventsReadMax {
			limit = eventsReadMax
		}
		tail, afterSup, afterLc := true, int64(0), 0
		if c := req.URL.Query().Get("after"); c != "" {
			var ok bool
			if afterSup, afterLc, ok = parseCursor(c); !ok {
				writeJSON(w, 400, map[string]string{"error": `after: a cursor from a previous answer ("<seq>.<record>")`})
				return
			}
			tail = false
		}
		events, next, running, more := r.sessionEvents(id, tail, afterSup, afterLc, limit)
		var run any
		if running != nil {
			run = map[string]string{"id": running.ID, "kind": running.Kind, "started": running.Started}
		}
		writeJSON(w, 200, map[string]any{"events": events, "next": next, "running": run, "more": more, "machine": machine})
	})
}
