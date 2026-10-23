package main

// The lifecycle log (Deyao, 2026-10-16): every boot, pause, resume, upgrade, restart and destroy of a session is an
// operation with its own log; the app and the web page show it in the session's one event stream (sessionevents.go),
// together with the supervisor's lines, live while it runs and afterwards.
// An operation's log is, in time order:
//
//   - the router's own steps (source "router"): asked the core to start a machine, the machine is up, the cert, asked
//     the machine for its final snapshot, the snapshot arrived, asked the core to destroy the machine, the archive…;
//   - what Fly did (source "fly"), read by the router itself with its READ-ONLY token (FLY_READ_TOKEN, app
//     jarvis4-sessions; no core change): the machine's Fly events (launch, start, exit, destroy, with their source and
//     exit code), polled every 2 s while the operation runs and for 30 s after it (Fly keeps only a few
//     events per machine, so each is kept the first time it is seen), and Fly's own platform log lines for the machine
//     (image pull, "Machine started in …", the VM's exit), from Fly's logs API (the app's stdout is left out);
//   - the supervisor's lines (source "supervisor", supervisorlog.go) of the operation's machines from 5 s before it
//     began until 30 s after it ended (until now while it runs), merged in when read.
//
// Stored per session on the router's volume (lifecycle/<session>.jsonl: the operation records and their router and
// Fly entries, appended), kept for the session's life, and archived on Destroy (jarvis2/lifecycle.json) before the
// file goes. The pollers run in the router process doing the operation (the leader); a drain stops their tails early,
// and the next leader closes an operation a crash left open ("cut off").

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	lcBootMax = 15 * time.Minute // how long a start's operation waits for the machine's first report
	lcLead    = 5 * time.Second  // supervisor lines from this long before an operation began belong to it
)

// LcOp: one operation
type LcOp struct {
	ID       string   `json:"id"`
	Session  string   `json:"session"`
	Kind     string   `json:"kind"` // boot | pause | resume | upgrade | restart | destroy | harness-pause | harness-resume
	Started  string   `json:"started"`
	Ended    string   `json:"ended,omitempty"`
	State    string   `json:"state"` // running | done | failed | cut off
	Error    string   `json:"error,omitempty"`
	Machines []string `json:"machines"`
}

// LcEntry: one line of an operation's log
type LcEntry struct {
	At      string `json:"at"`
	Source  string `json:"source"` // router | fly | supervisor
	Machine string `json:"machine,omitempty"`
	Text    string `json:"text"`
}

// lcRec: one line of a session's file
type lcRec struct {
	Op    *LcOp    `json:"op,omitempty"`    // the operation as it now is (the last record of an id wins)
	OpID  string   `json:"opId,omitempty"`  // an entry's operation
	Entry *LcEntry `json:"entry,omitempty"` // a router or Fly entry
}

type lcRun struct {
	mu       sync.Mutex
	op       LcOp
	seen     map[string]bool   // Fly events and log lines already kept
	logNext  map[string]string // machine → Fly logs' next_token
	logsOff  bool              // Fly's logs API refused: events only
	stop     chan struct{}
	stopOnce sync.Once
	job      bool // an upgrade or restart: its pause and resume join it
	ending   bool // end is writing its record: the operation is still current until it is written
	// handed: startAndCertify took over ending it (lcAwaitBoot ends it once the machine reports in). On the run, not
	// on a handle: startAndCertify holds its own (lcCurrent's), and the resume's deferred endFromState checks its own
	handed atomic.Bool
}

// lcHandle: what a flow holds. joined: the flow runs inside a job's operation, which the job ends
type lcHandle struct {
	r      *Router
	run    *lcRun
	joined bool
}

type lifecycle struct {
	// Fly, read only, and how often (tests swap them per router)
	pollEvery, tail time.Duration
	flyEvents       func(machine string) ([]flyEvent, error)
	flyLogs         func(machine, next string) ([]flyLogLine, string, error)
	flyOn           func() bool // a read token is there

	mu   sync.Mutex
	cur  map[string]*lcRun // session → its latest operation (running, or in its tail)
	gone map[string]bool   // destroyed: nothing more is written
	file sync.Mutex        // appends
}

func newLifecycle() *lifecycle {
	return &lifecycle{cur: map[string]*lcRun{}, gone: map[string]bool{}, pollEvery: 2 * time.Second, tail: 30 * time.Second,
		flyEvents: lcFlyEvents, flyLogs: lcFlyLogs, flyOn: func() bool { return machinesFly() != nil }}
}

func (l *lifecycle) dropped(session string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.gone[session]
}

func nowText() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func (r *Router) lcWrite(session string, rec lcRec) {
	if r.lc == nil || r.lc.dropped(session) {
		return
	}
	r.lc.file.Lock()
	defer r.lc.file.Unlock()
	b, _ := json.Marshal(rec)
	if err := r.st.AppendLog(session, logLifecycle, b); err != nil {
		log.Printf("[lifecycle] %v", err)
	}
}

// lcBegin: a new operation of the session (its kind), or the job's operation it runs inside
func (r *Router) lcBegin(session, kind string) *lcHandle { return r.lcStart(session, kind, false) }

// lcBeginJob: an operation that runs others (an Upgrade's free, pause and resume; a restart's): they join it, and it
// ends only by endJob
func (r *Router) lcBeginJob(session, kind string) *lcHandle { return r.lcStart(session, kind, true) }

func (r *Router) lcStart(session, kind string, job bool) *lcHandle {
	if r.lc == nil {
		return nil
	}
	r.lc.mu.Lock()
	if prev := r.lc.cur[session]; prev != nil {
		prev.mu.Lock()
		running := prev.op.State == "running" && !prev.ending // one ending is over: nothing joins it
		job := prev.job
		prev.mu.Unlock()
		if running && job {
			r.lc.mu.Unlock()
			h := &lcHandle{r: r, run: prev, joined: true}
			h.note("", kind+" (part of the "+prev.op.Kind+")")
			return h
		}
		if running { // shouldn't happen (the session lock): close it so only one runs
			r.lc.mu.Unlock()
			(&lcHandle{r: r, run: prev}).end("done", "")
			r.lc.mu.Lock()
		}
		prev.stopOnce.Do(func() { close(prev.stop) })
	}
	run := &lcRun{op: LcOp{ID: randID(), Session: session, Kind: kind, Started: nowText(), State: "running", Machines: []string{}},
		seen: map[string]bool{}, logNext: map[string]string{}, stop: make(chan struct{}), job: job}
	r.lc.cur[session] = run
	r.lc.mu.Unlock()
	op := run.op
	r.lcWrite(session, lcRec{Op: &op})
	go r.lcPoll(run)
	return &lcHandle{r: r, run: run}
}

// lcCurrent: the session's running operation (nil when none)
func (r *Router) lcCurrent(session string) *lcHandle {
	if r.lc == nil {
		return nil
	}
	r.lc.mu.Lock()
	run := r.lc.cur[session]
	r.lc.mu.Unlock()
	if run == nil {
		return nil
	}
	run.mu.Lock()
	running := run.op.State == "running"
	run.mu.Unlock()
	if !running {
		return nil
	}
	return &lcHandle{r: r, run: run, joined: true}
}

// lcNote: a router step into the session's running operation (none: nothing)
func (r *Router) lcNote(session, machine, text string) {
	if h := r.lcCurrent(session); h != nil {
		h.note(machine, text)
	}
}

// lcMachine: a machine the session's running operation involves (its Fly events and logs are read from now on)
func (r *Router) lcMachine(session, machine string) {
	if h := r.lcCurrent(session); h != nil {
		h.machine(machine)
	}
}

func (h *lcHandle) note(machine, text string) {
	if h == nil {
		return
	}
	h.add(LcEntry{At: nowText(), Source: "router", Machine: machine, Text: text})
}

func (h *lcHandle) add(e LcEntry) {
	h.r.lcWrite(h.run.op.Session, lcRec{OpID: h.run.op.ID, Entry: &e})
}

func (h *lcHandle) machine(m string) {
	if h == nil || m == "" {
		return
	}
	h.run.mu.Lock()
	for _, x := range h.run.op.Machines {
		if x == m {
			h.run.mu.Unlock()
			return
		}
	}
	h.run.op.Machines = append(h.run.op.Machines, m)
	op := h.run.op
	op.Machines = append([]string{}, op.Machines...)
	h.run.mu.Unlock()
	h.r.lcWrite(op.Session, lcRec{Op: &op})
}

// end: the operation is over (state done or failed); its Fly tail goes on for lifecycle.tail. A joined handle ends nothing.
// The end record is written before the operation stops being current: whoever sees no running operation (lcCurrent
// nil) also finds its end in the file, and nothing of it is still being written (DECISIONS 213).
func (h *lcHandle) end(state, errMsg string) {
	if h == nil || h.joined {
		return
	}
	h.run.mu.Lock()
	if h.run.op.State != "running" || h.run.ending {
		h.run.mu.Unlock()
		return
	}
	h.run.ending = true
	op := h.run.op
	op.State, op.Error, op.Ended = state, errMsg, nowText()
	op.Machines = append([]string{}, op.Machines...)
	h.run.mu.Unlock()
	h.r.lcWrite(op.Session, lcRec{Op: &op})
	h.run.mu.Lock()
	h.run.op.State, h.run.op.Error, h.run.op.Ended = op.State, op.Error, op.Ended
	h.run.mu.Unlock()
}

// endJob: a job (upgrade, restart) ends its own operation
func (h *lcHandle) endJob(err error) {
	if h == nil {
		return
	}
	j := &lcHandle{r: h.r, run: h.run}
	if err != nil {
		j.end("failed", err.Error())
	} else {
		j.end("done", "")
	}
}

// endFromState: done, or failed with the session's error (its state failed, or an error left on it)
func (h *lcHandle) endFromState() {
	if h == nil || h.joined || h.run.handed.Load() {
		return
	}
	var state, errMsg string
	h.r.st.Do(func(d *persisted) {
		if s := d.Sessions[h.run.op.Session]; s != nil {
			state, errMsg = s.State, s.Error
		}
	})
	if state == "failed" || errMsg != "" {
		h.end("failed", errMsg)
		return
	}
	h.end("done", "")
}

// lcDrop: the session is a record now (its archive holds the logs): its file goes and nothing more is written
func (r *Router) lcDrop(session string) {
	if r.lc == nil {
		return
	}
	r.lc.mu.Lock()
	if run := r.lc.cur[session]; run != nil {
		run.stopOnce.Do(func() { close(run.stop) })
	}
	delete(r.lc.cur, session)
	r.lc.gone[session] = true
	r.lc.mu.Unlock()
	r.lc.file.Lock()
	r.st.DropLog(session, logLifecycle)
	r.lc.file.Unlock()
}

// lcCutOff: at the leader's start, an operation still open in a log was cut off (a crash, or a drain that ended its
// log early): closed as such
func (r *Router) lcCutOff() {
	for _, session := range r.st.LogSessions(logLifecycle) {
		if r.jobBusy(session) {
			continue // another replica runs it (jobs.go)
		}
		ops, _ := r.lcRead(session)
		for _, op := range ops {
			if op.State == "running" {
				op.State, op.Ended, op.Error = "cut off", nowText(), "the router restarted while it ran: its log ends here (the supervisor's own log goes on)"
				o := op
				r.lcWrite(op.Session, lcRec{Op: &o})
			}
		}
	}
}

// ---- Fly, read only -------------------------------------------------------------------------------------------

type flyEvent struct {
	Type      string `json:"type"`
	Status    string `json:"status"`
	Source    string `json:"source"`
	Timestamp int64  `json:"timestamp"` // ms
	Request   *struct {
		ExitEvent *struct {
			ExitCode      int  `json:"exit_code"`
			OOMKilled     bool `json:"oom_killed"`
			RequestedStop bool `json:"requested_stop"`
		} `json:"exit_event"`
	} `json:"request"`
}

type flyLogLine struct {
	ID        string
	Timestamp string
	Message   string
	Provider  string // app | runner | proxy | …
}

// lcFlyEvents: the machine's events as Fly lists them now
func lcFlyEvents(machine string) ([]flyEvent, error) {
	f := machinesFly()
	if f == nil {
		return nil, fmt.Errorf("FLY_READ_TOKEN not set")
	}
	var m struct {
		Events []flyEvent `json:"events"`
	}
	return m.Events, f.get("/machines/"+url.PathEscape(machine), &m)
}

// flyLogsBase: Fly's logs API (tests point it at a fake)
var flyLogsBase = "https://api.fly.io"

// lcFlyLogs: the machine's log lines after next ("" = Fly's latest page), and the token for the next call
func lcFlyLogs(machine, next string) ([]flyLogLine, string, error) {
	token := os.Getenv("FLY_READ_TOKEN")
	if token == "" {
		return nil, next, fmt.Errorf("FLY_READ_TOKEN not set")
	}
	q := url.Values{"instance": {machine}}
	if next != "" {
		q.Set("next_token", next)
	}
	req, _ := http.NewRequest("GET", flyLogsBase+"/api/v1/apps/"+sessionsApp+"/logs?"+q.Encode(), nil)
	if !strings.HasPrefix(token, "FlyV1 ") && !strings.HasPrefix(token, "Bearer ") {
		token = "Bearer " + token
	}
	req.Header.Set("Authorization", token)
	req.Header.Set("Accept", "application/json")
	resp, err := flyOrgHTTP.Do(req)
	if err != nil {
		return nil, next, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, next, &flyLogsRefused{resp.StatusCode}
	}
	var out struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Timestamp string `json:"timestamp"`
				Message   string `json:"message"`
				Meta      struct {
					Event struct {
						Provider string `json:"provider"`
					} `json:"event"`
				} `json:"meta"`
			} `json:"attributes"`
		} `json:"data"`
		Meta struct {
			NextToken string `json:"next_token"`
		} `json:"meta"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, next, err
	}
	lines := make([]flyLogLine, 0, len(out.Data))
	for _, d := range out.Data {
		lines = append(lines, flyLogLine{ID: d.ID, Timestamp: d.Attributes.Timestamp, Message: d.Attributes.Message, Provider: d.Attributes.Meta.Event.Provider})
	}
	if out.Meta.NextToken != "" {
		next = out.Meta.NextToken
	}
	return lines, next, nil
}

type flyLogsRefused struct{ status int }

func (e *flyLogsRefused) Error() string { return fmt.Sprintf("Fly's logs API: HTTP %d", e.status) }

func eventText(e flyEvent) string {
	t := e.Type
	if e.Status != "" {
		t += " → " + e.Status
	}
	if e.Source != "" {
		t += " (" + e.Source + ")"
	}
	if e.Request != nil && e.Request.ExitEvent != nil {
		x := e.Request.ExitEvent
		t += fmt.Sprintf(", exit code %d", x.ExitCode)
		if x.OOMKilled {
			t += ", killed for memory (OOM)"
		}
		if x.RequestedStop {
			t += ", stop requested"
		}
	}
	return "Fly: machine " + t
}

// lcPollOnce: new Fly events and platform log lines of the operation's machines, each kept once
func (r *Router) lcPollOnce(run *lcRun) {
	run.mu.Lock()
	machines := append([]string{}, run.op.Machines...)
	started, _ := time.Parse(time.RFC3339Nano, run.op.Started)
	logsOff := run.logsOff
	run.mu.Unlock()
	h := &lcHandle{r: r, run: run}
	for _, m := range machines {
		if evs, err := r.lc.flyEvents(m); err == nil {
			sort.Slice(evs, func(i, j int) bool { return evs[i].Timestamp < evs[j].Timestamp })
			for _, e := range evs {
				at := time.UnixMilli(e.Timestamp)
				k := fmt.Sprintf("e|%s|%s|%s|%d", m, e.Type, e.Status, e.Timestamp)
				run.mu.Lock()
				old := run.seen[k]
				run.seen[k] = true
				run.mu.Unlock()
				if old || at.Before(started.Add(-lcLead)) {
					continue
				}
				h.add(LcEntry{At: at.UTC().Format(time.RFC3339Nano), Source: "fly", Machine: m, Text: eventText(e)})
			}
		}
		if logsOff {
			continue
		}
		run.mu.Lock()
		next := run.logNext[m]
		run.mu.Unlock()
		lines, nt, err := r.lc.flyLogs(m, next)
		if err != nil {
			if _, refused := err.(*flyLogsRefused); refused {
				run.mu.Lock()
				run.logsOff, logsOff = true, true
				run.mu.Unlock()
				h.note("", err.Error()+" for the router's read-only token: Fly's events only")
			}
			continue
		}
		run.mu.Lock()
		run.logNext[m] = nt
		run.mu.Unlock()
		for _, l := range lines {
			if l.Provider == "app" { // the machine's own output: the supervisor pushes its lines itself
				continue
			}
			at, err := time.Parse(time.RFC3339Nano, l.Timestamp)
			if err != nil || at.Before(started.Add(-lcLead)) {
				continue
			}
			k := "l|" + m + "|" + l.ID
			if l.ID == "" {
				k = "l|" + m + "|" + l.Timestamp + "|" + l.Message
			}
			run.mu.Lock()
			old := run.seen[k]
			run.seen[k] = true
			run.mu.Unlock()
			if old {
				continue
			}
			h.add(LcEntry{At: at.UTC().Format(time.RFC3339Nano), Source: "fly", Machine: m, Text: "Fly " + orStr(l.Provider, "platform") + ": " + strings.TrimSpace(l.Message)})
		}
	}
}

// lcPoll: Fly read while the operation runs and for lifecycle.tail after; a drain cuts the tail short
func (r *Router) lcPoll(run *lcRun) {
	if !r.lc.flyOn() {
		return // no read token (a test router, a dev box): router and supervisor entries only
	}
	for {
		select {
		case <-run.stop:
			r.lcPollOnce(run)
			return
		case <-time.After(r.lc.pollEvery):
		}
		r.lcPollOnce(run)
		run.mu.Lock()
		ended, _ := time.Parse(time.RFC3339Nano, run.op.Ended)
		state := run.op.State
		run.mu.Unlock()
		if state != "running" && (time.Since(ended) > r.lc.tail || r.draining()) {
			return
		}
		if r.lc.dropped(run.op.Session) {
			return
		}
	}
}

// ---- reading ------------------------------------------------------------------------------------------------

// lcRead: a session's log → its operations (oldest first) and each one's router and Fly entries
func (r *Router) lcRead(session string) ([]LcOp, map[string][]LcEntry) {
	byID := map[string]LcOp{}
	order := []string{}
	entries := map[string][]LcEntry{}
	for _, raw := range r.lcLines(session) {
		var rec lcRec
		if json.Unmarshal(raw, &rec) != nil {
			continue
		}
		if rec.Op != nil {
			if _, ok := byID[rec.Op.ID]; !ok {
				order = append(order, rec.Op.ID)
			}
			byID[rec.Op.ID] = *rec.Op
		}
		if rec.Entry != nil {
			entries[rec.OpID] = append(entries[rec.OpID], *rec.Entry)
		}
	}
	ops := make([]LcOp, 0, len(order))
	for _, id := range order {
		ops = append(ops, byID[id])
	}
	return ops, entries
}

func parseAt(s string) time.Time { t, _ := time.Parse(time.RFC3339Nano, s); return t }

// lcOpLog: an operation with its entries and the supervisor lines of its machines, in time order
func (r *Router) lcOpLog(op LcOp, own []LcEntry, sup []SupLine) []LcEntry {
	from := parseAt(op.Started).Add(-lcLead)
	to := time.Now().Add(time.Second)
	if op.State != "running" {
		to = parseAt(op.Ended).Add(r.lc.tail)
	}
	in := map[string]bool{}
	for _, m := range op.Machines {
		in[m] = true
	}
	out := append([]LcEntry{}, own...)
	for _, l := range sup {
		at := parseAt(l.At)
		if !in[l.Machine] || at.Before(from) || at.After(to) {
			continue
		}
		out = append(out, LcEntry{At: l.At, Source: "supervisor", Machine: l.Machine, Text: l.Text})
	}
	sort.SliceStable(out, func(i, j int) bool { return parseAt(out[i].At).Before(parseAt(out[j].At)) })
	return out
}

// lcAll: every operation of the session, each with its log (the archive's lifecycle.json), oldest first
func (r *Router) lcAll(session string) []map[string]any {
	ops, entries := r.lcRead(session)
	sup := r.readSupLog(session)
	out := []map[string]any{}
	for _, op := range ops {
		out = append(out, map[string]any{"id": op.ID, "kind": op.Kind, "started": op.Started, "ended": op.Ended, "state": op.State,
			"error": op.Error, "machines": op.Machines, "entries": r.lcOpLog(op, entries[op.ID], sup)})
	}
	return out
}

// lifecycleFiles: the supervisor log and every operation's log, for the session's archive (archivetar.go)
func (r *Router) lifecycleFiles(sid string) []memFile {
	if r.lc == nil {
		return nil
	}
	var out []memFile
	if ops := r.lcAll(sid); len(ops) > 0 {
		b, _ := json.MarshalIndent(ops, "", " ")
		out = append(out, memFile{"jarvis2/lifecycle.json", b})
	}
	if lines, _ := r.st.ReadLog(sid, logSupervisor); len(lines) > 0 {
		out = append(out, memFile{"jarvis2/supervisor-log.jsonl", append(bytes.Join(lines, []byte("\n")), '\n')})
	}
	return out
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// lcLines: a session's lifecycle log, its records' JSON in order
func (r *Router) lcLines(session string) [][]byte {
	r.lc.file.Lock()
	defer r.lc.file.Unlock()
	lines, err := r.st.ReadLog(session, logLifecycle)
	if err != nil {
		log.Printf("[lifecycle] reading %s: %v", session, err)
	}
	return lines
}

// ---- routes ---------------------------------------------------------------------------------------------------

func (r *Router) registerLifecycle(app appRoute) {
	exists := func(id string) (s Session, ok bool) {
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				s, ok = *x, true
			}
		})
		return
	}
	// the supervisor's pause and resume of the Claude process (machine/supervisor.go), unguarded like snapshot and free
	app("POST /api/sessions/{id}/harness", func(w http.ResponseWriter, req *http.Request) {
		id := req.PathValue("id")
		var in struct {
			Action string `json:"action"`
		}
		json.NewDecoder(http.MaxBytesReader(w, req.Body, 1<<12)).Decode(&in)
		if in.Action != "pause" && in.Action != "resume" {
			writeJSON(w, 400, map[string]string{"error": `action: "pause" or "resume"`})
			return
		}
		s, ok := exists(id)
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "no session " + id})
			return
		}
		if s.MachineID == "" {
			writeJSON(w, 409, map[string]string{"error": "session is " + orState(s.State) + ": it has no machine to send that to"})
			return
		}
		h := r.lcBegin(id, "harness-"+in.Action)
		h.machine(s.MachineID)
		cmd := in.Action + "-harness"
		r.send(s.MachineID, cmd)
		h.note(s.MachineID, "sent the supervisor "+cmd)
		h.end("done", "")
		writeJSON(w, 200, map[string]any{"ok": true, "machine": s.MachineID, "command": cmd, "op": h.run.op.ID})
	})
}

// endJoined: end the operation even when this handle joined it — unless it is a job's (an upgrade or restart ends
// its own); a start ends the resume operation it took over
func (h *lcHandle) endJoined(state, errMsg string) {
	if h == nil {
		return
	}
	h.run.mu.Lock()
	job := h.run.job
	h.run.mu.Unlock()
	if job {
		return
	}
	j := &lcHandle{r: h.r, run: h.run}
	j.end(state, errMsg)
}

// lcAwaitBoot: a start's operation ends when the machine first reports (booted), fails, or lcBootMax passes; a drain
// ends its log early (the supervisor's own log goes on)
func (r *Router) lcAwaitBoot(op *lcHandle, sid, machine string) {
	if op == nil {
		return
	}
	for end := time.Now().Add(lcBootMax); ; time.Sleep(time.Second) {
		var booted bool
		var state, errMsg, cur string
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[sid]; s != nil {
				booted, state, errMsg, cur = s.Booted == machine, s.State, s.Error, s.MachineID
			}
		})
		switch {
		case booted:
			op.note(machine, "the machine reported in: booted, the harness is starting")
			op.endJoined("done", "")
			return
		case cur != machine || state == "failed":
			op.endJoined("failed", orStr(errMsg, "the session moved on from machine "+machine+" ("+orState(state)+")"))
			return
		case r.draining():
			op.note(machine, "the router is updating: this log ends here; the supervisor's own log goes on")
			op.endJoined("done", "")
			return
		case time.Now().After(end):
			op.endJoined("failed", "the machine hasn't reported in within "+waitText(lcBootMax))
			return
		}
	}
}

func orStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
