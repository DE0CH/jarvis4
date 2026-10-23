package main

// A failed session always says why, and when (2026-10-22: Jarvis 2's "Kates work" failed on its first start, with no
// machine, and the setup API showed no reason). Whatever path makes a session failed, the state's every write
// (State.Do) checks it here: a failed session gets FailedAt (cleared once it is anything else) and, if the path left
// none, a reason saying so. Each new failure is in the session's event stream: the operation that failed ends with the
// reason (lifecycle.go); a failure outside any operation (an approval that lapsed, a router crash's cut-off, …) gets a
// one-line "Session failed: <reason>" of its own. The reason is shown wherever the session is listed: GET /api/state
// (the app's list and session page, the web page), GET /setup/sessions (infra/setup.py sessions -v), the events.

import "time"

// noReason: what a failed session says when the path that failed it gave no reason (a bug to fix there)
const noReason = "it failed without a reason recorded (the router's path that failed it gave none)"

// stampFailures: FailedAt and a reason on every failed session; the sessions that have just become failed, as
// [id, reason] pairs. Called under the state's lock.
func stampFailures(d *persisted, now time.Time) [][2]string {
	var out [][2]string
	for id, s := range d.Sessions {
		if s.State != "failed" {
			s.FailedAt = nil
			continue
		}
		if s.Error == "" {
			s.Error = noReason
		}
		if s.FailedAt == nil {
			t := now
			s.FailedAt = &t
			out = append(out, [2]string{id, s.Error})
		}
	}
	return out
}

// failureEvent: a session has just become failed: unless an operation of it is running (its end carries the reason)
// or the latest one already ended with this reason, the stream gets a "Session failed: <reason>" of its own
func (r *Router) failureEvent(session, reason string) {
	if r.lc == nil {
		return
	}
	r.lc.mu.Lock()
	run := r.lc.cur[session]
	r.lc.mu.Unlock()
	if run != nil {
		run.mu.Lock()
		covered := run.op.State == "running" || run.op.Error == reason
		run.mu.Unlock()
		if covered {
			return
		}
	}
	r.lcEnded(session, "session", "", reason)
}

// lcEnded: an operation written already ended, failed with reason (sessionevents.go shows only its end: "<Kind> failed:
// <reason>")
func (r *Router) lcEnded(session, kind, machine, reason string) {
	at := nowText()
	ms := []string{}
	if machine != "" {
		ms = append(ms, machine)
	}
	op := LcOp{ID: randID(), Session: session, Kind: kind, Started: at, Ended: at, State: "failed", Error: reason, Machines: ms}
	r.lcWrite(session, lcRec{Op: &op})
}
