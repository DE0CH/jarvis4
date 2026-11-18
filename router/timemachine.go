package main

// The time machine (docs/PLAN-fabric.md, "Next: freeze and the time machine"): a fabric session waits frozen. The
// machine asks with `time-machine <duration>` (POST /m/api/time-machine {seconds}); the router has the fabric hermit
// freeze its sandbox until then (hermit pauses it in place; the repacking may later evict it to S3) and the session
// becomes `frozen`, its machine kept. It comes back at the first of:
//
//   - the time: hermit thaws it itself at `until`, and the router sees it running again (frozenLoop);
//   - anything that would resume a paused session: a delivery (a message, wakeup, cron, watch, an Inbox decision's
//     outcome), the chat wanting a turn or an answer (hermit-jarvis resumes it), the app's Resume. Resume thaws a
//     frozen session (thaw), so each of these needs nothing of its own.
//
// The machine's command waits through it all (it is frozen with the sandbox) and then reads why it came back
// (GET /m/api/time-machine). Wakeups and crons stay as they are; the time machine is one more way to wait.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// TimeMachine: a frozen session's wait, and what ended its last one
type TimeMachine struct {
	Since time.Time  `json:"since"`
	Until *time.Time `json:"until,omitempty"`
	// Why: what brought it back ("the time", "a message", …); "" while frozen
	Why string `json:"why,omitempty"`
	// Back: when it was running again (the command's answer)
	Back *time.Time `json:"back,omitempty"`
}

const (
	timeMachineMax  = 30 * 24 * time.Hour
	thawWaitMax     = 20 * time.Minute // a thaw may wait for a host and a restore from S3
	frozenTickEvery = 15 * time.Second
)

// fabricHermitCall: a call to the fabric hermit as caller magpie (the router's pair)
var fabricHermitCall = func(method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, strings.TrimRight(os.Getenv("FABRIC_HERMIT_URL"), "/")+path, rd)
	req.Header.Set("Authorization", "Bearer "+os.Getenv("FABRIC_HERMIT_MAGPIE_TOKEN"))
	req.Header.Set("Aviary-Protocol", "hermit-core=1")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	return res.StatusCode, b, nil
}

// hermitSandboxState: the conversation's sandbox state at the fabric hermit ("" when it has none)
func hermitSandboxState(conversation string) (string, error) {
	code, b, err := fabricHermitCall("GET", "/v1/conversations/"+conversation+"/sandbox", nil)
	if err != nil {
		return "", err
	}
	if code == 404 {
		return "", nil
	}
	if code/100 != 2 {
		return "", fmt.Errorf("hermit: HTTP %d %s", code, strings.TrimSpace(string(b)))
	}
	var sb struct{ State string }
	if err := json.Unmarshal(b, &sb); err != nil {
		return "", fmt.Errorf("hermit: %v", err)
	}
	return sb.State, nil
}

// timeMachineWhy: what a delivery of this kind is, in the command's words
func timeMachineWhy(kind string) string {
	switch kind {
	case "wakeup":
		return "a scheduled wakeup"
	case "cron":
		return "a cron run"
	case "watch", "watch-fail":
		return "a watch"
	case "request-outcome":
		return "a decision on an Inbox request"
	case "peer":
		return "a message from another session"
	case "resume-prompt":
		return "a message from Deyao"
	}
	return "a message (" + kind + ")"
}

// freeze: the session goes into the time machine for `d` (the machine's own ask)
func (r *Router) freeze(sid string, d time.Duration) (*TimeMachine, error) {
	if !fabricEnabled() {
		return nil, errors.New("the time machine needs the fabric, and this router has none")
	}
	if d <= 0 || d > timeMachineMax {
		return nil, fmt.Errorf("a time between a second and %s, please", timeMachineMax)
	}
	var (
		state, runner, conv string
	)
	r.st.Read(func(p *persisted) {
		if s := p.Sessions[sid]; s != nil {
			state, runner = s.State, s.Runner
			if s.Fabric != nil {
				conv = s.Fabric.Conversation
			}
		}
	})
	if runner != "fabric" || conv == "" {
		return nil, errors.New("only a session on the fabric (gVisor) has the time machine")
	}
	if state != "started" {
		return nil, fmt.Errorf("the session is %s, not running", orState(state))
	}
	until := time.Now().Add(d).UTC()
	code, b, err := fabricHermitCall("POST", "/v1/conversations/"+conv+"/sandbox/freeze", map[string]any{"until": until.Format(time.RFC3339Nano)})
	if err != nil {
		return nil, err
	}
	if code/100 != 2 {
		return nil, fmt.Errorf("the fabric would not freeze it: HTTP %d %s", code, strings.TrimSpace(string(b)))
	}
	tm := &TimeMachine{Since: time.Now().UTC(), Until: &until}
	r.st.Do(func(p *persisted) {
		if s := p.Sessions[sid]; s != nil && s.State == "started" {
			s.State, s.TimeMachine = "frozen", tm
		}
	})
	log.Printf("[time-machine] %s frozen until %s", sid, until.Format(time.RFC3339))
	return tm, nil
}

// thaw: a frozen session comes back (hermit resumes it in place, or restores it from S3 on any host), and is
// `started` again once hermit has it running; why is what the machine's command reports
func (r *Router) thaw(sid, why string) error {
	var conv, state string
	r.st.Read(func(p *persisted) {
		if s := p.Sessions[sid]; s != nil {
			state = s.State
			if s.Fabric != nil {
				conv = s.Fabric.Conversation
			}
		}
	})
	if state != "frozen" {
		return nil
	}
	code, b, err := fabricHermitCall("POST", "/v1/conversations/"+conv+"/sandbox/thaw", nil)
	if err != nil {
		return err
	}
	if code/100 != 2 {
		return fmt.Errorf("the fabric would not thaw it: HTTP %d %s", code, strings.TrimSpace(string(b)))
	}
	log.Printf("[time-machine] %s thawing (%s)", sid, why)
	deadline := time.Now().Add(thawWaitMax)
	for {
		st, err := hermitSandboxState(conv)
		if err == nil && st == "ready" {
			r.back(sid, why)
			return nil
		}
		if err == nil && st == "frozen" { // a freeze that finished after the first thaw: ask again
			fabricHermitCall("POST", "/v1/conversations/"+conv+"/sandbox/thaw", nil)
		}
		if err == nil && (st == "" || st == "gone" || st == "releasing") {
			return fmt.Errorf("the session's sandbox is %s at the fabric: it could not come back", orState(st))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the session is not back after %s", thawWaitMax)
		}
		time.Sleep(3 * time.Second)
	}
}

// back: the frozen session runs again
func (r *Router) back(sid, why string) {
	now := time.Now().UTC()
	r.st.Do(func(p *persisted) {
		if s := p.Sessions[sid]; s != nil && s.State == "frozen" {
			s.State = "started"
			if s.TimeMachine == nil {
				s.TimeMachine = &TimeMachine{Since: now}
			}
			s.TimeMachine.Why, s.TimeMachine.Back = why, &now
		}
	})
	log.Printf("[time-machine] %s back (%s)", sid, why)
}

// frozenVerdict: a frozen session whose sandbox hermit runs again is back (hermit thawed it at its until); one hermit
// no longer has is lost to the time machine and goes as a lost machine does
func frozenVerdict(hermitState string) (back, lost bool) {
	switch hermitState {
	case "ready":
		return true, false
	case "", "gone":
		return false, true
	}
	return false, false
}

func (r *Router) frozenLoop() {
	if !fabricEnabled() {
		return
	}
	for {
		time.Sleep(frozenTickEvery)
		type fz struct{ id, conv string }
		var all []fz
		r.st.Read(func(p *persisted) {
			for id, s := range p.Sessions {
				if s.State == "frozen" && s.Fabric != nil {
					all = append(all, fz{id, s.Fabric.Conversation})
				}
			}
		})
		for _, f := range all {
			st, err := hermitSandboxState(f.conv)
			if err != nil {
				continue
			}
			switch back, lost := frozenVerdict(st); {
			case back:
				r.back(f.id, "the time")
			case lost:
				r.st.Do(func(p *persisted) {
					if s := p.Sessions[f.id]; s != nil && s.State == "frozen" {
						s.State, s.Error = "failed", "its frozen sandbox is gone from the fabric (Resume starts it from its files)"
						now := time.Now()
						s.FailedAt = &now
					}
				})
				log.Printf("[time-machine] %s: its frozen sandbox is gone at the fabric", f.id)
			}
		}
	}
}

func (r *Router) registerTimeMachine(m machineRoute) {
	own := func(fn func(w http.ResponseWriter, req *http.Request, sid string, body []byte)) func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		return func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
			sid, err := r.machineSession(machine)
			if err != nil {
				writeJSON(w, 403, map[string]string{"error": err.Error()})
				return
			}
			fn(w, req, sid, body)
		}
	}
	m("POST /m/api/time-machine", own(func(w http.ResponseWriter, req *http.Request, sid string, b []byte) {
		var in struct {
			Seconds int64 `json:"seconds"`
		}
		if err := json.Unmarshal(b, &in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "a body {seconds}"})
			return
		}
		tm, err := r.freeze(sid, time.Duration(in.Seconds)*time.Second)
		if err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 202, map[string]any{"frozen": true, "until": tm.Until})
	}))
	m("GET /m/api/time-machine", own(func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		var out map[string]any
		r.st.Read(func(p *persisted) {
			s := p.Sessions[sid]
			if s == nil {
				return
			}
			out = map[string]any{"frozen": s.State == "frozen"}
			if s.TimeMachine != nil {
				out["since"], out["until"], out["why"], out["back"] = s.TimeMachine.Since, s.TimeMachine.Until, s.TimeMachine.Why, s.TimeMachine.Back
			}
		})
		if out == nil {
			writeJSON(w, 404, map[string]string{"error": "no such session"})
			return
		}
		writeJSON(w, 200, out)
	}))
}
