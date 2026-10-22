package main

// Watches (conditional wakeups; Jarvis 1's lib/watch.js and its server.js loop, in Jarvis 4's shape). A session arms a
// watch with its own signed request: a check script, the prompt for when the condition is met, a "fail" prompt for when
// it gives up, an interval and a maximum age. The router runs the check on the box's watch runner (k8s/services/apps/watch/watch.yaml,
// services/watch) every interval, whether the session is running or paused; the runner holds no secrets and reaches
// only the public internet, so a check gets none of the session's stores (docs/DECISIONS.md 101). Exit 0 = met: the
// prompt is delivered (the session resumed first when it is paused); exit 3, or the maximum age passed = give up: the
// fail prompt is delivered instead. Any other exit = not yet.
//
// The delivery is the session's own signed request ("watch" or "watch-fail", machine/deliver.go checks it against the
// line's keys and the core attests it), exactly like a wakeup: the router picks when, never what. The runner's output
// never reaches the agent (nothing vouches for it); the machine runs the check once more itself, with the session's own
// env, and appends that output. Watches belong to their session (Schedule.Watches) and end with it; a session with an
// armed watch is kept (PendingSchedule), so a paused one stays until the watch fires.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	watchMaxScript       = 32 * 1024
	watchMaxPrompt       = 3500
	watchMinInterval     = 30
	watchMaxInterval     = 3600
	watchDefaultInterval = 60
	watchMaxSeconds      = 400 * 24 * 60 * 60
	watchDefaultSeconds  = 7 * 24 * 60 * 60
	watchCheckTimeout    = 90 // seconds, on the runner
	watchTickEvery       = 10 * time.Second
	watchKeepOutput      = 2000
)

type Watch struct {
	Name       string `json:"name"`
	Script     string `json:"script"`
	Prompt     string `json:"prompt"`
	FailPrompt string `json:"failPrompt,omitempty"`
	Interval   int64  `json:"interval"`   // seconds
	MaxSeconds int64  `json:"maxSeconds"` // from ArmedAt
	ArmedAt    int64  `json:"armedAt"`    // ms: the arming's identity (compare-and-clear)
	NextAt     int64  `json:"nextAt"`     // ms: the next check
	Runs       int    `json:"runs"`
	LastRunAt  int64  `json:"lastRunAt,omitempty"`
	LastExit   *int   `json:"lastExit,omitempty"`
	LastError  string `json:"lastError,omitempty"`  // the last stderr line, or why the runner couldn't run it
	LastOutput string `json:"lastOutput,omitempty"` // the start of the last stdout (shown in the app, never delivered)
	// Outcome: "" = checking; "met" or "gave-up" = waiting for its delivery
	Outcome string `json:"outcome,omitempty"`
	// Signed: the session's own request that armed it, as its machine signed it: what vouches for the delivery
	Signed *SignedRequest `json:"signed,omitempty"`
}

func normalizeWatch(b map[string]any, now time.Time) (*Watch, error) {
	name := strings.TrimSpace(fmt.Sprint(orDefault(b["name"], "")))
	if !scheduleNameRE.MatchString(name) {
		return nil, bad("name must be 1-40 chars of letters, digits, _ or -")
	}
	script, _ := b["script"].(string)
	script = strings.ReplaceAll(strings.ReplaceAll(script, "\r\n", "\n"), "\r", "\n")
	if strings.TrimSpace(script) == "" {
		return nil, bad("script is required (the check; exit 0 = condition met, 3 = give up, else not yet)")
	}
	if len(script) > watchMaxScript {
		return nil, bad("script longer than %d bytes", watchMaxScript)
	}
	prompt := cleanPrompt(b["prompt"])
	if prompt == "" {
		return nil, bad("prompt is required — what the session should do when the condition is met")
	}
	fail := cleanPrompt(b["failPrompt"])
	if len([]rune(prompt)) > watchMaxPrompt || len([]rune(fail)) > watchMaxPrompt {
		return nil, bad("prompt or failPrompt longer than %d characters", watchMaxPrompt)
	}
	interval := int64(watchDefaultInterval)
	if v, ok := b["interval"]; ok && v != nil {
		f, ok := number(v)
		if !ok {
			return nil, bad("interval must be seconds")
		}
		interval = int64(math.Min(watchMaxInterval, math.Max(watchMinInterval, math.Round(f))))
	}
	maxS := int64(watchDefaultSeconds)
	if v, ok := b["maxSeconds"]; ok && v != nil {
		f, ok := number(v)
		if !ok || f <= 0 {
			return nil, bad("maxSeconds must be a positive number")
		}
		maxS = int64(math.Min(watchMaxSeconds, math.Round(f)))
	}
	ms := now.UnixMilli()
	return &Watch{Name: name, Script: script, Prompt: prompt, FailPrompt: fail, Interval: interval, MaxSeconds: maxS, ArmedAt: ms, NextAt: ms}, nil
}

// watchView: no script body (Jarvis 1's view, plus the last run)
func watchView(w *Watch) map[string]any {
	v := map[string]any{"name": w.Name, "prompt": w.Prompt, "failPrompt": w.FailPrompt, "interval": w.Interval, "maxSeconds": w.MaxSeconds,
		"armedAt": w.ArmedAt, "armedAtIso": iso(w.ArmedAt), "expiresAtIso": iso(w.ArmedAt + w.MaxSeconds*1000), "nextCheckIso": iso(w.NextAt),
		"runs": w.Runs, "lastExit": nil, "lastRunIso": nil, "lastError": w.LastError, "lastOutput": w.LastOutput, "outcome": w.Outcome}
	if w.LastExit != nil {
		v["lastExit"] = *w.LastExit
	}
	if w.LastRunAt != 0 {
		v["lastRunIso"] = iso(w.LastRunAt)
	}
	return v
}

func sortedWatches(s *Schedule) []*Watch {
	out := []*Watch{}
	if s != nil {
		for _, w := range s.Watches {
			out = append(out, w)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ArmedAt < out[j].ArmedAt })
	return out
}

func watchesViewOf(d *persisted, sid string) []map[string]any {
	out := []map[string]any{}
	for _, w := range sortedWatches(d.Schedules[sid]) {
		out = append(out, watchView(w))
	}
	return out
}

func (r *Router) ListWatches(sid string) ([]map[string]any, error) {
	var out []map[string]any
	var err error
	r.st.Do(func(d *persisted) {
		if d.Sessions[sid] == nil {
			err = errNoSession
			return
		}
		out = watchesViewOf(d, sid)
	})
	return out, err
}

func (r *Router) ArmWatch(sid string, w *Watch) error {
	var err error
	r.st.Do(func(d *persisted) {
		if _, err = r.liveSession(d, sid); err == nil {
			sched(d, sid).Watches[w.Name] = w
		}
	})
	if err == nil {
		schedRun.forget(sid + "/watch/" + w.Name)
		log.Printf("[watch] %s armed %q every %ds for up to %dh: %s", sid, w.Name, w.Interval, w.MaxSeconds/3600, trimTo(w.Prompt, 80))
	}
	return err
}

func (r *Router) CancelWatch(sid, name string) error {
	var err error
	r.st.Do(func(d *persisted) {
		if d.Sessions[sid] == nil {
			err = errNoSession
			return
		}
		delete(sched(d, sid).Watches, name)
	})
	schedRun.forget(sid + "/watch/" + name)
	if err == nil {
		log.Printf("[watch] %s cancelled %q", sid, name)
	}
	return err
}

// ---- running the checks --------------------------------------------------------------------------------------

type checkResult struct {
	Exit     int    `json:"exit"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	TimedOut bool   `json:"timedOut"`
}

func watchRunnerURL() string {
	return strings.TrimSuffix(env("WATCH_URL", "http://10.77.0.3:30095"), "/")
}

var watchClient = &http.Client{Timeout: (watchCheckTimeout + 45) * time.Second}

// runCheckHook: a seam for tests; the real one asks the watch runner
var runCheckHook = func(w *Watch) (*checkResult, error) {
	b, _ := json.Marshal(map[string]any{"script": w.Script, "name": w.Name, "timeout": watchCheckTimeout})
	resp, err := watchClient.Post(watchRunnerURL()+"/run", "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("the watch runner is unreachable: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("the watch runner answered %d: %s", resp.StatusCode, trimTo(string(body), 200))
	}
	var out checkResult
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("the watch runner's answer: %v", err)
	}
	return &out, nil
}

func lastLineOf(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return trimTo(strings.TrimSpace(lines[len(lines)-1]), 300)
}

func (r *Router) watchLoop() {
	for {
		time.Sleep(watchTickEvery)
		r.watchTick(time.Now())
	}
}

var watchTicking sync.Mutex

// watchWG: the watch goroutines in flight (tests wait for them)
var watchWG sync.WaitGroup

// watchTick: each due check runs (one at a time per watch); each met or given-up watch is delivered
func (r *Router) watchTick(now time.Time) {
	if !watchTicking.TryLock() {
		return
	}
	defer watchTicking.Unlock()
	type due struct {
		sid, name string
		armedAt   int64
		deliver   bool
	}
	var items []due
	r.st.Do(func(d *persisted) {
		for sid, s := range d.Schedules {
			ss := d.Sessions[sid]
			if ss == nil || ss.State == "destroyed" || ss.State == "destroying" {
				continue
			}
			for _, w := range s.Watches {
				if w.Outcome != "" {
					items = append(items, due{sid, w.Name, w.ArmedAt, true})
				} else if w.NextAt <= now.UnixMilli() {
					items = append(items, due{sid, w.Name, w.ArmedAt, false})
				}
			}
		}
	})
	for _, it := range items {
		key := it.sid + "/watch/" + it.name
		if !schedRun.claim(key, now) {
			continue
		}
		watchWG.Add(1)
		go func() {
			defer watchWG.Done()
			defer schedRun.release(key)
			if it.deliver {
				r.deliverWatch(it.sid, it.name, it.armedAt, key)
			} else {
				r.checkWatch(it.sid, it.name, it.armedAt, key)
			}
		}()
	}
}

// watchOf: a copy of the armed watch, if it is still the one armed at armedAt
func (r *Router) watchOf(sid, name string, armedAt int64) *Watch {
	var w *Watch
	r.st.Do(func(d *persisted) {
		if s := d.Schedules[sid]; s != nil && s.Watches[name] != nil && s.Watches[name].ArmedAt == armedAt {
			c := *s.Watches[name]
			w = &c
		}
	})
	return w
}

func (r *Router) checkWatch(sid, name string, armedAt int64, key string) {
	w := r.watchOf(sid, name, armedAt)
	if w == nil || w.Outcome != "" {
		return
	}
	res, err := runCheckHook(w)
	now := time.Now()
	outcome := ""
	switch {
	case err == nil && res.Exit == 0:
		outcome = "met"
	case err == nil && res.Exit == 3:
		outcome = "gave-up"
	case now.UnixMilli() >= w.ArmedAt+w.MaxSeconds*1000:
		outcome = "gave-up"
	}
	r.st.Do(func(d *persisted) {
		s := d.Schedules[sid]
		if s == nil || s.Watches[name] == nil || s.Watches[name].ArmedAt != armedAt {
			return // cancelled or replaced meanwhile
		}
		cur := s.Watches[name]
		cur.Runs++
		cur.LastRunAt, cur.NextAt = now.UnixMilli(), now.Add(time.Duration(cur.Interval)*time.Second).UnixMilli()
		if err != nil {
			cur.LastError, cur.LastExit = err.Error(), nil
		} else {
			x := res.Exit
			cur.LastExit, cur.LastError, cur.LastOutput = &x, lastLineOf(res.Stderr), trimTo(res.Stdout, watchKeepOutput)
			if res.TimedOut {
				cur.LastError = "the check timed out after 90 s"
			}
		}
		cur.Outcome = outcome
	})
	switch {
	case outcome != "":
		log.Printf("[watch] %s %q %s after %d checks", sid, name, outcome, w.Runs+1)
		r.deliverWatch(sid, name, armedAt, key) // now rather than at the next tick
	case err != nil:
		log.Printf("[watch] %s %q: %v", sid, name, err)
	case res.Exit != 1 || res.TimedOut || strings.TrimSpace(res.Stderr) != "":
		log.Printf("[watch] %s %q not yet (exit %d%s) %s", sid, name, res.Exit, map[bool]string{true: ", timed out"}[res.TimedOut], trimTo(lastLineOf(res.Stderr), 160))
	}
}

func (r *Router) deliverWatch(sid, name string, armedAt int64, key string) {
	w := r.watchOf(sid, name, armedAt)
	if w == nil || w.Outcome == "" {
		return
	}
	kind := "watch"
	if w.Outcome == "gave-up" {
		kind = "watch-fail"
	}
	err := errNotVouched
	if w.Signed != nil {
		err = deliverVouchedHook(r, sid, Delivery{Kind: kind, Request: w.Signed})
	}
	if err == nil {
		schedRun.forget(key)
		log.Printf("[watch] %s %q delivered (%s)", sid, name, kind)
		r.st.Do(func(d *persisted) {
			if s := d.Schedules[sid]; s != nil && s.Watches[name] != nil && s.Watches[name].ArmedAt == armedAt {
				delete(s.Watches, name)
			}
		})
		return
	}
	if errors.Is(err, errSkip) {
		return
	}
	drop := schedRun.failed(key, time.Now())
	log.Printf("[watch] %s %q delivery failed (drop=%v): %v", sid, name, drop, err)
	r.st.Do(func(d *persisted) {
		if s := d.Schedules[sid]; s != nil && s.Watches[name] != nil && s.Watches[name].ArmedAt == armedAt {
			s.Watches[name].LastError = trimTo("delivery: "+err.Error(), 300)
		}
	})
	if drop {
		r.st.Do(func(d *persisted) {
			if s := d.Schedules[sid]; s != nil && s.Watches[name] != nil && s.Watches[name].ArmedAt == armedAt {
				delete(s.Watches, name)
			}
		})
		label := sid
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[sid]; s != nil {
				label = sessionTitle(*s)
			}
		})
		r.DM(fmt.Sprintf("Watch “%s” of session “%s” (%s) could not be delivered after %d attempts: %s", name, label, w.Outcome, scheduleMaxAttempt, trimTo(err.Error(), 300)))
	}
}

// ---- routes ------------------------------------------------------------------------------------------------

func (r *Router) registerWatches(app appRoute, m machineRoute) {
	app("GET /api/sessions/{id}/watches", func(w http.ResponseWriter, req *http.Request) { r.getWatches(w, req.PathValue("id")) })
	app("DELETE /api/sessions/{id}/watches/{name}", func(w http.ResponseWriter, req *http.Request) {
		r.deleteWatch(w, req.PathValue("id"), req.PathValue("name"))
	})
	// arming from the app: nothing would vouch for its delivery into the session (only the session's own request does)
	app("POST /api/sessions/{id}/watches", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, 400, map[string]string{"error": "a watch is armed by the session itself (scripts/schedule-watch.sh): only its own signed request can be delivered into it"})
	})
	own := func(pattern string, fn func(w http.ResponseWriter, req *http.Request, sid string, body []byte)) {
		m(pattern, func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
			sid, err := r.machineSession(machine)
			if err != nil {
				writeJSON(w, 403, map[string]string{"error": err.Error()})
				return
			}
			if id := req.PathValue("id"); id != sid {
				writeJSON(w, 403, map[string]string{"error": fmt.Sprintf("this machine is session %s, not %s", sid, id)})
				return
			}
			fn(w, req, sid, body)
		})
	}
	own("GET /m/api/sessions/{id}/watches", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) { r.getWatches(w, sid) })
	own("POST /m/api/sessions/{id}/watches", func(w http.ResponseWriter, req *http.Request, sid string, b []byte) {
		m, err := decodeBody(b)
		if err != nil {
			scheduleErr(w, err)
			return
		}
		wt, err := normalizeWatch(m, time.Now())
		if err == nil {
			wt.Signed = signedRequestOf(req, req.Header.Get("X-Machine"), b)
			err = r.ArmWatch(sid, wt)
		}
		if err != nil {
			scheduleErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "watch": watchView(wt)})
	})
	own("DELETE /m/api/sessions/{id}/watches/{name}", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		r.deleteWatch(w, sid, req.PathValue("name"))
	})
}

func (r *Router) getWatches(w http.ResponseWriter, sid string) {
	out, err := r.ListWatches(sid)
	if err != nil {
		scheduleErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"watches": out})
}

func (r *Router) deleteWatch(w http.ResponseWriter, sid, name string) {
	if !scheduleNameRE.MatchString(name) {
		writeJSON(w, 400, map[string]string{"error": "bad watch name"})
		return
	}
	if err := r.CancelWatch(sid, name); err != nil {
		scheduleErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
