package main

// The kernel's health, for a router that runs no core (NO_CORE=1, Jarvis 4): what the app's Sessions page warns about
// in place of the old "Core not answering". Every replica checks it on its own (read-only: GET /roster on each
// component of both copies), every kernelHealthEvery, and GET /api/state carries the last answer:
//
//	"kernel": {"checked": true, "healthy": false, "problems": ["notary-blue not answering", …], "at": …,
//	           "copies": {"blue": {"serving": true, "components": {"notary-blue": "ok", …}}, "green": {…}}}
//
// Healthy means: this box has a kernel, the root key has signed a roster, it isn't stale, every component of the
// serving copy answers and holds exactly that roster, and no copy flip is waiting (kernelflip.go). The other copy is
// shown as it is: idle between releases (its Deployments scaled to zero: "down"), or, once a release landed on it,
// holding its own roster ("ok" against the other copy's roster while it takes over). GET /api/kernel carries the same
// under "health".

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DE0CH/jarvis4/kernel/sig"
)

// KernelHealth: the last check
type KernelHealth struct {
	Healthy  bool                  `json:"healthy"`
	Problems []string              `json:"problems"`
	At       time.Time             `json:"at"`
	Copies   map[string]copyHealth `json:"copies"`
}

// copyHealth: one copy as the check found it: each Deployment "ok" (holds the copy's roster), "down", "none" (no
// roster) or "other" (another roster)
type copyHealth struct {
	Serving    bool              `json:"serving"`
	Roster     string            `json:"roster,omitempty"` // the ID of the roster it should hold ("" = none: idle)
	Components map[string]string `json:"components"`
}

var kernelHealthEvery = 15 * time.Second

// kernelHealthLoop: checks now, then every `every`
func (r *Router) kernelHealthLoop(every time.Duration) {
	for {
		r.kernelHealthCheck()
		time.Sleep(every)
	}
}

// kernelHealthCheck: checks the kernel once and keeps the answer
func (r *Router) kernelHealthCheck() *KernelHealth {
	probs, copies := r.kernelProblems()
	h := &KernelHealth{Problems: probs, At: time.Now().UTC(), Copies: copies}
	h.Healthy = len(h.Problems) == 0
	r.kernelHealthNow.Store(h)
	return h
}

// kernelProblems: what is wrong with the kernel right now, each a short plain sentence (none: healthy), and both
// copies as the check found them
func (r *Router) kernelProblems() ([]string, map[string]copyHealth) {
	if r.kernel == nil {
		return []string{"No kernel on this box"}, nil
	}
	probs := []string{}
	cur := r.currentRoster()
	serving := r.servingCopy()
	var stale []string
	pending := false
	waiting := ""
	r.st.Do(func(p *persisted) {
		pending = p.KernelRosterPending != nil
		if c := p.KernelRoster; c != nil {
			for dep := range c.Stale {
				stale = append(stale, dep)
			}
		}
		if f := p.KernelFlip; f != nil && f.Waiting != "" {
			waiting = "Kernel flip to " + f.To + " waiting: " + f.Waiting
		}
	})
	sort.Strings(stale)
	switch {
	case cur == nil && pending:
		probs = append(probs, "Kernel roster waiting for your signature")
	case cur == nil:
		probs = append(probs, "No signed kernel roster")
	case len(stale) > 0:
		probs = append(probs, "Kernel roster stale: "+strings.Join(stale, ", ")+" restarted")
	}
	if waiting != "" {
		probs = append(probs, waiting)
	}

	copies := map[string]copyHealth{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, c := range kernelCopies {
		rc := r.rosterOfCopy(c)
		var want *sig.Doc
		ch := copyHealth{Serving: c == serving, Components: map[string]string{}}
		if rc != nil {
			d := rc.doc()
			want, ch.Roster = &d, d.ID()
		}
		copies[c] = ch
		for _, dep := range rosterTargets(c) {
			wg.Add(1)
			go func(c, dep string, want *sig.Doc) {
				defer wg.Done()
				st := r.kernelRosterHeld(dep, want)
				if st == "" {
					st = "ok"
				}
				mu.Lock()
				copies[c].Components[dep] = st
				mu.Unlock()
			}(c, dep, want)
		}
	}
	wg.Wait()
	by := map[string][]string{}
	for dep, st := range copies[serving].Components {
		if st != "ok" {
			by[st] = append(by[st], dep)
		}
	}
	for _, s := range []string{"down", "none", "other"} {
		deps := by[s]
		if len(deps) == 0 {
			continue
		}
		sort.Strings(deps)
		names := strings.Join(deps, ", ")
		switch s {
		case "down":
			if len(deps) == len(kernelRoles) {
				probs = append(probs, "No kernel component answering")
			} else {
				probs = append(probs, names+" not answering")
			}
		case "none":
			if cur != nil { // without a signed roster, holding none is expected (said above)
				probs = append(probs, names+" holding no roster")
			}
		case "other":
			probs = append(probs, names+" not holding the current roster")
		}
	}
	return probs, copies
}

// kernelRosterHeld: one component's GET /roster against cur: "" (answers and holds cur, or holds a roster while none
// is signed), "down" (no answer, or not a roster), "none" (it holds no roster), "other" (another roster)
func (r *Router) kernelRosterHeld(dep string, cur *sig.Doc) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", r.kernel.url(dep)+"/roster", nil)
	if err != nil {
		return "down"
	}
	resp, err := r.kernel.http.Do(req)
	if err != nil {
		return "down"
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		if strings.Contains(string(b), "no roster yet") {
			return "none"
		}
		return "down"
	}
	var held sig.Doc
	if json.Unmarshal(b, &held) != nil || held.Payload == "" {
		return "down"
	}
	if cur != nil && held.Payload != cur.Payload {
		return "other"
	}
	return ""
}

// kernelHealthView: the last check as the app reads it ({"checked": false} before the first)
func (r *Router) kernelHealthView() map[string]any {
	h := r.kernelHealthNow.Load()
	if h == nil {
		return map[string]any{"checked": false, "healthy": false, "problems": []string{}}
	}
	return map[string]any{"checked": true, "healthy": h.Healthy, "problems": h.Problems, "at": h.At, "copies": h.Copies}
}

// GET /api/state's "kernel": only on a router that runs no core, where it replaces core.up as what the app warns about
func init() {
	stateHooks = append(stateHooks, func(r *Router, out map[string]any) {
		if r != nil && r.cfg.NoCore {
			out["kernel"] = r.kernelHealthView()
		}
	})
}
