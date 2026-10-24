package main

// The copy flip (docs/PLAN-cluster.md "Releases: the copy flip", DECISIONS 233): a kernel release lands on the copy
// that doesn't serve; the setup session files that copy's roster (its components' fresh keys, the serving copy's
// members as retired, its empty secrets as secretsBoot) and Deyao signs it with one Face ID. Then the router, on its
// own:
//
//  1. checks both copies are where the flip needs them: every component of the other copy holds the new roster
//     (posted again if one lost it), and every serving component is one the new roster retires (else one restarted
//     since the roster was read: a new roster is needed, nothing has frozen);
//  2. with every kernel call held (KernelClient.gate), asks each serving component for its handoff (POST /handoff
//     with the new roster): each freezes; the notarizer, the spawner and secrets seal their state to the other copy;
//  3. gives the other copy's notarizer, spawner and secrets their predecessor's handoff (POST /takeover);
//  4. switches every call to the other copy (persisted.KernelCopy; the new roster becomes the current one) and lets
//     the held calls go.
//
// Each step is kept (persisted.KernelFlip) before the next, and each is safe to repeat (a frozen component answers the
// same handoff again, a component that took a handoff answers it again), so a router that restarts mid-flip carries on
// (kernelFlipLoop). A step that fails ends the try (held calls go, to a copy partly frozen: they fail until the flip
// finishes) and the loop tries again; Deyao gets one DM. After the flip, a setup session commits
// k8s/cluster/kernel/active-kernel.txt and scales the old copy to zero (infra/setup.py kernel-flipped): the router can't
// push, and git is how the cluster changes.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DE0CH/jarvis4/kernel/sig"
)

// KernelFlip: the copy flip under way
type KernelFlip struct {
	To       string             `json:"to"`     // the copy that takes over
	Roster   string             `json:"roster"` // the ID of its roster (persisted.KernelRosterNext)
	Handoffs map[string]sig.Doc `json:"handoffs,omitempty"`
	Taken    map[string]bool    `json:"taken,omitempty"`
	Started  time.Time          `json:"started"`
	Waiting  string             `json:"waiting,omitempty"` // why the last try didn't finish
}

// flipStateful: the components whose state moves (the others only freeze)
var flipStateful = []string{"notarizer", "spawner", "secrets"}

var (
	kernelFlipMu sync.Mutex // one try at a time
	flipDMed     atomic.Bool
	flipEvery    = 30 * time.Second
)

// startFlip: the flip to copy `to`, whose roster (id) Deyao just signed. A newer roster during a flip to the same copy
// (one of its components restarted before taking over) starts the handoffs again for it; the takeovers done stay done
func (r *Router) startFlip(to, roster string) {
	r.st.Do(func(p *persisted) {
		taken := map[string]bool{}
		if f := p.KernelFlip; f != nil && f.To == to {
			taken = boolsClone(f.Taken)
		}
		p.KernelFlip = &KernelFlip{To: to, Roster: roster, Handoffs: map[string]sig.Doc{}, Taken: taken, Started: time.Now().UTC()}
	})
	flipDMed.Store(false)
	log.Printf("kernel: the flip to the %s copy begins", to)
	go r.kernelFlipRun()
}

// kernelFlipLoop: a flip that didn't finish (a failed step, a router restart) is tried again
func (r *Router) kernelFlipLoop() {
	for {
		awaitLead() // leaderlease.go
		pending := false
		r.st.Do(func(p *persisted) { pending = p.KernelFlip != nil })
		if pending && r.kernel != nil {
			if err := r.kernelFlipRun(); err != nil {
				log.Printf("kernel: the flip: %v (tried again in %s)", err, flipEvery)
			}
		}
		time.Sleep(flipEvery)
	}
}

// flipStatus: the flip under way, for the status views (nil: none)
func (r *Router) flipStatus() map[string]any {
	var out map[string]any
	r.st.Do(func(p *persisted) {
		f := p.KernelFlip
		if f == nil {
			return
		}
		handed := []string{}
		for role := range f.Handoffs {
			handed = append(handed, role)
		}
		slices.Sort(handed)
		taken := []string{}
		for role, ok := range f.Taken {
			if ok {
				taken = append(taken, role)
			}
		}
		slices.Sort(taken)
		out = map[string]any{"to": f.To, "roster": f.Roster, "started": f.Started, "handedOver": handed, "tookOver": taken, "waiting": f.Waiting}
	})
	return out
}

func (r *Router) flipWaiting(why string) {
	r.st.Do(func(p *persisted) {
		if p.KernelFlip != nil {
			p.KernelFlip.Waiting = why
		}
	})
	if flipDMed.CompareAndSwap(false, true) {
		r.DM("🔴 Jarvis 4's kernel flip is waiting — " + why + ". The router tries again every 30 s.")
	}
}

// kernelFlipRun: one try at the flip; nil once it finished (or there is none)
func (r *Router) kernelFlipRun() error {
	kernelFlipMu.Lock()
	defer kernelFlipMu.Unlock()
	var f KernelFlip
	var next *RosterCurrent
	have := false
	r.st.Do(func(p *persisted) {
		if p.KernelFlip != nil {
			f, have = *p.KernelFlip, true
			f.Handoffs, f.Taken = mapsClone(p.KernelFlip.Handoffs), boolsClone(p.KernelFlip.Taken)
		}
		if p.KernelRosterNext != nil {
			x := *p.KernelRosterNext
			next = &x
		}
	})
	if !have {
		return nil
	}
	if next == nil || next.Copy != f.To || next.doc().ID() != f.Roster {
		why := "the roster it was started with is gone"
		r.flipWaiting(why)
		return errors.New(why)
	}
	from := otherCopy(f.To)
	if len(f.Handoffs) == 0 {
		if why := r.flipReady(from, next); why != "" {
			r.flipWaiting(why)
			return errors.New(why)
		}
	}
	k := r.kernel
	k.gate.Lock()
	err := r.flipSteps(&f, next.doc(), from)
	if err == nil {
		r.st.Do(func(p *persisted) {
			p.KernelCopy = f.To
			cur := *next
			p.KernelRoster, p.KernelRosterNext, p.KernelFlip = &cur, nil, nil
		})
		k.forgetAll()
		r.kernelTokenDMed.Store(false) // the new spawner has the old one's Fly token
	}
	k.gate.Unlock()
	if err != nil {
		r.flipWaiting(err.Error())
		return err
	}
	log.Printf("kernel: the %s copy serves from now on (the flip took %s); a setup session commits active-kernel.txt (infra/setup.py kernel-flipped)",
		f.To, time.Since(f.Started).Round(time.Second))
	r.kernelHealthCheck()
	return nil
}

// flipReady: "" when the flip can begin: every component of the other copy holds its roster (posted again if one
// lost it), and every serving component is one that roster retires (the serving secrets: the one it names)
func (r *Router) flipReady(from string, next *RosterCurrent) string {
	k := r.kernel
	d := next.doc()
	ro := next.roster()
	for _, dep := range rosterTargets(next.Copy) {
		b, _, err := k.do(dep, dep, "GET", "/roster", nil)
		var held sig.Doc
		if err == nil && json.Unmarshal(b, &held) == nil && held.Payload == d.Payload {
			continue
		}
		if err := k.postRoster(dep, d); err != nil {
			return fmt.Sprintf("%s doesn't hold the %s roster (%v)", dep, next.Copy, err)
		}
	}
	for _, role := range kernelRoles {
		dep := role + "-" + from
		b, _, err := k.do(dep, dep, "GET", "/identity", nil)
		if err != nil {
			return fmt.Sprintf("%s doesn't answer (%v)", dep, err)
		}
		id, err := identityAnswer(dep, b)
		if err != nil {
			return err.Error()
		}
		if role == "secrets" {
			if m, _ := ro.Member("secrets"); m != id {
				return fmt.Sprintf("%s isn't the secrets the %s roster names (Recovered again since it was read?): a new roster is needed", dep, next.Copy)
			}
			continue
		}
		if !slices.Contains(ro.Retired, id) {
			return fmt.Sprintf("%s restarted since the %s roster was read (it doesn't retire its keys): a new roster is needed", dep, next.Copy)
		}
	}
	return ""
}

// identityAnswer: a component's GET /identity answer read (secrets answers its keys in the open; the others a
// self-signed document)
func identityAnswer(dep string, b []byte) (sig.Identity, error) {
	var id sig.Identity
	if copyOf(dep) != "" && dep[:len(dep)-len(copyOf(dep))-1] == "secrets" {
		var m struct{ SigningKey, AgreementKey string }
		if err := json.Unmarshal(b, &m); err != nil {
			return id, fmt.Errorf("%s: bad identity", dep)
		}
		return sig.Identity{Role: "secrets", SigningKey: m.SigningKey, AgreementKey: m.AgreementKey}, nil
	}
	var d sig.Doc
	if err := json.Unmarshal(b, &d); err != nil || json.Unmarshal([]byte(d.Payload), &id) != nil {
		return id, fmt.Errorf("%s: bad identity", dep)
	}
	return id, nil
}

// flipSteps: the handoffs, then the takeovers, each kept before the next (callers hold the gate)
func (r *Router) flipSteps(f *KernelFlip, roster sig.Doc, from string) error {
	k := r.kernel
	for _, role := range kernelRoles {
		if _, ok := f.Handoffs[role]; ok {
			continue
		}
		dep := role + "-" + from
		b, _, err := k.do(dep, dep, "POST", "/handoff", map[string]sig.Doc{"roster": roster})
		if err != nil {
			return fmt.Errorf("%s's handoff: %w", dep, err)
		}
		var d sig.Doc
		if json.Unmarshal(b, &d) != nil || d.Payload == "" {
			return fmt.Errorf("%s's handoff isn't a signed document", dep)
		}
		f.Handoffs[role] = d
		r.st.Do(func(p *persisted) {
			if p.KernelFlip != nil {
				if p.KernelFlip.Handoffs == nil {
					p.KernelFlip.Handoffs = map[string]sig.Doc{}
				}
				p.KernelFlip.Handoffs[role] = d
			}
		})
		log.Printf("kernel: %s handed over to the %s copy", dep, f.To)
	}
	for _, role := range flipStateful {
		if f.Taken[role] {
			continue
		}
		dep := role + "-" + f.To
		if _, _, err := k.do(dep, dep, "POST", "/takeover", map[string]sig.Doc{"handoff": f.Handoffs[role]}); err != nil {
			// secrets keeps nothing on disk: one that restarted before its takeover is Recovered with the kit (the crash
			// path), and then already serves with the keys the roster names
			if role != "secrets" || !r.secretsServesAs(dep, roster) {
				return fmt.Errorf("%s's takeover: %w", dep, err)
			}
			log.Printf("kernel: %s was Recovered with the kit instead of taking the handoff", dep)
		}
		f.Taken[role] = true
		r.st.Do(func(p *persisted) {
			if p.KernelFlip != nil {
				if p.KernelFlip.Taken == nil {
					p.KernelFlip.Taken = map[string]bool{}
				}
				p.KernelFlip.Taken[role] = true
			}
		})
		log.Printf("kernel: %s took over", dep)
	}
	return nil
}

// secretsServesAs: the secrets Deployment serves (set up, not handed off) with the keys the roster names for secrets
func (r *Router) secretsServesAs(dep string, roster sig.Doc) bool {
	b, _, err := r.kernel.do(dep, dep, "GET", "/identity", nil)
	if err != nil {
		return false
	}
	var id struct {
		SigningKey, AgreementKey string
		State                    sig.Doc
	}
	var ro sig.Roster
	if json.Unmarshal(b, &id) != nil || json.Unmarshal([]byte(roster.Payload), &ro) != nil {
		return false
	}
	var st struct{ Master, Serving string }
	m, _ := ro.Member("secrets")
	return m.SigningKey == id.SigningKey && sig.Verify(id.SigningKey, []byte(id.State.Payload), id.State.Sig) &&
		json.Unmarshal([]byte(id.State.Payload), &st) == nil && st.Master != "" && st.Serving == "serving"
}

func mapsClone(m map[string]sig.Doc) map[string]sig.Doc {
	out := map[string]sig.Doc{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func boolsClone(m map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k, v := range m {
		out[k] = v
	}
	return out
}
