package main

// A session's machine that stopped or went away without Jarvis doing it (2026-10-22: Claude ran `fly machine stop` on
// Jarvis 2's "YYC news monitor 2" after a sync; Jarvis 2 showed it "started, busy" for a long time, then "failed" with
// its machine still listed, and nothing said whether its work was lost).
//
//   - The leader looks at Fly every lostEvery with its read-only token (FLY_READ_TOKEN): a session that Jarvis has
//     running (started or initialising, no action of Jarvis's under way) whose machine Fly shows stopped, suspended,
//     failed or destroyed, or no longer lists, on two looks in a row, is marked lost: state failed, Session.Lost, and an
//     error saying plainly what happened (Fly's own stop or exit event, when), what is kept, and what Resume does. The
//     session's event stream gets it as a "machine lost" operation with Fly's events, and Deyao gets a DM.
//   - Resume of a lost kernel line goes through the kernel like any start: the spawner kills the machine into the
//     line's next source, naming the newest signed snapshot (the machine's own if it sent one, else the one its source
//     named), and a new machine starts from that source, as after a pause. What the session did after that snapshot
//     is lost. A line with no signed snapshot at all is refused (it would start empty), as snapsafe.go refuses. The
//     stopped machine is never started again: its key pair lived in its memory only (DECISIONS 228), so started again
//     it couldn't prove it is the machine its cert names.

import (
	"fmt"
	"log"
	"slices"
	"time"
)

// LostMachine: what became of a session's machine that stopped without Jarvis doing it
type LostMachine struct {
	Machine  string    `json:"machine"`
	At       time.Time `json:"at"`            // when it stopped, by Fly's event (else when the router saw it)
	Seen     time.Time `json:"seen"`          // when the router noticed
	FlyState string    `json:"flyState"`      // stopped | suspended | failed | destroyed | destroying | gone (Fly lists it no more)
	Fly      string    `json:"fly,omitempty"` // Fly's own event for it (the stop or exit)
	Resume   string    `json:"resume"`        // what Resume does, in plain words
}

// lostEvery: how often the leader looks; a machine is lost once it is down on two looks in a row
var lostEvery = 20 * time.Second

// machineDown: a Fly state of a machine that isn't running
func machineDown(state string) bool {
	return slices.Contains([]string{"stopped", "suspended", "failed", "destroyed", "destroying", "gone"}, state)
}

func (r *Router) lostLoop() {
	if machinesFly() == nil {
		log.Printf("[lost] FLY_READ_TOKEN unset: machines stopped outside Jarvis aren't noticed")
		return
	}
	seen := map[string]int{}
	for {
		awaitLead() // leaderlease.go
		r.lostTick(seen)
		time.Sleep(lostEvery)
	}
}

// lostTick: one look at Fly. seen: machine → how many looks in a row found it down (kept between looks)
func (r *Router) lostTick(seen map[string]int) {
	ms, err := listFlyMachines()
	if err != nil {
		log.Printf("[lost] Fly: %v", err)
		return
	}
	state := map[string]string{}
	for _, m := range ms {
		state[m.ID] = m.State
	}
	type cand struct{ sid, machine string }
	var cands []cand
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if s.MachineID != "" && s.Lost == nil && (s.State == "started" || s.State == "initialising") {
				cands = append(cands, cand{s.ID, s.MachineID})
			}
		}
	})
	next := map[string]int{}
	for _, c := range cands {
		st, ok := state[c.machine]
		if !ok {
			st = "gone"
		}
		if !machineDown(st) || r.busy(c.sid) {
			continue
		}
		next[c.machine] = seen[c.machine] + 1
		if next[c.machine] >= 2 {
			r.markLost(c.sid, c.machine, st)
		}
	}
	clear(seen)
	for k, v := range next {
		seen[k] = v
	}
}

// lostEvent: Fly's newest event that took the machine down (exit, stop, destroy), nil when Fly has none
func (r *Router) lostEvent(machine string) *flyEvent {
	if r.lc == nil || r.lc.flyEvents == nil {
		return nil
	}
	evs, err := r.lc.flyEvents(machine)
	if err != nil {
		return nil
	}
	var best *flyEvent
	for i := range evs {
		e := evs[i]
		if !slices.Contains([]string{"exit", "stop", "destroy", "suspend"}, e.Type) && !machineDown(e.Status) {
			continue
		}
		if best == nil || e.Timestamp > best.Timestamp {
			best = &e
		}
	}
	return best
}

// lostResume: what Resume will do for a lost machine, in plain words
func (r *Router) lostResume(sid string, l *LostMachine) string {
	const gone = "The machine isn't started again (its keys were in its memory only). "
	older, _, olderAt := r.latestSnapshot(sid)
	if older == "" {
		return gone + "There is no signed snapshot of the session, so Resume would start it empty and refuses; Destroy archives the live copies of its transcripts."
	}
	return gone + fmt.Sprintf("Resume starts a new machine from the newest signed snapshot (machine %s's, from %s); what the session did after that snapshot is lost.",
		older, olderAt.UTC().Format("2006-01-02 15:04 UTC"))
}

func lostWhat(state string) string {
	switch state {
	case "stopped":
		return "stopped"
	case "suspended":
		return "was suspended"
	case "failed":
		return "failed on Fly"
	case "gone":
		return "is gone from Fly"
	}
	return "was destroyed"
}

// lostText: the session's error for a lost machine
func lostText(l *LostMachine) string {
	msg := fmt.Sprintf("Its machine %s %s outside Jarvis at %s (Jarvis didn't pause or destroy it)", l.Machine, lostWhat(l.FlyState), l.At.UTC().Format("2006-01-02 15:04:05 UTC"))
	if l.Fly != "" {
		msg += "; " + l.Fly
	}
	return msg + ". " + l.Resume
}

// markLost: the session's machine is down and Jarvis didn't take it down: the session says so
func (r *Router) markLost(sid, machine, flyState string) {
	now := time.Now().UTC()
	l := &LostMachine{Machine: machine, At: now, Seen: now, FlyState: flyState}
	if ev := r.lostEvent(machine); ev != nil {
		l.At, l.Fly = time.UnixMilli(ev.Timestamp).UTC(), eventText(*ev)
	}
	l.Resume = r.lostResume(sid, l)
	msg := lostText(l)
	// the operation first, so the failure below is its end, not a second event (failures.go). An operation already
	// running (a boot still waiting for the machine's first report) gets the note, and the loss is its own event.
	h := r.lcCurrent(sid)
	own := h == nil
	if own {
		h = r.lcBegin(sid, "machine-lost")
		h.machine(machine)
	}
	changed := false
	r.st.Do(func(d *persisted) {
		s := d.Sessions[sid]
		if s == nil || s.MachineID != machine || s.Lost != nil || !(s.State == "started" || s.State == "initialising") {
			return
		}
		s.Lost, s.State, s.Error, s.Status, s.Waiting = l, "failed", msg, "", ""
		changed = true
	})
	if !changed { // Jarvis moved on meanwhile (a pause, a destroy)
		if own {
			h.end("done", "")
		}
		return
	}
	log.Printf("session %s: %s", sid, msg)
	h.note(machine, msg)
	if own {
		h.end("failed", msg)
	} else {
		r.lcEnded(sid, "machine-lost", machine, msg)
	}
	r.DM(fmt.Sprintf("🔴 Session “%s” — %s", r.dmName(sid), msg))
}

// kernelResumeLost: a lost kernel line's Resume (run by kernelResume). true: handled (failed with the reason); false:
// the machine is killed into the line's next source and the caller spawns from it.
func (r *Router) kernelResumeLost(s Session, op *lcHandle) bool {
	id, l := s.ID, s.Lost
	m := l.Machine
	op.machine(m)
	op.note(m, "its machine "+lostWhat(l.FlyState)+" outside Jarvis: asked the kernel's spawner to kill it into the line's next source, with the newest signed snapshot")
	snap, err := r.kernelKill(id, m, false)
	if err != nil {
		r.setState(id, "failed", fmt.Sprintf("Resume couldn't take machine %s off the line (%v): Resume tries again.", m, err))
		return true
	}
	now := time.Now().UTC()
	refused := ""
	r.st.Do(func(d *persisted) {
		x := d.Sessions[id]
		if x == nil {
			return
		}
		x.MachineID, x.PausedAt, x.Status, x.Lost = "", &now, "", nil
		if snap == "" && x.Booted == m {
			x.NoSnapshot = fmt.Sprintf("machine %s stopped outside Jarvis and there is no signed snapshot of the session", m)
			refused = x.NoSnapshot
		}
	})
	op.note(m, "the spawner confirmed the machine destroyed; the line's source names snapshot "+orStr(snap, "(none)"))
	if refused != "" {
		r.setState(id, "failed", "resume: "+refused+", so it would start empty: it doesn't")
		return true
	}
	return false
}
