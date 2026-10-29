package main

// A handover starts the next machine while the old one is still going (Deyao, 2026-10-19: "you can start a new
// machine before the old machine has completely shut down, as reported by Fly, as long as the stop command has been
// sent"; DECISIONS 193).
//
// A session moving to a new machine (Upgrade, Restart, More disk, Resume of a failed session that still has its
// machine) used to run strictly in a row: the final snapshot, the kill until Fly reported the old machine destroyed,
// then the core's start of the new one (a Fly create, the image pull and boot, init) and its cert. Now the router asks
// the core for the new machine (a SPARE) the moment the old one has been told to stop: the supervisor's "snapshot"
// command (it stops the Claude process and freezes the session before the snapshot), or "free" for an Upgrade, or
// the kill itself when no snapshot needs asking for. The spare's create, pull and boot run while the old machine
// snapshots and Fly destroys it.
//
// What still waits, and why (each is something the new machine depends on):
//   - The cert. A machine without a cert has no secrets, no snapshot and no session identity: it boots, prints its
//     keys and waits (machine/main.go prepare, up to ~10 min). The core certifies a successor only once its
//     predecessor is killed, and a kill is Fly-confirmed destroyed with the final snapshot named (core/core.go
//     Certify, Kill). So the snapshot the new machine restores is always the old machine's final one, never an
//     older one, and the old machine can no longer write state, pull secrets, register the tunnel, hold the Remote
//     Control entry or use a lease once the new one has its identity. Moving that line is a core change.
//   - The spare matches what the start would ask for (image, size, disk) or it isn't used: a start the phone
//     approves (a newer image, a resume prompt, another permission mode) gets its own machine, and the spare goes.
//   - A spare that isn't taken (the pause kept the machine, the resume went to the phone, nothing came within
//     spareMaxAge, so the machine's own wait for its cert could run out) is killed in the background; Fly's org
//     machine cap counts it until then (lessons/58). A spare never waits out the machine cap: at the cap it gives up
//     and the start makes its machine after the kill, as before.

import (
	"errors"
	"log"
	"slices"
	"sync"
	"time"
)

// nextMachine: what the handover's start will ask the core for (startAndCertify: the approval's image, the session's
// size, region and disk)
type nextMachine struct {
	Image  string
	Size   string // "" = medium
	Region string // regions.go: the session's region
	DiskGB int
}

func (n nextMachine) same(o nextMachine) bool {
	return n.Image == o.Image && orStr(n.Size, "medium") == orStr(o.Size, "medium") && n.Region == o.Region && n.DiskGB == o.DiskGB
}

type spare struct {
	want    nextMachine
	done    chan struct{} // closed once the start ended
	doc     *Doc          // the core's signed "started" document
	id      string        // the machine, once the core's Fly create made it
	err     error
	readyAt time.Time
	mu      sync.Mutex
}

func (sp *spare) machine() string { sp.mu.Lock(); defer sp.mu.Unlock(); return sp.id }

// spareMaxAge: how long a started spare may wait for its cert. The machine asks for it 300 times 2 s apart
// (machine/main.go prepare) and refuses to start after that, so a spare older than this is killed, not certified.
var spareMaxAge = 8 * time.Minute

// spareStarted: tests learn when a spare's start began (nil in production)
var spareStarted func(sid string)

// handoverNext: the machine an unattended resume of the session will start (the dead-machine rule: the cert's own
// image), or nil when the resume goes to the phone anyway (a newer image, a resume prompt or rollback, another
// permission mode, the Claude login's legacy image): those start their own machine after Deyao's approval.
func (r *Router) handoverNext(s Session, size string, diskGB int) *nextMachine {
	if s.Cert == nil {
		return nil
	}
	own := certImage(s.Cert, s.Image)
	if (slices.Contains(s.Stores, "claude") && legacyLoginImage(own, r.cfg.ImageOrder)) || r.resumeOnce(&s) != "" || certMode(s.Cert) != normMode(s.PermissionMode) {
		return nil
	}
	if size == "" {
		size = s.Size
	}
	if diskGB == 0 {
		diskGB = s.DiskGB
	}
	return &nextMachine{Image: own, Size: size, Region: r.regionOf(&s), DiskGB: diskGB}
}

// launchSpare: the core's start of the next machine, in the background. A spare for the same machine already under
// way stays; one for another is dropped.
func (r *Router) launchSpare(sid string, want *nextMachine) {
	if want == nil {
		return
	}
	sp := &spare{want: *want, done: make(chan struct{})}
	if old, ok := r.spares.Load(sid); ok {
		if old.(*spare).want.same(*want) {
			return
		}
		if r.spares.CompareAndDelete(sid, old) {
			r.dropSpare(sid, old.(*spare), "the handover asks for another machine now")
		}
	}
	if _, loaded := r.spares.LoadOrStore(sid, sp); loaded {
		return // another launch won the race for the same session
	}
	r.lcNote(sid, "", "the old machine has been told to stop: starting the next machine now ("+orStr(want.Size, "medium")+"); it gets its cert once the old one is killed")
	if spareStarted != nil {
		spareStarted(sid)
	}
	go func() {
		defer close(sp.done)
		d, err := r.startMachineWith(want.Image, want.Size, want.Region, want.DiskGB, func(id string) {
			sp.mu.Lock()
			sp.id = id
			sp.mu.Unlock()
			r.lcNote(sid, id, "the core's Fly create made the next machine "+id+" (spare); it boots while the old one stops")
		}, false)
		sp.mu.Lock()
		sp.doc, sp.err, sp.readyAt = d, err, time.Now()
		sp.mu.Unlock()
		if err != nil {
			log.Printf("session %s: the spare's start: %v (the start after the kill makes the machine)", sid, err)
			r.lcNote(sid, "", "the spare's start failed ("+err.Error()+"): the start after the kill makes the machine")
			r.spares.CompareAndDelete(sid, sp)
			return
		}
		// not taken in time: its machine would stop waiting for a cert, so it goes
		time.AfterFunc(spareMaxAge, func() {
			if r.spares.CompareAndDelete(sid, sp) {
				r.dropSpare(sid, sp, "not taken within "+waitText(spareMaxAge))
			}
		})
	}()
}

// takeSpare: the started spare for this start (its "started" document), or nil: none, another machine, a failed
// start, or too old (those are dropped). Waits for a spare still starting.
func (r *Router) takeSpare(sid string, want nextMachine) *Doc {
	v, ok := r.spares.LoadAndDelete(sid)
	if !ok {
		return nil
	}
	sp := v.(*spare)
	if !sp.want.same(want) {
		r.dropSpare(sid, sp, "the start asks for another machine")
		return nil
	}
	<-sp.done
	sp.mu.Lock()
	doc, err, at := sp.doc, sp.err, sp.readyAt
	sp.mu.Unlock()
	if err != nil || doc == nil {
		return nil
	}
	if time.Since(at) > spareMaxAge {
		r.dropSpare(sid, sp, "it waited too long for its cert")
		return nil
	}
	return doc
}

// cancelSpare: the handover ends without a start on this router's side (the pause kept the machine, the resume went
// to the phone): the spare goes
func (r *Router) cancelSpare(sid, why string) {
	if v, ok := r.spares.LoadAndDelete(sid); ok {
		r.dropSpare(sid, v.(*spare), why)
	}
}

// dropSpare: kill the spare's machine in the background, once its start has ended (Fly's org machine cap counts it
// until then: lessons/58)
func (r *Router) dropSpare(sid string, sp *spare, why string) {
	go func() {
		<-sp.done
		sp.mu.Lock()
		doc, err := sp.doc, sp.err
		sp.mu.Unlock()
		if err != nil || doc == nil {
			return // nothing made, or startMachineWith killed what it made
		}
		var st struct {
			Machine *Started `json:"machine"`
		}
		doc.Decode(&st)
		id := sp.machine()
		if st.Machine != nil && st.Machine.ID != "" {
			id = st.Machine.ID
		}
		if id == "" {
			return
		}
		r.lcNote(sid, id, "the spare machine "+id+" isn't used ("+why+"): asking the core to destroy it")
		if _, err := r.killUntilDestroyed(map[string]any{"machine": id}); err != nil {
			log.Printf("session %s: the unused spare %s: kill: %v (the Machines tab lists it)", sid, id, err)
		}
	}()
}

// handoverResume: a handover's resume right after its pause (waitState has seen the pause end and its lock go). An
// action that took the session in between (a wakeup's resume) can still hold it: it tries again for a while.
func (r *Router) handoverResume(id, prompt string, upgrade bool) error {
	err := errBusy
	for end := time.Now().Add(30 * time.Second); errors.Is(err, errBusy) && time.Now().Before(end); {
		if err = r.resumeWithPrompt(id, upgrade, prompt); errors.Is(err, errBusy) {
			time.Sleep(opsPoll)
		}
	}
	return err
}
