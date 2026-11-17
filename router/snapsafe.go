package main

// A pause never loses a session's state (2026-10-15: session sb8e0273d6c308894's final snapshot failed with "no space
// left on device", the machine was destroyed anyway and the resume started with an empty conversation).
//
//   - The machine's final snapshot streams to the router (snapstream.go): it needs no free disk on the machine.
//   - A machine whose final snapshot fails (an error the machine reports, no progress for the stall time, a machine
//     that went silent) is KEPT, never destroyed, with or without a volume (Deyao, 2026-10-21: session
//     sad35945f04b2124d's machine was killed after its snapshot failed): the session goes "failed" with
//     snapshotFailed set, and Deyao gets a "needs you" DM. Pause again retries; Destroy anyway (force) goes on
//     without it.
//   - A machine with a volume (a core with volumes, core/volumes.go) whose kill goes on: the core destroys it and
//     deletes the volume. No volume snapshot is taken (DECISIONS 222): the machine's signed snapshot is the only copy
//     of its state.
//   - A line whose last machine left no signed snapshot (while an earlier machine of it did, or it had booted) is
//     marked noSnapshot: Resume refuses (it would start the session empty), says why on the session, and Deyao gets a
//     DM. Destroy still archives the newest signed snapshot it has (and every live transcript copy
//     it doesn't hold, livearchive.go), never DMs about it, and notes the missing snapshot in the record.
//   - A kill that doesn't finish (the core still can't destroy it after killMax) leaves the session failed with its
//     machine, and DMs too.

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// Volume: a machine's Fly volume as the core's started document names it (core/volumes.go VolumeInfo)
type Volume struct {
	ID     string `json:"id"`
	SizeGB int    `json:"sizeGb"`
	Path   string `json:"path"`
}

// machineVolume: the volume the machine's cert names (nil: a machine of a core without volumes)
func (r *Router) machineVolume(machine string) *Volume {
	var cert *Doc
	var st *Started
	r.st.Do(func(d *persisted) { cert, st = d.Certs[machine], d.Started[machine] })
	if cert != nil {
		var c struct {
			Machine *struct {
				Volume *Volume `json:"volume"`
			} `json:"machine"`
		}
		if cert.Decode(&c) == nil && c.Machine != nil && c.Machine.Volume != nil {
			return c.Machine.Volume
		}
	}
	if st != nil {
		return st.Volume
	}
	return nil
}

// finalSnapshotAndKill: a pause's or destroy's end of a running machine. false: the machine is still there (kept
// after a failed snapshot, or a kill that didn't finish), the session failed with the reason, Deyao DMed.
func (r *Router) finalSnapshotAndKill(id, machine string, force bool) bool {
	return r.finalSnapshotAndKillFor(id, machine, false, force)
}

// finalSnapshotAndKillFor: destroying = a destroy's (archive.go snapshotAndKill: its kill falls back, DECISIONS 181)
func (r *Router) finalSnapshotAndKillFor(id, machine string, destroying, force bool) bool {
	return r.finalSnapshotAndKillWith(id, machine, destroying, force, nil)
}

// finalSnapshotAndKillNext: a pause's end that hands over to next (handover.go; nil = a plain pause)
func (r *Router) finalSnapshotAndKillNext(id, machine string, next *nextMachine) bool {
	return r.finalSnapshotAndKillWith(id, machine, false, false, next)
}

// finalSnapshotAndKillWith: next (a handover's next machine) starts as soon as the old one has been told to stop —
// the snapshot command, or the kill when no snapshot is asked for — and its cert still waits for this kill
// (handover.go). A machine kept here drops it.
func (r *Router) finalSnapshotAndKillWith(id, machine string, destroying, force bool, next *nextMachine) bool {
	stopSent := func() {}
	if next != nil {
		stopSent = sync.OnceFunc(func() { r.launchSpare(id, next) })
	}
	ok := false
	defer func() {
		if !ok && next != nil {
			r.cancelSpare(id, "the old machine was kept")
		}
	}()
	serr := r.lastSnapshotThen(id, machine, stopSent, destroying)
	vol := r.machineVolume(machine)
	if serr != nil && !force {
		r.keepMachine(id, machine, serr)
		return false
	}
	stopSent() // the kill below is the stop when no snapshot was asked for (one already here, or a machine never booted)
	if serr != nil {
		log.Printf("session %s: %s's final snapshot: %v; going on (destroy anyway)", id, machine, serr)
	}
	r.lcNote(id, machine, "asked the core to destroy the machine on Fly")
	if r.isKernelMachine(machine) { // kernelline.go: the spawner kills it into the line's next source
		return r.kernelKillDone(id, machine, destroying, serr, &ok)
	}
	kd, err := r.killMachine(machine, !destroying) // vouch.go: with the snapshot's hash; a pause only with it vouched for
	if err != nil && destroying {
		kd, err = r.destroyKillFallback(id, machine, force, err)
	}
	r.setWaiting(id, "")
	if err != nil {
		r.lcNote(id, machine, "the kill failed: "+err.Error())
		r.killFailed(id, machine, vol != nil, destroying, err)
		if destroying {
			r.st.Do(func(d *persisted) {
				if s := d.Sessions[id]; s != nil {
					s.Error += destroyAnywayHint
				}
			})
		}
		return false
	}
	r.recordKill(id, machine, kd, serr, destroying)
	r.lcNote(id, machine, "the core confirmed the machine destroyed on Fly")
	ok = true
	return true
}

func (r *Router) dmName(id string) string {
	name := id
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[id]; s != nil {
			var g *Registry
			if s.Live != nil {
				g = s.Live.Reg
			}
			name = sessionName(s, g)
		}
	})
	return name
}

// keepMachine: the final snapshot failed: the machine stays (with its volume, if it has one), so nothing is lost
func (r *Router) keepMachine(id, machine string, serr error) {
	msg := fmt.Sprintf("the final snapshot failed (%v): its machine %s is kept, nothing is lost. Pause again once it can snapshot, or Destroy anyway (that drops what changed since its last snapshot)", serr, machine)
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[id]; s != nil {
			s.State, s.Error, s.SnapshotFailed = "failed", msg, serr.Error()
		}
	})
	log.Printf("session %s: %s", id, msg)
	r.DM(fmt.Sprintf("🔴 Session “%s” needs you — its final snapshot failed (%v), so its machine was kept instead of destroyed: nothing is lost. Free what blocks it (or give it more disk), then Pause again; Destroy anyway drops what changed since its last snapshot.", r.dmName(id), serr))
}

// killFailed: the core still refuses or can't finish the kill: the machine (with its volume) stays
func (r *Router) killFailed(id, machine string, hasVolume, destroying bool, err error) {
	what := "its machine is kept"
	if hasVolume {
		what = "its machine and its volume are kept"
	}
	action, retry := "pause", "Pause again to retry"
	if destroying {
		action, retry = "destroy", "Destroy again to retry"
	}
	r.setState(id, "failed", "kill: "+err.Error()+" — "+what+": "+retry)
	r.DM(fmt.Sprintf("🔴 Session “%s” needs you — its %s couldn't finish (%v); %s, nothing was destroyed. %s.", r.dmName(id), action, err, what, retry))
}

// recordKill: the kill's record — a kill that names no snapshot of a line
// that had state marks it noSnapshot (Resume refuses) and DMs. A destroy's kill never DMs: a destroy isn't a resume,
// so there is nothing to refuse; the reason goes into its record (ArchiveInfo.NoSnapshot, the archive's session.json).
func (r *Router) recordKill(id, machine string, kd *Doc, serr error, destroying bool) {
	var k struct {
		Snapshot string `json:"snapshot"`
	}
	if kd != nil {
		kd.Decode(&k)
	}
	older, _, olderAt := r.latestSnapshot(id) // archive.go: the newest signed snapshot the router still holds
	if older == machine {
		older = ""
	}
	reason := ""
	r.st.Do(func(d *persisted) {
		s := d.Sessions[id]
		if s == nil {
			return
		}
		s.SnapshotFailed = ""
		if k.Snapshot != "" || (s.Booted != machine && older == "") {
			s.NoSnapshot, s.noSnapshotDMed = "", false // a snapshot, or a line with no state yet (its first machine never booted)
			return
		}
		why := "it sent none"
		if serr != nil {
			why = serr.Error()
		}
		reason = fmt.Sprintf("machine %s left no snapshot (%s)", machine, why)
		s.NoSnapshot, s.noSnapshotDMed = reason, true
	})
	if reason == "" {
		return
	}
	if destroying {
		log.Printf("session %s: %s; destroying, so the archive notes it (no DM)", id, reason)
		return
	}
	log.Printf("session %s: %s; it won't resume", id, reason)
	r.DM(fmt.Sprintf("🔴 Session “%s” needs you — %s, so it won't resume (it would start empty). %s", r.dmName(id), reason, stateLeft(older, olderAt)))
}

// stateLeft: where the session's last state is, for the DM and the refusal
func stateLeft(older string, olderAt time.Time) string {
	if older == "" {
		return "There is no other copy of its state."
	}
	return fmt.Sprintf("The newest signed snapshot is machine %s's from %s (Destroy archives it).", older, olderAt.UTC().Format("2006-01-02 15:04 UTC"))
}

// resumeRefusal: nil, or why Resume won't start the session (noSnapshot), DMed once per refusal episode
func (r *Router) resumeRefusal(id string) error {
	var reason string
	dm := false
	r.st.Do(func(d *persisted) {
		s := d.Sessions[id]
		if s == nil || s.NoSnapshot == "" {
			return
		}
		reason = s.NoSnapshot
		if !s.noSnapshotDMed {
			s.noSnapshotDMed, dm = true, true
		}
	})
	if reason == "" {
		return nil
	}
	older, _, olderAt := r.latestSnapshot(id)
	msg := fmt.Sprintf("session %s won't resume: its %s, so it would start empty. %s", id, reason, stateLeft(older, olderAt))
	if dm {
		r.DM("🔴 Session “" + r.dmName(id) + "” needs you — a resume was refused: " + msg)
	}
	return fmt.Errorf("%s", msg)
}

// snapshotView: what the final snapshot left behind, in /api/state and the records
func snapshotView(s *Session, v map[string]any) {
	v["noSnapshot"] = nullIfEmpty(s.NoSnapshot)
	v["snapshotFailed"] = nullIfEmpty(s.SnapshotFailed)
}

// destroyKillFallback: a destroy's kill that failed (DECISIONS 181). A refused snapshot claim (a machine from an
// earlier core: this core has no key for it) is killed without the claim, the session marked so its archive says
// so; a kill still failing is no obstacle when Fly no longer has the machine, or with force (the router stops taking
// the machine's calls; it is an orphan on the Machines tab, whose Destroy tries the kill again)
func (r *Router) destroyKillFallback(id, machine string, force bool, err error) (*Doc, error) {
	var kd *Doc
	if refusedSnapshot(err) {
		log.Printf("session %s: the core refused %s's snapshot (%v): killed without it (a destroy restores nothing)", id, machine, err)
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				x.SnapshotNote = snapshotFromEarlierCore
			}
		})
		if kd, err = r.killUntilDestroyed(map[string]any{"machine": machine}); err == nil {
			return kd, nil
		}
	}
	gone, ferr := flyMachineGone(machine)
	switch {
	case ferr == nil && gone:
		log.Printf("session %s: the kill of %s failed (%v) but Fly has no such machine: destroying on", id, machine, err)
		return nil, nil
	case force:
		log.Printf("session %s: the kill of %s failed (%v): destroyed anyway; the machine is left to the Machines tab", id, machine, err)
		r.st.Do(func(d *persisted) { delete(d.Started, machine) })
		return nil, nil
	}
	return nil, err
}
