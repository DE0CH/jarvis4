package main

// A machine that never boots fails its session (2026-11-17: the WeChat warm-up session's cron resume started a machine
// whose restore broke off ("REFUSING TO START: snapshot: … stream error … CANCEL"); the session ran an image from
// before /m/boot-failed, so nothing told the router, the resume's wait was cut off by a router restart, and the session
// showed "initialising" with no error for hours while its later crons did nothing).
//
//   - A supervisor-log line "REFUSING TO START: <why>" from the session's current machine, before its first status
//     report, fails the session as POST /m/boot-failed does (bootfailed.go): the keeper has written that line since
//     long before the report existed, so a session on an older image fails with the reason too.
//   - The leader looks every neverBootedEvery at sessions initialising on a machine that has not booted, waits on no
//     locked store and runs no action of Jarvis's: one whose machine has logged nothing for lcBootMax (counted from
//     the leader first seeing it, when the machine has logged nothing at all) fails with that said. A slow restore
//     logs its progress every 10 s, so only a machine that went silent is failed. Resume then kills the machine with
//     no snapshot and the next one restores the line's last snapshot, as after any refused boot.

import (
	"fmt"
	"strings"
	"time"
)

var neverBootedEvery = 30 * time.Second

const refusingToStart = "REFUSING TO START: "

// refusedInLog: the reason in a supervisor-log line that says the machine refuses to start, "" for any other line
func refusedInLog(text string) string {
	i := strings.Index(text, refusingToStart)
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(text[i+len(refusingToStart):])
}

func (r *Router) neverBootedLoop() {
	first := map[string]time.Time{}
	for {
		awaitLead() // leaderlease.go
		r.neverBootedTick(time.Now(), first)
		time.Sleep(neverBootedEvery)
	}
}

// neverBootedTick: one look. first: machine → when the leader first saw it initialising and not booted (kept between
// looks; a machine no longer a candidate is forgotten)
func (r *Router) neverBootedTick(now time.Time, first map[string]time.Time) {
	type cand struct{ sid, machine string }
	var cands []cand
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if s.State == "initialising" && s.MachineID != "" && s.Booted != s.MachineID && s.LockedStore == "" {
				cands = append(cands, cand{s.ID, s.MachineID})
			}
		}
	})
	keep := map[string]bool{}
	for _, c := range cands {
		keep[c.machine] = true
		if r.busy(c.sid) {
			delete(first, c.machine) // an action of Jarvis's runs: its own wait counts, the count starts after it
			continue
		}
		since, ok := first[c.machine]
		if !ok {
			since = now
			first[c.machine] = now
		}
		for _, l := range r.readSupLog(c.sid) {
			if l.Machine != c.machine {
				continue
			}
			if at, err := time.Parse(time.RFC3339Nano, l.At); err == nil && at.After(since) {
				since = at
			}
		}
		if now.Sub(since) < lcBootMax {
			continue
		}
		r.bootFailed(c.machine, fmt.Sprintf("it never booted and has logged nothing for %s", waitText(lcBootMax)))
		delete(first, c.machine)
	}
	for m := range first {
		if !keep[m] {
			delete(first, m)
		}
	}
}
