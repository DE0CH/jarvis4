package main

// A machine that refuses to start says so (2026-11-16: a machine whose restore ran out of disk logged "REFUSING TO
// START: snapshot: write …: no space left on device" and its session showed "initialising" with no error for good:
// only a machine that boots reports anything, and the harness check (autopilot.go) looks at booted machines only).
//
//	POST /m/boot-failed   {error}: the machine's boot steps ended without a harness (machine/main.go prepareCmd).
//	                      Its session becomes failed with the reason; the machine is kept, as after any failure
//	                      that leaves one: its supervisor still answers, Resume finishes its pause first (a
//	                      machine that never got past boot is killed with no snapshot, and the next one restores
//	                      the snapshot the line's source names, kernelline.go), More disk and Destroy as for any
//	                      failed session with a machine. Only from the session's current machine, before its
//	                      first status report, while the session is initialising or started; else nothing changes.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// bootFailedText: the failed session's error
func bootFailedText(machine, reason string) string {
	reason = strings.Join(strings.Fields(reason), " ")
	if r := []rune(reason); len(r) > 500 {
		reason = string(r[:500]) + "…"
	}
	if reason == "" {
		reason = "no reason given"
	}
	return fmt.Sprintf("machine %s refused to start: %s. Its machine is kept; Resume starts the session again on a new machine.", machine, reason)
}

// bootFailed: fail the machine's session with its reason and DM once → whether it did. The start's operation, still
// waiting for the machine's first report, ends failed with the reason (lifecycle.go lcAwaitBoot); once that is over,
// the event stream gets the failure's own line (failures.go)
func (r *Router) bootFailed(machine, reason string) bool {
	text := bootFailedText(machine, reason)
	sid, name := "", ""
	r.st.Do(func(d *persisted) {
		s := d.Sessions[d.Machines[machine]]
		if s == nil || s.MachineID != machine || s.Booted == machine || !(s.State == "initialising" || s.State == "started") {
			return
		}
		s.State, s.Error = "failed", text
		sid, name = s.ID, sessionName(s, nil)
	})
	if sid == "" {
		return false
	}
	log.Printf("session %s: failed: %s", sid, text)
	r.DM(fmt.Sprintf("🔴 Session “%s” didn't come up: %s", name, text))
	return true
}

func (r *Router) registerBootFailed(m machineRoute) {
	m("POST /m/boot-failed", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in struct{ Error string }
		json.Unmarshal(body, &in)
		writeJSON(w, 200, map[string]bool{"ok": r.bootFailed(machine, in.Error)})
	})
}
