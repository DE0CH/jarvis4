package main

// Since core continuity (core/continuity.go, Deyao 2026-10-15) a Recover with the same kit on the new app brings back
// the SAME core (keys derived from the master key, its line state handed back), so its sessions are untouched: only a
// session whose cert the running core's key didn't sign is an earlier core's. That is a core set up without the seed
// (an older app, or before continuity), or one after a Reset (a new master key). For those, what follows still holds.
//
// A new core (a restart, a core/ deploy, a box rebuild; empty, then Reset or Recovered) can't continue the lines of
// the core before it: their certs are signed by the earlier core, its killed/used sets are gone, and the secrets
// they carry (carry.go) were sealed under the earlier core's carry key. Deyao, 2026-10-11: "They are just
// automatically destroyed. Core restart is infrequent enough. No need to engineer around it." So when the router
// sees a new core identity it marks every session that has a line (OldCore) and destroys each one once it is paused,
// the normal way: the archive is kept as a record (Previous), the carry blob and snapshots go, the onDestroy hooks
// clean up (the Discord channel). A running one goes when it next pauses. Restoring one from Previous is an ordinary
// new line approved on the phone.

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

var coreChangeEvery = 30 * time.Second

// a destroy that failed (an archive the Storage Box refused) is tried again 10 minutes later, not every tick
var (
	oldCoreMu    sync.Mutex
	oldCoreTried = map[string]time.Time{}
)

func (r *Router) coreChangeLoop() {
	for {
		awaitLead() // leaderlease.go
		r.coreChangeTick()
		time.Sleep(coreChangeEvery)
	}
}

// coreIdentityKey: the running core's signing key, from an identity whose state document it signed itself ("" when
// the core can't be reached or answers something else: nothing is decided on that)
func (r *Router) coreIdentityKey() string {
	status, b, err := r.core.Raw("GET", "/identity", nil)
	if err != nil || status != 200 {
		return ""
	}
	var id struct {
		SigningKey string `json:"signingKey"`
		State      Doc    `json:"state"`
	}
	if json.Unmarshal(b, &id) != nil || id.SigningKey == "" || !verifyP256(id.SigningKey, []byte(id.State.Payload), id.State.Sig) {
		return ""
	}
	// an empty core (after a restart, before the Recover) shows only the keys it was started with; a core set up from
	// the master key's seed takes other keys at the claim (core/continuity.go), so nothing is decided before it is set up
	var st struct {
		Master string `json:"master"`
	}
	if id.State.Decode(&st) != nil || st.Master == "" {
		return ""
	}
	return id.SigningKey
}

func (r *Router) coreChangeTick() {
	key := r.coreIdentityKey()
	if key == "" {
		return
	}
	r.keepRunningClaim(key) // legacy.go: so its sessions can be taken over by whatever core comes next
	var marked int
	var gone []string
	r.st.Do(func(d *persisted) {
		switch d.CoreKey {
		case key:
		case "":
			d.CoreKey = key // first sight (a router that predates this): the sessions are this core's
		default:
			d.CoreKey = key
			for _, s := range d.Sessions {
				// a cert the new core's key signed is still this core's: a Recover with the same kit is the same core
				// (core/continuity.go), and its sessions go on
				if s.Cert != nil && !s.OldCore && !verifyP256(key, []byte(s.Cert.Payload), s.Cert.Sig) {
					s.OldCore = true
					marked++
				}
			}
		}
		for id, s := range d.Sessions {
			if s.OldCore && s.State == "paused" {
				gone = append(gone, id)
			}
		}
	})
	// legacy.go: a session whose earlier core a kept master-signed claim names isn't destroyed: the running core takes
	// its line over (a paused one now, a running one at its pause); only the rest go as before (a Reset's)
	keep := gone[:0]
	for _, id := range gone {
		var cert *Doc
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[id]; s != nil {
				cert = s.Cert
			}
		})
		if r.claimOfSigner(cert) != nil {
			go r.adoptPaused(id)
			continue
		}
		keep = append(keep, id)
	}
	gone = keep
	if marked > 0 { // (legacy ones are taken over, not destroyed: below)
		log.Printf("a new core (%.16s…): %d session(s) belong to an earlier core: taken over at their pause when a kept claim names that core, else destroyed once paused", key, marked)
	}
	for _, id := range gone {
		oldCoreMu.Lock()
		recent := time.Since(oldCoreTried[id]) < 10*time.Minute
		if !recent {
			oldCoreTried[id] = time.Now()
		}
		oldCoreMu.Unlock()
		if recent {
			continue
		}
		if err := r.destroy(id, destroyOpts{}); err != nil {
			log.Printf("session %s (an earlier core's): destroy: %v", id, err)
		} else {
			log.Printf("session %s (an earlier core's): destroying; Restore it from Previous as a new line", id)
		}
	}
}
