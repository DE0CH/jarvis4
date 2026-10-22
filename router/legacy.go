package main

// Sessions of an earlier core (core/legacy.go; Deyao, 2026-10-15: the release of core continuity must not end the
// sessions running on the random-key core before it). A session whose cert the running core's key didn't sign, but
// whose core a master-signed claim the router kept names (core-certs.json), is taken over by the running core at its
// machine's kill: the kill carries the earlier cert and that claim (`legacy`), and the core answers the same cert
// signed by itself (`adopted`), which becomes the session's cert. A running one is taken over when it pauses; a paused
// one at once (corechange.go). The earlier core's carry blob doesn't open on the new core, so the first resume waits
// for one unlock of the session's stores; the router files that Inbox request itself (noteSecretsPull).

import (
	"encoding/json"
	"log"
	"time"
)

// claimOfSigner: the kept master-signed claim naming a core whose key signed this document (nil: none)
func (r *Router) claimOfSigner(doc *Doc) *MasterCert {
	if doc == nil {
		return nil
	}
	claimDeviceMu.Lock()
	list := []MasterCert{}
	if b, ok := r.st.ReadDoc("core-certs.json"); ok {
		json.Unmarshal(b, &list)
	}
	claimDeviceMu.Unlock()
	for i := range list {
		var st struct {
			Core     struct{ SigningKey string }  `json:"core"`
			Identity *struct{ SigningKey string } `json:"identity"`
		}
		if json.Unmarshal([]byte(list[i].Statement), &st) != nil {
			continue
		}
		if verifyP256(st.Core.SigningKey, []byte(doc.Payload), doc.Sig) ||
			st.Identity != nil && verifyP256(st.Identity.SigningKey, []byte(doc.Payload), doc.Sig) {
			return &list[i]
		}
	}
	return nil
}

// legacyFor: the kill's `legacy` for a machine whose cert the running core (key) didn't sign; nil when it did, or
// when no kept claim names the core that did
func (r *Router) legacyFor(machine, key string) map[string]any {
	var cert *Doc
	r.st.Do(func(d *persisted) { cert = d.Certs[machine] })
	if cert == nil || key == "" || verifyP256(key, []byte(cert.Payload), cert.Sig) {
		return nil
	}
	mc := r.claimOfSigner(cert)
	if mc == nil {
		return nil
	}
	return map[string]any{"cert": cert, "coreCert": mc}
}

// adopted: the kill's answer took the machine's line over: its cert (the same payload, the running core's signature)
// replaces the earlier one, and the session's first resume will wait for an unlock (CarryLost)
func (r *Router) adopted(machine string, kd *Doc) {
	var k struct {
		Adopted *Doc `json:"adopted"`
	}
	if kd == nil || kd.Decode(&k) != nil || k.Adopted == nil {
		return
	}
	r.st.Do(func(d *persisted) {
		old := d.Certs[machine]
		if old == nil || old.Payload != k.Adopted.Payload {
			return
		}
		d.Certs[machine] = k.Adopted
		for _, s := range d.Sessions {
			if s.Cert != nil && s.Cert.Payload == k.Adopted.Payload {
				s.Cert, s.OldCore, s.CarryLost = k.Adopted, false, true
				if s.Error == legacyWaitText {
					s.Error = ""
				}
				log.Printf("session %s: its line was taken over by the running core at %s's kill", s.ID, machine)
			}
		}
	})
}

const legacyWaitText = "this session's line is an earlier core's: the running core takes it over at its pause"

// adoptPaused: a paused session of an earlier core, taken over now (its machine is long gone; the kill names the
// snapshot its machine signed, which the router keeps)
var adoptTried = map[string]time.Time{}

func (r *Router) adoptPaused(id string) {
	var machine string
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[id]; s != nil && s.State == "paused" && s.Cert != nil {
			var c struct {
				Machine *struct {
					ID string `json:"id"`
				} `json:"machine"`
			}
			s.Cert.Decode(&c)
			if c.Machine != nil {
				machine = c.Machine.ID
			}
		}
	})
	if machine == "" {
		return
	}
	oldCoreMu.Lock()
	recent := time.Since(adoptTried[id]) < 10*time.Minute
	if !recent {
		adoptTried[id] = time.Now()
	}
	oldCoreMu.Unlock()
	if recent {
		return
	}
	if _, err := r.killMachine(machine, false); err != nil {
		log.Printf("session %s (an earlier core's, paused): taking its line over: %v", id, err)
		return
	}
}

// keepRunningClaim: the router keeps the master-signed claim of the running core (it keeps every claim it passes on;
// a core claimed before the router did answers its own GET /core-cert), so a later core can take its lines over
func (r *Router) keepRunningClaim(key string) {
	claimDeviceMu.Lock()
	list := []MasterCert{}
	if b, ok := r.st.ReadDoc("core-certs.json"); ok {
		json.Unmarshal(b, &list)
	}
	claimDeviceMu.Unlock()
	for _, mc := range list {
		var st struct {
			Core     struct{ SigningKey string }  `json:"core"`
			Identity *struct{ SigningKey string } `json:"identity"`
		}
		if json.Unmarshal([]byte(mc.Statement), &st) == nil && (st.Core.SigningKey == key || st.Identity != nil && st.Identity.SigningKey == key) {
			return
		}
	}
	status, b, err := r.core.Raw("GET", "/core-cert", nil)
	if err != nil || status != 200 {
		return
	}
	var mc MasterCert
	var st struct {
		Kind   string                      `json:"kind"`
		Master string                      `json:"master"`
		Core   struct{ SigningKey string } `json:"core"`
	}
	if json.Unmarshal(b, &mc) != nil || json.Unmarshal([]byte(mc.Statement), &st) != nil || st.Kind != "claim" || st.Core.SigningKey != key ||
		!verifyP256(st.Master, []byte(mc.Statement), mc.MasterSig) {
		return
	}
	r.keepCoreCert(b)
	log.Printf("kept the running core's claim (%.16s…), for a later core to take its sessions over", key)
}
