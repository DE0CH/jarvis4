package main

// The app's device-key countersignature on a claim (R1 audit 2026-10-11: claim is first-come, so a router or box
// that claims an emptied core with its own master key must not get the setup session's writes). The app sends,
// with POST /api/core/claim, deviceKey (its long-lived Secure Enclave key, kept across Reset and Recover) and
// deviceSig over the exact claim statement. The core ignores both; the router keeps the last few here and serves
// them to the setup session (GET /setup/claim-device), which checks the signature itself against the device key it
// pinned (infra/setup.py). The router can only withhold one, never make one.

import (
	"encoding/json"
	"log"
	"sync"
)

type ClaimDevice struct {
	Statement string `json:"statement"`
	DeviceKey string `json:"deviceKey"`
	DeviceSig string `json:"deviceSig"`
}

var claimDeviceMu sync.Mutex

func (r *Router) claimDevices() []ClaimDevice {
	claimDeviceMu.Lock()
	defer claimDeviceMu.Unlock()
	out := []ClaimDevice{}
	if b, ok := r.st.ReadDoc("claim-device.json"); ok {
		json.Unmarshal(b, &out)
	}
	return out
}

// keepClaimDevice: the countersignature in a claim body, if any (the newest 10 kept)
func (r *Router) keepClaimDevice(body []byte) {
	var in ClaimDevice
	if json.Unmarshal(body, &in) != nil || in.Statement == "" || in.DeviceKey == "" || in.DeviceSig == "" ||
		len(in.Statement) > 8<<10 || len(in.DeviceKey) > 200 || len(in.DeviceSig) > 200 {
		return
	}
	list := r.claimDevices()
	claimDeviceMu.Lock()
	defer claimDeviceMu.Unlock()
	list = append([]ClaimDevice{in}, list...)
	if len(list) > 10 {
		list = list[:10]
	}
	b, _ := json.Marshal(list)
	if err := r.st.WriteDoc("claim-device.json", b); err != nil {
		log.Printf("claim device: %v", err)
	}
}

// ---- the master's signature on the core (R2: kept here, not in the core) ----------------------------------------
//
// A claim the core accepted is the master key's signature over a statement naming the core's keys: it verifies on
// its own, so who stores it doesn't matter. The router keeps the newest few (by the core's signing key) and serves
// the current core's to the setup session (GET /setup/core-cert) and into each archive (archive.go).

type MasterCert struct {
	Statement string `json:"statement"`
	MasterSig string `json:"masterSig"`
}

// keepCoreCert: a claim body the core answered 200
func (r *Router) keepCoreCert(body []byte) {
	var in MasterCert
	if json.Unmarshal(body, &in) != nil || in.Statement == "" || in.MasterSig == "" || len(in.Statement) > 8<<10 {
		return
	}
	claimDeviceMu.Lock()
	defer claimDeviceMu.Unlock()
	list := []MasterCert{}
	if b, ok := r.st.ReadDoc("core-certs.json"); ok {
		json.Unmarshal(b, &list)
	}
	list = append([]MasterCert{in}, list...)
	if len(list) > 10 {
		list = list[:10]
	}
	b, _ := json.Marshal(list)
	if err := r.st.WriteDoc("core-certs.json", b); err != nil {
		log.Printf("core certs: %v", err)
	}
}

// coreCert: the kept claim naming the running core (by its signing key from /identity); nil when none.
// A core claimed before the router kept them (the running core until the next claim) still answers GET /core-cert.
func (r *Router) coreCert() []byte {
	key, err := r.core.Key()
	if err != nil {
		return nil
	}
	claimDeviceMu.Lock()
	list := []MasterCert{}
	if b, ok := r.st.ReadDoc("core-certs.json"); ok {
		json.Unmarshal(b, &list)
	}
	claimDeviceMu.Unlock()
	for _, mc := range list {
		var st struct {
			Core struct {
				SigningKey string `json:"signingKey"`
			} `json:"core"`
			// a claim with the master key's seed names the keys the core takes from it (core/continuity.go)
			Identity *struct {
				SigningKey string `json:"signingKey"`
			} `json:"identity"`
		}
		if json.Unmarshal([]byte(mc.Statement), &st) == nil && (st.Core.SigningKey == key["signingKey"] || st.Identity != nil && st.Identity.SigningKey == key["signingKey"]) {
			b, _ := json.Marshal(mc)
			return b
		}
	}
	if st, b, err := r.core.Raw("GET", "/core-cert", nil); err == nil && st == 200 {
		return b
	}
	return nil
}
