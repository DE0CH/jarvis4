package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"
)

func TestMachineSignatureForAnotherService(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	r.st.Do(func(d *persisted) { d.Sessions["sA"].Harness = "aviary" })
	m := newTestMachine(r, "mA")
	now := time.Now()
	body := []byte(`{"session":"sA"}`)
	sum := sha256.Sum256(body)
	sign := func(method, path string, at time.Time) machineSigRequest {
		ts := strconv.FormatInt(at.Unix(), 10)
		sig, _ := signP256(m.key, []byte(method+" "+path+" "+ts+" "+hex.EncodeToString(sum[:])))
		return machineSigRequest{Machine: "mA", Method: method, Path: path, Time: ts, BodySha256: hex.EncodeToString(sum[:]), Sig: sig}
	}

	sid, harness, state, why := r.checkMachineSignature(sign("POST", "/jarvis/boot", now), now)
	if sid != "sA" || harness != "aviary" || state != "started" || why != "" {
		t.Fatalf("a good signature: %q %q %q %q", sid, harness, state, why)
	}
	// the signed path is part of it: another path does not verify
	bad := sign("POST", "/jarvis/boot", now)
	bad.Path = "/jarvis/other"
	if sid, _, _, _ := r.checkMachineSignature(bad, now); sid != "" {
		t.Fatal("a signature over another path verified")
	}
	// a body other than the signed one
	bad = sign("POST", "/jarvis/boot", now)
	bad.BodySha256 = hex.EncodeToString(make([]byte, 32))
	if sid, _, _, _ := r.checkMachineSignature(bad, now); sid != "" {
		t.Fatal("a signature over another body verified")
	}
	// too old
	if sid, _, _, why := r.checkMachineSignature(sign("POST", "/jarvis/boot", now.Add(-3*time.Minute)), now); sid != "" || why != "time too far off" {
		t.Fatalf("an old signature: %q %q", sid, why)
	}
	// a router path is never checked for someone else
	if sid, _, _, why := r.checkMachineSignature(sign("POST", "/m/status", now), now); sid != "" || why == "" {
		t.Fatal("a signature for /m was checked")
	}
	// a machine the router does not know
	unknown := sign("POST", "/jarvis/boot", now)
	unknown.Machine = "mZ"
	if sid, _, _, _ := r.checkMachineSignature(unknown, now); sid != "" {
		t.Fatal("an unknown machine verified")
	}
}
