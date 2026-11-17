package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// neverBootedLine: a kernel line paused with a snapshot and resumed: its second machine is up, has its cert and has
// not booted (the session initialising), as the WeChat warm-up session's machine was on 2026-11-17
func neverBootedLine(t *testing.T, label string) (*kernelLineT, string) {
	t.Helper()
	rg, k := kernelRig(t)
	l := &kernelLineT{t: t, rg: rg, k: k, sid: kernelStart(t, rg, k, label)}
	h := rg.r.MachineHandler()
	m1 := l.next("the machine")
	if code, body := kdo(t, h, m1, "POST", "/m/pull-secrets", "{}"); code != 200 {
		t.Fatal(code, string(body))
	}
	l.booted(m1)
	tarball := makeTar(t, rg.files)
	sum := sha256.Sum256(tarball)
	snapSig, _ := m1.Sig.Sign([]byte(hex.EncodeToString(sum[:])))
	putSnap(t, rg.r, m1.ID, tarball, snapSig)
	l.pause()
	l.resume()
	m2 := l.next("the second machine")
	if code, body := kdo(t, h, m2, "POST", "/m/pull-secrets", "{}"); code != 200 {
		t.Fatal(code, string(body))
	}
	r := rg.r
	r.st.Do(func(d *persisted) { d.Sessions[l.sid].State = "initialising" }) // its secrets came, its boot never ended
	return l, m2.ID
}

// a machine on an image older than POST /m/boot-failed still logs "REFUSING TO START: …": that line fails the session
// with the reason
func TestARefusingToStartLogLineFailsTheSession(t *testing.T) {
	dms := captureDM(t)
	l, m2 := neverBootedLine(t, "refusal in the log")
	h := l.rg.r.MachineHandler()
	const why = "snapshot: bytes 687865856-704643071: stream error: stream ID 97; CANCEL; received from peer"
	body := `{"lines":[{"at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","text":"boot: restore: downloading done"},` +
		`{"at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","text":"boot: REFUSING TO START: ` + why + `"}]}`
	if code, out := kdo(t, h, l.k.Fly.Machine(m2), "POST", "/m/supervisor-log", body); code != 200 {
		t.Fatal(code, string(out))
	}
	s := kernelSession(l.rg, l.sid)
	if s.State != "failed" || !strings.Contains(s.Error, why) || s.MachineID != m2 {
		t.Fatalf("the session after the line: %s %q on %q", s.State, s.Error, s.MachineID)
	}
	if got := dms(); len(got) != 1 || !strings.Contains(got[0], why) {
		t.Fatalf("the DMs: %q", got)
	}
}

// a machine that has its cert and then neither boots nor logs anything fails its session after lcBootMax; one that
// keeps logging (a slow restore), or waits on a locked store, does not
func TestAMachineThatNeverBootsFailsItsSession(t *testing.T) {
	dms := captureDM(t)
	l, m2 := neverBootedLine(t, "never boots")
	r := l.rg.r
	first := map[string]time.Time{}
	t0 := time.Now().Add(time.Hour) // past every line the rig's machines logged
	r.neverBootedTick(t0, first)
	if st := kernelSession(l.rg, l.sid).State; st != "initialising" {
		t.Fatalf("failed at once: %s", st)
	}
	// a locked store: the machine waits for Deyao, not stuck
	r.st.Do(func(d *persisted) { d.Sessions[l.sid].LockedStore = "infra" })
	r.neverBootedTick(t0.Add(2*lcBootMax), first)
	if st := kernelSession(l.rg, l.sid).State; st != "initialising" {
		t.Fatalf("a machine waiting on a locked store was failed: %s", st)
	}
	r.st.Do(func(d *persisted) { d.Sessions[l.sid].LockedStore = "" })
	first = map[string]time.Time{}
	r.neverBootedTick(t0, first)
	// a slow restore logs its progress: not failed
	if err := r.appendSupLog(l.sid, m2, []SupLine{{At: t0.Add(lcBootMax - time.Minute).UTC().Format(time.RFC3339Nano), Text: "boot: restore: downloading 97%"}}); err != nil {
		t.Fatal(err)
	}
	r.neverBootedTick(t0.Add(lcBootMax+time.Minute), first)
	if st := kernelSession(l.rg, l.sid).State; st != "initialising" {
		t.Fatalf("a machine still logging was failed: %s", st)
	}
	// silent for lcBootMax since its last line: failed, the machine kept
	r.neverBootedTick(t0.Add(2*lcBootMax), first)
	s := kernelSession(l.rg, l.sid)
	if s.State != "failed" || !strings.Contains(s.Error, "never booted") || s.MachineID != m2 {
		t.Fatalf("the session: %s %q on %q", s.State, s.Error, s.MachineID)
	}
	if l.k.Fly.Machine(m2).State == "destroyed" {
		t.Fatal("the machine was destroyed")
	}
	if got := dms(); len(got) != 1 {
		t.Fatalf("the DMs: %q", got)
	}
	if len(first) != 0 {
		t.Fatalf("machines still counted: %v", first)
	}
}
