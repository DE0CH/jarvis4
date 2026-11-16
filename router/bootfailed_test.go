package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/doc"
)

// a machine that refuses to start fails its session with the machine's reason (2026-11-16: a restore that ran out of
// disk left the session "initialising" with no error for good). The machine is kept, the line's last snapshot is not
// lost: Resume kills the machine that never booted and the next one restores that snapshot. A report from a machine
// that has booted, or from one the session has moved on from, changes nothing.
func TestAMachineThatRefusesToStartFailsItsSession(t *testing.T) {
	rg, k := kernelRig(t)
	dms := captureDM(t)
	l := &kernelLineT{t: t, rg: rg, k: k, sid: kernelStart(t, rg, k, "refuses to start")}
	h := rg.r.MachineHandler()
	const why = "snapshot: write /data/home/claude/.claude/projects/x.jsonl: no space left on device"
	failed := func(who string, code int, body []byte) bool {
		t.Helper()
		if code != 200 {
			t.Fatalf("%s: POST /m/boot-failed: %d %s", who, code, body)
		}
		return strings.Contains(string(body), "true")
	}
	m1 := l.next("the machine")
	if code, body := kdo(t, h, m1, "POST", "/m/pull-secrets", "{}"); code != 200 {
		t.Fatal(code, string(body))
	}
	l.booted(m1)
	// a machine that has booted: its session is not failed by such a report
	code, body := kdo(t, h, m1, "POST", "/m/boot-failed", `{"error":"x"}`)
	if failed("a booted machine", code, body) || kernelSession(rg, l.sid).State != "started" {
		t.Fatalf("a booted machine's report failed the session: %s", kernelSession(rg, l.sid).State)
	}
	tarball := makeTar(t, rg.files)
	sum := sha256.Sum256(tarball)
	want := hex.EncodeToString(sum[:])
	snapSig, _ := m1.Sig.Sign([]byte(want))
	putSnap(t, rg.r, m1.ID, tarball, snapSig)
	l.pause()
	l.resume()
	m2 := l.next("the second machine")
	if st := kernelSession(rg, l.sid).State; st != "initialising" {
		t.Fatalf("the session before the report: %s", st)
	}
	// the killed first machine's report is refused (its key is no longer a machine's of the line that runs)
	if code, body := kdo(t, h, m1, "POST", "/m/boot-failed", `{"error":"x"}`); code == 200 && strings.Contains(string(body), "true") {
		t.Fatalf("a killed machine's report failed the session: %d %s", code, body)
	}
	// the second machine's restore runs out of disk: it refuses to start and says why
	code, body = kdo(t, h, m2, "POST", "/m/boot-failed", `{"error":"`+why+`"}`)
	if !failed("the machine that refused", code, body) {
		t.Fatalf("the report changed nothing: %s", body)
	}
	s := kernelSession(rg, l.sid)
	if s.State != "failed" || !strings.Contains(s.Error, why) || !strings.Contains(s.Error, m2.ID) || s.MachineID != m2.ID {
		t.Fatalf("the session after the report: %s %q on %q", s.State, s.Error, s.MachineID)
	}
	if k.Fly.Machine(m2.ID).State == "destroyed" {
		t.Fatal("the machine that refused to start was destroyed")
	}
	if got := dms(); len(got) != 1 || !strings.Contains(got[0], why) {
		t.Fatalf("the DMs: %q", got)
	}
	// a second report (the boot steps tell it more than once when the answer is lost) changes and DMs nothing
	code, body = kdo(t, h, m2, "POST", "/m/boot-failed", `{"error":"again"}`)
	if failed("the second report", code, body) || len(dms()) != 1 || !strings.Contains(kernelSession(rg, l.sid).Error, why) {
		t.Fatalf("a second report: %s, DMs %q", body, dms())
	}
	// Resume: the machine that never booted is killed with nothing to snapshot, into a source that names the first
	// machine's snapshot still, and the third machine restores it
	l.resume()
	m3 := l.next("the third machine")
	if k.Fly.Machine(m2.ID).State != "destroyed" {
		t.Fatal("the machine that refused to start is still there after the resume")
	}
	ks := kernelSession(rg, l.sid)
	sc, _ := doc.PeekCert(*ks.Kernel.SourceCert)
	if sc.Source.Snapshot != want || ks.NoSnapshot != "" || ks.Error != "" {
		t.Fatalf("the line after the resume: %+v %q %q", sc.Source, ks.NoSnapshot, ks.Error)
	}
	if code, body := kdo(t, h, m3, "GET", "/m/snapshot", ""); code != 200 || string(body) != string(tarball) {
		t.Fatalf("the third machine's snapshot: %d", code)
	}
}
