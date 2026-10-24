package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/kerneltest"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// signRoster: the copy's roster as the setup session files it and Deyao signs it, taken by the router
func signRoster(t *testing.T, rg *rig, k *kerneltest.Kernel, copy string) map[string]any {
	t.Helper()
	d, err := k.RosterFor(copy)
	if err != nil {
		t.Fatal(err)
	}
	out, code, err := rg.r.takeRoster(d.Payload, d.Sig)
	if err != nil {
		t.Fatal(code, err)
	}
	return out
}

// a kernel release never interrupts anything: a live session on blue; a release onto green; green's roster signed
// (one Face ID) and the router flips by itself — every blue component hands over and freezes, green's notarizer,
// spawner and secrets take over, every call goes to green; the session's machine, booted on blue, reads its documents
// (blue's grant, certs and notarizations under green's roster) and pulls its secrets; it pauses (green's spawner kills
// the machine blue's made), resumes onto a new machine and pulls; a new session starts; and a router that restarted
// mid-flip carries the flip on from where it was kept
func TestAKernelReleaseFlipsWithoutInterruption(t *testing.T) {
	rg, k := kernelRig(t)
	t.Cleanup(pulledMachines.Clear) // the fake Fly's ids repeat across tests: this test's pulls would make others wait bootGrace
	sid := kernelStart(t, rg, k, "lives through a release")
	waitFor(t, "the machine", func() bool { s := kernelSession(rg, sid); return s.MachineID != "" && s.Kernel.MachineCert != nil })
	m1 := k.Fly.Machine(kernelSession(rg, sid).MachineID)
	h := rg.r.MachineHandler()
	if code, body := kdo(t, h, m1, "POST", "/m/pull-secrets", "{}"); code != 200 {
		t.Fatal(code, string(body))
	}
	blueGrant := *kernelSession(rg, sid).Kernel.Grant

	k.Release(t)
	out := signRoster(t, rg, k, "green")
	if out["flip"] != "green" {
		t.Fatalf("the green roster didn't start the flip: %v", out)
	}
	waitFor(t, "the flip", func() bool { return rg.r.servingCopy() == "green" })
	k.Serve("green") // (kerneltest's view follows the router's)
	var rest *KernelFlip
	var cur *RosterCurrent
	rg.r.st.Do(func(p *persisted) { rest, cur = p.KernelFlip, p.KernelRoster })
	if rest != nil || cur == nil || cur.Copy != "green" {
		t.Fatalf("after the flip: %+v %+v", rest, cur)
	}
	for _, dep := range []string{"notarizer-blue", "spawner-blue", "mover-blue"} {
		if _, err := k.Post(dep, "/identity", nil); err != nil {
			continue
		}
		if _, err := k.Post(dep, map[string]string{"notarizer-blue": "/notarize", "spawner-blue": "/init", "mover-blue": "/move"}[dep], map[string]any{}); err == nil || !strings.Contains(err.Error(), "handed over") {
			t.Fatalf("%s after the flip: %v", dep, err)
		}
	}

	// the live machine: its documents check against green's roster, and it pulls
	code, body := kdo(t, h, m1, "GET", "/m/kernel/boot", "")
	var boot struct {
		Grant  gv.Signed    `json:"grant"`
		Roster *sig.Doc     `json:"roster"`
		Notary sig.Identity `json:"notary"`
	}
	if code != 200 || json.Unmarshal(body, &boot) != nil || boot.Roster == nil || boot.Roster.Payload != cur.Payload || boot.Notary != k.Identity("notary") {
		t.Fatal(code, string(body))
	}
	if g, err := gv.Open(boot.Grant, k.Trust()); err != nil || g.Machine != doc.Object("fly-"+m1.ID) {
		t.Fatal("blue's grant under green's roster:", err)
	}
	if code, body := kdo(t, h, m1, "POST", "/m/pull-secrets", "{}"); code != 200 {
		t.Fatal("a pull after the flip:", code, string(body))
	}

	// pause and resume on green
	tarball := makeTar(t, rg.files)
	sum := sha256.Sum256(tarball)
	snapSig, _ := m1.Sig.Sign([]byte(hex.EncodeToString(sum[:])))
	putSnap(t, rg.r, m1.ID, tarball, snapSig)
	if err := rg.r.Pause(sid); err != nil {
		t.Fatal(err)
	}
	if err := rg.r.waitActionEnd(sid, "paused"); err != nil {
		t.Fatal(err, kernelSession(rg, sid).Error)
	}
	if m1.State != "destroyed" {
		t.Fatal("blue's machine wasn't killed by green's spawner")
	}
	if g := kernelSession(rg, sid).Kernel.Grant; g == nil || g.Signer.SigningKey == blueGrant.Signer.SigningKey {
		t.Fatal("the paused line's grant isn't green's mover's")
	}
	if err := rg.r.Resume(sid, false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the second machine", func() bool {
		s := kernelSession(rg, sid)
		return s.MachineID != "" && s.MachineID != m1.ID && s.Kernel.MachineCert != nil
	})
	m2 := k.Fly.Machine(kernelSession(rg, sid).MachineID)
	if code, body := kdo(t, h, m2, "GET", "/m/snapshot", ""); code != 200 || string(body) != string(tarball) {
		t.Fatalf("the predecessor's snapshot: %d", code)
	}
	if code, body := kdo(t, h, m2, "POST", "/m/pull-secrets", "{}"); code != 200 {
		t.Fatal("the resumed machine's pull:", code, string(body))
	}

	// a new session starts on green
	sid2 := kernelStart(t, rg, k, "after the release")
	waitFor(t, "the new session's machine", func() bool { s := kernelSession(rg, sid2); return s.MachineID != "" && s.Kernel.MachineCert != nil })

	// the next release lands on blue. The router died mid-flip: green's notarizer and spawner had handed over and blue's
	// notarizer had taken over, but only the two handoffs were kept. The kept flip carries on: a try that can't reach
	// secrets-blue keeps what it did; the next finishes (blue's notarizer answers the same handoff again)
	k.Release(t)
	d, _ := k.RosterFor("blue")
	var ro sig.Roster
	json.Unmarshal([]byte(d.Payload), &ro)
	if len(ro.Retired) < 2*8 {
		t.Fatalf("blue's roster retires green's members and the keys green still needs: %d", len(ro.Retired))
	}
	rg.r.st.Do(func(p *persisted) {
		p.KernelRosterNext = &RosterCurrent{Copy: "blue", Payload: d.Payload, Sig: d.Sig, Results: rg.r.distributeRoster(d, "blue")}
	})
	hn, err := k.Post("notarizer-green", "/handoff", map[string]any{"roster": d})
	if err != nil {
		t.Fatal(err)
	}
	hs, err := k.Post("spawner-green", "/handoff", map[string]any{"roster": d})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Post("notarizer-blue", "/takeover", map[string]any{"handoff": hn}); err != nil {
		t.Fatal(err)
	}
	rg.r.st.Do(func(p *persisted) {
		p.KernelFlip = &KernelFlip{To: "blue", Roster: d.ID(), Handoffs: map[string]sig.Doc{"notarizer": hn, "spawner": hs}, Taken: map[string]bool{}}
	})
	var down atomic.Bool
	down.Store(true)
	base := rg.r.kernel.url
	rg.r.kernel.url = func(dep string) string {
		if dep == "secrets-blue" && down.Load() {
			return "http://127.0.0.1:1"
		}
		return base(dep)
	}
	if err := rg.r.kernelFlipRun(); err == nil || !strings.Contains(err.Error(), "secrets-blue") {
		t.Fatal("the flip went through without secrets-blue:", err)
	}
	var kept KernelFlip
	rg.r.st.Do(func(p *persisted) { kept = *p.KernelFlip })
	if len(kept.Handoffs) != len(kernelRoles) || !kept.Taken["notarizer"] || !kept.Taken["spawner"] || kept.Taken["secrets"] ||
		rg.r.servingCopy() != "green" || kept.Waiting == "" {
		t.Fatalf("the failed try: %+v", kept)
	}
	down.Store(false)
	if err := rg.r.kernelFlipRun(); err != nil {
		t.Fatal("the flip carried on:", err)
	}
	if rg.r.servingCopy() != "blue" {
		t.Fatal("blue doesn't serve")
	}
	k.Serve("blue")
	if code, body := kdo(t, h, m2, "POST", "/m/pull-secrets", "{}"); code != 200 {
		t.Fatal("a pull after the second flip:", code, string(body))
	}
	snapSig2, _ := m2.Sig.Sign([]byte(hex.EncodeToString(sum[:])))
	putSnap(t, rg.r, m2.ID, tarball, snapSig2)
	if err := rg.r.Pause(sid); err != nil {
		t.Fatal(err)
	}
	if err := rg.r.waitActionEnd(sid, "paused"); err != nil {
		t.Fatal("a pause after the second flip:", err, kernelSession(rg, sid).Error)
	}
}

// ✱ a roster of the copy that doesn't serve that doesn't retire the serving copy's members, or names no empty secrets
// to take over, starts nothing; a serving component that restarted after the roster was read stops the flip before
// anything froze
func TestAFlipRefusesARosterThatCantTakeOver(t *testing.T) {
	rg, k := kernelRig(t)
	k.Release(t)
	green := k.Copies["green"]
	keep := green.Retired()
	green.SetRetired(nil)
	d, _ := k.RosterFor("green")
	if _, code, err := rg.r.takeRoster(d.Payload, d.Sig); err == nil || code != 403 || !strings.Contains(err.Error(), "retires every serving member") {
		t.Fatal(code, err)
	}
	green.SetRetired(keep)
	k.Restart(t, "merger") // blue's merger restarts after green's roster was read
	green.SetRetired(keep)
	d, _ = k.RosterFor("green")
	if _, _, err := rg.r.takeRoster(d.Payload, d.Sig); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the flip's wait", func() bool {
		w := ""
		rg.r.st.Do(func(p *persisted) {
			if p.KernelFlip != nil {
				w = p.KernelFlip.Waiting
			}
		})
		return strings.Contains(w, "merger-blue restarted")
	})
	var f KernelFlip
	rg.r.st.Do(func(p *persisted) { f = *p.KernelFlip })
	if len(f.Handoffs) != 0 || rg.r.servingCopy() != "blue" {
		t.Fatalf("something froze: %+v", f)
	}
}
