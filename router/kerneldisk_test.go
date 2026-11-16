package main

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/kerneltest"
)

// More disk on a kernel line never asks the old core (it knows none of the kernel's machines: "machine … has no volume
// of this core", and the session kept its disk): the size is the next spawn's. ✱ A running session moves to a new
// machine on the bigger volume (pause and resume); ✱ a failed one whose machine was kept (it refused to start: its
// restore ran out of disk) gets it at the Resume, which is what lets that restore fit.
func TestMoreDiskOnAKernelLineIsTheNextSpawns(t *testing.T) {
	rg, k := kernelRig(t)
	l := &kernelLineT{t: t, rg: rg, k: k, sid: kernelStart(t, rg, k, "more disk")}
	h := rg.r.MachineHandler()
	tarball := makeTar(t, rg.files)
	sum := sha256.Sum256(tarball)
	want := hex.EncodeToString(sum[:])
	up := func(m *kerneltest.FakeMachine) { // booted, with its final snapshot here already (the fake machine takes none)
		t.Helper()
		if code, body := kdo(t, h, m, "POST", "/m/pull-secrets", "{}"); code != 200 {
			t.Fatal(code, string(body))
		}
		l.booted(m)
		s, _ := m.Sig.Sign([]byte(want))
		putSnap(t, rg.r, m.ID, tarball, s)
	}
	volume := func(m string) int {
		gb := 0
		rg.r.st.Do(func(d *persisted) {
			if st := d.Started[m]; st != nil && st.Volume != nil {
				gb = st.Volume.SizeGB
			}
		})
		return gb
	}
	coreAsked := func() bool {
		rg.core.mu.Lock()
		defer rg.core.mu.Unlock()
		return slices.Contains(rg.core.calls, "/extend")
	}
	m1 := l.next("the machine")
	up(m1)
	if gb := volume(m1.ID); gb != defaultDisk {
		t.Fatalf("the first machine's volume: %d GB", gb)
	}
	// running: a new machine on twice the disk
	out, err := rg.r.MoreDisk(l.sid)
	if err != nil || out["started"] != true || out["fromGb"] != defaultDisk || out["toGb"] != 2*defaultDisk {
		t.Fatalf("more disk on the running session: %v %v", out, err)
	}
	m2 := l.next("the machine on the bigger disk")
	if gb := volume(m2.ID); gb != 2*defaultDisk || kernelSession(rg, l.sid).DiskGB != 2*defaultDisk {
		t.Fatalf("the second machine's volume: %d GB (the session's disk: %d)", gb, kernelSession(rg, l.sid).DiskGB)
	}
	if k.Fly.Machine(m1.ID).State != "destroyed" {
		t.Fatal("the machine on the smaller disk is still there")
	}
	if code, body := kdo(t, h, m2, "GET", "/m/snapshot", ""); code != 200 || string(body) != string(tarball) {
		t.Fatalf("the second machine's snapshot: %d", code)
	}
	waitFor(t, "the More disk job's end", func() bool { return !rg.r.busy(l.sid) })
	if coreAsked() {
		t.Fatal("the old core was asked to extend a kernel machine's volume")
	}
	// failed with its machine kept (it refused to start): the bigger disk is the next start's
	if code, body := kdo(t, h, m2, "POST", "/m/boot-failed", `{"error":"snapshot: no space left on device"}`); code != 200 {
		t.Fatal(code, string(body))
	}
	if s := kernelSession(rg, l.sid); s.State != "failed" || s.MachineID != m2.ID {
		t.Fatalf("the session: %s on %q", s.State, s.MachineID)
	}
	out, err = rg.r.MoreDisk(l.sid)
	if err != nil || out["nextStart"] != true || out["toGb"] != 4*defaultDisk || kernelSession(rg, l.sid).DiskGB != 4*defaultDisk {
		t.Fatalf("more disk on the failed session: %v %v (the session's disk: %d)", out, err, kernelSession(rg, l.sid).DiskGB)
	}
	if coreAsked() || k.Fly.Machine(m2.ID).State == "destroyed" {
		t.Fatal("the old core was asked, or the kept machine went")
	}
	l.resume()
	m3 := l.next("the third machine")
	if gb := volume(m3.ID); gb != 4*defaultDisk {
		t.Fatalf("the third machine's volume: %d GB", gb)
	}
}
