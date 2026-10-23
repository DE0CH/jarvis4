package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/kerneltest"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

const kernelImage = "ghcr.io/de0ch/jarvis4-session:sha-aaaaaaaaaaaa@sha256:1111111111111111111111111111111111111111111111111111111111111111"

// kernelRig: the archive rig with the real kernel beside the fake core, its root grant in, new sessions on it
func kernelRig(t *testing.T) (*rig, *kerneltest.Kernel) {
	rg := newRig(t)
	k := kerneltest.Start(t, map[string]string{"JARVIS2_URL": "http://router"})
	rg.r.wireKernel(&KernelClient{url: func(role string) string {
		if role == "secrets-blue" {
			return k.URLFor("secrets")
		}
		return k.URLFor(role)
	}, http: http.DefaultClient, ids: map[string]sig.Identity{}})
	rg.r.cfg.SessionImage, rg.r.cfg.Region = kernelImage, "lhr"
	rg.r.policy.Harnesses["claude"] = HarnessPolicy{}
	rg.r.st.Do(func(d *persisted) { d.KernelRoot = &gv.Signed{Grant: k.RootTop(), By: "root"} })
	return rg, k
}

// kdo: a request signed by a kernel machine's key, as the supervisor signs it (machine/main.go client.raw)
func kdo(t *testing.T, h http.Handler, m *kerneltest.FakeMachine, method, path, body string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256([]byte(body))
	s, _ := m.Sig.Sign([]byte(method + " " + path + " " + ts + " " + hex.EncodeToString(sum[:])))
	req.Header.Set("X-Machine", m.ID)
	req.Header.Set("X-Time", ts)
	req.Header.Set("X-Sig", s)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code, w.Body.Bytes()
}

func kernelSession(rg *rig, sid string) Session {
	var s Session
	rg.r.st.Do(func(d *persisted) {
		if x := d.Sessions[sid]; x != nil {
			s = *x
		}
	})
	return s
}

// a kernel line's life through the router and the real kernel: the phone signs the source, a machine is spawned and
// reads its boot documents, pulls its secrets, pauses into a source holding its snapshot, resumes from it (the new
// machine restores the old one's snapshot), and the destroy archives it and burns its source
func TestAKernelLinesLife(t *testing.T) {
	rg, k := kernelRig(t)
	sid, err := rg.r.CreateSession(NewSession{Label: "on the kernel", Harness: "claude"})
	if err != nil {
		t.Fatal(err)
	}
	var a *Approval
	waitFor(t, "the approval", func() bool {
		rg.r.st.Do(func(d *persisted) {
			for _, x := range d.Approvals {
				if x.Session == sid {
					a = x
				}
			}
		})
		return a != nil
	})
	if a.Kind != kernelApprovalKind {
		t.Fatalf("approval %s", a.Kind)
	}
	var c doc.Cert
	if err := json.Unmarshal([]byte(a.Challenge.Payload), &c); err != nil || c.Pred != doc.Sink || c.Source.Image != kernelImage {
		t.Fatal(err, c)
	}
	var settings struct {
		Harness, PermissionMode string
	}
	json.Unmarshal(c.Source.Settings, &settings)
	if settings.Harness != "claude" || settings.PermissionMode != "bypass" || c.Pair.Conditions[0] != "session:"+sid {
		t.Fatalf("%s %+v", c.Source.Settings, c.Pair)
	}
	signature, _ := k.Phone.Sign([]byte(a.Challenge.Payload))
	if _, _, err := rg.r.Respond(a.ID, signature); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the machine", func() bool { s := kernelSession(rg, sid); return s.MachineID != "" && s.Kernel.MachineCert != nil })
	s := kernelSession(rg, sid)
	m1 := k.Fly.Machine(s.MachineID)
	h := rg.r.MachineHandler()
	code, body := kdo(t, h, m1, "GET", "/m/kernel/boot", "")
	var boot struct {
		Grant gv.Signed `json:"grant"`
	}
	if code != 200 || json.Unmarshal(body, &boot) != nil {
		t.Fatal(code, string(body))
	}
	g, err := gv.Open(boot.Grant, k.Trust())
	if err != nil || g.Machine != doc.Object("fly-"+m1.ID) || g.Keys.SigningKey != m1.Sig.PublicKey() {
		t.Fatal(err, g)
	}
	if code, body := kdo(t, h, m1, "POST", "/m/pull-secrets", "{}"); code != 200 || !strings.Contains(string(body), "secrets") {
		t.Fatal(code, string(body))
	}
	if st := kernelSession(rg, sid).State; st != "started" {
		t.Fatalf("state %s", st)
	}
	// add-store: the phone signs both certs; the store's grant, moved onto the machine, merges with the main one
	aid, err := rg.r.addStoreApproval(m1.ID, "extra", Origin{}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var add *Approval
	rg.r.st.Do(func(d *persisted) { add = d.Approvals[aid] })
	if add == nil || add.Kind != kernelAddApprovalKind {
		t.Fatalf("%+v", add)
	}
	s1, _ := k.Phone.Sign([]byte(add.Challenge.Payload))
	s2, _ := k.Phone.Sign([]byte(add.Earlier[0].Payload))
	if _, _, err := rg.r.Respond(aid, s1+"\n"+s2); err != nil {
		t.Fatal(err)
	}
	g, err = gv.Open(*kernelSession(rg, sid).Kernel.Grant, k.Trust())
	if err != nil || !g.Pair.Allowed.Contains("store:extra") || g.Machine != doc.Object("fly-"+m1.ID) {
		t.Fatal(err, g)
	}
	// downgrade: the identity signer narrows the grant to what is kept
	if code, body := kdo(t, h, m1, "POST", "/m/kernel/downgrade", `{"keep":[]}`); code != 200 {
		t.Fatal(code, string(body))
	}
	g, err = gv.Open(*kernelSession(rg, sid).Kernel.Grant, k.Trust())
	if err != nil || g.Pair.Allowed.Contains("store:extra") || g.Machine != doc.Object("fly-"+m1.ID) {
		t.Fatal(err, g)
	}
	// pause: the machine's signed snapshot is here; the spawner kills it into a source holding its hash
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
	s = kernelSession(rg, sid)
	sc, _ := doc.PeekCert(*s.Kernel.SourceCert)
	if sc.Pred != doc.Object("fly-"+m1.ID) || sc.Source.Snapshot != hex.EncodeToString(sum[:]) || s.Kernel.Grant == nil || s.NoSnapshot != "" {
		t.Fatalf("%+v %q", sc, s.NoSnapshot)
	}
	if m1.State != "destroyed" {
		t.Fatal("the old machine is still there")
	}
	// resume: a new machine from that source restores m1's snapshot
	if err := rg.r.Resume(sid, false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the second machine", func() bool {
		s := kernelSession(rg, sid)
		return s.MachineID != "" && s.MachineID != m1.ID && s.Kernel.MachineCert != nil
	})
	m2 := k.Fly.Machine(kernelSession(rg, sid).MachineID)
	code, body = kdo(t, h, m2, "GET", "/m/snapshot", "")
	if code != 200 || string(body) != string(tarball) {
		t.Fatalf("the predecessor's snapshot: %d", code)
	}
	// ✱ the first machine is gone: its calls are refused
	if code, _ := kdo(t, h, m1, "GET", "/m/kernel/boot", ""); code == 200 {
		t.Fatal("a killed machine read the line's documents")
	}
	// destroy: archived, the source burned (a second spawn from it would be refused by the notarizer)
	if err := rg.r.Destroy(sid); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the record", func() bool {
		gone := false
		rg.r.st.Do(func(d *persisted) { gone = d.Sessions[sid] == nil })
		return gone
	})
	rec := rg.r.record(sid)
	if rec == nil || rec.Archive == nil || rec.Archive.Signer != m1.ID {
		t.Fatalf("the archive: %+v", rec)
	}
	// restore: a new kernel line whose source names the archived snapshot's hash (the phone signs it); its first
	// machine gets that snapshot
	nsid, err := rg.r.RestoreRecord(sid, "")
	if err != nil {
		t.Fatal(err)
	}
	var ra *Approval
	waitFor(t, "the restore's approval", func() bool {
		rg.r.st.Do(func(d *persisted) {
			for _, x := range d.Approvals {
				if x.Session == nsid {
					ra = x
				}
			}
		})
		return ra != nil
	})
	var rc doc.Cert
	if ra == nil || ra.Kind != kernelApprovalKind || json.Unmarshal([]byte(ra.Challenge.Payload), &rc) != nil || rc.Source.Snapshot != hex.EncodeToString(sum[:]) {
		t.Fatalf("%+v", ra)
	}
	rsig, _ := k.Phone.Sign([]byte(ra.Challenge.Payload))
	if _, _, err := rg.r.Respond(ra.ID, rsig); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the restored machine", func() bool {
		s := kernelSession(rg, nsid)
		return s.MachineID != "" && s.Kernel != nil && s.Kernel.MachineCert != nil
	})
	m3 := k.Fly.Machine(kernelSession(rg, nsid).MachineID)
	if code, body := kdo(t, h, m3, "GET", "/m/snapshot", ""); code != 200 || string(body) != string(tarball) {
		t.Fatalf("the archived snapshot: %d", code)
	}
}

// ✱ without the root grant, new sessions stay on the old core
func TestNoKernelRootNoKernelSessions(t *testing.T) {
	rg, _ := kernelRig(t)
	rg.r.st.Do(func(d *persisted) { d.KernelRoot = nil })
	sid, err := rg.r.CreateSession(NewSession{Label: "x", Harness: "claude"})
	if err != nil {
		t.Fatal(err)
	}
	if kernelSession(rg, sid).Kernel != nil {
		t.Fatal("a kernel line without the root's grant")
	}
}

// blue/green for the kernel's secrets: the standby (Recovered alongside with the same kit) takes the serving one's final
// state and serves; the old one answers nothing more; the router's secrets calls go to the new colour
func TestKernelSecretsFlip(t *testing.T) {
	rg, k := kernelRig(t)
	blue, ub := k.Secrets2(t)
	green, ug := k.Secrets2(t)
	seed := make([]byte, 32)
	rand.Read(seed)
	if err := k.ClaimSeeded(blue, seed, false); err != nil {
		t.Fatal(err)
	}
	if err := k.ClaimSeeded(green, seed, true); err != nil {
		t.Fatal(err)
	}
	rg.r.kernel.url = func(role string) string {
		switch role {
		case "secrets-blue":
			return ub
		case "secrets-green":
			return ug
		}
		return k.URLFor(role)
	}
	if _, err := rg.r.kernel.Doc("secrets", "/keys", map[string]any{}); err != nil {
		t.Fatal("blue doesn't serve:", err)
	}
	if _, err := rg.r.kernel.Doc("secrets-next", "/keys", map[string]any{}); err == nil {
		t.Fatal("the standby served before the flip")
	}
	c, err := rg.r.FlipSecrets()
	if err != nil || c != "green" {
		t.Fatal(c, err)
	}
	if _, err := rg.r.kernel.Doc("secrets", "/keys", map[string]any{}); err != nil {
		t.Fatal("green doesn't serve after the flip:", err)
	}
	if _, err := rg.r.kernel.Doc("secrets-next", "/keys", map[string]any{}); err == nil {
		t.Fatal("blue still serves after its handoff")
	}
	if blue.Mode() != "handed-off" || green.Mode() != "" {
		t.Fatal(blue.Mode(), green.Mode())
	}
}

// A kernel release restarts the mover (new keys, a new roster signed): a running line's grant, signed by the old
// mover, no longer opens. Its destroy still goes through: the line ends, so its grant isn't moved
func TestDestroyAfterTheMoverRestarted(t *testing.T) {
	rg, k := kernelRig(t)
	sid, err := rg.r.CreateSession(NewSession{Label: "on the kernel", Harness: "claude"})
	if err != nil {
		t.Fatal(err)
	}
	var a *Approval
	waitFor(t, "the approval", func() bool {
		rg.r.st.Do(func(d *persisted) {
			for _, x := range d.Approvals {
				if x.Session == sid {
					a = x
				}
			}
		})
		return a != nil
	})
	signature, _ := k.Phone.Sign([]byte(a.Challenge.Payload))
	if _, _, err := rg.r.Respond(a.ID, signature); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the machine", func() bool { s := kernelSession(rg, sid); return s.MachineID != "" && s.Kernel.MachineCert != nil })
	m1 := k.Fly.Machine(kernelSession(rg, sid).MachineID)
	k.Restart(t, "mover")
	if err := k.PostRoster(""); err != nil {
		t.Fatal(err)
	}
	if _, err := gv.Open(*kernelSession(rg, sid).Kernel.Grant, k.Trust()); err == nil {
		t.Fatal("the old mover's grant still opens")
	}
	pulledMachines.Delete(m1.ID) // the fake Fly's ids repeat across tests: an earlier test's pull would make this wait bootGrace
	if err := rg.r.Destroy(sid); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		gone, state, why := false, "", ""
		rg.r.st.Do(func(d *persisted) {
			if x := d.Sessions[sid]; x != nil {
				state, why = x.State, x.Error
			} else {
				gone = true
			}
		})
		if gone {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not destroyed: %s %s", state, why)
		}
	}
	if m1.State != "destroyed" {
		t.Fatalf("machine %s", m1.State)
	}
}
