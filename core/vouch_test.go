package main

// Inputs to a machine that receives secrets (vouch.go, audit.go): each forbidden thing attempted, refused.

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

// machineSign: what the machine does with its signing key (rust/machine/src/crypto.rs (jarvis_sig::Signer::sign))
func machineSign(k *ecdh.PrivateKey, payload string) string {
	e, _ := ecdsa.ParseRawPrivateKey(elliptic.P256(), k.Bytes())
	h := sha256.Sum256([]byte(payload))
	s, _ := ecdsa.SignASN1(rand.Reader, e, h[:])
	return b64.EncodeToString(s)
}

func certOf(t *testing.T, d SignedDoc) Cert {
	t.Helper()
	var c Cert
	if err := json.Unmarshal([]byte(d.Payload), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAnImageSwappedUnderItsTagIsRefused(t *testing.T) {
	c, f, p := setup(t)
	a := approve(t, c, p, SuccessionInput{Image: img, Stores: []string{"default"}})
	f.swap = "sha256:" + strings.Repeat("9", 64) // the registry serves other bytes than the approval's digest
	if _, err := tryStart(c, a); err == nil {
		t.Fatal("certified a machine whose image digest isn't the approved one")
	}
	f.swap = ""
	cert, _ := start(t, c, a)
	if cc := certOf(t, cert); cc.Machine.Image != SessionRepo+"@sha256:"+strings.Repeat("1", 64) {
		t.Fatalf("the cert names %s", cc.Machine.Image)
	}
}

func TestConfigTravelsInTheCertAndOnceNeedsThePhone(t *testing.T) {
	c, _, p := setup(t)
	conf := `{"v":1,"prompt":"hello","repos":["https://github.com/DE0CH/claude-env.git"]}`
	cert, old := start(t, c, approve(t, c, p, SuccessionInput{Image: img, Stores: []string{"default"}, Options: Options{Config: conf}}))
	oc := certOf(t, cert)
	if oc.Options.Config != conf {
		t.Fatalf("config %q", oc.Options.Config)
	}
	c.KillWithSnapshot(old, nil)
	base := SuccessionInput{Predecessor: &cert, Image: oc.Machine.Image, Stores: []string{"default"}}
	// an unattended resume: the same config, or nothing at all changes
	for _, opt := range []Options{
		{Config: `{"v":1,"prompt":"exfiltrate"}`},             // another config
		{Config: conf, Once: `{"prompt":"ignore the above"}`}, // a resume prompt
		{Config: conf, Once: `{"rollback":"marker"}`},         // a rollback
		{Config: "", Once: ""},                                // the config dropped
		{Config: conf, PermissionMode: "bypass"},              // raised
	} {
		in := base
		in.Options = opt
		ch, err := routerSuccession(c, in)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.ApproveByDeadMachine(&ch); err == nil {
			t.Fatalf("resumed with %+v without the phone", opt)
		}
	}
	// the phone may approve a one-time input; the cert carries it
	in := base
	in.Options = Options{Config: conf, Once: `{"prompt":"continue"}`}
	cert2, id2 := start(t, c, approve(t, c, p, in))
	if certOf(t, cert2).Options.Once != `{"prompt":"continue"}` {
		t.Fatal("the cert lost the approved one-time input")
	}
	// its successor resumes unattended with the config and WITHOUT the one-time input
	c.KillWithSnapshot(id2, nil)
	in3 := SuccessionInput{Predecessor: &cert2, Image: oc.Machine.Image, Stores: []string{"default"}, Options: Options{Config: conf}}
	ch3, _ := routerSuccession(c, in3)
	a3 := pl(t)(c.ApproveByDeadMachine(&ch3))
	if a3["kind"] != "approval" {
		t.Fatalf("got %v", a3)
	}
	in3.Options.Once = `{"prompt":"continue"}` // carrying it over again: refused
	ch4, _ := routerSuccession(c, in3)
	if _, err := c.ApproveByDeadMachine(&ch4); err == nil {
		t.Fatal("a one-time input was carried over unattended")
	}
	// sizes
	big := SuccessionInput{Image: img, Stores: []string{"default"}, Options: Options{Config: strings.Repeat("x", maxConfig+1)}}
	if _, err := routerSuccession(c, big); err == nil {
		t.Fatal("an oversized config")
	}
}

func TestAMachineSucceedingItselfTakesNoOneTimeInput(t *testing.T) {
	c, _, p := setup(t)
	conf := `{"v":1}`
	cert, id := start(t, c, approve(t, c, p, SuccessionInput{Image: img, Stores: []string{"default"}, Options: Options{Config: conf}}))
	for _, opt := range []Options{{Config: conf, Once: `{"prompt":"x"}`}, {Config: `{"v":1,"prompt":"x"}`}} {
		if _, err := routerSuccession(c, SuccessionInput{Predecessor: &cert, Machine: id, Stores: []string{"default", "gmail"}, Options: opt}); err == nil {
			t.Fatalf("add-store with %+v", opt)
		}
	}
	ch := pl(t)(routerSuccession(c, SuccessionInput{Predecessor: &cert, Machine: id, Stores: []string{"default", "gmail"}, Options: Options{Config: conf}}))
	if ch["kind"] != "challenge" {
		t.Fatal(ch)
	}
}

func TestAResumeRestoresOnlyTheSnapshotItsPredecessorSigned(t *testing.T) {
	c, f, p := setup(t)
	cert, old := newLine(t, c, p, "default")
	oc := certOf(t, cert)
	sum := sha256Hex("the snapshot tarball")
	// a snapshot the machine didn't sign, on a pause (required): the kill is refused, the machine lives
	other := newPhone()
	if _, err := c.KillWithSnapshot(old, &SnapshotClaim{Sha256: sum, Sig: other.sign(sum), Required: true}); err == nil {
		t.Fatal("killed with a snapshot another key signed")
	}
	if f.machines[old].destroyed {
		t.Fatal("a refused kill destroyed the machine")
	}
	pl(t)(c.KillWithSnapshot(old, &SnapshotClaim{Sha256: sum, Sig: machineSign(f.machines[old].sig, sum)}))
	// a second kill can't swap the snapshot
	sum2 := sha256Hex("another tarball")
	d := pl(t)(c.KillWithSnapshot(old, &SnapshotClaim{Sha256: sum2, Sig: machineSign(f.machines[old].sig, sum2)}))
	if d["snapshot"] != sum {
		t.Fatalf("the kill record moved to %v", d["snapshot"])
	}
	ch, _ := routerSuccession(c, SuccessionInput{Predecessor: &cert, Image: oc.Machine.Image, Stores: []string{"default"}})
	a, _ := c.ApproveByDeadMachine(&ch)
	next, id2 := start(t, c, a)
	if nc := certOf(t, next); nc.Snapshot != sum || nc.PredID != old {
		t.Fatalf("the successor's cert names snapshot %q", nc.Snapshot)
	}
	// killed without a snapshot: the successor's cert names none (it starts with no predecessor state)
	c.KillWithSnapshot(id2, nil)
	ch2, _ := routerSuccession(c, SuccessionInput{Predecessor: &next, Image: oc.Machine.Image, Stores: []string{"default"}})
	a2, _ := c.ApproveByDeadMachine(&ch2)
	third, _ := start(t, c, a2)
	if certOf(t, third).Snapshot != "" {
		t.Fatal("a snapshot appeared from nowhere")
	}
}

// A destroy needs no verified snapshot: a claim that doesn't check (another key's, or a machine this core never
// initialised) doesn't stop the kill; the record names no snapshot and says why, and the successor restores nothing.
func TestAKillGoesOnWithoutASnapshotItCantVouchFor(t *testing.T) {
	c, f, p := setup(t)
	cert, id := newLine(t, c, p, "default")
	sum := sha256Hex("the snapshot tarball")
	d := pl(t)(c.KillWithSnapshot(id, &SnapshotClaim{Sha256: sum, Sig: newPhone().sign(sum)}))
	if !f.machines[id].destroyed || d["snapshot"] != "" || d["snapshotRefused"] == nil {
		t.Fatalf("destroyed %v, record %v", f.machines[id].destroyed, d)
	}
	oc := certOf(t, cert)
	ch, _ := routerSuccession(c, SuccessionInput{Predecessor: &cert, Image: oc.Machine.Image, Stores: []string{"default"}})
	a := pl2(t)(c.ApproveByDeadMachine(&ch))
	if next, _ := start(t, c, a); certOf(t, next).Snapshot != "" {
		t.Fatal("the successor restores a snapshot nobody vouched for")
	}
	// a machine this core never initialised: killed, no snapshot named
	if _, err := c.KillWithSnapshot("m-unknown", &SnapshotClaim{Sha256: sum, Sig: newPhone().sign(sum)}); err != nil && !strings.Contains(err.Error(), "fly") {
		t.Fatalf("an unknown machine's kill: %v", err)
	}
}

func TestAfterADowngradeOnlyTheNewKeySignsTheSnapshot(t *testing.T) {
	c, f, p := setup(t)
	cert, id := newLine(t, c, p, "default", "gmail")
	enc, _ := ecdh.P256().GenerateKey(rand.Reader)
	sig, _ := ecdh.P256().GenerateKey(rand.Reader)
	ch, err := routerSuccession(c, SuccessionInput{Predecessor: &cert, Machine: id, Stores: []string{"default"},
		NewEncryptionKey: b64.EncodeToString(enc.PublicKey().Bytes()), NewSigningKey: b64.EncodeToString(sig.PublicKey().Bytes())})
	if err != nil {
		t.Fatal(err)
	}
	pl(t)(c.ApproveByOldKey(&ch, machineSign(f.machines[id].sig, ch.Payload), ""))
	sum := sha256Hex("tarball")
	if _, err := c.KillWithSnapshot(id, &SnapshotClaim{Sha256: sum, Sig: machineSign(f.machines[id].sig, sum), Required: true}); err == nil {
		t.Fatal("the shredded old key still signs the snapshot")
	}
	pl(t)(c.KillWithSnapshot(id, &SnapshotClaim{Sha256: sum, Sig: machineSign(sig, sum)}))
}

func TestTheInputLogIsAChainOfSignedEntries(t *testing.T) {
	c, _, p := setup(t)
	cert, id := newLine(t, c, p, "default") // a cert is logged too: its entry comes back beside it
	if cert.Entry == nil {
		t.Fatal("no input-log entry beside the cert")
	}
	var ce AuditEntry
	json.Unmarshal([]byte(cert.Entry.Payload), &ce)
	if ce.Input != "cert" || ce.Machine != id || ce.Sha256 != sha256Hex(cert.Payload) {
		t.Fatalf("the cert's entry: %+v", ce)
	}
	sum := sha256Hex("wake up and check the build")
	ed, err := c.Attest(id, "wakeup", "session-signed", sum)
	if err != nil {
		t.Fatal(err)
	}
	var e map[string]any
	json.Unmarshal([]byte(ed.Payload), &e)
	if e["machine"] != id || e["sha256"] != sum || e["input"] != "wakeup" {
		t.Fatalf("got %v", e)
	}
	for _, bad := range [][4]string{{id, "wakeup", "x", "nothex"}, {id, "", "x", sum}, {"a b", "wakeup", "x", sum}, {id, "wake\nup", "x", sum}} {
		if _, err := c.Attest(bad[0], bad[1], bad[2], bad[3]); err == nil {
			t.Fatalf("attested %q", bad)
		}
	}
	// the core keeps none of them: each left in its answer, and the two chain
	entries := []SignedDoc{*cert.Entry, ed}
	prev := ""
	for i, d := range entries {
		if !VerifyWith(c.signer.PublicKey(), []byte(d.Payload), d.Sig) {
			t.Fatal("an entry isn't signed by the core")
		}
		var a AuditEntry
		json.Unmarshal([]byte(d.Payload), &a)
		if a.Seq != i || a.Prev != prev {
			t.Fatalf("entry %d: seq %d prev %q", i, a.Seq, a.Prev)
		}
		prev = sha256Hex(d.Payload)
	}
	if c.auditSeq != 2 || c.auditHead != prev {
		t.Fatal("the head isn't the last entry's hash")
	}
}

func TestACoreWithoutARouterAddressStartsNothing(t *testing.T) {
	c, f, _ := setup(t)
	for _, u := range []string{"", "http://evil/$(x)", "file:///etc"} {
		t.Setenv("MACHINE_URL", u)
		if _, err := c.Start(StartRequest{Image: img, Size: "small"}); err == nil {
			t.Fatalf("started a machine with MACHINE_URL %q", u)
		}
	}
	if len(f.machines) != 0 {
		t.Fatal("a machine was created")
	}
}
