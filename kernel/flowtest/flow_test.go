// Package flowtest: a session's chain through the real notarizer, mover, merger and signers (no HTTP).
package flowtest

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/internal/kt"
	"github.com/DE0CH/jarvis4/kernel/merger"
	"github.com/DE0CH/jarvis4/kernel/mover"
	"github.com/DE0CH/jarvis4/kernel/notarizer"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
	"github.com/DE0CH/jarvis4/kernel/signers"
)

type k struct {
	t  *testing.T
	w  *kt.World
	nz *notarizer.Notarizer
	mv *mover.Mover
	mg *merger.Merger
}

func newK(t *testing.T) *k {
	w := kt.New(t)
	nz, err := notarizer.Open(filepath.Join(t.TempDir(), "s"), w.C["notarizer"].Signer, w.Trust)
	if err != nil {
		t.Fatal(err)
	}
	return &k{t, w, nz, mover.New(w.C["mover"].Signer, w.Trust), merger.New(w.C["merger"].Signer, w.Trust)}
}

// notarize: the cert with a fresh challenge
func (k *k) notarize(cert sig.Doc) sig.Doc {
	k.t.Helper()
	c, _ := doc.PeekCert(cert)
	in := notarizer.Input{Cert: cert, Challenge: k.w.Challenge(cert.ID(), "cert", time.Now()), Notary: k.w.C["notary"].Identity}
	if c.Signer == doc.ByIPhone || c.Signer == doc.ByRoot {
		in.Keys, in.Secrets = &k.w.KeysDoc, k.w.ID("secrets")
	} else {
		in.Signer = k.w.ID(c.Signer)
	}
	d, err := k.nz.Notarize(in)
	if err != nil {
		k.t.Fatal(err)
	}
	return d
}

// rootTop: ⊤ on the sink, by the root key
func (k *k) rootTop() gv.Signed {
	ik, _ := doc.IdealKeys(doc.Sink)
	d, _ := k.w.Root.SignJSON(doc.Grant{Kind: "grant", Machine: doc.Sink, Keys: ik, Pair: perm.Top(), From: []string{}, At: doc.Now()})
	return gv.Signed{Grant: d, By: "root", Keys: &k.w.KeysDoc, Secrets: k.w.ID("secrets")}
}

func (k *k) moveIn(g gv.Signed, cert, nz sig.Doc) mover.Input {
	return mover.Input{Signed: g, Cert: cert, Notarized: nz, Notarizer: k.w.C["notarizer"].Identity, Notary: k.w.C["notary"].Identity}
}

func (k *k) move(g gv.Signed, cert sig.Doc) (gv.Signed, doc.Grant) {
	k.t.Helper()
	d, err := k.mv.Move(k.moveIn(g, cert, k.notarize(cert)))
	if err != nil {
		k.t.Fatal(err)
	}
	s := gv.Signed{Grant: d, By: "mover", Signer: k.w.ID("mover")}
	out, err := gv.Open(s, k.w.Trust)
	if err != nil {
		k.t.Fatal(err)
	}
	return s, out
}

var p = perm.Pair{Allowed: perm.Only("store:claude", "store:default"), Conditions: []string{"session:s1"}}

// New session → spawn → narrow → add a shell for a while → merge → kill into a source → spawn again → burn
func TestASessionsChain(t *testing.T) {
	k := newK(t)
	w := k.w
	x := kt.Source()
	gX, onX := k.move(k.rootTop(), w.Cert(doc.ByIPhone, doc.Sink, x, p, kt.SourceContent("t"), nil))
	if onX.Machine != x || !onX.Pair.Leq(p) || !p.Leq(onX.Pair) {
		t.Fatalf("%+v", onX)
	}
	_, m1 := kt.MachineKeys()
	gM, onM := k.move(gX, w.Cert(doc.BySpawner, x, "fly-aaaaaaaa01", perm.Top(), nil, m1))
	if onM.Keys != m1.Keys || !onM.Pair.Allowed.Contains("store:claude") {
		t.Fatalf("%+v", onM)
	}
	// adding a shell until T: the phone's small grant, and the main grant narrowed to the same conditions
	cond := []string{"session:s1", "until:2026-10-21T15:00:00Z"}
	a := kt.Source()
	gA, _ := k.move(k.rootTop(), w.Cert(doc.ByIPhone, doc.Sink, a, perm.Pair{Allowed: perm.Only("shell"), Conditions: cond}, kt.SourceContent("add"), nil))
	gA2, _ := k.move(gA, w.Cert(doc.ByIPhone, a, "fly-aaaaaaaa01", perm.Top(), nil, m1))
	idc, err := signers.Identity(w.C["identity"].Signer, "fly-aaaaaaaa01", perm.Pair{Allowed: perm.Except(), Conditions: cond})
	if err != nil {
		t.Fatal(err)
	}
	gN, onN := k.move(gM, idc)
	if onN.Keys != m1.Keys || len(onN.Pair.Conditions) != 2 {
		t.Fatalf("%+v", onN)
	}
	md, err := k.mg.Merge(merger.Input{A: gN, B: gA2})
	if err != nil {
		t.Fatal(err)
	}
	merged, err := gv.Open(gv.Signed{Grant: md, By: "merger", Signer: w.ID("merger")}, w.Trust)
	if err != nil || !merged.Pair.Allowed.Contains("shell") || !merged.Pair.Allowed.Contains("store:default") {
		t.Fatal(err, merged)
	}
	// ✱ merging the main grant (no until) with the shell grant is refused: conditions differ
	if _, err := k.mg.Merge(merger.Input{A: gM, B: gA2}); err == nil || !strings.Contains(err.Error(), "conditions differ") {
		t.Fatal(err)
	}
	// pause: kill into y, then spawn from it; the main grant follows
	y := kt.Source()
	snap := kt.SourceContent("t")
	snap.Snapshot = strings.Repeat("cd", 32)
	gY, onY := k.move(gM, w.Cert(doc.BySpawner, "fly-aaaaaaaa01", y, perm.Top(), snap, nil))
	if onY.Machine != y {
		t.Fatal(onY)
	}
	_, m2 := kt.MachineKeys()
	_, on2 := k.move(gY, w.Cert(doc.BySpawner, y, "fly-aaaaaaaa02", perm.Top(), nil, m2))
	if on2.Keys != m2.Keys || !on2.Pair.Allowed.Contains("store:claude") || on2.Pair.Allowed.Contains("shell") {
		t.Fatal(on2)
	}
	// destroy: the burn ends y's line (y already spawned, so this is only the record)
	k.notarize(w.Cert(doc.ByGullible, y, doc.Sink, perm.Top(), nil, nil))
}

// ✱ the mover's refusals: a grant on another object, a cert not notarized, a forged notarizer, a grant by an
// unvouched mover, the root's grant that isn't ⊤ on the sink, ideal-keyed objects with other keys
func TestTheMoverRefuses(t *testing.T) {
	k := newK(t)
	w := k.w
	x := kt.Source()
	cert := w.Cert(doc.ByIPhone, doc.Sink, x, p, kt.SourceContent("t"), nil)
	nz := k.notarize(cert)
	gX, _ := k.move(k.rootTop(), w.Cert(doc.ByIPhone, doc.Sink, kt.Source(), p, kt.SourceContent("u"), nil))
	refuse := func(in mover.Input, want string) {
		t.Helper()
		if _, err := k.mv.Move(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("want %q, got %v", want, err)
		}
	}
	refuse(k.moveIn(gX, cert, nz), "the cert leaves sink")
	other := w.Cert(doc.ByIPhone, doc.Sink, kt.Source(), p, kt.SourceContent("v"), nil)
	refuse(k.moveIn(k.rootTop(), other, nz), "isn't notarized")
	in := k.moveIn(k.rootTop(), cert, nz)
	in.Notarizer = w.C["notary"].Identity
	refuse(in, "not a notarizer identity")
	fake, _ := sig.NewSigner()
	fakeNz, _ := fake.SignJSON(doc.Notarized{Kind: "notarized", Cert: cert.ID()})
	refuse(k.moveIn(k.rootTop(), cert, fakeNz), "isn't notarized")
	// a grant signed by a mover the roster doesn't name
	m2, _ := sig.NewComponent("mover")
	ik, _ := doc.IdealKeys(doc.Sink)
	gd, _ := m2.Signer.SignJSON(doc.Grant{Kind: "grant", Machine: doc.Sink, Keys: ik, Pair: perm.Top(), From: []string{}, At: doc.Now()})
	refuse(k.moveIn(gv.Signed{Grant: gd, By: "mover", Signer: &m2.Identity}, cert, nz), "isn't the roster's")
	// the root key's grant on anything but ⊤ on the sink
	rd, _ := w.Root.SignJSON(doc.Grant{Kind: "grant", Machine: doc.Sink, Keys: ik, Pair: p, From: []string{}, At: doc.Now()})
	refuse(k.moveIn(gv.Signed{Grant: rd, By: "root", Keys: &w.KeysDoc, Secrets: w.ID("secrets")}, cert, nz), "⊤ on the sink only")
	// a grant on the sink naming other keys
	_, mk := kt.MachineKeys()
	bd, _ := w.C["mover"].Signer.SignJSON(doc.Grant{Kind: "grant", Machine: doc.Sink, Keys: mk.Keys, Pair: perm.Top(), From: []string{}, At: doc.Now()})
	refuse(k.moveIn(gv.Signed{Grant: bd, By: "mover", Signer: w.ID("mover")}, cert, nz), "aren't its own")
	// the real one goes
	if _, err := k.mv.Move(k.moveIn(k.rootTop(), cert, nz)); err != nil {
		t.Fatal(err)
	}
}

// a move only narrows: whatever the cert's pair, the result is ≤ the grant
func TestAMoveOnlyNarrows(t *testing.T) {
	k := newK(t)
	w := k.w
	small := perm.Pair{Allowed: perm.Only("store:a"), Conditions: []string{"session:s1"}}
	gX, _ := k.move(k.rootTop(), w.Cert(doc.ByIPhone, doc.Sink, kt.Source(), small, kt.SourceContent("t"), nil))
	_, mk := kt.MachineKeys()
	x, _ := gv.Open(gX, w.Trust)
	_, on := k.move(gX, w.Cert(doc.ByRoot, x.Machine, "fly-aaaaaaaa01", perm.Top(), nil, mk))
	if !on.Pair.Leq(small) || on.Pair.Allowed.Contains("shell") {
		t.Fatal(on)
	}
}

// ✱ the merger: different machines
func TestTheMergerRefusesOtherMachines(t *testing.T) {
	k := newK(t)
	w := k.w
	a, _ := k.move(k.rootTop(), w.Cert(doc.ByIPhone, doc.Sink, kt.Source(), p, kt.SourceContent("a"), nil))
	b, _ := k.move(k.rootTop(), w.Cert(doc.ByIPhone, doc.Sink, kt.Source(), p, kt.SourceContent("b"), nil))
	if _, err := k.mg.Merge(merger.Input{A: a, B: b}); err == nil || !strings.Contains(err.Error(), "different machines") {
		t.Fatal(err)
	}
}

// ✱ the identity signer signs only (M, M) for a Fly machine
func TestTheIdentitySignerOnlyFlyMachines(t *testing.T) {
	w := kt.New(t)
	if _, err := signers.Identity(w.C["identity"].Signer, kt.Source(), perm.Top()); err == nil {
		t.Fatal("signed for a source")
	}
}
