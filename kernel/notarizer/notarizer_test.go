package notarizer

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/internal/kt"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

type rig struct {
	w    *kt.World
	n    *Notarizer
	path string
}

func newRig(t *testing.T) *rig {
	w := kt.New(t)
	path := filepath.Join(t.TempDir(), "state")
	n, err := Open(path, w.C["notarizer"].Signer, w.Trust)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{w, n, path}
}

// input: the cert with a fresh challenge and whatever names its signer's key
func (r *rig) input(cert sig.Doc) Input {
	c, _ := doc.PeekCert(cert)
	in := Input{Cert: cert, Challenge: r.w.Challenge(cert.ID(), "cert", time.Now()), Notary: r.w.C["notary"].Identity}
	switch c.Signer {
	case doc.ByIPhone, doc.ByRoot:
		in.Keys, in.Secrets = &r.w.KeysDoc, r.w.ID("secrets")
	default:
		in.Signer = r.w.ID(c.Signer)
	}
	return in
}

func (r *rig) ok(cert sig.Doc) {
	r.w.T.Helper()
	d, err := r.n.Notarize(r.input(cert))
	if err != nil {
		r.w.T.Fatal(err)
	}
	var nz doc.Notarized
	if err := d.Open(r.w.C["notarizer"].Identity.SigningKey, &nz); err != nil || nz.Cert != cert.ID() {
		r.w.T.Fatal(err, nz)
	}
}

func (r *rig) refused(in Input, want string) {
	r.w.T.Helper()
	if _, err := r.n.Notarize(in); err == nil || !strings.Contains(err.Error(), want) {
		r.w.T.Fatalf("want a refusal containing %q, got %v", want, err)
	}
}

var store = perm.Pair{Allowed: perm.Only("store:claude"), Conditions: []string{"session:s1"}}

// a whole life: phone → source, spawn, kill into a new source, spawn again, burn
func TestALifeAlongTheTable(t *testing.T) {
	r := newRig(t)
	w := r.w
	x, y := kt.Source(), kt.Source()
	_, m1 := kt.MachineKeys()
	_, m2 := kt.MachineKeys()
	r.ok(w.Cert(doc.ByIPhone, doc.Sink, x, store, kt.SourceContent("t"), nil))
	r.ok(w.Cert(doc.BySpawner, x, "fly-aaaaaaaa01", perm.Top(), nil, m1))
	r.ok(w.Cert(doc.ByIdentity, "fly-aaaaaaaa01", "fly-aaaaaaaa01", store, nil, nil))
	snap := kt.SourceContent("t")
	snap.Snapshot = strings.Repeat("ab", 32)
	r.ok(w.Cert(doc.BySpawner, "fly-aaaaaaaa01", y, perm.Top(), snap, nil))
	r.ok(w.Cert(doc.BySpawner, y, "fly-aaaaaaaa02", perm.Top(), nil, m2))
	// the state survives a restart: y has its successor, so a second spawn from it is refused
	r.n.f.Close()
	n2, err := Open(r.path, w.C["notarizer"].Signer, w.Trust)
	if err != nil {
		t.Fatal(err)
	}
	r.n = n2
	_, m3 := kt.MachineKeys()
	r.refused(r.input(w.Cert(doc.BySpawner, y, "fly-aaaaaaaa03", perm.Top(), nil, m3)), "already has a successor")
	// the burn is the gullible signer's, and it isn't a first-successor row
	r.ok(w.Cert(doc.ByGullible, y, doc.Sink, store, nil, nil))
}

// ✱ every shape outside the table, per signer
func TestShapesOutsideTheTableAreRefused(t *testing.T) {
	r := newRig(t)
	w := r.w
	x := kt.Source()
	_, m := kt.MachineKeys()
	r.ok(w.Cert(doc.ByIPhone, doc.Sink, x, store, kt.SourceContent("t"), nil))
	for _, c := range []sig.Doc{
		w.Cert(doc.ByIPhone, doc.Sink, "fly-aaaaaaaa01", store, nil, m),                        // the phone can't widen onto a machine
		w.Cert(doc.ByIPhone, "fly-aaaaaaaa01", kt.Source(), store, kt.SourceContent("t"), nil), // nor kill
		w.Cert(doc.ByIPhone, x, doc.Sink, store, nil, nil),                                     // nor burn
		w.Cert(doc.BySpawner, doc.Sink, kt.Source(), perm.Top(), kt.SourceContent("t"), nil),   // the spawner widens nothing out of the sink
		w.Cert(doc.BySpawner, x, doc.Sink, perm.Top(), nil, nil),
		w.Cert(doc.ByIdentity, "fly-aaaaaaaa01", "fly-aaaaaaaa02", store, nil, m),             // identity only (M, M)
		w.Cert(doc.ByIdentity, x, x, store, kt.SourceContent("t"), nil),                       // and only for Fly machines
		w.Cert(doc.ByGullible, doc.Sink, kt.Source(), perm.Top(), kt.SourceContent("t"), nil), // gullible only ends things
		w.Cert(doc.ByGullible, "fly-aaaaaaaa01", doc.Sink, store, nil, nil),                   // a machine can't be burned
	} {
		r.refused(r.input(c), "not in the table")
	}
	// ✱ the spawner's pair is always ⊤
	r.refused(r.input(w.Cert(doc.BySpawner, x, "fly-aaaaaaaa01", store, nil, m)), "⊤")
}

// ✱ a cert signed by the wrong key for its signer, a vouched identity of another role, an unvouched one
func TestSignerKeysAreChecked(t *testing.T) {
	r := newRig(t)
	w := r.w
	x := kt.Source()
	r.ok(w.Cert(doc.ByIPhone, doc.Sink, x, store, kt.SourceContent("t"), nil))
	_, m := kt.MachineKeys()
	// signed by the identity signer but claiming the spawner
	c := doc.Cert{Kind: "succession", Pred: x, Succ: "fly-aaaaaaaa01", Pair: perm.Top(), Machine: m, Signer: doc.BySpawner, IssuedAt: doc.Now()}
	forged, _ := w.C["identity"].Signer.SignJSON(c)
	r.refused(r.input(forged), "isn't signed by the spawner")
	// the identity signer's identity passed off as the spawner's
	in := r.input(w.Cert(doc.BySpawner, x, "fly-aaaaaaaa01", perm.Top(), nil, m))
	in.Signer = r.w.ID("identity")
	r.refused(in, "not a spawner identity")
	// an identity the roster doesn't name
	fake, _ := sig.NewComponent("spawner")
	in = r.input(w.Cert(doc.BySpawner, x, "fly-aaaaaaaa01", perm.Top(), nil, m))
	in.Signer = &fake.Identity
	r.refused(in, "isn't the roster's")
	// the phone's cert checked against keys secrets didn't sign
	y := kt.Source()
	in = r.input(w.Cert(doc.ByIPhone, doc.Sink, y, store, kt.SourceContent("t"), nil))
	bad, _ := w.C["notary"].Signer.SignJSON(map[string]string{"kind": "keys", "phone": w.Phone.PublicKey(), "root": w.Root.PublicKey()})
	in.Keys = &bad
	r.refused(in, "secrets' keys")
	// the root key is not the phone key
	c = doc.Cert{Kind: "succession", Pred: doc.Sink, Succ: y, Pair: store, Source: kt.SourceContent("t"), Signer: doc.ByIPhone, IssuedAt: doc.Now()}
	rootSigned, _ := w.Root.SignJSON(c)
	r.refused(r.input(rootSigned), "isn't signed by the iphone's key")
}

// ✱ a challenge from elsewhere: another subject, not about a cert, stale, by an unvouched notary
func TestTheChallengeIsChecked(t *testing.T) {
	r := newRig(t)
	w := r.w
	cert := w.Cert(doc.ByIPhone, doc.Sink, kt.Source(), store, kt.SourceContent("t"), nil)
	in := r.input(cert)
	in.Challenge = w.Challenge(strings.Repeat("0", 64), "cert", time.Now())
	r.refused(in, "challenge")
	in = r.input(cert)
	in.Challenge = w.Challenge(cert.ID(), "grant", time.Now())
	r.refused(in, "challenge")
	in = r.input(cert)
	in.Challenge = w.Challenge(cert.ID(), "cert", time.Now().Add(-time.Hour))
	r.refused(in, "challenge")
	in = r.input(cert)
	in.Notary = w.C["mover"].Identity
	r.refused(in, "not a notary identity")
	r.ok(cert)
}

// ✱ a source defined twice; a successor of a source never defined
func TestSourcesAreDefinedOnce(t *testing.T) {
	r := newRig(t)
	w := r.w
	x := kt.Source()
	r.ok(w.Cert(doc.ByIPhone, doc.Sink, x, store, kt.SourceContent("a"), nil))
	r.refused(r.input(w.Cert(doc.ByIPhone, doc.Sink, x, perm.Top(), kt.SourceContent("b"), nil)), "already defined")
	r.refused(r.input(w.Cert(doc.ByRoot, doc.Sink, x, perm.Top(), kt.SourceContent("b"), nil)), "already defined")
	_, m := kt.MachineKeys()
	r.refused(r.input(w.Cert(doc.BySpawner, kt.Source(), "fly-aaaaaaaa01", perm.Top(), nil, m)), "never defined")
	// root signs any shape
	r.ok(w.Cert(doc.ByRoot, "fly-aaaaaaaa09", doc.Sink, store, nil, nil))
}
