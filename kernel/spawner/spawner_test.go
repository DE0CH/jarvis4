package spawner

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/internal/kt"
	"github.com/DE0CH/jarvis4/kernel/notarizer"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

const img = "ghcr.io/de0ch/jarvis4-session@sha256:" + "2222222222222222222222222222222222222222222222222222222222222222"

type fakeM struct {
	image, state, volume string
	keys                 *sig.Signer
	enc                  *sig.Signer
}

type fakeFly struct {
	mu       sync.Mutex
	n        int
	ms       map[string]*fakeM
	vols     map[string]bool
	swap     string // report this image instead
	slowStop bool
}

func newFly() *fakeFly { return &fakeFly{ms: map[string]*fakeM{}, vols: map[string]bool{}} }

func (f *fakeFly) Configure(string) {}
func (f *fakeFly) CreateVolume(string, int) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	v := fmt.Sprintf("vol_%d", f.n)
	f.vols[v] = true
	return v, nil
}
func (f *fakeFly) Create(image, region string, guest map[string]any, env map[string]string, volume string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	id := fmt.Sprintf("%014x", f.n)
	s, _ := sig.NewSigner()
	e, _ := sig.NewSigner()
	f.ms[id] = &fakeM{image: image, state: "created", volume: volume, keys: s, enc: e}
	return id, nil
}
func (f *fakeFly) start(id string) { f.mu.Lock(); f.ms[id].state = "started"; f.mu.Unlock() }
func (f *fakeFly) Inspect(id string) (FlyMachine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.ms[id]
	if m == nil {
		return FlyMachine{State: "destroyed"}, nil
	}
	im := m.image
	if f.swap != "" {
		im = f.swap
	}
	return FlyMachine{State: m.state, Image: strings.Replace(im, "ghcr.io/", "ghcr.io/", 1)}, nil
}
func (f *fakeFly) Init(id string) (MachineKeys, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.ms[id]
	return MachineKeys{EncryptionKey: m.enc.PublicKey(), SigningKey: m.keys.PublicKey()}, nil
}
func (f *fakeFly) Destroy(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.slowStop {
		f.ms[id].state = "stopping"
		return nil
	}
	f.ms[id].state = "destroyed"
	return nil
}
func (f *fakeFly) DeleteVolume(v string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.vols, v)
	return nil
}
func (f *fakeFly) ExtendVolume(string, int) (bool, error) { return true, nil }

type rig struct {
	t    *testing.T
	w    *kt.World
	fly  *fakeFly
	sp   *Spawner
	nz   *notarizer.Notarizer
	path string
}

func newRig(t *testing.T) *rig {
	w := kt.New(t)
	dir := t.TempDir()
	fly := newFly()
	sp, err := Open(filepath.Join(dir, "sp.json"), w.C["spawner"], w.Trust, fly, map[string]string{"JARVIS2_URL": "http://router"})
	if err != nil {
		t.Fatal(err)
	}
	nz, err := notarizer.Open(filepath.Join(dir, "nz"), w.C["notarizer"].Signer, w.Trust)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t, w, fly, sp, nz, filepath.Join(dir, "sp.json")}
}

func (r *rig) notarize(cert sig.Doc) sig.Doc {
	r.t.Helper()
	c, _ := doc.PeekCert(cert)
	in := notarizer.Input{Cert: cert, Challenge: r.w.Challenge(cert.ID(), "cert", time.Now()), Notary: r.w.C["notary"].Identity}
	if c.Signer == doc.ByIPhone || c.Signer == doc.ByRoot {
		in.Keys, in.Secrets = &r.w.KeysDoc, r.w.ID("secrets")
	} else {
		in.Signer = r.w.ID(c.Signer)
	}
	d, err := r.nz.Notarize(in)
	if err != nil {
		r.t.Fatal(err)
	}
	return d
}

// source: a notarized new source (phone) with the test image
func (r *rig) source() (sig.Doc, sig.Doc) {
	src := kt.SourceContent("t")
	src.Image = img
	cert := r.w.Cert(doc.ByIPhone, doc.Sink, kt.Source(), perm.Pair{Allowed: perm.Only("store:a"), Conditions: []string{}}, src, nil)
	return cert, r.notarize(cert)
}

func (r *rig) spawn() (string, sig.Doc) {
	r.t.Helper()
	cert, nz := r.source()
	out, err := r.sp.Spawn(SpawnInput{Cert: cert, Notarized: nz, Notarizer: r.w.C["notarizer"].Identity, Region: "lhr", Size: "medium"})
	if err != nil {
		r.t.Fatal(err)
	}
	id := out.(map[string]any)["id"].(string)
	if _, err := r.sp.Init(id); err == nil || !strings.Contains(err.Error(), "not started") {
		r.t.Fatalf("init before start: %v", err)
	}
	r.fly.start(id)
	d, err := r.sp.Init(id)
	if err != nil {
		r.t.Fatal(err)
	}
	return id, d
}

// spawn → a cert the notarizer takes; kill with the machine's signed snapshot → a source the notarizer takes, holding
// the snapshot; the volume is gone; a second kill answers the same cert, also after a restart
func TestSpawnAndKill(t *testing.T) {
	r := newRig(t)
	id, d := r.spawn()
	c, err := doc.OpenCert(d, r.w.C["spawner"].Identity.SigningKey)
	if err != nil || c.Succ != doc.Object("fly-"+id) || c.Machine == nil || c.Machine.SigningKey != r.fly.ms[id].keys.PublicKey() {
		t.Fatal(err, c)
	}
	r.notarize(d)
	sum := strings.Repeat("ef", 32)
	ssig, _ := r.fly.ms[id].keys.Sign([]byte(sum))
	kd, err := r.sp.Kill(id, &Snapshot{Sha256: sum, Sig: ssig, Required: true})
	if err != nil {
		t.Fatal(err)
	}
	kc, err := doc.OpenCert(kd, r.w.C["spawner"].Identity.SigningKey)
	if err != nil || kc.Source.Snapshot != sum || kc.Source.Image != img || kc.Pred != doc.Object("fly-"+id) {
		t.Fatal(err, kc)
	}
	r.notarize(kd)
	if len(r.fly.vols) != 0 {
		t.Fatalf("volumes left: %v", r.fly.vols)
	}
	sp2, err := Open(r.path, r.w.C["spawner"], r.w.Trust, r.fly, nil)
	if err != nil {
		t.Fatal(err)
	}
	again, err := sp2.Kill(id, nil)
	if err != nil || again != kd {
		t.Fatal("a second kill signed another cert", err)
	}
}

// ✱ a required snapshot that isn't the machine's keeps it; ✱ a snapshot signed by another key; none at all
func TestARequiredSnapshotKeepsTheMachine(t *testing.T) {
	r := newRig(t)
	id, _ := r.spawn()
	other, _ := sig.NewSigner()
	sum := strings.Repeat("ef", 32)
	bad, _ := other.Sign([]byte(sum))
	for _, s := range []*Snapshot{{Sha256: sum, Sig: bad, Required: true}, {Required: true}, {Sha256: "x", Sig: bad, Required: true}} {
		if _, err := r.sp.Kill(id, s); err == nil || !strings.Contains(err.Error(), "kept") {
			t.Fatal(err)
		}
	}
	if r.fly.ms[id].state != "started" {
		t.Fatal("the machine was touched")
	}
	// not required: killed, its source with no snapshot
	kd, err := r.sp.Kill(id, &Snapshot{Sha256: sum, Sig: bad})
	if err != nil {
		t.Fatal(err)
	}
	kc, _ := doc.OpenCert(kd, r.w.C["spawner"].Identity.SigningKey)
	if kc.Source.Snapshot != "" {
		t.Fatal("an unvouched snapshot was named")
	}
	// a machine of a source with a snapshot that signs none passes that snapshot on
	r2 := newRig(t)
	src := kt.SourceContent("t")
	src.Image, src.Snapshot = img, strings.Repeat("cd", 32)
	cert := r2.w.Cert(doc.ByIPhone, doc.Sink, kt.Source(), perm.Top(), src, nil)
	out, err := r2.sp.Spawn(SpawnInput{Cert: cert, Notarized: r2.notarize(cert), Notarizer: r2.w.C["notarizer"].Identity, Region: "lhr", Size: "medium"})
	if err != nil {
		t.Fatal(err)
	}
	id2 := out.(map[string]any)["id"].(string)
	r2.fly.start(id2)
	if _, err := r2.sp.Init(id2); err != nil {
		t.Fatal(err)
	}
	kd2, err := r2.sp.Kill(id2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if kc2, _ := doc.OpenCert(kd2, r2.w.C["spawner"].Identity.SigningKey); kc2.Source.Snapshot != src.Snapshot {
		t.Fatalf("the source's snapshot wasn't passed on: %q", kc2.Source.Snapshot)
	}
}

// ✱ a spawn from a cert that isn't notarized, or not into a source, or with another image; ✱ Fly running another digest
func TestSpawnRefuses(t *testing.T) {
	r := newRig(t)
	cert, nz := r.source()
	other, _ := r.source()
	if _, err := r.sp.Spawn(SpawnInput{Cert: other, Notarized: nz, Notarizer: r.w.C["notarizer"].Identity, Region: "lhr", Size: "medium"}); err == nil {
		t.Fatal("spawned from a cert not notarized")
	}
	src := kt.SourceContent("t")
	src.Image = "docker.io/evil/image@sha256:" + strings.Repeat("3", 64)
	evil := r.w.Cert(doc.ByIPhone, doc.Sink, kt.Source(), perm.Top(), src, nil)
	if _, err := r.sp.Spawn(SpawnInput{Cert: evil, Notarized: r.notarize(evil), Notarizer: r.w.C["notarizer"].Identity, Region: "lhr", Size: "medium"}); err == nil {
		t.Fatal("spawned another repo's image")
	}
	if _, err := r.sp.Spawn(SpawnInput{Cert: cert, Notarized: nz, Notarizer: r.w.C["notarizer"].Identity, Region: "lhr", Size: "huge"}); err == nil {
		t.Fatal("a size that isn't one")
	}
	out, err := r.sp.Spawn(SpawnInput{Cert: cert, Notarized: nz, Notarizer: r.w.C["notarizer"].Identity, Region: "lhr", Size: "medium"})
	if err != nil {
		t.Fatal(err)
	}
	id := out.(map[string]any)["id"].(string)
	r.fly.start(id)
	r.fly.swap = "ghcr.io/de0ch/jarvis4-session@sha256:" + strings.Repeat("4", 64)
	if _, err := r.sp.Init(id); err == nil || !strings.Contains(err.Error(), "not its source's") {
		t.Fatal(err)
	}
}

// a kill waits until Fly says destroyed (409 meanwhile); a machine never up gets a kill record, not a source
func TestKillWaitsForFly(t *testing.T) {
	r := newRig(t)
	cert, nz := r.source()
	out, _ := r.sp.Spawn(SpawnInput{Cert: cert, Notarized: nz, Notarizer: r.w.C["notarizer"].Identity, Region: "lhr", Size: "small"})
	id := out.(map[string]any)["id"].(string)
	r.fly.slowStop = true
	if _, err := r.sp.Kill(id, nil); err == nil || !strings.Contains(err.Error(), "not destroyed yet") {
		t.Fatal(err)
	}
	r.fly.slowStop = false
	d, err := r.sp.Kill(id, nil)
	if err != nil || !strings.Contains(d.Payload, `"up":false`) {
		t.Fatal(err, d.Payload)
	}
}
