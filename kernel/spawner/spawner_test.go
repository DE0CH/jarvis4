package spawner

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/internal/kt"
	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/notarizer"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

const img = "ghcr.io/de0ch/jarvis4-session@sha256:" + "2222222222222222222222222222222222222222222222222222222222222222"

type fakeM struct {
	image, state, volume, source string
	keys                         *sig.Signer
	enc                          *sig.Signer
}

type fakeFly struct {
	mu        sync.Mutex
	n         int
	ms        map[string]*fakeM
	vols      map[string]bool
	swap      string // report this image instead
	slowStop  bool
	creates   int
	lose      bool             // Create makes the machine but answers an error (a lost answer)
	full      bool             // Create answers that the volume's host is full (412 volume_placement_capacity)
	stuckVols bool             // DeleteVolume fails
	guests    []map[string]any // the compute hint of each CreateVolume
}

func newFly() *fakeFly { return &fakeFly{ms: map[string]*fakeM{}, vols: map[string]bool{}} }

func (f *fakeFly) Configure(string) {}
func (f *fakeFly) CreateVolume(_ string, _ int, guest map[string]any) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.guests = append(f.guests, guest)
	f.n++
	v := fmt.Sprintf("vol_%d", f.n)
	f.vols[v] = true
	return v, nil
}
func (f *fakeFly) Create(image, region string, guest map[string]any, env map[string]string, volume, source string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.full {
		return "", &FlyError{HTTP: 412, Status: "volume_placement_capacity", Msg: fmt.Sprintf(`POST /machines: HTTP 412 {"error":"failed_precondition: insufficient resources to create new machine with existing volume '%s'","status":"volume_placement_capacity"}`, volume)}
	}
	f.n++
	f.creates++
	id := fmt.Sprintf("%014x", f.n)
	s, _ := sig.NewSigner()
	e, _ := sig.NewSigner()
	f.ms[id] = &fakeM{image: image, state: "created", volume: volume, keys: s, enc: e, source: source}
	if f.lose {
		return "", fmt.Errorf("connection reset")
	}
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
	return FlyMachine{State: m.state, Image: im, Volume: m.volume, Source: m.source}, nil
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
	if f.stuckVols {
		return &FlyError{HTTP: 412, Msg: "volume is attached"}
	}
	delete(f.vols, v)
	return nil
}

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

func (r *rig) input(cert, nz sig.Doc) SpawnInput {
	return SpawnInput{Cert: cert, Notarized: nz, Notarizer: r.w.C["notarizer"].Identity, Region: "lhr", Size: "medium", DiskGB: 10}
}

func (r *rig) spawn() (string, sig.Doc) {
	r.t.Helper()
	cert, nz := r.source()
	out, err := r.sp.Spawn(r.input(cert, nz))
	if err != nil {
		r.t.Fatal(err)
	}
	id := out.(map[string]any)["id"].(string)
	if _, err := r.sp.Init(id); reason(err) != ReasonNotStarted {
		r.t.Fatalf("init before start: %v", err)
	}
	r.fly.start(id)
	d, err := r.sp.Init(id)
	if err != nil {
		r.t.Fatal(err)
	}
	return id, d
}

// reason: the stable reason of a spawner refusal
func reason(err error) string {
	var e *serve.Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func killCert(t *testing.T, out any, err error) (sig.Doc, string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	o := out.(map[string]any)
	return o["cert"].(sig.Doc), o["volumeLeft"].(string)
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
	if r.fly.ms[id].source != string(c.Pred) {
		t.Fatalf("the machine's Fly metadata names %q, not its source", r.fly.ms[id].source)
	}
	r.notarize(d)
	sum := strings.Repeat("ef", 32)
	ssig, _ := r.fly.ms[id].keys.Sign([]byte(sum))
	out, err := r.sp.Kill(id, &Snapshot{Sha256: sum, Sig: ssig})
	kd, left := killCert(t, out, err)
	kc, err := doc.OpenCert(kd, r.w.C["spawner"].Identity.SigningKey)
	if err != nil || kc.Source.Snapshot != sum || kc.Source.Image != img || kc.Pred != doc.Object("fly-"+id) {
		t.Fatal(err, kc)
	}
	r.notarize(kd)
	if len(r.fly.vols) != 0 || left != "" {
		t.Fatalf("volumes left: %v %q", r.fly.vols, left)
	}
	sp2, err := Open(r.path, r.w.C["spawner"], r.w.Trust, r.fly, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err = sp2.Kill(id, nil)
	if again, _ := killCert(t, out, err); again != kd {
		t.Fatal("a second kill signed another cert")
	}
	// the first cert wins: init again answers the cert it signed
	if again, err := sp2.Init(id); err != nil || again != d {
		t.Fatal("init signed a second cert", err)
	}
}

// ✱ a snapshot that isn't signed by the machine's key (another key, not a hash) is refused and the machine untouched;
// ✱ none: the source's own snapshot is passed on
func TestABadSnapshotIsRefused(t *testing.T) {
	r := newRig(t)
	id, _ := r.spawn()
	other, _ := sig.NewSigner()
	sum := strings.Repeat("ef", 32)
	bad, _ := other.Sign([]byte(sum))
	for _, s := range []*Snapshot{{Sha256: sum, Sig: bad}, {}, {Sha256: "x", Sig: bad}} {
		if _, err := r.sp.Kill(id, s); reason(err) != ReasonBadSnapshot {
			t.Fatal(err)
		}
	}
	if r.fly.ms[id].state != "started" {
		t.Fatal("the machine was touched")
	}
	// a machine of a source with a snapshot that signs none passes that snapshot on
	r2 := newRig(t)
	src := kt.SourceContent("t")
	src.Image, src.Snapshot = img, strings.Repeat("cd", 32)
	cert := r2.w.Cert(doc.ByIPhone, doc.Sink, kt.Source(), perm.Top(), src, nil)
	out, err := r2.sp.Spawn(r2.input(cert, r2.notarize(cert)))
	if err != nil {
		t.Fatal(err)
	}
	id2 := out.(map[string]any)["id"].(string)
	r2.fly.start(id2)
	if _, err := r2.sp.Init(id2); err != nil {
		t.Fatal(err)
	}
	out, err = r2.sp.Kill(id2, nil)
	kd2, _ := killCert(t, out, err)
	if kc2, _ := doc.OpenCert(kd2, r2.w.C["spawner"].Identity.SigningKey); kc2.Source.Snapshot != src.Snapshot {
		t.Fatalf("the source's snapshot wasn't passed on: %q", kc2.Source.Snapshot)
	}
}

// ✱ a spawn from a cert that isn't notarized, or not into a source, or with another image, or with no disk; ✱ Fly
// running another digest
func TestSpawnRefuses(t *testing.T) {
	r := newRig(t)
	cert, nz := r.source()
	other, _ := r.source()
	if _, err := r.sp.Spawn(r.input(other, nz)); err == nil {
		t.Fatal("spawned from a cert not notarized")
	}
	src := kt.SourceContent("t")
	src.Image = "docker.io/evil/image@sha256:" + strings.Repeat("3", 64)
	evil := r.w.Cert(doc.ByIPhone, doc.Sink, kt.Source(), perm.Top(), src, nil)
	if _, err := r.sp.Spawn(r.input(evil, r.notarize(evil))); err == nil {
		t.Fatal("spawned another repo's image")
	}
	in := r.input(cert, nz)
	in.Size = "huge"
	if _, err := r.sp.Spawn(in); err == nil {
		t.Fatal("a size that isn't one")
	}
	in = r.input(cert, nz)
	in.DiskGB = 0
	if _, err := r.sp.Spawn(in); err == nil {
		t.Fatal("no disk size")
	}
	out, err := r.sp.Spawn(r.input(cert, nz))
	if err != nil {
		t.Fatal(err)
	}
	id := out.(map[string]any)["id"].(string)
	r.fly.start(id)
	r.fly.swap = "ghcr.io/de0ch/jarvis4-session@sha256:" + strings.Repeat("4", 64)
	if _, err := r.sp.Init(id); reason(err) != ReasonWrongImage {
		t.Fatal(err)
	}
	if _, err := r.sp.Init("nosuch"); reason(err) != ReasonUnknown {
		t.Fatal(err)
	}
}

// a kill waits until Fly says destroyed (409 meanwhile); a machine never up gets a kill record, not a source
func TestKillWaitsForFly(t *testing.T) {
	r := newRig(t)
	cert, nz := r.source()
	out, _ := r.sp.Spawn(r.input(cert, nz))
	id := out.(map[string]any)["id"].(string)
	r.fly.slowStop = true
	if _, err := r.sp.Kill(id, nil); reason(err) != ReasonNotDestroyed {
		t.Fatal(err)
	}
	r.fly.slowStop = false
	out, err := r.sp.Kill(id, nil)
	d, _ := killCert(t, out, err)
	if !strings.Contains(d.Payload, `"up":false`) {
		t.Fatal(d.Payload)
	}
}

// a volume Fly won't delete yet: the kill still answers its cert and names the volume left; the next kill deletes it
// and answers the same cert
func TestAKillTriesTheVolumeOnce(t *testing.T) {
	r := newRig(t)
	id, _ := r.spawn()
	vol := r.fly.ms[id].volume
	r.fly.stuckVols = true
	out, err := r.sp.Kill(id, nil)
	kd, left := killCert(t, out, err)
	if left != vol || !r.fly.vols[vol] {
		t.Fatalf("volume left %q, Fly's %v", left, r.fly.vols)
	}
	r.fly.stuckVols = false
	out, err = r.sp.Kill(id, nil)
	again, left := killCert(t, out, err)
	if again != kd || left != "" || len(r.fly.vols) != 0 {
		t.Fatalf("second kill: same cert %v, left %q, Fly's %v", again == kd, left, r.fly.vols)
	}
}

// a spawn is single calls: ✱ Fly's 412 volume_placement_capacity answers host-full and deletes the volume it made (the
// router spawns again); ✱ every volume is made with the machine's size as its hint; ✱ a lost create answer leaves the
// machine, which the router's destroy takes off Fly with its volume, also after a restart forgot it; ✱ a machine with
// a cert isn't destroyed, and nor is one the spawner didn't make
func TestSpawnIsSingleCalls(t *testing.T) {
	r := newRig(t)
	cert, nz := r.source()
	r.fly.full = true
	if _, err := r.sp.Spawn(r.input(cert, nz)); reason(err) != ReasonHostFull || len(r.fly.vols) != 0 {
		t.Fatalf("host full: %v, volumes %v", err, r.fly.vols)
	}
	r.fly.full = false
	if _, err := r.sp.Spawn(r.input(cert, nz)); err != nil {
		t.Fatal(err)
	}
	for _, g := range r.fly.guests {
		if g["cpus"] == nil || g["memory_mb"] == nil || g["cpu_kind"] == nil {
			t.Fatalf("a volume without the machine's size as its hint: %v", g)
		}
	}

	r2 := newRig(t)
	cert2, nz2 := r2.source()
	r2.fly.lose = true
	if _, err := r2.sp.Spawn(r2.input(cert2, nz2)); reason(err) != ReasonFly {
		t.Fatal(err)
	}
	r2.fly.lose = false
	var stray string
	for id := range r2.fly.ms {
		stray = id
	}
	if r2.fly.ms[stray].source != string(mustPeek(cert2).Succ) {
		t.Fatalf("the stray's metadata: %q", r2.fly.ms[stray].source)
	}
	sp2, _ := Open(r2.path, r2.w.C["spawner"], r2.w.Trust, r2.fly, map[string]string{"JARVIS2_URL": "http://router"})
	out, err := sp2.Destroy(stray)
	if err != nil || out.(map[string]any)["volumeLeft"] != "" || r2.fly.ms[stray].state != "destroyed" || len(r2.fly.vols) != 0 {
		t.Fatalf("destroy: %v %v %s %v", out, err, r2.fly.ms[stray].state, r2.fly.vols)
	}
	if _, err := sp2.Init(stray); err == nil {
		t.Fatal("a destroyed machine initialised")
	}
	if _, err := sp2.Destroy(stray); err != nil {
		t.Fatal("a repeated destroy:", err)
	}

	id, _ := r.spawn()
	if _, err := r.sp.Destroy(id); reason(err) != ReasonCameUp || r.fly.ms[id].state != "started" {
		t.Fatal(err)
	}
	r.fly.ms["elsewhere"] = &fakeM{state: "started"}
	if _, err := r.sp.Destroy("elsewhere"); reason(err) != ReasonUnknown || r.fly.ms["elsewhere"].state != "started" {
		t.Fatal(err)
	}
}

func mustPeek(d sig.Doc) doc.Cert {
	c, _ := doc.PeekCert(d)
	return c
}
