package spawner

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/doc"
)

// preFly: the fake Fly with the preloader's calls: forks record their source and size, a golden machine runs until
// the test stops it with an exit code
type preFly struct {
	*fakeFly
	forks   []fork
	goldens map[string]*int // golden machine → its exit code once stopped (nil: running)
	envs    map[string]map[string]string
	sizes   map[string]int // volume → size
}

type fork struct {
	source, volume string
	size           int
}

func newPreFly() *preFly {
	return &preFly{fakeFly: newFly(), goldens: map[string]*int{}, envs: map[string]map[string]string{}, sizes: map[string]int{}}
}

func (f *preFly) CreateVolume(region string, size int, guest map[string]any) (string, error) {
	v, err := f.fakeFly.CreateVolume(region, size, guest)
	f.sizes[v] = size
	return v, err
}

func (f *preFly) ForkVolume(source, region string, guest map[string]any) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.vols[source] {
		return "", &FlyError{HTTP: 404, Msg: "no volume " + source}
	}
	f.n++
	v := fmt.Sprintf("vol_%d", f.n)
	f.vols[v] = true
	f.sizes[v] = f.sizes[source]
	f.forks = append(f.forks, fork{source, v, f.sizes[source]})
	return v, nil
}

func (f *preFly) CreateGolden(image, region, volume string) (string, error) {
	id, err := f.fakeFly.Create(image, region, goldenGuest, nil, volume, "")
	if err == nil {
		f.goldens[id] = nil
		f.fakeFly.start(id)
	}
	return id, err
}

func (f *preFly) Create(image, region string, guest map[string]any, env map[string]string, volume, source string) (string, error) {
	id, err := f.fakeFly.Create(image, region, guest, env, volume, source)
	f.envs[id] = env
	return id, err
}

// exit: the golden machine id stops with code
func (f *preFly) exit(id string, code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.goldens[id] = &code
	f.ms[id].state = "stopped"
}

func (f *preFly) Inspect(id string) (FlyMachine, error) {
	fm, err := f.fakeFly.Inspect(id)
	if code, ok := f.goldens[id]; ok {
		fm.Exit = code
	}
	return fm, err
}

func newPreloadRig(t *testing.T) (*rig, *preFly) {
	r := newRig(t)
	fly := newPreFly()
	sp, err := OpenRole(PreloaderRole, filepath.Join(t.TempDir(), "pre.json"), r.w.C["preloader"], r.w.Trust, fly, nil,
		map[string]string{"JARVIS2_URL": "http://router"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.sp, r.path = sp, sp.path
	r.fly = fly.fakeFly
	return r, fly
}

func mg(t *testing.T, sp *Spawner, in GoldenInput) Golden {
	t.Helper()
	out, err := sp.MakeGolden(in)
	if err != nil {
		t.Fatal(err)
	}
	return out.(Golden)
}

// readyGolden: a golden volume for img in region, begun and filled
func readyGoldenIn(t *testing.T, sp *Spawner, fly *preFly, region string, image string) Golden {
	t.Helper()
	g := mg(t, sp, GoldenInput{Region: region, Image: image, DiskGB: 20})
	fly.exit(g.Machine, 0)
	return mg(t, sp, GoldenInput{Region: region, Image: image, DiskGB: 20})
}

// ✱ each of the two makes only its own runner's machines
func TestThePreloaderMakesOnlyFlyPreloadMachines(t *testing.T) {
	r, _ := newPreloadRig(t)
	for _, runner := range []string{"", "fly", "aws", "fabric"} {
		cert, nz := r.source()
		in := r.input(cert, nz)
		in.Runner = runner
		if _, err := r.sp.Spawn(in); err == nil {
			t.Fatalf("the preloader made a %q machine", runner)
		}
	}
	s := newRig(t)
	cert, nz := s.source()
	in := s.input(cert, nz)
	in.Runner = "fly-preload"
	if _, err := s.sp.Spawn(in); err == nil {
		t.Fatal("the spawner made a fly-preload machine")
	}
	if _, err := s.sp.MakeGolden(GoldenInput{Region: "lhr", Image: img, DiskGB: 20}); err == nil {
		t.Fatal("the spawner made a golden volume")
	}
}

// a golden volume: begun (its volume and the machine that fills it), still making while that machine runs, ready once
// it stops with exit 0 (the machine destroyed, the volume kept); then a fly-preload spawn in that region is a fork of
// its size, named flypreload-<id> in the preloader's cert, which the notarizer takes
func TestAFlyPreloadSessionStartsOnAForkOfTheGoldenVolume(t *testing.T) {
	r, fly := newPreloadRig(t)
	g := mg(t, r.sp, GoldenInput{Region: "lhr", Image: img, DiskGB: 20})
	if g.State != "making" || g.Volume == "" || g.Machine == "" || g.SizeGB != 20 {
		t.Fatalf("begun: %+v", g)
	}
	if again := mg(t, r.sp, GoldenInput{Region: "lhr", Image: img, DiskGB: 20}); again.State != "making" || again.Machine != g.Machine {
		t.Fatalf("while its machine runs: %+v", again)
	}
	fly.exit(g.Machine, 0)
	g = mg(t, r.sp, GoldenInput{Region: "lhr", Image: img, DiskGB: 20})
	if g.State != "ready" || g.Machine != "" || !fly.vols[g.Volume] {
		t.Fatalf("filled: %+v", g)
	}
	for id := range fly.goldens {
		if fly.ms[id].state != "destroyed" {
			t.Fatalf("the golden machine %s is %s", id, fly.ms[id].state)
		}
	}
	cert, nz := r.source()
	in := r.input(cert, nz)
	in.Runner = "fly-preload"
	out, err := r.sp.Spawn(in)
	if err != nil {
		t.Fatal(err)
	}
	o := out.(map[string]any)
	id := o["id"].(string)
	if len(fly.forks) != 1 || fly.forks[0].source != g.Volume || fly.forks[0].volume != o["volume"] || fly.forks[0].size != 20 {
		t.Fatalf("forks %+v, spawn %+v", fly.forks, o)
	}
	if fly.envs[id]["JARVIS2_RUNNER"] != "fly-preload" {
		t.Fatalf("the machine's env: %v", fly.envs[id])
	}
	fly.start(id)
	d, err := r.sp.Init(id)
	if err != nil {
		t.Fatal(err)
	}
	c, err := doc.OpenCert(d, r.w.C["preloader"].Identity.SigningKey)
	if err != nil || c.Signer != doc.ByPreloader || c.Succ != doc.Object("flypreload-"+id) {
		t.Fatal(err, c)
	}
	r.notarize(d)
	// a disk bigger than the golden volume: an empty volume (Fly can't make a fork bigger at once)
	cert, nz = r.source()
	in = r.input(cert, nz)
	in.Runner, in.DiskGB = "fly-preload", 30
	if _, err := r.sp.Spawn(in); err != nil || len(fly.forks) != 1 {
		t.Fatalf("a disk bigger than the golden: %v, forks %+v", err, fly.forks)
	}
	// another region has no golden yet: an empty volume, as the plain fly runner
	cert, nz = r.source()
	in = r.input(cert, nz)
	in.Runner, in.Region = "fly-preload", "sin"
	if _, err := r.sp.Spawn(in); err != nil || len(fly.forks) != 1 {
		t.Fatalf("a region with no golden: %v, forks %+v", err, fly.forks)
	}
}

// ✱ a golden whose machine fails (exit ≠ 0) is failed and its volume deleted; the next call begins it again
func TestAFailedGoldenIsBegunAgain(t *testing.T) {
	r, fly := newPreloadRig(t)
	g := mg(t, r.sp, GoldenInput{Region: "lhr", Image: img, DiskGB: 20})
	fly.exit(g.Machine, 1)
	f := mg(t, r.sp, GoldenInput{Region: "lhr", Image: img, DiskGB: 20})
	if f.State != "failed" || fly.vols[g.Volume] || f.Error == "" {
		t.Fatalf("failed: %+v (volume kept: %v)", f, fly.vols[g.Volume])
	}
	cert, nz := r.source()
	in := r.input(cert, nz)
	in.Runner = "fly-preload"
	if _, err := r.sp.Spawn(in); err != nil || len(fly.forks) != 0 {
		t.Fatalf("a spawn with a failed golden: %v, forks %+v", err, fly.forks)
	}
	again := mg(t, r.sp, GoldenInput{Region: "lhr", Image: img, DiskGB: 20})
	if again.State != "making" || again.Volume == g.Volume {
		t.Fatalf("begun again: %+v", again)
	}
}

// a region keeps its newest keptGoldens ready golden volumes; an older one's volume is deleted; other regions keep
// theirs; the goldens survive a restart and a handoff to the other kernel copy
func TestOldGoldensGoAndTheRestSurvive(t *testing.T) {
	r, fly := newPreloadRig(t)
	var made []Golden
	for i := range keptGoldens + 1 {
		image := fmt.Sprintf("ghcr.io/de0ch/jarvis4-session@sha256:%064x", i+1)
		g := readyGoldenIn(t, r.sp, fly, "lhr", image)
		r.sp.mu.Lock()
		r.sp.goldens[goldenKey("lhr", image)].Asked = fmt.Sprintf("2026-11-20T00:00:%02dZ", i) // in order
		r.sp.mu.Unlock()
		made = append(made, g)
	}
	other := readyGoldenIn(t, r.sp, fly, "sin", img)
	// the last one's turn came before its Asked was rewritten: one more ready golden makes the order count
	newest := readyGoldenIn(t, r.sp, fly, "lhr", "ghcr.io/de0ch/jarvis4-session@sha256:"+fmt.Sprintf("%064x", 99))
	kept := map[string]bool{}
	for _, g := range r.sp.Goldens() {
		kept[g.Volume] = true
	}
	if kept[made[0].Volume] || kept[made[1].Volume] || fly.vols[made[0].Volume] || fly.vols[made[1].Volume] {
		t.Fatalf("the oldest goldens stayed: %v", kept)
	}
	if !kept[made[2].Volume] || !kept[made[3].Volume] || !kept[newest.Volume] || !kept[other.Volume] {
		t.Fatalf("a golden that should stay went: %v", kept)
	}
	// a restart reads them back
	sp2, err := OpenRole(PreloaderRole, r.path, r.w.C["preloader"], r.w.Trust, fly, nil, nil, nil)
	if err != nil || len(sp2.Goldens()) != len(r.sp.Goldens()) {
		t.Fatalf("after a restart: %v, %d goldens", err, len(sp2.Goldens()))
	}
	// a handoff carries them
	h, err := handoffState(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Goldens) != len(r.sp.Goldens()) {
		t.Fatalf("handed %d goldens", len(h.Goldens))
	}
}

func handoffState(r *rig) (handed, error) {
	r.sp.mu.Lock()
	defer r.sp.mu.Unlock()
	return handed{Machines: r.sp.machines, Goldens: r.sp.goldens}, nil
}

// the notarizer refuses the preloader's cert for a machine object of the spawner's runner (and the spawner's for its)
func TestThePreloadersCertsNameOnlyItsObjects(t *testing.T) {
	r, fly := newPreloadRig(t)
	readyGoldenIn(t, r.sp, fly, "lhr", img)
	cert, nz := r.source()
	in := r.input(cert, nz)
	in.Runner = "fly-preload"
	out, err := r.sp.Spawn(in)
	if err != nil {
		t.Fatal(err)
	}
	id := out.(map[string]any)["id"].(string)
	if r.sp.object(id) != doc.Object("flypreload-"+id) {
		t.Fatalf("object %s", r.sp.object(id))
	}
	s := newRig(t)
	if s.sp.object(id) != doc.Object("fly-"+id) {
		t.Fatalf("the spawner's object %s", s.sp.object(id))
	}
}
