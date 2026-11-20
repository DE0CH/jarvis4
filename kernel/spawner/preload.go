package spawner

// The preloader (docs/PLAN-one-image.md): the spawner's code under a second role. It makes the machines of the
// runner fly-preload in its own Fly app, each on a fork of a golden volume: a volume on which a machine of the same
// session image ran `aviary-sandbox --fetch`, so the session finds aviary's sandbox image already unpacked
// (/data/aviary/image-<digest12>.ok) instead of fetching it for minutes. Fly's forks are lazy: usable at once, their
// blocks read from the golden volume until the copy is done.
//
// Its certs carry its own signer (doc.ByPreloader) and its machines their own objects (flypreload-<id>); the
// notarizer's table gives each of the two only its own machines. A session's volume is forked only from a golden
// volume this preloader made and recorded, never from an id a request names, so no session's files reach another.

import (
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/internal/serve"
)

// Role: which of the two Fly signers a Spawner is
type Role struct {
	Name      string // the roster's role, the cert's signer and the continuity's name
	FlyObject string // the object prefix of its Fly machines
	FlyRunner string // the runner a spawn names for its Fly machines ("" also means fly for the spawner)
}

var (
	SpawnerRole   = Role{Name: doc.BySpawner, FlyObject: "fly", FlyRunner: "fly"}
	PreloaderRole = Role{Name: doc.ByPreloader, FlyObject: "flypreload", FlyRunner: "fly-preload"}
)

// PreloadFlyApp: the preloader's Fly app (its token is narrowed to it, as the spawner's to FlyApp)
const PreloadFlyApp = "jarvis4-sessions-preload"

// Preloads: what the preloader needs of Fly beyond the spawner's calls
type Preloads interface {
	// ForkVolume: a new volume in region, a copy of source (lazy: usable at once), of sizeGB (at least source's)
	ForkVolume(source, region string, sizeGB int, guest map[string]any) (string, error)
	// CreateGolden: a machine of image that runs `aviary-sandbox --fetch` on volume and stops
	CreateGolden(image, region, volume string) (string, error)
}

// Golden: a volume holding a session image's preload in one region
type Golden struct {
	Region  string `json:"region"`
	Image   string `json:"image"` // the session image, pinned by digest
	Volume  string `json:"volume"`
	Machine string `json:"machine,omitempty"` // the machine filling it, until it is done
	SizeGB  int    `json:"sizeGb"`
	State   string `json:"state"` // making, ready, failed
	Asked   string `json:"asked"` // RFC3339 UTC: when this golden was begun
	Error   string `json:"error,omitempty"`
}

// GoldenInput: POST /golden
type GoldenInput struct {
	Region string `json:"region"`
	Image  string `json:"image"`
	DiskGB int    `json:"diskGb"`
}

// keptGoldens: the ready golden volumes kept per region, newest first. A session image is pinned several times a day
// and each golden is a whole volume (about USD 0.15 per GB-month), so older ones go once newer ones are ready; the
// few kept cover sessions still being made from the previous pins.
const keptGoldens = 3

// goldenGuest: the machine that fills a golden volume (crane and tar, nothing else)
var goldenGuest = map[string]any{"cpu_kind": "shared", "cpus": 2, "memory_mb": 2048}

func goldenKey(region, image string) string { return region + " " + imageDigest(image) }

// readyGolden: the ready golden volume for a spawn of image in region (nil: none yet, the spawn gets an empty volume)
func (sp *Spawner) readyGolden(region, image string) *Golden {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if g := sp.goldens[goldenKey(region, image)]; g != nil && g.State == "ready" {
		c := *g
		return &c
	}
	return nil
}

// MakeGolden: one step towards the golden volume of (region, image), the same call until it is ready: none (or a
// failed one) → its volume and the machine that fills it; making → the machine looked at once (stopped with exit 0:
// ready, the machine destroyed and the region's older goldens beyond keptGoldens deleted; stopped otherwise:
// failed, its volume deleted); ready → as it is. Answers the golden.
func (sp *Spawner) MakeGolden(in GoldenInput) (any, error) {
	sp.op.RLock()
	defer sp.op.RUnlock()
	if err := sp.serving(); err != nil {
		return nil, err
	}
	if sp.role != PreloaderRole {
		return nil, serve.Fail(404, "golden volumes are the preloader's")
	}
	pre, ok := sp.fly.(Preloads)
	if !ok {
		return nil, serve.Fail(503, "this preloader's Fly can't fork volumes")
	}
	if imageDigest(in.Image) == "" {
		return nil, serve.Fail(400, "image: %s pinned by digest", SessionRepo)
	}
	if in.Region == "" || in.DiskGB < 1 || in.DiskGB > maxDiskGB {
		return nil, serve.Fail(400, "a region and diskGb 1 to %d", maxDiskGB)
	}
	sp.goldenMu.Lock() // one golden step at a time: they are rare, and each may call Fly
	defer sp.goldenMu.Unlock()
	key := goldenKey(in.Region, in.Image)
	sp.mu.Lock()
	var g Golden
	if old := sp.goldens[key]; old != nil {
		g = *old
	}
	sp.mu.Unlock()
	switch g.State {
	case "ready":
		return g, nil
	case "making":
		fm, err := sp.fly.Inspect(g.Machine)
		if err != nil {
			return nil, flyFail("inspect", err)
		}
		if fm.State != "stopped" && fm.State != "destroyed" {
			return g, nil
		}
		if fm.Exit != nil && *fm.Exit == 0 {
			if err := sp.fly.Destroy(g.Machine); err != nil {
				return nil, flyFail("destroy", err)
			}
			g.State, g.Machine = "ready", ""
			log.Printf("golden volume %s ready (%s, %s)", g.Volume, g.Region, g.Image)
		} else {
			why := "the machine stopped with no exit code"
			if fm.Exit != nil {
				why = fmt.Sprintf("aviary-sandbox --fetch exited %d", *fm.Exit)
			}
			_ = sp.fly.Destroy(g.Machine)
			if err := sp.fly.DeleteVolume(g.Volume); err != nil {
				why += fmt.Sprintf(" (volume %s left: %v)", g.Volume, err)
			}
			g.State, g.Machine, g.Error = "failed", "", why
			log.Printf("golden volume for %s in %s failed: %s", g.Image, g.Region, why)
		}
	default: // none yet, or failed: begin again
		vid, err := sp.fly.CreateVolume(in.Region, in.DiskGB, goldenGuest)
		if err != nil {
			return nil, flyFail("create volume", err)
		}
		mid, err := pre.CreateGolden(in.Image, in.Region, vid)
		if err != nil {
			if derr := sp.fly.DeleteVolume(vid); derr != nil {
				err = fmt.Errorf("%w (volume %s left: %v)", err, vid, derr)
			}
			return nil, flyFail("create", err)
		}
		g = Golden{Region: in.Region, Image: in.Image, Volume: vid, Machine: mid, SizeGB: in.DiskGB, State: "making",
			Asked: time.Now().UTC().Format(time.RFC3339)}
		log.Printf("golden volume %s begun for %s in %s (machine %s)", vid, in.Image, in.Region, mid)
	}
	sp.mu.Lock()
	sp.goldens[key] = &g
	var old []*Golden
	if g.State == "ready" {
		old = sp.overflowGoldens(in.Region)
	}
	err := sp.save()
	sp.mu.Unlock()
	if err != nil {
		return nil, err
	}
	for _, o := range old {
		sp.dropGolden(o)
	}
	return g, nil
}

// overflowGoldens: the region's ready goldens past the newest keptGoldens (callers hold mu)
func (sp *Spawner) overflowGoldens(region string) []*Golden {
	var ready []*Golden
	for _, g := range sp.goldens {
		if g.Region == region && g.State == "ready" {
			ready = append(ready, g)
		}
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i].Asked > ready[j].Asked })
	if len(ready) <= keptGoldens {
		return nil
	}
	return ready[keptGoldens:]
}

// dropGolden: its volume deleted, then its record (a volume Fly won't delete yet stays recorded, and goes on a later
// golden's turn)
func (sp *Spawner) dropGolden(g *Golden) {
	if err := sp.fly.DeleteVolume(g.Volume); err != nil {
		log.Printf("golden volume %s (%s, %s) not deleted yet: %v", g.Volume, g.Region, g.Image, err)
		return
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if cur := sp.goldens[goldenKey(g.Region, g.Image)]; cur != nil && cur.Volume == g.Volume {
		delete(sp.goldens, goldenKey(g.Region, g.Image))
		if err := sp.save(); err != nil {
			log.Printf("saving after golden volume %s: %v", g.Volume, err)
		}
	}
	log.Printf("golden volume %s (%s, %s) deleted", g.Volume, g.Region, g.Image)
}

// Goldens: every golden volume recorded (GET /goldens)
func (sp *Spawner) Goldens() []Golden {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	out := make([]Golden, 0, len(sp.goldens))
	for _, g := range sp.goldens {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Asked > out[j].Asked })
	return out
}

// preloadRunner: a fly-preload machine: a fork of the golden volume (an empty volume while there is none), then the
// machine on it, as flyRunner
type preloadRunner struct {
	Fly
	pre    Preloads
	golden *Golden
}

func (p preloadRunner) Create(in CreateInput) (string, string, error) {
	var vid string
	var err error
	if p.golden != nil {
		vid, err = p.pre.ForkVolume(p.golden.Volume, in.Region, max(in.DiskGB, p.golden.SizeGB), in.Guest)
	} else {
		vid, err = p.Fly.CreateVolume(in.Region, in.DiskGB, in.Guest)
	}
	if err != nil {
		return "", "", err
	}
	id, err := p.Fly.Create(in.Image, in.Region, in.Guest, in.Env, vid, in.Source)
	if err != nil {
		if derr := p.Fly.DeleteVolume(vid); derr != nil {
			err = fmt.Errorf("%w (volume %s left: %v)", err, vid, derr)
		}
		return "", "", err
	}
	return id, vid, nil
}
