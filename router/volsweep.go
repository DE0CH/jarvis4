package main

// The leftover-volume sweep (DECISIONS 195, which builds on 194). A session machine's volume (`jarvis4_state`,
// core/volumes.go) is deleted by the core at the machine's kill, but only while the core remembers it (`vol.live`,
// `vol.orphans`, both in its memory): after a core restart or Reset, or when a test run's core exits, a volume whose
// machine is gone stays in jarvis4-sessions forever, billed. Every 10 minutes the leader router lists the app's
// volumes and machines with its read-only FLY_READ_TOKEN and deletes, with FLY_VOLUME_TOKEN (infra/fly-volume-token.sh:
// a token that can do nothing but delete volumes in jarvis4-sessions), each volume that is
//
//   - named `jarvis4_state` and in state `created`,
//   - attached to nothing and in no listed machine's `config.mounts`,
//   - at least 15 minutes old (a volume between its create and its machine's create looks like a leftover), and
//   - named by no session the router knows: neither its current machine's nor its booted machine's volume (the
//     machine's cert or start record).
//
// A delete Fly answers 404 (already gone) counts as done; a failed one is simply looked at again next sweep. A test
// router (the replica's, the e2e's) has no FLY_VOLUME_TOKEN and never sweeps. The core is unchanged: a volume the
// core still lists in `vol.orphans` and the sweep deletes first only makes the core's later delete a no-op (Fly
// answers a repeated delete with the destroyed volume, 200).

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	volSweepEvery    = 10 * time.Minute
	volSweepFirst    = 2 * time.Minute // after the router starts: its first look, so a rollout shows it working
	volSweepMinAge   = 15 * time.Minute
	volSweepMaxPerGo = 20 // a bug can't empty the app in one sweep
	sessionVolume    = "jarvis4_state"
)

// sweepMachine: a machine as the sweep needs it (its mounts)
type sweepMachine struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Config struct {
		Mounts []struct {
			Volume string `json:"volume"`
		} `json:"mounts"`
	} `json:"config"`
}

// sweepChoice: what one sweep decided, volume by volume
type sweepChoice struct {
	Delete []string          // volume ids to delete
	Kept   map[string]string // volume id → why it stays ("category: detail")
}

// sweepSelect: the pure decision (tested): which volumes are leftovers. named = volume id → who names it.
func sweepSelect(vols []flyVolume, ms []sweepMachine, named map[string]string, now time.Time) sweepChoice {
	mounted := map[string]string{}
	for _, m := range ms {
		if m.State == "destroyed" {
			continue
		}
		for _, mt := range m.Config.Mounts {
			if mt.Volume != "" {
				mounted[mt.Volume] = m.ID
			}
		}
	}
	out := sweepChoice{Kept: map[string]string{}}
	for _, v := range vols {
		why := ""
		switch {
		case v.Name != sessionVolume:
			why = "other name: " + v.Name
		case v.State != "created":
			why = "state: " + v.State
		case v.AttachedMachineID != "":
			why = "attached: " + v.AttachedMachineID
		case mounted[v.ID] != "":
			why = "mounted: " + mounted[v.ID]
		case named[v.ID] != "":
			why = "named: " + named[v.ID]
		default:
			t, err := time.Parse(time.RFC3339, v.CreatedAt)
			if err != nil {
				why = "no creation time: " + v.CreatedAt
			} else if now.Sub(t) < volSweepMinAge {
				why = "young: created " + v.CreatedAt
			}
		}
		if why != "" {
			out.Kept[v.ID] = why
			continue
		}
		if len(out.Delete) >= volSweepMaxPerGo {
			out.Kept[v.ID] = "limit: next sweep"
			continue
		}
		out.Delete = append(out.Delete, v.ID)
	}
	sort.Strings(out.Delete)
	return out
}

// certVolume: the volume a core-signed cert names for its machine ("" = none)
func certVolume(d *Doc) string {
	if d == nil {
		return ""
	}
	var c struct {
		Machine *struct {
			Volume *Volume `json:"volume"`
		} `json:"machine"`
	}
	if d.Decode(&c) != nil || c.Machine == nil || c.Machine.Volume == nil {
		return ""
	}
	return c.Machine.Volume.ID
}

// sweepNamed: every volume a session the router knows still names (called with nothing held)
func (r *Router) sweepNamed() map[string]string {
	named := map[string]string{}
	add := func(vol, who string) {
		if vol != "" && named[vol] == "" {
			named[vol] = who
		}
	}
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			add(certVolume(s.Cert), "session "+s.ID+"'s line")
			add(certVolume(d.SessCerts[s.ID]), "session "+s.ID+"'s line")
			for _, m := range []string{s.MachineID, s.Booted} {
				if m == "" {
					continue
				}
				add(certVolume(d.Certs[m]), "session "+s.ID+"'s machine "+m)
				if st := d.Started[m]; st != nil && st.Volume != nil {
					add(st.Volume.ID, "session "+s.ID+"'s machine "+m)
				}
			}
		}
	})
	return named
}

// volumeDelete: DELETE one volume with the volume-only token; 200 and 404 (gone) are done. Swappable in tests.
var volumeDelete = func(token, id string) error {
	req, _ := http.NewRequest("DELETE", "https://api.machines.dev/v1/apps/"+sessionsApp+"/volumes/"+url.PathEscape(id), nil)
	auth := token
	if !strings.HasPrefix(auth, "FlyV1 ") && !strings.HasPrefix(auth, "Bearer ") {
		auth = "Bearer " + auth
	}
	req.Header.Set("Authorization", auth)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode == 200 || resp.StatusCode == 404 {
		return nil
	}
	return fmt.Errorf("HTTP %d", resp.StatusCode)
}

// volSweepReader: the Fly lists (read-only token); swappable in tests
var volSweepReader = func() (vols []flyVolume, ms []sweepMachine, err error) {
	f := machinesFly()
	if f == nil {
		return nil, nil, fmt.Errorf("FLY_READ_TOKEN not set")
	}
	if err := f.get("/volumes", &vols); err != nil {
		return nil, nil, err
	}
	if err := f.get("/machines", &ms); err != nil {
		return nil, nil, err
	}
	return vols, ms, nil
}

var volSweepStatus struct {
	sync.Mutex
	v map[string]any
}

// volumeSweep: one sweep. Returns the ids deleted.
func (r *Router) volumeSweep(token string, now time.Time) ([]string, error) {
	vols, ms, err := volSweepReader()
	if err != nil {
		return nil, fmt.Errorf("Fly list: %v", err)
	}
	// the named set is read AFTER the Fly lists: a session that starts in between names its volume by then, or its
	// volume is under 15 minutes old
	ch := sweepSelect(vols, ms, r.sweepNamed(), now)
	deleted, failed := []string{}, map[string]string{}
	for _, id := range ch.Delete {
		if err := volumeDelete(token, id); err != nil {
			failed[id] = err.Error()
			continue
		}
		deleted = append(deleted, id)
	}
	kept := map[string]int{}
	for _, why := range ch.Kept {
		cat, _, _ := strings.Cut(why, ":")
		kept[cat]++
	}
	log.Printf("[volsweep] %d volumes, %d machines in %s: deleted %v, failed %v (tried again next sweep), kept %v",
		len(vols), len(ms), sessionsApp, deleted, failed, kept)
	volSweepStatus.Lock()
	volSweepStatus.v = map[string]any{"checkedAt": now.UTC().Format(time.RFC3339), "volumes": len(vols), "deleted": deleted,
		"failed": failed, "kept": kept}
	volSweepStatus.Unlock()
	return deleted, nil
}

func (r *Router) volSweepLoop() {
	token := os.Getenv("FLY_VOLUME_TOKEN")
	if token == "" || os.Getenv("FLY_READ_TOKEN") == "" {
		log.Printf("[volsweep] FLY_VOLUME_TOKEN or FLY_READ_TOKEN unset: no leftover-volume sweep")
		volSweepStatus.Lock()
		volSweepStatus.v = map[string]any{"error": "off: FLY_VOLUME_TOKEN or FLY_READ_TOKEN not set"}
		volSweepStatus.Unlock()
		return
	}
	time.Sleep(volSweepFirst)
	for {
		awaitLead() // leaderlease.go
		if _, err := r.volumeSweep(token, time.Now()); err != nil {
			log.Printf("[volsweep] %v (tried again in %s)", err, volSweepEvery)
			volSweepStatus.Lock()
			volSweepStatus.v = map[string]any{"checkedAt": time.Now().UTC().Format(time.RFC3339), "error": err.Error()}
			volSweepStatus.Unlock()
		}
		time.Sleep(volSweepEvery)
	}
}

// volumeSweepStatus: the last sweep, for /setup/status (counts and ids only)
func volumeSweepStatus() map[string]any {
	volSweepStatus.Lock()
	defer volSweepStatus.Unlock()
	return volSweepStatus.v
}
