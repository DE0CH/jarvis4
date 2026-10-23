package main

// Volumes: each session machine keeps its state (the snapshot's paths: ~/workspace, ~/artifacts, the transcripts,
// ~/.claude.json, …) on a Fly volume of its own, mounted at /data (the machine bind-mounts those paths onto it). The
// core, the only holder of the Fly token, makes it with the machine and ends it with the machine's kill:
//
//   kill = (the machine's own signed snapshot, or none) → destroy the machine → only once Fly reports it destroyed:
//          delete the volume.
//
// No Fly volume snapshot of any kind is taken (Deyao, 2026-10-22: "modify to not take volumn snapshot"; DECISIONS
// 222): volumes are made with Fly's daily automatic snapshots off, and a kill takes none. The machine's signed
// snapshot is the only copy of its state. A successor always gets a new, empty volume and its state from the
// predecessor's signed snapshot, so a volume never carries one line's data into another machine.
//
// More disk = Extend: the live machine's volume grows (Fly can't shrink one); the router asks for the size a
// successor's volume gets in each StartRequest (DiskGB).
//
// A Fly without VolumeFly (the CI fake, the tests' plain fake) makes machines without volumes: everything else is
// unchanged.

import (
	"fmt"
	"strings"
)

const (
	volumePath    = "/data" // where the machine finds its volume (machine/volume.go)
	volumeName    = "jarvis4_state"
	defaultDiskGB = 10  // a session's volume when the router asks for no size
	maxDiskGB     = 500 // the largest volume a start or Extend makes
)

// VolumeFly: the Fly calls volumes need (FlyAPI; single calls, no waiting, like Fly)
type VolumeFly interface {
	CreateVolume(region string, sizeGB int, guest map[string]any) (string, error)
	CreateWithVolume(r StartRequest, guest map[string]any, env map[string]string, volume, path string) (string, error)
	ExtendVolume(volume string, sizeGB int) (needsRestart bool, err error)
	DeleteVolume(volume string) error
}

// VolumeInfo: a machine's volume, in its "created" and "started" documents and so in its cert
type VolumeInfo struct {
	ID     string `json:"id"`
	SizeGB int    `json:"sizeGb"`
	Path   string `json:"path"`
}

type volState struct {
	live    map[string]*VolumeInfo // a machine this core made → its volume (until the kill deletes it)
	orphans map[string]bool        // volumes whose delete failed: tried again at every kill
}

func newVolState() volState {
	return volState{live: map[string]*VolumeInfo{}, orphans: map[string]bool{}}
}

func (c *Core) volumeFly() (VolumeFly, bool) {
	vf, ok := c.fly.(VolumeFly)
	return vf, ok
}

// diskSize: the volume a start makes (0 = the default)
func diskSize(gb int) (int, error) {
	switch {
	case gb == 0:
		return defaultDiskGB, nil
	case gb < 1 || gb > maxDiskGB:
		return 0, fail(400, "diskGb: 1 to %d (0 = %d)", maxDiskGB, defaultDiskGB)
	}
	return gb, nil
}

// placementTries: how many new volumes a start makes when Fly answers that a volume's host has no room for the
// machine (412 volume_placement_capacity): a volume is pinned to one host, so a new one is the way to another host
const placementTries = 3

// hostFull: Fly's answer that the volume's host has no room for a machine of this size
func hostFull(err error) bool {
	return err != nil && strings.Contains(err.Error(), "volume_placement_capacity")
}

// createMachine: Start's Fly create, with a new empty volume when Fly has volumes. The volume goes again if the
// machine can't be made.
func (c *Core) createMachine(r StartRequest, guest map[string]any, env map[string]string) (string, *VolumeInfo, error) {
	vf, ok := c.volumeFly()
	if !ok {
		id, err := c.fly.Create(r, guest, env)
		return id, nil, err
	}
	gb, err := diskSize(r.DiskGB)
	if err != nil {
		return "", nil, err
	}
	var vid, id string
	for try := 1; ; try++ {
		if vid, err = vf.CreateVolume(r.Region, gb, guest); err != nil {
			return "", nil, fmt.Errorf("volume: %w", err)
		}
		if id, err = vf.CreateWithVolume(r, guest, env, vid, volumePath); err == nil {
			break
		}
		if derr := vf.DeleteVolume(vid); derr != nil {
			c.mu.Lock()
			c.vol.orphans[vid] = true
			c.mu.Unlock()
		}
		// the volume's host had no room for the machine: a new volume lands elsewhere
		if !hostFull(err) || try == placementTries {
			return "", nil, err
		}
		c.logf("start: volume %s's host is full (%v); a new volume, try %d", vid, err, try+1)
	}
	v := &VolumeInfo{ID: vid, SizeGB: gb, Path: volumePath}
	c.logf("machine %s: volume %s (%d GB)", id, vid, gb) // infra/run-volumes.py reads a test run's volumes from it
	c.mu.Lock()
	c.vol.live[id] = v
	c.mu.Unlock()
	return id, v, nil
}

// dropVolume: after Fly confirmed the machine destroyed, its volume goes; a delete that fails is tried again at the
// next kill
func (c *Core) dropVolume(id string) {
	vf, ok := c.volumeFly()
	c.mu.Lock()
	v := c.vol.live[id]
	delete(c.vol.live, id)
	todo := []string{}
	if v != nil {
		c.vol.orphans[v.ID] = true
	}
	for o := range c.vol.orphans {
		todo = append(todo, o)
	}
	c.mu.Unlock()
	if !ok {
		return
	}
	for _, vid := range todo {
		if err := vf.DeleteVolume(vid); err != nil {
			c.logf("volume %s: delete: %v (tried again at the next kill)", vid, err)
			continue
		}
		c.mu.Lock()
		delete(c.vol.orphans, vid)
		c.mu.Unlock()
	}
}

// Extend: the live machine's volume grows to sizeGB (More disk). Fly says whether the machine must restart to see
// it; the router then pauses and resumes it (the successor's volume is made at the new size).
func (c *Core) Extend(id string, sizeGB int) (SignedDoc, error) {
	vf, ok := c.volumeFly()
	if !ok {
		return SignedDoc{}, fail(501, "this core's Fly has no volumes")
	}
	c.mu.Lock()
	v := c.vol.live[id]
	live := c.signing[id] != "" && !c.isKilled(id)
	var cur VolumeInfo
	if v != nil {
		cur = *v
	}
	c.mu.Unlock()
	if v == nil || !live {
		return SignedDoc{}, fail(409, "machine %s has no volume of this core", id)
	}
	if sizeGB <= cur.SizeGB || sizeGB > maxDiskGB {
		return SignedDoc{}, fail(400, "sizeGb: more than the volume's %d GB, at most %d", cur.SizeGB, maxDiskGB)
	}
	restart, err := vf.ExtendVolume(cur.ID, sizeGB)
	if err != nil {
		return SignedDoc{}, fail(502, "fly volume extend: %v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if v := c.vol.live[id]; v != nil {
		v.SizeGB = sizeGB
	}
	c.logf("machine %s: volume %s extended to %d GB (restart: %v)", id, cur.ID, sizeGB, restart)
	return c.sign(map[string]any{"kind": "extended", "id": id, "volume": cur.ID, "sizeGb": sizeGB, "needsRestart": restart})
}
