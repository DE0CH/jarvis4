package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// volFly: the tests' fake Fly with volumes (volumes.go)
type volFly struct {
	*fakeFly
	n         int
	vols      map[string]*fakeVol
	mounts    map[string]string // machine → volume
	calls     []string
	createErr error
	full      int              // the next this-many creates answer that the volume's host is full
	guests    []map[string]any // each volume's compute hint
}

type fakeVol struct {
	size    int
	deleted bool
}

func withVolumes(c *Core, f *fakeFly) *volFly {
	v := &volFly{fakeFly: f, vols: map[string]*fakeVol{}, mounts: map[string]string{}}
	c.fly = v
	return v
}

func (v *volFly) log(s string, a ...any) { v.calls = append(v.calls, fmt.Sprintf(s, a...)) }

func (v *volFly) CreateVolume(region string, sizeGB int, guest map[string]any) (string, error) {
	v.guests = append(v.guests, guest)
	v.n++
	id := fmt.Sprintf("vol_%d", v.n)
	v.vols[id] = &fakeVol{size: sizeGB}
	v.log("create-volume %s %d", id, sizeGB)
	return id, nil
}
func (v *volFly) CreateWithVolume(r StartRequest, guest map[string]any, env map[string]string, volume, path string) (string, error) {
	if v.createErr != nil {
		return "", v.createErr
	}
	if v.full > 0 {
		v.full--
		return "", fmt.Errorf(`POST /machines: HTTP 412 {"status":"volume_placement_capacity"}`)
	}
	id, err := v.fakeFly.Create(r, guest, env)
	v.mounts[id] = volume + ":" + path
	return id, err
}
func (v *volFly) ExtendVolume(vol string, size int) (bool, error) {
	v.vols[vol].size = size
	v.log("extend %s %d", vol, size)
	return true, nil
}
func (v *volFly) DeleteVolume(vol string) error {
	if fv := v.vols[vol]; fv != nil {
		fv.deleted = true
	}
	v.log("delete-volume %s", vol)
	return nil
}
func (v *volFly) Destroy(id string) error {
	v.log("destroy %s", id)
	return v.fakeFly.Destroy(id)
}

func volumeOf(t *testing.T, v *volFly, machine string) string {
	t.Helper()
	vol, _, _ := strings.Cut(v.mounts[machine], ":")
	if vol == "" {
		t.Fatalf("machine %s has no volume", machine)
	}
	return vol
}

func status(err error) int {
	if e, ok := err.(*Err); ok {
		return e.Status
	}
	return 0
}

// every machine gets its own new, empty volume at /data, named in its cert; the size is the router's ask
func TestAStartMakesTheMachinesOwnVolume(t *testing.T) {
	c, f, p := setup(t)
	v := withVolumes(c, f)
	d, id := newLine(t, c, p, "default")
	vol := volumeOf(t, v, id)
	if v.mounts[id] != vol+":/data" || v.vols[vol].size != defaultDiskGB {
		t.Fatalf("volume %s %+v", v.mounts[id], v.vols[vol])
	}
	cert := certOf(t, d)
	if cert.Machine.Volume == nil || cert.Machine.Volume.ID != vol || cert.Machine.Volume.Path != "/data" || cert.Machine.Volume.SizeGB != defaultDiskGB {
		t.Fatalf("the cert names %+v", cert.Machine.Volume)
	}
	created := pl(t)(c.Start(StartRequest{Image: img, Region: "lhr", Size: "large", DiskGB: 40}))
	if vv, _ := created["volume"].(map[string]any); vv == nil || vv["sizeGb"] != float64(40) {
		t.Fatalf("created %v", created)
	}
	if _, err := c.Start(StartRequest{Image: img, Region: "lhr", Size: "large", DiskGB: maxDiskGB + 1}); status(err) != 400 {
		t.Fatalf("a %d GB disk: %v", maxDiskGB+1, err)
	}
	// a machine Fly can't make leaves no volume behind
	v.createErr = fmt.Errorf("no capacity")
	before := len(v.vols)
	if _, err := c.Start(StartRequest{Image: img, Region: "lhr", Size: "large"}); err == nil {
		t.Fatal("started anyway")
	}
	if len(v.vols) != before+1 || !v.vols[fmt.Sprintf("vol_%d", v.n)].deleted {
		t.Fatal("the failed start's volume wasn't deleted")
	}
}

// a volume's host with no room for the machine: the start makes a new volume (another host), up to placementTries;
// the volumes it gave up on go, and each carries the machine's size as its placement hint
func TestAStartMovesOffAFullHost(t *testing.T) {
	c, f, _ := setup(t)
	v := withVolumes(c, f)
	v.full = 2
	created := pl(t)(c.Start(StartRequest{Image: img, Region: "lhr", Size: "large"}))
	live := 0
	for _, fv := range v.vols {
		if !fv.deleted {
			live++
		}
	}
	if created["id"] == nil || len(v.vols) != 3 || live != 1 || len(v.guests) != 3 || v.guests[0]["memory_mb"] == nil {
		t.Fatalf("created %v vols=%d live=%d guests=%v", created, len(v.vols), live, v.guests)
	}
	v.full = 100
	if _, err := c.Start(StartRequest{Image: img, Region: "lhr", Size: "large"}); err == nil || !strings.Contains(err.Error(), "volume_placement_capacity") {
		t.Fatalf("always full: %v", err)
	}
	if len(v.guests) != 3+placementTries {
		t.Fatalf("tries: %d volumes", len(v.guests)-3)
	}
}

// the kill: the destroy, and only once Fly reports it destroyed the volume's delete; no volume snapshot, no stop
// first, and the signed record names only the machine's own snapshot
func TestAKillDestroysThenDeletesTheVolume(t *testing.T) {
	c, f, p := setup(t)
	v := withVolumes(c, f)
	_, id := newLine(t, c, p, "default")
	vol := volumeOf(t, v, id)
	sum := strings.Repeat("ab", 32)
	claim := &SnapshotClaim{Sha256: sum, Sig: machineSign(f.machines[id].sig, sum)}
	k := pl(t)(c.KillWithSnapshot(id, claim))
	if k["snapshot"] != sum || k["backup"] != nil {
		t.Fatalf("record %v", k)
	}
	if !f.machines[id].destroyed || !v.vols[vol].deleted {
		t.Fatal("machine or volume left")
	}
	want := []string{"destroy " + id, "delete-volume " + vol}
	got := []string{}
	for _, x := range v.calls {
		if !strings.HasPrefix(x, "create-volume") {
			got = append(got, x)
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("calls %v", v.calls)
	}
	// without the machine's own snapshot the kill is the same
	_, id2 := newLine(t, c, p, "default")
	if k := pl(t)(c.KillWithSnapshot(id2, nil)); k["snapshot"] != "" || k["backup"] != nil || !v.vols[volumeOf(t, v, id2)].deleted {
		t.Fatalf("record %v", k)
	}
}

// More disk: only growth, only a live machine's own volume; a Fly without volumes says so
func TestExtendGrowsTheLiveVolumeOnly(t *testing.T) {
	c, f, p := setup(t)
	if _, err := c.Extend("m1", 20); status(err) != 501 {
		t.Fatalf("no volumes: %v", err)
	}
	v := withVolumes(c, f)
	_, id := newLine(t, c, p, "default")
	vol := volumeOf(t, v, id)
	if _, err := c.Extend(id, defaultDiskGB); status(err) != 400 {
		t.Fatalf("no growth: %v", err)
	}
	d := pl(t)(c.Extend(id, 20))
	if d["kind"] != "extended" || d["sizeGb"] != float64(20) || d["needsRestart"] != true || v.vols[vol].size != 20 {
		t.Fatalf("extend %v", d)
	}
	if _, err := c.Extend("nope", 40); status(err) != 409 {
		t.Fatalf("another machine: %v", err)
	}
}

// a core that takes the line over (continuity.go) knows the live machines' volumes; a line state an earlier core
// sealed with "backups" still reads
func TestTheLineStateCarriesVolumes(t *testing.T) {
	c, f, p := setup(t)
	v := withVolumes(c, f)
	_, a := newLine(t, c, p, "default")
	c.mu.Lock()
	st := c.lineSnapshot()
	c.mu.Unlock()
	raw, _ := json.Marshal(st)
	var m map[string]any
	json.Unmarshal(raw, &m)
	m["backups"] = map[string]any{"m0": map[string]any{"volume": "vol_0", "snapshot": "vs_0", "retentionDays": 3}}
	raw, _ = json.Marshal(m)
	var back lineState
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	c2, _, _ := newCore(t)
	c2.mu.Lock()
	c2.restoreLine(back, false)
	c2.mu.Unlock()
	if c2.vol.live[a] == nil || c2.vol.live[a].ID != volumeOf(t, v, a) {
		t.Fatalf("live %v", c2.vol.live)
	}
}
