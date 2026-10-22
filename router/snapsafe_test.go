package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// volCore: a core that kills like a core with volumes (core/volumes.go): the record names the backup
type volCore struct {
	fakeCore
	mu      sync.Mutex
	kills   int
	extends []map[string]any
	restart bool
	oldKill bool // the kill record names a volume backup, as an earlier core's did: read without acting on it
}

func (c *volCore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/kill":
		var in struct {
			Machine  string `json:"machine"`
			Snapshot *struct {
				Sha256 string `json:"sha256"`
			} `json:"snapshot"`
		}
		json.NewDecoder(req.Body).Decode(&in)
		c.mu.Lock()
		c.kills++
		c.mu.Unlock()
		sum := ""
		if in.Snapshot != nil {
			sum = in.Snapshot.Sha256
		}
		rec := map[string]any{"kind": "killed", "id": in.Machine, "snapshot": sum}
		if c.oldKill {
			rec["backup"] = map[string]any{"volume": "vol_" + in.Machine, "snapshot": "vs_" + in.Machine, "at": "2026-10-15T05:00:00Z", "retentionDays": 60, "signedSnapshot": sum != ""}
		}
		writeJSON(w, 200, c.key.doc(rec))
	case "/extend":
		var in map[string]any
		json.NewDecoder(req.Body).Decode(&in)
		c.mu.Lock()
		c.extends = append(c.extends, in)
		restart := c.restart
		c.mu.Unlock()
		writeJSON(w, 200, c.key.doc(map[string]any{"kind": "extended", "id": in["machine"], "sizeGb": in["sizeGb"], "needsRestart": restart}))
	default:
		c.fakeCore.ServeHTTP(w, req)
	}
}

func volRig(t *testing.T) (*rig, *volCore) {
	rg := newRig(t)
	vc := &volCore{fakeCore: fakeCore{key: rg.core.key}}
	cs := httptest.NewServer(vc)
	t.Cleanup(cs.Close)
	rg.r.core = &CoreClient{base: cs.URL, http: http.DefaultClient}
	return rg, vc
}

// m2: a running, booted, reporting machine of s1 (whose m1 left the rig's snapshot); withVolume: its cert names one
func runningM2(rg *rig, withVolume bool) {
	machine := map[string]any{"id": "m2", "signingKey": rg.mkey.pub()}
	if withVolume {
		machine["volume"] = map[string]any{"id": "vol_m2", "sizeGb": 10, "path": "/data"}
	}
	cert := rg.core.key.doc(map[string]any{"kind": "succession-cert", "predecessorId": "m1", "line": "m1", "machine": machine, "stores": []string{"default"}})
	rg.r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.State, s.MachineID, s.Booted, s.Cert = "started", "m2", "m2", cert
		s.Live = &Liveness{LastReport: time.Now()}
		d.Machines["m2"], d.Certs["m2"] = "s1", cert
		d.Started["m2"] = &Started{ID: "m2", SigningKey: rg.mkey.pub()}
	})
}

func sessionS1(rg *rig) (s Session) {
	rg.r.st.Do(func(d *persisted) { s = *d.Sessions["s1"] })
	return
}

// the incident (2026-10-15): the final snapshot failed and the machine was destroyed anyway. Now a machine without a
// volume whose snapshot fails is kept, the session says why, and Deyao gets a "needs you" DM; nothing is killed
func TestAFailedFinalSnapshotKeepsTheMachine(t *testing.T) {
	rg := newRig(t)
	dms := captureDM(t)
	rg.r.cfg.SnapshotStall = 200 * time.Millisecond
	runningM2(rg, false)
	if err := rg.r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	if err := rg.r.waitState("s1", "failed", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	s := sessionS1(rg)
	if s.MachineID != "m2" || !strings.Contains(s.SnapshotFailed, "made no progress for") || !strings.Contains(s.Error, "is kept") {
		t.Fatalf("session %+v", s)
	}
	rg.core.mu.Lock()
	for _, c := range rg.core.calls {
		if c == "/kill" {
			t.Fatal("the machine was killed")
		}
	}
	rg.core.mu.Unlock()
	waitFor(t, "DM", func() bool { return len(dms()) == 1 })
	if !strings.Contains(dms()[0], "needs you") || !strings.Contains(dms()[0], "kept instead of destroyed") {
		t.Fatalf("%q", dms())
	}
	// the machine reports its failure: the next pause stops waiting at once (no stall wait)
	rg.r.cfg.SnapshotStall = time.Minute
	rg.r.st.Do(func(d *persisted) { d.Sessions["s1"].State = "started" })
	t0 := time.Now()
	if err := rg.r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "asked", func() bool { return sessionS1(rg).Waiting != "" })
	m := testMachine{"m2", rg.mkey.k}
	if code, _ := m.do(t, rg.r.MachineHandler(), "POST", "/m/snapshot-failed", `{"error":"no space left on device"}`); code != 200 {
		t.Fatal(code)
	}
	if err := rg.r.waitState("s1", "failed", 5*time.Second); err != nil || time.Since(t0) > 10*time.Second {
		t.Fatal(err)
	}
	if s := sessionS1(rg); !strings.Contains(s.SnapshotFailed, "no space left on device") || s.MachineID != "m2" {
		t.Fatalf("%+v", s)
	}
	// Destroy anyway goes on past it
	rg.r.cfg.SnapshotStall = 200 * time.Millisecond
	if err := rg.r.DestroyWith("s1", true); err != nil { // waitState saw the pause end, its lock gone too
		t.Fatal(err)
	}
	waitFor(t, "destroyed", func() bool {
		gone := false
		rg.r.st.Do(func(d *persisted) { gone = d.Sessions["s1"] == nil })
		return gone
	})
}

// a machine with a volume whose snapshot fails is kept too (2026-10-21: the YYC session's was killed after its
// snapshot failed): no kill, a "needs you" DM
func TestAFailedFinalSnapshotKeepsAMachineWithAVolume(t *testing.T) {
	rg, vc := volRig(t)
	dms := captureDM(t)
	rg.r.cfg.SnapshotStall = 200 * time.Millisecond
	runningM2(rg, true)
	if err := rg.r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	if err := rg.r.waitState("s1", "failed", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if s := sessionS1(rg); vc.kills != 0 || s.MachineID != "m2" || !strings.Contains(s.Error, "is kept") || s.SnapshotFailed == "" {
		t.Fatalf("kills %d, session %+v", vc.kills, s)
	}
	waitFor(t, "DM", func() bool { return len(dms()) == 1 })
	if !strings.Contains(dms()[0], "kept instead of destroyed") {
		t.Fatalf("%q", dms())
	}
}

// a kill that goes on past a failed snapshot (force) of a machine with a volume: a line whose last machine left no
// snapshot won't resume (it would start empty): the session and a DM say so. A kill record that still names a volume
// backup (an earlier core's) is read without acting on it.
func TestNoSnapshotStopsTheResume(t *testing.T) {
	rg, vc := volRig(t)
	vc.oldKill = true
	dms := captureDM(t)
	rg.r.cfg.SnapshotStall = 200 * time.Millisecond
	runningM2(rg, true)
	if rg.r.finalSnapshotAndKill("s1", "m2", true) != true {
		t.Fatal("the forced kill didn't finish")
	}
	rg.r.st.Do(func(d *persisted) { d.Sessions["s1"].State, d.Sessions["s1"].MachineID = "paused", "" }) // as a pause leaves it
	s := sessionS1(rg)
	if vc.kills != 1 || !strings.Contains(s.NoSnapshot, "machine m2 left no snapshot") {
		t.Fatalf("kills %d, noSnapshot %q", vc.kills, s.NoSnapshot)
	}
	waitFor(t, "DM", func() bool { return len(dms()) == 1 })
	if !strings.Contains(dms()[0], "won't resume") || strings.Contains(dms()[0], "vs_m2") || strings.Contains(dms()[0], "backup") {
		t.Fatalf("%q", dms())
	}
	err := rg.r.Resume("s1", false)
	if err == nil || !strings.Contains(err.Error(), "would start empty") || !strings.Contains(err.Error(), "machine m1's") {
		t.Fatalf("resume: %v", err)
	}
	rg.r.Resume("s1", false)
	if len(dms()) != 1 {
		t.Fatalf("the refusal DMed again: %q", dms())
	}
	rg.r.st.Do(func(d *persisted) {
		v := sessionView(d.Sessions["s1"], d)
		if _, ok := v["backups"]; ok || v["noSnapshot"] == nil {
			t.Fatalf("view %v", v)
		}
	})
}

// a pause whose machine did send its snapshot: no noSnapshot
func TestASignedSnapshotPausesNormally(t *testing.T) {
	rg, _ := volRig(t)
	runningM2(rg, true)
	rg.writeSnapshot(t, "m2", rg.files)
	if err := rg.r.Pause("s1"); err != nil {
		t.Fatal(err)
	}
	if err := rg.r.waitState("s1", "paused", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if s := sessionS1(rg); s.NoSnapshot != "" {
		t.Fatalf("%+v", s)
	}
}

// the snapshot streams in (no disk on the machine), then the machine's signature over the router's hash commits it
func TestTheStreamedSnapshotIsCommittedOnlyWithTheMachinesSignature(t *testing.T) {
	rg := newRig(t)
	runningM2(rg, false)
	h := rg.r.MachineHandler()
	body := strings.Repeat("snapshot bytes ", 1000)
	stream := func(sig string) (int, map[string]any) {
		req := httptest.NewRequest("POST", "/m/snapshot-stream", strings.NewReader(body))
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		if sig == "" {
			sig, _ = signP256(rg.mkey.k, []byte("POST /m/snapshot-stream "+ts+" stream"))
		}
		req.Header.Set("X-Machine", "m2")
		req.Header.Set("X-Time", ts)
		req.Header.Set("X-Sig", sig)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		out := map[string]any{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, _ := stream("bm90IGEgc2ln"); code != 401 {
		t.Fatalf("an unsigned stream: %d", code)
	}
	code, out := stream("")
	sum := sha256.Sum256([]byte(body))
	want := hex.EncodeToString(sum[:])
	if code != 200 || out["sha256"] != want || out["bytes"] != float64(len(body)) {
		t.Fatalf("%d %v", code, out)
	}
	m := testMachine{"m2", rg.mkey.k}
	other := newTestKey()
	bad, _ := signP256(other.k, []byte(want))
	if code, _ := m.do(t, h, "POST", "/m/snapshot-commit", `{"sha256":"`+want+`","sig":"`+bad+`"}`); code != 403 {
		t.Fatalf("committed with another key's signature: %d", code)
	}
	good, _ := signP256(rg.mkey.k, []byte(want))
	if code, _ := m.do(t, h, "POST", "/m/snapshot-commit", `{"sha256":"`+strings.Repeat("0", 64)+`","sig":"`+good+`"}`); code != 409 {
		t.Fatalf("committed another hash: %d", code)
	}
	if code, _ := m.do(t, h, "POST", "/m/snapshot-commit", `{"sha256":"`+want+`","sig":"`+good+`"}`); code != 200 {
		t.Fatalf("commit: %d", code)
	}
	if b := snapBytes(rg.r, "m2"); string(b) != body || !rg.r.haveSnap("m2") {
		t.Fatal("the snapshot isn't in place")
	}
	if kd, err := rg.r.killMachine("m2", false); err != nil || !strings.Contains(kd.Payload, want) {
		t.Fatalf("the kill doesn't name it: %v %v", kd, err)
	}
}

// a machine paused while still booting carries its predecessor's snapshot over: the line keeps its state
func TestABootingMachineCarriesThePredecessorsSnapshot(t *testing.T) {
	rg := newRig(t)
	hh := sha256.Sum256(snapBytes(rg.r, "m1"))
	sum := hex.EncodeToString(hh[:])
	cert := rg.core.key.doc(map[string]any{"kind": "succession-cert", "predecessorId": "m1", "snapshot": sum, "machine": map[string]any{"id": "m2", "signingKey": rg.mkey.pub()}})
	rg.r.st.Do(func(d *persisted) {
		d.Machines["m2"], d.Certs["m2"] = "s1", cert
		d.Started["m2"] = &Started{ID: "m2", SigningKey: rg.mkey.pub()}
	})
	m := testMachine{"m2", rg.mkey.k}
	h := rg.r.MachineHandler()
	wrong := strings.Repeat("1", 64)
	ws, _ := signP256(rg.mkey.k, []byte(wrong))
	if code, _ := m.do(t, h, "POST", "/m/snapshot-carry", `{"sha256":"`+wrong+`","sig":"`+ws+`"}`); code != 409 {
		t.Fatalf("carried a hash the cert doesn't name: %d", code)
	}
	sig, _ := signP256(rg.mkey.k, []byte(sum))
	if code, _ := m.do(t, h, "POST", "/m/snapshot-carry", `{"sha256":"`+sum+`","sig":"`+sig+`"}`); code != 200 {
		t.Fatalf("carry: %d", code)
	}
	if s := rg.r.snap("m2"); s == nil || s.Sha256 != sum || !rg.r.haveSnap("m2") || string(snapBytes(rg.r, "m2")) != string(snapBytes(rg.r, "m1")) {
		t.Fatal("the predecessor's snapshot isn't m2's")
	}
}

// disk reports: shown like memory; a low disk is DMed once with the size More disk gives; More disk extends the
// volume through the core (and needs a volume)
func TestDiskReportsWarnAndMoreDiskExtends(t *testing.T) {
	rg, vc := volRig(t)
	dms := captureDM(t)
	runningM2(rg, false)
	h := rg.r.MachineHandler()
	m := testMachine{"m2", rg.mkey.k}
	if code, _ := m.do(t, h, "POST", "/m/disk", `{"root":{"totalKb":8000000,"availKb":4000000}}`); code != 200 {
		t.Fatal(code)
	}
	if code, _ := m.do(t, h, "POST", "/m/disk", `{"root":{"totalKb":0,"availKb":4}}`); code != 400 {
		t.Fatal(code)
	}
	// a machine without a volume: the next start gets the bigger disk
	if out, err := rg.r.MoreDisk("s1"); err != nil || out["nextStart"] != true {
		t.Fatalf("more disk without a volume: %v %v", out, err)
	}
	rg.r.st.Do(func(d *persisted) { d.Sessions["s1"].DiskGB = 0 })
	m.do(t, h, "POST", "/m/disk", `{"root":{"totalKb":8000000,"availKb":200000}}`)
	m.do(t, h, "POST", "/m/disk", `{"root":{"totalKb":8000000,"availKb":100000}}`) // the same episode: no second DM
	if len(dms()) != 1 || !strings.Contains(dms()[0], "running out of disk: 0.2 GB free of 7.6 GB on its machine's disk") || !strings.Contains(dms()[0], "no volume") {
		t.Fatalf("%q", dms())
	}
	rg.r.st.Do(func(d *persisted) {
		v := sessionView(d.Sessions["s1"], d)
		a, _ := v["diskAlert"].(map[string]any)
		if dk, _ := v["disk"].(map[string]any); dk == nil || dk["availMb"] != int64(97) || a == nil || a["canGrow"] != false {
			t.Fatalf("view %v %v", v["disk"], v["diskAlert"])
		}
	})
	// with a volume: the volume is the disk that counts, and More disk doubles it
	runningM2(rg, true)
	m.do(t, h, "POST", "/m/disk", `{"root":{"totalKb":8000000,"availKb":4000000},"data":{"totalKb":10485760,"availKb":300000}}`)
	if len(dms()) != 2 || !strings.Contains(dms()[1], "on its volume") || !strings.Contains(dms()[1], "gives it 20 GB") {
		t.Fatalf("%q", dms())
	}
	out, err := rg.r.MoreDisk("s1")
	if err != nil || out["toGb"] != 20 {
		t.Fatalf("%v %v", out, err)
	}
	waitFor(t, "extended", func() bool { return sessionS1(rg).DiskGB == 20 })
	vc.mu.Lock()
	ext := vc.extends
	vc.mu.Unlock()
	if len(ext) != 1 || ext[0]["machine"] != "m2" || ext[0]["sizeGb"] != float64(20) {
		t.Fatalf("extend %v", ext)
	}
	// recovered: the episode ends
	m.do(t, h, "POST", "/m/disk", `{"root":{"totalKb":8000000,"availKb":4000000},"data":{"totalKb":20971520,"availKb":10000000}}`)
	rg.r.st.Do(func(d *persisted) {
		if v := sessionView(d.Sessions["s1"], d); v["diskAlert"] != nil {
			t.Fatalf("still alerted: %v", v["diskAlert"])
		}
	})
}
