package main

// Disk: the machine's disk report, the warning before it fills, and More disk — the disk counterpart of memory.go
// (2026-10-15: a session's disk filled, its final snapshot failed with "no space left on device").
//
// Every 30 s the machine's agent POSTs /m/disk (machine/disk.go): its root filesystem and, on a machine with a volume
// (core/volumes.go), the volume at /data that holds the session's state. The disk that counts is the volume when
// there is one, else the root. An episode begins when it has less than diskLowPct free or less than diskLowMB; it is
// DMed once, shown on the session as diskAlert {since, reason, detail, nextGb, canGrow, why} with a More disk button,
// and ends when it has diskClearPct and diskClearMB free again.
//
// More disk (POST /api/sessions/:id/disk): the core extends the machine's volume to twice its size (core /extend; at
// most 500 GB); the session's diskGb is the new size, which every later machine of the line gets. When Fly says the
// machine must restart to see it, the session is paused (its signed snapshot) and resumed. A machine without a volume
// (a core from before volumes) can't grow: the button says so.

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

const (
	diskLowPct   = 10.0
	diskLowMB    = 1024
	diskClearPct = 20.0
	diskClearMB  = 2048
	diskSilent   = 3 * time.Minute
	maxDiskGB    = 500 // core/volumes.go
	defaultDisk  = 10  // core/volumes.go defaultDiskGB: the volume when the session asks for no size
)

type DiskFS struct {
	TotalKb int64 `json:"totalKb"`
	AvailKb int64 `json:"availKb"`
}

// DiskSample: what the machine reports (machine/disk.go)
type DiskSample struct {
	Root *DiskFS `json:"root"`
	Data *DiskFS `json:"data"` // the volume, when the machine has one
}

type DiskAlert struct {
	Since  time.Time `json:"since"`
	Reason string    `json:"reason"`
	Detail string    `json:"detail"`
}

type DiskState struct {
	Machine string      `json:"machine"`
	Last    *DiskSample `json:"last,omitempty"`
	LastAt  time.Time   `json:"lastAt"`
	Alert   *DiskAlert  `json:"alert,omitempty"`
}

func (s DiskSample) main() (*DiskFS, string) {
	if s.Data != nil && s.Data.TotalKb > 0 {
		return s.Data, "its volume"
	}
	return s.Root, "its machine's disk"
}

func (f DiskFS) pct() float64 { return 100 * float64(f.AvailKb) / float64(f.TotalKb) }

func gbText(kb int64) string { return fmt.Sprintf("%.1f GB", float64(kb)/1048576) }

// observe: a sample → true when a new low-disk episode begins (DM it)
func (d *DiskState) observe(s *DiskSample, now time.Time) bool {
	d.Last, d.LastAt = s, now
	fs, where := s.main()
	if fs == nil || fs.TotalKb <= 0 {
		return false
	}
	low := fs.pct() < diskLowPct || fs.AvailKb < diskLowMB*1024
	detail := fmt.Sprintf("%s free of %s on %s", gbText(fs.AvailKb), gbText(fs.TotalKb), where)
	switch {
	case low && d.Alert == nil:
		d.Alert = &DiskAlert{Since: now, Reason: "it is almost out of disk", Detail: detail}
		return true
	case low:
		d.Alert.Detail = detail
	case d.Alert != nil && fs.pct() >= diskClearPct && fs.AvailKb >= diskClearMB*1024:
		d.Alert = nil
	case d.Alert != nil:
		d.Alert.Detail = detail
	}
	return false
}

// nextDisk: More disk's size: twice the volume, at most maxDiskGB
func nextDisk(cur int) int {
	if cur <= 0 {
		cur = defaultDisk
	}
	return min(2*cur, maxDiskGB)
}

func diskMessage(name string, a *DiskAlert, vol *Volume) string {
	msg := fmt.Sprintf("🔴 Session “%s” is running out of disk: %s.", name, a.Detail)
	if vol == nil {
		return msg + "\nIts machine has no volume, so More disk can't grow it yet (that comes with the core release that adds volumes): free space in it, or ask it to."
	}
	return msg + fmt.Sprintf("\nOne tap gives it %d GB: the More disk button on its card in the Jarvis 4 app.", nextDisk(vol.SizeGB))
}

// diskView: the session's disk, diskAlert and diskGb in /api/state (under the state lock)
func diskView(s *Session, v map[string]any) {
	v["diskGb"] = s.DiskGB
	if s.Live == nil || s.Live.Disk == nil || s.State != "started" || s.Live.Disk.Machine != s.MachineID {
		return
	}
	d := s.Live.Disk
	if d.Last == nil || time.Since(d.LastAt) > diskSilent {
		return
	}
	fs, _ := d.Last.main()
	if fs == nil {
		return
	}
	out := map[string]any{"totalMb": fs.TotalKb / 1024, "availMb": fs.AvailKb / 1024, "at": d.LastAt, "volume": d.Last.Data != nil && d.Last.Data.TotalKb > 0}
	if r := d.Last.Root; r != nil && d.Last.Data != nil {
		out["rootTotalMb"], out["rootAvailMb"] = r.TotalKb/1024, r.AvailKb/1024
	}
	v["disk"] = out
	if d.Alert != nil {
		a := map[string]any{"since": d.Alert.Since, "reason": d.Alert.Reason, "detail": d.Alert.Detail, "canGrow": d.Last.Data != nil}
		if d.Last.Data != nil {
			a["nextGb"] = nextDisk(int(d.Last.Data.TotalKb / 1048576))
		} else {
			a["why"] = "its machine has no volume: More disk comes with the core release that adds volumes"
		}
		v["diskAlert"] = a
	}
}

func (r *Router) registerDisk(app appRoute, m machineRoute) {
	m("POST /m/disk", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in DiskSample
		bad := func(f *DiskFS) bool { return f != nil && (f.TotalKb <= 0 || f.AvailKb < 0 || f.AvailKb > f.TotalKb) }
		if json.Unmarshal(body, &in) != nil || in.Root == nil || bad(in.Root) || bad(in.Data) {
			writeJSON(w, 400, map[string]string{"error": "bad disk sample"})
			return
		}
		dm := ""
		r.st.Do(func(d *persisted) {
			s := d.Sessions[d.Machines[machine]]
			if s == nil || s.MachineID != machine {
				return
			}
			if s.Live == nil {
				s.Live = &Liveness{}
			}
			if s.Live.Disk == nil || s.Live.Disk.Machine != machine {
				s.Live.Disk = &DiskState{Machine: machine}
			}
			if s.Live.Disk.observe(&in, time.Now().UTC()) {
				dm = sessionName(s, s.Live.Reg)
			}
		})
		if dm != "" {
			var a *DiskAlert
			r.st.Do(func(d *persisted) {
				if s := d.Sessions[d.Machines[machine]]; s != nil && s.Live != nil && s.Live.Disk != nil && s.Live.Disk.Alert != nil {
					x := *s.Live.Disk.Alert
					a = &x
				}
			})
			if a != nil {
				msg := diskMessage(dm, a, r.machineVolume(machine))
				log.Printf("[disk] %s", msg)
				r.DM(msg)
			}
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	app("POST /api/sessions/{id}/disk", func(w http.ResponseWriter, req *http.Request) {
		out, err := r.MoreDisk(req.PathValue("id"))
		if err != nil {
			scheduleErr(w, err)
			return
		}
		writeJSON(w, 202, out)
	})
}

// MoreDisk: the machine's volume to twice its size; a pause and resume when Fly says the machine must restart
func (r *Router) MoreDisk(id string) (map[string]any, error) {
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	if s.ID == "" {
		return nil, errNoSession
	}
	// a running session's volume grows now; a failed one whose machine was kept (its snapshot ran out of space) too,
	// then Pause again; one with no machine (paused, failed) or no volume gets the bigger disk at its next start
	live := s.MachineID != "" && (s.State == "started" || s.State == "failed")
	var vol *Volume
	if live {
		vol = r.machineVolume(s.MachineID)
	}
	if vol == nil {
		if s.State != "paused" && s.State != "failed" && s.State != "started" {
			return nil, fmt.Errorf("session is %s: More disk once it is running, paused or failed", s.State) // "session is …" → 409
		}
		to := nextDisk(s.DiskGB)
		if to <= s.DiskGB {
			return nil, fmt.Errorf("session is at the largest disk (%d GB)", maxDiskGB)
		}
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				x.DiskGB = to
			}
		})
		return map[string]any{"ok": true, "kind": "disk", "fromGb": max(s.DiskGB, defaultDisk), "toGb": to, "nextStart": true}, nil
	}
	from := max(vol.SizeGB, s.DiskGB)
	to := nextDisk(from)
	if to <= from {
		return nil, fmt.Errorf("session is at the largest disk (%d GB)", maxDiskGB)
	}
	endJob, err := r.beginJob(id, "disk")
	if err != nil {
		return nil, err
	}
	j, err := r.ops.startJob(id, "disk")
	if err != nil {
		endJob()
		return nil, err
	}
	r.ops.setBusy(id, "growing-disk")
	go func() {
		defer endJob()
		defer r.ops.setBusy(id, "")
		fail := func(err error) {
			log.Printf("[disk] more disk for %s failed: %v", id, err)
			r.cancelSpare(id, "more disk failed")
			r.ops.phase(j, "failed", err)
		}
		r.ops.phase(j, "extending", nil)
		d, err := r.core.Call("/extend", map[string]any{"machine": s.MachineID, "sizeGb": to})
		if err != nil {
			fail(err)
			return
		}
		var ext struct {
			NeedsRestart bool `json:"needsRestart"`
		}
		d.Decode(&ext)
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				x.DiskGB = to // every later machine of the line gets the new size
			}
		})
		if ext.NeedsRestart && s.State == "started" {
			r.ops.phase(j, "snapshotting", nil)
			// handover.go: the machine on the bigger volume starts as soon as the old one is told to stop
			next := r.handoverNext(s, "", to)
			if err := r.pauseWith(id, next); err != nil {
				fail(err)
				return
			}
			if err := r.waitActionEnd(id, "paused"); err != nil {
				fail(err)
				return
			}
			r.ops.phase(j, "resuming", nil)
			if err := r.handoverResume(id, "", false); err != nil {
				fail(err)
				return
			}
			if msg := r.waitStartOutcome(id, upgradeStartWait); msg != "" {
				fail(fmt.Errorf("%s", msg))
				return
			}
		}
		r.ops.phase(j, "done", nil)
		log.Printf("[disk] %s: volume %d → %d GB (restart: %v)", id, from, to, ext.NeedsRestart)
	}()
	return map[string]any{"started": true, "kind": "disk", "fromGb": from, "toGb": to}, nil
}
