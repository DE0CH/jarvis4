package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

var sweepNow = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func vol(id, name, state, attached string, age time.Duration) flyVolume {
	return flyVolume{ID: id, Name: name, State: state, AttachedMachineID: attached, CreatedAt: sweepNow.Add(-age).Format(time.RFC3339)}
}

func mounting(id, state string, vols ...string) sweepMachine {
	m := sweepMachine{ID: id, State: state}
	for _, v := range vols {
		m.Config.Mounts = append(m.Config.Mounts, struct {
			Volume string `json:"volume"`
		}{v})
	}
	return m
}

func TestSweepSelect(t *testing.T) {
	vols := []flyVolume{
		vol("vol_leftover", "jarvis4_state", "created", "", 2*time.Hour),
		vol("vol_young", "jarvis4_state", "created", "", 14*time.Minute),
		vol("vol_attached", "jarvis4_state", "created", "m1", 2*time.Hour),
		vol("vol_mounted", "jarvis4_state", "created", "", 2*time.Hour),
		vol("vol_named", "jarvis4_state", "created", "", 2*time.Hour),
		vol("vol_other", "data", "created", "", 2*time.Hour),
		vol("vol_destroying", "jarvis4_state", "pending_destroy", "", 2*time.Hour),
		vol("vol_deadmount", "jarvis4_state", "created", "", 2*time.Hour),
		{ID: "vol_notime", Name: "jarvis4_state", State: "created", CreatedAt: "yesterday"},
	}
	ms := []sweepMachine{mounting("m2", "stopped", "vol_mounted"), mounting("m3", "destroyed", "vol_deadmount")}
	ch := sweepSelect(vols, ms, map[string]string{"vol_named": "session s1's machine m9"}, sweepNow)
	if want := []string{"vol_deadmount", "vol_leftover"}; !reflect.DeepEqual(ch.Delete, want) {
		t.Fatalf("delete %v, want %v", ch.Delete, want)
	}
	for id, cat := range map[string]string{"vol_young": "young", "vol_attached": "attached", "vol_mounted": "mounted",
		"vol_named": "named", "vol_other": "other name", "vol_destroying": "state", "vol_notime": "no creation time"} {
		if c, _, _ := strings.Cut(ch.Kept[id], ":"); c != cat {
			t.Errorf("%s kept as %q, want %s", id, ch.Kept[id], cat)
		}
	}
}

func TestSweepSelectBoundaryAndLimit(t *testing.T) {
	ch := sweepSelect([]flyVolume{vol("vol_15", "jarvis4_state", "created", "", 15*time.Minute)}, nil, nil, sweepNow)
	if len(ch.Delete) != 1 {
		t.Fatalf("a volume exactly 15 minutes old is a leftover: %+v", ch)
	}
	vols := []flyVolume{}
	for i := 0; i < volSweepMaxPerGo+5; i++ {
		vols = append(vols, vol(fmt.Sprintf("vol_%02d", i), "jarvis4_state", "created", "", time.Hour))
	}
	ch = sweepSelect(vols, nil, nil, sweepNow)
	if len(ch.Delete) != volSweepMaxPerGo || len(ch.Kept) != 5 {
		t.Fatalf("limit: %d deleted, %d kept", len(ch.Delete), len(ch.Kept))
	}
}

func certWithVolume(vol string) *Doc {
	p, _ := json.Marshal(map[string]any{"machine": map[string]any{"volume": map[string]any{"id": vol, "sizeGb": 10, "path": "/data"}}})
	return &Doc{Payload: string(p)}
}

func TestSweepNamed(t *testing.T) {
	r := newTestRouter(t)
	r.st.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", State: "running", MachineID: "m1", Booted: "m0"}
		d.Certs["m1"] = certWithVolume("vol_current_cert")
		d.Started["m0"] = &Started{ID: "m0", Volume: &Volume{ID: "vol_booted_started"}}
		// an earlier machine of the same session: its volume is no longer named (the leak the sweep exists for)
		d.Started["m_old"] = &Started{ID: "m_old", Volume: &Volume{ID: "vol_old_machine"}}
		d.Certs["m_old"] = certWithVolume("vol_old_machine")
		d.Machines["m_old"] = "s1"
	})
	named := r.sweepNamed()
	for _, v := range []string{"vol_current_cert", "vol_booted_started"} {
		if named[v] == "" {
			t.Errorf("%s not named: %v", v, named)
		}
	}
	for _, v := range []string{"vol_old_machine"} {
		if named[v] != "" {
			t.Errorf("%s named (%s)", v, named[v])
		}
	}
}

func TestVolumeSweepDeletesAndRetries(t *testing.T) {
	r := newTestRouter(t)
	r.st.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", State: "running", MachineID: "m1"}
		d.Started["m1"] = &Started{ID: "m1", Volume: &Volume{ID: "vol_live"}}
	})
	oldR, oldD := volSweepReader, volumeDelete
	defer func() { volSweepReader, volumeDelete = oldR, oldD }()
	volSweepReader = func() ([]flyVolume, []sweepMachine, error) {
		return []flyVolume{vol("vol_live", "jarvis4_state", "created", "", time.Hour), vol("vol_a", "jarvis4_state", "created", "", time.Hour),
			vol("vol_b", "jarvis4_state", "created", "", time.Hour)}, nil, nil
	}
	calls := []string{}
	volumeDelete = func(token, id string) error {
		calls = append(calls, id)
		if token != "tok" {
			t.Errorf("token %q", token)
		}
		if id == "vol_b" {
			return fmt.Errorf("HTTP 500")
		}
		return nil
	}
	got, err := r.volumeSweep("tok", sweepNow)
	if err != nil || !reflect.DeepEqual(got, []string{"vol_a"}) || !reflect.DeepEqual(calls, []string{"vol_a", "vol_b"}) {
		t.Fatalf("deleted %v (calls %v), %v", got, calls, err)
	}
	st := volumeSweepStatus()
	if f, _ := st["failed"].(map[string]string); f["vol_b"] == "" {
		t.Fatalf("status %v", st)
	}
	// a failed list deletes nothing
	volSweepReader = func() ([]flyVolume, []sweepMachine, error) { return nil, nil, fmt.Errorf("HTTP 503") }
	calls = nil
	if _, err := r.volumeSweep("tok", sweepNow); err == nil || len(calls) != 0 {
		t.Fatalf("list failure: %v, calls %v", err, calls)
	}
}
