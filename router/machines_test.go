package main

import (
	"errors"
	"testing"
	"time"
)

func flyM(id, state, created, routerURL string) flyMachineDetail {
	var m flyMachineDetail
	m.ID, m.State, m.CreatedAt, m.Region = id, state, created, "lhr"
	m.Config.Image = "ghcr.io/de0ch/jarvis4-session@sha256:abc"
	m.Config.Guest = &flyGuest{CPUKind: "shared", CPUs: 4, MemoryMB: 4096}
	m.Config.Env = map[string]string{"JARVIS2_URL": routerURL}
	return m
}

const prodURL = "http://jarvis4-box._peer.internal:8081"

func TestMachinesView(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "s1", "running", "m-cur", false)
	r.st.Do(func(d *persisted) { d.Machines["m-old"] = "s1" }) // an earlier machine of s1 Fly still lists
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	old, fresh := now.Add(-2*time.Hour).Format(time.RFC3339), now.Add(-time.Minute).Format(time.RFC3339)
	vs := r.machinesView([]flyMachineDetail{
		flyM("m-cur", "started", old, prodURL),
		flyM("m-old", "stopped", old, prodURL),
		flyM("m-orphan", "stopped", old, prodURL),
		flyM("m-test", "started", old, "http://e2e-peer-1._peer.internal:8081"),
		flyM("m-new", "started", fresh, prodURL),
		flyM("m-gone", "destroyed", old, prodURL),
	}, now)
	by := map[string]machineView{}
	for _, v := range vs {
		by[v.ID] = v
	}
	if len(vs) != 5 || vs[0].ID != "m-new" {
		t.Fatalf("list %+v", vs)
	}
	if v := by["m-cur"]; v.SessionID != "s1" || !v.Current || v.Test || v.NoDestroy == "" || v.Size != "medium" || v.Guest != "4×shared · 4 GB" {
		t.Fatalf("session machine %+v", v)
	}
	if v := by["m-old"]; v.SessionID != "s1" || v.Current || v.NoDestroy == "" {
		t.Fatalf("earlier machine %+v", v)
	}
	if v := by["m-orphan"]; v.SessionID != "" || v.NoDestroy != "" || v.Test {
		t.Fatalf("orphan %+v", v)
	}
	if v := by["m-test"]; !v.Test || v.NoDestroy != "" {
		t.Fatalf("test machine %+v", v)
	}
	if v := by["m-new"]; v.NoDestroy == "" {
		t.Fatalf("a machine minutes old (a Start in flight) offered Destroy: %+v", v)
	}
}

func TestDestroyOrphanOnlyKillsMachinesWithNoSession(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "s1", "running", "m-cur", false)
	r.st.Do(func(d *persisted) { d.Started["m-started"] = &Started{} })
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	fleet := []flyMachineDetail{flyM("m-cur", "started", old, prodURL), flyM("m-started", "started", old, prodURL),
		flyM("m-orphan", "stopped", old, prodURL), flyM("m-new", "started", time.Now().UTC().Format(time.RFC3339), prodURL)}
	var killed []string
	oldList, oldKill := listFlyMachines, orphanKill
	defer func() { listFlyMachines, orphanKill = oldList, oldKill }()
	listFlyMachines = func() ([]flyMachineDetail, error) { return fleet, nil }
	orphanKill = func(r *Router, id string) error { killed = append(killed, id); return nil }
	for _, id := range []string{"m-cur", "m-new"} {
		if err := r.DestroyOrphan(id); err == nil || !errors.Is(err, errBusy) {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if err := r.DestroyOrphan("m-nope"); err == nil {
		t.Fatal("destroyed a machine Fly doesn't list")
	}
	if len(killed) != 0 {
		t.Fatalf("killed %v", killed)
	}
	if err := r.DestroyOrphan("m-orphan"); err != nil || len(killed) != 1 || killed[0] != "m-orphan" {
		t.Fatalf("orphan: %v %v", err, killed)
	}
	// one the router started that no session names (Started and Machines are set together at a start, so this is a
	// destroyed session's machine left behind): an orphan too
	if err := r.DestroyOrphan("m-started"); err != nil || len(killed) != 2 {
		t.Fatalf("left behind: %v %v", err, killed)
	}
}
