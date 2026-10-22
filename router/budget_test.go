package main

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestCosts(t *testing.T) {
	small := &flyGuest{CPUKind: "shared", CPUs: 2, MemoryMB: 2048}
	// Fly's calculator (fly.io/docs/about/pricing, London): shared-cpu-2x 2 GB, performance-2x 4 GB (RAM included)
	if math.Abs(hourlyMachineCost(small)-0.0211) > 0.00005 {
		t.Fatal(hourlyMachineCost(small))
	}
	perf := &flyGuest{CPUKind: "performance", CPUs: 2, MemoryMB: 4096}
	if math.Abs(hourlyMachineCost(perf)-0.1040) > 0.00005 {
		t.Fatal(hourlyMachineCost(perf))
	}
	// the Upgrade's sizes (sizes.go): 16 GB shared, 32 GB on 8 performance CPUs
	for size, perHour := range map[string]float64{"large": 0.0844, "16gb": 0.1601, "32gb": 0.5674, "64gb": 0.8701, "128gb": 1.7402} {
		kind, cpus, mb := sizeGuest(size)
		if got := hourlyMachineCost(&flyGuest{CPUKind: kind, CPUs: cpus, MemoryMB: mb}); math.Abs(got-perHour) > 0.00005 {
			t.Fatalf("%s: %.4f an hour, Fly says %.4f", size, got, perHour)
		}
	}
	if hourlyMachineCost(nil) != 0 || !near(hourlyVolumeCost(10), 1.5/730) {
		t.Fatal("nil guest / volume")
	}
	b := burnRate([]flyMachine{
		{State: "started", Config: struct {
			Guest *flyGuest `json:"guest"`
		}{small}},
		{State: "stopped", Config: struct {
			Guest *flyGuest `json:"guest"`
		}{perf}},
	}, []flyVolume{{State: "created", SizeGB: 10}, {State: "destroyed", SizeGB: 99},
		{State: "pending_destroy", SizeGB: 10}, {State: "destroying", SizeGB: 10}}) // deleted: not billed
	if b.Running != 1 || b.Volumes != 1 || !near(b.RatePerHour, hourlyMachineCost(small)+hourlyVolumeCost(10)) {
		t.Fatalf("%+v", b)
	}
}

func TestApplySample(t *testing.T) {
	t0 := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	s, a, _ := applySample(nil, t0, 1, 30, 25)
	if s.SpentUSD != 0 || a != (budgetActions{}) || s.Month != "2026-10" {
		t.Fatalf("first sample %+v %+v", s, a)
	}
	// a gap longer than maxDeltaH bills only maxDeltaH
	s, _, dh := applySample(&s, t0.Add(10*time.Hour), 1, 30, 25)
	if dh != maxDeltaH || s.SpentUSD != 6 {
		t.Fatalf("gap %v %+v", dh, s)
	}
	// clock going backwards bills nothing
	s2, _, dh := applySample(&s, t0.Add(9*time.Hour), 1, 30, 25)
	if dh != 0 || s2.SpentUSD != 6 {
		t.Fatalf("backwards %v %+v", dh, s2)
	}
	// warn once
	s.SpentUSD = 24.5
	s, a, _ = applySample(&s, s.LastSampleAt.Add(time.Hour), 1, 30, 25)
	if !a.WarnDM || a.Enforce || !s.Warned {
		t.Fatalf("warn %+v %+v", s, a)
	}
	s, a, _ = applySample(&s, s.LastSampleAt.Add(time.Hour), 1, 30, 25)
	if a.WarnDM {
		t.Fatal("warned twice")
	}
	// cap: DM once, enforce every tick
	s.SpentUSD = 29.5
	s, a, _ = applySample(&s, s.LastSampleAt.Add(time.Hour), 1, 30, 25)
	if !a.Enforce || !a.CapDM || !s.Capped || s.CappedAt == nil {
		t.Fatalf("cap %+v %+v", s, a)
	}
	s, a, _ = applySample(&s, s.LastSampleAt.Add(time.Hour), 0, 30, 25)
	if !a.Enforce || a.CapDM {
		t.Fatalf("still capped %+v", a)
	}
	// a new month starts from zero
	s, a, _ = applySample(&s, time.Date(2026, 11, 1, 0, 1, 0, 0, time.UTC), 1, 30, 25)
	if s.Month != "2026-11" || s.SpentUSD != 0 || s.Capped || s.Warned || a.Enforce {
		t.Fatalf("new month %+v %+v", s, a)
	}
	// straight past both lines: the cap, without a warn DM
	_, a, _ = applySample(&BudgetState{Month: "2026-11", SpentUSD: 20, LastSampleAt: s.LastSampleAt}, s.LastSampleAt.Add(5*time.Hour), 3, 30, 25)
	if !a.CapDM || a.WarnDM {
		t.Fatalf("jump %+v", a)
	}
}

// raising the lines mid-month re-arms them: warned at 25, the warn line moved to 35 → one DM at 35, one at 40
func TestRaisedLinesRearm(t *testing.T) {
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	s, a, _ := applySample(&BudgetState{Month: "2026-10", SpentUSD: 28, Warned: true, LastSampleAt: &t0}, t0.Add(time.Hour), 1, 40, 35)
	if s.Warned || a != (budgetActions{}) {
		t.Fatalf("not re-armed %+v %+v", s, a)
	}
	s, a, _ = applySample(&s, t0.Add(8*time.Hour), 1, 40, 35)
	if !a.WarnDM || !s.Warned {
		t.Fatalf("no DM at 35 %+v %+v", s, a)
	}
	s, a, _ = applySample(&s, t0.Add(9*time.Hour), 1, 40, 35)
	if a.WarnDM || a.CapDM {
		t.Fatalf("DM twice %+v", a)
	}
	// capped at 30, the cap raised to 40: no longer capped until 40
	s, a, _ = applySample(&BudgetState{Month: "2026-10", SpentUSD: 31, Warned: true, Capped: true, CappedAt: &t0, LastSampleAt: &t0}, t0.Add(time.Hour), 1, 40, 35)
	if s.Capped || a.Enforce || s.Warned {
		t.Fatalf("still capped %+v %+v", s, a)
	}
}

func TestThresholds(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if c, w := budgetThresholds(env(nil)); c != 50 || w != 45 {
		t.Fatal(c, w)
	}
	if c, w := budgetThresholds(env(map[string]string{"FLY_BUDGET_USD": "50"})); c != 50 || w != 40 {
		t.Fatal(c, w)
	}
	if c, w := budgetThresholds(env(map[string]string{"FLY_BUDGET_USD": "0", "FLY_BUDGET_WARN_USD": "0"})); c != 0 || w != 0 {
		t.Fatal(c, w)
	}
}

type fakeFly struct {
	ms  []flyMachine
	vs  []flyVolume
	err error
}

func (f *fakeFly) Machines() ([]flyMachine, error) { return f.ms, f.err }
func (f *fakeFly) Volumes() ([]flyVolume, error)   { return f.vs, nil }

func machine(id, state string) flyMachine {
	m := flyMachine{ID: id, State: state}
	m.Config.Guest = &flyGuest{CPUKind: "shared", CPUs: 4, MemoryMB: 4096}
	return m
}

func TestBudgetTick(t *testing.T) {
	st, _ := testState(t, t.TempDir())
	r := NewRouter(Config{}, st, nil, Policy{})
	st.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", MachineID: "m1", Label: "one", State: "started"}
		d.Sessions["s2"] = &Session{ID: "s2", MachineID: "m2", Label: "two", State: "started"}
		d.Sessions["s3"] = &Session{ID: "s3", MachineID: "", State: "paused"}
		d.Machines["m1"], d.Machines["m2"], d.Machines["m3old"] = "s1", "s2", "s3"
	})
	var paused, dms []string
	budgetPause = func(r *Router, sid string) error {
		if sid == "s2" {
			return errBusy
		}
		paused = append(paused, sid)
		return nil
	}
	budgetDM = func(r *Router, text string) { dms = append(dms, text) }
	defer func() {
		budgetPause = func(r *Router, sid string) error { return r.Pause(sid) }
		budgetDM = func(r *Router, text string) { r.DM(text) }
	}()
	fly := &fakeFly{ms: []flyMachine{machine("m1", "started"), machine("m2", "started"), machine("m3old", "started"), machine("x9", "started"), machine("m4", "stopped")},
		vs: []flyVolume{{ID: "v1", State: "created", SizeGB: 1}}}
	t0 := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)

	// under the warn line: nothing happens; Also on Fly lists the strangers
	a, _, err := r.budgetTick(fly, t0, 30, 25)
	if err != nil || a != (budgetActions{}) || len(dms) != 0 {
		t.Fatalf("%v %+v %v", err, a, dms)
	}
	other := budgetView.fly["other"].([]flyOther)
	var ids []string
	for _, o := range other {
		ids = append(ids, o.Kind+":"+o.ID)
	}
	if strings.Join(ids, ",") != "machine:m3old,machine:m4,machine:x9,volume:v1" {
		t.Fatalf("also on fly %v", ids)
	}

	// over the cap: pause what can be paused, DM once with the strangers named
	st.Do(func(d *persisted) { d.Budget.SpentUSD = 31 })
	a, p, _ := r.budgetTick(fly, t0.Add(time.Minute), 30, 25)
	if !a.Enforce || !a.CapDM || strings.Join(p, ",") != "one" || strings.Join(paused, ",") != "s1" {
		t.Fatalf("%+v %v %v", a, p, paused)
	}
	if len(dms) != 1 || !strings.Contains(dms[0], "Paused 1 running session(s): one") || !strings.Contains(dms[0], "m3old, x9") {
		t.Fatalf("dm %q", dms)
	}
	if budgetView.budget["capped"] != true {
		t.Fatalf("view %v", budgetView.budget)
	}
	// next tick: s2 is free now and gets paused, with a DM naming it; nothing to pause → no DM
	paused = nil
	budgetPause = func(r *Router, sid string) error { paused = append(paused, sid); return nil }
	r.budgetTick(fly, t0.Add(2*time.Minute), 30, 25)
	if strings.Join(paused, ",") != "s1,s2" || len(dms) != 2 {
		t.Fatalf("%v %v", paused, dms)
	}
	r.budgetTick(&fakeFly{}, t0.Add(3*time.Minute), 30, 25)
	if len(dms) != 2 {
		t.Fatalf("DM with nothing paused: %v", dms)
	}

	// Fly unreachable: the error shows, nothing else changes
	if _, _, err := r.budgetTick(&fakeFly{err: errors.New("down")}, t0.Add(4*time.Minute), 30, 25); err == nil || budgetView.fly["error"] != "down" {
		t.Fatal("no error shown")
	}
}

func TestStateHook(t *testing.T) {
	out := map[string]any{}
	for _, h := range stateHooks {
		h(nil, out)
	}
	if _, ok := out["budget"]; !ok || out["flyApp"] != sessionsApp {
		t.Fatalf("%v", out)
	}
}

// snapFly: a reader that also lists volume snapshots (the real Fly API's GET /volumes/:id/snapshots)
type snapFly struct {
	fakeFly
	snaps map[string][]flySnapshot
	asked []string
}

func (f *snapFly) Snapshots(v string) ([]flySnapshot, error) {
	f.asked = append(f.asked, v)
	return f.snaps[v], nil
}

// the cap counts what Fly bills for volume snapshots too: those of Fly's volumes, each snapshot once, past the free
// 10 GB, at USD 0.08 per GB-month
func TestTheBudgetCountsVolumeSnapshots(t *testing.T) {
	snapCache.Lock()
	snapCache.at, snapCache.snaps = map[string]time.Time{}, map[string][]flySnapshot{}
	snapCache.Unlock()
	if c := hourlySnapshotCost(8e9); c != 0 {
		t.Fatalf("under the free 10 GB: %v", c)
	}
	if c := hourlySnapshotCost(20e9) * hoursPerMonth; math.Abs(c-0.80) > 1e-9 {
		t.Fatalf("20 GB stored: USD %v a month, want 0.80", c)
	}
	st, _ := testState(t, t.TempDir())
	r := NewRouter(Config{}, st, nil, Policy{})
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	fly := &snapFly{fakeFly: fakeFly{vs: []flyVolume{{ID: "vol_live", State: "created", SizeGB: 10}, {ID: "vol_rec", State: "created", SizeGB: 10}}},
		snaps: map[string][]flySnapshot{
			"vol_live": {{ID: "vs_d1", Size: 6e9, Status: "created"}, {ID: "vs_x", Size: 9e9, Status: "failed"}},
			"vol_rec":  {{ID: "vs_r", Size: 4e9, Status: "created"}, {ID: "vs_d1", Size: 6e9, Status: "created"}}, // listed twice: once
		}}
	if _, _, err := r.budgetTick(fly, now, 30, 25); err != nil {
		t.Fatal(err)
	}
	if strings.Join(fly.asked, ",") != "vol_live,vol_rec" {
		t.Fatalf("asked %v", fly.asked)
	}
	budgetView.Lock()
	v := budgetView.budget
	budgetView.Unlock()
	want := hourlyVolumeCost(20) + hourlySnapshotCost(10e9) // 6 + 4 GB stored
	if v["snapshots"] != 2 || math.Abs(v["snapshotGb"].(float64)-10) > 1e-9 || math.Abs(v["ratePerHour"].(float64)-want) > 1e-12 {
		t.Fatalf("view %v, want rate %v", v, want)
	}
	// listed at most every 30 min
	r.budgetTick(fly, now.Add(2*time.Minute), 30, 25)
	if len(fly.asked) != 2 {
		t.Fatalf("listed again within 30 min: %v", fly.asked)
	}
}
