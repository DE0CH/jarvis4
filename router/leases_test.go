package main

import (
	"strings"
	"sync"
	"testing"
)

const lt0 = int64(1790000000000)

func sp(s string) *string { return &s }

func newLeases() *LeaseState { return leasesOf(&persisted{}) }

func TestLeaseGrantRenewQueue(t *testing.T) {
	st := newLeases()
	a, err := st.acquire("wechat-phone", "A", LeaseOpts{Purpose: sp("map")}, lt0)
	if err != nil || a.Status != "granted" || st.Resources["wechat-phone"].Holder.ExpiresAt != lt0+leaseDefaultTTL*1000 {
		t.Fatalf("%+v %v", a, err)
	}
	if again, _ := st.acquire("wechat-phone", "A", LeaseOpts{}, lt0+100_000); again.Status != "renewed" ||
		st.Resources["wechat-phone"].Holder.ExpiresAt != lt0+100_000+leaseDefaultTTL*1000 {
		t.Fatalf("%+v", again)
	}
	st.acquire("p", "A", LeaseOpts{}, lt0)
	if o, _ := st.acquire("p", "B", LeaseOpts{Prompt: "go B"}, lt0); o.Status != "queued" || o.Position != 1 {
		t.Fatalf("%+v", o)
	}
	if o, _ := st.acquire("p", "C", LeaseOpts{}, lt0); o.Position != 2 {
		t.Fatalf("%+v", o)
	}
	if o, _ := st.acquire("p", "B", LeaseOpts{}, lt0); o.Position != 1 {
		t.Fatal("re-queueing keeps the place")
	}
	if o, _ := st.acquire("p", "W", LeaseOpts{LowPriority: true}, lt0); o.Status != "busy" {
		t.Fatalf("low priority is never queued: %+v", o)
	}
	if q := st.Resources["p"].Queue; len(q) != 2 || q[0].Sid != "B" || q[1].Sid != "C" {
		t.Fatalf("%+v", q)
	}
	if _, err := st.acquire("Bad Name", "A", LeaseOpts{}, lt0); err == nil {
		t.Fatal("bad name")
	}
	// only the holder renews; a renew pushes the expiry by the lease's own ttl
	st.acquire("q", "A", LeaseOpts{TTL: float64(120)}, lt0)
	if _, err := st.renew("q", "B", lt0); err == nil || !strings.Contains(err.Error(), "does not hold") {
		t.Fatal(err)
	}
	if o, _ := st.renew("q", "A", lt0+100_000); o.Lease["holder"].(map[string]any)["expiresAt"] != lt0+220_000 {
		t.Fatalf("%+v", o.Lease)
	}
	// ttl is clamped
	st.acquire("r", "A", LeaseOpts{TTL: float64(5)}, lt0)
	if st.Resources["r"].Holder.TTL != leaseMinTTL {
		t.Fatal("ttl clamp")
	}
}

func TestLeaseReturnPromotesAndNotifiesOnce(t *testing.T) {
	st := newLeases()
	st.acquire("p", "A", LeaseOpts{}, lt0)
	st.acquire("p", "B", LeaseOpts{Prompt: "carry on with the map", TTL: float64(600)}, lt0)
	if _, err := st.giveBack("p", "B", lt0, false); err == nil {
		t.Fatal("a waiter can't return it")
	}
	out, _ := st.giveBack("p", "A", lt0+5000, false)
	if out.Promoted == nil || out.Promoted.Sid != "B" {
		t.Fatalf("%+v", out)
	}
	h := st.Resources["p"].Holder
	if h.Sid != "B" || h.ExpiresAt != lt0+5000+600_000 || h.Prompt != "carry on with the map" {
		t.Fatalf("%+v", h)
	}
	p := st.pendingNotifications()
	if len(p) != 1 || p[0].Sid != "B" || p[0].Since != lt0+5000 || p[0].TTL != 600 {
		t.Fatalf("%+v", p)
	}
	st.markNotified("p", "B", lt0+5000)
	if len(st.pendingNotifications()) != 0 {
		t.Fatal("notified once")
	}
	st.giveBack("p", "B", lt0+10_000, false)
	if st.Resources["p"].Holder != nil {
		t.Fatal("free")
	}
	// leave the queue; force return
	st.acquire("x", "A", LeaseOpts{}, lt0)
	st.acquire("x", "B", LeaseOpts{}, lt0)
	st.acquire("x", "C", LeaseOpts{}, lt0)
	if left, _ := st.leave("x", "B"); !left {
		t.Fatal("leave")
	}
	f, _ := st.giveBack("x", "", lt0, true)
	if f.Previous != "A" || f.Promoted.Sid != "C" {
		t.Fatalf("%+v", f)
	}
}

func TestLeaseSweep(t *testing.T) {
	st := newLeases()
	st.acquire("p", "A", LeaseOpts{TTL: float64(60)}, lt0)
	st.acquire("p", "GONE", LeaseOpts{}, lt0)
	st.acquire("p", "B", LeaseOpts{}, lt0)
	if ch := st.sweep(lt0+30_000, func(string) bool { return true }); len(ch) != 0 {
		t.Fatal(ch)
	}
	ch := st.sweep(lt0+61_000, func(s string) bool { return s != "GONE" })
	if len(ch) != 1 || ch[0].Expired != "A" || ch[0].Promoted.Sid != "B" {
		t.Fatalf("the gone waiter is skipped: %+v", ch)
	}
	ch = st.sweep(lt0+62_000, func(s string) bool { return s != "B" })
	if len(ch) != 1 || ch[0].Expired != "B" || ch[0].Promoted != nil || st.Resources["p"].Holder != nil {
		t.Fatalf("a gone holder is freed before expiry: %+v", ch)
	}
	if st.Resources["p"] == nil {
		t.Fatal("kept: its log is the trail")
	}
	// the known devices are always listed
	l := st.list(lt0)
	if len(l) < 3 || l[0]["name"] != "wechat-phone" || l[1]["name"] != "iphone" || l[2]["name"] != "mac" {
		t.Fatalf("%v", l)
	}
}

func TestLeaseTakeOverHandBack(t *testing.T) {
	st := newLeases()
	st.acquire("iphone", "A", LeaseOpts{Purpose: sp("pay"), Prompt: "finish paying"}, lt0)
	st.acquire("iphone", "B", LeaseOpts{}, lt0)
	out, _ := st.takeOver("iphone", sp("need it myself"), lt0+1000)
	if !out.Taken || out.Interrupted != "A" {
		t.Fatalf("%+v", out)
	}
	r := st.Resources["iphone"]
	if !r.Holder.Human || r.Holder.ExpiresAt != 0 || r.Queue[0].Sid != "A" || !r.Queue[0].Interrupted || r.Queue[0].Prompt != "finish paying" || r.Queue[1].Sid != "B" {
		t.Fatalf("%+v %+v", r.Holder, r.Queue)
	}
	// he never expires
	if ch := st.sweep(lt0+100*3600*1000, func(string) bool { return true }); len(ch) != 0 {
		t.Fatal("Deyao's hold doesn't expire")
	}
	// an agent's renew is refused with his note, and it is recorded to be told
	_, err := st.renew("iphone", "C", lt0+2000)
	if le, ok := err.(*leaseError); !ok || !le.takenOver || !strings.Contains(le.msg, "need it myself") {
		t.Fatalf("%v", err)
	}
	if again, _ := st.takeOver("iphone", sp("long term"), lt0+3000); !again.NoteUpdated || r.Holder.Note != "long term" {
		t.Fatal("a take-over while he has it only updates the note")
	}
	hb, _ := st.handBack("iphone", "left WeChat open", lt0+4000)
	if !hb.HandedBack || hb.Promoted.Sid != "A" || len(hb.Notify) != 1 || hb.Notify[0] != "C" {
		t.Fatalf("%+v", hb)
	}
	p := st.pendingNotifications()
	if len(p) != 1 || !p[0].Handover || !p[0].Interrupted {
		t.Fatalf("%+v", p)
	}
}

func TestLeaseTextsMatchTheMachine(t *testing.T) {
	// rust/machine/src/tests/vouch.rs checks the same strings
	got := leaseGrantedText("mac", 60, false, false, "go on")
	want := `[lease "mac" granted] This session now holds the shared device "mac" (you were queued for it). It is yours for 60 min, renewed automatically by the device helpers on every action; return it when done (scripts/lease.py return mac). The previous holder may have left it in any state: inspect it first. Your note: go on`
	if got != want {
		t.Fatalf("%q", got)
	}
}

func TestLeaseAPI(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	addSession(r, "sB", "paused", "", false)
	addSession(r, "sC", "started", "mC", false)
	ma, mc := newTestMachine(r, "mA"), newTestMachine(r, "mC")
	h := r.MachineHandler()
	var mu sync.Mutex
	var got []Delivery
	old := deliverVouchedHook
	deliverVouchedHook = func(_ *Router, sid string, d Delivery) error {
		mu.Lock()
		defer mu.Unlock()
		d.ID = sid
		got = append(got, d)
		return nil
	}
	t.Cleanup(func() { leaseWG.Wait(); deliverVouchedHook = old })

	code, out := ma.do(t, h, "POST", "/m/api/sessions/sA/leases/mac", `{"purpose":"screen","description":"step 1"}`)
	if code != 200 || out["status"] != "granted" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := ma.do(t, h, "POST", "/m/api/sessions/sC/leases/mac", `{}`); code != 403 {
		t.Fatal("another session's path")
	}
	code, out = mc.do(t, h, "POST", "/m/api/sessions/sC/leases/mac", `{"purpose":"wait","prompt":"continue the  build"}`)
	if code != 200 || out["status"] != "queued" || out["position"] != float64(1) {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := mc.do(t, h, "POST", "/m/api/sessions/sC/leases/iphone", `{"lowPriority":true}`); code != 200 || out["status"] != "granted" {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := ma.do(t, h, "POST", "/m/api/sessions/sA/leases/iphone", `{"lowPriority":true}`); code != 409 || out["status"] != "busy" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := mc.do(t, h, "PUT", "/m/api/sessions/sC/leases/mac", ``); code != 409 {
		t.Fatal("a waiter can't renew")
	}
	if code, out := ma.do(t, h, "PATCH", "/m/api/sessions/sA/leases/mac", `{"description":"step 2"}`); code != 200 || out["status"] != "holder" {
		t.Fatalf("%d %v", code, out)
	}
	code, out = ma.do(t, h, "GET", "/m/api/leases/mac", ``)
	l := out["lease"].(map[string]any)
	if code != 200 || l["holder"].(map[string]any)["description"] != "step 2" || len(l["queue"].([]any)) != 1 {
		t.Fatalf("%d %v", code, out)
	}
	// returning promotes C and wakes it with its own signed acquire
	code, out = ma.do(t, h, "DELETE", "/m/api/sessions/sA/leases/mac", ``)
	if code != 200 || out["returned"] != true || out["next"] != "sC" {
		t.Fatalf("%d %v", code, out)
	}
	r.leaseTick()
	waitFor(t, "leases", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 1 })
	d := got[0]
	if d.ID != "sC" || d.Kind != "lease-granted" || d.Device != "mac" || d.Minutes != 60 || d.Request == nil || signedPrompt(d.Request) != "continue the build" {
		t.Fatalf("%+v", d)
	}
	waitFor(t, "leases", func() bool { return len(r.LeaseList()) > 0 && leasePendingCount(r) == 0 })
	// the attestation's input is the text the machine builds
	in, origin, err := attested(d)
	if err != nil || origin != "session-signed:mC" || !strings.HasSuffix(string(in), "Your note: continue the build") {
		t.Fatalf("%s %s %v", in, origin, err)
	}

	// the app: take over (C is told), hand back (A, who looked meanwhile, is told), force return
	if code, out := appDo(t, r, "POST", "/api/leases/mac/take-over", `{"note":"mine"}`); code != 200 || out["interrupted"] != "sC" {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := ma.do(t, h, "POST", "/m/api/sessions/sA/leases/mac/seen", `{}`); code != 200 || out["takenOver"] != true {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := appDo(t, r, "POST", "/api/leases/mac/hand-back", `{"note":"done"}`); code != 200 || out["next"] != "sC" || len(out["notified"].([]any)) != 1 {
		t.Fatalf("%d %v", code, out)
	}
	r.leaseTick()
	waitFor(t, "leases", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) >= 4 })
	kinds := map[string]bool{}
	mu.Lock()
	for _, d := range got[1:] {
		kinds[d.ID+" "+d.Kind] = true
		if d.Kind == "lease-granted" && (!d.Handover || !d.Interrupted) {
			t.Fatalf("%+v", d)
		}
	}
	mu.Unlock()
	if !kinds["sC lease-taken"] || !kinds["sA lease-back"] || !kinds["sC lease-granted"] {
		t.Fatalf("%v", kinds)
	}
	if code, out := appDo(t, r, "POST", "/api/leases/mac/force-return", ``); code != 200 || out["previous"] != "sC" {
		t.Fatalf("%d %v", code, out)
	}
	// the setup session can take over and hand back for Deyao
	if code, out := appDo(t, r, "POST", "/setup/leases/iphone/take-over", `{"note":"long term"}`); code != 200 || out["taken"] != true {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := appDo(t, r, "GET", "/api/leases/iphone", ``); code != 200 || out["lease"].(map[string]any)["holder"].(map[string]any)["note"] != "long term" {
		t.Fatalf("%d %v", code, out)
	}
	// /api/state lists them; a destroyed session's queue place goes at the next tick
	ma.do(t, h, "POST", "/m/api/sessions/sA/leases/wechat-phone", `{}`)
	mc.do(t, h, "POST", "/m/api/sessions/sC/leases/wechat-phone", `{}`)
	r.st.Do(func(d *persisted) { d.Sessions["sC"].State = "destroyed" })
	r.leaseTick()
	if code, out := appDo(t, r, "GET", "/api/leases/wechat-phone", ``); code != 200 || len(out["lease"].(map[string]any)["queue"].([]any)) != 0 {
		t.Fatalf("%d %v", code, out)
	}
}

func leasePendingCount(r *Router) int {
	n := 0
	r.leaseTx(func(st *LeaseState) error { n = len(st.pendingNotifications()); return nil })
	return n
}

// describing a lease the session neither holds nor waits for changes nothing and isn't refused
func TestLeaseDescribeWithNothingHeld(t *testing.T) {
	st := newLeases()
	st.acquire("p", "A", LeaseOpts{Purpose: sp("map")}, lt0)
	o, err := st.describe("p", "B", LeaseOpts{Purpose: sp("other")}, lt0)
	if err != nil || o.Status != "none" || st.Resources["p"].Holder.Sid != "A" {
		t.Fatalf("%+v %v", o, err)
	}
}
