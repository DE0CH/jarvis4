package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLiveStateOf(t *testing.T) {
	wk := func(jobs, sub int) *Workers { return &Workers{Subagents: sub, Jobs: map[string]int{"shell": jobs}} }
	spin := "  ✻ Thinking… (12s · esc to interrupt)\n"
	for _, c := range []struct {
		g      *Registry
		fresh  bool
		screen string
		want   string
		jobs   int
	}{
		{nil, false, "", "booting", 0},
		{&Registry{Status: "idle"}, false, "", "booting", 0}, // a report too old to say
		{&Registry{Status: ""}, true, "", "booting", 0},      // claude not up yet
		{&Registry{Status: "idle"}, true, "", "idle", 0},
		{&Registry{Status: "idle", BgTasks: 1}, true, "", "background", 1},
		{&Registry{Status: "idle", Workers: wk(0, 2)}, true, "", "background", 0},
		{&Registry{Status: "waiting"}, true, "", "waiting", 0},
		{&Registry{Status: "busy"}, true, "", "working", 0},
		{&Registry{Status: "busy", Workers: wk(2, 0)}, true, spin, "working", 2},      // a turn and jobs
		{&Registry{Status: "busy", Workers: wk(2, 0)}, true, "> \n", "background", 2}, // the turn ended, jobs run
		{&Registry{Status: "busy", Workers: wk(2, 0)}, true, "", "working", 2},        // no pane: can't tell, as busy says
	} {
		got, jobs, _ := liveStateOf(c.g, c.fresh, c.screen)
		if got != c.want || jobs != c.jobs {
			t.Errorf("%+v fresh=%v screen=%q: %s %d, want %s %d", c.g, c.fresh, c.screen, got, jobs, c.want, c.jobs)
		}
	}
}

func TestLiveDoc(t *testing.T) {
	r := newTestRouter(t)
	now := time.Now()
	reg := func(id, status string, bg int, at int64) {
		r.st.Do(func(d *persisted) {
			d.Sessions[id].Live = &Liveness{LastReport: now, Reg: &Registry{Status: status, BgTasks: bg, StatusUpdatedAt: at}}
		})
	}
	for i, st := range []string{"idle", "busy", "waiting", "idle"} {
		id := string(rune('a' + i))
		addSession(r, id, "started", "m"+id, false)
		reg(id, st, map[int]int{3: 1}[i], int64(1000+i))
	}
	addSession(r, "e", "paused", "", false) // paused, nothing armed: not listed
	addSession(r, "f", "paused", "", false) // paused with a cron and a wakeup: scheduled, the sooner one
	addSession(r, "g", "started", "mg", false)
	reg("g", "idle", 0, 1)
	addSession(r, "h", "paused", "", false) // a watch only: scheduled, no time, after the timed ones
	r.st.Do(func(d *persisted) {
		sched(d, "f").Crons["c"] = &Cron{Name: "c", NextAt: 9000}
		sched(d, "f").Wakeups["w"] = &Wakeup{Name: "w", At: 7000}
		sched(d, "g").Wakeups["w"] = &Wakeup{Name: "w", At: 8000} // idle with a wakeup: scheduled
		sched(d, "h").Watches["x"] = &Watch{Name: "x", NextAt: 1}
	})
	for i := 0; i < 20; i++ {
		id := "z" + string(rune('a'+i))
		addSession(r, id, "started", "m"+id, false)
		reg(id, "idle", 0, int64(i))
	}
	for i := 0; i < 10; i++ { // past liveMax: the oldest idle ones are left out
		id := "y" + string(rune('a'+i))
		addSession(r, id, "started", "m"+id, false)
		reg(id, "idle", 0, int64(i))
	}
	doc := r.liveDoc(now)
	if doc.Total != 37 || len(doc.Sessions) != liveMax {
		t.Fatalf("total %d, %d sessions", doc.Total, len(doc.Sessions))
	}
	var order []string
	for _, x := range doc.Sessions[:8] {
		order = append(order, x.State+":"+x.Name)
	}
	want := []string{"waiting:label c", "working:label b", "background:label d", "scheduled:label f", "scheduled:label g", "scheduled:label h", "idle:label a", "idle:label zt"}
	if b, _ := json.Marshal(order); string(b) != func() string { w, _ := json.Marshal(want); return string(w) }() {
		t.Fatalf("order %v, want %v", order, want)
	}
	if doc.Sessions[2].Jobs != 1 || doc.Sessions[0].Since != 1002 || doc.Sessions[3].Next != 7000 || doc.Sessions[4].Next != 8000 || doc.Sessions[5].Next != 0 {
		t.Fatalf("%+v", doc.Sessions[:3])
	}
}

func TestLivePost(t *testing.T) {
	var got liveDocument
	var secret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		secret = req.Header.Get("X-Jarvis-Secret")
		b, _ := io.ReadAll(req.Body)
		json.Unmarshal(b, &got)
		if secret != "s3" {
			w.WriteHeader(403)
		}
	}))
	defer srv.Close()
	doc := liveDocument{At: 5, Total: 1, Sessions: []liveSession{{Name: "n", State: "idle"}}}
	if err := livePost(srv.Client(), srv.URL, "s3", doc); err != nil || got.Sessions[0].Name != "n" || secret != "s3" {
		t.Fatalf("%v %+v %q", err, got, secret)
	}
	if err := livePost(srv.Client(), srv.URL, "wrong", doc); err == nil {
		t.Fatal("a refused push is an error")
	}
}
