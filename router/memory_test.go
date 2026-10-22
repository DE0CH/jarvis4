package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func i64(n int64) *int64     { return &n }
func f64(x float64) *float64 { return &x }

func TestMemWatchEpisodes(t *testing.T) {
	now := time.Now()
	m := &memState{machine: "m1"}
	healthy := &MemSample{TotalKb: 4 << 20, AvailKb: 2 << 20, OOMKills: i64(0), PSIFull60: f64(0)}
	if m.observe(healthy, now) || m.alert != nil {
		t.Fatal("a healthy machine starts no episode")
	}
	// the kernel killed something
	oom := &MemSample{TotalKb: 4 << 20, AvailKb: 400 << 10, OOMKills: i64(2), PSIFull60: f64(1),
		Top: []MemProc{{900 << 10, "claude"}, {300 << 10, "chrome"}, {50 << 10, "node"}}}
	if !m.observe(oom, now.Add(10*time.Second)) {
		t.Fatal("an OOM kill starts an episode")
	}
	if !strings.Contains(m.alert.Reason, "killed 2 processes") || m.alert.Detail != "400 MB free of 4.0 GB (biggest: claude 0.9 GB, chrome 0.3 GB)" {
		t.Fatalf("%+v", m.alert)
	}
	// more starvation in the same episode: no second DM
	thrash := &MemSample{TotalKb: 4 << 20, AvailKb: 300 << 10, OOMKills: i64(2), PSIFull60: f64(25)}
	if m.observe(thrash, now.Add(20*time.Second)) || !strings.Contains(m.alert.Reason, "thrashing") {
		t.Fatalf("%+v", m.alert)
	}
	// healthy for less than memClear: still on; then off
	healthy = &MemSample{TotalKb: 4 << 20, AvailKb: 2 << 20, OOMKills: i64(2), PSIFull60: f64(0)}
	m.observe(healthy, now.Add(time.Minute))
	if m.alert == nil {
		t.Fatal("cleared too early")
	}
	m.observe(healthy, now.Add(time.Minute+memClear))
	if m.alert != nil {
		t.Fatal("not cleared after memClear of healthy samples")
	}
	// almost out
	low := &MemSample{TotalKb: 4 << 20, AvailKb: 100 << 10, OOMKills: i64(2)}
	if !m.observe(low, now.Add(time.Hour)) || m.alert.Reason != "it is almost out of memory" {
		t.Fatalf("%+v", m.alert)
	}
}

func TestMemSilentTick(t *testing.T) {
	now := time.Now()
	short := &MemSample{TotalKb: 4 << 20, AvailKb: 300 << 10}
	d := &persisted{Sessions: map[string]*Session{
		"s1": {ID: "s1", Label: "Busy one", State: "started", MachineID: "m1", Size: "small",
			Live: &Liveness{mem: &memState{machine: "m1", last: short, lastAt: now.Add(-2 * time.Minute)}}},
		"s2": {ID: "s2", State: "started", MachineID: "m2",
			Live: &Liveness{mem: &memState{machine: "m2", last: &MemSample{TotalKb: 4 << 20, AvailKb: 3 << 20}, lastAt: now.Add(-2 * time.Minute)}}},
		"s3": {ID: "s3", State: "paused", Live: &Liveness{mem: &memState{machine: "m3", last: short, lastAt: now.Add(-time.Hour)}}},
	}}
	dms := memSilentTick(d, now)
	if len(dms) != 1 || !strings.Contains(dms[0], "“Busy one”") || !strings.Contains(dms[0], "stopped answering") || !strings.Contains(dms[0], "medium (4 GB)") {
		t.Fatalf("%q", dms)
	}
	if len(memSilentTick(d, now.Add(time.Minute))) != 0 {
		t.Fatal("one DM per episode")
	}
	if d.Sessions["s3"].Live.mem != nil {
		t.Fatal("a paused session's watch is dropped")
	}
	if d.Sessions["s2"].Live.mem.alert != nil {
		t.Fatal("a silent machine with plenty of memory isn't starving")
	}
}

func TestMemoryReportViewAndUpgradeRefusals(t *testing.T) {
	st, err := testState(t, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := NewRouter(Config{}, st, nil, Policy{})
	var dms []string
	old := dmHook
	dmHook = func(s string) { dms = append(dms, s) }
	defer func() { dmHook = old }()
	mux := http.NewServeMux()
	r.registerMemory(func(p string, fn http.HandlerFunc) { mux.HandleFunc(p, fn) },
		func(p string, fn func(http.ResponseWriter, *http.Request, string, []byte)) {
			mux.HandleFunc(p, func(w http.ResponseWriter, req *http.Request) {
				b := make([]byte, 1<<16)
				n, _ := req.Body.Read(b)
				fn(w, req, req.Header.Get("X-Machine"), b[:n])
			})
		})
	st.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", Label: "Megathread", State: "started", MachineID: "m1", Size: "medium"}
		d.Sessions["s2"] = &Session{ID: "s2", State: "started", MachineID: "m2", Size: "large"}
		d.Sessions["s3"] = &Session{ID: "s3", State: "paused", Size: "small"}
		d.Machines["m1"], d.Machines["m2"] = "s1", "s2"
	})
	post := func(path, machine, body string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("X-Machine", machine)
		mux.ServeHTTP(w, req)
		return w.Code
	}
	if c := post("/m/memory", "m1", `{"totalKb":4000000,"availKb":2000000,"oomKills":0}`); c != 200 {
		t.Fatal(c)
	}
	if c := post("/m/memory", "m1", `{"totalKb":4000000,"availKb":100000,"oomKills":1,"top":[{"rssKb":2000000,"comm":"claude"}]}`); c != 200 {
		t.Fatal(c)
	}
	if c := post("/m/memory", "m1", `{"totalKb":0}`); c != 400 {
		t.Fatal(c)
	}
	if len(dms) != 1 || !strings.Contains(dms[0], "“Megathread” is running out of memory: the kernel killed 1 process for lack of memory") ||
		!strings.Contains(dms[0], "large (8 GB)") {
		t.Fatalf("%q", dms)
	}
	st.Do(func(d *persisted) {
		v := sessionView(d.Sessions["s1"], d)
		a, ok := v["memAlert"].(map[string]any)
		if !ok || a["nextSize"] != "large" || !strings.Contains(a["detail"].(string), "biggest: claude 1.9 GB") {
			t.Fatalf("%v", v["memAlert"])
		}
		if mem, ok := v["memory"].(map[string]any); !ok || mem["availMb"] != int64(97) {
			t.Fatalf("%v", v["memory"])
		}
		if _, ok := sessionView(d.Sessions["s2"], d)["memAlert"]; ok {
			t.Fatal("no alert on a session that reported nothing")
		}
	})
	// paused: its next start is on the bigger size
	if c := post("/api/sessions/s3/upgrade", "", `{}`); c != 200 && c != 202 {
		t.Fatalf("paused: %d", c)
	}
	r.st.Do(func(d *persisted) {
		if d.Sessions["s3"].Size != nextSize("small") {
			t.Fatalf("paused: next size %q", d.Sessions["s3"].Size)
		}
	})
	if c := post("/api/sessions/nope/upgrade", "", `{}`); c != 404 {
		t.Fatalf("no session: %d", c)
	}
}

// the "upgraded" text is built on both sides; the core attests the router's bytes and the machine refuses others
func TestUpgradedTextMatchesMachine(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "machine", "deliver.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := regexp.MustCompile(`(?s)func upgradedText\(from, to string\) \(string, error\) \{.*?return (fmt\.Sprintf.*?), nil\n\}`).FindSubmatch(src)
	mine, _ := os.ReadFile("memory.go")
	ours := regexp.MustCompile(`(?s)func upgradedText\(from, to string\) string \{\n\treturn (fmt\.Sprintf.*?)\n\}`).FindSubmatch(mine)
	if body == nil || ours == nil || string(body[1]) != string(ours[1]) {
		t.Fatal("router/memory.go upgradedText and machine/deliver.go upgradedText differ")
	}
	if _, _, err := attested(Delivery{Kind: "upgraded", From: "medium", To: "evil"}); err == nil {
		t.Fatal("a size outside the three must be refused")
	}
	b, origin, err := attested(Delivery{Kind: "upgraded", From: "small", To: "medium"})
	if err != nil || origin != "image-text" || !strings.Contains(string(b), "from a small (2 GB) to a medium (4 GB)") {
		t.Fatalf("%q %s %v", b, origin, err)
	}
	b, _, err = attested(Delivery{Kind: "upgraded", From: "large", To: "16gb"})
	if err != nil || !strings.Contains(string(b), "from a large (8 GB) to a 16 GB machine") {
		t.Fatalf("%q %v", b, err)
	}
}

// sizes past large need the new core (it reports sizeLadder in /identity): until it runs, the memory DM, memAlert
// and Upgrade offer only what the running core starts
func TestMemUpgradeOffersOnlySizesTheCoreStarts(t *testing.T) {
	ladder := false
	cs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		id := map[string]any{"signingKey": "k", "agreementKey": "a"}
		if ladder {
			id["sizeLadder"] = 1
		}
		writeJSON(w, 200, id)
	}))
	defer cs.Close()
	t.Cleanup(func() { noteCoreSizes(false) })
	c := &CoreClient{base: cs.URL, http: http.DefaultClient}
	if _, err := c.Key(); err != nil {
		t.Fatal(err)
	}
	a := &MemAlert{Reason: "r"}
	if !coreTakesSize("large") || coreTakesSize("16gb") || upgradeTarget("large") != "" || upgradeTarget("medium") != "large" {
		t.Fatal("the running core (no sizeLadder) starts only the named sizes")
	}
	if msg := memMessage("x", "large", a); strings.Contains(msg, "Upgrade button") || strings.Contains(msg, "moves it to") ||
		!strings.Contains(msg, "large (8 GB), the largest size the running core starts") {
		t.Fatalf("%q", msg)
	}
	if msg := memMessage("x", "medium", a); !strings.Contains(msg, "One tap moves it to large (8 GB)") {
		t.Fatalf("%q", msg)
	}
	s := &Session{ID: "s1", State: "started", MachineID: "m1", Size: "large", Live: &Liveness{mem: &memState{machine: "m1", alert: a}}}
	v := map[string]any{}
	memView(s, v)
	if m := v["memAlert"].(map[string]any); m["nextSize"] != nil || m["nextGb"] != nil {
		t.Fatalf("an Upgrade the core can't start: %v", m)
	}
	r := newTestRouter(t)
	r.core = c
	r.st.Do(func(d *persisted) { d.Sessions["s1"] = s; d.Machines["m1"] = "s1" })
	if _, err := r.Upgrade("s1"); err == nil || !strings.Contains(err.Error(), "needs the new core") {
		t.Fatalf("upgrade past large on the old core: %v", err)
	}
	// the new core says it starts the ladder: 16 GB is offered
	ladder = true
	if _, err := c.Key(); err != nil {
		t.Fatal(err)
	}
	if upgradeTarget("large") != "16gb" || !strings.Contains(memMessage("x", "large", a), "One tap moves it to 16 GB") {
		t.Fatal(memMessage("x", "large", a))
	}
	v = map[string]any{}
	memView(s, v)
	if m := v["memAlert"].(map[string]any); m["nextSize"] != "16gb" || m["nextGb"] != 16 {
		t.Fatalf("%v", m)
	}
}
