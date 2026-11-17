package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHetzner: the Cloud API as runners.go uses it (servers and key objects of one project)
type fakeHetzner struct {
	mu      sync.Mutex
	next    int64
	servers map[int64]map[string]any
	keys    map[int64]map[string]any
	actions []string
	fail    map[int64]bool // servers whose delete Hetzner refuses
}

func startFakeHetzner(t *testing.T) *fakeHetzner {
	f := &fakeHetzner{next: 100, servers: map[int64]map[string]any{}, keys: map[int64]map[string]any{}, fail: map[int64]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	old := hetznerAPI
	hetznerAPI = srv.URL
	t.Setenv("HETZNER_RUNNERS_TOKEN", "test-token")
	t.Cleanup(func() { hetznerAPI = old; srv.Close() })
	return f
}

func (f *fakeHetzner) add(name string, labels map[string]string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	if labels == nil {
		labels = map[string]string{}
	}
	f.servers[f.next] = map[string]any{"id": f.next, "name": name, "status": "running", "created": fmt.Sprintf("2026-11-17T03:00:%02dZ", f.next%60),
		"labels": labels, "location": map[string]any{"name": "fsn1"},
		"server_type": map[string]any{"name": "cx23", "cores": 2, "memory": 4.0, "prices": []any{
			map[string]any{"location": "fsn1", "price_monthly": map[string]any{"gross": "6.5880000000000000"}}}},
		"public_net": map[string]any{"ipv6": map[string]any{"ip": fmt.Sprintf("2a01:4f8:c0c:%x::/64", f.next)}}}
	return f.next
}

func (f *fakeHetzner) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, s := range f.servers {
		out = append(out, s["name"].(string))
	}
	sort.Strings(out)
	return out
}

func (f *fakeHetzner) serve(w http.ResponseWriter, req *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fail := func(status int, code, msg string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
	}
	if req.Header.Get("Authorization") != "Bearer test-token" {
		fail(401, "unauthorized", "bad token")
		return
	}
	b, _ := io.ReadAll(req.Body)
	in := map[string]any{}
	json.Unmarshal(b, &in)
	var id int64
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(parts) > 1 {
		fmt.Sscanf(parts[1], "%d", &id)
	}
	switch {
	case req.Method == "GET" && req.URL.Path == "/servers":
		sel := req.URL.Query().Get("label_selector")
		out := []any{}
		for _, s := range f.servers {
			if k, v, ok := strings.Cut(sel, "="); sel == "" || ok && s["labels"].(map[string]string)[k] == v {
				out = append(out, s)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"servers": out, "meta": map[string]any{"pagination": map[string]any{"next_page": nil}}})
	case req.Method == "POST" && req.URL.Path == "/servers":
		for _, s := range f.servers {
			if s["name"] == in["name"] {
				fail(409, "uniqueness_error", "server name is already used")
				return
			}
		}
		labels := map[string]string{}
		for k, v := range in["labels"].(map[string]any) {
			labels[k] = v.(string)
		}
		f.mu.Unlock()
		nid := f.add(in["name"].(string), labels)
		f.mu.Lock()
		f.servers[nid]["request"] = in
		json.NewEncoder(w).Encode(map[string]any{"server": f.servers[nid]})
	case req.Method == "DELETE" && parts[0] == "servers":
		if f.fail[id] {
			fail(423, "locked", "server is locked")
			return
		}
		if f.servers[id] == nil {
			fail(404, "not_found", "server not found")
			return
		}
		delete(f.servers, id)
		w.Write([]byte(`{"action":{"status":"running"}}`))
	case req.Method == "POST" && parts[0] == "servers" && len(parts) == 4:
		f.actions = append(f.actions, fmt.Sprintf("%s %s", f.servers[id]["name"], parts[3]))
		w.Write([]byte(`{"action":{"status":"running"}}`))
	case req.Method == "GET" && req.URL.Path == "/ssh_keys":
		out := []any{}
		for _, k := range f.keys {
			if k["name"] == req.URL.Query().Get("name") {
				out = append(out, k)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"ssh_keys": out})
	case req.Method == "POST" && req.URL.Path == "/ssh_keys":
		f.next++
		in["id"] = f.next
		f.keys[f.next] = in
		json.NewEncoder(w).Encode(map[string]any{"ssh_key": in})
	case req.Method == "DELETE" && parts[0] == "ssh_keys":
		delete(f.keys, id)
		w.WriteHeader(204)
	default:
		fail(404, "not_found", req.Method+" "+req.URL.Path)
	}
}

const testPub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3Qta2V5LW9mLWEtc2Vzc2lvbi1ydW5uZXIh hz-runner-sA"

// a session makes, lists, acts on and deletes its own runners through its machine: the server carries the session's
// label whatever the caller sends, has no IPv4 and the session's key; another session can't touch it
func TestASessionsRunnersAreItsOwn(t *testing.T) {
	f := startFakeHetzner(t)
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	addSession(r, "sC", "started", "mC", false)
	ma, mc := newTestMachine(r, "mA"), newTestMachine(r, "mC")
	h := r.MachineHandler()

	body, _ := json.Marshal(map[string]any{"name": "build-1", "type": "cpx42", "sshKey": testPub, "userData": "#!/bin/bash\ntrue\n",
		"labels": map[string]string{"session": "sC", "purpose": "mine", "role": "gw"}})
	code, out := ma.do(t, h, "POST", "/m/api/sessions/sA/runners", string(body))
	if code != 200 || out["name"] != "build-1" || out["sessionId"] != "sA" || !strings.HasSuffix(out["ipv6"].(string), "::1") || out["monthly"] != "EUR 6.59/month" {
		t.Fatalf("%d %v", code, out)
	}
	var made map[string]any
	for _, s := range f.servers {
		made = s
	}
	labels := made["labels"].(map[string]string)
	reqIn := made["request"].(map[string]any)
	if labels["session"] != "sA" || labels["purpose"] != "runner" || labels["role"] != "gw" {
		t.Fatalf("labels %v", labels)
	}
	if pn := reqIn["public_net"].(map[string]any); pn["enable_ipv4"] != false || pn["enable_ipv6"] != true || reqIn["server_type"] != "cpx42" ||
		reqIn["image"] != "ubuntu-24.04" || reqIn["location"] != "fsn1" || len(reqIn["ssh_keys"].([]any)) != 1 || reqIn["user_data"] != "#!/bin/bash\ntrue\n" {
		t.Fatalf("request %v", reqIn)
	}
	if len(f.keys) != 1 {
		t.Fatalf("keys %v", f.keys)
	}
	for _, k := range f.keys {
		if k["name"] != "runner-sA" || k["public_key"] != keyBody(testPub) {
			t.Fatalf("key %v", k)
		}
	}
	// the same name again, a bad name, no key, another session's path
	if code, out := ma.do(t, h, "POST", "/m/api/sessions/sA/runners", string(body)); code != 409 {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := ma.do(t, h, "POST", "/m/api/sessions/sA/runners", `{"name":"Bad_Name","sshKey":"`+testPub+`"}`); code != 400 {
		t.Fatal("a bad name")
	}
	if code, _ := ma.do(t, h, "POST", "/m/api/sessions/sA/runners", `{"name":"nokey"}`); code != 400 {
		t.Fatal("no key")
	}
	if code, _ := mc.do(t, h, "POST", "/m/api/sessions/sA/runners", string(body)); code != 403 {
		t.Fatal("another session's path")
	}
	// sC sees none of sA's, and can neither act on nor delete it
	if code, out := mc.do(t, h, "GET", "/m/api/sessions/sC/runners", ""); code != 200 || len(out["runners"].([]any)) != 0 {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := mc.do(t, h, "DELETE", "/m/api/sessions/sC/runners/build-1", ""); code != 400 {
		t.Fatal("deleted another session's runner")
	}
	if code, _ := mc.do(t, h, "POST", "/m/api/sessions/sC/runners/build-1/poweroff", ""); code != 400 || len(f.actions) != 0 {
		t.Fatal("acted on another session's runner")
	}
	if code, out := ma.do(t, h, "GET", "/m/api/sessions/sA/runners", ""); code != 200 || len(out["runners"].([]any)) != 1 {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := ma.do(t, h, "POST", "/m/api/sessions/sA/runners/build-1/poweroff", ""); code != 200 || len(f.actions) != 1 || f.actions[0] != "build-1 poweroff" {
		t.Fatalf("%d %v", code, f.actions)
	}
	if code, _ := ma.do(t, h, "POST", "/m/api/sessions/sA/runners/build-1/rebuild", ""); code != 400 {
		t.Fatal("an action that isn't offered")
	}
	// a session on a new machine has a new key: the key object is replaced
	other := strings.Replace(testPub, "AAAAIHRl", "AAAAIHRm", 1)
	if code, out := ma.do(t, h, "POST", "/m/api/sessions/sA/runners", `{"name":"build-2","sshKey":"`+other+`"}`); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if len(f.keys) != 1 {
		t.Fatalf("keys %v", f.keys)
	}
	for _, k := range f.keys {
		if k["public_key"] != keyBody(other) {
			t.Fatalf("key %v", k)
		}
	}
	// the last runner takes the key with it
	if code, _ := ma.do(t, h, "DELETE", "/m/api/sessions/sA/runners/build-1", ""); code != 200 || len(f.keys) != 1 {
		t.Fatal(code, f.keys)
	}
	if code, _ := ma.do(t, h, "DELETE", "/m/api/sessions/sA/runners/build-2", ""); code != 200 || len(f.keys) != 0 || len(f.servers) != 0 {
		t.Fatal(code, f.keys, f.servers)
	}
	// a session has at most maxSessionRunners
	for i := 0; i < maxSessionRunners; i++ {
		f.add(fmt.Sprintf("r%d", i), map[string]string{"session": "sA"})
	}
	if code, out := ma.do(t, h, "POST", "/m/api/sessions/sA/runners", `{"name":"one-more","sshKey":"`+testPub+`"}`); code != 400 || !strings.Contains(out["error"].(string), "delete one first") {
		t.Fatalf("%d %v", code, out)
	}
}

// with no token the routes say so and a pause or destroy passes them by
func TestRunnersNotSetUp(t *testing.T) {
	t.Setenv("HETZNER_RUNNERS_TOKEN", "")
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	ma := newTestMachine(r, "mA")
	if code, out := ma.do(t, r.MachineHandler(), "GET", "/m/api/sessions/sA/runners", ""); code != 503 || !strings.Contains(out["error"].(string), "HETZNER_RUNNERS_TOKEN") {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := inboxDo(t, r, "GET", "/api/runners", "", true); code != 503 {
		t.Fatal(code)
	}
}

// the Machines view lists every server of the project with its session, or why it stands out: no session label, a
// session that is gone or destroyed, a paused session nothing will wake. Delete is only for those.
func TestRunnersOverviewShowsStrays(t *testing.T) {
	f := startFakeHetzner(t)
	r := newTestRouter(t)
	addSession(r, "sRun", "started", "mRun", false)
	addSession(r, "sIdle", "paused", "", false)
	addSession(r, "sWake", "paused", "", false)
	w, err := normalizeWakeup(body(`{"delaySeconds": 3600, "prompt": "check the build"}`), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ArmWakeup("sWake", w); err != nil {
		t.Fatal(err)
	}
	r.st.Do(func(d *persisted) { d.Records = append(d.Records, &Record{Session: Session{ID: "sDead"}}) })
	ids := map[string]int64{
		"of-running":   f.add("of-running", map[string]string{"session": "sRun", "purpose": "runner"}),
		"of-idle":      f.add("of-idle", map[string]string{"session": "sIdle"}),
		"of-waking":    f.add("of-waking", map[string]string{"session": "sWake"}),
		"of-destroyed": f.add("of-destroyed", map[string]string{"session": "sDead"}),
		"of-unknown":   f.add("of-unknown", map[string]string{"session": "sNever"}),
		"by-hand":      f.add("by-hand", nil),
	}
	code, out := inboxDo(t, r, "GET", "/api/runners", "", true)
	if code != 200 || out["attention"] != float64(4) || out["project"] != "runners" {
		t.Fatalf("%d %v", code, out)
	}
	got := map[string]string{}
	for _, x := range out["runners"].([]any) {
		v := x.(map[string]any)
		att, _ := v["attention"].(string)
		del, _ := v["deletable"].(bool)
		if (att != "") != del {
			t.Fatalf("%v: stands out %q, deletable %v", v["name"], att, del)
		}
		got[v["name"].(string)] = att
	}
	want := map[string]string{"of-running": "", "of-waking": "", "of-idle": "Its session is paused and nothing is armed to wake it",
		"of-destroyed": "Its session was destroyed", "of-unknown": "Its session is gone", "by-hand": "No session: made outside Jarvis 4"}
	for name, att := range want {
		if got[name] != att {
			t.Fatalf("%s: %q, want %q", name, got[name], att)
		}
	}
	// Delete: refused for a runner of a session at work or one that will wake, done for a stray
	for _, name := range []string{"of-running", "of-waking"} {
		if code, out := inboxDo(t, r, "POST", fmt.Sprintf("/api/runners/%d/delete", ids[name]), "", true); code != 400 || !strings.Contains(out["error"].(string), "goes with its session") {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	for _, name := range []string{"of-idle", "of-destroyed", "of-unknown", "by-hand"} {
		if code, out := inboxDo(t, r, "POST", fmt.Sprintf("/api/runners/%d/delete", ids[name]), "", true); code != 200 {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	if got := strings.Join(f.names(), " "); got != "of-running of-waking" {
		t.Fatal(got)
	}
	if code, _ := inboxDo(t, r, "POST", "/api/runners/999/delete", "", true); code != 400 {
		t.Fatal("a runner that isn't there")
	}
}

// a pause deletes the session's runners unless a wakeup is armed; the pause of a restart keeps them; a destroy
// deletes them; a runner Hetzner won't delete doesn't fail the pause
func TestRunnersGoWithTheirSession(t *testing.T) {
	rg, k, sid, m1 := lostRig(t)
	f := startFakeHetzner(t)
	r := rg.r
	other := f.add("someone-elses", map[string]string{"session": "sOther"})
	snap := func() {
		t.Helper()
		tarball := makeTar(t, rg.files)
		sum := sha256.Sum256(tarball)
		s := kernelSession(rg, sid)
		m := m1
		if s.MachineID != m1.ID {
			t.Fatal("the session moved machines in this test")
		}
		sig, _ := m.Sig.Sign([]byte(hex.EncodeToString(sum[:])))
		putSnap(t, r, s.MachineID, tarball, sig)
	}
	notes := func() string {
		var b strings.Builder
		for _, l := range r.lcLines(sid) {
			b.Write(l)
		}
		return b.String()
	}

	// a wakeup is armed: the pause keeps the runners
	w, err := normalizeWakeup(body(`{"delaySeconds": 7200, "prompt": "look at the runner"}`), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ArmWakeup(sid, w); err != nil {
		t.Fatal(err)
	}
	f.add("keep-1", map[string]string{"session": sid})
	stuck := f.add("stuck-1", map[string]string{"session": sid})
	f.keys[1] = map[string]any{"id": int64(1), "name": runnerKeyName(sid), "public_key": keyBody(testPub)}
	snap()
	if err := r.Pause(sid); err != nil {
		t.Fatal(err)
	}
	if err := r.waitActionEnd(sid, "paused"); err != nil {
		t.Fatal(err, kernelSession(rg, sid).Error)
	}
	if got := strings.Join(f.names(), " "); got != "keep-1 someone-elses stuck-1" || len(f.keys) != 1 {
		t.Fatal(got, f.keys)
	}
	if !strings.Contains(notes(), "kept the session's 2 runner(s): a wakeup or cron is armed") {
		t.Fatal(notes())
	}

	// the wakeup is cancelled and the session, running again, pauses: its runners go; one Hetzner refuses stays, the
	// pause still ends, and the key stays with it
	if err := r.Resume(sid, false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the next machine", func() bool { s := kernelSession(rg, sid); return s.MachineID != "" && s.Kernel.MachineCert != nil })
	if _, err := r.CancelWakeups(sid, nil, true); err != nil {
		t.Fatal(err)
	}
	f.fail[stuck] = true
	m2 := k.Fly.Machine(kernelSession(rg, sid).MachineID)
	m1 = m2
	h := r.MachineHandler()
	if code, b := kdo(t, h, m2, "POST", "/m/pull-secrets", "{}"); code != 200 {
		t.Fatal(code, string(b))
	}
	if code, b := kdo(t, h, m2, "POST", "/m/status", `{"raw":""}`); code != 200 {
		t.Fatal(code, string(b))
	}
	waitFor(t, "the session started", func() bool { return kernelSession(rg, sid).State == "started" && !r.busy(sid) })
	snap()
	if err := r.Pause(sid); err != nil {
		t.Fatal(err)
	}
	if err := r.waitActionEnd(sid, "paused"); err != nil {
		t.Fatal(err, kernelSession(rg, sid).Error)
	}
	if got := strings.Join(f.names(), " "); got != "someone-elses stuck-1" || len(f.keys) != 1 {
		t.Fatal(got, f.keys)
	}
	if n := notes(); !strings.Contains(n, "deleted the session's runners (paused with no wakeup or cron armed): keep-1") || !strings.Contains(n, "a runner was not deleted") {
		t.Fatal(n)
	}

	// a destroy deletes what is left, and the key
	f.fail[stuck] = false
	if err := r.Destroy(sid); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the record", func() bool {
		gone := false
		r.st.Do(func(d *persisted) { gone = d.Sessions[sid] == nil })
		return gone
	})
	if got := strings.Join(f.names(), " "); got != "someone-elses" || len(f.keys) != 0 {
		t.Fatal(got, f.keys)
	}
	_ = other
}

// the pause of a restart (an Upgrade, a bigger machine) is no pause: the runners stay
func TestARestartKeepsRunners(t *testing.T) {
	rg, _, sid, m1 := lostRig(t)
	f := startFakeHetzner(t)
	f.add("mine", map[string]string{"session": sid})
	tarball := makeTar(t, rg.files)
	sum := sha256.Sum256(tarball)
	sig, _ := m1.Sig.Sign([]byte(hex.EncodeToString(sum[:])))
	putSnap(t, rg.r, m1.ID, tarball, sig)
	if err := rg.r.pauseWith(sid, nil); err != nil {
		t.Fatal(err)
	}
	if err := rg.r.waitActionEnd(sid, "paused"); err != nil {
		t.Fatal(err, kernelSession(rg, sid).Error)
	}
	if got := strings.Join(f.names(), " "); got != "mine" {
		t.Fatal(got)
	}
}
