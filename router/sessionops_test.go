package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// appDo: a request to the public listener (NoAccess routers only)
func appDo(t *testing.T, r *Router, method, target, body string, hdr ...string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)
	out := map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// answerExecs: plays the machine for r.Exec — records each command and answers with code
func answerExecs(r *Router, machine string, code int, stop chan struct{}) *[]string {
	var mu sync.Mutex
	cmds := &[]string{}
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if b, ok := mqWaitKind(r, machine, "exec", 50*time.Millisecond); ok {
				var it execItem
				json.Unmarshal(b, &it)
				var req struct{ ID, Cmd string }
				json.Unmarshal([]byte(it.Request), &req)
				mu.Lock()
				*cmds = append(*cmds, req.Cmd)
				mu.Unlock()
				r.execResult(ExecResult{ID: req.ID, Code: code})
			}
		}
	}()
	return cmds
}

func TestPermissionModeInPlaceAndPaused(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	addSession(r, "sP", "paused", "", false)
	stop := make(chan struct{})
	defer close(stop)
	cmds := answerExecs(r, "mA", 0, stop)

	// raising to bypass needs a fresh phone grant (a rule or the allow list isn't enough)
	code, out := inboxDo(t, r, "POST", "/api/sessions/sA/permission-mode", `{"mode":"bypass"}`, true)
	if code != 403 || out["needsGrant"] != "terminal" || out["phoneGrant"] != true {
		t.Fatalf("without a phone grant: %d %v", code, out)
	}
	addGrant(r, "sA", "terminal", "rule")
	if code, _ := inboxDo(t, r, "POST", "/api/sessions/sA/permission-mode", `{"mode":"bypass"}`, true); code != 403 {
		t.Fatalf("a standing rule raised to bypass: %d", code)
	}
	addGrant(r, "sA", "terminal", "grant")
	code, out = appDo(t, r, "POST", "/api/sessions/sA/permission-mode", `{"mode":"bypass"}`)
	if code != 202 || out["inPlace"] != true {
		t.Fatalf("%d %v", code, out)
	}
	waitFor(t, "mode switched", func() bool {
		var m string
		r.st.Do(func(d *persisted) { m = d.Sessions["sA"].PermissionMode })
		return m == "bypass"
	})
	if len(*cmds) != 1 || (*cmds)[0] != "/usr/local/bin/set-permission-mode bypass" {
		t.Fatalf("%v", *cmds)
	}
	waitFor(t, "job done", func() bool { j := r.ops.jobView("sA"); return j != nil && j["phase"] == "done" })
	// the same mode again: nothing to do
	if code, out := appDo(t, r, "POST", "/api/sessions/sA/permission-mode", `{"mode":"bypass"}`); code != 200 || out["unchanged"] != true {
		t.Fatalf("%d %v", code, out)
	}
	// paused: recorded for the next start, which passes it in the env
	if code, out := appDo(t, r, "POST", "/api/sessions/sP/permission-mode", `{"mode":"bypass"}`); code != 200 || out["nextStart"] != true {
		t.Fatalf("%d %v", code, out)
	}
	var s Session
	r.st.Do(func(d *persisted) { s = *d.Sessions["sP"] })
	if r.machineEnv(&s)["SESSION_PERMISSION_MODE"] != "bypass" {
		t.Fatal("the next start doesn't carry the mode")
	}
}

func TestPermissionModeFailureKeepsMode(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	r.st.Do(func(d *persisted) { d.Sessions["sA"].PermissionMode = "auto" })
	stop := make(chan struct{})
	defer close(stop)
	answerExecs(r, "mA", 1, stop)
	addGrant(r, "sA", "terminal", "grant")
	if code, _ := appDo(t, r, "POST", "/api/sessions/sA/permission-mode", `{"mode":"bypass"}`); code != 202 {
		t.Fatal(code)
	}
	waitFor(t, "job failed", func() bool { j := r.ops.jobView("sA"); return j != nil && j["phase"] == "failed" })
	r.st.Do(func(d *persisted) {
		if d.Sessions["sA"].PermissionMode != "auto" {
			t.Fatal("mode changed although the switch failed")
		}
	})
}

func TestBusyInState(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	r.core = &CoreClient{base: "http://127.0.0.1:1", http: http.DefaultClient}
	unlock, err := r.lock("sA", "pausing")
	if err != nil {
		t.Fatal(err)
	}
	_, out := appDo(t, r, "GET", "/api/state", "")
	ss := out["sessions"].([]any)
	b, _ := ss[0].(map[string]any)["busy"].(map[string]any)
	if b == nil || b["kind"] != "pausing" {
		t.Fatalf("%v", ss[0])
	}
	if _, err := r.lock("sA", "starting"); !errors.Is(err, errBusy) || !strings.Contains(err.Error(), "pausing") {
		t.Fatal("a second action got the lock")
	}
	unlock()
	_, out = appDo(t, r, "GET", "/api/state", "")
	if _, ok := out["sessions"].([]any)[0].(map[string]any)["busy"]; ok {
		t.Fatal("still busy")
	}
}

// startCore: a core that answers every call and records /start's body
type startCore struct {
	fakeCore
	mu     sync.Mutex
	starts []map[string]any
}

func (c *startCore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/start" {
		var b map[string]any
		json.NewDecoder(req.Body).Decode(&b)
		c.mu.Lock()
		c.starts = append(c.starts, b)
		c.mu.Unlock()
		writeJSON(w, 502, map[string]string{"error": "no Fly in tests"})
		return
	}
	c.fakeCore.ServeHTTP(w, req)
}

func (c *startCore) lastStart() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.starts) == 0 {
		return nil
	}
	return c.starts[len(c.starts)-1]
}

func newOpsRig(t *testing.T) (*rig, *startCore) {
	rg := newRig(t)
	sc := &startCore{fakeCore: fakeCore{key: newTestKey()}}
	cs := httptest.NewServer(sc)
	t.Cleanup(cs.Close)
	rg.r.core = &CoreClient{base: cs.URL, http: http.DefaultClient}
	rg.r.cfg.NoAccess = true
	rg.r.st.Do(func(d *persisted) { d.Sessions["s1"].Cert = rg.cert })
	opsPoll = time.Millisecond
	return rg, sc
}

// (a restart with a rollback needs the phone: the rollback is a one-time input in the cert, vouch_test.go)
func TestRestartPatchesEnv(t *testing.T) {
	rg, sc := newOpsRig(t)
	r := rg.r
	code, out := appDo(t, r, "POST", "/api/sessions/s1/restart",
		`{"env":{"FEATURE_FLAG":"on","DEBUG":1},"size":"large","apiProxy":true}`)
	if code != 202 {
		t.Fatalf("%d %v", code, out)
	}
	waitFor(t, "start asked", func() bool { return sc.lastStart() != nil })
	st := sc.lastStart()
	if _, has := st["env"]; st["size"] != "large" || has {
		t.Fatalf("start %v (the core sets a machine's env itself: the router sends none)", st)
	}
	// the settings reach the machine as the router's machine config, from the session
	var s0 Session
	r.st.Do(func(d *persisted) { s0 = *d.Sessions["s1"] })
	if env := r.machineEnv(&s0); env["FEATURE_FLAG"] != "on" || env["DEBUG"] != "1" || env["SESSION_API_PROXY"] != "1" {
		t.Fatalf("machine env %v", env)
	}
	waitFor(t, "job finished", func() bool { j := r.ops.jobView("s1"); return j != nil && j["finishedAt"] != nil })
	// the patch stays for later starts
	var s Session
	r.st.Do(func(d *persisted) { s = *d.Sessions["s1"] })
	other := s
	other.Cert = rg.core.key.doc(map[string]any{"machine": map[string]string{"id": "m9"}})
	e := r.machineEnv(&other)
	if e["FEATURE_FLAG"] != "on" || e["JARVIS2_ROLLBACK"] != "" {
		t.Fatalf("later start env %v", e)
	}
	// "" removes a key
	r.st.Do(func(d *persisted) { d.Sessions["s1"].State = "paused" })
	r.ops.wake = nil
	if code, out := appDo(t, r, "POST", "/api/sessions/s1/env", `{"env":{"FEATURE_FLAG":""}}`); code != 202 {
		t.Fatalf("%d %v", code, out)
	}
	waitFor(t, "removed", func() bool {
		var ok bool
		r.st.Do(func(d *persisted) { _, has := d.Sessions["s1"].Ops.Env["FEATURE_FLAG"]; ok = !has })
		return ok
	})
	// that env change runs as a job of its own: let it end before the test does, or it writes into the state dir
	// while the test's TempDir is being removed ("directory not empty", a flaky CI failure)
	waitFor(t, "env job finished", func() bool { j := r.ops.jobView("s1"); return j != nil && j["finishedAt"] != nil })
	// …and the resume it set off (its own goroutine under the session's lifecycle lock): take that lock and keep it,
	// so nothing writes after the test
	waitFor(t, "session idle", func() bool { _, err := r.lock("s1", "test-end"); return err == nil })
}

func TestEnvPatchRefusesSecrets(t *testing.T) {
	for _, k := range []string{"GITHUB_TOKEN", "OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD", "IPROYAL_API", "MY_KEY",
		"SESSION_PROMPT", "JARVIS2_ROLLBACK", "CLAUDE_CREDENTIALS", "PATH", "LD_PRELOAD", "CF_ACCESS_CLIENT_ID", "1BAD", "STRIPE_AUTH"} {
		if envKeyAllowed(k) == nil {
			t.Errorf("%s allowed", k)
		}
	}
	for _, k := range []string{"FEATURE_FLAG", "DEBUG", "GIT_AUTHOR_NAME", "NODE_ENV", "TZ", "KEYBOARD_LAYOUT"} {
		if err := envKeyAllowed(k); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	if _, err := normalizeEnvPatch(map[string]any{"X": map[string]any{}}); err == nil {
		t.Error("an object value was accepted")
	}
	rg, _ := newOpsRig(t)
	if code, out := appDo(t, rg.r, "POST", "/api/sessions/s1/restart", `{"env":{"API_TOKEN":"x"}}`); code != 400 || !strings.Contains(out["error"].(string), "secret") {
		t.Fatalf("%d %v", code, out)
	}
}

func TestResumeWithSizeAndModel(t *testing.T) {
	rg, sc := newOpsRig(t)
	r := rg.r
	if code, _ := appDo(t, r, "POST", "/api/sessions/s1/resume", `{"size":"huge"}`); code != 400 {
		t.Fatal("a bad size was accepted")
	}
	if code, _ := appDo(t, r, "POST", "/api/sessions/s1/resume", `{"model":"gpt-9"}`); code != 400 {
		t.Fatal("an unknown model was accepted")
	}
	code, out := appDo(t, r, "POST", "/api/sessions/s1/resume", `{"size":"small","model":"claude-fable-5-1"}`)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	waitFor(t, "start asked", func() bool { return sc.lastStart() != nil })
	st := sc.lastStart()
	var s0 Session
	r.st.Do(func(d *persisted) { s0 = *d.Sessions["s1"] })
	if _, has := st["env"]; st["size"] != "small" || has || r.machineEnv(&s0)["SESSION_MODEL"] != "claude-fable-5-1" {
		t.Fatalf("%v", st)
	}
	// the core saw a plain dead-machine resume (size and model aren't in its options)
	found := false
	for _, c := range sc.calls {
		found = found || c == "/approve/by-dead-machine"
	}
	if !found {
		t.Fatalf("calls %v", sc.calls)
	}
}

func TestIdempotentCreateAndAttachments(t *testing.T) {
	rg, _ := newOpsRig(t)
	r := rg.r
	// stage two files
	for _, f := range []struct{ name, body string }{{"my photo.png", "PNG"}, {"notes.txt", "text"}} {
		code, out := appDo(t, r, "POST", "/api/uploads", f.body, "x-upload-id", "up1", "x-upload-name", f.name)
		if code != 200 {
			t.Fatalf("%d %v", code, out)
		}
	}
	if code, _ := appDo(t, r, "POST", "/api/uploads", "x", "x-upload-id", "../bad"); code != 400 {
		t.Fatal("a bad upload id was accepted")
	}
	req := `{"requestId":"req-1","label":"x","harness":"claude","apiProxy":true,
		"attachments":{"uploadId":"up1","files":[{"name":"my photo.png"},{"name":"notes.txt"}]}}`
	code, out := appDo(t, r, "POST", "/api/sessions", req)
	if code != 200 || out["id"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	id := out["id"].(string)
	code, out = appDo(t, r, "POST", "/api/sessions", req)
	if code != 200 || out["id"] != id {
		t.Fatalf("a repeat made another session: %d %v", code, out)
	}
	n := 0
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if s.RequestID == "req-1" {
				n++
			}
		}
	})
	if n != 1 {
		t.Fatalf("%d sessions for one requestId", n)
	}
	waitFor(t, "approval", func() bool {
		var ok bool
		r.st.Do(func(d *persisted) {
			for _, a := range d.Approvals {
				ok = ok || (a.Session == id && a.Options["attachments"] == "2 file(s)" && a.Options["apiProxy"] == "on")
			}
		})
		return ok
	})
	// another session can't take the same upload
	if code, out := appDo(t, r, "POST", "/api/sessions", `{"requestId":"req-2","attachments":{"uploadId":"up1","files":[{"name":"notes.txt"}]}}`); code != 400 {
		t.Fatalf("%d %v", code, out)
	}
	// the first machine's env names them
	var s Session
	r.st.Do(func(d *persisted) { s = *d.Sessions[id] })
	e := r.machineEnv(&s)
	if e["SESSION_ATTACHMENTS_JSON"] != `[{"name":"my_photo.png","isImage":true},{"name":"notes.txt","isImage":false}]` || e["SESSION_API_PROXY"] != "1" {
		t.Fatalf("%v", e)
	}
	// the session's machine fetches them; another machine can't
	r.st.Do(func(d *persisted) {
		d.Sessions[id].MachineID, d.Sessions[id].State = "mX", "initialising"
		d.Machines["mX"] = id
	})
	mx, my := newTestMachine(r, "mX"), newTestMachine(r, "mY")
	h := r.MachineHandler()
	if code, out := mx.do(t, h, "GET", "/m/attachments", ""); code != 200 || len(out["files"].([]any)) != 2 {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := my.do(t, h, "GET", "/m/attachments", ""); code != 404 {
		t.Fatalf("another machine: %d", code)
	}
	rq := httptest.NewRequest("GET", "/m/attachments/my_photo.png", nil)
	w := mxRaw(t, mx, h, rq)
	if w.Code != 200 || w.Body.String() != "PNG" {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}
	if code, _ := mx.do(t, h, "GET", "/m/attachments/other.txt", ""); code != 404 {
		t.Fatal(code)
	}
	if code, _ := mx.do(t, h, "DELETE", "/m/attachments", ""); code != 200 {
		t.Fatal(code)
	}
	if keys, _ := r.objects.List(context.Background(), "uploads/up1/"); len(keys) != 0 {
		t.Fatal("the staged files are still there")
	}
	// once certified (a resume), no attachment env
	s.Cert = &Doc{Payload: "{}"}
	if _, ok := r.machineEnv(&s)["SESSION_ATTACHMENTS_JSON"]; ok {
		t.Fatal("attachments on a later start")
	}
}

// mxRaw: a signed request as testMachine.do signs it, the raw response kept
func mxRaw(t *testing.T, m testMachine, h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256(nil)
	sig, _ := signP256(m.key, []byte(req.Method+" "+req.URL.Path+" "+ts+" "+hex.EncodeToString(sum[:])))
	req.Header.Set("X-Machine", m.id)
	req.Header.Set("X-Time", ts)
	req.Header.Set("X-Sig", sig)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestSweepUploads(t *testing.T) {
	r := newTestRouter(t)
	r.StageUpload("old", "", "a.txt", strings.NewReader("a"))
	r.StageUpload("new", "", "b.txt", strings.NewReader("b"))
	r.StageUpload("orphan", "", "c.txt", strings.NewReader("c"))
	r.st.Do(func(d *persisted) {
		d.Uploads["old"].Created = time.Now().Add(-25 * time.Hour)
		d.Uploads["orphan"].Session = "sGone"
	})
	r.sweepUploads(time.Now())
	r.st.Do(func(d *persisted) {
		if d.Uploads["old"] != nil || d.Uploads["orphan"] != nil || d.Uploads["new"] == nil {
			t.Fatalf("%v", d.Uploads)
		}
	})
	if _, err := r.StageUpload("big", "", "x.bin", io.LimitReader(zeros{}, attachMaxBytes+10)); err == nil {
		t.Fatal("an oversize file was accepted")
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { return len(p), nil }

func TestReposAndGitHub(t *testing.T) {
	r := newTestRouter(t)
	// a stand-in core: the begin is relayed as asked; a finish answers what the core signs
	var begun map[string]any
	answer := `{"kind":"deploy-key-added","repo":"DE0CH/jarvis2","store":"github-jarvis2","sensitive":true,"fingerprint":"SHA256:abc"}`
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		switch req.URL.Path {
		case "/deploy-keys/begin":
			json.Unmarshal(b, &begun)
			w.Write([]byte(`{"payload":"{\"kind\":\"deploy-key-begin\"}","sig":"s"}`))
		case "/deploy-keys/finish":
			p, _ := json.Marshal(answer)
			w.Write([]byte(`{"payload":` + string(p) + `,"sig":"s"}`))
		default:
			http.NotFound(w, req)
		}
	}))
	defer core.Close()
	r.core = &CoreClient{base: core.URL, http: http.DefaultClient}
	if code, _ := appDo(t, r, "POST", "/api/repos/key/begin", `{"action":"add","repo":"https://github.com/DE0CH/jarvis2.git"}`); code != 200 || begun["repo"] != "DE0CH/jarvis2" || begun["action"] != "add" {
		t.Fatal(code, begun)
	}
	for _, b := range []string{`{"action":"add","repo":"gitlab.com/x/y"}`, `{"action":"rotate","repo":"DE0CH/x"}`, `{"action":"add","repo":"DE0CH/.."}`} {
		if code, _ := appDo(t, r, "POST", "/api/repos/key/begin", b); code != 400 {
			t.Fatal("accepted", b)
		}
	}
	// the list follows the core's answer only
	if _, out := appDo(t, r, "GET", "/api/repos", ""); len(out["repos"].([]any)) != 0 {
		t.Fatal("a begin added to the list")
	}
	if code, _ := appDo(t, r, "POST", "/api/repos/key/finish", `{"pending":"p"}`); code != 200 {
		t.Fatal(code)
	}
	_, out := appDo(t, r, "GET", "/api/state", "")
	rs := out["repos"].([]any)
	if len(rs) != 1 || rs[0].(map[string]any)["name"] != "jarvis2" || rs[0].(map[string]any)["store"] != "github-jarvis2" ||
		rs[0].(map[string]any)["sensitive"] != true || rs[0].(map[string]any)["url"] != "https://github.com/DE0CH/jarvis2.git" {
		t.Fatalf("%v", rs)
	}
	answer = `{"kind":"deploy-key-removed","repo":"DE0CH/jarvis2","store":"github-jarvis2"}`
	appDo(t, r, "POST", "/api/repos/key/finish", `{"pending":"p"}`)
	if _, out := appDo(t, r, "GET", "/api/repos", ""); len(out["repos"].([]any)) != 0 {
		t.Fatalf("%v", out)
	}
	// a core from before deploy keys: a plain sentence
	r.core = &CoreClient{base: httptest.NewServer(http.NotFoundHandler()).URL, http: http.DefaultClient}
	if code, out := appDo(t, r, "POST", "/api/repos/key/begin", `{"action":"add","repo":"DE0CH/x"}`); code != 501 || !strings.Contains(out["error"].(string), "predates") {
		t.Fatal(code, out)
	}
	// entries that aren't GitHub repos (an older list) are left off
	r.st.WriteDoc("repos.json", []byte(`[{"name":"a","url":"https://gitlab.com/x/a.git"},{"name":"b","url":"https://github.com/DE0CH/b.git"}]`))
	if rs := r.Repos(); len(rs) != 1 || rs[0].Repo != "DE0CH/b" || rs[0].Store != "github-b" {
		t.Fatalf("%+v", rs)
	}
	// the same store names as the core's RepoStore (core/deploykeys_test.go)
	for in, want := range map[string]string{"DE0CH/claude-env": "github-claude-env", "DE0CH/china_train": "github-china-train",
		"de0ch/Jarvis2": "github-jarvis2", "someone/Thing.js": "github-someone-thing-js"} {
		if got := repoStore(in); got != want {
			t.Errorf("repoStore(%s) = %s, want %s", in, got, want)
		}
	}

	t.Setenv("GITHUB_READ_TOKEN", "")
	if code, out := appDo(t, r, "GET", "/api/github/repos", ""); code != 503 || out["configured"] != false {
		t.Fatalf("%d %v", code, out)
	}
	var auth string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		auth = req.Header.Get("Authorization")
		w.Write([]byte(`[{"full_name":"DE0CH/jarvis2","clone_url":"https://github.com/DE0CH/jarvis2.git","private":false,"pushed_at":"2026-10-09T00:00:00Z","owner":{"login":"DE0CH"}}]`))
	}))
	defer gh.Close()
	old := githubAPI
	githubAPI = gh.URL
	defer func() { githubAPI = old }()
	t.Setenv("GITHUB_READ_TOKEN", "read-only")
	code, out := appDo(t, r, "GET", "/api/github/repos", "")
	if code != 200 || auth != "Bearer read-only" || out["repos"].([]any)[0].(map[string]any)["fullName"] != "DE0CH/jarvis2" {
		t.Fatalf("%d %v %q", code, out, auth)
	}
	if strings.Contains(strings.ToLower(jsonString(out)), "read-only") {
		t.Fatal("the token leaked into the answer")
	}
}

func jsonString(v any) string { b, _ := json.Marshal(v); return string(b) }

// addGrant: a stored grant as if the phone had signed it (the machine's checks are tested in machine/)
func addGrant(r *Router, session, holder, kind string) {
	r.st.Do(func(d *persisted) {
		id := randID()
		d.Grants[id] = &StoredGrant{ID: id, Session: session, Holder: holder, Kind: kind, Ends: time.Now().Add(5 * time.Minute), Doc: &Doc{Payload: "{}"}}
	})
}

// TestWebRequestTakesSensitiveStores: the web page proposes any store, sensitive ones included (Deyao, 2026-10-13;
// docs/DECISIONS.md 164): the request becomes an approval holding them, filed as the web's, for the phone to review;
// the core's own store and the deploy-key token's store are still refused.
func TestWebRequestTakesSensitiveStores(t *testing.T) {
	rg, _ := newOpsRig(t)
	r := rg.r
	code, out := appDo(t, r, "POST", "/api/sessions", `{"requestId":"web-sens","harness":"claude","stores":["default","identity","github-jarvis2"]}`)
	if code != 200 || out["id"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	id := out["id"].(string)
	waitFor(t, "approval", func() bool {
		var ok bool
		r.st.Do(func(d *persisted) {
			for _, a := range d.Approvals {
				ok = ok || (a.Session == id && a.Kind == "new-session" && a.Origin != nil && a.Origin.Caller.Kind == "web")
			}
		})
		return ok
	})
	r.st.Do(func(d *persisted) {
		s := d.Sessions[id]
		if s == nil || !containsString(s.Stores, "identity") || !containsString(s.Stores, "github-jarvis2") {
			t.Fatalf("the sensitive stores didn't reach the request: %+v", s)
		}
	})
	for _, bad := range []string{flyStore, deployKeyTokenStore} {
		if code, out := appDo(t, r, "POST", "/api/sessions", `{"requestId":"web-`+bad+`","harness":"claude","stores":["`+bad+`"]}`); code == 200 {
			t.Fatalf("store %s was accepted: %v", bad, out)
		}
	}
}

// phoneSession: a running session whose cert names a phone key, so AddGrant takes what that key signs
func phoneSession(t *testing.T, r *Router, id, machine string) func(holder, kind string) {
	t.Helper()
	phone, _ := ecdh.P256().GenerateKey(rand.Reader)
	cert, _ := json.Marshal(map[string]any{"line": "L" + id, "phone": base64.StdEncoding.EncodeToString(phone.PublicKey().Bytes())})
	r.st.Do(func(d *persisted) {
		d.Sessions[id] = &Session{ID: id, State: "started", MachineID: machine, Label: "label " + id, Harness: "claude", PermissionMode: "auto", Cert: &Doc{Payload: string(cert)}}
		d.Machines[machine] = id
	})
	return func(holder, kind string) {
		t.Helper()
		pub, err := r.HolderPublicKeys()
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		g := map[string]any{"kind": kind, "holder": pub[holder], "session": "L" + id, "scope": "shell", "issued": now.Format(time.RFC3339)}
		if kind == "grant" {
			g["expires"] = now.Add(10 * time.Minute).Format(time.RFC3339)
		} else {
			g["until"] = now.Add(24 * time.Hour).Format(time.RFC3339)
		}
		text, _ := json.Marshal(g)
		sig, _ := signP256(phone, text)
		if _, err := r.AddGrant(id, &Doc{Payload: string(text), Sig: sig}); err != nil {
			t.Fatal(err)
		}
	}
}

// The web page's "Switch to bypass mode" (Deyao, 2026-10-20: it showed "this needs a fresh phone grant" instead of
// asking): the router files the terminal grant in the Inbox as the web's request and switches once the phone signs it.
// The iPhone app still gets the 403 and opens its own grant review.
func TestBypassFromTheWebWaitsInTheInbox(t *testing.T) {
	r := newTestRouter(t)
	sign := phoneSession(t, r, "sW", "mW")
	stop := make(chan struct{})
	defer close(stop)
	cmds := answerExecs(r, "mW", 0, stop)

	if code, out := inboxDo(t, r, "POST", "/api/sessions/sW/permission-mode", `{"mode":"bypass"}`, true); code != 403 || out["needsGrant"] != "terminal" {
		t.Fatalf("the app: %d %v", code, out)
	}
	if len(r.Inbox()) != 0 {
		t.Fatal("the app's 403 filed a request")
	}
	code, out := appDo(t, r, "POST", "/api/sessions/sW/permission-mode", `{"mode":"bypass"}`)
	if code != 202 || out["waiting"] != "inbox" || out["needsGrant"] != "terminal" || out["inboxId"] == nil {
		t.Fatalf("the web: %d %v", code, out)
	}
	qid := out["inboxId"].(string)
	it, ok := r.InboxItem(qid)
	if !ok || it.Kind != requestKindGrant || it.Params.Holder != "terminal" || it.Params.Minutes != 10 || it.Caller.Kind != "web" ||
		it.Call.Path != "/api/sessions/sW/permission-mode" || it.Call.Args["mode"] != "bypass" || it.Open["kind"] != "grant" {
		t.Fatalf("%+v", it)
	}
	// who and what asked, never "Jarvis 4" itself (Deyao, 2026-10-20)
	if it.CallerText != "Deyao, from the web page" || it.SessionName != "label sW" ||
		!strings.HasPrefix(it.Explanation, "Switch session “label sW” (sW) to bypass permission mode") || strings.Contains(it.CallerText, "Jarvis 4") {
		t.Fatalf("named as %q: %q", it.CallerText, it.Explanation)
	}
	if code, out := appDo(t, r, "POST", "/api/sessions/sW/permission-mode", `{"mode":"bypass"}`); code != 202 || out["inboxId"] != qid || out["duplicate"] != true {
		t.Fatalf("again: %d %v", code, out)
	}
	r.core = &CoreClient{base: "http://127.0.0.1:1", http: http.DefaultClient}
	_, st := appDo(t, r, "GET", "/api/state", "")
	var view map[string]any
	for _, x := range st["sessions"].([]any) {
		if v := x.(map[string]any); v["id"] == "sW" {
			view = v
		}
	}
	if mg, _ := view["modeAfterGrant"].(map[string]any); mg == nil || mg["mode"] != "bypass" || mg["inbox"] != qid {
		t.Fatalf("the state doesn't show the waiting switch: %v", view["modeAfterGrant"])
	}

	// signed: the request is answered and the switch runs under the grant
	sign("terminal", "grant")
	if _, still := r.InboxItem(qid); still {
		t.Fatal("the grant request stayed in the Inbox")
	}
	waitFor(t, "mode switched", func() bool {
		var m string
		r.st.Do(func(d *persisted) { m = d.Sessions["sW"].PermissionMode })
		return m == "bypass"
	})
	waitFor(t, "job done", func() bool { j := r.ops.jobView("sW"); return j != nil && j["phase"] == "done" })
	if len(*cmds) != 1 || (*cmds)[0] != "/usr/local/bin/set-permission-mode bypass" {
		t.Fatalf("%v", *cmds)
	}
	r.st.Do(func(d *persisted) {
		if d.Sessions["sW"].Ops.ModeAfterGrant != nil {
			t.Fatal("the switch stayed waiting")
		}
	})
}

// a standing rule answers the request but doesn't allow bypass: nothing switches, and the waiting switch goes
func TestBypassRequestAnsweredByARule(t *testing.T) {
	r := newTestRouter(t)
	sign := phoneSession(t, r, "sW", "mW")
	stop := make(chan struct{})
	defer close(stop)
	cmds := answerExecs(r, "mW", 0, stop)
	if code, out := appDo(t, r, "POST", "/api/sessions/sW/permission-mode", `{"mode":"bypass"}`); code != 202 || out["waiting"] != "inbox" {
		t.Fatalf("%d %v", code, out)
	}
	sign("terminal", "rule")
	time.Sleep(100 * time.Millisecond)
	r.st.Do(func(d *persisted) {
		s := d.Sessions["sW"]
		if s.PermissionMode != "auto" || s.Ops.ModeAfterGrant != nil {
			t.Fatalf("%s %+v", s.PermissionMode, s.Ops.ModeAfterGrant)
		}
	})
	if len(*cmds) != 0 {
		t.Fatalf("%v", *cmds)
	}
}

// the same switch asked for by a session's actions as an API call (how it was reproduced, 2026-10-20): the approved
// call answers 202 and its review sheet follows the grant it filed
func TestBypassAsAnAPICallFollowsItsGrant(t *testing.T) {
	r := newTestRouter(t)
	r.cfg.NoAccess = true
	phoneSession(t, r, "sW", "mW")
	addSession(r, "sR", "started", "mR", false)
	m, mh := newTestMachine(r, "mR"), r.MachineHandler()
	code, out := m.do(t, mh, "POST", "/m/api/actions/requests/call", `{"method": "POST", "path": "/api/sessions/sW/permission-mode", "body": {"mode": "bypass"}, "explanation": "bypass for the build"}`)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	id := out["id"].(string)
	if code, out := inboxDo(t, r, "POST", "/api/requests/"+id+"/approve", "", true); code != 200 || out["status"] != float64(202) {
		t.Fatalf("approve: %d %v", code, out)
	}
	f, ok := r.CallFollowupsOf(id)
	if !ok || len(f.Followups) != 1 || !f.Followups[0].Open || f.Followups[0].Item.Kind != requestKindGrant || f.Followups[0].Item.Caller.Kind != "actions" {
		t.Fatalf("%+v", f)
	}
	if g := f.Followups[0].Item; g.CallerText != "the actions of session “label sR” (sR)" || !strings.HasPrefix(g.Explanation, "Switch session “label sW” (sW) to bypass") {
		t.Fatalf("named as %q: %q", g.CallerText, g.Explanation)
	}
}
