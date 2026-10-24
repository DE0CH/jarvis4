package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// keeperStandIn (from TestMain): the test binary stands in for jarvis-machine when the keeper's code re-runs
// /proc/self/exe (unprotected, signal-session) and for the probes of the root tests below
func keeperStandIn() {
	if u := os.Getenv("JARVIS_TEST_SESSION_USER"); u != "" {
		sessionUser = u
	}
	if g, r, ok := strings.Cut(os.Getenv("JARVIS_TEST_CGROUPS"), ","); ok { // oomguard_test.go
		sessionCgroup, rescueCgroup = g, r
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "unprotected":
			if err := unprotected(os.Args[2:]); err != nil {
				os.Stderr.WriteString(err.Error() + "\n")
				os.Exit(1)
			}
		case "signal-session":
			if err := signalSessionCmd(os.Args[2:]); err != nil {
				os.Stderr.WriteString(err.Error() + "\n")
				os.Exit(1)
			}
			os.Exit(0)
		case "fsuid-probe": // the worker's identity: root's uid, the session user's file access
			if err := sessionFileAccess(); err != nil {
				os.Stderr.WriteString(err.Error() + "\n")
				os.Exit(1)
			}
			if err := os.WriteFile(os.Args[2], []byte("x"), 0o600); err != nil {
				os.Stderr.WriteString(err.Error() + "\n")
				os.Exit(1)
			}
			time.Sleep(time.Hour)
		}
	}
}

// the harness's env: the clean env, the secrets over it, the fallback only where nothing set it, the cert's fixed
// values over everything; never a secret with a bad name
func TestHarnessSpecEnv(t *testing.T) {
	spec := harnessSpec{
		Clean:    []string{"PATH=/bin", "LANG=C", "HOME=/home/claude"},
		Fixed:    map[string]string{"SESSION_ID": "s1", "LANG": "fixed"},
		Fallback: map[string]string{"CLAUDE_ACCOUNT": "router", "OTHER": "fb"},
	}
	m := envMap(spec.env(map[string]string{"API_KEY": "v", "CLAUDE_ACCOUNT": "store", "PATH": "/secret", "bad name": "x", "SESSION_ID": "no"}))
	want := map[string]string{"PATH": "/secret", "LANG": "fixed", "HOME": "/home/claude", "API_KEY": "v", "CLAUDE_ACCOUNT": "store", "OTHER": "fb", "SESSION_ID": "s1"}
	if len(m) != len(want) {
		t.Fatalf("env %v", m)
	}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("%s = %q, want %q (%v)", k, m[k], v, m)
		}
	}
	if m := envMap(spec.env(nil)); m["CLAUDE_ACCOUNT"] != "router" || m["API_KEY"] != "" {
		t.Fatalf("no secrets: %v", m)
	}
}

// boot-env: the keeper (root, the worker's parent) at any time; the boot steps (harness.pid) only before booted;
// nobody else
func TestBootEnvForTheKeeper(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // held.set rewrites the deploy keys under $HOME
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "gitconfig"))
	held.set(map[string]string{"API_KEY": "v1"})
	defer held.set(map[string]string{})
	oldPID, oldBooted := harnessPIDPath, booted
	defer func() { harnessPIDPath, booted = oldPID, oldBooted }()
	harnessPIDPath = filepath.Join(t.TempDir(), "harness.pid")
	os.WriteFile(harnessPIDPath, []byte("4242"), 0o644)
	booted = func() bool { return true }
	keeper := keeperPID()
	if r := answerSecrets(nil, secretsReq{Op: "boot-env"}, keeper, 0, "keeper"); !r.OK || r.Secrets["API_KEY"] != "v1" {
		t.Fatalf("the keeper after booted: %+v", r)
	}
	if r := answerSecrets(nil, secretsReq{Op: "boot-env"}, keeper, 1001, "same pid, not root"); r.OK {
		t.Fatalf("a non-root caller with the keeper's pid: %+v", r)
	}
	if r := answerSecrets(nil, secretsReq{Op: "boot-env"}, 4242, 1001, "the launcher"); r.OK {
		t.Fatalf("the harness's launcher after booted: %+v", r)
	}
	booted = func() bool { return false }
	if r := answerSecrets(nil, secretsReq{Op: "boot-env"}, 4242, 1001, "the boot steps"); !r.OK {
		t.Fatalf("the boot steps before booted: %+v", r)
	}
	if r := answerSecrets(nil, secretsReq{Op: "boot-env"}, 4243, 0, "another root process"); r.OK {
		t.Fatalf("a root process that isn't the keeper: %+v", r)
	}
}

func TestExitHow(t *testing.T) {
	c := exec.Command("sh", "-c", "kill -TERM $$")
	err := c.Run()
	if got := exitHow(err, c.ProcessState); got != "killed by SIGTERM" {
		t.Fatalf("got %q", got)
	}
	c = exec.Command("sh", "-c", "exit 3")
	err = c.Run()
	if got := exitHow(err, c.ProcessState); got != "exit status 3" {
		t.Fatalf("got %q", got)
	}
}

// keeperRig: a harness that records each start (its JARVIS_HARNESS_START and pid) and ends the way the test says
func keeperRig(t *testing.T, script string) (k *keeperT, starts func() []string, done chan struct{}) {
	t.Helper()
	d := t.TempDir()
	if os.Geteuid() == 0 { // the harness runs as the session user: it writes here
		os.Chmod(filepath.Dir(d), 0o755)
		os.Chmod(d, 0o777)
	}
	rec := filepath.Join(d, "starts")
	entry := filepath.Join(d, "entry.sh")
	os.WriteFile(entry, []byte("#!/bin/sh\necho \"$JARVIS_HARNESS_START $$ $API_KEY\" >> "+rec+"\n"+script+"\n"), 0o755)
	oldE, oldB, oldS := baseEntry, harnessBackoff0, finalSnapshotSig
	oldSt := harnessStatePath
	t.Cleanup(func() { baseEntry, harnessBackoff0, finalSnapshotSig, harnessStatePath = oldE, oldB, oldS, oldSt })
	baseEntry, harnessBackoff0, finalSnapshotSig = entry, 20*time.Millisecond, filepath.Join(d, "final.sig")
	harnessStatePath = filepath.Join(d, "harness.json")
	k = newKeeper()
	k.secretsFn = func() map[string]string { return map[string]string{"API_KEY": "held-now"} }
	t.Cleanup(func() { // a loop never outlives its test
		k.mu.Lock()
		if !k.stopping {
			k.stopping = true
			close(k.stopCh)
		}
		k.mu.Unlock()
	})
	done = make(chan struct{})
	go func() {
		k.harnessLoop(harnessSpec{Clean: []string{"PATH=" + os.Getenv("PATH"), "JARVIS_TEST_SESSION_USER=" + os.Getenv("JARVIS_TEST_SESSION_USER")}, Fixed: map[string]string{}})
		close(done)
	}()
	starts = func() []string {
		b, _ := os.ReadFile(rec)
		return strings.Fields(strings.ReplaceAll(strings.TrimSpace(string(b)), "\n", " | "))
	}
	return k, starts, done
}

func waitFor(t *testing.T, what string, d time.Duration, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// a harness killed by SIGTERM (2026-10-21: a subagent's `xargs kill` hit the launcher) is started again with the
// secrets held now and its start number; the keeper itself carries on; a stop ends the loop
func TestTheKeeperRestartsAKilledHarness(t *testing.T) {
	k, starts, done := keeperRig(t, "kill -TERM $$")
	waitFor(t, "three starts", 5*time.Second, func() bool { return strings.Count(strings.Join(starts(), " "), "|") >= 2 })
	got := strings.Join(starts(), " ")
	if !strings.HasPrefix(got, "1 ") || !strings.Contains(got, "| 2 ") || !strings.Contains(got, "| 3 ") || !strings.Contains(got, "held-now") {
		t.Fatalf("starts %q", got)
	}
	k.mu.Lock()
	k.stopping = true
	close(k.stopCh)
	k.mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the harness loop didn't end on stop")
	}
	k.mu.Lock()
	s := k.state
	k.mu.Unlock()
	if s.LastExit != "killed by SIGTERM" || s.Starts < 3 || s.Running {
		t.Fatalf("state %+v", s)
	}
}

// once the session is stopped for its final snapshot, a harness that ends isn't started again
func TestNoRestartAfterTheFinalSnapshot(t *testing.T) {
	_, starts, done := keeperRig(t, "exit 1")
	os.WriteFile(finalSnapshotSig, []byte("sig"), 0o600)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("restarted after the final snapshot")
	}
	if n := len(strings.Split(strings.Join(starts(), " "), "|")); n != 1 {
		t.Fatalf("%d starts", n)
	}
}

// what is left of a dead launcher's process group (its loops) is ended before the next start
func TestTheDeadHarnessGroupIsCleared(t *testing.T) {
	d := t.TempDir()
	pidf := filepath.Join(d, "child")
	k, starts, _ := keeperRig(t, "sleep 300 & echo $! > "+pidf+"\nkill -TERM $$")
	defer func() {
		k.mu.Lock()
		if !k.stopping {
			k.stopping = true
			close(k.stopCh)
		}
		k.mu.Unlock()
	}()
	waitFor(t, "a second start", 5*time.Second, func() bool { return strings.Contains(strings.Join(starts(), " "), "| 2 ") })
	b, _ := os.ReadFile(pidf)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if pid <= 1 {
		t.Fatalf("no child pid: %q", b)
	}
	waitFor(t, "the old group's child gone", 8*time.Second, func() bool { return syscall.Kill(pid, 0) != nil })
}

// the teardown: the transcripts that changed go first (newest first, subagents after), then the final snapshot,
// whose stream carries the transcripts and ~/.claude.json before the workspace and the artifacts. A short window
// (the router cuts the stream off, as Fly's kill would) still leaves the router the transcript tail.
func TestTheTeardownSendsTheTranscriptTailFirst(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	oldCH, oldBooted := claudeHome, booted
	defer func() { claudeHome, booted = oldCH, oldBooted }()
	claudeHome, booted = home, func() bool { return true }
	key := newKey()
	defer snapTestState(t, key)()
	live = nil
	liveOnce = sync.Once{}
	defer func() { live = nil; liveOnce = sync.Once{} }()

	proj := filepath.Join(home, ".claude", "projects", "-home-claude-workspace")
	os.MkdirAll(filepath.Join(proj, "conv1", "subagents"), 0o755)
	os.WriteFile(filepath.Join(proj, "old.jsonl"), []byte(`{"type":"user"}`+"\n"), 0o600)
	os.WriteFile(filepath.Join(proj, "conv1.jsonl"), []byte(`{"type":"assistant","tail":"the latest turn"}`+"\n"), 0o600)
	os.WriteFile(filepath.Join(proj, "conv1", "subagents", "agent-a1.jsonl"), []byte(`{"type":"user"}`+"\n"), 0o600)
	past := time.Now().Add(-time.Hour)
	os.Chtimes(filepath.Join(proj, "old.jsonl"), past, past)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{}`), 0o600)
	os.MkdirAll(filepath.Join(home, "workspace"), 0o755)
	big := make([]byte, 4<<20) // incompressible: the cut-off falls inside it
	rand.Read(big)
	os.WriteFile(filepath.Join(home, "workspace", "big"), big, 0o644)
	os.MkdirAll(filepath.Join(home, "artifacts"), 0o755)
	os.WriteFile(filepath.Join(home, "artifacts", "a"), []byte("a"), 0o644)

	var mu sync.Mutex
	var events []string
	var entries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/m/live-transcript":
			b, _ := io.ReadAll(req.Body)
			mu.Lock()
			events = append(events, "live "+req.Header.Get("X-Name"))
			if req.Header.Get("X-Name") == "conv1.jsonl" && !strings.Contains(string(b), "the latest turn") {
				events = append(events, "WRONG BODY")
			}
			mu.Unlock()
			w.Write([]byte(`{"ok":true}`))
		case "/m/snapshot-stream":
			mu.Lock()
			events = append(events, "snapshot")
			mu.Unlock()
			// the window closes partway: read what came, list the tar entries, then cut the connection
			gz, err := gzip.NewReader(io.LimitReader(req.Body, 64<<10))
			if err == nil {
				tr := tar.NewReader(gz)
				for {
					h, err := tr.Next()
					if err != nil {
						break
					}
					mu.Lock()
					entries = append(entries, h.Name)
					mu.Unlock()
				}
			}
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			conn.Close()
		default:
			w.WriteHeader(200)
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()
	c := &client{base: srv.URL, me: "m1", sig: key.k, http: srv.Client()}
	teardown(c)

	mu.Lock()
	defer mu.Unlock()
	got := strings.Join(events, ", ")
	if got != "live conv1.jsonl, live old.jsonl, live agent-a1.jsonl, snapshot" {
		t.Fatalf("order: %s", got)
	}
	// the stream: the conversations and ~/.claude.json come before the workspace and the artifacts
	first := map[string]int{}
	for i, e := range entries {
		top := strings.SplitN(e, "/", 2)[0]
		if e == ".claude.json" {
			top = e
		}
		if _, ok := first[top]; !ok {
			first[top] = i
		}
	}
	if len(entries) == 0 || !strings.HasPrefix(entries[0], ".claude/projects") {
		t.Fatalf("the stream doesn't start with the transcripts: %v", entries)
	}
	if w, ok := first["workspace"]; ok && w < first[".claude.json"] {
		t.Fatalf("the workspace before ~/.claude.json: %v", entries)
	}
	if _, ok := first["artifacts"]; ok {
		t.Fatalf("the artifacts reached the router before the cut-off workspace: %v", entries)
	}
	if committed {
		t.Fatal("a cut-off stream was committed")
	}
}

// a machine whose final snapshot the router already has (a pause: snapshot, then the core's stop) uploads nothing more
func TestTheTeardownAfterAPauseUploadsNothing(t *testing.T) {
	key := newKey()
	defer snapTestState(t, key)()
	committed = true
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/m/supervisor-log" {
			n++
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	teardown(&client{base: srv.URL, me: "m1", sig: key.k, http: srv.Client()})
	if n != 0 {
		t.Fatalf("%d uploads after a committed snapshot", n)
	}
}

// every command the supervisor runs for the session goes through sessionCommand (as root: user claude); only the
// keeper's own starts and sudo run otherwise
func TestEveryCommandGoesThroughSessionCommand(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	allowed := map[string]int{"keeper.go": 6, "main.go": 2, "volume.go": 1}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		n := strings.Count(string(b), "exec.Command(") + strings.Count(string(b), "exec.CommandContext(")
		if n > allowed[f] {
			t.Errorf("%s: %d direct exec.Command calls (allowed %d): use sessionCommand", f, n, allowed[f])
		}
	}
}

// ---- as root, with a real second user (the uid split) -------------------------------------------------------------
//
// sudo env JARVIS_TEST_SESSION_USER=<a throwaway user> go test -run AsRoot   (the user must not be the one running
// anything else: kill -TERM -1 as that user ends all of its processes)

func rootRig(t *testing.T) string {
	t.Helper()
	u := os.Getenv("JARVIS_TEST_SESSION_USER")
	if os.Geteuid() != 0 || u == "" {
		t.Skip("needs root and JARVIS_TEST_SESSION_USER")
	}
	old := sessionUser
	sessionUser, sessionOnce = u, sync.Once{}
	t.Cleanup(func() { sessionUser, sessionOnce = old, sync.Once{} })
	if session().uid == 0 {
		t.Fatalf("no user %s", u)
	}
	return u
}

// asUser: a shell command as the session user (setpriv: no sudo, no new session); its combined output and error
func asUser(u, cmd string) (string, error) {
	out, err := exec.Command("setpriv", "--reuid="+u, "--regid="+u, "--init-groups", "--", "sh", "-c", cmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func procStatusField(pid int, field string) string {
	b, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, field+":"); ok {
			return strings.Fields(v)[0]
		}
	}
	return ""
}

func TestKeeperAsRoot(t *testing.T) {
	u := rootRig(t)
	uid := strconv.Itoa(session().uid)
	os.WriteFile("/proc/self/oom_score_adj", []byte("-1000\n"), 0o644) // the keeper's protection
	defer os.WriteFile("/proc/self/oom_score_adj", []byte("0\n"), 0o644)
	notDumpable()
	me := os.Getpid()

	k, starts, done := keeperRig(t, "exec sleep 300")
	waitFor(t, "the harness", 5*time.Second, func() bool { return len(starts()) > 0 })
	harness := func() int {
		k.mu.Lock()
		defer k.mu.Unlock()
		if k.harness == nil {
			return 0
		}
		return k.harness.Process.Pid
	}
	waitFor(t, "the harness pid", 5*time.Second, func() bool { return harness() > 0 })
	h := harness()
	// the harness: the session user (real, effective, saved), its own session, the default OOM score with its floor
	if got := procStatusField(h, "Uid"); got != uid {
		t.Fatalf("harness uid %s, want %s", got, uid)
	}
	if sid, _, _ := syscall.RawSyscall(syscall.SYS_GETSID, uintptr(h), 0, 0); int(sid) != h {
		t.Fatalf("harness session %d, want its own (%d)", sid, h)
	}
	if b, _ := os.ReadFile("/proc/" + strconv.Itoa(h) + "/oom_score_adj"); strings.TrimSpace(string(b)) != "0" {
		t.Fatalf("harness oom_score_adj %q", b)
	}
	if out, err := asUser(u, "echo -1000 > /proc/"+strconv.Itoa(h)+"/oom_score_adj"); err == nil {
		t.Fatalf("the harness took -1000 back: %s", out)
	}
	pid := strconv.Itoa(me)
	// the session can't touch the keeper: kill, pkill -f, process-group kill, its OOM score, its environ
	for _, c := range []string{"kill -TERM " + pid, "kill -KILL " + pid, "kill -TERM -" + pid, "kill -STOP " + pid,
		"echo 1000 > /proc/" + pid + "/oom_score_adj", "cat /proc/" + pid + "/environ"} {
		if out, err := asUser(u, c); err == nil {
			t.Fatalf("%q as %s worked: %s", c, u, out)
		}
	}
	asUser(u, "pkill -f '"+filepath.Base(os.Args[0])+"'")
	if b, _ := os.ReadFile("/proc/self/oom_score_adj"); strings.TrimSpace(string(b)) != "-1000" {
		t.Fatalf("keeper oom_score_adj %q", b)
	}
	// the incident: a session process SIGTERMs the harness's launcher → the keeper is up, the harness comes back
	if out, err := asUser(u, "kill -TERM "+strconv.Itoa(h)); err != nil {
		t.Fatalf("kill the harness: %v %s", err, out)
	}
	waitFor(t, "the second start", 5*time.Second, func() bool { return strings.Contains(strings.Join(starts(), " "), "| 2 ") })
	// kill -TERM -1 as the session user: every one of its processes, never the keeper; the harness comes back again
	asUser(u, "kill -TERM -1")
	waitFor(t, "the third start", 10*time.Second, func() bool { return strings.Contains(strings.Join(starts(), " "), "| 3 ") })
	if syscall.Kill(me, 0) != nil {
		t.Fatal("the keeper is gone")
	}
	// the teardown (no worker here): the harness's group and the session's processes end, the loop ends
	waitFor(t, "the harness pid", 5*time.Second, func() bool { return harness() > 0 && harness() != h })
	last := harness()
	close(k.workerEnd) // no worker in this rig
	k.teardown(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the harness loop didn't end in the teardown")
	}
	waitFor(t, "the harness gone", 10*time.Second, func() bool { return syscall.Kill(last, 0) != nil })
	if out, _ := exec.Command("pgrep", "-u", u).Output(); len(strings.TrimSpace(string(out))) > 0 {
		t.Fatalf("processes of %s left: %s", u, out)
	}
}

// the worker's identity: root's uid (the session can't signal it or read its memory), the session user's file
// access (what it writes is the session user's)
func TestWorkerIdentityAsRoot(t *testing.T) {
	u := rootRig(t)
	d := t.TempDir()
	os.Chmod(filepath.Dir(d), 0o755)
	os.Chown(d, session().uid, session().gid)
	os.Chmod(d, 0o700) // only the session user (and root with its file capabilities) may write here
	f := filepath.Join(d, "written")
	cmd := exec.Command(os.Args[0], "fsuid-probe", f)
	cmd.Env = append(os.Environ(), "SECRET_PROBE=hunter2hunter2")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	waitFor(t, "the probe's file", 5*time.Second, func() bool { _, err := os.Stat(f); return err == nil })
	var st syscall.Stat_t
	syscall.Stat(f, &st)
	if int(st.Uid) != session().uid || int(st.Gid) != session().gid {
		t.Fatalf("written as %d:%d, want %d:%d", st.Uid, st.Gid, session().uid, session().gid)
	}
	pid := strconv.Itoa(cmd.Process.Pid)
	if got := procStatusField(cmd.Process.Pid, "Uid"); got != "0" {
		t.Fatalf("worker uid %s", got)
	}
	for _, c := range []string{"kill -TERM " + pid, "kill -TERM -" + pid, "kill -TERM -1; sleep 0.2", "cat /proc/" + pid + "/environ", "echo 0 > /proc/" + pid + "/oom_score_adj"} {
		out, err := asUser(u, c)
		if c == "kill -TERM -1; sleep 0.2" {
			if syscall.Kill(cmd.Process.Pid, 0) != nil {
				t.Fatal("kill -TERM -1 as the session user ended the worker")
			}
			continue
		}
		if err == nil || strings.Contains(out, "hunter2") {
			t.Fatalf("%q as %s worked: %s", c, u, out)
		}
	}
}
