package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// pause-harness stops the launcher, the tmux panes and their children (parents first), never the supervisor;
// resume-harness lets the same ones go on, children first
func TestPauseAndResumeTheHarness(t *testing.T) {
	d := t.TempDir()
	oldPID, oldPaused, oldKids, oldPanes, oldSig := harnessPIDPath, harnessPausedPath, children, tmuxPanes, signalProc
	defer func() {
		harnessPIDPath, harnessPausedPath, children, tmuxPanes, signalProc = oldPID, oldPaused, oldKids, oldPanes, oldSig
	}()
	harnessPIDPath, harnessPausedPath = filepath.Join(d, "harness.pid"), filepath.Join(d, "paused")
	os.WriteFile(harnessPIDPath, []byte("100"), 0o644)
	self, keeper := os.Getpid(), os.Getppid()
	children = func() map[int][]int {
		return map[int][]int{100: {keeper, 101}, 101: {102}, 200: {201}, 1: {100, 200}}
	}
	tmuxPanes = func() []int { return []int{200, self} }
	var mu sync.Mutex
	var got []string
	signalProc = func(pid int, sig syscall.Signal) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, sig.String()[:4]+":"+itoa(pid))
		return nil
	}
	if err := pauseHarness(); err != nil {
		t.Fatal(err)
	}
	want := "stop:100 stop:101 stop:102 stop:200 stop:201"
	if strings.Join(got, " ") != want {
		t.Fatalf("stopped %v, want %s", got, want)
	}
	got = nil
	if err := resumeHarness(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "cont:201 cont:200 cont:102 cont:101 cont:100" {
		t.Fatalf("resumed %v", got)
	}
	if resumeHarness() == nil {
		t.Fatal("resumed a harness that isn't paused")
	}
}

// resume-harness is refused while the session is frozen for its final snapshot; an unknown command is ignored
func TestUnguardedCommands(t *testing.T) {
	d := t.TempDir()
	oldPaused, oldSig := harnessPausedPath, signalProc
	defer func() { harnessPausedPath, signalProc = oldPaused, oldSig; frozen.Store(false) }()
	harnessPausedPath = filepath.Join(d, "paused")
	os.WriteFile(harnessPausedPath, []byte("100"), 0o600)
	n := 0
	signalProc = func(int, syscall.Signal) error { n++; return nil }
	frozen.Store(true)
	runCommand(nil, "resume-harness")
	if n != 0 {
		t.Fatal("let the harness go on during the final snapshot")
	}
	frozen.Store(false)
	runCommand(nil, "resume-harness")
	if n != 1 {
		t.Fatal("resume-harness didn't run")
	}
	runCommand(nil, "rm -rf /") // not a command: ignored, nothing runs
}

// not root (a CLI command, the tests): a command runs as it is; as root (the worker) it goes through `unprotected`,
// which takes user claude's identity and the default OOM score
func TestSessionCommand(t *testing.T) {
	old := privileged
	defer func() { privileged = old }()
	privileged = func() bool { return false }
	if c := sessionCommand(nil, "bash", "-c", "true"); filepath.Base(c.Path) != "bash" {
		t.Fatalf("not root: %v", c.Args)
	}
	privileged = func() bool { return true }
	c := sessionCommand(nil, "bash", "-c", "true")
	if c.Path != "/proc/self/exe" || strings.Join(c.Args[1:4], " ") != "unprotected -- bash" {
		t.Fatalf("as root: %v", c.Args)
	}
}

// the supervisor log: boot's and the supervisor's lines, pushed once each (also across a worker restart), with any
// value the supervisor holds replaced, rotated once pushed
func TestSupervisorLogPush(t *testing.T) {
	d := t.TempDir()
	t.Setenv("HOME", t.TempDir()) // held.set rewrites the deploy keys under $HOME
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	held.set(map[string]string{"A": "hunter2hunter2", "B": "it's a long one", "C": "short"})
	defer held.set(map[string]string{})
	oldP, oldS, oldR := supervisorLogPath, supervisorLogSent, supervisorLogRoll
	defer func() { supervisorLogPath, supervisorLogSent, supervisorLogRoll = oldP, oldS, oldR }()
	supervisorLogPath, supervisorLogSent, supervisorLogRoll = filepath.Join(d, "s.log"), filepath.Join(d, "s.sent"), 400
	var mu sync.Mutex
	var lines []logLine
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/m/supervisor-log" {
			http.NotFound(w, r)
			return
		}
		var in struct{ Lines []logLine }
		json.NewDecoder(r.Body).Decode(&in)
		mu.Lock()
		lines = append(lines, in.Lines...)
		mu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := testClient(t, srv.URL)
	boot := fileLog{supervisorLogPath, "boot"}
	sup := fileLog{supervisorLogPath, "supervisor"}
	boot.Write([]byte("[jarvis] keys ready; waiting for init\n"))
	sup.Write([]byte("[jarvis] exec x refused: token hunter2hunter2 and it's a long one, short\n"))
	if err := pushLogOnce(c); err != nil {
		t.Fatal(err)
	}
	if err := pushLogOnce(c); err != nil { // nothing new: nothing pushed again
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0].Text != "boot: keys ready; waiting for init" {
		t.Fatalf("pushed %+v", lines)
	}
	if strings.Contains(lines[1].Text, "hunter2") || strings.Contains(lines[1].Text, "long one") || !strings.Contains(lines[1].Text, "[secret]") || !strings.Contains(lines[1].Text, "short") {
		t.Fatalf("not redacted: %q", lines[1].Text)
	}
	for i := 0; i < 10; i++ { // past the roll size: rotated after the push, nothing lost or repeated
		sup.Write([]byte("[jarvis] line " + itoa(i) + "\n"))
		pushLogOnce(c)
	}
	if len(lines) != 12 || lines[11].Text != "supervisor: line 9" {
		t.Fatalf("after rotation %d lines, last %+v", len(lines), lines[len(lines)-1])
	}
	if st, err := os.Stat(supervisorLogPath); err == nil && st.Size() > 400 {
		t.Fatalf("not rotated: %d bytes", st.Size())
	}
}

func testClient(t *testing.T, url string) *client {
	t.Helper()
	return &client{base: url, me: "m1", sig: newKey().k, http: http.DefaultClient}
}
