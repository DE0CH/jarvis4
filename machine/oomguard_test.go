package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestSessionLimit(t *testing.T) {
	for _, c := range []struct{ totalMB, want int64 }{
		{4010184 >> 10, (4010184 >> 10) - 640}, // medium (Fly's 4 GB guest: MemTotal 3916 MB)
		{8 << 10, 8<<10 - 640},
		{1024, 512}, // never under half the machine
	} {
		if got := sessionLimit(c.totalMB<<10) >> 20; got != c.want {
			t.Errorf("sessionLimit(%d MB) = %d MB, want %d", c.totalMB, got, c.want)
		}
	}
	if got := rescueLimit(3916<<10) >> 20; got != 384 {
		t.Errorf("rescueLimit(3916 MB) = %d MB, want 384", got)
	}
	if got := rescueLimit(1024<<10) >> 20; got != 256 {
		t.Errorf("rescueLimit(1024 MB) = %d MB, want 256 (a quarter)", got)
	}
}

// TestSessionCgroupAsRoot: the keeper's cgroup gets MemTotal minus the reserve; a process that joins it (as
// `unprotected` does) takes its children along, and the session user's hog over the limit is OOM-killed inside it
// while this process (outside again) carries on
func TestSessionCgroupAsRoot(t *testing.T) {
	u := rootRig(t)
	if _, err := os.Stat("/sys/fs/cgroup/memory/cgroup.procs"); err != nil {
		t.Skip("no cgroup v1 memory controller")
	}
	oldS, oldR := sessionCgroup, rescueCgroup
	sessionCgroup = "/sys/fs/cgroup/memory/jarvis2-test-session-" + strconv.Itoa(os.Getpid())
	rescueCgroup = "/sys/fs/cgroup/memory/jarvis2-test-rescue-" + strconv.Itoa(os.Getpid())
	t.Cleanup(func() {
		os.WriteFile("/sys/fs/cgroup/memory/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0o644)
		os.Remove(sessionCgroup)
		os.Remove(rescueCgroup)
		sessionCgroup, rescueCgroup = oldS, oldR
	})
	if err := setupCgroups(); err != nil {
		t.Fatal(err)
	}
	s, _ := readMemory()
	b, _ := os.ReadFile(filepath.Join(sessionCgroup, "memory.limit_in_bytes"))
	if got := strings.TrimSpace(string(b)); got != strconv.FormatInt(sessionLimit(s.TotalKb), 10) {
		t.Fatalf("limit %s, want %d", got, sessionLimit(s.TotalKb))
	}
	b, _ = os.ReadFile(filepath.Join(rescueCgroup, "memory.limit_in_bytes"))
	if got := strings.TrimSpace(string(b)); got != strconv.FormatInt(rescueLimit(s.TotalKb), 10) {
		t.Fatalf("rescue limit %s, want %d", got, rescueLimit(s.TotalKb))
	}

	os.WriteFile(filepath.Join(sessionCgroup, "memory.limit_in_bytes"), []byte(strconv.Itoa(64<<20)), 0o644)
	joinCgroup(sessionCgroup)
	out, err := asUser(u, `python3 -c 'a=bytearray(256<<20); print("not killed")'`)
	os.WriteFile("/sys/fs/cgroup/memory/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0o644)
	if err == nil || strings.Contains(out, "not killed") {
		t.Fatalf("the hog over the limit wasn't killed: %q %v", out, err)
	}
	if ws, ok := err.(interface{ Sys() any }); ok {
		if st, ok := ws.Sys().(syscall.WaitStatus); ok && st.Signaled() && st.Signal() != syscall.SIGKILL {
			t.Fatalf("the hog ended by %v, want SIGKILL", st.Signal())
		}
	}
	b, _ = os.ReadFile(filepath.Join(sessionCgroup, "memory.failcnt"))
	if strings.TrimSpace(string(b)) == "0" {
		t.Fatal("the cgroup never reached its limit")
	}
}

// TestRescueOutsideTheSessionAsRoot: `unprotected` puts a session command in the session's cgroup and
// `unprotected --rescue` (a terminal grant's exec) in the rescue one; with the session's cgroup full (a hog of the
// session user held at its limit), a rescue command still allocates and can kill the hog
func TestRescueOutsideTheSessionAsRoot(t *testing.T) {
	rootRig(t)
	if _, err := os.Stat("/sys/fs/cgroup/memory/cgroup.procs"); err != nil {
		t.Skip("no cgroup v1 memory controller")
	}
	oldS, oldR := sessionCgroup, rescueCgroup
	sessionCgroup = "/sys/fs/cgroup/memory/jarvis2-test-session-" + strconv.Itoa(os.Getpid())
	rescueCgroup = "/sys/fs/cgroup/memory/jarvis2-test-rescue-" + strconv.Itoa(os.Getpid())
	t.Setenv("JARVIS_TEST_CGROUPS", sessionCgroup+","+rescueCgroup)
	var hog *exec.Cmd
	t.Cleanup(func() {
		if hog != nil && hog.Process != nil {
			hog.Process.Kill()
			hog.Wait()
		}
		os.Remove(sessionCgroup)
		os.Remove(rescueCgroup)
		sessionCgroup, rescueCgroup = oldS, oldR
	})
	if err := setupCgroups(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(sessionCgroup, "memory.limit_in_bytes"), []byte(strconv.Itoa(96<<20)), 0o644)

	cg := func(c *exec.Cmd) string {
		out, err := c.Output()
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(string(out), "\n") {
			if _, p, ok := strings.Cut(l, ":memory:"); ok {
				return p
			}
		}
		return ""
	}
	if got := cg(sessionCommand(nil, "cat", "/proc/self/cgroup")); got != strings.TrimPrefix(sessionCgroup, "/sys/fs/cgroup/memory") {
		t.Fatalf("a session command is in %q, want the session's cgroup", got)
	}
	if got := cg(rescueCommand(nil, "cat", "/proc/self/cgroup")); got != strings.TrimPrefix(rescueCgroup, "/sys/fs/cgroup/memory") {
		t.Fatalf("a rescue command is in %q, want the rescue cgroup", got)
	}

	// the session at its limit: a hog that takes 80 MB of its 96 and sits there, page cache squeezed out
	hog = sessionCommand(nil, "python3", "-c", `import time; a=b"x"*(80<<20); print("full", flush=True); time.sleep(300)`)
	pr, _ := hog.StdoutPipe()
	if err := hog.Start(); err != nil {
		t.Fatal(err)
	}
	line := make([]byte, 5)
	if _, err := io.ReadFull(pr, line); err != nil || string(line) != "full\n" {
		t.Fatalf("the hog didn't fill the session: %q %v", line, err)
	}
	// a rescue command needs 128 MB, more than the whole session's limit, and kills the hog
	out, err := rescueCommand(nil, "sh", "-c", `python3 -c 'a=b"x"*(128<<20); print("rescued")' && kill -KILL `+strconv.Itoa(hog.Process.Pid)).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "rescued") {
		t.Fatalf("the rescue command didn't run beside a full session: %q %v", out, err)
	}
	if err := hog.Wait(); err == nil {
		t.Fatal("the hog wasn't killed by the rescue command")
	}
	hog = nil
}

func TestLockMemoryAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if err := mlockAll(); err != nil {
		t.Fatal(err)
	}
	defer syscall.Munlockall()
	if v := procStatusField(os.Getpid(), "VmLck"); v == "" || v == "0" {
		t.Fatalf("VmLck %q after mlockall", v)
	}
}
