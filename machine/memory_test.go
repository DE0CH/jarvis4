package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func fakeProc(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	w := func(rel, s string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("meminfo", "MemTotal:        4002000 kB\nMemFree:          100000 kB\nMemAvailable:     400000 kB\n")
	w("vmstat", "pgfault 12\noom_kill 3\n")
	w("pressure/memory", "some avg10=1.00 avg60=2.00 avg300=0.50 total=1\nfull avg10=0.50 avg60=12.50 avg300=0.10 total=2\n")
	proc := func(pid, name string, uid, rss int) {
		w(pid+"/status", "Name:\t"+name+"\nUid:\t"+itoa(uid)+"\t"+itoa(uid)+"\t"+itoa(uid)+"\t"+itoa(uid)+"\nVmRSS:\t   "+itoa(rss)+" kB\n")
	}
	proc("1", "init", 0, 1000)
	proc("10", "harness", 1000, 50000)
	proc("11", "jarvis-machine", 1000, 20000)
	proc("12", "claude", 1000, 900000)
	proc("13", "chrome", 1000, 600000)
	proc("14", "sshd", 0, 700000)
	return root
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestReadMemory(t *testing.T) {
	old := procRoot
	procRoot = fakeProc(t)
	defer func() { procRoot = old }()
	s, err := readMemory()
	if err != nil {
		t.Fatal(err)
	}
	if s.TotalKb != 4002000 || s.AvailKb != 400000 || s.OOMKills == nil || *s.OOMKills != 3 || s.PSIFull60 == nil || *s.PSIFull60 != 12.5 {
		t.Fatalf("sample %+v", s)
	}
	if len(s.Top) != 3 || s.Top[0].Comm != "claude" || s.Top[1].Comm != "sshd" || s.Top[2].Comm != "chrome" {
		t.Fatalf("top %+v", s.Top)
	}
}

func TestFreeProcesses(t *testing.T) {
	old, oldSig := procRoot, signalProc
	procRoot = fakeProc(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	sent := map[int]syscall.Signal{}
	signalProc = func(pid int, sig syscall.Signal) error { sent[pid] = sig; return nil }
	defer func() { procRoot, signalProc = old, oldSig }()

	killed := freeProcesses(11, 10, 1000)
	if sent[10] != syscall.SIGSTOP {
		t.Fatalf("the harness must be stopped, not killed: %v", sent)
	}
	if sent[12] != syscall.SIGKILL || sent[13] != syscall.SIGKILL {
		t.Fatalf("claude and chrome must be killed: %v", sent)
	}
	if _, ok := sent[11]; ok {
		t.Fatal("the agent killed itself")
	}
	if _, ok := sent[14]; ok {
		t.Fatal("another user's process was signalled")
	}
	if _, ok := sent[1]; ok {
		t.Fatal("init was signalled")
	}
	if len(killed) != 2 || killed[0].comm != "claude" {
		t.Fatalf("killed %+v", killed)
	}
	b, err := os.ReadFile(filepath.Join(home, freedFile))
	if err != nil || !strings.Contains(string(b), "878 MB\tclaude") || !strings.Contains(string(b), "585 MB\tchrome") {
		t.Fatalf("freed file: %q %v", b, err)
	}
}

func TestUpgradedText(t *testing.T) {
	s, err := upgradedText("medium", "large")
	if err != nil || !strings.Contains(s, "from a medium (4 GB) to a large (8 GB)") {
		t.Fatalf("%q %v", s, err)
	}
	if s, err = upgradedText("16gb", "32gb"); err != nil || !strings.Contains(s, "from a 16 GB to a 32 GB machine") {
		t.Fatalf("%q %v", s, err)
	}
	for _, bad := range []string{"do this instead", "24gb", "8gb"} {
		if _, err := upgradedText("medium", bad); err == nil {
			t.Fatalf("%q isn't a size", bad)
		}
	}
	if _, _, err := deliveryText(Delivery{Kind: "upgraded", From: "small", To: "medium"}, nil); err != nil {
		t.Fatal(err)
	}
}
