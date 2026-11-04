package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// the tee: every line of the pipe goes on to the original output unchanged and into the file, a long one in pieces
func TestTeeLines(t *testing.T) {
	d := t.TempDir()
	f := &shipFile{path: filepath.Join(d, "out.log"), source: "machine"}
	r, w := io.Pipe()
	var out bytes.Buffer
	done := make(chan struct{})
	go func() { teeLines(r, &out, f); close(done) }()
	long := strings.Repeat("x", 20<<10)
	io.WriteString(w, "[jarvis] keeper up\r\nsecond\n\n"+long+"\nlast without newline")
	w.Close()
	<-done
	if out.String() != "[jarvis] keeper up\r\nsecond\n\n"+long+"\nlast without newline" {
		t.Fatal("the original output changed")
	}
	b, _ := os.ReadFile(f.path)
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var ll logLine
		if err := json.Unmarshal([]byte(l), &ll); err != nil {
			t.Fatal(err)
		}
		got = append(got, ll.Text)
	}
	if len(got) != 5 || got[0] != "[jarvis] keeper up" || got[1] != "second" || len(got[2]) != 16<<10 || got[4] != "last without newline" {
		t.Fatalf("%d lines: %q…", len(got), got[0])
	}
}

// the push: both files to /m/machine-output with their source, each line once, the held values replaced; a file
// past its cap takes no more lines and says how many it missed
func TestOutputPush(t *testing.T) {
	d := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("JARVIS2_RUNNER", "aws")
	held.set(map[string]string{"A": "hunter2hunter2"})
	defer held.set(map[string]string{})
	oldO, oldJ, oldCap := outputShip.path, journalShip.path, shipFileCap
	defer func() { outputShip.path, journalShip.path, shipFileCap = oldO, oldJ, oldCap }()
	outputShip.path, journalShip.path = filepath.Join(d, "o.log"), filepath.Join(d, "j.log")
	var mu sync.Mutex
	got := map[string][]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/m/machine-output" {
			http.NotFound(w, r)
			return
		}
		var in struct {
			Source string
			Lines  []logLine
		}
		json.NewDecoder(r.Body).Decode(&in)
		mu.Lock()
		for _, l := range in.Lines {
			got[in.Source] = append(got[in.Source], l.Text)
		}
		mu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := testClient(t, srv.URL)
	outputShip.add(time.Now(), "panic: token hunter2hunter2")
	journalShip.add(time.Now(), "jarvis4-session.service docker: Pulling fs layer")
	pushOutputsOnce(c)
	pushOutputsOnce(c)
	if strings.Join(got["machine"], "|") != "panic: token [secret]" || strings.Join(got["journal"], "|") != "jarvis4-session.service docker: Pulling fs layer" {
		t.Fatalf("%v", got)
	}
	shipFileCap = 10
	outputShip.add(time.Now(), "taken: everything before it was pushed")
	outputShip.add(time.Now(), "past the cap: counted")
	outputShip.add(time.Now(), "and another")
	shipFileCap = oldCap
	outputShip.add(time.Now(), "room again")
	pushOutputsOnce(c)
	if m := got["machine"]; len(m) != 4 || m[1] != "taken: everything before it was pushed" || !strings.Contains(m[2], "2 machine lines not sent") || m[3] != "room again" {
		t.Fatalf("%q", m)
	}
}

// the journal's entries as lines: the kernel's left out (the console has them), the session unit's docker client
// from the keeper's start on left out (the container's own output), a non-UTF-8 message kept
func TestJournalLine(t *testing.T) {
	since := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	us := func(t time.Time) string { return itoa(int(t.UnixMicro())) }
	before, after := us(since.Add(-time.Minute)), us(since.Add(time.Second))
	cases := []struct {
		e    journalEntry
		want string
	}{
		{journalEntry{Realtime: before, Message: json.RawMessage(`"Pulling fs layer"`), Unit: "jarvis4-session.service", Ident: "docker", Comm: "docker"}, "jarvis4-session.service docker: Pulling fs layer"},
		{journalEntry{Realtime: after, Message: json.RawMessage(`"[jarvis] keeper up"`), Unit: "jarvis4-session.service", Ident: "docker", Comm: "docker"}, ""},
		{journalEntry{Realtime: after, Message: json.RawMessage(`"Out of memory: Killed process 7"`), Transport: "kernel"}, ""},
		{journalEntry{Realtime: after, Message: json.RawMessage(`"Started jarvis4-session.service"`), Unit: "init.scope", Ident: "systemd"}, "systemd: Started jarvis4-session.service"},
		{journalEntry{Realtime: after, Message: json.RawMessage(`[104,105,255]`), Ident: "x"}, "x: hi�"},
	}
	for i, c := range cases {
		at, got := journalLine(c.e, since)
		if got != c.want {
			t.Fatalf("%d: %q, want %q", i, got, c.want)
		}
		if c.e.Realtime == after && !at.Equal(since.Add(time.Second)) {
			t.Fatalf("%d: at %v", i, at)
		}
	}
}

// the ROOT partition, found by its name in sysfs
func TestRootPartition(t *testing.T) {
	d := t.TempDir()
	old := sysBlock
	sysBlock = d
	defer func() { sysBlock = old }()
	for name, ev := range map[string]string{"nvme0n1": "DEVTYPE=disk\nDEVNAME=nvme0n1\n", "nvme0n1p6": "PARTNAME=OEM\nDEVNAME=nvme0n1p6\n",
		"nvme0n1p9": "MAJOR=259\nDEVNAME=nvme0n1p9\nDEVTYPE=partition\nPARTN=9\nPARTNAME=ROOT\n"} {
		os.MkdirAll(filepath.Join(d, name), 0o755)
		os.WriteFile(filepath.Join(d, name, "uevent"), []byte(ev), 0o644)
	}
	if dev, err := rootPartition(); err != nil || dev != "/dev/nvme0n1p9" {
		t.Fatal(dev, err)
	}
}
