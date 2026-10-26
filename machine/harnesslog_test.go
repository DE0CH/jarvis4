package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// only the launcher's tagged lines reach the supervisor log, clipped and rate limited; the rest stays on the console
func TestHarnessLogKeepsOnlyTaggedLines(t *testing.T) {
	var b bytes.Buffer
	h := newHarnessLog(&b)
	h.line("[dsh] dsh web exited (code 1) after 3 s; restarting")
	h.line("some program's own output, maybe a prompt")
	h.line("[Weird] not a tag")
	h.line("[entrypoint] " + strings.Repeat("x", 3000))
	got := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(got) != 2 || got[0] != "[dsh] dsh web exited (code 1) after 3 s; restarting" || len(got[1]) != maxLogLine {
		t.Fatalf("%q", got)
	}
	b.Reset()
	for i := 0; i < 200; i++ {
		h.line("[dsh] flood")
	}
	if n := strings.Count(b.String(), "\n"); n > harnessLogBurst {
		t.Fatalf("%d lines past the burst", n)
	}
	h.last = h.last.Add(-time.Minute)
	b.Reset()
	h.line("[dsh] after")
	if !strings.Contains(b.String(), "harness lines left out") || !strings.HasSuffix(b.String(), "[dsh] after\n") {
		t.Fatalf("%q", b.String())
	}
}

// the pipe: a child's lines arrive, and the reader ends once the last holder of the write end is gone
func TestHarnessStdoutPipe(t *testing.T) {
	var b bytes.Buffer
	h := newHarnessLog(&b)
	w, err := harnessStdout(h)
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString("[dsh] up\nnoise\n")
	w.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		h.mu.Lock()
		s := b.String()
		h.mu.Unlock()
		if s == "[dsh] up\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%q", s)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
