package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DE0CH/jarvis4/kernel/spawner"
)

// fakeShipper: Loki's push API as the shipper serves it; every stream it was sent
type fakeShipper struct {
	mu      sync.Mutex
	streams []struct {
		Stream map[string]string `json:"stream"`
		Values [][2]string       `json:"values"`
	}
	fail bool
}

func useFakeShipper(t *testing.T) *fakeShipper {
	f := &fakeShipper{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path != "/loki/api/v1/push" || f.fail {
			w.WriteHeader(503)
			return
		}
		var in struct {
			Streams []struct {
				Stream map[string]string `json:"stream"`
				Values [][2]string       `json:"values"`
			} `json:"streams"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		f.streams = append(f.streams, in.Streams...)
		w.WriteHeader(204)
	}))
	t.Cleanup(srv.Close)
	old := awsLogs
	awsLogs = &awsLogQueue{}
	t.Cleanup(func() { awsLogs = old })
	t.Setenv("AWS_LOG_SHIPPER_URL", srv.URL+"/loki/api/v1/push")
	return f
}

// lines: every line of the streams with these labels, in order
func (f *fakeShipper) lines(labels map[string]string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, s := range f.streams {
		ok := true
		for k, v := range labels {
			if s.Stream[k] != v {
				ok = false
			}
		}
		if ok {
			for _, v := range s.Values {
				out = append(out, v[1])
			}
		}
	}
	return out
}

// an AWS machine's output: signed by the machine, labelled by the router with its instance, region, session and
// source, kept while the shipper refuses and sent once it takes them; a Fly machine's is Fly's
func TestMachineOutputToTheShipper(t *testing.T) {
	sh := useFakeShipper(t)
	r := newTestRouter(t)
	addSession(r, "sA", "started", "i-0abc", false)
	awsSeenMu.Lock()
	awsSeen["i-0abc"] = spawner.Instance{ID: "i-0abc", Region: "eu-west-2", State: "started"}
	awsSeenMu.Unlock()
	t.Cleanup(func() { awsSeenMu.Lock(); delete(awsSeen, "i-0abc"); awsSeenMu.Unlock() })
	m := newTestMachine(r, "i-0abc")
	push := func(m testMachine, source string, lines ...string) int {
		ls := []map[string]string{}
		for _, l := range lines {
			ls = append(ls, map[string]string{"at": time.Now().UTC().Format(time.RFC3339Nano), "text": l})
		}
		code, _ := m.do(t, r.MachineHandler(), "POST", "/m/machine-output", jsonString(map[string]any{"source": source, "lines": ls}))
		return code
	}
	sh.mu.Lock()
	sh.fail = true
	sh.mu.Unlock()
	if c := push(m, "machine", "[jarvis] keeper up", "second"); c != 200 {
		t.Fatal(c)
	}
	if c := push(m, "journal", "systemd: Started jarvis4-session.service"); c != 200 {
		t.Fatal(c)
	}
	if awsLogs.pushOnce() == nil {
		t.Fatal("a refused push counted as sent")
	}
	sh.mu.Lock()
	sh.fail = false
	sh.mu.Unlock()
	if err := awsLogs.pushOnce(); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"instance": "i-0abc", "aws_region": "eu-west-2", "session": "sA", "source": "machine"}
	if got := sh.lines(want); strings.Join(got, "|") != "[jarvis] keeper up|second" {
		t.Fatalf("%v", sh.streams)
	}
	want["source"] = "journal"
	if got := sh.lines(want); len(got) != 1 {
		t.Fatalf("%v", sh.streams)
	}
	if c := push(m, "other"); c != 400 {
		t.Fatalf("an unknown source: %d", c)
	}
	if c := push(newTestMachine(r, "mFly"), "machine", "x"); c != 404 {
		t.Fatalf("a Fly machine's output: %d", c)
	}
	too := make([]string, machineOutLines+1)
	if c := push(m, "machine", too...); c != 400 {
		t.Fatalf("too many lines: %d", c)
	}
}

// the console's window: what follows the last shipped line, also when the 64 KB window slid on; an unfinished line
// waits; terminal escapes and carriage returns go
func TestConsoleNew(t *testing.T) {
	lines, prev := consoleNew("", "\x1b[2J\x1b[01;01HGRUB\r\n[    0.000000] Linux version 6.12\npartial")
	if strings.Join(lines, "|") != "GRUB|[    0.000000] Linux version 6.12" || prev != "\x1b[2J\x1b[01;01HGRUB\r\n[    0.000000] Linux version 6.12\n" {
		t.Fatalf("%q %q", lines, prev)
	}
	out := prev + "partial line done\nlogin: "
	if lines, prev = consoleNew(prev, out); strings.Join(lines, "|") != "partial line done" {
		t.Fatalf("%q", lines)
	}
	if lines, _ = consoleNew(prev, out); len(lines) != 0 {
		t.Fatalf("again: %q", lines)
	}
	// the window slides: the start is gone, the anchor (prev's end) is found
	var b strings.Builder
	for i := 0; i < 4000; i++ {
		fmt.Fprintf(&b, "[ %8.3f] line %d\n", float64(i)/100, i)
	}
	all := b.String()
	_, prev = consoleNew("", all[:40000])
	prev = prev[:strings.LastIndex(prev[:len(prev)-1], "\n")+1]
	lines, _ = consoleNew(prev, all[len(all)-65535:])
	first := strings.Count(prev, "\n")
	if len(lines) != 4000-first || !strings.HasSuffix(lines[0], fmt.Sprintf("line %d", first)) {
		t.Fatalf("%d lines from %q (want %d from line %d)", len(lines), lines[0], 4000-first, first)
	}
	// nothing in common: all of it
	if lines, _ = consoleNew("something else entirely\n", "a\nb\n"); strings.Join(lines, "|") != "a|b" {
		t.Fatalf("%q", lines)
	}
	if c := cleanConsole("\x1bP+q6E616D65\x1b\\\x1b[?7h\x1b[1G\x1b[0J\x1b[6n ip-10-40-0-146 login: x"); c != "ip-10-40-0-146 login: x" {
		t.Fatalf("%q", c)
	}
}

// the leader's console read: each live instance's new lines to the shipper as source "console", once; an OOM kill
// also into the session's running operation; a read key without GetConsoleOutput stops it for a while
func TestConsoleTick(t *testing.T) {
	sh := useFakeShipper(t)
	r := newTestRouter(t)
	var mu sync.Mutex
	console := "[    1.0] Linux version 6.12\nJARVIS2-KEYS {\"sign\":\"…\"}\n"
	refuse := false
	ec2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		mu.Lock()
		defer mu.Unlock()
		if !strings.Contains(string(b), "Action=GetConsoleOutput") || !strings.Contains(string(b), "InstanceId=i-0abc") ||
			!strings.HasPrefix(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIATEST/") {
			w.WriteHeader(400)
			return
		}
		if refuse {
			w.WriteHeader(403)
			io.WriteString(w, `<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>no</Message></Error></Errors></Response>`)
			return
		}
		fmt.Fprintf(w, `<GetConsoleOutputResponse><output>%s</output></GetConsoleOutputResponse>`, base64.StdEncoding.EncodeToString([]byte(console)))
	}))
	defer ec2.Close()
	old := awsReadEndpoint
	awsReadEndpoint = func(string) string { return ec2.URL + "/" }
	defer func() { awsReadEndpoint = old }()
	t.Setenv("AWS_READ_ACCESS_KEY_ID", "AKIATEST")
	t.Setenv("AWS_READ_SECRET_ACCESS_KEY", "secret")
	consoleMu.Lock()
	clear(consoleReads)
	consoleOff = time.Time{}
	consoleMu.Unlock()
	addSession(r, "sA", "started", "i-0abc", false)
	awsSeenMu.Lock()
	awsSeen["i-0abc"] = spawner.Instance{ID: "i-0abc", Region: "eu-west-2", State: "started"}
	awsSeen["i-0old"] = spawner.Instance{ID: "i-0old", Region: "eu-west-2", State: "destroyed"}
	awsSeenMu.Unlock()
	t.Cleanup(func() { awsSeenMu.Lock(); delete(awsSeen, "i-0abc"); delete(awsSeen, "i-0old"); awsSeenMu.Unlock() })
	h := r.lcBegin("sA", "boot")
	h.machine("i-0abc")
	r.consoleTick()
	mu.Lock()
	console += "[   61.2] Out of memory: Killed process 4242 (node)\n"
	mu.Unlock()
	r.consoleTick()
	r.consoleTick()
	if err := awsLogs.pushOnce(); err != nil {
		t.Fatal(err)
	}
	got := sh.lines(map[string]string{"instance": "i-0abc", "source": "console", "session": "sA", "aws_region": "eu-west-2"})
	if strings.Join(got, "|") != `[    1.0] Linux version 6.12|JARVIS2-KEYS {"sign":"…"}|[   61.2] Out of memory: Killed process 4242 (node)` {
		t.Fatalf("%q", got)
	}
	_, entries := r.lcRead("sA")
	var aws []string
	for _, e := range entries[h.run.op.ID] {
		if e.Source == "aws" {
			aws = append(aws, e.Text)
		}
	}
	if strings.Join(aws, "|") != "AWS console: [   61.2] Out of memory: Killed process 4242 (node)" {
		t.Fatalf("%q", aws)
	}
	mu.Lock()
	refuse = true
	mu.Unlock()
	r.consoleTick()
	consoleMu.Lock()
	off := time.Now().Before(consoleOff)
	consoleMu.Unlock()
	if !off {
		t.Fatal("a refused GetConsoleOutput didn't stop the reads")
	}
}

// the push body: one stream per label set, its values in time order, as Loki takes them
func TestLokiPush(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	a, b := awsLogLabels("i-1", "eu-west-2", "s1", "machine"), awsLogLabels("i-1", "eu-west-2", "s1", "console")
	body, err := lokiPush([]awsLogLine{{a, t0.Add(2), "two"}, {b, t0, "console"}, {a, t0.Add(1), "one"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"streams":[{"stream":{"aws_region":"eu-west-2","instance":"i-1","session":"s1","source":"machine"},"values":[["1700000000000000001","one"],["1700000000000000002","two"]]},{"stream":{"aws_region":"eu-west-2","instance":"i-1","session":"s1","source":"console"},"values":[["1700000000000000000","console"]]}]}` {
		t.Fatalf("%s", body)
	}
}
