package main

// The AWS machines' logs to Grafana Cloud (docs/PLAN-aws.md "Logs"), next to what the Fly app jarvis2-log-shipper
// ships of the Fly machines (box="fly"). Fly reads a machine's output on its own platform; an EC2 instance's output
// has no such reader, so it reaches Grafana from two places, both through the router, which names the machine:
//
//   - the machine's own output (source "machine"): the keeper tees its and its children's stdout and stderr into a
//     file in memory (machine/output.go) that supervisor-core pushes here, POST /m/machine-output, signed by the
//     machine's certified key like every /m request, so the instance id on the lines is the router's word, not the
//     machine's. With the kernel's journal bind (docs/PLAN-aws.md "Logs": a proposal) the machine also pushes the
//     host's journal (source "journal": the session unit's image pull, docker, the kernel).
//   - the instance's serial console (source "console": the kernel's messages from the first second, the boot,
//     Ignition, an OOM kill, a panic), read by the leader every consoleEvery with the router's read-only key
//     (GetConsoleOutput, awsread.go): what a machine that never got as far as its own output still shows.
//
// Every line goes to the shipper (AWS_LOG_SHIPPER_URL: the Deployment aws-log-shipper in jarvis2-obs,
// k8s/cluster/obs/aws-log-shipper.yaml), Alloy with the same secret-shape redaction as the boxes and the Fly shipper,
// which holds the Grafana write token and labels everything box="aws"; the router labels each stream with
// instance, aws_region, session and source. Grafana keeps them as it keeps the Fly machines' lines (the same stack,
// its retention), read with the same token (RUNBOOK "Logs and metrics").

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	awsLogQueueMax  = 50000 // lines held for the shipper; past it the oldest go (counted)
	awsLogBatch     = 2000  // lines per push
	awsLogLineMax   = 4000  // bytes per line (clipped)
	machineOutLines = 500   // lines per machine push
)

var (
	awsLogEvery  = 2 * time.Second  // the queue's push to the shipper
	consoleEvery = 15 * time.Second // the leader's console read of each live instance
	awsLogHTTP   = &http.Client{Timeout: 30 * time.Second}
)

type awsLogLine struct {
	labels string // the stream's labels, canonical JSON
	at     time.Time
	text   string
}

type awsLogQueue struct {
	mu      sync.Mutex
	lines   []awsLogLine
	dropped int
	once    sync.Once
	url     string
	failing bool
}

var awsLogs = &awsLogQueue{}

// awsLogLabels: the labels of one machine's stream (box="aws" is the shipper's)
func awsLogLabels(instance, region, session, source string) string {
	l := map[string]string{"instance": instance, "source": source}
	if region != "" {
		l["aws_region"] = region
	}
	if session != "" {
		l["session"] = session
	}
	b, _ := json.Marshal(l) // map keys sorted: the same set, the same string
	return string(b)
}

// ship: lines of one stream into the queue (nothing when no shipper is configured)
func (q *awsLogQueue) ship(labels string, at []time.Time, texts []string) {
	q.once.Do(func() { q.url = os.Getenv("AWS_LOG_SHIPPER_URL") })
	if q.url == "" {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, t := range texts {
		if len(t) > awsLogLineMax {
			t = t[:awsLogLineMax] + "…"
		}
		q.lines = append(q.lines, awsLogLine{labels: labels, at: at[i], text: t})
	}
	if over := len(q.lines) - awsLogQueueMax; over > 0 {
		q.lines = append([]awsLogLine(nil), q.lines[over:]...)
		q.dropped += over
	}
}

// pushOnce: up to awsLogBatch queued lines to the shipper as one Loki push; kept for the next round when it fails
func (q *awsLogQueue) pushOnce() error {
	q.mu.Lock()
	n := min(len(q.lines), awsLogBatch)
	batch := append([]awsLogLine(nil), q.lines[:n]...)
	dropped := q.dropped
	q.dropped = 0
	url := q.url
	q.mu.Unlock()
	if n == 0 && dropped == 0 {
		return nil
	}
	if dropped > 0 {
		batch = append(batch, awsLogLine{labels: awsLogLabels("router", "", "", "router"), at: time.Now(),
			text: fmt.Sprintf("[router] %d AWS machine log lines dropped: the shipper didn't take them in time", dropped)})
	}
	body, err := lokiPush(batch)
	if err == nil {
		var resp *http.Response
		if resp, err = awsLogHTTP.Post(url, "application/json", bytes.NewReader(body)); err == nil {
			resp.Body.Close()
			if resp.StatusCode/100 != 2 {
				err = fmt.Errorf("the shipper answered HTTP %d", resp.StatusCode)
			}
		}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err != nil {
		q.dropped += dropped
		if !q.failing {
			log.Printf("[aws-logs] push: %v (kept, tried again)", err)
		}
		q.failing = true
		return err
	}
	if q.failing {
		log.Printf("[aws-logs] the shipper takes lines again")
	}
	q.failing = false
	q.lines = q.lines[n:]
	return nil
}

// lokiPush: the lines as Loki's push API JSON, one stream per label set, each in time order
func lokiPush(lines []awsLogLine) ([]byte, error) {
	type stream struct {
		Stream map[string]string `json:"stream"`
		Values [][2]string       `json:"values"`
	}
	by := map[string]*stream{}
	order := []string{}
	for _, l := range lines {
		s := by[l.labels]
		if s == nil {
			s = &stream{Stream: map[string]string{}}
			if err := json.Unmarshal([]byte(l.labels), &s.Stream); err != nil {
				return nil, err
			}
			by[l.labels] = s
			order = append(order, l.labels)
		}
		s.Values = append(s.Values, [2]string{strconv.FormatInt(l.at.UnixNano(), 10), l.text})
	}
	out := struct {
		Streams []*stream `json:"streams"`
	}{}
	for _, k := range order {
		s := by[k]
		sort.SliceStable(s.Values, func(i, j int) bool {
			a, _ := strconv.ParseInt(s.Values[i][0], 10, 64)
			b, _ := strconv.ParseInt(s.Values[j][0], 10, 64)
			return a < b
		})
		out.Streams = append(out.Streams, s)
	}
	return json.Marshal(out)
}

// awsLogLoop: the queue to the shipper, on every replica (each ships what its machines pushed to it)
func (r *Router) awsLogLoop() {
	for {
		time.Sleep(awsLogEvery)
		for awsLogs.pushOnce() == nil {
			awsLogs.mu.Lock()
			more := len(awsLogs.lines) > 0
			awsLogs.mu.Unlock()
			if !more {
				break
			}
		}
	}
}

// ---- the machine's own output -------------------------------------------------------------------------------

func (r *Router) registerMachineOutput(m machineRoute) {
	// POST /m/machine-output {"source":"machine"|"journal","lines":[{"at","text"}]}: an AWS machine's output (Fly's
	// machines' output is Fly's to ship)
	m("POST /m/machine-output", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		if !isAWSMachine(machine) {
			writeJSON(w, 404, map[string]string{"error": "only an AWS machine pushes its output: Fly ships its machines' (jarvis2-log-shipper)"})
			return
		}
		var in struct {
			Source string `json:"source"`
			Lines  []struct {
				At   string `json:"at"`
				Text string `json:"text"`
			} `json:"lines"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "not JSON: " + err.Error()})
			return
		}
		if in.Source == "" {
			in.Source = "machine"
		}
		if in.Source != "machine" && in.Source != "journal" {
			writeJSON(w, 400, map[string]string{"error": `source: "machine" or "journal"`})
			return
		}
		if len(in.Lines) > machineOutLines {
			writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("at most %d lines per push", machineOutLines)})
			return
		}
		var session string
		r.st.Do(func(d *persisted) { session = d.Machines[machine] })
		now := time.Now()
		ats, texts := make([]time.Time, 0, len(in.Lines)), make([]string, 0, len(in.Lines))
		for _, l := range in.Lines {
			at, err := time.Parse(time.RFC3339Nano, l.At)
			if err != nil || at.After(now.Add(time.Minute)) || at.Before(now.Add(-24*time.Hour)) {
				at = now // a machine clock off by a lot: the router's time
			}
			ats, texts = append(ats, at), append(texts, l.Text)
		}
		awsLogs.ship(awsLogLabels(machine, awsRegionOfInstance(machine), session, in.Source), ats, texts)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
}

// ---- the serial console ---------------------------------------------------------------------------------------

// consoleRead: what the router has shipped of one instance's console
type consoleRead struct {
	shipped string // the console's text up to the end of its last shipped line, as the newest read had it
}

var (
	consoleMu    sync.Mutex
	consoleReads = map[string]*consoleRead{}
	consoleOff   time.Time // GetConsoleOutput refused (the read key without it): not asked again until then
)

// consoleNew: the complete lines of out that follow what was shipped (prev), and the new prev. EC2 gives the newest
// 64 KB, so the window slides: prev's last bytes are looked for in out; not there (more than 64 KB came between
// two reads), everything in out is new.
func consoleNew(prev, out string) ([]string, string) {
	rest := out
	switch {
	case prev == "":
	case strings.HasPrefix(out, prev):
		rest = out[len(prev):]
	default:
		anchor := prev[max(0, len(prev)-1024):]
		if i := strings.LastIndex(out, anchor); i >= 0 {
			rest = out[i+len(anchor):]
		} else if strings.Contains(prev, out) || strings.HasSuffix(prev, strings.TrimRight(out, "\n")) {
			return nil, prev // nothing new (an older read came back)
		}
	}
	cut := strings.LastIndexByte(rest, '\n')
	if cut < 0 {
		return nil, prev // only part of a line so far
	}
	shippedTo := len(out) - len(rest) + cut + 1
	var lines []string
	for _, l := range strings.Split(rest[:cut], "\n") {
		if l = cleanConsole(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, out[:shippedTo]
}

var (
	consoleANSIRE    = regexp.MustCompile(`\x1b(\[[0-9;?=]*[ -/]*[@-~]|\][^\x07\x1b]*(\x07|\x1b\\)|P[^\x1b]*\x1b\\|[()][0-9A-Za-z]|[=>78DEHMc])`)
	consoleCtrlRE    = regexp.MustCompile(`[\x00-\x08\x0b-\x1f\x7f]`)
	consoleNotableRE = regexp.MustCompile(`(?i)out of memory|oom-kill|killed process|kernel panic|call trace|ignition.*(fail|error)|segfault|hung_task|blocked for more than|\breboot: |EXT4-fs error|I/O error|JARVIS4-SESSION-END`)
)

// cleanConsole: a console line without its terminal escapes (GRUB's menu, getty's), carriage returns and control bytes
func cleanConsole(l string) string {
	l = consoleANSIRE.ReplaceAllString(l, "")
	if i := strings.LastIndexByte(l, '\r'); i >= 0 && strings.TrimSpace(l[i+1:]) != "" {
		l = l[i+1:] // a line written over: what shows
	}
	return strings.TrimSpace(strings.ToValidUTF8(consoleCtrlRE.ReplaceAllString(l, ""), "�"))
}

// consoleTick: each live session instance's new console lines to the shipper, and the notable ones (an OOM kill, a
// panic, Ignition failing, the power-off) into the session's running lifecycle operation. Only on the leader.
func (r *Router) consoleTick() {
	if !awsReadOn() || os.Getenv("AWS_LOG_SHIPPER_URL") == "" {
		return
	}
	consoleMu.Lock()
	off := time.Now().Before(consoleOff)
	consoleMu.Unlock()
	if off {
		return
	}
	awsSeenMu.Lock()
	live := map[string]string{} // id → region
	for id, in := range awsSeen {
		if in.State == "created" || in.State == "started" || in.State == "destroying" {
			live[id] = in.Region
		}
	}
	awsSeenMu.Unlock()
	consoleMu.Lock()
	for id := range consoleReads {
		if _, ok := live[id]; !ok {
			delete(consoleReads, id) // gone: EC2 keeps no console of a terminated instance
		}
	}
	consoleMu.Unlock()
	for id, region := range live {
		out, err := awsConsole(region, id)
		if err != nil {
			if e, ok := err.(*ec2ReadError); ok && e.Code == "UnauthorizedOperation" {
				consoleMu.Lock()
				consoleOff = time.Now().Add(10 * time.Minute)
				consoleMu.Unlock()
				log.Printf("[aws-logs] the read key may not GetConsoleOutput (infra/aws/iam.tf jarvis4-router-read): no console lines for 10 min")
				return
			}
			continue
		}
		consoleMu.Lock()
		cr := consoleReads[id]
		if cr == nil {
			cr = &consoleRead{}
			consoleReads[id] = cr
		}
		lines, next := consoleNew(cr.shipped, out)
		cr.shipped = next
		consoleMu.Unlock()
		if len(lines) == 0 {
			continue
		}
		var session string
		r.st.Do(func(d *persisted) { session = d.Machines[id] })
		now := time.Now()
		ats := make([]time.Time, len(lines))
		for i := range lines {
			ats[i] = now.Add(time.Duration(i-len(lines)) * time.Microsecond) // one read, its lines in order
		}
		awsLogs.ship(awsLogLabels(id, region, session, "console"), ats, lines)
		if session == "" {
			continue
		}
		if h := r.lcCurrent(session); h != nil {
			for _, l := range lines {
				if consoleNotableRE.MatchString(l) && !strings.Contains(l, keysLineMark) {
					h.add(LcEntry{At: now.UTC().Format(time.RFC3339Nano), Source: "aws", Machine: id, Text: "AWS console: " + l})
				}
			}
		}
	}
}

// keysLineMark: the machine's keys line on the console (kernel/spawner keysMark): shipped, never a lifecycle entry
const keysLineMark = "JARVIS2-KEYS "

// consoleLoop: consoleTick every consoleEvery on the replica holding the scheduler's lease
func (r *Router) consoleLoop() {
	for {
		time.Sleep(consoleEvery)
		if leads() {
			r.consoleTick()
		}
	}
}
