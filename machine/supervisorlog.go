package main

// The supervisor log: what boot and the supervisor do, one JSON line each ({"at","text"}) in supervisorLogPath
// (tmpfs, this machine only). The boot steps, the keeper and the worker append to it (each write opens the file, so a rotation
// never loses a line); the worker pushes new lines to the router (POST /m/supervisor-log), which keeps the session's
// log for its whole life and shows it in the app (Supervisor log, and inside each Lifecycle log). The lines name
// commands, ids, counts, key names and errors, never a command's text, a prompt or a secret value; as a second line
// of defence every value the supervisor holds (8 characters or more) is replaced by [secret] before a line leaves.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	supervisorLogPath = dir + "/supervisor.log"
	supervisorLogSent = dir + "/supervisor.log.sent" // how far the push got (bytes), across worker restarts
	supervisorLogRoll = int64(2 << 20)               // rotate once everything is pushed and the file is this big
	supervisorLogTag  = "supervisor"
	logPushEvery      = 2 * time.Second
)

const (
	maxLogLine  = 2000
	maxLogBatch = 500
)

type logLine struct {
	At   string `json:"at"`
	Text string `json:"text"`
}

// fileLog: one JSON line per log call (the log package writes each message in one Write)
type fileLog struct{ path, tag string }

func (f fileLog) Write(p []byte) (int, error) {
	text := strings.TrimSuffix(strings.TrimPrefix(string(p), "[jarvis] "), "\n")
	b, _ := json.Marshal(logLine{At: time.Now().UTC().Format(time.RFC3339Nano), Text: f.tag + ": " + text})
	if fh, err := os.OpenFile(f.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
		if privileged() { // the keeper (root): the file stays user claude's, as the worker reads and rotates it
			fh.Chown(session().uid, session().gid)
		}
		fh.Write(append(b, '\n'))
		fh.Close()
	}
	return len(p), nil
}

// logToSupervisorLog: this process's log lines also go to the supervisor log
func logToSupervisorLog() {
	tag := supervisorLogTag
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "prepare":
			tag = "boot"
		case "boot":
			tag = "keeper"
		case "supervisor":
			if len(os.Args) > 2 && os.Args[2] == "--normal" {
				tag = "supervisor-normal"
			}
		}
	}
	log.SetOutput(io.MultiWriter(os.Stderr, fileLog{supervisorLogPath, tag}))
}

// pushSupervisorLog: supervisor-core's push loop (supervisor-normal's lines are in the same file)
func pushSupervisorLog(c *client) {
	for ; ; time.Sleep(logPushEvery) {
		pushLogOnce(c)
	}
}

var pushMu sync.Mutex

// pushLogOnce: everything not yet pushed, in batches; then the rotation when it is due
func pushLogOnce(c *client) error {
	pushMu.Lock()
	defer pushMu.Unlock()
	off := readOffset()
	n, err := pushFrom(c, supervisorLogPath, off)
	off += n
	writeOffset(off)
	if err != nil {
		return err
	}
	if st, err := os.Stat(supervisorLogPath); err == nil && st.Size() >= supervisorLogRoll && off >= st.Size() {
		old := supervisorLogPath + ".old"
		if os.Rename(supervisorLogPath, old) == nil {
			time.Sleep(50 * time.Millisecond) // a write that opened the old file just before
			pushFrom(c, old, off)
			os.Remove(old)
			writeOffset(0)
		}
	}
	return nil
}

func readOffset() int64 {
	s, _ := readTrim(supervisorLogSent)
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func writeOffset(n int64) { os.WriteFile(supervisorLogSent, []byte(strconv.FormatInt(n, 10)), 0o600) }

// pushFrom: the complete lines of path after off, pushed; returns the bytes pushed
func pushFrom(c *client, path string, off int64) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	rd := bufio.NewReaderSize(f, 64<<10)
	red := secretRedactor()
	var done int64
	for {
		var batch []logLine
		var size int64
		for len(batch) < maxLogBatch {
			b, err := rd.ReadBytes('\n')
			if err != nil { // an unfinished last line waits for the next round
				break
			}
			size += int64(len(b))
			var l logLine
			if json.Unmarshal(bytes.TrimSpace(b), &l) != nil {
				continue
			}
			l.Text = red(l.Text)
			if len(l.Text) > maxLogLine {
				l.Text = l.Text[:maxLogLine-3] + "…"
			}
			batch = append(batch, l)
		}
		if size == 0 {
			return done, nil
		}
		if len(batch) > 0 {
			_, _, status, err := c.raw("POST", "/m/supervisor-log", mustJSON(map[string]any{"lines": batch}))
			if err != nil {
				return done, err
			}
			if status == 404 || status == 405 { // a router without the supervisor log: try again later
				time.Sleep(time.Minute)
				return done, nil
			}
			if status != 200 {
				return done, errHTTP(status)
			}
		}
		done += size
	}
}

type errHTTP int

func (e errHTTP) Error() string { return "HTTP " + strconv.Itoa(int(e)) }

// secretRedactor: replaces every value the supervisor holds (secrets.go) of 8 characters or more
var secretRedactor = func() func(string) string {
	var vals []string
	for _, v := range held.snapshot() {
		if len(v) >= 8 {
			vals = append(vals, v)
		}
		for _, l := range strings.Split(v, "\n") { // a multi-line value's lines on their own (a PEM in an error)
			if l = strings.TrimSpace(l); len(l) >= 16 && l != v {
				vals = append(vals, l)
			}
		}
	}
	return func(s string) string {
		for _, v := range vals {
			if strings.Contains(s, v) {
				s = strings.ReplaceAll(s, v, "[secret]")
			}
		}
		return s
	}
}
