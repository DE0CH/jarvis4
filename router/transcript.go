package main

// Reading a Claude Code transcript (JSONL) for people: the last messages and the title (Jarvis 1
// lib/archive.js parseTranscript). Only what was said: user prompts and assistant text. Tool calls and
// results, meta lines, sidechains (subagents) and injected <system-reminder>-style blocks are left out. The
// title is what the Claude app showed: the last custom-title (a rename), else the last ai-title. A message
// typed while Claude was mid-turn only exists as a queue-operation enqueue, so those count as user messages
// too (deduplicated against the user record a normally delivered one also gets).

import (
	"archive/tar"
	"encoding/json"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

const tailBytes = 2 << 20 // how much of a transcript's end is read for its tail

type TailMessage struct {
	Role string `json:"role"`
	Text string `json:"text"`
	At   any    `json:"at"`
}

type Tail struct {
	Title     string        `json:"title"`
	SessionID string        `json:"sessionId"`
	Messages  []TailMessage `json:"messages"`
	// Stale: the session runs, so this is its last pause snapshot's tail, older than what it is doing now
	Stale bool `json:"stale,omitempty"`
}

// injected: one pattern per tag (Go's regexp has no backreferences to pair the open and close tags)
var injected = func() []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, t := range []string{"system-reminder", "task-notification", "local-command-stdout", "command-name", "command-message", "command-args"} {
		out = append(out, regexp.MustCompile(`(?s)<`+t+`>.*?</`+t+`>`))
	}
	return out
}()

func clipText(t string, n int) string {
	r := []rune(t)
	if len(r) <= n {
		return t
	}
	return string(r[:n])
}

// parseTranscript: partialFirstLine when text starts mid-file (a tail read); max messages, clip runes each
func parseTranscript(text string, partialFirstLine bool, max, clip int) Tail {
	lines := strings.Split(text, "\n")
	if partialFirstLine && len(lines) > 0 {
		lines = lines[1:]
	}
	var aiTitle, customTitle, sid string
	type msg struct {
		TailMessage
		queued bool
	}
	var msgs []msg
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var j struct {
			Type        string          `json:"type"`
			SessionID   string          `json:"sessionId"`
			AiTitle     string          `json:"aiTitle"`
			CustomTitle string          `json:"customTitle"`
			Operation   string          `json:"operation"`
			Content     json.RawMessage `json:"content"`
			Timestamp   any             `json:"timestamp"`
			IsSidechain bool            `json:"isSidechain"`
			IsMeta      bool            `json:"isMeta"`
			Message     *struct {
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal([]byte(l), &j) != nil {
			continue
		}
		if j.SessionID != "" && sid == "" {
			sid = j.SessionID
		}
		switch {
		case j.Type == "ai-title" && j.AiTitle != "":
			aiTitle = j.AiTitle
			continue
		case j.Type == "custom-title" && j.CustomTitle != "":
			customTitle = j.CustomTitle
			continue
		case j.Type == "queue-operation" && j.Operation == "enqueue":
			var c string
			if json.Unmarshal(j.Content, &c) == nil && !strings.HasPrefix(strings.TrimLeft(c, " \t\r\n"), "<") {
				msgs = append(msgs, msg{TailMessage{"user", clipText(strings.TrimSpace(c), clip), j.Timestamp}, true})
			}
			continue
		}
		if (j.Type != "user" && j.Type != "assistant") || j.IsSidechain || j.IsMeta || j.Message == nil {
			continue
		}
		t := contentText(j.Message.Content)
		for _, re := range injected {
			t = re.ReplaceAllString(t, "")
		}
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if j.Type == "user" {
			for i, m := range msgs {
				if m.queued && m.Text == clipText(t, clip) {
					msgs = append(msgs[:i], msgs[i+1:]...)
					break
				}
			}
		}
		if len([]rune(t)) > clip {
			t = clipText(t, clip) + " …"
		}
		msgs = append(msgs, msg{TailMessage{j.Type, t, j.Timestamp}, false})
	}
	if len(msgs) > max {
		msgs = msgs[len(msgs)-max:]
	}
	out := Tail{Title: customTitle, SessionID: sid, Messages: []TailMessage{}}
	if out.Title == "" {
		out.Title = aiTitle
	}
	for _, m := range msgs {
		out.Messages = append(out.Messages, m.TailMessage)
	}
	return out
}

func contentText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return ""
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n\n")
}

// tailOf: the tail of a transcript's text (the whole file or its last bytes)
func tailOf(text []byte) Tail {
	return parseTranscript(string(text), len(text) >= tailBytes, 40, 4000)
}

// snippet: what a conversation ended on, for a card
func snippet(t Tail) *TailMessage {
	if len(t.Messages) == 0 {
		return nil
	}
	m := t.Messages[len(t.Messages)-1]
	m.Text = clipText(strings.Join(strings.Fields(m.Text), " "), 280)
	return &m
}

// ---- inside a snapshot (tar.gz relative to $HOME) ------------------------------------------------------

// isTranscript: .claude/projects/<project>/<id>.jsonl
func isTranscript(name string) bool {
	name = path.Clean(name)
	m, _ := path.Match(".claude/projects/*/*.jsonl", name)
	return m
}

type tailBuf struct {
	b []byte
	n int
}

func (t *tailBuf) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 2*t.n {
		t.b = append([]byte{}, t.b[len(t.b)-t.n:]...)
	}
	return len(p), nil
}

func (t *tailBuf) bytes() []byte {
	if len(t.b) > t.n {
		return t.b[len(t.b)-t.n:]
	}
	return t.b
}

// snapshotFacts: one pass over a snapshot: the tail of its newest transcript and the repos' changes file
type snapshotFacts struct {
	Transcripts []string // newest last
	Tail        *Tail
	Changes     *string
}

func readSnapshotFacts(p string) (*snapshotFacts, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readSnapshotFactsFrom(f)
}

// readSnapshotFactsFrom: the facts of a snapshot's bytes (snapformat.go), read through once
func readSnapshotFactsFrom(f io.Reader) (*snapshotFacts, error) {
	gz, err := openSnapReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := &snapshotFacts{}
	var newest time.Time
	var newestTail []byte
	type tx struct {
		name string
		at   time.Time
	}
	var all []tx
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(h.Name)
		switch {
		case isTranscript(name):
			all = append(all, tx{name, h.ModTime})
			if newestTail == nil || !h.ModTime.Before(newest) {
				tb := &tailBuf{n: tailBytes}
				if _, err := io.Copy(tb, tr); err != nil {
					return nil, err
				}
				newest, newestTail = h.ModTime, tb.bytes()
			}
		case name == changesFile:
			b, err := io.ReadAll(io.LimitReader(tr, 1<<20))
			if err != nil {
				return nil, err
			}
			s := string(b)
			out.Changes = &s
		}
	}
	for i := 1; i < len(all); i++ { // oldest first (insertion sort: a handful of files)
		for k := i; k > 0 && all[k].at.Before(all[k-1].at); k-- {
			all[k], all[k-1] = all[k-1], all[k]
		}
	}
	for _, t := range all {
		out.Transcripts = append(out.Transcripts, t.name)
	}
	if newestTail != nil {
		t := tailOf(newestTail)
		out.Tail = &t
	}
	return out, nil
}
