package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDiscord: just enough of Discord's REST API, in memory
type fakeDiscord struct {
	mu       sync.Mutex
	channels map[string]*discordChannel
	messages map[string][]map[string]any // channel → newest first
	posted   map[string][]string
	calls    []string
	rate     map[string]int // "METHOD path" → 429s still to answer
	next     int
}

func newFakeDiscord() *fakeDiscord {
	return &fakeDiscord{channels: map[string]*discordChannel{}, messages: map[string][]map[string]any{}, posted: map[string][]string{}, rate: map[string]int{}, next: 100}
}

func (f *fakeDiscord) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := req.Method + " " + req.URL.Path
	f.calls = append(f.calls, key)
	if req.Header.Get("Authorization") != "Bot tok" {
		w.WriteHeader(401)
		return
	}
	if f.rate[key] > 0 {
		f.rate[key]--
		w.WriteHeader(429)
		io.WriteString(w, `{"retry_after":0.25,"global":false}`)
		return
	}
	var body map[string]any
	json.NewDecoder(req.Body).Decode(&body)
	p := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	out := func(v any) { json.NewEncoder(w).Encode(v) }
	switch {
	case len(p) == 3 && p[0] == "guilds" && req.Method == "GET":
		list := []*discordChannel{}
		for _, c := range f.channels {
			if c.GuildID == p[1] {
				list = append(list, c)
			}
		}
		out(list)
	case len(p) == 3 && p[0] == "guilds" && req.Method == "POST":
		f.next++
		c := &discordChannel{ID: strconv.Itoa(f.next), GuildID: p[1]}
		c.Name, _ = body["name"].(string)
		c.Topic, _ = body["topic"].(string)
		c.ParentID, _ = body["parent_id"].(string)
		t, _ := body["type"].(float64)
		c.Type = int(t)
		f.channels[c.ID] = c
		out(c)
	case len(p) == 2 && p[0] == "channels":
		c := f.channels[p[1]]
		if c == nil {
			w.WriteHeader(404)
			return
		}
		switch req.Method {
		case "GET":
			out(c)
		case "PATCH":
			if n, ok := body["name"].(string); ok {
				c.Name = n
			}
			if t, ok := body["topic"].(string); ok {
				c.Topic = t
			}
			out(c)
		case "DELETE":
			delete(f.channels, p[1])
			out(c)
		}
	case len(p) == 3 && p[0] == "channels" && p[2] == "messages" && req.Method == "POST":
		f.posted[p[1]] = append(f.posted[p[1]], body["content"].(string))
		out(map[string]string{"id": "m"})
	case len(p) == 3 && p[0] == "channels" && p[2] == "messages" && req.Method == "GET":
		all := f.messages[p[1]]
		limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))
		start := 0
		if b := req.URL.Query().Get("before"); b != "" {
			for i, m := range all {
				if m["id"] == b {
					start = i + 1
				}
			}
		}
		end := min(start+limit, len(all))
		out(all[start:end])
	default:
		w.WriteHeader(404)
	}
}

func testDiscord(t *testing.T) (*fakeDiscord, *discordClient, *[]time.Duration) {
	f := newFakeDiscord()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	slept := &[]time.Duration{}
	d := &discordClient{api: srv.URL, token: "tok", guild: "g1", dm: "dm1", category: "Jarvis 4", channels: true,
		http: srv.Client(), maxWait: 30 * time.Second, sleep: func(x time.Duration) { *slept = append(*slept, x) },
		now: time.Now, names: map[string]*discordChanInfo{}}
	return f, d, slept
}

func TestChannelName(t *testing.T) {
	for in, want := range map[string]string{
		"Fix the Jarvis 4 router!": "fix-the-jarvis-4-router",
		"  --Café déjà vu-- ":      "cafe-deja-vu",
		"深圳 hotel":                 "深圳-hotel",
		"":                         "session-89abcdef",
		"!!!":                      "session-89abcdef",
		strings.Repeat("a", 120):   strings.Repeat("a", 90),
	} {
		in2 := in
		if in == "  --Café déjà vu-- " {
			in2 = "  --Café déjà vu-- " // decomposed: the marks drop
		}
		if got := channelName(in2, "s0123456789abcdef"); got != want {
			t.Errorf("channelName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSessionTitleOrder(t *testing.T) {
	s := Session{ID: "s1", Label: "label", Title: "ai"}
	if sessionTitle(s) != "label" {
		t.Fatal("label should beat the AI title")
	}
	s.UserTitle = "mine"
	if sessionTitle(s) != "mine" {
		t.Fatal("Deyao's rename should beat the label")
	}
	s.AppTitle = "the app's"
	if sessionTitle(s) != "the app's" {
		t.Fatal("the Claude app's title should beat everything (Jarvis 1's serverTitle)")
	}
	if sessionTitle(Session{ID: "s1", Title: "ai"}) != "ai" || sessionTitle(Session{ID: "s1"}) != "s1" {
		t.Fatal("fallbacks")
	}
}

func TestSplitMessage(t *testing.T) {
	text := strings.Repeat("x", 1500) + "\n" + strings.Repeat("y", 1000)
	parts := splitMessage(text)
	if len(parts) != 2 || parts[0] != strings.Repeat("x", 1500)+"\n" || parts[1] != strings.Repeat("y", 1000) {
		t.Fatalf("split on the line break: %d parts", len(parts))
	}
	parts = splitMessage(strings.Repeat("z", 4500))
	if len(parts) != 3 || len(parts[0]) != 2000 || len(parts[2]) != 500 {
		t.Fatalf("hard split: %d parts", len(parts))
	}
}

func TestRateLimitRetries(t *testing.T) {
	f, d, slept := testDiscord(t)
	f.rate["POST /channels/dm1/messages"] = 2
	if err := d.send("dm1", "hello"); err != nil {
		t.Fatal(err)
	}
	if len(f.posted["dm1"]) != 1 || len(*slept) != 2 || (*slept)[0] != 250*time.Millisecond {
		t.Fatalf("posted %v slept %v", f.posted["dm1"], *slept)
	}
	// a wait longer than maxWait fails at once, without sleeping
	d.maxWait = 100 * time.Millisecond
	f.rate["POST /channels/dm1/messages"] = 1
	err := d.send("dm1", "again")
	if _, ok := err.(*errDiscordRateLimited); !ok || len(*slept) != 2 {
		t.Fatalf("err %v slept %v", err, *slept)
	}
	// always 429: gives up after 3 retries
	d.maxWait = time.Minute
	f.rate["POST /channels/dm1/messages"] = 10
	if err := d.send("dm1", "x"); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("want a 429 error, got %v", err)
	}
}

func TestEnsureChannelAndCategory(t *testing.T) {
	f, d, _ := testDiscord(t)
	// Jarvis 1's category exists and is left alone
	f.channels["1"] = &discordChannel{ID: "1", Type: 4, Name: "Sessions", GuildID: "g1"}
	ch, created, err := d.ensureChannel("", "s1", "My task")
	if err != nil || !created {
		t.Fatal(err, created)
	}
	cat := f.channels[ch.ParentID]
	if cat == nil || cat.Name != "Jarvis 4" || cat.Type != 4 || ch.Name != "my-task" || ch.Topic != "Jarvis 4 session s1" {
		t.Fatalf("channel %+v category %+v", ch, cat)
	}
	// the category is reused
	ch2, _, _ := d.ensureChannel("", "s2", "other")
	if ch2.ParentID != ch.ParentID {
		t.Fatal("a second category")
	}
	// the carried channel is kept
	again, created, err := d.ensureChannel(ch.ID, "s1", "My task")
	if err != nil || created || again.ID != ch.ID {
		t.Fatal("carried channel not reused", err, created)
	}
	// deleted by hand → a new one
	delete(f.channels, ch.ID)
	again, created, _ = d.ensureChannel(ch.ID, "s1", "My task")
	if !created || again.ID == ch.ID {
		t.Fatal("a gone channel should be replaced")
	}
	// another guild's channel id → a new one
	f.channels["999"] = &discordChannel{ID: "999", GuildID: "other"}
	if c, created, _ := d.ensureChannel("999", "s3", "x"); !created || c.ID == "999" {
		t.Fatal("another guild's channel was reused")
	}
}

func TestSyncNameRenameLimit(t *testing.T) {
	f, d, _ := testDiscord(t)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	ch, _, _ := d.ensureChannel("", "s1", "first")
	patches := func() int {
		n := 0
		for _, c := range f.calls {
			if c == "PATCH /channels/"+ch.ID {
				n++
			}
		}
		return n
	}
	if ok, _ := d.syncName(ch.ID, "first", "s1"); ok || patches() != 0 {
		t.Fatal("no change should not PATCH")
	}
	for i, title := range []string{"second", "third", "fourth"} {
		ok, err := d.syncName(ch.ID, title, "s1")
		if err != nil || ok != (i < 2) {
			t.Fatalf("rename %d: ok=%v err=%v", i, ok, err)
		}
	}
	if patches() != 2 || f.channels[ch.ID].Name != "third" {
		t.Fatalf("2 renames per window: %d patches, name %s", patches(), f.channels[ch.ID].Name)
	}
	now = now.Add(discordEditWindow + time.Second)
	if ok, _ := d.syncName(ch.ID, "fourth", "s1"); !ok || f.channels[ch.ID].Name != "fourth" {
		t.Fatal("the window should reopen")
	}
	// a channel first seen after a router restart: learned with one GET
	d.mu.Lock()
	d.names = map[string]*discordChanInfo{}
	d.mu.Unlock()
	if ok, _ := d.syncName(ch.ID, "fourth", "s1"); ok {
		t.Fatal("unchanged after learning")
	}
}

type memSink struct{ files map[string][]byte }

func (m *memSink) putBytes(rel string, b []byte, _ string) error {
	m.files[rel] = b
	return nil
}

func TestExportChannel(t *testing.T) {
	f, d, _ := testDiscord(t)
	ch, _, _ := d.ensureChannel("", "s1", "t")
	// 150 messages, newest first as Discord pages them; two carry attachments, one of which fails
	var msgs []map[string]any
	for i := 150; i >= 1; i-- {
		m := map[string]any{"id": fmt.Sprintf("%04d", i), "content": fmt.Sprintf("msg %d", i)}
		if i == 3 {
			m["attachments"] = []any{map[string]any{"id": "a1", "filename": "shot/1.png", "url": "ok://1", "content_type": "image/png"}}
		}
		if i == 120 {
			m["attachments"] = []any{map[string]any{"id": "a2", "filename": "x.txt", "url": "bad://2"}}
		}
		msgs = append(msgs, m)
	}
	f.messages[ch.ID] = msgs
	sink := &memSink{files: map[string][]byte{}}
	fetch := func(u string) ([]byte, error) {
		if u == "ok://1" {
			return []byte("PNG"), nil
		}
		return nil, fmt.Errorf("HTTP 403")
	}
	res, err := d.exportChannel(ch.ID, sink, fetch)
	if err != nil {
		t.Fatal(err)
	}
	if res.Messages != 150 || res.Attachments != 1 || res.AttachmentsFailed != 1 {
		t.Fatalf("%+v", res)
	}
	if string(sink.files["attachments/0003-shot_1.png"]) != "PNG" {
		t.Fatalf("attachment not saved: %v", keys(sink.files))
	}
	var out struct {
		Channel  map[string]string
		Messages []map[string]any
	}
	if err := json.Unmarshal(sink.files["messages.json"], &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Messages) != 150 || out.Messages[0]["id"] != "0001" || out.Messages[149]["id"] != "0150" || out.Channel["id"] != ch.ID {
		t.Fatalf("messages not oldest first: %d", len(out.Messages))
	}
	a := out.Messages[2]["attachments"].([]any)[0].(map[string]any)
	b := out.Messages[119]["attachments"].([]any)[0].(map[string]any)
	if a["exported"] != "attachments/0003-shot_1.png" || b["exportError"] != "HTTP 403" {
		t.Fatalf("attachment notes: %v %v", a, b)
	}
	// a gone channel exports nothing
	if res, err := d.exportChannel("nope", sink, fetch); res != nil || err != nil {
		t.Fatal("gone channel")
	}
}

// destroy: the channel goes into the session's archive (discordExport into the archive's scratch dir), and is
// deleted only once the archive holds it; a failed export, or no archive, keeps it and tells Deyao
func TestDestroyExportsAndDeletes(t *testing.T) {
	f, d, _ := testDiscord(t)
	oldDisc, oldFetch, oldDM := disc, discFetch, dmHook
	defer func() { disc, discFetch, dmHook = oldDisc, oldFetch, oldDM }()
	disc, discFetch = d, func(string) ([]byte, error) { return []byte("bytes"), nil }
	var dms []string
	dmHook = func(t string) { dms = append(dms, t) }

	st, _ := testState(t, t.TempDir())
	r := &Router{st: st}
	s := &Session{ID: "s1", Label: "My task", Created: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)}
	st.Do(func(d *persisted) { d.Sessions[s.ID] = s })

	// start: a channel, its id in the env and on the session
	env := map[string]string{}
	copyS := *s
	discordEnv(r, &copyS, env)
	var stored string
	st.Do(func(d *persisted) { stored = d.Sessions["s1"].DiscordChannel })
	if env["LOBSTER_CHANNEL"] == "" || env["LOBSTER_CHANNEL"] != stored {
		t.Fatalf("env %v stored %q", env, stored)
	}
	f.messages[stored] = []map[string]any{{"id": "2", "content": "done", "attachments": []any{map[string]any{"id": "a", "filename": "f.txt", "url": "x"}}}, {"id": "1", "content": "hi"}}
	copyS.DiscordChannel = stored

	// no archive: the channel is kept and Deyao told
	discordDestroy(r, copyS)
	if f.channels[stored] == nil || len(dms) != 1 {
		t.Fatalf("channel should be kept without an archive (dms %v)", dms)
	}

	// the archive's export: the files in its scratch dir; then the destroy deletes the channel
	tmp := t.TempDir()
	dir, done := r.discordExport(copyS, tmp)
	if dir == "" {
		t.Fatal("no export")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "attachments", "2-f.txt")); string(b) != "bytes" {
		t.Fatalf("attachment %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "messages.json")); len(b) == 0 {
		t.Fatal("no messages.json")
	}
	// the archive holding it failed (a forced destroy goes on): the channel is kept, Deyao told
	done(errors.New("PUT: HTTP 507"))
	discordDestroy(r, copyS)
	if f.channels[stored] == nil || len(dms) != 2 {
		t.Fatalf("channel should be kept when its archive failed (dms %v)", dms)
	}
	// on the Storage Box: the destroy deletes the channel
	done(nil)
	discordDestroy(r, copyS)
	if f.channels[stored] != nil || len(dms) != 2 {
		t.Fatalf("channel not deleted after the export (dms %v)", dms)
	}
	// gone already: nothing is exported
	if d, _ := r.discordExport(copyS, t.TempDir()); d != "" {
		t.Fatal("exported a deleted channel")
	}
}

func TestTickRenamesAndFillsMissing(t *testing.T) {
	f, d, _ := testDiscord(t)
	old := disc
	defer func() { disc = old }()
	disc = d
	st, _ := testState(t, t.TempDir())
	r := &Router{st: st}
	ch, _, _ := d.ensureChannel("", "s1", "old name")
	st.Do(func(p *persisted) {
		p.Sessions["s1"] = &Session{ID: "s1", State: "started", MachineID: "m1", Title: "New AI title", DiscordChannel: ch.ID}
		p.Sessions["s2"] = &Session{ID: "s2", State: "started", MachineID: "m2", Label: "no channel yet"}
		p.Sessions["s3"] = &Session{ID: "s3", State: "approval", Label: "waits"}
	})
	r.discordTick()
	if f.channels[ch.ID].Name != "new-ai-title" {
		t.Fatalf("not renamed: %s", f.channels[ch.ID].Name)
	}
	var s2, s3 string
	st.Do(func(p *persisted) { s2, s3 = p.Sessions["s2"].DiscordChannel, p.Sessions["s3"].DiscordChannel })
	if s2 == "" || f.channels[s2].Name != "no-channel-yet" || s3 != "" {
		t.Fatalf("s2 %q s3 %q", s2, s3)
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
