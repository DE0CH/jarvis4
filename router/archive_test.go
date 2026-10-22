package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- an in-memory WebDAV server (the Storage Box) ------------------------------------------------------

type memDAV struct {
	mu    sync.Mutex
	files map[string][]byte
	dirs  map[string]bool
	fail  string // a path prefix whose PUTs fail
}

func newMemDAV() *memDAV { return &memDAV{files: map[string][]byte{}, dirs: map[string]bool{}} }

func (m *memDAV) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, p, ok := req.BasicAuth(); !ok || u != "u" || p != "p" {
		w.WriteHeader(401)
		return
	}
	p := strings.Trim(req.URL.Path, "/")
	switch req.Method {
	case "MKCOL":
		if m.dirs[p] {
			w.WriteHeader(405)
			return
		}
		if parent := filepath.Dir(p); parent != "." && !m.dirs[parent] {
			w.WriteHeader(409)
			return
		}
		m.dirs[p] = true
		w.WriteHeader(201)
	case "PUT":
		if m.fail != "" && strings.HasPrefix(p, m.fail) {
			w.WriteHeader(507)
			return
		}
		if parent := filepath.Dir(p); parent != "." && !m.dirs[parent] {
			w.WriteHeader(409)
			return
		}
		b, _ := io.ReadAll(req.Body)
		m.files[p] = b
		w.WriteHeader(201)
	case "GET", "HEAD":
		b, ok := m.files[p]
		if !ok {
			w.WriteHeader(404)
			return
		}
		if rg := req.Header.Get("Range"); strings.HasPrefix(rg, "bytes=-") {
			n, _ := strconv.Atoi(strings.TrimPrefix(rg, "bytes=-"))
			if n < len(b) {
				b = b[len(b)-n:]
			}
			w.WriteHeader(206)
		}
		w.Write(b)
	case "DELETE":
		found := false
		for f := range m.files {
			if f == p || strings.HasPrefix(f, p+"/") {
				delete(m.files, f)
				found = true
			}
		}
		for d := range m.dirs {
			if d == p || strings.HasPrefix(d, p+"/") {
				delete(m.dirs, d)
				found = true
			}
		}
		if !found {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(204)
	case "PROPFIND": // Depth 0 or 1, as Apache mod_dav answers (content.go)
		isDir := p == "" || m.dirs[p]
		if _, ok := m.files[p]; !ok && !isDir {
			w.WriteHeader(404)
			return
		}
		type ent struct {
			href string
			dir  bool
			size int
		}
		ents := []ent{{"/" + p, isDir, len(m.files[p])}}
		if isDir && req.Header.Get("Depth") == "1" {
			for f, b := range m.files {
				if filepath.Dir(f) == p || (p == "" && !strings.Contains(f, "/")) {
					ents = append(ents, ent{"/" + f, false, len(b)})
				}
			}
			for d := range m.dirs {
				if filepath.Dir(d) == p && d != p {
					ents = append(ents, ent{"/" + d + "/", true, 0})
				}
			}
		}
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">`)
		for _, e := range ents {
			href := e.href
			if e.dir && !strings.HasSuffix(href, "/") {
				href += "/"
			}
			rt := "<D:resourcetype/>"
			if e.dir {
				rt = "<D:resourcetype><D:collection/></D:resourcetype>"
			}
			fmt.Fprintf(&b, `<D:response><D:href>%s</D:href><D:propstat><D:prop>%s<lp1:getcontentlength xmlns:lp1="DAV:">%d</lp1:getcontentlength><lp1:getlastmodified xmlns:lp1="DAV:">Mon, 12 Oct 2026 10:00:00 GMT</lp1:getlastmodified></D:prop></D:propstat></D:response>`,
				(&url.URL{Path: href}).EscapedPath(), rt, e.size)
		}
		b.WriteString(`</D:multistatus>`)
		w.WriteHeader(207)
		w.Write([]byte(b.String()))
	default:
		w.WriteHeader(405)
	}
}

func (m *memDAV) get(p string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.files[p]
}

func (m *memDAV) under(dir string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for f := range m.files {
		if strings.HasPrefix(f, dir+"/") {
			out = append(out, strings.TrimPrefix(f, dir+"/"))
		}
	}
	sort.Strings(out)
	return out
}

// ---- keys, a fake core, a snapshot -------------------------------------------------------------------

type key struct{ k *ecdh.PrivateKey }

func newTestKey() key { k, _ := ecdh.P256().GenerateKey(rand.Reader); return key{k} }
func (k key) pub() string {
	return base64.StdEncoding.EncodeToString(k.k.PublicKey().Bytes())
}
func (k key) doc(v any) *Doc {
	b, _ := json.Marshal(v)
	s, _ := signP256(k.k, b)
	return &Doc{Payload: string(b), Sig: s}
}

type fakeCore struct {
	key   key
	calls []string
	mu    sync.Mutex
}

func (c *fakeCore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c.mu.Lock()
	c.calls = append(c.calls, req.URL.Path)
	c.mu.Unlock()
	switch req.URL.Path {
	case "/key":
		writeJSON(w, 200, map[string]string{"signingKey": c.key.pub()})
	case "/identity": // a set-up core (features.go coreSetUp)
		writeJSON(w, 200, map[string]any{"signingKey": c.key.pub(), "state": c.key.doc(map[string]string{"kind": "core-state", "master": "m"})})
	case "/core-cert":
		writeJSON(w, 200, map[string]string{"statement": "{}", "masterSig": "x"})
	case "/kill": // the core's record names the snapshot the kill named (core.go KillWithSnapshot)
		var in struct {
			Machine  string `json:"machine"`
			Snapshot *struct {
				Sha256 string `json:"sha256"`
			} `json:"snapshot"`
		}
		json.NewDecoder(req.Body).Decode(&in)
		sum := ""
		if in.Snapshot != nil {
			sum = in.Snapshot.Sha256
		}
		writeJSON(w, 200, c.key.doc(map[string]any{"kind": "killed", "id": in.Machine, "snapshot": sum, "path": req.URL.Path}))
	default:
		writeJSON(w, 200, c.key.doc(map[string]string{"kind": "ok", "path": req.URL.Path}))
	}
}

type tfile struct {
	name, body, link string
	at               time.Time
}

func makeTar(t *testing.T, files []tfile) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		h := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), ModTime: f.at, Typeflag: tar.TypeReg}
		if f.link != "" {
			h.Typeflag, h.Linkname, h.Size = tar.TypeSymlink, f.link, 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(f.body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func line(v map[string]any) string { b, _ := json.Marshal(v); return string(b) + "\n" }

type rig struct {
	r     *Router
	dav   *memDAV
	core  *fakeCore
	mkey  key
	cert  *Doc
	stop  func()
	files []tfile
}

// newRig: a router with one paused session "s1" whose machine m1 left a signed snapshot
func newRig(t *testing.T) *rig {
	t.Helper()
	t.Setenv("RECORDS_OFF", "")
	putBackoff = time.Millisecond
	dav := newMemDAV()
	ds := httptest.NewServer(dav)
	core := &fakeCore{key: newTestKey()}
	cs := httptest.NewServer(core)
	st, err := testState(t, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pol := Policy{Harnesses: map[string]HarnessPolicy{"claude": {Stores: []string{"tunnel"}}}}
	r := NewRouter(Config{DataDir: st.dir, SnapshotStall: time.Second, SessionImage: "img"}, st, &CoreClient{base: cs.URL, http: http.DefaultClient}, pol)
	sboxOnce.Do(func() {})
	sbox = newStorageBox(ds.URL, "u", "p")
	mkey := newTestKey()
	cert := core.key.doc(map[string]any{"kind": "succession-cert", "predecessorId": "", "line": "m1",
		"machine": map[string]string{"id": "m1", "signingKey": mkey.pub()}, "stores": []string{"default"}})
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	files := []tfile{
		{name: ".claude/projects/-home-claude-workspace/aaaa.jsonl", at: t0,
			body: line(map[string]any{"type": "user", "sessionId": "aaaa", "message": map[string]any{"content": "old one"}})},
		{name: ".claude/projects/-home-claude-workspace/bbbb.jsonl", at: t0.Add(time.Hour),
			body: line(map[string]any{"type": "ai-title", "aiTitle": "Fix the: router"}) +
				line(map[string]any{"type": "user", "sessionId": "bbbb", "message": map[string]any{"content": "hello"}}) +
				line(map[string]any{"type": "assistant", "message": map[string]any{"content": []map[string]string{{"type": "text", "text": "done it"}}}})},
		{name: "artifacts/record.md", body: "# record", at: t0},
		{name: "artifacts/sub/shot.png", body: "png", at: t0},
		{name: "artifacts/report.html", link: "../workspace/proj/out/report.html", at: t0},
		{name: "artifacts/proj", link: "/home/claude/workspace/proj/out", at: t0},
		{name: "artifacts/outside", link: "/etc/passwd", at: t0},
		{name: "workspace/proj/out/report.html", body: "<p>r</p>", at: t0},
		{name: changesFile, body: "proj 2 1\nother 0 -1\n", at: t0},
	}
	rg := &rig{r: r, dav: dav, core: core, mkey: mkey, cert: cert, files: files, stop: func() { ds.Close(); cs.Close() }}
	rg.writeSnapshot(t, "m1", files)
	r.st.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", State: "paused", Created: t0, Harness: "claude", Stores: []string{"claude", "default"},
			Model: "claude-opus-5-5", Size: "medium", PermissionMode: "auto", Repos: "https://github.com/DE0CH/x"}
		d.Machines["m1"] = "s1"
		d.Certs["m1"] = cert
	})
	t.Cleanup(rg.stop)
	return rg
}

func (rg *rig) writeSnapshot(t *testing.T, machine string, files []tfile) {
	body := makeTar(t, files)
	sum := sha256.Sum256(body)
	sig, _ := signP256(rg.mkey.k, []byte(hex.EncodeToString(sum[:])))
	putSnap(t, rg.r, machine, body, sig)
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// ---- tests ------------------------------------------------------------------------------------------

func TestArchiveLayoutAndIndex(t *testing.T) {
	rg := newRig(t)
	info, err := rg.r.archive("s1")
	if err != nil || info == nil {
		t.Fatalf("archive: %v %v", info, err)
	}
	dir := "claude-records/2026-10-01 Fix the router" // the transcript's title, made path-safe
	if info.Dir != dir {
		t.Fatalf("dir %q", info.Dir)
	}
	got := rg.dav.under(dir)
	want := []string{"artifacts/proj/report.html", "artifacts/record.md", "artifacts/report.html", "artifacts/sub/shot.png",
		"jarvis2/cert.json", "jarvis2/core-cert.json", "jarvis2/snapshot.sig", "jarvis2/snapshot.tar.gz",
		"restore-s1.json", "session.json", "transcript-aaaa.jsonl", "transcript-bbbb.jsonl"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("files:\n got %v\nwant %v", got, want)
	}
	if string(rg.dav.get(dir+"/artifacts/report.html")) != "<p>r</p>" {
		t.Fatal("a symlinked artifact wasn't followed")
	}
	if strings.Join(info.Transcripts, ",") != "transcript-aaaa.jsonl,transcript-bbbb.jsonl" {
		t.Fatalf("transcripts not oldest first: %v", info.Transcripts)
	}
	var meta map[string]any
	json.Unmarshal(rg.dav.get(dir+"/session.json"), &meta)
	if meta["id"] != "s1" || meta["snapshotMachine"] != "m1" || fmt.Sprint(meta["unresolvedArtifactLinks"]) != "[artifacts/outside]" {
		t.Fatalf("session.json %v", meta)
	}
	// the signed snapshot verifies against the archived cert's machine key
	var c struct {
		Machine struct{ SigningKey string } `json:"machine"`
	}
	var cd Doc
	json.Unmarshal(rg.dav.get(dir+"/jarvis2/cert.json"), &cd)
	cd.Decode(&c)
	sum := sha256.Sum256(rg.dav.get(dir + "/jarvis2/snapshot.tar.gz"))
	if !verifyP256(c.Machine.SigningKey, []byte(hex.EncodeToString(sum[:])), string(rg.dav.get(dir+"/jarvis2/snapshot.sig"))) {
		t.Fatal("archived snapshot doesn't verify against the archived cert")
	}
	var idx []map[string]any
	json.Unmarshal(rg.dav.get(recordsIndex), &idx)
	if len(idx) != 1 || idx[0]["id"] != "s1" || idx[0]["archiveDir"] != dir {
		t.Fatalf("index %v", idx)
	}
	var s Session
	rg.r.st.Do(func(d *persisted) { s = *d.Sessions["s1"] })
	if rg.r.archiveDir(s) != dir {
		t.Fatal("archiveDir doesn't return the chosen dir")
	}
}

func TestArchiveDirUnique(t *testing.T) {
	rg := newRig(t)
	rg.r.st.Do(func(d *persisted) { d.Sessions["s1"].Label = "Mine" })
	box := rg.r.box()
	box.Mkcols("claude-records/2026-10-01 Mine")
	box.PutBytes("claude-records/2026-10-01 Mine/session.json", []byte("{}")) // Jarvis 1's, same day and title
	info, err := rg.r.archive("s1")
	if err != nil || info.Dir != "claude-records/2026-10-01 Mine 2" {
		t.Fatalf("%v %v", info, err)
	}
}

func TestDestroyArchivesThenRecords(t *testing.T) {
	rg := newRig(t)
	var hooked string
	onDestroy = append(onDestroy, func(r *Router, s Session) { hooked = s.ID + " " + r.archiveDir(s) })
	defer func() { onDestroy = onDestroy[:len(onDestroy)-1] }()
	if err := rg.r.Destroy("s1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the record", func() bool { return rg.r.record("s1") != nil && rg.r.record("s1").Archive != nil })
	rec := rg.r.record("s1")
	if rec.Archive.Dir != "claude-records/2026-10-01 Fix the router" || rec.Archive.Last == nil || rec.Archive.Last.Text != "done it" {
		t.Fatalf("record %+v", rec.Archive)
	}
	if hooked != "s1 claude-records/2026-10-01 Fix the router" {
		t.Fatalf("destroy hook got %q", hooked)
	}
	waitFor(t, "the snapshot gone", func() bool { return rg.r.snap("m1") == nil })
	if keys, _ := rg.r.objects.List(context.Background(), "snapshots/"); len(keys) != 0 {
		t.Fatalf("the snapshot stayed in the bucket: %v", keys)
	}
	// the tail of the archived conversation
	tail, st, err := rg.r.RecordTail("s1")
	if err != nil || st != 200 || tail.Title != "Fix the: router" || len(tail.Messages) != 2 {
		t.Fatalf("tail %v %d %+v", err, st, tail)
	}
}

func TestDestroyArchiveFailureKeepsSession(t *testing.T) {
	rg := newRig(t)
	rg.dav.fail = "claude-records/2026"
	rg.r.Destroy("s1")
	waitFor(t, "the error", func() bool {
		var s Session
		rg.r.st.Do(func(d *persisted) { s = *d.Sessions["s1"] })
		return s.State == "paused" && strings.HasPrefix(s.Error, "archive:")
	})
	if rg.r.record("s1") != nil {
		t.Fatal("a failed archive still destroyed the session")
	}
	// force: destroyed anyway, the error kept on the record
	waitFor(t, "the lock", func() bool { return rg.r.DestroyWith("s1", true) == nil })
	waitFor(t, "the record", func() bool { return rg.r.record("s1") != nil })
	if rec := rg.r.record("s1"); rec.Archive != nil || rec.ArchiveError == "" {
		t.Fatalf("forced record %+v", rec)
	}
}

func TestDestroyWithoutSnapshotNeedsNoBox(t *testing.T) {
	rg := newRig(t)
	rg.r.snapDrop("m1")
	sbox = nil
	rg.r.Destroy("s1")
	waitFor(t, "the record", func() bool { return rg.r.record("s1") != nil })
}

func TestPausedTailAndChanges(t *testing.T) {
	rg := newRig(t)
	tail, st, err := rg.r.PausedTail("s1")
	if err != nil || st != 200 || tail.Title != "Fix the: router" || tail.Messages[len(tail.Messages)-1].Text != "done it" {
		t.Fatalf("%v %d %+v", err, st, tail)
	}
	ch := rg.r.Changes("s1")
	repos, _ := ch["repos"].([]RepoChange)
	if ch["checked"] != true || len(repos) != 2 || repos[0] != (RepoChange{"proj", 2, 1}) || repos[1].Unpushed != -1 {
		t.Fatalf("changes %v", ch)
	}
	rg.r.st.Do(func(d *persisted) { d.Sessions["s1"].MachineID, d.Sessions["s1"].State = "m1", "started" })
	if tl, st, _ := rg.r.PausedTail("s1"); st != 200 || !tl.Stale { // its last pause's tail, marked stale
		t.Fatalf("a running session's tail: %d %+v", st, tl)
	}
	if ch := rg.r.Changes("s1"); ch["checked"] != false {
		t.Fatalf("a running session without a grant: %v", ch) // Exec has no machine to answer
	}
}

func TestPurgeRecord(t *testing.T) {
	rg := newRig(t)
	rg.r.Destroy("s1")
	waitFor(t, "the record", func() bool { return rg.r.record("s1") != nil && rg.r.record("s1").Archive != nil }) // finish lists it a moment before its archive is set (flows.go)
	dir := rg.r.record("s1").Archive.Dir
	// a second record sharing the dir keeps the shared files
	rg.r.st.Do(func(d *persisted) {
		d.Records = append(d.Records, &Record{Session: Session{ID: "s2"}, Archive: &ArchiveInfo{Dir: dir, Transcripts: []string{"transcript-bbbb.jsonl"}}})
	})
	out, err := rg.r.DeleteRecord("s1", true)
	if err != nil {
		t.Fatal(err)
	}
	if rg.dav.get(dir+"/transcript-aaaa.jsonl") != nil || rg.dav.get(dir+"/transcript-bbbb.jsonl") == nil || rg.dav.get(dir+"/restore-s1.json") != nil {
		t.Fatalf("shared purge %v", out)
	}
	if _, err := rg.r.DeleteRecord("s2", true); err != nil {
		t.Fatal(err)
	}
	if len(rg.dav.under(dir)) != 0 {
		t.Fatalf("left %v", rg.dav.under(dir))
	}
	var idx []map[string]any
	json.Unmarshal(rg.dav.get(recordsIndex), &idx)
	if len(idx) != 0 || rg.r.record("s1") != nil {
		t.Fatalf("index %v", idx)
	}
}

func TestRestoreRecord(t *testing.T) {
	rg := newRig(t)
	rg.r.Destroy("s1")
	waitFor(t, "the record", func() bool { return rg.r.record("s1") != nil && rg.r.record("s1").Archive != nil }) // finish lists it a moment before its archive is set (flows.go)
	sid, err := rg.r.RestoreRecord("s1", "req1")
	if err != nil {
		t.Fatal(err)
	}
	var s Session
	var appr *Approval
	rg.r.st.Do(func(d *persisted) {
		s = *d.Sessions[sid]
		for _, a := range d.Approvals {
			if a.Session == sid {
				appr = a
			}
		}
	})
	if s.State != "approval" || s.RestoreFrom != "s1" || s.RestoreCert == nil || s.RestoreCert.Payload != rg.cert.Payload {
		t.Fatalf("session %+v", s)
	}
	if appr == nil || appr.Kind != "new-session" || !strings.HasPrefix(appr.Options["restore"], "Fix the: router (destroyed ") {
		t.Fatalf("approval %+v", appr)
	}
	if s.PermissionMode != "bypass" || appr.Options["permissionMode"] != "bypass" { // the only start mode, whatever s1 ran in
		t.Fatalf("restored in %q (approval %q)", s.PermissionMode, appr.Options["permissionMode"])
	}
	// the first machine gets the old cert in its env; a later one doesn't
	env := rg.r.machineEnv(&s)
	if env["JARVIS2_RESTORE_CERT"] == "" {
		t.Fatal("no restore cert in the first machine's env")
	}
	// only the line's first machine may fetch the snapshot
	rg.r.st.Do(func(d *persisted) {
		d.Machines["m9"] = sid
		d.Sessions[sid].MachineID = "m9"
		d.Certs["m9"] = rg.core.key.doc(map[string]any{"kind": "succession-cert", "predecessorId": ""})
		d.Sessions[sid].Cert = d.Certs["m9"]
	})
	if rg.r.restoreFilesFor("m9") == nil {
		t.Fatal("the first machine can't fetch the restore")
	}
	if env := rg.r.machineEnv(&Session{RestoreCert: s.RestoreCert, Cert: rg.cert}); env["JARVIS2_RESTORE_CERT"] != "" {
		t.Fatal("a successor got the restore cert")
	}
	rg.r.st.Do(func(d *persisted) {
		d.Certs["m9"] = rg.core.key.doc(map[string]any{"kind": "succession-cert", "predecessorId": "m8"})
	})
	if rg.r.restoreFilesFor("m9") != nil {
		t.Fatal("a successor may fetch the restore")
	}
	// once it runs, the files go and the record notes the restore
	rg.r.st.Do(func(d *persisted) { d.Sessions[sid].State = "started" })
	rg.r.tidyRestores()
	if rg.r.snap(restoreSnap(sid)) != nil {
		t.Fatal("the restore's snapshot stayed")
	}
	if rec := rg.r.record("s1"); len(rec.Restored) != 1 || rec.Restored[0].Session != sid {
		t.Fatalf("restored %+v", rec.Restored)
	}
}

func TestRestoreRefusesBadSignature(t *testing.T) {
	rg := newRig(t)
	rg.r.Destroy("s1")
	waitFor(t, "the record", func() bool { return rg.r.record("s1") != nil && rg.r.record("s1").Archive != nil }) // finish lists it a moment before its archive is set (flows.go)
	dir := rg.r.record("s1").Archive.Dir
	rg.r.box().PutBytes(dir+"/jarvis2/snapshot.tar.gz", []byte("tampered"))
	if _, err := rg.r.RestoreRecord("s1", "r"); err == nil || !strings.Contains(err.Error(), "isn't signed") {
		t.Fatalf("err %v", err)
	}
}

func TestResolveLink(t *testing.T) {
	for _, c := range [][3]string{
		{"artifacts/a", "../workspace/x", "workspace/x"},
		{"artifacts/a", "/home/claude/workspace/x", "workspace/x"},
		{"artifacts/a", "/etc/passwd", ""},
		{"artifacts/a", "../../../etc", ""},
		{"artifacts/sub/a", "b", "artifacts/sub/b"},
	} {
		if got := resolveLink(c[0], c[1]); got != c[2] {
			t.Errorf("resolveLink(%q,%q)=%q want %q", c[0], c[1], got, c[2])
		}
	}
}

func TestArchiveDirFor(t *testing.T) {
	s := &Session{ID: "s1", Created: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	if got := archiveDirFor(s, "..hidden/x"); got != "claude-records/2026-10-01 hidden x" {
		t.Fatal(got)
	}
	if got := archiveDirFor(s, ""); got != "claude-records/2026-10-01 s1" {
		t.Fatal(got)
	}
}

// A snapshot with no transcript (a session destroyed before its first conversation) archived with Transcripts nil,
// which went out as "transcripts": null and blanked the web page's Previous tab (Records.tsx read its .length).
// GET /api/records always lists them as an array, old records included.
func TestRecordsListNoTranscriptsAsArray(t *testing.T) {
	rg := newRig(t)
	r := rg.r
	r.cfg.NoAccess = true
	r.st.Do(func(d *persisted) {
		d.Records = append(d.Records, &Record{Session: Session{ID: "s9"}, DestroyedAt: time.Now(),
			Archive: &ArchiveInfo{Dir: "claude-records/2026-10-16 s9", Title: "s9", Signer: "m9"}})
	})
	req := httptest.NewRequest("GET", "/api/records", nil)
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET /api/records: %d %s", w.Code, w.Body)
	}
	var out struct {
		Records []struct {
			Archive map[string]json.RawMessage `json:"archive"`
		} `json:"records"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Records) == 0 {
		t.Fatalf("records %v %s", err, w.Body)
	}
	if got := string(out.Records[len(out.Records)-1].Archive["transcripts"]); got != "[]" {
		t.Fatalf("transcripts = %s, want []", got)
	}
}

// DECISIONS 226: the uploads run in parallel, each directory is made once (parents first), progress is reported, and
// a failed upload fails the archive without leaving temp files
func TestArchiveParallelUploadsAndProgress(t *testing.T) {
	rg := newRig(t)
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	files := append([]tfile{}, rg.files...)
	for i := 0; i < 60; i++ {
		files = append(files, tfile{name: fmt.Sprintf("artifacts/deep/d%d/e/f%d.txt", i%7, i), body: fmt.Sprint("file ", i), at: t0})
	}
	rg.writeSnapshot(t, "m1", files)
	every := archiveProgressEvery
	archiveProgressEvery = 0
	defer func() { archiveProgressEvery = every }()
	info, err := rg.r.archive("s1")
	if err != nil || info == nil {
		t.Fatalf("archive: %v %v", info, err)
	}
	got := map[string]bool{}
	for _, f := range rg.dav.under(info.Dir) {
		got[f] = true
	}
	for i := 0; i < 60; i++ {
		f := fmt.Sprintf("artifacts/deep/d%d/e/f%d.txt", i%7, i)
		if !got[f] || string(rg.dav.get(info.Dir+"/"+f)) != fmt.Sprint("file ", i) {
			t.Fatalf("%s missing or wrong", f)
		}
	}
	if info.Artifacts != 64 || len(info.Transcripts) != 2 {
		t.Fatalf("artifacts %d transcripts %v", info.Artifacts, info.Transcripts)
	}
	var s Session
	rg.r.st.Do(func(d *persisted) { s = *d.Sessions["s1"] })
	if s.Waiting != "" {
		t.Fatalf("waiting left as %q", s.Waiting)
	}
	tmp := filepath.Join(rg.r.cfg.DataDir, "tmp")
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("temp files left: %d", len(left))
	}

	// a failing upload: the archive fails, nothing is left in tmp
	rg = newRig(t)
	rg.writeSnapshot(t, "m1", files)
	tmp = filepath.Join(rg.r.cfg.DataDir, "tmp")
	rg.dav.mu.Lock()
	rg.dav.fail = "claude-records/2026-10-01 Fix the router/artifacts/deep/d3"
	rg.dav.mu.Unlock()
	if _, err := rg.r.archive("s1"); err == nil || !strings.Contains(err.Error(), "507") {
		t.Fatalf("want the 507, got %v", err)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("temp files left after the failure: %d", len(left))
	}
}

func TestArchiveProgressText(t *testing.T) {
	rg := newRig(t)
	every := archiveProgressEvery
	archiveProgressEvery = time.Hour
	defer func() { archiveProgressEvery = every }()
	p := rg.r.archiveProgress("s1")
	p(1, 10) // the first is always shown
	p(2, 10) // within the interval: not
	var s Session
	rg.r.st.Do(func(d *persisted) { s = *d.Sessions["s1"] })
	if s.Waiting != "archiving to the Storage Box: 1 of 10 files uploaded" {
		t.Fatalf("waiting %q", s.Waiting)
	}
	p(10, 10) // the last always
	rg.r.st.Do(func(d *persisted) { s = *d.Sessions["s1"] })
	if s.Waiting != "archiving to the Storage Box: 10 of 10 files uploaded" {
		t.Fatalf("waiting %q", s.Waiting)
	}
}
