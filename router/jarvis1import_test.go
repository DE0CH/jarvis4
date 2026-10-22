package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const j1TestID = "j1abcdef012345"

// j1Put: a paused Jarvis 1 session's file on the (in-memory) Storage Box
func j1Put(t *testing.T, rg *rig, name string, body []byte) {
	t.Helper()
	box := rg.r.box()
	if err := box.Mkcols(j1PausedRoot + "/" + j1TestID); err != nil {
		t.Fatal(err)
	}
	if err := box.PutBytes(j1PausedRoot+"/"+j1TestID+"/"+name, body); err != nil {
		t.Fatal(err)
	}
}

const j1TestUUID = "0fa81372-5d1c-49af-b680-25a842f5df96"

func j1Snapshot(t *testing.T, rg *rig) map[string][]byte {
	files := map[string][]byte{
		"session.json": []byte(`{"id":"` + j1TestID + `","title":"OWCS ticket cron","label":"","model":"claude-opus-5-5","size":"xlarge",` +
			`"harness":"claude","permissionMode":"auto","autoPause":"on","repos":"https://github.com/de0ch/claude-env.git https://github.com/DE0CH/YCC.git",` +
			`"pausedAt":"2026-10-12T13:50:30.612Z","metadata":{"cron_owcs":"{\"name\":\"owcs\",\"prompt\":\"check\",\"every\":86400,\"nextAt\":1}"}}`),
		"manifest.txt":           []byte(j1TestUUID + ".jsonl\n"),
		j1TestUUID + ".jsonl":    []byte(`{"type":"user"}` + "\n"),
		"claude.json":            []byte(`{"machineID":"abc"}`),
		"workspace.tar.gz":       makeTar(t, []tfile{{name: "workspace/claude-env/README.md", body: "hi", at: time.Now()}}),
		"changes.txt":            []byte("claude-env 0 0\n"), // not taken
		"artifacts-manifest.txt": []byte("x\n"),              // not taken
	}
	for n, b := range files {
		j1Put(t, rg, n, b)
	}
	return files
}

func waitPrepared(t *testing.T, r *Router) *j1Prep {
	t.Helper()
	var p j1Prep
	waitFor(t, "the prepare", func() bool {
		j1Preps.Lock()
		defer j1Preps.Unlock()
		if x := j1Preps.m[j1TestID]; x != nil && x.State != "preparing" {
			p = *x
			return true
		}
		return false
	})
	return &p
}

func TestJarvis1ImportPrepareAndImport(t *testing.T) {
	rg := newRig(t)
	files := j1Snapshot(t, rg)
	// an import nobody prepared prepares it first (rather than refusing)
	if err := rg.r.ensurePreparedJarvis1(j1TestID); err != nil {
		t.Fatalf("an import's own prepare: %v", err)
	}
	if _, _, _, err := rg.r.preparedJarvis1(j1TestID); err != nil {
		t.Fatalf("not prepared by the import: %v", err)
	}
	if _, err := rg.r.PrepareJarvis1("../etc"); err == nil {
		t.Fatal("prepared a bad id")
	}
	if _, err := rg.r.PrepareJarvis1(j1TestID); err != nil {
		t.Fatal(err)
	}
	p := waitPrepared(t, rg.r)
	if p.State != "ready" || p.Sha256 == "" {
		t.Fatalf("prepare %+v", p)
	}
	mb, sum, rec, err := rg.r.preparedJarvis1(j1TestID)
	if err != nil || sum != p.Sha256 || rec.Title != "OWCS ticket cron" {
		t.Fatalf("%v %s %+v", err, sum, rec)
	}
	var man J1ImportManifest
	if err := json.Unmarshal(mb, &man); err != nil || man.Kind != "jarvis1-import" || man.Session != j1TestID {
		t.Fatalf("manifest %s", mb)
	}
	got := map[string]J1ImportFile{}
	for _, f := range man.Files {
		got[f.Name] = f
	}
	for _, n := range []string{"session.json", "manifest.txt", j1TestUUID + ".jsonl", "claude.json", "workspace.tar.gz"} {
		s := sha256.Sum256(files[n])
		if got[n].Sha256 != hex.EncodeToString(s[:]) || got[n].Size != int64(len(files[n])) {
			t.Fatalf("%s: %+v", n, got[n])
		}
	}
	if _, ok := got["changes.txt"]; ok || len(got) != 5 {
		t.Fatalf("took files it shouldn't: %v", got)
	}
	if man.Files[0].Name != "session.json" || man.Files[len(man.Files)-1].Name != "workspace.tar.gz" {
		t.Fatalf("order %v", man.Files)
	}

	// the import: a new session waiting for the phone, its cert's restore naming the manifest's hash
	o := Origin{Caller: Caller{Kind: "setup"}}
	sid, err := rg.r.ImportJarvis1(j1TestID, J1ImportIn{Stores: []string{"default"}, Explanation: "move it"}, o)
	if err != nil {
		t.Fatal(err)
	}
	var s Session
	var appr *Approval
	waitFor(t, "the approval", func() bool {
		rg.r.st.Do(func(d *persisted) {
			s = *d.Sessions[sid]
			for _, a := range d.Approvals {
				if a.Session == sid {
					appr = a
				}
			}
		})
		return appr != nil
	})
	if s.State != "approval" || s.ImportFrom != j1TestID || s.ImportSha != sum || s.Label != "OWCS ticket cron" || s.Size != "large" ||
		s.PermissionMode != "bypass" /* Jarvis 1 ran it in auto: bypass is the only start mode */ || s.Model != "claude-opus-5-5" || s.Repos != "https://github.com/de0ch/claude-env.git,https://github.com/DE0CH/YCC.git" ||
		strings.Join(s.Stores, ",") != "default,tunnel" || s.Live == nil || s.Live.AutoPauseOff {
		t.Fatalf("session %+v", s)
	}
	if !strings.Contains(s.Prompt, "moved from Jarvis 1 to Jarvis 4") || !strings.Contains(s.Prompt, j1TestID) {
		t.Fatalf("prompt %q", s.Prompt)
	}
	if appr.Kind != "new-session" || !strings.HasPrefix(appr.Options["restore"], "Jarvis 1 session “OWCS ticket cron” ("+j1TestID+", paused 2026-10-12)") ||
		appr.Explanation != "move it" || appr.Origin == nil || appr.Origin.Caller.Kind != "setup" {
		t.Fatalf("approval %+v", appr)
	}
	config, _ := rg.r.sessionConfig(&s)
	var c SessionConfig
	json.Unmarshal([]byte(config), &c)
	if c.Restore == nil || c.Restore.Machine != j1TestID || c.Restore.Sha256 != sum || c.Label != "OWCS ticket cron" || c.Prompt != s.Prompt {
		t.Fatalf("config %s", config)
	}
	// the same import again answers the same session
	if again, err := rg.r.ImportJarvis1(j1TestID, J1ImportIn{Stores: []string{"default"}}, o); err != nil || again != sid {
		t.Fatalf("again: %s %v", again, err)
	}

	// only the line's first machine gets the manifest and the files, and only the manifest's files
	m := newTestMachine(rg.r, "m9")
	h := rg.r.MachineHandler()
	rg.r.st.Do(func(d *persisted) {
		d.Machines["m9"] = sid
		d.Sessions[sid].MachineID = "m9"
		d.Certs["m9"] = rg.core.key.doc(map[string]any{"kind": "succession-cert", "predecessorId": ""})
	})
	get := func(path string) (int, []byte) {
		req := httptest.NewRequest("GET", path, nil)
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		empty := sha256.Sum256(nil)
		sig, _ := signP256(m.key, []byte("GET "+req.URL.Path+" "+ts+" "+hex.EncodeToString(empty[:])))
		req.Header.Set("X-Machine", "m9")
		req.Header.Set("X-Time", ts)
		req.Header.Set("X-Sig", sig)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code, w.Body.Bytes()
	}
	if code, b := get("/m/restore-snapshot"); code != 200 || string(b) != string(mb) {
		t.Fatalf("manifest: %d %s", code, b)
	}
	if code, b := get("/m/import-file/workspace.tar.gz"); code != 200 || string(b) != string(files["workspace.tar.gz"]) {
		t.Fatalf("file: %d %d bytes", code, len(b))
	}
	if code, _ := get("/m/import-file/changes.txt"); code != 404 {
		t.Fatalf("a file outside the manifest: %d", code)
	}
	// a successor whose predecessor left no snapshot takes the import again; one with a snapshot doesn't
	rg.r.st.Do(func(d *persisted) {
		d.Certs["m9"] = rg.core.key.doc(map[string]any{"kind": "succession-cert", "predecessorId": "m8"})
	})
	if code, _ := get("/m/restore-snapshot"); code != 200 {
		t.Fatalf("a successor with no snapshot can't take the import again: %d", code)
	}
	rg.r.st.Do(func(d *persisted) {
		d.Certs["m9"] = rg.core.key.doc(map[string]any{"kind": "succession-cert", "predecessorId": "m8", "snapshot": strings.Repeat("b", 64)})
	})
	if code, _ := get("/m/import-file/workspace.tar.gz"); code != 404 {
		t.Fatalf("a successor fetched an import file: %d", code)
	}
	if code, _ := get("/m/restore-snapshot"); code == 200 {
		t.Fatal("a successor fetched the import manifest")
	}

	// once it came up, the import notes the session
	rg.r.st.Do(func(d *persisted) { d.Sessions[sid].Booted = "m9" })
	rg.r.tidyImports()
	v := map[string]any{}
	rg.r.j1Status(j1TestID, v)
	if imp, _ := v["imported"].(map[string]any); imp == nil || imp["session"] != sid {
		t.Fatalf("status %v", v)
	}
}

func TestJarvis1ImportRefusesAnIncompleteSnapshot(t *testing.T) {
	rg := newRig(t)
	j1Put(t, rg, "session.json", []byte(`{"id":"`+j1TestID+`"}`))
	j1Put(t, rg, "workspace.tar.gz", []byte("x"))
	if _, err := rg.r.PrepareJarvis1(j1TestID); err != nil {
		t.Fatal(err)
	}
	if p := waitPrepared(t, rg.r); p.State != "failed" || !strings.Contains(p.Error, "manifest.txt") {
		t.Fatalf("%+v", p)
	}
	if _, ok := rg.r.st.ReadDoc(j1Doc(j1TestID, j1ManifestFile)); ok {
		t.Fatal("a manifest was written")
	}
}

func TestSnapshotUploadStreamsAndChecksTheSignature(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	h := r.MachineHandler()
	body := strings.Repeat("snapshot bytes ", 1000)
	req := func(signed string) *httptest.ResponseRecorder {
		q := httptest.NewRequest("POST", "/m/snapshot", strings.NewReader(body))
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		sum := sha256.Sum256([]byte(signed))
		sig, _ := signP256(m.key, []byte("POST /m/snapshot "+ts+" "+hex.EncodeToString(sum[:])))
		q.Header.Set("X-Machine", "mA")
		q.Header.Set("X-Time", ts)
		q.Header.Set("X-Sig", sig)
		q.Header.Set("X-Snapshot-Sig", "snapsig")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, q)
		return w
	}
	// a signature over other bytes: refused, nothing kept
	if w := req("other bytes"); w.Code != 401 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if r.snap("mA") != nil {
		t.Fatal("a snapshot with a bad signature was kept")
	}
	ents, _ := os.ReadDir(filepath.Join(r.cfg.DataDir, "tmp"))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".upload-") {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
	if w := req(body); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if b := snapBytes(r, "mA"); string(b) != body {
		t.Fatal("stored snapshot differs")
	}
	if s := r.snap("mA"); s == nil || s.Sig != "snapsig" {
		t.Fatalf("%+v", s)
	}
	// an unknown machine: refused before a byte is read
	q := httptest.NewRequest("POST", "/m/snapshot", strings.NewReader(body))
	q.Header.Set("X-Machine", "nobody")
	q.Header.Set("X-Time", strconv.FormatInt(time.Now().Unix(), 10))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, q)
	if w.Code != 401 {
		t.Fatalf("unknown machine: %d", w.Code)
	}
}

// Apache redirects a collection asked for without its trailing slash; Go's client would follow the 301 as a GET
func TestPropfindKeepsTheDirectorySlash(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got = append(got, req.Method+" "+req.URL.Path)
		if !strings.HasSuffix(req.URL.Path, "/") {
			http.Redirect(w, req, req.URL.Path+"/", 301)
			return
		}
		w.WriteHeader(207)
		w.Write([]byte(`<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>/a/b/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat></D:response>` +
			`<D:response><D:href>/a/b/f.txt</D:href><D:propstat><D:prop><D:resourcetype/><D:getcontentlength>3</D:getcontentlength></D:prop></D:propstat></D:response></D:multistatus>`))
	}))
	defer srv.Close()
	ls, err := newStorageBox(srv.URL, "u", "p").List("a/b")
	if err != nil || ls["f.txt"] != 3 || len(got) != 1 || got[0] != "PROPFIND /a/b/" {
		t.Fatalf("%v %v %v", ls, err, got)
	}
}
