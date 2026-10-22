package main

// Importing a paused Jarvis 1 session (Deyao, 2026-10-13: "move all paused Jarvis 1 sessions to Jarvis 4, so each
// continues there as the same conversation with its working tree").
//
// Jarvis 1 left each paused session on the Storage Box at claude-records/.paused/<id>/: its transcripts (<uuid>.jsonl),
// ~/.claude.json (claude.json), ~/workspace and ~/artifacts (workspace.tar.gz, artifacts.tar.gz), an optional harness
// tarball, the record (session.json: title, model, size, repos, armed wakeups and crons) and manifest.txt, written
// last (its presence = the snapshot is complete). None of it is signed by anything Jarvis 4 trusts, so an import is a
// NEW line whose cert vouches for exactly those bytes (DESIGN "Inputs to a machine" (a)):
//
//  1. prepare: the router streams every file once and hashes it, and writes the import manifest
//     {kind "jarvis1-import", session, files: [{name, sha256, size}]} onto its volume;
//  2. import: a new session whose config carries restore = {machine: the Jarvis 1 session id (its first machine's
//     id), sha256: the manifest's sha256}, waiting for the phone like any new session (the app shows "Restores
//     machine <id>" and the hash, as for a restore of a destroyed Jarvis 4 session). Deyao's Face ID signs that hash,
//     so it vouches for every byte the manifest lists;
//  3. the line's first machine fetches the manifest (/m/restore-snapshot), checks its hash against the cert, then
//     fetches each file through the router (/m/import-file/<name>, streamed from the Storage Box: the machine holds
//     no Storage Box credential) and refuses any whose sha256 or size differs (machine/jarvis1import.go).
//
// The router's choice of WHICH bytes to hash is its own (as with attachments, decision 78): the phone binds the
// bytes the router read at prepare time, and the Storage Box (ours, over TLS) is where they came from.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	j1ImportKind   = "jarvis1-import"
	j1PausedRoot   = "claude-records/.paused"
	j1PausedIndex  = "claude-records/.index/paused-sessions.json"
	j1ManifestFile = "manifest.json" // the import manifest, on the router's volume
	j1RecordFile   = "record.json"   // Jarvis 1's session.json as read at prepare (the router's own use: label, model…)
	j1ImportedFile = "imported.json" // the Jarvis 4 session the import became, once it came up
)

var (
	j1SessionIDRE = regexp.MustCompile(`^[a-z0-9]{1,40}$`)
	// the files an import takes (machine/jarvis1import.go accepts the same names)
	j1FileRE = regexp.MustCompile(`^(session\.json|claude\.json|manifest\.txt|workspace\.tar\.gz|artifacts\.tar\.gz|harness\.tar\.gz|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jsonl)$`)
)

// J1ImportFile / J1ImportManifest: what the cert's restore hash covers (the manifest's exact bytes)
type J1ImportFile struct {
	Name   string `json:"name"`
	Sha256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type J1ImportManifest struct {
	Kind    string         `json:"kind"`
	V       int            `json:"v"`
	Session string         `json:"session"`
	Files   []J1ImportFile `json:"files"`
}

// j1Record: the parts of Jarvis 1's session.json the router uses to fill in the new session (all of it goes to
// the phone in the challenge or the approval's options)
type j1Record struct {
	ID          string            `json:"id"`
	Label       string            `json:"label"`
	Title       string            `json:"title"`
	Model       string            `json:"model"`
	Size        string            `json:"size"`
	Harness     string            `json:"harness"`
	AutoPause   string            `json:"autoPause"`
	OneShot     bool              `json:"oneShot"`
	Repos       string            `json:"repos"`
	Environment string            `json:"environment"`
	PausedAt    string            `json:"pausedAt"`
	Metadata    map[string]string `json:"metadata"`
}

// j1Source: where the paused sessions are — the Storage Box (production), or JARVIS1_PAUSED_URL (the end-to-end
// test's stand-in: the same WebDAV calls, no credentials)
func (r *Router) j1Source() (*StorageBox, string, error) {
	if u := os.Getenv("JARVIS1_PAUSED_URL"); u != "" {
		return newStorageBox(u, "", ""), "", nil
	}
	box := r.box()
	if box == nil {
		return nil, "", errNoStorageBox
	}
	return box, j1PausedRoot, nil
}

func j1Path(root string, parts ...string) string {
	if root == "" {
		return strings.Join(parts, "/")
	}
	return root + "/" + strings.Join(parts, "/")
}

func (r *Router) j1Dir(id string) string { return filepath.Join(r.cfg.DataDir, "jarvis1-imports", id) }

// ---- the Storage Box: a directory listing and a streamed GET ----------------------------------------------

// List: the names (and sizes) of the files directly in a directory (content.go's children); nil when it is missing
func (b *StorageBox) List(dir string) (map[string]int64, error) {
	ents, ok, err := b.children(dir)
	if err != nil || !ok {
		return nil, err
	}
	out := map[string]int64{}
	for _, e := range ents {
		if !e.Dir {
			out[e.Name] = e.Size
		}
	}
	return out, nil
}

// Open: a file streamed (the caller closes it); nil, 0, nil when it is missing
func (b *StorageBox) Open(p string) (io.ReadCloser, int64, error) {
	u := davURL(b.base, p)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, 0, err
	}
	if b.user != "" {
		req.SetBasicAuth(b.user, b.pass)
	}
	resp, err := streamClient.Do(req) // no overall time limit: a multi-GB workspace outlasts any fixed one
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode == 404 {
		resp.Body.Close()
		return nil, 0, nil
	}
	if resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, 0, fmt.Errorf("GET %s: HTTP %d", p, resp.StatusCode)
	}
	return resp.Body, resp.ContentLength, nil
}

var streamClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, ResponseHeaderTimeout: 2 * time.Minute}}

// ---- prepare ------------------------------------------------------------------------------------------------

type j1Prep struct {
	State   string    `json:"state"` // preparing | ready | failed
	File    string    `json:"file,omitempty"`
	Done    int64     `json:"bytesDone"`
	Total   int64     `json:"bytesTotal"`
	Error   string    `json:"error,omitempty"`
	Sha256  string    `json:"sha256,omitempty"` // the manifest's
	Started time.Time `json:"started"`
}

var j1Preps = struct {
	sync.Mutex
	m map[string]*j1Prep
}{m: map[string]*j1Prep{}}

// PrepareJarvis1: starts hashing a paused Jarvis 1 session's files (in the background; JarvisOneStatus follows it)
func (r *Router) PrepareJarvis1(id string) (*j1Prep, error) {
	if !j1SessionIDRE.MatchString(id) {
		return nil, bad("not a Jarvis 1 session id: %q", id)
	}
	j1Preps.Lock()
	defer j1Preps.Unlock()
	if p := j1Preps.m[id]; p != nil && p.State == "preparing" {
		c := *p
		return &c, nil
	}
	p := &j1Prep{State: "preparing", Started: time.Now().UTC()}
	j1Preps.m[id] = p
	go func() {
		sum, err := r.prepareJarvis1(id, p)
		j1Preps.Lock()
		defer j1Preps.Unlock()
		if err != nil {
			p.State, p.Error = "failed", err.Error()
			log.Printf("jarvis1 import %s: prepare failed: %v", id, err)
			return
		}
		p.State, p.Sha256, p.File = "ready", sum, ""
		log.Printf("jarvis1 import %s: prepared (manifest sha256 %s)", id, sum)
	}()
	c := *p
	return &c, nil
}

func (r *Router) prepareJarvis1(id string, p *j1Prep) (string, error) {
	src, root, err := r.j1Source()
	if err != nil {
		return "", err
	}
	dir := j1Path(root, id)
	ls, err := src.List(dir)
	if err != nil {
		return "", err
	}
	if ls == nil {
		return "", fmt.Errorf("no paused Jarvis 1 session %s", id)
	}
	if _, ok := ls["manifest.txt"]; !ok {
		return "", errors.New("the snapshot has no manifest.txt (Jarvis 1 writes it last): incomplete, not imported")
	}
	if _, ok := ls["session.json"]; !ok {
		return "", errors.New("the snapshot has no session.json")
	}
	names := []string{}
	var total int64
	for n, size := range ls {
		if j1FileRE.MatchString(n) {
			names = append(names, n)
			total += size
		}
	}
	sort.Slice(names, func(i, j int) bool {
		return j1Order(names[i]) < j1Order(names[j]) || (j1Order(names[i]) == j1Order(names[j]) && names[i] < names[j])
	})
	j1Preps.Lock()
	p.Total = total
	j1Preps.Unlock()
	man := J1ImportManifest{Kind: j1ImportKind, V: 1, Session: id}
	var rec []byte
	for _, n := range names {
		j1Preps.Lock()
		p.File = n
		j1Preps.Unlock()
		body, _, err := src.Open(j1Path(root, id, n))
		if err != nil {
			return "", err
		}
		if body == nil {
			return "", fmt.Errorf("%s went missing", n)
		}
		h := newHashCounter(func(n int64) { j1Preps.Lock(); p.Done += n; j1Preps.Unlock() })
		var keep io.Writer = io.Discard
		var recBuf strings.Builder
		if n == "session.json" {
			keep = &recBuf
		}
		_, err = io.Copy(io.MultiWriter(h, keep), body)
		body.Close()
		if err != nil {
			return "", fmt.Errorf("%s: %v", n, err)
		}
		if n == "session.json" {
			rec = []byte(recBuf.String())
		}
		man.Files = append(man.Files, J1ImportFile{Name: n, Sha256: h.sum(), Size: h.n})
	}
	var jr j1Record
	if err := json.Unmarshal(rec, &jr); err != nil {
		return "", fmt.Errorf("session.json: %v", err)
	}
	if jr.ID != "" && jr.ID != id {
		return "", fmt.Errorf("session.json names session %s, not %s", jr.ID, id)
	}
	mb, _ := json.Marshal(man)
	out := r.j1Dir(id)
	if err := os.MkdirAll(out, 0o700); err != nil {
		return "", err
	}
	if err := writeFileAtomic(filepath.Join(out, j1RecordFile), rec); err != nil {
		return "", err
	}
	if err := writeFileAtomic(filepath.Join(out, j1ManifestFile), mb); err != nil {
		return "", err
	}
	return sha256Bytes(mb), nil
}

// j1Order: small files first (the record, the manifest, claude.json, transcripts), then the tarballs
func j1Order(n string) int {
	switch {
	case n == "session.json":
		return 0
	case n == "manifest.txt":
		return 1
	case n == "claude.json":
		return 2
	case strings.HasSuffix(n, ".jsonl"):
		return 3
	case n == "harness.tar.gz":
		return 4
	case n == "artifacts.tar.gz":
		return 5
	}
	return 6
}

func writeFileAtomic(p string, b []byte) error {
	if err := os.WriteFile(p+".tmp", b, 0o600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

// j1PrepareWait: how long an import waits for the prepare it starts itself
var j1PrepareWait = 10 * time.Minute

// ensurePreparedJarvis1: an import of a session nobody prepared prepares it first (rather than refusing): the prepare
// starts (or the running one is joined) and the import waits for it
func (r *Router) ensurePreparedJarvis1(id string) error {
	if !j1SessionIDRE.MatchString(id) {
		return bad("not a Jarvis 1 session id: %q", id)
	}
	if _, err := os.Stat(filepath.Join(r.j1Dir(id), j1ManifestFile)); err == nil {
		return nil
	}
	if _, err := r.PrepareJarvis1(id); err != nil {
		return err
	}
	for end := time.Now().Add(j1PrepareWait); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		j1Preps.Lock()
		p := j1Preps.m[id]
		var st, msg string
		if p != nil {
			st, msg = p.State, p.Error
		}
		j1Preps.Unlock()
		switch st {
		case "ready":
			return nil
		case "failed":
			return fmt.Errorf("Jarvis 1 session %s couldn't be prepared: %s", id, msg)
		}
	}
	return fmt.Errorf("Jarvis 1 session %s is still being prepared after %s: ask again once GET …/jarvis1/%s says ready", id, j1PrepareWait, id)
}

// preparedJarvis1: the prepared manifest (its bytes and sha256) and record, or an error saying what's missing
func (r *Router) preparedJarvis1(id string) ([]byte, string, *j1Record, error) {
	if !j1SessionIDRE.MatchString(id) {
		return nil, "", nil, bad("not a Jarvis 1 session id: %q", id)
	}
	mb, err := os.ReadFile(filepath.Join(r.j1Dir(id), j1ManifestFile))
	if err != nil {
		return nil, "", nil, bad("Jarvis 1 session %s isn't prepared: POST …/jarvis1/%s/prepare first", id, id)
	}
	rb, err := os.ReadFile(filepath.Join(r.j1Dir(id), j1RecordFile))
	if err != nil {
		return nil, "", nil, err
	}
	var rec j1Record
	if err := json.Unmarshal(rb, &rec); err != nil {
		return nil, "", nil, err
	}
	return mb, sha256Bytes(mb), &rec, nil
}

// ---- import: a new session, waiting for the phone ---------------------------------------------------------

type J1ImportIn struct {
	Stores      []string `json:"stores"` // Jarvis 4 stores (the harness's come with it)
	Prompt      string   `json:"prompt"` // typed into the resumed conversation once it is up ("" = j1DefaultPrompt)
	Size        string   `json:"size"`   // "" = Jarvis 1's size (xlarge → large)
	Explanation string   `json:"explanation"`
	Account     string   `json:"account"` // its Claude account (claudeaccounts.go); "" = the default
	Batch       string   `json:"-"`       // batches.go: filed in this batch
}

// J1ImportRef: on NewSession, the import a new line restores
type J1ImportRef struct {
	Session string // the Jarvis 1 session id
	Sha256  string // the import manifest's
	Shown   string // the approval's "restore" line
}

// j1DefaultPrompt: what the resumed conversation is told first (the phone shows it; Deyao signs it)
func j1DefaultPrompt(id string, stores []string) string {
	return "[Jarvis 4] This conversation was moved from Jarvis 1 to Jarvis 4 on " + time.Now().UTC().Format("2006-01-02") +
		" (Jarvis 1 session " + id + "). Its transcript, ~/workspace and ~/artifacts were restored from the Jarvis 1 pause snapshot, and " +
		"any wakeups or crons it had armed were re-armed on Jarvis 4 (see ~/artifacts/jarvis1-import/rearmed.txt). It now runs on Jarvis 4 with " +
		"the stores " + strings.Join(stores, ", ") + " (`jarvis2 stores` lists them; `jarvis2-request add-store` asks for another). " +
		"Jarvis 1 is being frozen, so don't use its API. Nothing to do now: reply with one short line and wait for Deyao."
}

var j1SizeMap = map[string]string{"small": "small", "medium": "medium", "large": "large", "xlarge": "large", "": "medium"}

// ImportJarvis1: the prepared Jarvis 1 session as a new session waiting for the phone (approval kind new-session,
// options.restore names it). The same import asked again answers the session it already made (requestId).
func (r *Router) ImportJarvis1(id string, in J1ImportIn, o Origin) (string, error) {
	if err := r.ensurePreparedJarvis1(id); err != nil {
		return "", err
	}
	_, sum, rec, err := r.preparedJarvis1(id)
	if err != nil {
		return "", err
	}
	var kept []string // the shared login's old store comes as the Claude account
	for _, n := range in.Stores {
		if n != legacyClaudeStore {
			kept = append(kept, n)
		}
	}
	in.Stores = kept
	label := firstNonEmpty(rec.Title, rec.Label, "Jarvis 1 "+id)
	harness := firstNonEmpty(rec.Harness, "claude")
	if _, ok := r.policy.Harnesses[harness]; !ok {
		return "", fmt.Errorf("no harness %s in the policy", harness)
	}
	size := in.Size
	if size == "" {
		var ok bool
		if size, ok = j1SizeMap[rec.Size]; !ok {
			size = "medium"
		}
	}
	h := r.policy.Harnesses[harness]
	all, err := r.withHarnessStores(in.Stores, h.Stores)
	if err != nil {
		return "", err
	}
	prompt := strings.TrimSpace(in.Prompt)
	if prompt == "" {
		prompt = j1DefaultPrompt(id, all)
	}
	repos := []string{}
	for _, u := range strings.FieldsFunc(rec.Repos, func(c rune) bool { return c == ',' || c == ' ' || c == '\n' }) {
		repos = append(repos, u)
	}
	auto := rec.AutoPause != "off"
	paused := rec.PausedAt
	if len(paused) >= 10 {
		paused = paused[:10]
	}
	ns := NewSession{
		RequestID: "jarvis1-import:" + id + ":" + sum[:16], Label: label, Prompt: prompt, Model: rec.Model, PermissionMode: "bypass", // the only start mode
		Size: size, Harness: harness, Stores: in.Stores, Account: in.Account, Repos: strings.Join(repos, ","), AutoPause: &auto,
		Origin: &o, Explanation: in.Explanation, Batch: in.Batch,
		Import: &J1ImportRef{Session: id, Sha256: sum, Shown: fmt.Sprintf("Jarvis 1 session “%s” (%s, paused %s)", label, id, paused)},
	}
	return r.CreateSession(ns)
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if strings.TrimSpace(x) != "" {
			return strings.TrimSpace(x)
		}
	}
	return ""
}

// ---- the machine's side: the manifest and the files, only to the importing line's first machine -------------

// importFor: the Jarvis 1 session a machine imports
func (r *Router) importFor(machine string) string {
	var id string
	r.st.Do(func(d *persisted) {
		s := d.Sessions[d.Machines[machine]]
		// the line's first machine, or a successor whose cert names no snapshot (its predecessor left none: the
		// machine takes the import again, machine/restore.go reimportJarvis1)
		cert := d.Certs[machine]
		if s == nil || s.ImportFrom == "" || s.MachineID != machine || (certField(cert, "predecessorId") != "" && certField(cert, "snapshot") != "") {
			return
		}
		id = s.ImportFrom
	})
	return id
}

func (r *Router) serveImportManifest(w http.ResponseWriter, id string) {
	mb, _, _, err := r.preparedJarvis1(id)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(mb)
}

func (r *Router) serveImportFile(w http.ResponseWriter, machine, name string) {
	id := r.importFor(machine)
	if id == "" {
		writeJSON(w, 404, map[string]string{"error": "no Jarvis 1 import for this machine"})
		return
	}
	mb, _, _, err := r.preparedJarvis1(id)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	var man J1ImportManifest
	json.Unmarshal(mb, &man)
	var want *J1ImportFile
	for i := range man.Files {
		if man.Files[i].Name == name {
			want = &man.Files[i]
		}
	}
	if want == nil {
		writeJSON(w, 404, map[string]string{"error": "not a file of this import"})
		return
	}
	src, root, err := r.j1Source()
	if err != nil {
		writeErr(w, err)
		return
	}
	body, _, err := src.Open(j1Path(root, id, name))
	if err != nil || body == nil {
		writeJSON(w, 502, map[string]string{"error": fmt.Sprintf("the Storage Box: %v", err)})
		return
	}
	defer body.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(want.Size)) // the machine checks size and sha256 itself
	if n, err := io.Copy(w, io.LimitReader(body, want.Size)); err != nil {
		log.Printf("jarvis1 import %s: %s to %s cut off after %d bytes: %v", id, name, machine, n, err)
	}
}

// tidyImports: an import whose session came up is noted (imported.json) so the list shows where it went
func (r *Router) tidyImports() {
	type done struct{ from, sid string }
	var list []done
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if s.ImportFrom != "" && s.Booted != "" {
				list = append(list, done{s.ImportFrom, s.ID})
			}
		}
	})
	for _, x := range list {
		p := filepath.Join(r.j1Dir(x.from), j1ImportedFile)
		if _, err := os.Stat(p); err == nil {
			continue
		}
		b, _ := json.Marshal(map[string]any{"session": x.sid, "at": time.Now().UTC()})
		writeFileAtomic(p, b)
	}
}

// ---- the list ---------------------------------------------------------------------------------------------------

// Jarvis1List: Jarvis 1's paused sessions (its index) with each one's import state here
func (r *Router) Jarvis1List() ([]map[string]any, error) {
	src, root, err := r.j1Source()
	if err != nil {
		return nil, err
	}
	var ids []string
	titles := map[string]map[string]any{}
	if root != "" {
		b, err := src.Get(j1PausedIndex)
		if err != nil {
			return nil, err
		}
		var idx []map[string]any
		json.Unmarshal(b, &idx)
		for _, e := range idx {
			if id, _ := e["id"].(string); j1SessionIDRE.MatchString(id) {
				ids = append(ids, id)
				titles[id] = e
			}
		}
	}
	out := []map[string]any{}
	for _, id := range ids {
		e := titles[id]
		v := map[string]any{"id": id, "title": firstNonEmpty(fmt.Sprint(orDefault(e["title"], "")), fmt.Sprint(orDefault(e["label"], ""))),
			"pausedAt": e["pausedAt"], "size": e["size"], "model": e["model"], "environment": e["environment"], "repos": e["repos"]}
		r.j1Status(id, v)
		out = append(out, v)
	}
	return out, nil
}

// j1Status: prepare state, manifest hash, the session made from it (waiting or imported)
func (r *Router) j1Status(id string, v map[string]any) {
	j1Preps.Lock()
	if p := j1Preps.m[id]; p != nil {
		c := *p
		v["prepare"] = &c
	}
	j1Preps.Unlock()
	if _, sum, _, err := r.preparedJarvis1(id); err == nil {
		v["sha256"] = sum
	}
	if b, err := os.ReadFile(filepath.Join(r.j1Dir(id), j1ImportedFile)); err == nil {
		var x map[string]any
		json.Unmarshal(b, &x)
		v["imported"] = x
	}
	sessions := []map[string]any{}
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if s.ImportFrom == id {
				sessions = append(sessions, map[string]any{"id": s.ID, "state": s.State})
			}
		}
	})
	v["sessions"] = sessions
}

// ---- routes ------------------------------------------------------------------------------------------------------

func (r *Router) registerJarvis1Import(app appRoute, m machineRoute, public publicRoute) {
	list := func(w http.ResponseWriter) {
		l, err := r.Jarvis1List()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"sessions": l})
	}
	status := func(w http.ResponseWriter, id string) {
		v := map[string]any{"id": id}
		r.j1Status(id, v)
		writeJSON(w, 200, v)
	}
	prepare := func(w http.ResponseWriter, id string) {
		p, err := r.PrepareJarvis1(id)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 202, map[string]any{"id": id, "prepare": p})
	}
	importIt := func(w http.ResponseWriter, req *http.Request, id string, caller Caller, b []byte) {
		var in J1ImportIn
		if err := json.Unmarshal(b, &in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
			return
		}
		expl, err := cleanExplanation(in.Explanation, caller.Kind == "setup")
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		in.Explanation = expl
		o := Origin{Caller: caller, Call: APICall{Method: "POST", Path: req.URL.Path, Args: map[string]any{"stores": in.Stores, "size": in.Size}}}
		sid, err := r.ImportJarvis1(id, in, o)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"id": sid, "from": id, "approval": true})
	}
	// Deyao's login (the web page; the app later)
	app("GET /api/jarvis1/paused", func(w http.ResponseWriter, req *http.Request) { list(w) })
	app("GET /api/jarvis1/paused/{id}", func(w http.ResponseWriter, req *http.Request) { status(w, req.PathValue("id")) })
	app("POST /api/jarvis1/paused/{id}/prepare", func(w http.ResponseWriter, req *http.Request) { prepare(w, req.PathValue("id")) })
	app("POST /api/jarvis1/paused/{id}/import", func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<16))
		importIt(w, req, req.PathValue("id"), appCaller(req), b)
	})
	// the setup session (Claude): its Access token and the setup key's signature
	setupOnly := func(fn func(w http.ResponseWriter, req *http.Request, body []byte)) http.Handler {
		return r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<16))
			if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), b); err != nil {
				writeJSON(w, 401, map[string]string{"error": err.Error()})
				return
			}
			fn(w, req, b)
		})
	}
	public("GET /setup/jarvis1/paused", setupOnly(func(w http.ResponseWriter, req *http.Request, _ []byte) { list(w) }))
	public("GET /setup/jarvis1/paused/{id}", setupOnly(func(w http.ResponseWriter, req *http.Request, _ []byte) { status(w, req.PathValue("id")) }))
	public("POST /setup/jarvis1/paused/{id}/prepare", setupOnly(func(w http.ResponseWriter, req *http.Request, _ []byte) { prepare(w, req.PathValue("id")) }))
	public("POST /setup/jarvis1/paused/{id}/import", setupOnly(func(w http.ResponseWriter, req *http.Request, b []byte) {
		importIt(w, req, req.PathValue("id"), Caller{Kind: "setup"}, b)
	}))
	// stopping a session from the setup session (2026-10-13: Deyao stopped the imported sessions): pause it (its
	// snapshot if the machine answers, else none) and cancel its wakeups and crons, so nothing resumes it by itself
	public("POST /setup/sessions/{id}/pause", setupOnly(func(w http.ResponseWriter, req *http.Request, _ []byte) {
		id := req.PathValue("id")
		cancelled, _ := r.CancelWakeups(id, nil, true)
		crons, _ := r.ListCrons(id)
		for _, c := range crons {
			r.CancelCron(id, c.Name)
			cancelled = append(cancelled, "cron "+c.Name)
		}
		if err := r.Pause(id); err != nil {
			status := 400
			if errors.Is(err, errBusy) {
				status = 409 // another action holds it: try again (as writeErr)
			} else if errors.Is(err, errDraining) {
				status = 503
			}
			writeJSON(w, status, map[string]any{"error": err.Error(), "cancelled": cancelled})
			return
		}
		writeJSON(w, 202, map[string]any{"ok": true, "phase": "pausing", "cancelled": cancelled})
	}))
	// resume and restart from the setup session, as the actions key's resume and the app's Restart (no prompt, no option
	// change): a line on an image from before the router's Claude login gets a resume-upgrade approval instead
	// (flows.go legacyLoginImage), so the phone decides; wakeups and crons stay armed
	public("POST /setup/sessions/{id}/resume", setupOnly(func(w http.ResponseWriter, req *http.Request, _ []byte) {
		if err := r.Resume(req.PathValue("id"), false); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 202, map[string]any{"ok": true})
	}))
	public("POST /setup/sessions/{id}/restart", setupOnly(func(w http.ResponseWriter, req *http.Request, _ []byte) {
		out, err := r.Restart(req.PathValue("id"), RestartRequest{})
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 202, out)
	}))
	// the importing line's first machine (its manifest is served at /m/restore-snapshot, restore.go)
	m("GET /m/import-file/{name}", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		r.serveImportFile(w, machine, req.PathValue("name"))
	})
}

// ---- small helpers -----------------------------------------------------------------------------------------------

func sha256Bytes(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// hashCounter: sha256 and byte count of what is written through it, reporting progress
type hashCounter struct {
	h        hash.Hash
	n        int64
	progress func(int64)
}

func newHashCounter(progress func(int64)) *hashCounter {
	return &hashCounter{h: sha256.New(), progress: progress}
}

func (c *hashCounter) Write(p []byte) (int, error) {
	c.h.Write(p)
	c.n += int64(len(p))
	if c.progress != nil {
		c.progress(int64(len(p)))
	}
	return len(p), nil
}

func (c *hashCounter) sum() string { return hex.EncodeToString(c.h.Sum(nil)) }
