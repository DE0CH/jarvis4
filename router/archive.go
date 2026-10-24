package main

// Archives of destroyed sessions, previous sessions and restoring one (Jarvis 1 lib/archive.js, server.js
// destroySession / records). docs/PARITY.md "Previous sessions".
//
// Destroy (flows.go) pauses a running session first, so its machine signs and uploads a final snapshot, then
// archive() writes it to the Storage Box with the router's own credentials as ONE streamed .tar.gz in Jarvis 4's
// own folder (archivetar.go has the layout). A reader verifies jarvis2/ in it: core-cert against the master key →
// cert against the core key → snapshot against the cert's machine signing key.
//
// Restore (a destroyed session back as a NEW line): see restoreRecord.

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	recordsRoot  = "claude-records"
	recordsIndex = archivesRoot + "/index.json" // Jarvis 4's own (archivetar.go); Jarvis 2 keeps claude-records/.index
	// changesFile: the repos' state, written by the machine into every snapshot (machine/restore.go)
	changesFile = ".jarvis2-changes.txt"
)

// repoChangesSH: one "<repo> <uncommitted files> <unpushed commits, -1 = no upstream>" line per repo under
// ~/workspace (the same script as Jarvis 1's REPO_CHANGES_SH and machine/restore.go's)
const repoChangesSH = `cd ~/workspace 2>/dev/null || exit 0; for d in */; do d=${d%/}; [ -d "$d/.git" ] || continue; ` +
	`u=$(git -C "$d" status --porcelain 2>/dev/null | wc -l); ` +
	`if git -C "$d" rev-parse --abbrev-ref @{u} >/dev/null 2>&1; then p=$(git -C "$d" rev-list @{u}..HEAD --count 2>/dev/null || echo 0); else p=-1; fi; ` +
	`echo "$d $u $p"; done`

// ArchiveInfo: what a destroy put on the Storage Box
type ArchiveInfo struct {
	File        string    `json:"file"`        // claude-records/.jarvis4-records/<date> <title>.tar.gz (archivetar.go)
	Title       string    `json:"title"`       // the title it was archived under
	Transcripts []string  `json:"transcripts"` // their names in the archive, oldest first
	Artifacts   int       `json:"artifacts"`
	Signer      string    `json:"signer"` // the machine whose snapshot it is
	SnapshotAt  time.Time `json:"snapshotAt"`
	// the snapshot wasn't named in the kill (Session.SnapshotNote): kept, but not restorable until the core vouches
	Unverified string       `json:"unverified,omitempty"`
	Last       *TailMessage `json:"last,omitempty"`
	// Live: the session's .live transcripts, each in the snapshot or copied into the archive (livearchive.go)
	Live []LiveCopy `json:"live,omitempty"`
	// NoSnapshot: why the record has no signed snapshot, or why the snapshot isn't the last machine's
	NoSnapshot string `json:"noSnapshot,omitempty"`
	// Bytes: the archive's size on the Storage Box; UploadSeconds: how long its upload took
	Bytes         int64   `json:"bytes,omitempty"`
	UploadSeconds float64 `json:"uploadSeconds,omitempty"`
}

// MarshalJSON: transcripts always go out as an array. A snapshot with no transcript (a session destroyed before its
// first conversation) leaves the slice nil, and "transcripts": null blanked the web page's Previous tab; records
// already stored that way are covered too.
func (a ArchiveInfo) MarshalJSON() ([]byte, error) {
	type plain ArchiveInfo
	if a.Transcripts == nil {
		a.Transcripts = []string{}
	}
	return json.Marshal(plain(a))
}

type RestoreMark struct {
	Session string    `json:"sessionId"`
	At      time.Time `json:"at"`
}

// ---- the Storage Box: the router's own credentials --------------------------------------------------

var (
	sboxOnce sync.Once
	sbox     *StorageBox
	indexMu  sync.Mutex // the index is read-modify-write and WebDAV has no append
)

func (r *Router) box() *StorageBox {
	sboxOnce.Do(func() { sbox = recordsBoxFromEnv() })
	return sbox
}

// recordsOff: RECORDS_OFF=1 (the e2e test, which has no Storage Box) destroys without archiving
func recordsOff() bool { return os.Getenv("RECORDS_OFF") == "1" }

// ---- the snapshot to archive ---------------------------------------------------------------------------

// latestSnapshot: the newest snapshot any of the session's machines left on the volume, and that machine's
// cert (its signing key checks the snapshot)
func (r *Router) latestSnapshot(sessionID string) (machine string, cert *Doc, at time.Time) {
	var machines []string
	certs := map[string]*Doc{}
	r.st.Do(func(d *persisted) {
		for m, sid := range d.Machines {
			if sid == sessionID {
				machines = append(machines, m)
				certs[m] = d.Certs[m]
				if st := d.Started[m]; certs[m] == nil && st != nil && st.KernelCert != nil {
					certs[m] = st.KernelCert // kernelline.go: a kernel machine's, the spawner's cert naming its key
				}
			}
		}
	})
	for _, m := range machines {
		s := r.snap(m)
		if s == nil || s.State != "committed" || certs[m] == nil {
			continue
		}
		if machine == "" || s.CommittedAt.After(at) {
			machine, cert, at = m, certs[m], s.CommittedAt
		}
	}
	return
}

// ---- destroy: snapshot + kill, then archive ------------------------------------------------------------

// snapshotAndKill: what a destroy does to a running machine (flows.go); false (state failed, machine kept) when its
// final snapshot or the kill fails (snapsafe.go; force: Destroy anyway goes on past a failed snapshot or kill). A
// destroy ends the line, so nothing will restore the snapshot through the core: when the core refuses the kill for the
// snapshot's signature (a machine certified by an earlier core), it kills without naming one and the router's copy is
// archived as is, marked; it goes on when Fly no longer has the machine, or with force whatever the kill said (the
// router then stops serving the machine, which shows on the Machines tab with no session). DECISIONS 181.
func (r *Router) snapshotAndKill(id, machine string, force bool) bool {
	if !r.finalSnapshotAndKillFor(id, machine, true, force) {
		return false
	}
	now := time.Now().UTC()
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			x.MachineID, x.PausedAt, x.Status = "", &now, ""
		}
	})
	return true
}

// snapshotFromEarlierCore: the mark on an archive whose snapshot the core refused to name in the kill
const snapshotFromEarlierCore = "from an earlier core, not verified by this core"

// destroyAnywayHint: the end of a failed destroy's error, which the apps match to offer Destroy anyway
const destroyAnywayHint = " (Destroy anyway removes the session; the machine is then on the Machines tab)"

// refusedSnapshot: the core refusing a kill because the snapshot isn't signed by the machine's current key
func refusedSnapshot(err error) bool {
	var ce *CoreError
	return errors.As(err, &ce) && ce.Status == 403 && strings.Contains(ce.Msg, "snapshot")
}

// flyMachineGone: Fly (the router's read token) lists no such live machine. An error when Fly can't be asked.
var flyMachineGone = func(id string) (bool, error) {
	ms, err := listFlyMachines()
	if err != nil {
		return false, err
	}
	for _, m := range ms {
		if m.ID == id && m.State != "destroyed" {
			return false, nil
		}
	}
	return true, nil
}

// archive: the session's archive onto the Storage Box (archivetar.go): its latest snapshot with every live copy it
// doesn't hold, or the live copies alone. nil when there is nothing to archive (no snapshot and no live copy: the
// session never ran) or records are off.
func (r *Router) archive(id string) (*ArchiveInfo, error) {
	if recordsOff() {
		return nil, nil
	}
	box := r.box()
	if box == nil {
		if m, _, _ := r.latestSnapshot(id); m == "" {
			log.Printf("session %s: no snapshot to archive", id)
			return nil, nil
		}
		return nil, errNoStorageBox
	}
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	if s.ID == "" {
		return nil, fmt.Errorf("no session %s", id)
	}
	info, err := r.archiveSession(box, &s)
	if err == nil && info != nil {
	}
	return info, err
}

// resolveLink: a symlink's target as a path in the snapshot ("" when it points outside it)
func resolveLink(link, target string) string {
	const home = "/home/claude/"
	var t string
	if path.IsAbs(target) {
		if !strings.HasPrefix(target, home) {
			return ""
		}
		t = path.Clean(strings.TrimPrefix(target, home))
	} else {
		t = path.Clean(path.Join(path.Dir(link), target))
	}
	if t == "." || t == ".." || strings.HasPrefix(t, "../") || path.IsAbs(t) {
		return ""
	}
	return t
}

func walkTar(p string, fn func(h *tar.Header, body io.Reader) error) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := fn(h, tr); err != nil {
			return err
		}
	}
}

func updateIndex(box *StorageBox, fn func([]map[string]any) []map[string]any) error {
	indexMu.Lock()
	defer indexMu.Unlock()
	raw, err := box.Get(recordsIndex)
	if err != nil {
		return err
	}
	var list []map[string]any
	if raw != nil {
		if err := json.Unmarshal(raw, &list); err != nil {
			return fmt.Errorf("%s is not a JSON array: %w", recordsIndex, err)
		}
	}
	next := fn(list)
	if err := box.Mkcols(path.Dir(recordsIndex)); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(next, "", " ")
	return box.PutBytes(recordsIndex, b)
}

// ---- the uncommitted-work check ----------------------------------------------------------------------

type RepoChange struct {
	Name        string `json:"name"`
	Uncommitted int    `json:"uncommitted"`
	Unpushed    int    `json:"unpushed"` // -1: the branch has no upstream
}

func parseRepoChanges(text string) []RepoChange {
	out := []RepoChange{}
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		u, _ := strconv.Atoi(f[1])
		p, err := strconv.Atoi(f[2])
		if err != nil {
			p = 0
		}
		out = append(out, RepoChange{f[0], u, p})
	}
	return out
}

// Changes: a running session's repos (a command under the archive holder's grant), or a paused session's as
// its last snapshot recorded them
func (r *Router) Changes(id string) map[string]any {
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	no := func(reason string) map[string]any {
		return map[string]any{"checked": false, "reason": reason, "repos": []RepoChange{}}
	}
	switch {
	case s.ID == "":
		return no("no such session")
	case s.MachineID != "" && s.State == "started":
		res, err := r.Exec(id, "archive", repoChangesSH, 20*time.Second)
		if err != nil {
			return no(err.Error())
		}
		return map[string]any{"checked": true, "repos": parseRepoChanges(res.Stdout), "status": s.Status}
	case s.MachineID == "" && s.State == "paused":
		return r.snapshotChanges(id)
	}
	return no("session is " + s.State)
}

// snapshotChanges: the repos' state as the session's newest snapshot recorded it (the machine writes it just
// before tarring the workspace, and a snapshot is frozen)
func (r *Router) snapshotChanges(id string) map[string]any {
	no := func(reason string) map[string]any {
		return map[string]any{"checked": false, "reason": reason, "repos": []RepoChange{}}
	}
	m, _, _ := r.latestSnapshot(id)
	if m == "" {
		return no("it has no pause snapshot")
	}
	facts, err := r.snapFactsOf(m)
	if err != nil {
		return no(err.Error())
	}
	if facts.Changes == nil {
		return no("its pause snapshot has no record of the repos' state — resume it and check again")
	}
	return map[string]any{"checked": true, "paused": true, "repos": parseRepoChanges(*facts.Changes), "status": ""}
}

// ---- tails ------------------------------------------------------------------------------------------

// PausedTail: the end of a paused session's conversation, from its snapshot on the volume
func (r *Router) PausedTail(id string) (*Tail, int, error) {
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	if s.ID == "" {
		return nil, 404, errors.New("no such session")
	}
	stale := s.MachineID != "" // running: its last pause snapshot's tail, marked stale (the live view is Remote Control)
	m, _, _ := r.latestSnapshot(id)
	if m == "" {
		return nil, 404, errors.New("this session has no pause snapshot yet")
	}
	facts, err := r.snapFactsOf(m)
	if err != nil {
		return nil, 500, err
	}
	t := Tail{Messages: []TailMessage{}}
	if facts.Tail != nil {
		t = *facts.Tail
	}
	t.Stale = stale
	return &t, 200, nil
}

func (r *Router) record(id string) *Record {
	var rec *Record
	r.st.Do(func(d *persisted) {
		for _, x := range d.Records {
			if x.ID == id {
				c := *x
				rec = &c
			}
		}
	})
	return rec
}

// RecordTail: the end of a destroyed session's conversation, from its archive (a Range read)
func (r *Router) RecordTail(id string) (*Tail, int, error) {
	rec := r.record(id)
	if rec == nil {
		return nil, 404, errors.New("no such previous session")
	}
	if rec.Archive == nil || len(rec.Archive.Transcripts) == 0 {
		return nil, 404, errors.New("this session was destroyed without an archived transcript")
	}
	box := r.box()
	if box == nil {
		return nil, 500, errNoStorageBox
	}
	name := rec.Archive.Transcripts[len(rec.Archive.Transcripts)-1]
	text, err := archiveTail(box, rec.Archive.File, name, tailBytes)
	if err != nil {
		if errors.Is(err, errNoArchive) {
			return nil, 404, err
		}
		return nil, 500, err
	}
	if text == nil {
		return nil, 404, fmt.Errorf("transcript missing: %s in %s", name, rec.Archive.File)
	}
	if len(text) > tailBytes {
		text = text[len(text)-tailBytes:]
	}
	t := tailOf(text)
	return &t, 200, nil
}

// ---- forget / purge a record ------------------------------------------------------------------------

var archiveFileRE = regexp.MustCompile(`^claude-records/\.jarvis4-records/[^/.][^/]*\.tar\.gz$`)

// DeleteRecord: off the list (and the box's index); with purge its archive file too
func (r *Router) DeleteRecord(id string, purge bool) (map[string]any, error) {
	rec := r.record(id)
	if rec == nil {
		return map[string]any{"ok": true, "already": true}, nil // gone already: what was asked for
	}
	box := r.box()
	out := map[string]any{"ok": true}
	if purge && rec.Archive != nil {
		if box == nil {
			return nil, errNoStorageBox
		}
		file := rec.Archive.File
		if !archiveFileRE.MatchString(file) {
			return nil, fmt.Errorf("refusing to delete '%s': not a %s/<name>.tar.gz archive", file, archivesRoot)
		}
		if err := box.Delete(file); err != nil {
			return nil, err
		}
		out["purged"] = map[string]any{"file": file}
	}
	if box != nil {
		if err := updateIndex(box, func(list []map[string]any) []map[string]any {
			out := []map[string]any{}
			for _, e := range list {
				if e["id"] != id {
					out = append(out, e)
				}
			}
			return out
		}); err != nil {
			return nil, err
		}
	}
	r.st.Do(func(d *persisted) {
		keep := d.Records[:0]
		for _, x := range d.Records {
			if x.ID != id {
				keep = append(keep, x)
			}
		}
		d.Records = keep
	})
	return out, nil
}

// ---- routes ---------------------------------------------------------------------------------------

func (r *Router) registerArchive(app appRoute, m machineRoute) {
	app("GET /api/sessions/{id}/changes", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, 200, r.Changes(req.PathValue("id")))
	})
	app("GET /api/sessions/{id}/tail", func(w http.ResponseWriter, req *http.Request) {
		t, st, err := r.PausedTail(req.PathValue("id"))
		if err != nil {
			writeJSON(w, st, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, t)
	})
	app("GET /api/records/{id}/tail", func(w http.ResponseWriter, req *http.Request) {
		t, st, err := r.RecordTail(req.PathValue("id"))
		if err != nil {
			writeJSON(w, st, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, t)
	})
	app("DELETE /api/records/{id}", func(w http.ResponseWriter, req *http.Request) {
		out, err := r.DeleteRecord(req.PathValue("id"), req.URL.Query().Get("purge") == "1")
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	app("POST /api/records/{id}/restore", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			RequestID string `json:"requestId"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		if in.RequestID == "" {
			in.RequestID = randID()
		}
		sid, err := r.RestoreRecord(req.PathValue("id"), in.RequestID)
		if err != nil {
			writeErr(w, err)
			return
		}
		r.noteOrigin(sid, Origin{Caller: appCaller(req), Call: APICall{Method: "POST", Path: req.URL.Path}, ViaCall: viaCall(req)}) // inbox.go
		writeJSON(w, 200, map[string]any{"id": sid, "requestId": in.RequestID})
	})
	m("POST /m/live-transcript", r.liveTranscript) // livesync.go
	m("GET /m/restore-snapshot", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		if id := r.importFor(machine); id != "" { // jarvis1import.go: an import's manifest (the cert names its hash)
			r.serveImportManifest(w, id)
			return
		}
		s := r.restoreFilesFor(machine)
		if s == nil {
			writeJSON(w, 404, map[string]string{"error": "no restore for this machine"})
			return
		}
		rd, err := r.snapOpen(req.Context(), s)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "no restore snapshot"})
			return
		}
		defer rd.Close()
		w.Header().Set("X-Snapshot-Sig", s.Sig)
		w.Header().Set("Content-Type", "application/gzip")
		http.ServeContent(w, req, "", s.CommittedAt, rd)
	})
}

// sha256hex: what a machine signs for a snapshot
func sha256hex(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (r *Router) archiveLoop() {
	for {
		awaitLead() // leaderlease.go
		r.tidyRestores()
		r.tidyImports() // jarvis1import.go
		time.Sleep(time.Minute)
	}
}
