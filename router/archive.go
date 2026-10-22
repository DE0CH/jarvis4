package main

// Archives of destroyed sessions, previous sessions and restoring one (Jarvis 1 lib/archive.js, server.js
// destroySession / records). docs/PARITY.md "Previous sessions".
//
// Destroy (flows.go) pauses a running session first, so its machine signs and uploads a final snapshot,
// then archive() writes it to the Storage Box with the router's own credentials, in Jarvis 1's layout so its
// transcript search indexes it:
//
//	claude-records/<yyyy-mm-dd> <title>/
//	  transcript-<id>.jsonl         every ~/.claude/projects/*/*.jsonl in the snapshot, and every live copy
//	                                (.live/<session id>/) the snapshot doesn't hold byte-identical (livearchive.go)
//	  artifacts/**                  everything under ~/artifacts (symlinks followed inside the snapshot)
//	  session.json                  what the session was (title, stores, repos, model, …)
//	  restore-<session id>.json     which of the files are this session's (the dir may be shared)
//	  jarvis2/snapshot.tar.gz       the machine-signed snapshot, as it came from the machine
//	  jarvis2/snapshot.sig          its signature: the signer's signing key over sha256hex(snapshot)
//	  jarvis2/cert.json             the signer's core-signed succession cert (names its signing key)
//	  jarvis2/core-cert.json        the master-signed statement naming the core's key
//
// and adds the session to claude-records/.index/jarvis2-destroyed-sessions.json (Jarvis 1 keeps its own
// index, .index/destroyed-sessions.json; a separate file keeps each Jarvis's Previous list and purge to its
// own sessions). A reader verifies jarvis2/: core-cert against the master key → cert against the core key →
// snapshot against the cert's machine signing key.
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
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	recordsRoot  = "claude-records"
	recordsIndex = recordsRoot + "/.index/jarvis4-destroyed-sessions.json" // Jarvis 2 keeps its own index
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
	Dir         string    `json:"dir"`
	Title       string    `json:"title"`       // the title it was archived under
	Transcripts []string  `json:"transcripts"` // file names in Dir, oldest first
	Artifacts   int       `json:"artifacts"`
	Signer      string    `json:"signer"` // the machine whose snapshot it is
	SnapshotAt  time.Time `json:"snapshotAt"`
	// the snapshot wasn't named in the kill (Session.SnapshotNote): kept, but not restorable until the core vouches
	Unverified string       `json:"unverified,omitempty"`
	Last       *TailMessage `json:"last,omitempty"`
	// Live: the session's .live transcripts, each in the snapshot or copied into Dir (livearchive.go)
	Live []LiveCopy `json:"live,omitempty"`
	// NoSnapshot: why the record has no signed snapshot, or why the snapshot isn't the last machine's
	NoSnapshot string `json:"noSnapshot,omitempty"`
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

// ---- the archive dir ---------------------------------------------------------------------------------

// archiveDirFor: the dir for a title (archivedir.go's layout); a leading "." would hide it from the search
func archiveDirFor(s *Session, title string) string {
	c := *s
	c.ArchiveDir, c.AppTitle, c.UserTitle, c.Label, c.Title = "", "", "", strings.TrimLeft(title, ". "), ""
	return (&Router{}).archiveDir(c)
}

// pickArchiveDir: the session's dir, made unique against what is already on the box (Jarvis 1 or another
// session may have the same date and title) and kept on the session, so a retried destroy and the destroy
// hooks (the Discord export) use the same one
func (r *Router) pickArchiveDir(box *StorageBox, s *Session, title string) (string, error) {
	if s.ArchiveDir != "" {
		return s.ArchiveDir, nil
	}
	base := archiveDirFor(s, title)
	dir := base
	for i := 2; ; i++ {
		taken, err := box.Exists(dir + "/session.json")
		if err != nil {
			return "", err
		}
		if !taken {
			break
		}
		if i > 50 { // 50 of the same name: the session id makes it unique
			dir = base + " " + s.ID
			break
		}
		dir = base + " " + strconv.Itoa(i)
	}
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[s.ID]; x != nil {
			x.ArchiveDir = dir
		}
	})
	s.ArchiveDir = dir
	return dir, nil
}

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

// archive: the session's latest snapshot onto the Storage Box (layout at the top), with every live copy it doesn't
// hold. With no snapshot, the live copies alone (archiveLiveOnly). nil when there is nothing to archive (no snapshot
// and no live copy: the session never ran) or records are off. Then the destroy hooks run (the Discord export into
// the same dir).
func (r *Router) archive(id string) (*ArchiveInfo, error) {
	if recordsOff() {
		return nil, nil
	}
	box := r.box()
	if m, _, _ := r.latestSnapshot(id); m == "" {
		if box == nil {
			log.Printf("session %s: no snapshot to archive", id)
			return nil, nil
		}
		live, err := box.List(liveDir(id))
		if err != nil {
			return nil, fmt.Errorf("listing the live copies: %w", err)
		}
		if len(live) == 0 {
			log.Printf("session %s: no snapshot and no live copy to archive", id)
			return nil, nil
		}
	}
	if box == nil {
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
	info, err := r.archiveSnapshot(box, &s)
	if err == nil && info == nil {
		info, err = r.archiveLiveOnly(box, &s)
	}
	if err == nil && info != nil {
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				x.ArchiveDir = info.Dir
			}
		})
		pokeSearch() // searchable at once (searchsvc.go)
	}
	return info, err
}

func (r *Router) archiveSnapshot(box *StorageBox, s *Session) (*ArchiveInfo, error) {
	machine, cert, at := r.latestSnapshot(s.ID)
	if machine == "" {
		log.Printf("session %s: no snapshot to archive", s.ID)
		return nil, nil
	}
	sn := r.snap(machine)
	if sn == nil {
		return nil, fmt.Errorf("the snapshot of %s is gone", machine)
	}
	facts, err := r.snapFacts(sn)
	if err != nil {
		return nil, fmt.Errorf("reading the snapshot: %w", err)
	}
	title := sessionTitle(*s)
	if s.AppTitle == "" && s.Label == "" && s.UserTitle == "" && facts.Tail != nil && facts.Tail.Title != "" {
		title = facts.Tail.Title // the title the app showed, from the transcript
	}
	dir, err := r.pickArchiveDir(box, s, title)
	if err != nil {
		return nil, err
	}
	if err := box.Mkcols(dir + "/jarvis2"); err != nil {
		return nil, err
	}
	tmp := filepath.Join(r.cfg.DataDir, "tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return nil, err
	}
	snap, err := r.snapToFile(sn, tmp) // the archive walks it twice: a scratch copy, gone after
	if err != nil {
		return nil, fmt.Errorf("fetching the snapshot: %w", err)
	}
	defer os.Remove(snap)
	defer os.Remove(snap + ".sig")
	up, err := uploadSnapshotFiles(box, dir, snap, tmp, r.archiveProgress(s.ID))
	r.setWaiting(s.ID, "")
	if err != nil {
		return nil, err
	}
	taken := map[string]bool{}
	for _, t := range up.transcripts {
		taken[t] = true
	}
	live, liveAdded, err := r.archiveLive(box, s.ID, dir, up.sums, taken)
	if err != nil {
		return nil, err
	}
	up.transcripts = append(liveAdded, up.transcripts...) // older conversations first; the snapshot's newest stays last
	// the signed snapshot and what verifies it
	sig, err := os.ReadFile(snap + ".sig")
	if err != nil {
		return nil, err
	}
	certJSON, _ := json.Marshal(cert)
	if err := box.PutFile(dir+"/jarvis2/snapshot.tar.gz", snap); err != nil {
		return nil, err
	}
	if err := box.PutBytes(dir+"/jarvis2/snapshot.sig", []byte(strings.TrimSpace(string(sig)))); err != nil {
		return nil, err
	}
	if err := box.PutBytes(dir+"/jarvis2/cert.json", certJSON); err != nil {
		return nil, err
	}
	if b := r.coreCert(); b != nil {
		if err := box.PutBytes(dir+"/jarvis2/core-cert.json", b); err != nil {
			return nil, err
		}
	}
	info := &ArchiveInfo{Dir: dir, Title: title, Transcripts: up.transcripts, Artifacts: up.artifacts, Signer: machine, SnapshotAt: at.UTC(),
		Unverified: s.SnapshotNote, Live: live, NoSnapshot: s.NoSnapshot}
	if facts.Tail != nil {
		info.Last = snippet(*facts.Tail)
	}
	now := time.Now().UTC()
	meta := map[string]any{
		"id": s.ID, "jarvis": 2, "title": title, "label": s.Label, "aiTitle": s.Title, "created": s.Created,
		"destroyedAt": now, "archiveDir": dir, "environment": strings.Join(s.Stores, ","), "stores": s.Stores,
		"repos": s.Repos, "model": s.Model, "permissionMode": s.PermissionMode, "size": s.Size, "harness": s.Harness,
		"image": s.Image, "line": certField(cert, "line"), "snapshotMachine": machine, "snapshotAt": info.SnapshotAt,
		"unresolvedArtifactLinks": up.unresolved, "live": live,
	}
	if s.NoSnapshot != "" {
		meta["noSnapshot"] = s.NoSnapshot + "; this is the newest signed snapshot the router had"
	}
	if s.SnapshotNote != "" {
		meta["snapshotUnverified"] = s.SnapshotNote
	}
	mb, _ := json.MarshalIndent(meta, "", " ")
	if err := box.PutBytes(dir+"/session.json", mb); err != nil {
		return nil, err
	}
	man, _ := json.Marshal(map[string]any{"id": s.ID, "archiveDir": dir, "transcripts": up.transcripts, "artifacts": up.artifactNames,
		"snapshot": "jarvis2/snapshot.tar.gz", "signer": machine})
	if err := box.PutBytes(dir+"/restore-"+s.ID+".json", man); err != nil {
		return nil, err
	}
	entry := map[string]any{"id": s.ID, "jarvis": 2, "title": title, "label": s.Label, "archiveDir": dir, "created": s.Created,
		"destroyedAt": now, "transcripts": len(up.transcripts), "artifacts": up.artifacts, "last": info.Last,
		"environment": strings.Join(s.Stores, ","), "repos": s.Repos, "model": s.Model, "size": s.Size, "harness": s.Harness,
		"permissionMode": s.PermissionMode, "restored": []any{}}
	if err := updateIndex(box, func(list []map[string]any) []map[string]any {
		out := []map[string]any{entry}
		for _, e := range list {
			if e["id"] != s.ID {
				out = append(out, e)
			}
		}
		return out
	}); err != nil {
		return nil, fmt.Errorf("indexing the archive: %w", err)
	}
	log.Printf("session %s: archived to %s (%d transcript(s), %d artifact file(s))", s.ID, dir, len(up.transcripts), up.artifacts)
	return info, nil
}

type uploaded struct {
	transcripts   []string           // archive names, oldest first
	sums          map[string]fileSum // transcript file name (<uuid>.jsonl) → its size and sha256
	artifacts     int
	artifactNames []string
	unresolved    []string
}

// uploadSnapshotFiles: the transcripts and ~/artifacts out of the snapshot, as plain files. Two passes: the
// first learns the names, the modification times and the symlinks under artifacts/ (followed when they
// point inside the snapshot, like Jarvis 1's `find -L`), the second uploads.
// archiveProgress: an archive's upload progress, as the session's waiting text (the app shows it on the destroying
// session) and, at most every 20 s, a line in the destroy's lifecycle log and the router's log
func (r *Router) archiveProgress(sid string) func(done, total int) {
	var mu sync.Mutex
	var last time.Time
	return func(done, total int) {
		mu.Lock()
		defer mu.Unlock()
		if done < total && time.Since(last) < archiveProgressEvery {
			return
		}
		last = time.Now()
		text := fmt.Sprintf("archiving to the Storage Box: %d of %d files uploaded", done, total)
		r.setWaiting(sid, text)
		r.lcNote(sid, "", text)
		log.Printf("session %s: %s", sid, text)
	}
}

var archiveProgressEvery = 20 * time.Second

// archiveUploads: how many artifact/transcript uploads of one archive run at once
var archiveUploads = 4

// errStopWalk: the tar walk ends early because an upload already failed (that error is the one returned)
var errStopWalk = errors.New("an upload failed")

// uploadSnapshotFiles: progress (may be nil) hears every finished upload: done of total (a file a symlink also names
// counts once per name)
func uploadSnapshotFiles(box *StorageBox, dir, snap, tmp string, progress func(done, total int)) (*uploaded, error) {
	type entry struct {
		at time.Time
	}
	regular := map[string]entry{}
	links := map[string]string{}
	err := walkTar(snap, func(h *tar.Header, _ io.Reader) error {
		name := path.Clean(h.Name)
		switch h.Typeflag {
		case tar.TypeReg:
			regular[name] = entry{h.ModTime}
		case tar.TypeSymlink:
			if strings.HasPrefix(name, "artifacts/") {
				links[name] = h.Linkname
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := &uploaded{sums: map[string]fileSum{}}
	dests := map[string][]string{} // snapshot name → archive names
	var transcripts []string
	for name := range regular {
		if isTranscript(name) {
			transcripts = append(transcripts, name)
			dests[name] = append(dests[name], "transcript-"+path.Base(name))
		} else if strings.HasPrefix(name, "artifacts/") {
			dests[name] = append(dests[name], name)
		}
	}
	for l, target := range links {
		t := resolveLink(l, target)
		if t == "" {
			out.unresolved = append(out.unresolved, l)
			continue
		}
		hit := false
		for name := range regular {
			switch {
			case name == t:
				dests[name] = append(dests[name], l)
				hit = true
			case strings.HasPrefix(name, t+"/"):
				dests[name] = append(dests[name], l+strings.TrimPrefix(name, t))
				hit = true
			}
		}
		if !hit {
			out.unresolved = append(out.unresolved, l)
		}
	}
	sort.Slice(transcripts, func(i, j int) bool {
		a, b := regular[transcripts[i]].at, regular[transcripts[j]].at
		if a.Equal(b) {
			return transcripts[i] < transcripts[j]
		}
		return a.Before(b)
	})
	for _, t := range transcripts {
		out.transcripts = append(out.transcripts, "transcript-"+path.Base(t))
	}
	sort.Strings(out.unresolved)
	total := 0
	for _, ds := range dests {
		total += len(ds)
	}
	// the uploads run archiveUploads at a time (DECISIONS 226): one by one, a session with thousands of artifact files
	// took the Storage Box's round trip per file (2094 files: 20 min) and its destroy looked stuck. The tar is read in
	// order; each file goes to a temp file the worker deletes once it is up, so at most a few are on disk at once.
	type job struct {
		name, local string
		ds          []string
	}
	jobs := make(chan job)
	var (
		mu       sync.Mutex
		firstErr error
		done     int
		wg       sync.WaitGroup
	)
	fail := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}
	failed := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return firstErr != nil
	}
	for i := 0; i < archiveUploads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				for _, d := range j.ds {
					if failed() {
						break
					}
					if err := box.PutFile(dir+"/"+d, j.local); err != nil {
						fail(err)
						break
					}
					mu.Lock()
					done++
					n := done
					if strings.HasPrefix(d, "artifacts/") {
						out.artifacts++
						out.artifactNames = append(out.artifactNames, strings.TrimPrefix(d, "artifacts/"))
					}
					mu.Unlock()
					if progress != nil {
						progress(n, total)
					}
				}
				os.Remove(j.local)
			}
		}()
	}
	made := map[string]bool{dir: true, dir + "/jarvis2": true} // the archive dir is made by the caller
	mkdirs := func(p string) error {                           // each directory once, its parents first, one MKCOL each
		if p == "." || made[dir+"/"+p] {
			return nil
		}
		segs := strings.Split(p, "/")
		for i := range segs {
			d := dir + "/" + strings.Join(segs[:i+1], "/")
			if made[d] {
				continue
			}
			if err := box.mkcol(d); err != nil {
				return err
			}
			made[d] = true
		}
		return nil
	}
	err = walkTar(snap, func(h *tar.Header, body io.Reader) error {
		name := path.Clean(h.Name)
		ds := dests[name]
		if h.Typeflag != tar.TypeReg || len(ds) == 0 {
			return nil
		}
		if failed() {
			return errStopWalk
		}
		f, err := os.CreateTemp(tmp, "archive-*")
		if err != nil {
			return err
		}
		_, err = io.Copy(f, body)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil && isTranscript(name) {
			var sum fileSum
			if sum, err = sumFile(f.Name()); err == nil {
				out.sums[path.Base(name)] = sum
			}
		}
		for _, d := range ds {
			if err == nil {
				err = mkdirs(path.Dir(d))
			}
		}
		if err != nil {
			os.Remove(f.Name())
			return err
		}
		jobs <- job{name: name, local: f.Name(), ds: ds}
		return nil
	})
	close(jobs)
	wg.Wait()
	if err == errStopWalk {
		err = nil
	}
	if err == nil {
		err = firstErr
	}
	if err != nil {
		return nil, err
	}
	sort.Strings(out.artifactNames)
	return out, nil
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
	p := rec.Archive.Dir + "/" + rec.Archive.Transcripts[len(rec.Archive.Transcripts)-1]
	text, err := box.GetTail(p, tailBytes)
	if err != nil {
		return nil, 500, err
	}
	if text == nil {
		return nil, 404, fmt.Errorf("transcript missing: %s", p)
	}
	if len(text) > tailBytes {
		text = text[len(text)-tailBytes:]
	}
	t := tailOf(text)
	return &t, 200, nil
}

// ---- forget / purge a record ------------------------------------------------------------------------

// DeleteRecord: off the list (and the box's index); with purge its archive too — the whole dir unless
// another Jarvis 4 record shares it, then only this session's own files
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
		dir := rec.Archive.Dir
		if !regexp.MustCompile(`^claude-records/[^/.][^/]*$`).MatchString(dir) {
			return nil, fmt.Errorf("refusing to delete '%s': not a claude-records/<folder> archive dir", dir)
		}
		keep := map[string]bool{}
		shared := []string{}
		r.st.Do(func(d *persisted) {
			for _, o := range d.Records {
				if o.ID != id && o.Archive != nil && o.Archive.Dir == dir {
					shared = append(shared, o.ID)
					for _, t := range o.Archive.Transcripts {
						keep[t] = true
					}
				}
			}
		})
		if len(shared) == 0 {
			if err := box.Delete(dir + "/"); err != nil {
				return nil, err
			}
			out["purged"] = map[string]any{"dir": dir, "removed": "folder"}
		} else {
			files := []string{"restore-" + id + ".json"}
			for _, t := range rec.Archive.Transcripts {
				if !keep[t] {
					files = append(files, t)
				}
			}
			for _, f := range files {
				if err := box.Delete(dir + "/" + f); err != nil {
					return nil, err
				}
			}
			out["purged"] = map[string]any{"dir": dir, "removed": "files", "files": files, "sharedWith": shared}
		}
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
	app("POST /api/records", r.indexRecord)        // records.go: an archive already on the Storage Box, by hand
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
