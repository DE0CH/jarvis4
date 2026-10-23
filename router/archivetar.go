package main

// A destroyed session's archive: ONE .tar.gz on the Storage Box, written while it uploads (a chunked PUT fed by a
// pipe: no copy of the archive on disk or in memory), in Jarvis 4's own folder, which only Jarvis 4 reads and writes
// (Deyao, 2026-10-22: Jarvis 2's router writes claude-records/<date> <title>/ and its own index):
//
//	claude-records/.jarvis4-records/<yyyy-mm-dd> <title>.tar.gz      (" 2", " 3", … when the name is taken)
//	claude-records/.jarvis4-records/index.json                        every archive, newest first
//
// Inside, in this order (readers that want a transcript stop early; the snapshot, the biggest part, is last):
//
//	session.json                  what the session was (title, stores, repos, model, …)
//	restore-<session id>.json     the transcripts and artifacts it holds, and its snapshot
//	transcript-<id>.jsonl         every ~/.claude/projects/*/*.jsonl in the snapshot, and every live copy
//	                              (.live/<session id>/) the snapshot doesn't hold byte-identical (livearchive.go)
//	artifacts/**                  everything under ~/artifacts (symlinks followed inside the snapshot; a file a link
//	                              also names is stored once and the other names are tar hard links to it)
//	jarvis2/lifecycle.json        every boot/pause/resume/destroy's log (lifecycle.go), up to the archive
//	jarvis2/supervisor-log.jsonl  the supervisor's log (supervisorlog.go)
//	discord/messages.json, discord/attachments/<message id>-<file>    the session's Discord channel (discord.go)
//	jarvis2/cert.json             the snapshot signer's cert (names its signing key)
//	jarvis2/core-cert.json        the master-signed statement naming the core's key (when the router has one)
//	jarvis2/snapshot.sig          the signer's signing key over sha256hex(snapshot)
//	jarvis2/snapshot.tar.gz       the machine-signed snapshot, as it came from the machine
//
// A session with no signed snapshot but live copies gets the same archive without the snapshot parts (its
// session.json says why). The upload goes to <name>.part and is renamed once the Storage Box holds every byte, so an
// archive under its real name is always whole.

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const archivesRoot = recordsRoot + "/.jarvis4-records"

// archiveFileFor: the archive's name for a title (a leading "." is dropped)
func archiveFileFor(s *Session, title string) string {
	created := s.Created
	if created.IsZero() {
		created = time.Now()
	}
	return archivesRoot + "/" + created.UTC().Format("2006-01-02") + " " + safeTitle(strings.TrimLeft(title, ". "), s.ID) + ".tar.gz"
}

func safeTitle(t, fallback string) string {
	t = strings.Map(func(c rune) rune {
		if strings.ContainsRune(`/\:*?"<>|`, c) || c < 0x20 {
			return ' '
		}
		return c
	}, t)
	t = strings.Join(strings.Fields(t), " ")
	if r := []rune(t); len(r) > 60 {
		t = strings.TrimSpace(string(r[:60]))
	}
	if t == "" {
		return fallback
	}
	return t
}

// pickArchiveFile: the session's archive name, made unique against what is already in the folder and kept on the
// session, so a retried destroy writes the same one
func (r *Router) pickArchiveFile(box *StorageBox, s *Session, title string) (string, error) {
	if s.ArchiveFile != "" {
		return s.ArchiveFile, nil
	}
	base := strings.TrimSuffix(archiveFileFor(s, title), ".tar.gz")
	name := base
	for i := 2; ; i++ {
		taken, err := box.Exists(name + ".tar.gz")
		if err != nil {
			return "", err
		}
		if !taken {
			break
		}
		if i > 50 { // 50 of the same name: the session id makes it unique
			name = base + " " + s.ID
			break
		}
		name = base + " " + strconv.Itoa(i)
	}
	file := name + ".tar.gz"
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[s.ID]; x != nil {
			x.ArchiveFile = file
		}
	})
	s.ArchiveFile = file
	return file, nil
}

// ---- what goes in --------------------------------------------------------------------------------------------

// archivePlan: everything one archive holds, gathered before the upload so the stream can be made again on a retry
type archivePlan struct {
	file string
	head []memFile // session.json, restore-<id>.json
	live []diskFile
	// the snapshot (nil: a live-only archive): its local copy, and per snapshot name the archive names it goes to
	snap        string
	dests       map[string][]string
	transcripts map[string]bool // snapshot names that are transcripts (written first)
	tail        []memFile       // jarvis2/lifecycle.json, jarvis2/supervisor-log.jsonl
	discord     string          // a local dir with the Discord export ("" none)
	sigs        []memFile       // jarvis2/cert.json, core-cert.json, snapshot.sig
	rawBytes    int64           // the files' total size (progress)
}

type memFile struct {
	name string
	body []byte
}

type diskFile struct {
	name, local string
}

// snapshotLayout: pass one over the snapshot: what each file becomes in the archive (transcripts, artifacts, links
// followed), the transcripts in time order, and the transcripts' sums (to compare with the live copies)
type snapshotLayout struct {
	dests         map[string][]string
	transcripts   []string // archive names, oldest first
	isTranscript  map[string]bool
	sums          map[string]fileSum // transcript file name (<uuid>.jsonl) → its size and sha256
	artifacts     int
	artifactNames []string
	unresolved    []string
	bytes         int64
}

func layoutSnapshot(snap string) (*snapshotLayout, error) {
	type entry struct {
		at   time.Time
		size int64
	}
	regular := map[string]entry{}
	links := map[string]string{}
	out := &snapshotLayout{dests: map[string][]string{}, isTranscript: map[string]bool{}, sums: map[string]fileSum{}}
	err := walkTar(snap, func(h *tar.Header, body io.Reader) error {
		name := path.Clean(h.Name)
		switch h.Typeflag {
		case tar.TypeReg:
			regular[name] = entry{h.ModTime, h.Size}
			if isTranscript(name) {
				sum, err := sumReader(body)
				if err != nil {
					return err
				}
				out.sums[path.Base(name)] = sum
			}
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
	var transcripts []string
	for name := range regular {
		if isTranscript(name) {
			transcripts = append(transcripts, name)
			out.isTranscript[name] = true
			out.dests[name] = append(out.dests[name], "transcript-"+path.Base(name))
		} else if strings.HasPrefix(name, "artifacts/") {
			out.dests[name] = append(out.dests[name], name)
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
				out.dests[name] = append(out.dests[name], l)
				hit = true
			case strings.HasPrefix(name, t+"/"):
				out.dests[name] = append(out.dests[name], l+strings.TrimPrefix(name, t))
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
	for name, ds := range out.dests {
		sort.Strings(ds) // the first name holds the bytes, the others link to it: the same on every pass
		out.bytes += regular[name].size
		for _, d := range ds {
			if strings.HasPrefix(d, "artifacts/") {
				out.artifacts++
				out.artifactNames = append(out.artifactNames, strings.TrimPrefix(d, "artifacts/"))
			}
		}
	}
	sort.Strings(out.artifactNames)
	sort.Strings(out.unresolved)
	return out, nil
}

// ---- writing ---------------------------------------------------------------------------------------------------

// errStopWalk: a tar walk ends early (the reader found what it wanted)
var errStopWalk = errors.New("stop")

// writeArchive: the plan as one gzip-compressed tar into w
func writeArchive(w io.Writer, p *archivePlan, progress func(raw int64)) error {
	gz, _ := gzip.NewWriterLevel(w, gzip.BestSpeed) // the snapshot inside is compressed already
	tw := tar.NewWriter(gz)
	now := time.Now()
	var raw int64
	add := func(name string, size int64, at time.Time, body io.Reader) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: size, ModTime: at, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return err
		}
		n, err := io.Copy(tw, body)
		if err == nil && n != size {
			err = fmt.Errorf("%s: %d bytes, expected %d", name, n, size)
		}
		raw += n
		if progress != nil {
			progress(raw)
		}
		return err
	}
	mem := func(fs []memFile) error {
		for _, f := range fs {
			if err := add(f.name, int64(len(f.body)), now, strings.NewReader(string(f.body))); err != nil {
				return err
			}
		}
		return nil
	}
	disk := func(name, local string) error {
		f, err := os.Open(local)
		if err != nil {
			return err
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		return add(name, fi.Size(), fi.ModTime(), f)
	}
	if err := mem(p.head); err != nil {
		return err
	}
	for _, f := range p.live {
		if err := disk(f.name, f.local); err != nil {
			return err
		}
	}
	if p.snap != "" {
		// two passes over the local snapshot: the transcripts first, then the artifacts
		for _, transcripts := range []bool{true, false} {
			err := walkTar(p.snap, func(h *tar.Header, body io.Reader) error {
				name := path.Clean(h.Name)
				ds := p.dests[name]
				if h.Typeflag != tar.TypeReg || len(ds) == 0 || p.transcripts[name] != transcripts {
					return nil
				}
				if err := add(ds[0], h.Size, h.ModTime, body); err != nil {
					return err
				}
				for _, d := range ds[1:] {
					if err := tw.WriteHeader(&tar.Header{Name: d, Linkname: ds[0], Typeflag: tar.TypeLink, Mode: 0o644, ModTime: h.ModTime, Format: tar.FormatPAX}); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
	}
	if err := mem(p.tail); err != nil {
		return err
	}
	if p.discord != "" {
		err := filepath.Walk(p.discord, func(local string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(p.discord, local)
			return disk("discord/"+filepath.ToSlash(rel), local)
		})
		if err != nil {
			return err
		}
	}
	if err := mem(p.sigs); err != nil {
		return err
	}
	if p.snap != "" {
		if err := disk("jarvis2/snapshot.tar.gz", p.snap); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// archiveTries: how often an upload is made again from the plan before the archive fails
var archiveTries = 3

// uploadArchive: the plan streamed to <file>.part, its size checked against what was sent, then renamed to file.
// Returns the bytes the Storage Box holds and how long the upload took.
func (r *Router) uploadArchive(box *StorageBox, sid string, p *archivePlan) (int64, time.Duration, error) {
	if err := box.Mkcols(archivesRoot); err != nil {
		return 0, 0, err
	}
	part := p.file + ".part"
	var last error
	for try := 1; try <= archiveTries; try++ {
		t0 := time.Now()
		pr, pw := io.Pipe()
		var sent atomic.Int64
		progress := r.archiveProgress(sid, p.rawBytes)
		go func() {
			pw.CloseWithError(writeArchive(sentCounter{pw, &sent}, p, progress))
		}()
		err := box.PutStream(part, pr)
		pr.CloseWithError(errors.New("upload ended")) // the writer stops if the PUT ended early
		if err == nil {
			var size int64
			if size, err = box.Size(part); err == nil && size != sent.Load() {
				err = fmt.Errorf("the Storage Box holds %d bytes of %s, %d were sent", size, part, sent.Load())
			}
			if err == nil {
				if err = box.Move(part, p.file); err == nil {
					took := time.Since(t0)
					r.setWaiting(sid, "")
					return size, took, nil
				}
			}
		}
		last = err
		log.Printf("session %s: archive upload %d of %d: %v", sid, try, archiveTries, err)
		box.Delete(part)
		time.Sleep(time.Duration(try) * putBackoff)
	}
	r.setWaiting(sid, "")
	return 0, 0, last
}

type sentCounter struct {
	w io.Writer
	n *atomic.Int64
}

func (c sentCounter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n.Add(int64(n))
	return n, err
}

// archiveProgress: an archive's upload progress, as the session's waiting text (the app shows it on the destroying
// session) and, at most every 20 s, a line in the destroy's lifecycle log and the router's log
func (r *Router) archiveProgress(sid string, total int64) func(raw int64) {
	var mu sync.Mutex
	var last time.Time
	return func(raw int64) {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(last) < archiveProgressEvery {
			return
		}
		last = time.Now()
		text := fmt.Sprintf("archiving to the Storage Box: %s of %s", mb(raw), mb(total))
		r.setWaiting(sid, text)
		r.lcNote(sid, "", text)
		log.Printf("session %s: %s", sid, text)
	}
}

var archiveProgressEvery = 20 * time.Second

func mb(n int64) string { return fmt.Sprintf("%.1f MB", float64(n)/1e6) }

// ---- the archive of one session ------------------------------------------------------------------------------

// archiveSession: the session's archive (its latest snapshot, or only its live copies) onto the Storage Box and into
// the index. nil when there is neither (the session never ran).
func (r *Router) archiveSession(box *StorageBox, s *Session) (*ArchiveInfo, error) {
	tmp, err := os.MkdirTemp(filepath.Join(r.cfg.DataDir, "tmp"), "archive-")
	if err != nil {
		if err = os.MkdirAll(filepath.Join(r.cfg.DataDir, "tmp"), 0o700); err == nil {
			tmp, err = os.MkdirTemp(filepath.Join(r.cfg.DataDir, "tmp"), "archive-")
		}
		if err != nil {
			return nil, err
		}
	}
	defer os.RemoveAll(tmp) // the snapshot's scratch copy, the live copies, the Discord export: gone after
	p := &archivePlan{}
	lay := &snapshotLayout{sums: map[string]fileSum{}}
	title := sessionTitle(*s)
	var cert *Doc
	var machine string
	var at time.Time
	var tail *Tail
	machine, cert, at = r.latestSnapshot(s.ID)
	if machine != "" {
		sn := r.snap(machine)
		if sn == nil {
			return nil, fmt.Errorf("the snapshot of %s is gone", machine)
		}
		facts, err := r.snapFacts(sn)
		if err != nil {
			return nil, fmt.Errorf("reading the snapshot: %w", err)
		}
		tail = facts.Tail
		if s.AppTitle == "" && s.Label == "" && s.UserTitle == "" && tail != nil && tail.Title != "" {
			title = tail.Title // the title the app showed, from the transcript
		}
		if p.snap, err = r.snapToFile(sn, tmp); err != nil {
			return nil, fmt.Errorf("fetching the snapshot: %w", err)
		}
		if lay, err = layoutSnapshot(p.snap); err != nil {
			return nil, err
		}
		p.dests, p.transcripts = lay.dests, lay.isTranscript
	}
	taken := map[string]bool{}
	for _, t := range lay.transcripts {
		taken[t] = true
	}
	live, liveFiles, err := r.gatherLive(box, s.ID, tmp, lay.sums, taken)
	if err != nil {
		return nil, err
	}
	if machine == "" && len(live) == 0 {
		log.Printf("session %s: no snapshot and no live copy to archive", s.ID)
		return nil, nil
	}
	file, err := r.pickArchiveFile(box, s, title)
	if err != nil {
		return nil, err
	}
	p.file, p.live = file, liveFiles
	transcripts := []string{}
	for _, f := range liveFiles {
		transcripts = append(transcripts, f.name)
	}
	transcripts = append(transcripts, lay.transcripts...) // older conversations first; the snapshot's newest stays last
	info := &ArchiveInfo{File: file, Title: title, Transcripts: transcripts, Artifacts: lay.artifacts, Live: live, NoSnapshot: s.NoSnapshot}
	now := time.Now().UTC()
	meta := map[string]any{
		"id": s.ID, "jarvis": 4, "title": title, "label": s.Label, "aiTitle": s.Title, "created": s.Created,
		"destroyedAt": now, "archive": file, "environment": strings.Join(s.Stores, ","), "stores": s.Stores,
		"repos": s.Repos, "model": s.Model, "permissionMode": s.PermissionMode, "size": s.Size, "harness": s.Harness,
		"image": s.Image, "live": live,
	}
	man := map[string]any{"id": s.ID, "archive": file, "transcripts": transcripts, "artifacts": lay.artifactNames}
	if machine != "" {
		info.Signer, info.SnapshotAt, info.Unverified = machine, at.UTC(), s.SnapshotNote
		if tail != nil {
			info.Last = snippet(*tail)
		}
		meta["line"], meta["snapshotMachine"], meta["snapshotAt"], meta["unresolvedArtifactLinks"] = certField(cert, "line"), machine, info.SnapshotAt, lay.unresolved
		if s.NoSnapshot != "" {
			meta["noSnapshot"] = s.NoSnapshot + "; this is the newest signed snapshot the router had"
		}
		if s.SnapshotNote != "" {
			meta["snapshotUnverified"] = s.SnapshotNote
		}
		man["snapshot"], man["signer"] = "jarvis2/snapshot.tar.gz", machine
		sig, err := os.ReadFile(p.snap + ".sig")
		if err != nil {
			return nil, err
		}
		certJSON, _ := json.Marshal(cert)
		p.sigs = append(p.sigs, memFile{"jarvis2/cert.json", certJSON})
		if b := r.coreCert(); b != nil {
			p.sigs = append(p.sigs, memFile{"jarvis2/core-cert.json", b})
		}
		p.sigs = append(p.sigs, memFile{"jarvis2/snapshot.sig", []byte(strings.TrimSpace(string(sig)))})
	} else {
		why := "the session left no signed snapshot"
		if s.NoSnapshot != "" {
			why += " (" + s.NoSnapshot + ")"
		}
		why += ": this record holds only its live transcript copies, so it can't be restored"
		info.NoSnapshot = why
		meta["line"], meta["snapshot"], meta["noSnapshot"] = certField(s.Cert, "line"), nil, why
		man["snapshot"] = nil
	}
	mj, _ := json.MarshalIndent(meta, "", " ")
	manj, _ := json.Marshal(man)
	p.head = []memFile{{"session.json", mj}, {"restore-" + s.ID + ".json", manj}}
	r.lcNote(s.ID, "", "uploading the archive to "+file)
	p.tail = r.lifecycleFiles(s.ID) // up to here
	var discordDone func(error)
	p.discord, discordDone = r.discordExport(*s, tmp) // discord.go: "" when there is no channel or the export failed
	p.rawBytes = lay.bytes
	for _, f := range append(append(append([]memFile{}, p.head...), p.tail...), p.sigs...) {
		p.rawBytes += int64(len(f.body))
	}
	for _, f := range liveFiles {
		if fi, err := os.Stat(f.local); err == nil {
			p.rawBytes += fi.Size()
		}
	}
	if p.snap != "" {
		if fi, err := os.Stat(p.snap); err == nil {
			p.rawBytes += fi.Size()
		}
	}
	size, took, err := r.uploadArchive(box, s.ID, p)
	discordDone(err) // the channel goes only once its archive is on the Storage Box
	if err != nil {
		return nil, err
	}
	info.Bytes, info.UploadSeconds = size, took.Seconds()
	entry := map[string]any{"id": s.ID, "jarvis": 4, "title": title, "label": s.Label, "archive": file, "bytes": size, "created": s.Created,
		"destroyedAt": now, "transcripts": len(transcripts), "artifacts": lay.artifacts, "last": info.Last,
		"environment": strings.Join(s.Stores, ","), "repos": s.Repos, "model": s.Model, "size": s.Size, "harness": s.Harness,
		"permissionMode": s.PermissionMode, "restored": []any{}}
	if info.Signer == "" {
		entry["noSnapshot"] = info.NoSnapshot
	}
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
	log.Printf("session %s: archived to %s (%d transcript(s), %d artifact file(s), %s in %.1f s)", s.ID, file, len(transcripts), lay.artifacts, mb(size), took.Seconds())
	return info, nil
}

// ---- reading ---------------------------------------------------------------------------------------------------

// errNoArchive: the record's archive isn't on the Storage Box
var errNoArchive = errors.New("the archive is not on the Storage Box")

// walkArchive: an archive's entries, streamed from the Storage Box (fn returns errStopWalk to stop early)
func walkArchive(box *StorageBox, file string, fn func(h *tar.Header, body io.Reader) error) error {
	rc, _, err := box.Open(file)
	if err != nil {
		return err
	}
	if rc == nil {
		return fmt.Errorf("%w: %s", errNoArchive, file)
	}
	defer rc.Close()
	gz, err := gzip.NewReader(rc)
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
			if err == errStopWalk {
				return nil
			}
			return err
		}
	}
}

// archiveTail: the last n bytes of one file in an archive (nil when the archive doesn't hold it)
func archiveTail(box *StorageBox, file, name string, n int) ([]byte, error) {
	var out []byte
	err := walkArchive(box, file, func(h *tar.Header, body io.Reader) error {
		if h.Name != name {
			return nil
		}
		t := &tailBuf{n: n}
		if _, err := io.Copy(t, body); err != nil {
			return err
		}
		out = t.bytes()
		if out == nil {
			out = []byte{}
		}
		return errStopWalk
	})
	return out, err
}

// extractArchive: the named entries of an archive into dir (each under its base name); the names it found
func extractArchive(box *StorageBox, file, dir string, names ...string) (map[string]bool, error) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	found := map[string]bool{}
	err := walkArchive(box, file, func(h *tar.Header, body io.Reader) error {
		if h.Typeflag != tar.TypeReg || !want[h.Name] {
			return nil
		}
		f, err := os.OpenFile(filepath.Join(dir, path.Base(h.Name)), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, body)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		found[h.Name] = true
		if len(found) == len(want) {
			return errStopWalk
		}
		return nil
	})
	return found, err
}
