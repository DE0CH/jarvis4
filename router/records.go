package main

// Indexing an archive by hand (Jarvis 1 POST /api/records): an archive that is ALREADY on the Storage Box —
// pre-indexed, hand-uploaded, or one of Jarvis 1's — goes on the Previous list, so its transcript tail can be
// read and it can be removed or deleted like any other. Nothing is scanned or guessed: the caller names the
// folder and its transcripts, and the router checks they exist.
//
// Such a record can't be restored in Jarvis 4: a restore needs the machine-signed snapshot and its core-signed
// cert (jarvis2/ in an archive made by a Jarvis 4 destroy), which a hand-uploaded folder doesn't have.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var (
	archiveDirRE = regexp.MustCompile(`^claude-records/[^/.][^/]*$`)
	recFileRE    = regexp.MustCompile(`^[^/\\]+$`)
	uuidRE       = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	errHandIndex = errors.New("this archive was indexed by hand: it has no machine-signed snapshot, so Jarvis 4 can't restore it (read its transcript, or restore it in Jarvis 1 if it is Jarvis 1's)")
)

// IndexInput: Jarvis 1's body (environment → stores; repos a list or a space-separated string)
type IndexInput struct {
	ArchiveDir     string    `json:"archiveDir"`
	Transcripts    []string  `json:"transcripts"`
	Artifacts      []string  `json:"artifacts"`
	Title          string    `json:"title"`
	Environment    string    `json:"environment"`
	Stores         []string  `json:"stores"`
	Repos          any       `json:"repos"`
	PermissionMode string    `json:"permissionMode"`
	Model          string    `json:"model"`
	Size           string    `json:"size"`
	Harness        string    `json:"harness"`
	Created        time.Time `json:"created"`
	DestroyedAt    time.Time `json:"destroyedAt"`
}

func (r *Router) indexRecord(w http.ResponseWriter, req *http.Request) {
	var in IndexInput
	if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
		return
	}
	rec, err := r.IndexArchive(in)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "record": rec})
}

// IndexArchive: checks the folder and its transcripts on the box, adds the record (newest first) and the
// Storage Box index entry
func (r *Router) IndexArchive(in IndexInput) (*Record, error) {
	dir := strings.TrimRight(strings.TrimSpace(in.ArchiveDir), "/")
	if !archiveDirRE.MatchString(dir) {
		return nil, errors.New(`archiveDir must be "claude-records/<folder>"`)
	}
	if len(in.Transcripts) == 0 {
		return nil, errors.New("nothing indexed (no transcript)")
	}
	for _, f := range in.Transcripts {
		if !recFileRE.MatchString(f) || f == "." || f == ".." {
			return nil, errors.New("a transcript must be a file name in archiveDir: " + f)
		}
	}
	for _, f := range in.Artifacts {
		if strings.HasPrefix(f, "/") || strings.Contains(f, "..") {
			return nil, errors.New("bad artifact path: " + f)
		}
	}
	box := r.box()
	if box == nil {
		return nil, errNoStorageBox
	}
	for _, f := range in.Transcripts {
		ok, err := box.Exists(dir + "/" + f)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("not on the Storage Box: " + dir + "/" + f)
		}
	}
	id := "archive-" + randID()[:8]
	if u := uuidRE.FindString(in.Transcripts[0]); u != "" {
		id = "archive-" + u[:8]
	}
	title := strings.TrimSpace(in.Title)
	if title == "" {
		title = strings.TrimPrefix(dir, recordsRoot+"/")
	}
	stores := in.Stores
	if len(stores) == 0 && in.Environment != "" {
		stores = strings.Split(in.Environment, ",")
	}
	repos := ""
	switch v := in.Repos.(type) {
	case string:
		repos = v
	case []any:
		var rs []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				rs = append(rs, s)
			}
		}
		repos = strings.Join(rs, ",")
	}
	mode := "auto"
	if in.PermissionMode == "bypass" {
		mode = "bypass"
	}
	harness := in.Harness
	if harness == "" {
		harness = "claude"
	}
	destroyed := in.DestroyedAt
	if destroyed.IsZero() {
		destroyed = time.Now().UTC()
	}
	rec := &Record{
		Session: Session{ID: id, State: "destroyed", Created: in.Created, Label: title, Model: in.Model, Size: in.Size,
			PermissionMode: mode, Harness: harness, Stores: stores, Repos: repos, ArchiveDir: dir},
		DestroyedAt: destroyed,
		Archive:     &ArchiveInfo{Dir: dir, Title: title, Transcripts: in.Transcripts, Artifacts: len(in.Artifacts)},
	}
	var existing *Record
	r.st.Do(func(d *persisted) {
		for _, x := range d.Records {
			if x.ID == id {
				c := *x
				existing = &c
			}
		}
		if existing == nil {
			d.Records = append([]*Record{rec}, d.Records...)
		}
	})
	if existing != nil { // already on the list: that record is the answer
		return existing, nil
	}
	entry := map[string]any{"id": id, "jarvis": 2, "indexedByHand": true, "title": title, "label": title, "archiveDir": dir,
		"created": in.Created, "destroyedAt": destroyed, "transcripts": len(in.Transcripts), "artifacts": len(in.Artifacts),
		"environment": strings.Join(stores, ","), "repos": repos, "model": in.Model, "size": in.Size, "harness": harness,
		"permissionMode": mode, "restored": []any{}}
	if err := updateIndex(box, func(list []map[string]any) []map[string]any { return append([]map[string]any{entry}, list...) }); err != nil {
		r.st.Do(func(d *persisted) {
			keep := d.Records[:0]
			for _, x := range d.Records {
				if x.ID != id {
					keep = append(keep, x)
				}
			}
			d.Records = keep
		})
		return nil, err
	}
	return rec, nil
}
