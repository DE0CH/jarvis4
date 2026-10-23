package main

// The live copies go into the archive before any of them goes (2026-10-15: destroying session sb8e0273d6c308894
// deleted claude-records/.live/sb8e0273d6c308894/, which held its ORIGINAL conversation — its machine's snapshot had
// failed, the session went on under a new conversation, and the archive took only the latest snapshot's
// transcripts, so the original had no other copy).
//
//   - An archive holds EVERY transcript in the session's .live dir that the snapshot doesn't already hold
//     byte-identical (same size and sha256): transcript-<uuid>.jsonl, or transcript-<uuid>.live.jsonl when the
//     snapshot holds a different version of that conversation. They count once the whole archive is on the Storage
//     Box (its size checked, archivetar.go). The record lists them all (ArchiveInfo.Live).
//   - A session with no snapshot but live copies still gets an archive: the live transcripts and session.json, which
//     notes that there is no snapshot (nothing to restore).
//   - clearArchivedLive deletes only the .live files the archive accounted for, each still the size it had then; the
//     dir goes only once it is empty. Anything else (no archive, a failed one, a file that came or changed since)
//     stays, and the record says so (Record.LiveKept). There is no other path that deletes .live copies.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// LiveCopy: one .live transcript as the archive accounted for it
type LiveCopy struct {
	Name   string `json:"name"` // its name in claude-records/.live/<session id>/
	Size   int64  `json:"size"`
	Sha256 string `json:"sha256"`
	// In: where the record holds it — "snapshot" (the signed snapshot has it byte-identical, and so its transcript-…
	// file), else the file in the archive dir it was copied to
	In string `json:"in"`
}

type fileSum struct {
	size int64
	sha  string
}

// sumFile: a local file's size and sha256
func sumFile(p string) (fileSum, error) {
	f, err := os.Open(p)
	if err != nil {
		return fileSum{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return fileSum{}, err
	}
	return fileSum{n, hex.EncodeToString(h.Sum(nil))}, nil
}

// sumReader: a stream's size and sha256
func sumReader(rd io.Reader) (fileSum, error) {
	h := sha256.New()
	n, err := io.Copy(h, rd)
	if err != nil {
		return fileSum{}, err
	}
	return fileSum{n, hex.EncodeToString(h.Sum(nil))}, nil
}

// gatherLive: every .live transcript of the session downloaded into tmp, unless held (snapshot transcript name →
// sum) has it byte-identical; taken: the transcript names the archive already uses. Returns the accounting (sorted by
// name) and the files to put in the archive. Any error: nothing may be deleted from .live.
func (r *Router) gatherLive(box *StorageBox, sid, tmp string, held map[string]fileSum, taken map[string]bool) ([]LiveCopy, []diskFile, error) {
	listed, err := box.List(liveDir(sid))
	if err != nil {
		return nil, nil, fmt.Errorf("listing the live copies: %w", err)
	}
	names := make([]string, 0, len(listed))
	for n := range listed {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []LiveCopy
	var files []diskFile
	for _, name := range names {
		if !liveNameRE.MatchString(name) {
			log.Printf("[livesync] %s: %q in the live dir isn't a transcript: left there", sid, name)
			continue
		}
		local := filepath.Join(tmp, "live-"+name)
		found, err := box.Download(liveDir(sid)+"/"+name, local)
		if err != nil {
			return nil, nil, fmt.Errorf("reading the live transcript %s: %w", name, err)
		}
		if !found {
			continue // gone since the listing
		}
		sum, err := sumFile(local)
		if err != nil {
			return nil, nil, err
		}
		if sum.size != listed[name] {
			return nil, nil, fmt.Errorf("the live transcript %s changed while being read (%d bytes listed, %d read)", name, listed[name], sum.size)
		}
		c := LiveCopy{Name: name, Size: sum.size, Sha256: sum.sha}
		if h, ok := held[name]; ok && h == sum {
			c.In = "snapshot"
			out = append(out, c)
			continue
		}
		stem := strings.TrimSuffix(name, ".jsonl")
		dest := "transcript-" + name
		if _, inSnapshot := held[name]; inSnapshot || taken[dest] {
			dest = "transcript-" + stem + ".live.jsonl" // the snapshot's version of this conversation differs
			for i := 2; taken[dest]; i++ {
				dest = "transcript-" + stem + ".live-" + strconv.Itoa(i) + ".jsonl"
			}
		}
		taken[dest] = true
		c.In = dest
		out = append(out, c)
		files = append(files, diskFile{name: dest, local: local})
	}
	return out, files, nil
}

// clearArchivedLive: the .live files the archive accounted for go (each only while it is still the size it had);
// "" when the dir is gone, else what was kept and why (for the record and the log)
func (r *Router) clearArchivedLive(sid string, archived *ArchiveInfo, aerr error) string {
	liveDirs.Delete(sid)
	box := r.box()
	if box == nil || recordsOff() {
		return ""
	}
	listed, err := box.List(liveDir(sid))
	if err != nil {
		msg := fmt.Sprintf("the live copies in %s/ were kept (listing them failed: %v)", liveDir(sid), err)
		log.Printf("[livesync] %s: %s", sid, msg)
		return msg
	}
	if len(listed) == 0 {
		if listed != nil { // an empty dir
			box.Delete(liveDir(sid) + "/")
		}
		return ""
	}
	done := map[string]LiveCopy{}
	if archived != nil && aerr == nil {
		for _, c := range archived.Live {
			done[c.Name] = c
		}
	}
	var kept []string
	for name, size := range listed {
		c, ok := done[name]
		if !ok || c.Size != size {
			kept = append(kept, name)
			continue
		}
		if err := box.Delete(liveDir(sid) + "/" + name); err != nil {
			log.Printf("[livesync] %s: removing the archived live copy %s: %v", sid, name, err)
			kept = append(kept, name)
		}
	}
	if len(kept) == 0 {
		if err := box.Delete(liveDir(sid) + "/"); err != nil {
			log.Printf("[livesync] %s: removing the empty live dir: %v", sid, err)
		}
		return ""
	}
	sort.Strings(kept)
	why := "not in the archive"
	switch {
	case aerr != nil:
		why = "the archive failed: " + aerr.Error()
	case archived == nil:
		why = "there is no archive"
	}
	msg := fmt.Sprintf("kept %d live transcript(s) in %s/ (%s): %s", len(kept), liveDir(sid), why, strings.Join(kept, ", "))
	log.Printf("[livesync] %s: %s", sid, msg)
	return msg
}
