package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const liveS1 = "claude-records/.live/s1"

// putLive: a .live copy of s1 on the box, as the machine's live sync leaves it
func putLive(t *testing.T, rg *rig, name, body string) {
	t.Helper()
	box := rg.r.box()
	if err := box.Mkcols(liveS1); err != nil {
		t.Fatal(err)
	}
	if err := box.PutBytes(liveS1+"/"+name, []byte(body)); err != nil {
		t.Fatal(err)
	}
}

// the rig's snapshot transcript bbbb, byte for byte
func snapshotBody(rg *rig, name string) string {
	for _, f := range rg.files {
		if strings.HasSuffix(f.name, "/"+name) {
			return f.body
		}
	}
	return ""
}

func shaOf(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func s1Destroyed(rg *rig) bool {
	gone := false
	rg.r.st.Do(func(d *persisted) { gone = d.Sessions["s1"] == nil })
	return gone
}

// the incident (2026-10-15, sb8e0273d6c308894): the session went on under a new conversation after a failed snapshot,
// so its original conversation was only in .live; the archive took the latest snapshot's transcripts and the destroy
// deleted .live. Now every live copy the snapshot doesn't hold byte-identical is copied in (and checked) first, and
// the destroy sends no resume DM: the missing snapshot is noted in the record.
func TestDestroyArchivesEveryLiveTranscriptFirst(t *testing.T) {
	rg, _ := volRig(t)
	dms := captureDM(t)
	rg.r.cfg.SnapshotStall = 200 * time.Millisecond
	runningM2(rg, true) // its final snapshot never comes; Destroy anyway goes on (its volume is backed up)
	orig := strings.Repeat(`{"type":"user","message":{"content":"the original conversation"}}`+"\n", 2000)
	putLive(t, rg, "cccc.jsonl", orig)                           // only here: the original conversation
	putLive(t, rg, "bbbb.jsonl", snapshotBody(rg, "bbbb.jsonl")) // the snapshot holds it byte-identical
	putLive(t, rg, "aaaa.jsonl", "an older version\n")           // the snapshot holds another version of it
	if err := rg.r.DestroyWith("s1", true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the record", func() bool { return s1Destroyed(rg) })
	rec := rg.r.record("s1")
	if rec == nil || rec.Archive == nil || rec.ArchiveError != "" || rec.LiveKept != "" {
		t.Fatalf("record %+v", rec)
	}
	files, _ := rg.dav.archive(t, rec.Archive.File)
	if got := string(files["transcript-cccc.jsonl"]); got != orig {
		t.Fatalf("the original conversation isn't in the archive (%d bytes)", len(got))
	}
	if got := string(files["transcript-aaaa.live.jsonl"]); got != "an older version\n" {
		t.Fatalf("the other version of aaaa: %q", got)
	}
	if got := string(files["transcript-aaaa.jsonl"]); got != snapshotBody(rg, "aaaa.jsonl") {
		t.Fatalf("the snapshot's aaaa was replaced: %q", got)
	}
	want := map[string]string{"aaaa.jsonl": "transcript-aaaa.live.jsonl", "bbbb.jsonl": "snapshot", "cccc.jsonl": "transcript-cccc.jsonl"}
	if len(rec.Archive.Live) != 3 {
		t.Fatalf("live %+v", rec.Archive.Live)
	}
	for _, c := range rec.Archive.Live {
		if want[c.Name] != c.In {
			t.Fatalf("live %+v", rec.Archive.Live)
		}
	}
	if c := rec.Archive.Live[2]; c.Size != int64(len(orig)) || c.Sha256 != shaOf(orig) {
		t.Fatalf("cccc accounted as %+v", c)
	}
	tr := strings.Join(rec.Archive.Transcripts, ",")
	if tr != "transcript-aaaa.live.jsonl,transcript-cccc.jsonl,transcript-aaaa.jsonl,transcript-bbbb.jsonl" {
		t.Fatalf("transcripts %s (the snapshot's newest must stay last)", tr)
	}
	if len(rg.dav.under(liveS1)) != 0 {
		t.Fatalf("the live copies stayed after a full archive: %v", rg.dav.under(liveS1))
	}
	// no resume-refusal DM from a destroy; the record says the last machine left no snapshot
	for _, dm := range dms() {
		if strings.Contains(dm, "won't resume") || strings.Contains(dm, "left no snapshot") {
			t.Fatalf("a destroy DMed: %q", dm)
		}
	}
	if !strings.Contains(rec.Archive.NoSnapshot, "machine m2 left no snapshot") {
		t.Fatalf("noSnapshot %q", rec.Archive.NoSnapshot)
	}
	var meta map[string]any
	json.Unmarshal(files["session.json"], &meta)
	if !strings.Contains(meta["noSnapshot"].(string), "machine m2 left no snapshot") || meta["live"] == nil {
		t.Fatalf("session.json %v", meta)
	}
}

// a copy that fails keeps the session (an archive failure) and every live copy; Destroy anyway goes on but still
// deletes none of them, and the record says so
func TestALiveCopyFailureKeepsEveryLiveFile(t *testing.T) {
	rg := newRig(t)
	putLive(t, rg, "cccc.jsonl", "the original\n")
	putLive(t, rg, "bbbb.jsonl", snapshotBody(rg, "bbbb.jsonl"))
	rg.dav.fail = archivesRoot + "/2026"
	rg.r.Destroy("s1")
	waitFor(t, "the error", func() bool {
		s := sessionS1(rg)
		return s.State == "paused" && strings.HasPrefix(s.Error, "archive:")
	})
	// the destroy sets that state a moment before it releases the session: its end is waitState's (not the state's)
	if err := rg.r.waitState("s1", "paused", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if n := len(rg.dav.under(liveS1)); n != 2 {
		t.Fatalf("live copies after a failed archive: %v", rg.dav.under(liveS1))
	}
	if err := rg.r.DestroyWith("s1", true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the record", func() bool { return s1Destroyed(rg) })
	rec := rg.r.record("s1")
	if rec.ArchiveError == "" || !strings.Contains(rec.LiveKept, "kept 2 live transcript(s)") || !strings.Contains(rec.LiveKept, "the archive failed") {
		t.Fatalf("record: archiveError %q, liveKept %q", rec.ArchiveError, rec.LiveKept)
	}
	if string(rg.dav.get(liveS1+"/cccc.jsonl")) != "the original\n" || len(rg.dav.under(liveS1)) != 2 {
		t.Fatalf("a forced destroy deleted live copies: %v", rg.dav.under(liveS1))
	}
}

// a session with no snapshot at all but live copies gets a record of them (nothing to restore), and they go only then
func TestNoSnapshotStillArchivesTheLiveCopies(t *testing.T) {
	rg := newRig(t)
	rg.r.snapDrop("m1")
	putLive(t, rg, "dddd.jsonl", "only here\n")
	if err := rg.r.Destroy("s1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the record", func() bool { return s1Destroyed(rg) })
	rec := rg.r.record("s1")
	if rec.Archive == nil || rec.Archive.Signer != "" || len(rec.Archive.Live) != 1 || !strings.Contains(rec.Archive.NoSnapshot, "no signed snapshot") {
		t.Fatalf("record %+v", rec.Archive)
	}
	files, order := rg.dav.archive(t, rec.Archive.File)
	if string(files["transcript-dddd.jsonl"]) != "only here\n" || len(rg.dav.under(liveS1)) != 0 {
		t.Fatalf("archive %v, live %v", order, rg.dav.under(liveS1))
	}
	if !strings.HasPrefix(strings.Join(order, ","), "session.json,restore-s1.json,transcript-dddd.jsonl,jarvis2/") || files["jarvis2/snapshot.tar.gz"] != nil {
		t.Fatalf("members %v", order)
	}
	var meta map[string]any
	json.Unmarshal(files["session.json"], &meta)
	if meta["snapshot"] != nil || !strings.Contains(meta["noSnapshot"].(string), "only its live transcript copies") {
		t.Fatalf("session.json %v", meta)
	}
	var idx []map[string]any
	json.Unmarshal(rg.dav.get(recordsIndex), &idx)
	if len(idx) != 1 || idx[0]["id"] != "s1" {
		t.Fatalf("index %v", idx)
	}
}

// only what the archive accounted for goes: a copy that arrived or grew since stays, and so does the dir
func TestClearDeletesOnlyArchivedLiveFiles(t *testing.T) {
	rg := newRig(t)
	putLive(t, rg, "a.jsonl", "aa\n")
	putLive(t, rg, "b.jsonl", "bb grown\n")
	putLive(t, rg, "c.jsonl", "late\n")
	info := &ArchiveInfo{Live: []LiveCopy{{Name: "a.jsonl", Size: 3, In: "transcript-a.jsonl"}, {Name: "b.jsonl", Size: 3, In: "transcript-b.jsonl"}}}
	kept := rg.r.clearArchivedLive("s1", info, nil)
	if got := strings.Join(rg.dav.under(liveS1), ","); got != "b.jsonl,c.jsonl" {
		t.Fatalf("left %s", got)
	}
	if !strings.Contains(kept, "kept 2") || !strings.Contains(kept, "b.jsonl, c.jsonl") {
		t.Fatalf("kept %q", kept)
	}
	if kept := rg.r.clearArchivedLive("s1", nil, nil); !strings.Contains(kept, "there is no archive") || len(rg.dav.under(liveS1)) != 2 {
		t.Fatalf("no archive: %q %v", kept, rg.dav.under(liveS1))
	}
}
