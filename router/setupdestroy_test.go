package main

import (
	"testing"
)

// POST /setup/sessions/{id}/destroy: setup-signed, the app's destroy (archive, then the record); a failed archive
// leaves the session paused unless force
func TestSetupDestroy(t *testing.T) {
	rg := newRig(t)
	setup := newTestKey()
	rg.r.cfg.SetupKey, rg.r.cfg.NoAccess = setup.pub(), true
	h := rg.r.Handler()
	if code, _ := rdo(t, h, "POST", "/setup/sessions/s1/destroy", map[string]any{}, nil); code != 401 {
		t.Fatalf("unsigned: %d", code)
	}
	if code, out := rdo(t, h, "POST", "/setup/sessions/nope/destroy", map[string]any{}, &setup); code != 400 {
		t.Fatalf("no such session: %d %v", code, out)
	}
	// the archive fails (the Storage Box refuses): paused with the error, no record
	rg.dav.fail = archivesRoot + "/2026"
	if code, out := rdo(t, h, "POST", "/setup/sessions/s1/destroy", map[string]any{}, &setup); code != 202 || out["ok"] != true {
		t.Fatalf("%d %v", code, out)
	}
	waitFor(t, "paused with the archive error", func() bool {
		var st, e string
		rg.r.st.Do(func(d *persisted) { st, e = d.Sessions["s1"].State, d.Sessions["s1"].Error })
		return st == "paused" && e != ""
	})
	if rg.r.record("s1") != nil {
		t.Fatal("a record without force")
	}
	// force in the signed body: destroyed anyway
	waitFor(t, "the forced destroy", func() bool {
		code, _ := rdo(t, h, "POST", "/setup/sessions/s1/destroy", map[string]any{"force": true}, &setup)
		return code == 202
	})
	waitFor(t, "the record", func() bool { return rg.r.record("s1") != nil })
	if rec := rg.r.record("s1"); rec.Archive != nil || rec.ArchiveError == "" {
		t.Fatalf("forced record %+v", rec)
	}
}

// with the Storage Box answering, the setup destroy archives the session and leaves its record
func TestSetupDestroyArchives(t *testing.T) {
	rg := newRig(t)
	setup := newTestKey()
	rg.r.cfg.SetupKey, rg.r.cfg.NoAccess = setup.pub(), true
	if code, out := rdo(t, rg.r.Handler(), "POST", "/setup/sessions/s1/destroy", nil, &setup); code != 202 {
		t.Fatalf("%d %v", code, out)
	}
	waitFor(t, "the archived record", func() bool { rec := rg.r.record("s1"); return rec != nil && rec.Archive != nil })
	rg.dav.archive(t, rg.r.record("s1").Archive.File) // one .tar.gz that opens
}
