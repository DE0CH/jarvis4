package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// putSnap: a committed snapshot of machine (snapstore.go), as a machine's stream and commit leave it
func putSnap(t testing.TB, r *Router, machine string, body []byte, sig string) {
	t.Helper()
	if err := r.snapPutWhole(machine, bytes.NewReader(body), sig); err != nil {
		t.Fatal(err)
	}
}

// snapBytes: the machine's snapshot's bytes (nil: none)
func snapBytes(r *Router, machine string) []byte {
	s := r.snap(machine)
	if s == nil {
		return nil
	}
	rd, err := r.snapOpen(context.Background(), s)
	if err != nil {
		return nil
	}
	defer rd.Close()
	b, _ := io.ReadAll(rd)
	return b
}

// unsignSnap: the machine hasn't signed (sent) its final snapshot yet
func unsignSnap(r *Router, machine string) {
	r.pool().pool.Exec(context.Background(), "UPDATE snapshots SET state = 'pending', sig = '', committed_at = NULL WHERE machine_id = $1", machine)
}

// the volume's committed snapshots (and carries) go into the bucket and the table once; a stream's facts are read on
// the way in, and a carried-over snapshot shares its predecessor's object until both are dropped
func TestSnapshotsInTheBucket(t *testing.T) {
	r := newTestRouter(t)
	tarball := makeTar(t, []tfile{{name: "workspace/a.txt", body: "a"}})
	os.MkdirAll(filepath.Join(r.cfg.DataDir, "snapshots"), 0o700)
	os.WriteFile(filepath.Join(r.cfg.DataDir, "snapshots", "m1.tar.gz"), tarball, 0o600)
	os.WriteFile(filepath.Join(r.cfg.DataDir, "snapshots", "m1.tar.gz.sig"), []byte("sig1\n"), 0o600)
	os.WriteFile(filepath.Join(r.cfg.DataDir, "snapshots", "m0.tar.gz"), tarball, 0o600) // never signed: not taken
	os.WriteFile(filepath.Join(r.cfg.DataDir, "snapshots", "m1.carry"), []byte("blob"), 0o600)
	if err := r.importSnapshotFiles(); err != nil {
		t.Fatal(err)
	}
	s := r.snap("m1")
	if s == nil || s.State != "committed" || s.Sig != "sig1" || string(snapBytes(r, "m1")) != string(tarball) || r.snap("m0") != nil {
		t.Fatalf("imported %+v", s)
	}
	if s.Facts == nil || r.readCarry("m1") != "blob" {
		t.Fatalf("facts %+v carry %q", s.Facts, r.readCarry("m1"))
	}
	if err := r.snapCarry("m2", "m1", s.Sha256, "sig2"); err != nil {
		t.Fatal(err)
	}
	r.snapDrop("m1")
	if string(snapBytes(r, "m2")) != string(tarball) {
		t.Fatal("dropping the predecessor took the carried object with it")
	}
	r.snapDrop("m2")
	if keys, _ := r.objects.List(context.Background(), "snapshots/"); len(keys) != 0 {
		t.Fatalf("left: %v", keys)
	}
}
