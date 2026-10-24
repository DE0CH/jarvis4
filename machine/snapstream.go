package main

// The final snapshot without free disk (router/snapstream.go): the tar.gz is made straight into the request body
// (POST /m/snapshot-stream, signed over the marker "stream" because the hash isn't known before the bytes), the router
// answers the hash it stored, the machine checks it against its own, signs it and commits (POST /m/snapshot-commit).
// The R1 rule stands: the machine signs exactly one snapshot in its life, after stopping the session; a later
// snapshot command commits that same one again (or, if the first commit never reached the router, streams the
// frozen files again and commits only when they hash the same). A router without streaming (404) gets the old
// whole-file upload.
//
// A failure is reported (POST /m/snapshot-failed), so the pause stops waiting and keeps the machine; when nothing
// was signed yet, the session is let go on (SIGCONT) so it can be fixed (space freed) and the pause tried again.
//
// A machine asked while still booting has no state of its own: its state is the predecessor's snapshot, the one its
// cert names. It signs that hash (its one signature) and the router links the predecessor's file as its snapshot
// (POST /m/snapshot-carry), then the machine never finishes booting (holdIfCarried). The first machine of a line,
// with no predecessor snapshot, still answers "nothing to snapshot".

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	signedMu   sync.Mutex
	signedSum  string // the one snapshot this machine signed (also in finalSnapshotSig files, best effort)
	signedSig  string
	committed  bool // the router took it
	carriedRun = dir + "/carried"
	certFile   = certPath // a var: tests move it
)

func uploadSnapshot(c *client) error {
	signedMu.Lock()
	defer signedMu.Unlock()
	if signedSum == "" {
		if sum, sig, err := finalSnapshotSum(); err == nil { // an earlier supervisor-core of this machine signed one
			signedSum, signedSig = sum, sig
		}
	}
	if signedSum != "" && committed {
		return commitSnapshot(c, signedSum, signedSig)
	}
	if signedSum == "" {
		frozen.Store(true)
		freezeSession()
		writeChanges() // restore.go: the repos' state, for the router's uncommitted-work check
		mirrorVolumeFiles()
	}
	prog := startProgress(c) // snapprogress.go: measured, then counted as it streams
	prog.setPhase("uploading")
	sum, n, err := streamSnapshot(c)
	prog.end(err)
	if errors.Is(err, errNoStreaming) {
		return uploadSnapshotFile(c)
	}
	if err != nil {
		if signedSum == "" { // nothing signed: the session may go on and the pause be tried again
			frozen.Store(false)
			thawSession()
		}
		return err
	}
	if signedSum == "" {
		key, err := snapshotKey()
		if err != nil {
			return err
		}
		sig, err := sign(key, []byte(sum))
		if err != nil {
			return err
		}
		signedSum, signedSig = sum, sig
		// best effort: a full disk can't stop the snapshot (the signature lives in memory)
		os.WriteFile(finalSnapshotSig+".sha256", []byte(sum), 0o600)
		os.WriteFile(finalSnapshotSig, []byte(sig), 0o600)
	} else if sum != signedSum {
		return fmt.Errorf("the files changed since the snapshot this machine signed (%s…): it signs no second one", signedSum[:12])
	}
	if err := commitSnapshot(c, signedSum, signedSig); err != nil {
		return err
	}
	committed = true
	log.Printf("snapshot streamed and committed (%d bytes)", n)
	return nil
}

var errNoStreaming = errors.New("the router has no snapshot streaming")

// streamSnapshot: the snapshot made into the request body → the hash both sides agree on
func streamSnapshot(c *client) (string, int64, error) {
	h, err := c.signed("POST", "/m/snapshot-stream", "stream")
	if err != nil {
		return "", 0, err
	}
	pr, pw := io.Pipe()
	type made struct {
		sum string
		n   int64
		err error
	}
	done := make(chan made, 1)
	go func() {
		sum, n, err := writeSnapshot(pw)
		pw.CloseWithError(err)
		done <- made{sum, n, err}
	}()
	req, _ := http.NewRequest("POST", c.base+"/m/snapshot-stream", pr)
	for k, v := range h {
		req.Header.Set(k, v)
	}
	hc := streamHTTP
	if c.http != nil && c.http.Transport != nil {
		hc = &http.Client{Transport: c.http.Transport}
	}
	resp, err := hc.Do(req)
	pr.CloseWithError(errors.New("request over"))
	m := <-done
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == 404 || resp.StatusCode == 405 {
		return "", 0, errNoStreaming
	}
	if m.err != nil {
		return "", 0, fmt.Errorf("making the snapshot: %w", m.err)
	}
	if resp.StatusCode != 200 {
		return "", 0, fmt.Errorf("snapshot stream: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var got struct {
		Sha256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	}
	if json.Unmarshal(b, &got) != nil || got.Sha256 != m.sum || got.Bytes != m.n {
		return "", 0, fmt.Errorf("the router stored other bytes (%s, %d) than were sent (%s, %d)", got.Sha256, got.Bytes, m.sum, m.n)
	}
	return m.sum, m.n, nil
}

func commitSnapshot(c *client, sum, sig string) error {
	return c.json("POST", "/m/snapshot-commit", map[string]string{"sha256": sum, "sig": sig}, nil)
}

// reportSnapshotFailed: tell the router at once (it stops waiting and keeps the machine)
func reportSnapshotFailed(c *client, err error) {
	if rerr := c.json("POST", "/m/snapshot-failed", map[string]string{"error": err.Error()}, nil); rerr != nil {
		log.Printf("reporting the failed snapshot: %v", rerr)
	}
}

// bootingSnapshot: a snapshot command while booting — the predecessor's snapshot, carried over as this machine's,
// when its cert names one; else (the line's first machine) "nothing to snapshot"
func bootingSnapshot(c *client) error {
	var cert Cert
	raw, err := os.ReadFile(certFile)
	var doc SignedDoc
	if err == nil && json.Unmarshal(raw, &doc) == nil {
		json.Unmarshal([]byte(doc.Payload), &cert) // the boot verified it before writing it here
	}
	if cert.Snapshot == "" || cert.PredID == "" || cert.PredID == c.me {
		return noSnapshot(c)
	}
	signedMu.Lock()
	defer signedMu.Unlock()
	if signedSum != "" && signedSum != cert.Snapshot {
		return fmt.Errorf("this machine signed another snapshot already")
	}
	if signedSum == "" {
		key, err := snapshotKey()
		if err != nil {
			return err
		}
		sig, err := sign(key, []byte(cert.Snapshot))
		if err != nil {
			return err
		}
		signedSum, signedSig = cert.Snapshot, sig
		os.WriteFile(carriedRun, []byte(cert.Snapshot), 0o600) // the boot stops before the harness
	}
	b, _, status, err := c.raw("POST", "/m/snapshot-carry", mustJSON(map[string]string{"sha256": signedSum, "sig": signedSig}))
	if err != nil {
		return err
	}
	if status == 404 || status == 405 { // an older router: what it knew before
		return noSnapshot(c)
	}
	if status != 200 {
		return fmt.Errorf("snapshot carry: HTTP %d %s", status, bytes.TrimSpace(b))
	}
	committed = true
	log.Printf("snapshot asked while booting: the predecessor's snapshot carried over as this machine's")
	return nil
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// holdIfCarried: the boot goes no further once a pause took the predecessor's snapshot as this machine's
func holdIfCarried() {
	if _, err := os.Stat(carriedRun); err != nil {
		return
	}
	log.Printf("paused while booting: this machine's snapshot is its predecessor's; not starting the harness")
	for {
		time.Sleep(time.Hour)
	}
}
