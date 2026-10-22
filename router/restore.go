package main

// Restoring a destroyed session (Jarvis 1 POST /api/records/:id/restore). The destroy burnt the old line, so
// a restore is a NEW line from null — the phone approves it like any new session — whose first machine
// restores the archived snapshot.
//
// What the machine trusts (machine/restore.go): the core's succession challenge has no room for "restore
// from" (core Options carry only the harness, and the core is off-limits), so the router passes the old
// line's signer cert in the machine's env (JARVIS2_RESTORE_CERT) and serves the archived snapshot at
// /m/restore-snapshot. The machine accepts it only on a line's FIRST machine (a cert with no predecessor),
// checks the old cert against the core key (a core-signed succession cert, another machine), the snapshot
// against that cert's machine signing key, and refuses a snapshot from a line that held a sensitive store
// into a line that holds none.
//
// The risk this leaves (docs/PARITY.md): the restore choice is not signed by the phone. A malicious router
// can make a new line, which Deyao approved as "restore X", restore some other old snapshot of Deyao's
// (signed by one of his own machines), or none. It can't forge a snapshot or bring one from outside Deyao's
// own lines; and the router holds every snapshot in plaintext anyway, so the mix-up moves no data to anyone
// who didn't already have it (confidentiality-neutral), apart from the sensitive-store rule above.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func init() {
	envHooks = append(envHooks, func(_ *Router, s *Session, env map[string]string) {
		if s.RestoreCert != nil && s.Cert == nil { // only the new line's first machine
			b, _ := json.Marshal(s.RestoreCert)
			env["JARVIS2_RESTORE_CERT"] = string(b)
		}
	})
}

// restoreSnap: the snapshot row (snapstore.go) holding a restoring session's archived snapshot, until its first boot
func restoreSnap(sid string) string { return "restore-" + sid }

// restoresDir: the scratch directory the archive's files are fetched into and checked in (then gone)
func (r *Router) restoresDir(sid string) string {
	return filepath.Join(r.cfg.DataDir, "tmp", "restore-"+sid)
}

// RestoreRecord: the record's archived snapshot onto the volume, then a new session with the record's
// options, waiting for the phone (approval kind new-session, options.restore names what it restores)
func (r *Router) RestoreRecord(recordID, requestID string) (string, error) {
	rec := r.record(recordID)
	if rec == nil {
		return "", errors.New("no such previous session")
	}
	if rec.Archive == nil {
		return "", errors.New("this session was destroyed without an archive: nothing to restore")
	}
	if rec.Archive.Signer == "" {
		return "", errHandIndex // records.go
	}
	// an archive marked unverified (its snapshot wasn't named in its kill: an earlier core's machine) is checked like
	// any other below (checkRestoreFiles: its cert by this core or an earlier core the master key claimed, the snapshot
	// by the cert's machine), and again by the restoring machine
	box := r.box()
	if box == nil {
		return "", errNoStorageBox
	}
	h, ok := r.policy.Harnesses[rec.Harness]
	if !ok { // a harness the policy no longer has: restored on claude, as CreateSession falls back
		log.Printf("restore %s: no harness %s in the policy; restoring on claude", recordID, rec.Harness)
		rec.Harness = "claude"
		if h, ok = r.policy.Harnesses[rec.Harness]; !ok {
			return "", errors.New("no harness claude in the policy")
		}
	}
	var kept []string // the record's stores, less the shared login's old store (its account comes as the account)
	for _, n := range rec.Stores {
		if n != legacyClaudeStore {
			kept = append(kept, n)
		}
	}
	stores, err := r.withHarnessStores(kept, h.Stores)
	if err != nil {
		return "", err
	}
	named := rec.ClaudeAccount // the account it ran on, while it exists; else the default
	if r.accounts().hub(named) == nil {
		named = ""
	}
	account, err := r.accounts().resolve(named, h.ClaudeAccount)
	if err != nil {
		return "", err
	}
	sid := "s" + randID()
	dir := r.restoresDir(sid)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	defer os.RemoveAll(dir) // the snapshot goes into the bucket (below); nothing of the restore stays on disk
	fail := func(err error) (string, error) {
		r.snapDrop(restoreSnap(sid))
		return "", err
	}
	for _, f := range []string{"snapshot.tar.gz", "snapshot.sig", "cert.json"} {
		found, err := box.Download(rec.Archive.Dir+"/jarvis2/"+f, filepath.Join(dir, f))
		if err != nil {
			return fail(err)
		}
		if !found {
			return fail(fmt.Errorf("the archive has no jarvis2/%s", f))
		}
	}
	// the master key's claim of the core that signed the cert (archive.go writes it): an archive from an earlier core
	// restores through it (core continuity); absent in archives from before the router kept claims
	box.Download(rec.Archive.Dir+"/jarvis2/core-cert.json", filepath.Join(dir, "core-cert.json"))
	cert, err := r.checkRestoreFiles(dir)
	if err != nil {
		return fail(err)
	}
	if err := r.putRestoreSnapshot(sid, dir); err != nil {
		return fail(err)
	}
	var coreCert *MasterCert
	if b, err := os.ReadFile(filepath.Join(dir, "core-cert.json")); err == nil {
		var mc MasterCert
		if json.Unmarshal(b, &mc) == nil && mc.Statement != "" {
			coreCert = &mc
		}
	}
	label := rec.Label
	if label == "" {
		label = rec.Archive.Title
	}
	s := &Session{ID: sid, State: "approval", Created: time.Now().UTC(), Label: label, Model: rec.Model, PermissionMode: "bypass", // the only start mode, whatever the destroyed session ran in
		Size: rec.Size, Harness: rec.Harness, Stores: stores, ClaudeAccount: account, Repos: rec.Repos, RequestID: requestID, RestoreFrom: recordID, RestoreCert: cert, RestoreCoreCert: coreCert}
	r.st.Do(func(d *persisted) { d.Sessions[sid] = s })
	config, err := r.sessionConfig(s) // vouch.go: names the snapshot this line restores (machine + sha256)
	if err != nil {
		r.st.Do(func(d *persisted) { delete(d.Sessions, sid) })
		return fail(err)
	}
	what := label
	if what == "" {
		what = recordID
	}
	if r.kernelServes() { // kernelline.go: the restore on the kernel; the phone signs the snapshot's hash into the source
		sum, err := "", error(nil)
		if s := r.snap(restoreSnap(sid)); s != nil {
			sum = s.Sha256
		} else {
			err = errors.New("the restore's snapshot is gone")
		}
		if err == nil {
			err = r.kernelNewSessionApproval(s, config, map[string]string{"model": s.Model, "size": s.Size, "permissionMode": s.PermissionMode,
				"repos": s.Repos, "restore": fmt.Sprintf("%s (destroyed %s)", what, rec.DestroyedAt.UTC().Format("2006-01-02"))}, NewSession{}, sum)
		}
		if err != nil {
			r.st.Do(func(d *persisted) { delete(d.Sessions, sid) })
			return fail(err)
		}
		return sid, nil
	}
	ch, err := r.succession(nil, "", s.Stores, s.Harness, s.PermissionMode, r.cfg.SessionImage, config, "")
	if err != nil {
		r.st.Do(func(d *persisted) { delete(d.Sessions, sid) })
		return fail(err)
	}
	r.addApproval(&Approval{Kind: "new-session", Session: sid, Label: s.Label, Challenge: ch,
		Options: map[string]string{"model": s.Model, "size": s.Size, "permissionMode": s.PermissionMode, "repos": s.Repos,
			"restore": fmt.Sprintf("%s (destroyed %s)", what, rec.DestroyedAt.UTC().Format("2006-01-02"))}})
	return sid, nil
}

// checkRestoreFiles: the router's own early check (the machine checks again, and only its check counts):
// the cert is the core's and the snapshot is signed by the cert's machine
func (r *Router) checkRestoreFiles(dir string) (*Doc, error) {
	b, err := os.ReadFile(filepath.Join(dir, "cert.json"))
	if err != nil {
		return nil, err
	}
	var cert Doc
	if json.Unmarshal(b, &cert) != nil || cert.Payload == "" {
		return nil, errors.New("the archive's cert.json isn't a signed document")
	}
	var c struct {
		Kind    string `json:"kind"`
		Machine *struct {
			ID         string `json:"id"`
			SigningKey string `json:"signingKey"`
		} `json:"machine"`
	}
	var kc struct {
		Kind    string `json:"kind"`
		Machine *struct {
			SigningKey string `json:"signingKey"`
		} `json:"machine"`
	}
	if cert.Decode(&kc) == nil && kc.Kind == "succession" && kc.Machine != nil { // a kernel line's: the spawner's cert
		c.Kind, c.Machine = "succession-cert", &struct {
			ID         string `json:"id"`
			SigningKey string `json:"signingKey"`
		}{SigningKey: kc.Machine.SigningKey}
	} else if cert.Decode(&c) != nil || c.Kind != "succession-cert" || c.Machine == nil {
		return nil, errors.New("the archive's cert.json isn't a succession cert")
	} else if key, err := r.core.Key(); err == nil && key["signingKey"] != "" && !verifyP256(key["signingKey"], []byte(cert.Payload), cert.Sig) &&
		!r.earlierCoreSigned(dir, &cert) {
		return nil, errors.New("the archive's cert isn't signed by this core, nor by an earlier core the master key claimed")
	}
	sig, err := os.ReadFile(filepath.Join(dir, "snapshot.sig"))
	if err != nil {
		return nil, err
	}
	sum, err := sha256hex(filepath.Join(dir, "snapshot.tar.gz"))
	if err != nil {
		return nil, err
	}
	if !verifyP256(c.Machine.SigningKey, []byte(sum), strings.TrimSpace(string(sig))) {
		return nil, errors.New("the archived snapshot isn't signed by the machine its cert names")
	}
	return &cert, nil
}

// restoreFilesFor: the restore snapshot a machine may fetch — only the first machine of a restoring session
func (r *Router) restoreFilesFor(machine string) *Snap {
	var sid string
	r.st.Do(func(d *persisted) {
		s := d.Sessions[d.Machines[machine]]
		if s == nil || s.RestoreCert == nil || s.MachineID != machine || certField(d.Certs[machine], "predecessorId") != "" {
			return
		}
		sid = s.ID
	})
	if sid == "" {
		return nil
	}
	return r.snap(restoreSnap(sid))
}

// putRestoreSnapshot: the checked archive's snapshot (dir) into the bucket, as the restoring session's row
func (r *Router) putRestoreSnapshot(sid, dir string) error {
	sig, err := os.ReadFile(filepath.Join(dir, "snapshot.sig"))
	if err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(dir, "snapshot.tar.gz"))
	if err != nil {
		return err
	}
	defer f.Close()
	return r.snapPutWhole(restoreSnap(sid), f, strings.TrimSpace(string(sig)))
}

// tidyRestores: once a restoring session is past its first boot (or gone), its restore files go; a session
// that came up is noted on the record it was restored from
func (r *Router) tidyRestores() {
	for _, m := range r.snapsLike("restore-") {
		sid := strings.TrimPrefix(m, "restore-")
		var state, from string
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[sid]; s != nil {
				state, from = s.State, s.RestoreFrom
			}
		})
		switch state {
		case "approval", "starting", "initialising":
			continue
		case "started":
			r.markRestored(from, sid)
		}
		r.snapDrop(m)
	}
}

func (r *Router) markRestored(recordID, sid string) {
	if recordID == "" {
		return
	}
	now := time.Now().UTC()
	r.st.Do(func(d *persisted) {
		for _, x := range d.Records {
			if x.ID == recordID {
				x.Restored = append(x.Restored, RestoreMark{Session: sid, At: now})
			}
		}
	})
	if box := r.box(); box != nil {
		err := updateIndex(box, func(list []map[string]any) []map[string]any {
			for _, e := range list {
				if e["id"] == recordID {
					prev, _ := e["restored"].([]any)
					e["restored"] = append(prev, map[string]any{"sessionId": sid, "at": now})
				}
			}
			return list
		})
		if err != nil {
			log.Printf("record %s: restored by %s, not noted in the index: %v", recordID, sid, err)
		}
	}
}

// earlierCoreSigned: the archive's core-cert.json is the master key's claim (the running core's master) of a core whose
// key signed the cert — the router's early check of what machine/restore.go checks again (core continuity)
func (r *Router) earlierCoreSigned(dir string, cert *Doc) bool {
	b, err := os.ReadFile(filepath.Join(dir, "core-cert.json"))
	if err != nil {
		return false
	}
	var mc MasterCert
	if json.Unmarshal(b, &mc) != nil {
		return false
	}
	st := r.coreStateDoc()
	var cs struct {
		Master string `json:"master"`
	}
	if st == nil || st.Decode(&cs) != nil || cs.Master == "" || !verifyP256(cs.Master, []byte(mc.Statement), mc.MasterSig) {
		return false
	}
	var claim struct {
		Kind     string                       `json:"kind"`
		Master   string                       `json:"master"`
		Core     struct{ SigningKey string }  `json:"core"`
		Identity *struct{ SigningKey string } `json:"identity"`
	}
	if json.Unmarshal([]byte(mc.Statement), &claim) != nil || claim.Kind != "claim" || claim.Master != cs.Master {
		return false
	}
	if verifyP256(claim.Core.SigningKey, []byte(cert.Payload), cert.Sig) {
		return true
	}
	return claim.Identity != nil && verifyP256(claim.Identity.SigningKey, []byte(cert.Payload), cert.Sig)
}

// coreStateDoc: the running core's signed state (its master key), as /identity answers it
func (r *Router) coreStateDoc() *Doc {
	status, b, err := r.core.Raw("GET", "/identity", nil)
	if err != nil || status != 200 {
		return nil
	}
	var id struct {
		State *Doc `json:"state"`
	}
	if json.Unmarshal(b, &id) != nil {
		return nil
	}
	return id.State
}
