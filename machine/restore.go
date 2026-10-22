package main

// Restoring a destroyed session's archived snapshot into a NEW line (router/restore.go), and the repos'
// state recorded in every snapshot (for the router's uncommitted-work check of a paused session).
//
// A new line (a cert with no predecessor) whose cert names a restore (Config.restore: the old machine and the
// snapshot's sha256, which the phone approved) restores the snapshot the router serves at /m/restore-snapshot,
// after checking:
//   - its sha256 is the one the cert names;
//   - the old cert (/m/restore-cert) is a succession cert signed by the core, for the machine the cert names;
//   - the snapshot is signed by that cert's machine signing key (same format as a pause snapshot);
//   - a snapshot from a line that held a sensitive store doesn't land in a line that holds none.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// restoreTmp: where a restore's bytes land while they are checked (a var: tests move it)
var restoreTmp = dir + "/restore.tar.gz"

// changesFile: the repos' state when the snapshot was taken (router/archive.go reads it); in snapshotPaths
const changesFile = ".jarvis2-changes.txt"

// repoChangesSH: one "<repo> <uncommitted files> <unpushed commits, -1 = no upstream>" line per repo
const repoChangesSH = `cd ~/workspace 2>/dev/null || exit 0; for d in */; do d=${d%/}; [ -d "$d/.git" ] || continue; ` +
	`u=$(git -C "$d" status --porcelain 2>/dev/null | wc -l); ` +
	`if git -C "$d" rev-parse --abbrev-ref @{u} >/dev/null 2>&1; then p=$(git -C "$d" rev-list @{u}..HEAD --count 2>/dev/null || echo 0); else p=-1; fi; ` +
	`echo "$d $u $p"; done`

// changesTimeout: the repo check runs with the session frozen (2026-10-21: session sad35945f04b2124d's final snapshot
// went silent right after the freeze, with this check the only step before the snapshot's first progress line); a
// git that waits on a stopped process or a slow disk can't hold the snapshot up past it
var (
	changesTimeout = 60 * time.Second
	changesScript  = repoChangesSH // a var: tests make it hang
)

// writeChanges: before every snapshot; a failure (or the time limit) only leaves the router without the check. No
// optional locks and no fsmonitor: the session's processes are stopped, so nothing may be waited on.
func writeChanges() {
	home, _ := os.UserHomeDir()
	ctx, cancel := context.WithTimeout(context.Background(), changesTimeout)
	defer cancel()
	t0 := time.Now()
	cmd := sessionCommand(ctx, "bash", "-c", changesScript)
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0", "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=core.fsmonitor", "GIT_CONFIG_VALUE_0=false")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) } // bash and every git it started
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.Output()
	switch {
	case ctx.Err() != nil:
		log.Printf("repo changes: not done within %s; the snapshot goes on without them", changesTimeout)
		out = nil
	case err != nil:
		log.Printf("repo changes: %v", err)
	default:
		log.Printf("repo changes: checked in %.1f s", time.Since(t0).Seconds())
	}
	os.WriteFile(filepath.Join(home, changesFile), out, 0o600)
}

// restoreArchived: the archived snapshot into a new line's first machine, only when the cert names it
// (Config.restore: the old line's machine and the snapshot's sha256, approved on the phone with the new line). The
// bytes whose hash the cert names are either a destroyed Jarvis 4 session's signed snapshot, or a Jarvis 1 import's
// manifest (jarvis1import.go), told apart by their content: either way they are exactly what the phone approved.
func restoreArchived(c *client, coreKey, me string, cert *Cert, v Vouched) error {
	ref := v.Config.Restore
	if cert.PredID != "" || ref == nil {
		return nil
	}
	tmp := restoreTmp
	defer os.Remove(tmp)
	sum, hdr, err := c.download("/m/restore-snapshot", tmp)
	if err != nil {
		return fmt.Errorf("a restore was asked for but the router serves no snapshot (%v)", err)
	}
	if sum != ref.Sha256 {
		return errors.New("the archived snapshot isn't the one the cert names")
	}
	if man, ok := readJ1Manifest(tmp, ref.Machine); ok {
		return importJarvis1(c, man)
	}
	var rc restoreCertDocs
	if err := c.json("GET", "/m/restore-cert", nil, &rc); err != nil || rc.Cert == nil {
		return fmt.Errorf("the cert names a restore but the router serves no old cert (%v)", err)
	}
	signer, err := restoreSigner(coreKey, rc)
	if err != nil {
		return err
	}
	old, err := checkRestoreCert(signer, me, cert, rc.Cert)
	if err != nil {
		return err
	}
	if old.Machine.ID != ref.Machine {
		return fmt.Errorf("the old cert is for %s, the cert names %s", old.Machine.ID, ref.Machine)
	}
	if !verify(old.Machine.SigningKey, []byte(sum), hdr.Get("X-Snapshot-Sig")) {
		return errors.New("the snapshot isn't signed by the machine its cert names")
	}
	n, err := unpackFile(tmp)
	if err != nil {
		return err
	}
	restoredArchive = true
	log.Printf("restored the archived snapshot of %s (line %s, %d files)", old.Machine.ID, old.Line, n)
	return nil
}

// restoreCertDocs: what /m/restore-cert serves — the old line's cert, and for a cert an earlier core signed, that core's
// claim (the master key's statement naming it: the archive's core-cert.json) and the running core's signed state
// (naming its master key)
type restoreCertDocs struct {
	Cert     *SignedDoc `json:"cert"`
	CoreCert *struct {
		Statement string `json:"statement"`
		MasterSig string `json:"masterSig"`
	} `json:"coreCert"`
	CoreState *SignedDoc `json:"coreState"`
}

// restoreSigner: the key the old cert must be signed by — this machine's core's, or an earlier core's that the master
// key claimed: the running core states its master key (signed with the key this machine trusts), the master key
// signed the claim naming the earlier core (its keys, or the keys a seeded claim derives), so a session archived under
// any core Deyao set up with this kit restores (docs/DESIGN.md "Core continuity")
func restoreSigner(coreKey string, rc restoreCertDocs) (string, error) {
	if verify(coreKey, []byte(rc.Cert.Payload), rc.Cert.Sig) || rc.CoreCert == nil || rc.CoreState == nil {
		return coreKey, nil
	}
	var st struct {
		Kind   string `json:"kind"`
		Master string `json:"master"`
	}
	if err := verifyDoc(coreKey, rc.CoreState, &st); err != nil || st.Kind != "core-state" || st.Master == "" {
		return "", errors.New("the restore names an earlier core, but the core's state isn't signed by this machine's core")
	}
	if !verify(st.Master, []byte(rc.CoreCert.Statement), rc.CoreCert.MasterSig) {
		return "", errors.New("the earlier core's claim isn't signed by the master key")
	}
	var claim struct {
		Kind     string                       `json:"kind"`
		Master   string                       `json:"master"`
		Core     struct{ SigningKey string }  `json:"core"`
		Identity *struct{ SigningKey string } `json:"identity"`
	}
	if json.Unmarshal([]byte(rc.CoreCert.Statement), &claim) != nil || claim.Kind != "claim" || claim.Master != st.Master {
		return "", errors.New("the earlier core's claim isn't a claim by this master key")
	}
	for _, k := range []string{claim.Core.SigningKey, func() string {
		if claim.Identity != nil {
			return claim.Identity.SigningKey
		}
		return ""
	}()} {
		if k != "" && verify(k, []byte(rc.Cert.Payload), rc.Cert.Sig) {
			return k, nil
		}
	}
	return "", errors.New("the restore cert isn't signed by the core the master key's claim names")
}

// checkRestoreCert: the old line's cert, core-signed, for another machine; sensitive stays sensitive
func checkRestoreCert(coreKey, me string, cert *Cert, doc *SignedDoc) (*Cert, error) {
	var old Cert
	if err := verifyDoc(coreKey, doc, &old); err != nil || old.Kind != "succession-cert" || old.Machine == nil {
		return nil, fmt.Errorf("the restore cert isn't a succession cert signed by the core (%v)", err)
	}
	if old.Machine.ID == me {
		return nil, errors.New("the restore cert names this machine")
	}
	if old.Sensitive && !cert.Sensitive {
		return nil, errors.New("the snapshot comes from a line with a sensitive store; this line holds none")
	}
	return &old, nil
}

func checkSnapshotSig(signingKey string, body []byte, sig string) error {
	sum := sha256.Sum256(body)
	if !verify(signingKey, []byte(hex.EncodeToString(sum[:])), sig) {
		return errors.New("the snapshot isn't signed by the machine its cert names")
	}
	return nil
}

// reimportJarvis1: a successor whose cert names no snapshot (its predecessor left none: e.g. its machine was stopped
// before it could sign one) while the line's config names a restore takes that restore again, if it is a Jarvis 1
// import — exactly the bytes the phone approved for the line (DECISIONS 141). A destroyed Jarvis 4 session's snapshot
// is not taken again this way.
func reimportJarvis1(c *client, v Vouched) error {
	ref := v.Config.Restore
	tmp := restoreTmp
	defer os.Remove(tmp)
	sum, _, err := c.download("/m/restore-snapshot", tmp)
	if err != nil {
		log.Printf("no snapshot and no import to take again (%v): starting with no predecessor state", err)
		return nil
	}
	if sum != ref.Sha256 {
		return errors.New("the import manifest isn't the one the cert names")
	}
	man, ok := readJ1Manifest(tmp, ref.Machine)
	if !ok {
		log.Printf("the line's restore isn't a Jarvis 1 import: starting with no predecessor state")
		return nil
	}
	log.Printf("the predecessor left no snapshot: importing Jarvis 1 session %s again", man.Session)
	return importJarvis1(c, man)
}
