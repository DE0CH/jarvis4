package main

// The router's state, backed up to the Storage Box (Deyao, 2026-10-15: a lost control box keeps the paused sessions).
// Everything the router keeps lives in /data, on the box's own disk; before this, a rebuilt box started with none of it.
//
//   - Every 15 min (and when a drain or a move begins) a tar.gz of /data — state.json, line-state.json, the input
//     log, the store docs, repos, the Claude login, the carry blobs, task runs, everything but the
//     snapshots, tmp/, uploads over 200 MB and the lock — encrypted with age to ROUTER_BACKUP_AGE_PUB (the private half
//     is ROUTER_BACKUP_AGE_KEY in the `infra` store, never on the box), as
//     claude-records/.jarvis2-router/state-<UTC>.tar.gz.age; the newest 48 are kept. Nothing changed (every file's
//     size and mtime): nothing sent.
//   - The session snapshots (snapshots/*.tar.gz, written once each) go one by one, encrypted the same way, to
//     claude-records/.jarvis2-router/snapshots/<name>.age, and are deleted there once gone here.
//   - Restoring (a rebuilt box): the router with ROUTER_RESTORE=1 and ROUTER_BACKUP_AGE_KEY, and a /data with no
//     state.json, fetches the newest state and every snapshot before it starts (restoreFromBackup); or offline:
//     `router restore-backup DIR` with the same env.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
)

const (
	backupDir      = "claude-records/.jarvis4-router" // Jarvis 4's own: Jarvis 2's router keeps .jarvis2-router
	backupKeep     = 48
	backupEvery    = 15 * time.Minute
	backupMaxFile  = 200 << 20
	backupSnapsDir = backupDir + "/snapshots"
)

type backupInfo struct {
	At    time.Time `json:"at,omitempty"`
	Path  string    `json:"path,omitempty"`
	Size  int64     `json:"size,omitempty"`
	Snaps int       `json:"snapshots,omitempty"`
	Error string    `json:"error,omitempty"`
}

var (
	backupMu   sync.Mutex // one backup at a time
	backupLast backupInfo
	backupFP   string // the last sent state's fingerprint
)

func backupStatus() backupInfo {
	backupMu.Lock()
	defer backupMu.Unlock()
	return backupLast
}

// backupSkip: what the state tarball leaves out
func backupSkip(rel string, size int64) bool {
	return moveSkip(rel) || strings.HasPrefix(rel, "snapshots/") && strings.HasSuffix(rel, ".tar.gz") ||
		strings.HasPrefix(rel, "uploads/") && size > backupMaxFile || strings.HasSuffix(rel, ".tmp")
}

// startStateBackups: the 15-minute loop (no Storage Box or no ROUTER_BACKUP_AGE_PUB: off, logged)
func (r *Router) startStateBackups() {
	if os.Getenv("ROUTER_BACKUP_AGE_PUB") == "" || recordsBoxFromEnv() == nil {
		log.Printf("backup: off (no ROUTER_BACKUP_AGE_PUB or no Storage Box)")
		return
	}
	go func() {
		time.Sleep(2 * time.Minute)
		for {
			r.BackupState("every 15 min")
			time.Sleep(backupEvery)
		}
	}()
}

// BackupState: one backup now (why: for the log). Safe to call from anywhere; overlapping calls wait.
func (r *Router) BackupState(why string) {
	pub := os.Getenv("ROUTER_BACKUP_AGE_PUB")
	box := recordsBoxFromEnv()
	if pub == "" || box == nil {
		return
	}
	rcpt, err := age.ParseX25519Recipient(strings.TrimSpace(pub))
	if err != nil {
		log.Printf("backup: ROUTER_BACKUP_AGE_PUB: %v", err)
		return
	}
	backupMu.Lock()
	defer backupMu.Unlock()
	info, err := backupData(r.cfg.DataDir, box, rcpt, time.Now().UTC())
	if err != nil {
		log.Printf("backup (%s): %v", why, err)
		backupLast.Error = err.Error()
		return
	}
	if info != nil {
		backupLast = *info
		log.Printf("backup (%s): %s, %d bytes, %d new snapshots", why, info.Path, info.Size, info.Snaps)
	}
}

// backupData: the state tarball (unless unchanged) and new snapshots; nil info = nothing changed. Caller holds backupMu.
func backupData(dir string, box *StorageBox, rcpt age.Recipient, now time.Time) (*backupInfo, error) {
	files, err := listData(dir)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	var keep, snaps []moveFile
	for _, f := range files {
		if strings.HasPrefix(f.Path, "snapshots/") && strings.HasSuffix(f.Path, ".tar.gz") {
			snaps = append(snaps, f)
			continue
		}
		if backupSkip(f.Path, f.Size) {
			continue
		}
		keep = append(keep, f)
		fmt.Fprintf(h, "%s %d %d\n", f.Path, f.Size, f.Mtime)
		if f.Size < 4<<20 { // small files by content too: a same-size rewrite within one mtime tick
			if b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Path))); err == nil {
				h.Write(b)
			}
		}
	}
	if err := box.Mkcols(backupSnapsDir); err != nil {
		return nil, err
	}
	// snapshots: each once
	have, err := davList(box, backupSnapsDir)
	if err != nil {
		return nil, err
	}
	sent := 0
	want := map[string]bool{}
	for _, f := range snaps {
		name := path.Base(f.Path) + ".age"
		want[name] = true
		if have[name] {
			continue
		}
		if err := putEncrypted(box, backupSnapsDir+"/"+name, rcpt, func(w io.Writer) error {
			src, err := os.Open(filepath.Join(dir, filepath.FromSlash(f.Path)))
			if err != nil {
				return err
			}
			defer src.Close()
			_, err = io.Copy(w, src)
			return err
		}, dir); err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", f.Path, err)
		}
		sent++
	}
	for name := range have {
		if !want[name] && strings.HasSuffix(name, ".tar.gz.age") {
			box.Delete(backupSnapsDir + "/" + name)
		}
	}
	fp := hex.EncodeToString(h.Sum(nil))
	if fp == backupFP && sent == 0 {
		return nil, nil
	}
	info := &backupInfo{At: now, Snaps: sent}
	if fp != backupFP {
		name := "state-" + now.Format("20060102T150405Z") + ".tar.gz.age"
		var size int64
		err := putEncrypted(box, backupDir+"/"+name, rcpt, func(w io.Writer) error {
			cw := &countWriter{w: w}
			err := writeTarGz(cw, dir, keep)
			size = cw.n
			return err
		}, dir)
		if err != nil {
			return nil, err
		}
		backupFP = fp
		info.Path, info.Size = backupDir+"/"+name, size
		// keep the newest backupKeep
		all, err := davList(box, backupDir)
		if err == nil {
			var states []string
			for n := range all {
				if strings.HasPrefix(n, "state-") && strings.HasSuffix(n, ".tar.gz.age") {
					states = append(states, n)
				}
			}
			sort.Strings(states)
			for i := 0; i+backupKeep < len(states); i++ {
				box.Delete(backupDir + "/" + states[i])
			}
		}
	} else {
		info.Path, info.Size = backupLast.Path, backupLast.Size
	}
	return info, nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func writeTarGz(w io.Writer, dir string, files []moveFile) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		src, err := os.Open(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil {
			continue // gone since the listing
		}
		fi, err := src.Stat()
		if err != nil {
			src.Close()
			continue
		}
		hdr := &tar.Header{Name: f.Path, Mode: 0o600, Size: fi.Size(), ModTime: fi.ModTime(), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			src.Close()
			return err
		}
		_, err = io.CopyN(tw, src, fi.Size())
		src.Close()
		if err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// putEncrypted: write → age → a temp file in dir/tmp → PUT
func putEncrypted(box *StorageBox, remote string, rcpt age.Recipient, write func(io.Writer) error, dir string) error {
	tmpDir := filepath.Join(dir, "tmp")
	os.MkdirAll(tmpDir, 0o700)
	f, err := os.CreateTemp(tmpDir, "backup-*.age")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	aw, err := age.Encrypt(f, rcpt)
	if err != nil {
		f.Close()
		return err
	}
	if err := write(aw); err != nil {
		f.Close()
		return err
	}
	if err := aw.Close(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return box.PutFile(remote, f.Name())
}

// davList: the names in a Storage Box directory (PROPFIND, depth 1)
func davList(box *StorageBox, dir string) (map[string]bool, error) {
	resp, err := box.do("PROPFIND", dir+"/", strings.NewReader(""), 0, map[string]string{"Depth": "1"})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return map[string]bool{}, nil
	}
	if resp.StatusCode != 207 {
		return nil, fmt.Errorf("PROPFIND %s: HTTP %d", dir, resp.StatusCode)
	}
	var ms struct {
		Responses []struct {
			Href string `xml:"href"`
		} `xml:"response"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err := xml.Unmarshal(b, &ms); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, r := range ms.Responses {
		h, _ := url.PathUnescape(r.Href)
		h = strings.TrimSuffix(h, "/")
		if strings.HasSuffix(h, strings.TrimSuffix(dir, "/")) {
			continue // the directory itself
		}
		out[path.Base(h)] = true
	}
	return out, nil
}

// restoreFromBackup: the newest state and every snapshot into dir (a rebuilt box: no state.json yet)
func restoreFromBackup(dir string, box *StorageBox, keyText string) error {
	id, err := age.ParseX25519Identity(strings.TrimSpace(keyText))
	if err != nil {
		return fmt.Errorf("ROUTER_BACKUP_AGE_KEY: %w", err)
	}
	all, err := davList(box, backupDir)
	if err != nil {
		return err
	}
	var states []string
	for n := range all {
		if strings.HasPrefix(n, "state-") && strings.HasSuffix(n, ".tar.gz.age") {
			states = append(states, n)
		}
	}
	if len(states) == 0 {
		return errors.New("no state backup on the Storage Box")
	}
	sort.Strings(states)
	newest := states[len(states)-1]
	enc, err := box.Get(backupDir + "/" + newest)
	if err != nil || enc == nil {
		return fmt.Errorf("fetching %s: %v", newest, err)
	}
	ar, err := age.Decrypt(bytes.NewReader(enc), id)
	if err != nil {
		return err
	}
	gz, err := gzip.NewReader(ar)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	n := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		p, err := dataPath(dir, hdr.Name)
		if err != nil {
			return fmt.Errorf("backup entry %q: %w", hdr.Name, err)
		}
		os.MkdirAll(filepath.Dir(p), 0o700)
		out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, tr)
		out.Close()
		if err != nil {
			return err
		}
		os.Chtimes(p, hdr.ModTime, hdr.ModTime)
		n++
	}
	snaps, err := davList(box, backupSnapsDir)
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Join(dir, "snapshots"), 0o700)
	for name := range snaps {
		if !strings.HasSuffix(name, ".tar.gz.age") {
			continue
		}
		enc, err := box.Get(backupSnapsDir + "/" + name)
		if err != nil || enc == nil {
			return fmt.Errorf("snapshot %s: %v", name, err)
		}
		ar, err := age.Decrypt(bytes.NewReader(enc), id)
		if err != nil {
			return fmt.Errorf("snapshot %s: %w", name, err)
		}
		b, err := io.ReadAll(ar)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "snapshots", strings.TrimSuffix(name, ".age")), b, 0o600); err != nil {
			return err
		}
	}
	log.Printf("restore: %s (%d files) and %d snapshots into %s", newest, n, len(snaps), dir)
	return nil
}

// maybeRestore: at start, on a rebuilt box (ROUTER_RESTORE=1, a key, no state.json)
func maybeRestore(dir string) {
	if os.Getenv("ROUTER_RESTORE") != "1" {
		return
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err == nil {
		log.Printf("restore: state.json exists, nothing restored (ROUTER_RESTORE can go)")
		return
	}
	box := recordsBoxFromEnv()
	key := os.Getenv("ROUTER_BACKUP_AGE_KEY")
	if box == nil || key == "" {
		log.Fatal("restore: ROUTER_RESTORE=1 needs the Storage Box and ROUTER_BACKUP_AGE_KEY")
	}
	if err := restoreFromBackup(dir, box, key); err != nil {
		log.Fatalf("restore: %v", err)
	}
}

// restoreCommand: `router restore-backup DIR` (offline, same env)
func restoreCommand(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: router restore-backup DIR   (env STORAGEBOX_HOST/USER/PASSWORD, ROUTER_BACKUP_AGE_KEY)")
		os.Exit(2)
	}
	box := recordsBoxFromEnv()
	if box == nil {
		fmt.Fprintln(os.Stderr, "no STORAGEBOX_HOST/USER/PASSWORD")
		os.Exit(1)
	}
	if err := restoreFromBackup(args[0], box, os.Getenv("ROUTER_BACKUP_AGE_KEY")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
