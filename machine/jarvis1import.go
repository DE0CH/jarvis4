package main

// A Jarvis 1 import (router/jarvis1import.go): a new line whose cert's restore names a paused Jarvis 1 session (its
// id) and the sha256 of the router's import manifest {kind "jarvis1-import", session, files: [{name, sha256, size}]}.
// Deyao's Face ID signed that hash, so it vouches for every byte the manifest lists (DESIGN "Inputs to a machine"
// (a)); this machine takes each file through the router (no Storage Box credential here) and refuses any whose
// sha256 or size differs from the manifest. Then it does what Jarvis 1's restore-snapshot + entrypoint did:
//
//   - workspace.tar.gz → ~/workspace, artifacts.tar.gz → ~/artifacts, harness.tar.gz → ~/.paseo, ~/.openclaw,
//     ~/.local/share/opencode (each tarball extracted into a staging dir while it is hashed, moved into place only
//     once its hash matched; nothing outside those roots, nothing through a symlink);
//   - the transcripts (<uuid>.jsonl) → ~/.claude/projects/<slug of the working dir>/ once the repos are in place, so
//     the supervisor resumes the newest (`claude --resume <id>`) under the same conversation id;
//   - claude.json → ~/.claude.json without Jarvis 1's account fields (the entrypoint merges this session's account
//     over it; machineID stays, so Remote Control reattaches the same conversation in the Claude app);
//   - repo remotes: credentials embedded in a GitHub https URL are dropped and the URL normalised to
//     https://github.com/<owner>/<name>.git, which this machine's deploy-key rewrites send over SSH;
//   - session.json (the Jarvis 1 record) → ~/artifacts/jarvis1-import/session.json, and every wakeup and cron it had
//     armed is armed again as THIS line's own signed request (vouched (c), delivered later like any of its own): a
//     wakeup whose time has passed fires 5 minutes after boot, a cron keeps its period and time of day (its next run
//     after now), and a cron run that was missed while paused fires once 5 minutes after boot as a wakeup. What was
//     armed is written to ~/artifacts/jarvis1-import/rearmed.txt.

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const j1Kind = "jarvis1-import"

var (
	j1FileRE   = regexp.MustCompile(`^(session\.json|claude\.json|manifest\.txt|workspace\.tar\.gz|artifacts\.tar\.gz|harness\.tar\.gz|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jsonl)$`)
	j1StageDir = ".jarvis1-import" // under $HOME, outside snapshotPaths
	j1Soon     = 5 * time.Minute   // a wakeup (or a missed cron run) whose time passed while paused fires this long after boot
	// the roots each tarball may write (relative to $HOME)
	j1Roots = map[string][]string{
		"workspace.tar.gz": {"workspace"},
		"artifacts.tar.gz": {"artifacts"},
		"harness.tar.gz":   {".paseo", ".openclaw", ".local/share/opencode"},
	}
)

type j1File struct {
	Name   string `json:"name"`
	Sha256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type j1Manifest struct {
	Kind    string   `json:"kind"`
	V       int      `json:"v"`
	Session string   `json:"session"`
	Files   []j1File `json:"files"`
}

// readJ1Manifest: the restore bytes as an import manifest (strictly: known fields and names, for the session the cert
// names), or false (they are something else: a Jarvis 4 snapshot)
func readJ1Manifest(p, session string) (*j1Manifest, bool) {
	fi, err := os.Stat(p)
	if err != nil || fi.Size() > 1<<20 {
		return nil, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var m j1Manifest
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || m.Kind != j1Kind || m.V != 1 || m.Session != session || len(m.Files) == 0 {
		return nil, false
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		if !j1FileRE.MatchString(f.Name) || !sha256RE.MatchString(f.Sha256) || f.Size < 0 || seen[f.Name] {
			return nil, false
		}
		seen[f.Name] = true
	}
	return &m, true
}

// importJarvis1: every file of the manifest, checked, into place (the transcripts wait in the staging dir for
// placeImportedTranscripts, after the repos are cloned)
func importJarvis1(c *client, m *j1Manifest) error {
	home, _ := os.UserHomeDir()
	stage := filepath.Join(home, j1StageDir)
	os.RemoveAll(stage)
	if err := os.MkdirAll(filepath.Join(stage, "transcripts"), 0o700); err != nil {
		return err
	}
	var record []byte
	for _, f := range m.Files {
		start := time.Now()
		var err error
		switch {
		case j1Roots[f.Name] != nil:
			err = j1Extract(c, f, stage, j1Roots[f.Name])
		case strings.HasSuffix(f.Name, ".jsonl"):
			err = j1FetchFile(c, f, filepath.Join(stage, "transcripts", f.Name))
		default: // session.json, claude.json, manifest.txt
			p := filepath.Join(stage, f.Name)
			if err = j1FetchFile(c, f, p); err == nil {
				switch f.Name {
				case "claude.json":
					err = j1ClaudeJSON(p, filepath.Join(home, ".claude.json"))
				case "session.json":
					record, err = os.ReadFile(p)
				}
			}
		}
		if err != nil {
			return fmt.Errorf("Jarvis 1 import, %s: %w", f.Name, err)
		}
		log.Printf("jarvis1 import: %s (%d bytes) checked and in place in %s", f.Name, f.Size, time.Since(start).Round(time.Second))
	}
	out := filepath.Join(home, "artifacts", "jarvis1-import")
	os.MkdirAll(out, 0o700)
	if record != nil {
		os.WriteFile(filepath.Join(out, "session.json"), record, 0o600)
	}
	j1FixRemotes(filepath.Join(home, "workspace"))
	restoredArchive = false // a new line's own keys: Jarvis 1 brings none (deliver.go)
	j1Imported = m
	log.Printf("imported Jarvis 1 session %s (%d files)", m.Session, len(m.Files))
	return nil
}

var j1Imported *j1Manifest // set by importJarvis1: the transcripts and the schedule still to place

// j1FetchFile: one file through the router, to p, refused unless its size and sha256 are the manifest's
func j1FetchFile(c *client, f j1File, p string) error {
	sum, _, err := c.download("/m/import-file/"+f.Name, p)
	if err != nil {
		os.Remove(p)
		return err
	}
	return j1Check(f, sum, fileSize(p), func() { os.Remove(p) })
}

func j1Check(f j1File, sum string, n int64, drop func()) error {
	if n != f.Size || sum != f.Sha256 {
		drop()
		return fmt.Errorf("not the bytes the cert names (got %d bytes, sha256 %.12s…)", n, sum)
	}
	return nil
}

func fileSize(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return -1
	}
	return fi.Size()
}

// j1Extract: a tarball streamed through the router, extracted into the staging dir while it is hashed, then (only
// when the hash and size match) each of its roots moved into $HOME
func j1Extract(c *client, f j1File, stage string, roots []string) error {
	tmp := filepath.Join(stage, "x-"+strings.TrimSuffix(f.Name, ".tar.gz"))
	os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	sum, _, n, err := c.downloadTo("/m/import-file/"+f.Name, func(r io.Reader) error { return untarConfined(r, tmp, roots) })
	if err != nil {
		return err
	}
	if err := j1Check(f, sum, n, func() {}); err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	for _, root := range roots {
		src := filepath.Join(tmp, root)
		if _, err := os.Lstat(src); err != nil {
			continue
		}
		dst := filepath.Join(home, root)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if root == "workspace" || root == "artifacts" {
			// the image may have made the directory already: move its entries in, replacing what is there
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
			ents, _ := os.ReadDir(src)
			for _, e := range ents {
				os.RemoveAll(filepath.Join(dst, e.Name()))
				if err := moveAcross(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
					return err
				}
			}
			continue
		}
		os.RemoveAll(dst)
		if err := moveAcross(src, dst); err != nil {
			return err
		}
	}
	return nil
}

// untarConfined: a tar.gz into dir, only entries under one of roots, never through a symlink, never outside dir.
// It reads the stream to its end (the caller hashes all of it).
func untarConfined(r io.Reader, dir string, roots []string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	skipped := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(strings.TrimPrefix(h.Name, "./"))
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") || !underRoots(name, roots) {
			skipped++
			continue
		}
		dst := filepath.Join(dir, name)
		if !noSymlinkParents(dir, name) {
			skipped++
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, os.FileMode(h.Mode)&0o777|0o700); err != nil {
				return err
			}
		case tar.TypeSymlink:
			os.MkdirAll(filepath.Dir(dst), 0o755)
			os.RemoveAll(dst)
			if err := os.Symlink(h.Linkname, dst); err != nil {
				return err
			}
		case tar.TypeLink:
			target := filepath.Clean(strings.TrimPrefix(h.Linkname, "./"))
			if filepath.IsAbs(target) || strings.HasPrefix(target, "..") || !underRoots(target, roots) || !noSymlinkParents(dir, target) {
				skipped++
				continue
			}
			os.MkdirAll(filepath.Dir(dst), 0o755)
			os.RemoveAll(dst)
			if err := os.Link(filepath.Join(dir, target), dst); err != nil {
				return err
			}
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(dst), 0o755)
			os.RemoveAll(dst)
			f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(h.Mode)&0o777|0o600)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
			os.Chtimes(dst, h.ModTime, h.ModTime) // git's index keeps trusting unchanged files
		default:
			skipped++
		}
	}
	if skipped > 0 {
		log.Printf("jarvis1 import: %d tar entries skipped (outside %v, through a symlink, or not a file/dir/link)", skipped, roots)
	}
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return err
	}
	return nil
}

func underRoots(name string, roots []string) bool {
	for _, r := range roots {
		if name == r || strings.HasPrefix(name, r+"/") {
			return true
		}
	}
	return false
}

// noSymlinkParents: no directory between dir and name's parent is a symlink (an entry can't be written through one)
func noSymlinkParents(dir, name string) bool {
	parts := strings.Split(filepath.Dir(name), "/")
	cur := dir
	for _, p := range parts {
		if p == "." || p == "" {
			continue
		}
		cur = filepath.Join(cur, p)
		fi, err := os.Lstat(cur)
		if err != nil {
			return true // not made yet: MkdirAll makes a real directory
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	return true
}

// j1ClaudeJSON: Jarvis 1's ~/.claude.json without its account (the entrypoint adds this session's)
func j1ClaudeJSON(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("not JSON: %v", err)
	}
	delete(m, "oauthAccount")
	delete(m, "userID")
	out, _ := json.Marshal(m)
	return os.WriteFile(dst, out, 0o600)
}

var ghCredURLRE = regexp.MustCompile(`^https://[^/@]+@github\.com/(.+)$`)
var ghHTTPSRE = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+?)(\.git)?/?$`)

// j1FixRemotes: each repo's remotes without embedded credentials, GitHub https URLs ending in .git (the form the
// deploy-key rewrites match)
func j1FixRemotes(ws string) {
	ents, _ := os.ReadDir(ws)
	for _, e := range ents {
		repo := filepath.Join(ws, e.Name())
		if _, err := os.Stat(filepath.Join(repo, ".git")); err != nil {
			continue
		}
		out, _ := sessionCommand(nil, "git", "-C", repo, "config", "--get-regexp", `^remote\..*\.url$`).Output()
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			key, url, ok := strings.Cut(line, " ")
			if !ok {
				continue
			}
			fixed := j1FixURL(url)
			if fixed != url {
				if err := sessionCommand(nil, "git", "-C", repo, "config", key, fixed).Run(); err == nil {
					log.Printf("jarvis1 import: %s %s → %s", e.Name(), key, fixed)
				}
			}
		}
	}
}

func j1FixURL(u string) string {
	if m := ghCredURLRE.FindStringSubmatch(u); m != nil {
		u = "https://github.com/" + m[1]
	}
	if m := ghHTTPSRE.FindStringSubmatch(u); m != nil {
		return "https://github.com/" + m[1] + ".git"
	}
	return u
}

// placeImportedTranscripts: after the repos are cloned (the working dir decides the project slug, as Jarvis 1's
// entrypoint computes it): the imported transcripts into ~/.claude/projects/<slug>/
func placeImportedTranscripts() {
	if j1Imported == nil {
		return
	}
	home, _ := os.UserHomeDir()
	src := filepath.Join(home, j1StageDir, "transcripts")
	ents, _ := os.ReadDir(src)
	if len(ents) == 0 {
		return
	}
	pdir := filepath.Join(home, ".claude", "projects", projectSlug(workingDir(home)))
	if err := os.MkdirAll(pdir, 0o700); err != nil {
		log.Printf("jarvis1 import: %v", err)
		return
	}
	for _, e := range ents {
		if err := moveAcross(filepath.Join(src, e.Name()), filepath.Join(pdir, e.Name())); err != nil {
			log.Printf("jarvis1 import: transcript %s: %v", e.Name(), err)
		}
	}
	os.Remove(filepath.Join(home, ".claude", ".first-prompt-sent")) // the approved first prompt goes into the resumed conversation
	log.Printf("jarvis1 import: %d transcript(s) in %s", len(ents), pdir)
}

// workingDir: the single repo in ~/workspace if there is exactly one, else ~/workspace (Jarvis 1's entrypoint)
func workingDir(home string) string {
	ws := filepath.Join(home, "workspace")
	ents, _ := os.ReadDir(ws)
	var dirs []string
	for _, e := range ents {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	if len(dirs) == 1 {
		return filepath.Join(ws, dirs[0])
	}
	return ws
}

var slugRE = regexp.MustCompile(`[^A-Za-z0-9]`)

func projectSlug(wd string) string { return slugRE.ReplaceAllString(wd, "-") }

// ---- the schedule ----------------------------------------------------------------------------------------------

type j1Wake struct {
	Name   string `json:"name"`
	At     int64  `json:"at"`
	Prompt string `json:"prompt"`
}

type j1Cron struct {
	Name   string `json:"name"`
	Prompt string `json:"prompt"`
	Every  int64  `json:"every"`
	TZ     string `json:"tz"`
	NextAt int64  `json:"nextAt"`
	Until  int64  `json:"until"`
}

// j1Schedule: the wakeups and crons the Jarvis 1 record had armed, as this line's own requests (path, body), with
// a line for rearmed.txt each
type j1Arm struct {
	Path string
	Body map[string]any
	Note string
}

func j1Schedule(record []byte, sid string, now time.Time) ([]j1Arm, []string) {
	var rec struct {
		Metadata map[string]string `json:"metadata"`
	}
	json.Unmarshal(record, &rec)
	keys := make([]string, 0, len(rec.Metadata))
	for k := range rec.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []j1Arm
	var notes []string
	ms := now.UnixMilli()
	for _, k := range keys {
		v := rec.Metadata[k]
		switch {
		case strings.HasPrefix(k, "wake_"):
			var w j1Wake
			if json.Unmarshal([]byte(v), &w) != nil || w.Prompt == "" {
				notes = append(notes, "skipped "+k+": not a wakeup record")
				continue
			}
			if w.Name == "" {
				w.Name = strings.TrimPrefix(k, "wake_")
			}
			body := map[string]any{"name": w.Name, "prompt": w.Prompt}
			when := time.UnixMilli(w.At).UTC()
			if w.At <= ms+int64(time.Minute/time.Millisecond) {
				body["delaySeconds"] = int(j1Soon.Seconds())
				out = append(out, j1Arm{"/m/api/sessions/" + sid + "/wakeups", body,
					fmt.Sprintf("wakeup %q: was due %s (passed while paused), fires %s after this boot", w.Name, when.Format(time.RFC3339), j1Soon)})
			} else {
				body["at"] = w.At
				out = append(out, j1Arm{"/m/api/sessions/" + sid + "/wakeups", body, fmt.Sprintf("wakeup %q: at %s, as in Jarvis 1", w.Name, when.Format(time.RFC3339))})
			}
		case strings.HasPrefix(k, "cron_"):
			var c j1Cron
			if json.Unmarshal([]byte(v), &c) != nil || c.Prompt == "" || c.Every <= 0 {
				notes = append(notes, "skipped "+k+": not a cron record")
				continue
			}
			if c.Name == "" {
				c.Name = strings.TrimPrefix(k, "cron_")
			}
			if c.Until > 0 && c.Until <= ms {
				notes = append(notes, fmt.Sprintf("cron %q: ended %s in Jarvis 1, not armed", c.Name, time.UnixMilli(c.Until).UTC().Format(time.RFC3339)))
				continue
			}
			next, step := c.NextAt, c.Every*1000
			missed := next > 0 && next <= ms
			if next <= ms {
				if next <= 0 {
					next = ms
				}
				next += ((ms-next)/step + 1) * step
			}
			body := map[string]any{"name": c.Name, "prompt": c.Prompt, "everySeconds": c.Every, "at": next}
			if c.TZ != "" {
				body["tz"] = c.TZ
			}
			if c.Until > next {
				body["until"] = c.Until
			}
			out = append(out, j1Arm{"/m/api/sessions/" + sid + "/crons", body,
				fmt.Sprintf("cron %q: every %ds, next %s (Jarvis 1's time of day kept)", c.Name, c.Every, time.UnixMilli(next).UTC().Format(time.RFC3339))})
			if missed {
				out = append(out, j1Arm{"/m/api/sessions/" + sid + "/wakeups",
					map[string]any{"name": j1MissedName(c.Name), "prompt": c.Prompt, "delaySeconds": int(j1Soon.Seconds())},
					fmt.Sprintf("cron %q: its run due %s was missed while paused, so it runs once %s after this boot (wakeup %q)",
						c.Name, time.UnixMilli(c.NextAt).UTC().Format(time.RFC3339), j1Soon, j1MissedName(c.Name))})
			}
		case strings.HasPrefix(k, "watch_"):
			notes = append(notes, "not armed: "+k+" (a Jarvis 1 watch; Jarvis 4 has no watches yet)")
		}
	}
	return out, notes
}

func j1MissedName(n string) string {
	n = "missed-" + n
	if len(n) > 40 {
		n = n[:40]
	}
	return n
}

// rearmJarvis1: the Jarvis 1 record's wakeups and crons, signed by this machine (the router keeps each request
// exactly as signed: what vouches for its delivery later). A failure is noted, never fatal.
func rearmJarvis1(c *client, sid string) {
	if j1Imported == nil {
		return
	}
	home, _ := os.UserHomeDir()
	out := filepath.Join(home, "artifacts", "jarvis1-import")
	record, err := os.ReadFile(filepath.Join(out, "session.json"))
	if err != nil {
		return
	}
	arms, notes := j1Schedule(record, sid, time.Now())
	lines := []string{"Re-armed from Jarvis 1 session " + j1Imported.Session + " on " + time.Now().UTC().Format(time.RFC3339) + ":"}
	for _, a := range arms {
		if err := c.json("POST", a.Path, a.Body, nil); err != nil {
			lines = append(lines, "FAILED "+a.Note+": "+err.Error())
			log.Printf("jarvis1 import: arming failed: %s: %v", a.Note, err)
			continue
		}
		lines = append(lines, a.Note)
		log.Printf("jarvis1 import: armed %s", a.Note)
	}
	lines = append(lines, notes...)
	if len(arms) == 0 && len(notes) == 0 {
		lines = append(lines, "(nothing was armed in Jarvis 1)")
	}
	os.WriteFile(filepath.Join(out, "rearmed.txt"), []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	os.RemoveAll(filepath.Join(home, j1StageDir))
}

// moveAcross: a rename, or (the state directories are bind-mounted from the volume, volume.go, so the import's
// staging dir on the root disk is another filesystem) a copy that keeps modes, links and times, then the source goes
func moveAcross(src, dst string) error {
	err := os.Rename(src, dst)
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	if out, err := sessionCommand(nil, "cp", "-a", "--", src, dst).CombinedOutput(); err != nil {
		return fmt.Errorf("copying %s across filesystems: %v %s", filepath.Base(src), err, strings.TrimSpace(string(out)))
	}
	return os.RemoveAll(src)
}
