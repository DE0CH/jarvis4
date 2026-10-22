package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// the machine's own run dir: the restore temp files and the private keys go to a temp dir (a test host may itself be a
// session machine: the client re-reads privPath before signing and would sign with that machine's real key)
func TestMain(m *testing.M) {
	keeperStandIn() // keeper_test.go: when the binary is re-run as jarvis2-machine
	d, _ := os.MkdirTemp("", "jarvis2-run")
	restoreTmp, predecessorTmp = filepath.Join(d, "restore.tar.gz"), filepath.Join(d, "predecessor.tar.gz")
	privPath = filepath.Join(d, "private.json")
	code := m.Run()
	os.RemoveAll(d)
	os.Exit(code)
}

type tentry struct {
	name, body, link string
	typ              byte
}

func tgz(t *testing.T, ents []tentry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: e.typ, Linkname: e.link, ModTime: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
		if e.typ == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if h.Typeflag == tar.TypeDir {
			h.Mode = 0o755
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(e.body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func shaHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

const tUUID = "0fa81372-5d1c-49af-b680-25a842f5df96"

// a fake router serving one import: the manifest at /m/restore-snapshot, its files at /m/import-file/<name>, and
// taking the wakeups and crons the machine arms
func importRouter(t *testing.T, key tkey, files map[string][]byte, order []string, tamper map[string][]byte) (*client, []byte, *[]string) {
	t.Helper()
	man := j1Manifest{Kind: "jarvis1-import", V: 1, Session: "j1abc"}
	for _, n := range order {
		man.Files = append(man.Files, j1File{Name: n, Sha256: shaHex(files[n]), Size: int64(len(files[n]))})
	}
	mb, _ := json.Marshal(man)
	var armed []string
	srv := fakeRouter(t, key, func(w http.ResponseWriter, req *http.Request, body []byte) {
		switch {
		case req.URL.Path == "/m/restore-snapshot":
			w.Write(mb)
		case strings.HasPrefix(req.URL.Path, "/m/import-file/"):
			n := strings.TrimPrefix(req.URL.Path, "/m/import-file/")
			if b, ok := tamper[n]; ok {
				w.Write(b)
				return
			}
			w.Write(files[n])
		case strings.HasPrefix(req.URL.Path, "/m/api/sessions/s1/"):
			armed = append(armed, req.URL.Path+" "+string(body))
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(404)
		}
	})
	t.Cleanup(srv.Close)
	return &client{base: srv.URL, me: "m1", sig: key.k, http: srv.Client()}, mb, &armed
}

func j1Files(t *testing.T, home string) (map[string][]byte, []string) {
	ws := tgz(t, []tentry{
		{name: "workspace/", typ: tar.TypeDir},
		{name: "workspace/claude-env/", typ: tar.TypeDir},
		{name: "workspace/claude-env/README.md", body: "readme"},
		{name: "workspace/claude-env/link", link: "README.md", typ: tar.TypeSymlink},
		{name: "workspace/claude-env/hard", link: "workspace/claude-env/README.md", typ: tar.TypeLink},
		{name: "workspace/escape", link: home + "/.ssh", typ: tar.TypeSymlink},
		{name: "workspace/escape/authorized_keys", body: "through a symlink"},
		{name: "../evil", body: "outside"},
		{name: ".bashrc", body: "outside the root"},
	})
	art := tgz(t, []tentry{{name: "artifacts/record.md", body: "# record"}})
	rec := `{"id":"j1abc","title":"T","metadata":{` +
		`"wake_default":"{\"name\":\"default\",\"at\":1000,\"prompt\":\"warm up\"}",` +
		`"cron_owcs-tix":"{\"name\":\"owcs-tix\",\"prompt\":\"check tickets\",\"every\":86400,\"tz\":\"Asia/Shanghai\",\"nextAt\":` + jsonInt(time.Now().Add(-2*time.Hour).UnixMilli()) + `,\"until\":` + jsonInt(time.Now().Add(30*24*time.Hour).UnixMilli()) + `}",` +
		`"watch_x":"{}"}}`
	files := map[string][]byte{
		"session.json":     []byte(rec),
		"manifest.txt":     []byte(tUUID + ".jsonl\n"),
		"claude.json":      []byte(`{"machineID":"m-old","oauthAccount":{"emailAddress":"x"},"userID":"u","projects":{"/home/claude/workspace/claude-env":{}}}`),
		tUUID + ".jsonl":   []byte(`{"type":"user","message":{"content":"hello"}}` + "\n"),
		"workspace.tar.gz": ws,
		"artifacts.tar.gz": art,
	}
	return files, []string{"session.json", "manifest.txt", "claude.json", tUUID + ".jsonl", "artifacts.tar.gz", "workspace.tar.gz"}
}

func jsonInt(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestJarvis1ImportRestoresWhatTheCertNames(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	key := newKey()
	files, order := j1Files(t, home)
	c, mb, armed := importRouter(t, key, files, order, nil)
	cert := v2(`{"v":1,"restore":{"machine":"j1abc","sha256":"`+shaHex(mb)+`"}}`, "")
	v, err := vouch(cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := restoreArchived(c, "", "m1", &cert, v); err != nil {
		t.Fatal(err)
	}
	read := func(rel string) string { b, _ := os.ReadFile(filepath.Join(home, rel)); return string(b) }
	if read("workspace/claude-env/README.md") != "readme" || read("artifacts/record.md") != "# record" {
		t.Fatal("tarballs not in place")
	}
	if l, _ := os.Readlink(filepath.Join(home, "workspace/claude-env/link")); l != "README.md" {
		t.Fatalf("symlink %q", l)
	}
	if read("workspace/claude-env/hard") != "readme" {
		t.Fatal("hard link")
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh/authorized_keys")); err == nil {
		t.Fatal("wrote through a symlink")
	}
	if _, err := os.Stat(filepath.Join(home, ".bashrc")); err == nil {
		t.Fatal("wrote outside the tarball's root")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(home), "evil")); err == nil {
		t.Fatal("wrote outside home")
	}
	var cj map[string]any
	json.Unmarshal([]byte(read(".claude.json")), &cj)
	if cj["machineID"] != "m-old" || cj["oauthAccount"] != nil || cj["userID"] != nil || cj["projects"] == nil {
		t.Fatalf("claude.json %v", cj)
	}
	// the transcripts wait for the repos, then go under the working dir's project
	placeImportedTranscripts()
	if read(".claude/projects/-"+strings.ReplaceAll(strings.Trim(home, "/"), "/", "-")+"-workspace-claude-env/"+tUUID+".jsonl") == "" {
		ents, _ := filepath.Glob(filepath.Join(home, ".claude/projects/*/*"))
		t.Fatalf("transcript not placed: %v", ents)
	}
	// the record's wakeup (long past) fires soon; the cron keeps its period and time of day; its missed run fires soon
	rearmJarvis1(c, "s1")
	if len(*armed) != 3 {
		t.Fatalf("armed %v", *armed)
	}
	all := strings.Join(*armed, "\n")
	if !strings.Contains(all, `/wakeups {"delaySeconds":300,"name":"default","prompt":"warm up"}`) ||
		!strings.Contains(all, `/crons {"at":`) || !strings.Contains(all, `"everySeconds":86400`) || !strings.Contains(all, `"tz":"Asia/Shanghai"`) ||
		!strings.Contains(all, `"name":"missed-owcs-tix"`) {
		t.Fatalf("armed %s", all)
	}
	note := read("artifacts/jarvis1-import/rearmed.txt")
	if !strings.Contains(note, "passed while paused") || !strings.Contains(note, "watch_x") || read("artifacts/jarvis1-import/session.json") == "" {
		t.Fatalf("rearmed.txt %s", note)
	}
	if _, err := os.Stat(filepath.Join(home, j1StageDir)); err == nil {
		t.Fatal("staging dir left")
	}
}

func TestJarvis1ImportRefusesOtherBytes(t *testing.T) {
	for _, n := range []string{"workspace.tar.gz", tUUID + ".jsonl", "claude.json"} {
		home := t.TempDir()
		t.Setenv("HOME", home)
		key := newKey()
		files, order := j1Files(t, home)
		other := map[string][]byte{n: append(append([]byte{}, files[n]...), 'x')}
		if n == "workspace.tar.gz" {
			other[n] = tgz(t, []tentry{{name: "workspace/claude-env/README.md", body: "swapped"}})
		}
		c, mb, _ := importRouter(t, key, files, order, other)
		cert := v2(`{"v":1,"restore":{"machine":"j1abc","sha256":"`+shaHex(mb)+`"}}`, "")
		v, _ := vouch(cert)
		if err := restoreArchived(c, "", "m1", &cert, v); err == nil || !strings.Contains(err.Error(), "not the bytes the cert names") {
			t.Fatalf("%s: %v", n, err)
		}
		if n == "workspace.tar.gz" {
			if _, err := os.Stat(filepath.Join(home, "workspace/claude-env/README.md")); err == nil {
				t.Fatal("swapped workspace moved into place")
			}
		}
	}
	// a manifest whose hash isn't the cert's: refused before anything is fetched
	home := t.TempDir()
	t.Setenv("HOME", home)
	key := newKey()
	files, order := j1Files(t, home)
	c, _, _ := importRouter(t, key, files, order, nil)
	cert := v2(`{"v":1,"restore":{"machine":"j1abc","sha256":"`+strings.Repeat("a", 64)+`"}}`, "")
	v, _ := vouch(cert)
	if err := restoreArchived(c, "", "m1", &cert, v); err == nil || !strings.Contains(err.Error(), "isn't the one the cert names") {
		t.Fatal(err)
	}
	// a manifest for another Jarvis 1 session than the cert names is not an import (and not a signed snapshot)
	c, mb, _ := importRouter(t, key, files, order, nil)
	cert = v2(`{"v":1,"restore":{"machine":"other","sha256":"`+shaHex(mb)+`"}}`, "")
	v, _ = vouch(cert)
	if err := restoreArchived(c, "", "m1", &cert, v); err == nil {
		t.Fatal("imported a manifest naming another session")
	}
}

func TestJ1FixURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://x-access-token:ghp_abc@github.com/DE0CH/claude-env.git": "https://github.com/DE0CH/claude-env.git",
		"https://github.com/de0ch/claude-env":                            "https://github.com/de0ch/claude-env.git",
		"https://github.com/DE0CH/YCC.git":                               "https://github.com/DE0CH/YCC.git",
		"git@github.com:DE0CH/x.git":                                     "git@github.com:DE0CH/x.git",
		"https://gitlab.com/a/b":                                         "https://gitlab.com/a/b",
	} {
		if got := j1FixURL(in); got != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
	if _, err := exec.LookPath("git"); err != nil {
		return
	}
	ws := t.TempDir()
	repo := filepath.Join(ws, "r")
	exec.Command("git", "init", "-q", repo).Run()
	exec.Command("git", "-C", repo, "remote", "add", "origin", "https://u:secret@github.com/DE0CH/r").Run()
	j1FixRemotes(ws)
	out, _ := exec.Command("git", "-C", repo, "remote", "get-url", "origin").Output()
	if strings.TrimSpace(string(out)) != "https://github.com/DE0CH/r.git" {
		t.Fatalf("remote %s", out)
	}
}

func TestJ1ScheduleKeepsFutureTimes(t *testing.T) {
	now := time.Date(2026, 10, 13, 2, 0, 0, 0, time.UTC)
	at := now.Add(3 * time.Hour).UnixMilli()
	next := now.Add(10 * time.Hour).UnixMilli()
	rec := `{"metadata":{"wake_a":"{\"name\":\"a\",\"at\":` + jsonInt(at) + `,\"prompt\":\"p\"}",` +
		`"cron_c":"{\"name\":\"c\",\"prompt\":\"q\",\"every\":86400,\"nextAt\":` + jsonInt(next) + `,\"until\":` + jsonInt(now.Add(-time.Hour).UnixMilli()) + `}",` +
		`"cron_d":"{\"name\":\"d\",\"prompt\":\"q\",\"every\":3600,\"nextAt\":` + jsonInt(next) + `}"}}`
	arms, notes := j1Schedule([]byte(rec), "s1", now)
	if len(arms) != 2 || arms[0].Body["name"] != "d" || arms[0].Body["at"] != next || arms[0].Body["until"] != nil || arms[1].Body["at"] != at {
		t.Fatalf("%+v", arms)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], `cron "c": ended`) {
		t.Fatalf("%v", notes)
	}
}

func TestASuccessorWithNoSnapshotImportsAgain(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	key := newKey()
	files, order := j1Files(t, home)
	c, mb, _ := importRouter(t, key, files, order, nil)
	cert := v2(`{"v":1,"restore":{"machine":"j1abc","sha256":"`+shaHex(mb)+`"}}`, "")
	cert.PredID = "m0"
	v, _ := vouch(cert)
	if err := reimportJarvis1(c, v); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(home, "workspace/claude-env/README.md")); string(b) != "readme" {
		t.Fatal("not imported again")
	}
	bad := v2(`{"v":1,"restore":{"machine":"j1abc","sha256":"`+strings.Repeat("c", 64)+`"}}`, "")
	bv, _ := vouch(bad)
	if err := reimportJarvis1(c, bv); err == nil {
		t.Fatal("took a manifest the cert doesn't name")
	}
}

// the import's staging dir and the volume-backed state dirs are different filesystems: a move copies across
func TestMoveAcrossFilesystems(t *testing.T) {
	other, err := os.MkdirTemp("/dev/shm", "j2move")
	if err != nil {
		t.Skip("no /dev/shm")
	}
	defer os.RemoveAll(other)
	src := filepath.Join(t.TempDir(), "d")
	os.MkdirAll(filepath.Join(src, "sub"), 0o755)
	os.WriteFile(filepath.Join(src, "sub", "f"), []byte("x"), 0o640)
	dst := filepath.Join(other, "d")
	if err := moveAcross(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "sub", "f")); err != nil || string(b) != "x" {
		t.Fatalf("%q %v", b, err)
	}
	if fi, _ := os.Stat(filepath.Join(dst, "sub", "f")); fi.Mode().Perm() != 0o640 {
		t.Fatal("mode not kept")
	}
	if _, err := os.Stat(src); err == nil {
		t.Fatal("the source stayed")
	}
}
