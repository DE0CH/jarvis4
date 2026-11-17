package main

import (
	"encoding/base64"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

func testKey(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("no ssh-keygen")
	}
	f := filepath.Join(t.TempDir(), "k")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", f).CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	b, _ := os.ReadFile(f)
	return base64.StdEncoding.EncodeToString(b)
}

func getURL(t *testing.T, u string) string {
	t.Helper()
	out, err := exec.Command("git", "ls-remote", "--get-url", u).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestDeployKeysGiveEachRepoItsOwnKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte("Host other\n  HostName example.com\n"), 0o600)
	a, b := testKey(t), testKey(t)
	secrets := map[string]string{
		"GITHUB_DEPLOY_REPO_DE0CH_CLAUDE_ENV": "DE0CH/claude-env", "GITHUB_DEPLOY_KEY_DE0CH_CLAUDE_ENV": a,
		"GITHUB_DEPLOY_REPO_DE0CH_JARVIS2": "DE0CH/jarvis2", "GITHUB_DEPLOY_KEY_DE0CH_JARVIS2": b,
		"GITHUB_DEPLOY_REPO_DE0CH_BROKEN": "DE0CH/broken", // no key: skipped
		"GITHUB_DEPLOY_REPO_EVIL":         "../../x", "GITHUB_DEPLOY_KEY_EVIL": a,
		"OTHER": "x",
	}
	if err := setupDeployKeys(secrets); err != nil {
		t.Fatal(err)
	}
	// the keys, one per repo, in the supervisor's agent; on disk only their public halves
	for _, n := range []string{"DE0CH__claude-env", "DE0CH__jarvis2"} {
		b, err := os.ReadFile(filepath.Join(home, deployKeyDir, n+".pub"))
		if err != nil || !strings.HasPrefix(string(b), "ssh-ed25519 ") {
			t.Fatalf("%s: %v %q", n, err, b)
		}
	}
	if es, _ := os.ReadDir(filepath.Join(home, deployKeyDir)); len(es) != 2 {
		t.Fatalf("%d key files", len(es))
	}
	if out, _ := exec.Command("grep", "-rl", "PRIVATE KEY", home).Output(); len(out) > 0 {
		t.Fatalf("a private key on disk: %s", out)
	}
	if ks, _ := deployAgent.List(); len(ks) != 2 {
		t.Fatalf("%d keys in the agent", len(ks))
	}
	// git sends exactly these repos to their own alias; anything else stays as it was
	for in, want := range map[string]string{
		"https://github.com/DE0CH/claude-env.git":   "git@github.com-jarvis2-de0ch-claude-env:DE0CH/claude-env.git",
		"git@github.com:DE0CH/claude-env.git":       "git@github.com-jarvis2-de0ch-claude-env:DE0CH/claude-env.git",
		"https://github.com/de0ch/jarvis2.git":      "git@github.com-jarvis2-de0ch-jarvis2:DE0CH/jarvis2.git",
		"https://github.com/DE0CH/jarvis2.git":      "git@github.com-jarvis2-de0ch-jarvis2:DE0CH/jarvis2.git",
		"https://github.com/DE0CH/claude-env-x.git": "https://github.com/DE0CH/claude-env-x.git",
		"https://github.com/DE0CH/broken.git":       "https://github.com/DE0CH/broken.git",
		"https://github.com/someone/else.git":       "https://github.com/someone/else.git",
	} {
		if got := getURL(t, in); got != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
	// ssh: the alias reaches github.com with that key only and GitHub's host keys pinned; our block comes first
	cfg, _ := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if !strings.HasPrefix(string(cfg), sshConfigBegin) || !strings.Contains(string(cfg), "Host other\n") {
		t.Fatalf("ssh config:\n%s", cfg)
	}
	// the files by ~/ (the user's own home, whatever its path), never the machine's absolute home: the aviary sandbox
	// sees this home as another user's /home/sandbox
	for _, want := range []string{"IdentityFile ~/" + deployKeyDir + "/DE0CH__jarvis2.pub\n", "UserKnownHostsFile ~/" + githubKnownHosts + "\n"} {
		if !strings.Contains(string(cfg), want) {
			t.Errorf("ssh config lacks %q:\n%s", want, cfg)
		}
	}
	if strings.Contains(string(cfg), home) {
		t.Errorf("ssh config names the absolute home %s:\n%s", home, cfg)
	}
	if _, err := exec.LookPath("ssh"); err == nil {
		out, err := exec.Command("ssh", "-F", filepath.Join(home, ".ssh", "config"), "-G", "github.com-jarvis2-de0ch-jarvis2").Output()
		if err != nil {
			t.Fatal(err)
		}
		g := string(out)
		for _, want := range []string{"hostname github.com\n", "user git\n", "identitiesonly yes\n", "stricthostkeychecking true\n",
			"identityagent " + sshAgentSock + "\n", "/" + githubKnownHosts + "\n"} {
			if !strings.Contains(g, want) {
				t.Errorf("ssh -G lacks %q", want)
			}
		}
	}
	kh, _ := os.ReadFile(filepath.Join(home, githubKnownHosts))
	if strings.Count(string(kh), "github.com ") != 3 {
		t.Fatal("GitHub's host keys aren't pinned")
	}

	// a downgrade to one repo: the other's key and rewrite go; the rest of the ssh config stays
	delete(secrets, "GITHUB_DEPLOY_REPO_DE0CH_JARVIS2")
	if err := setupDeployKeys(secrets); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, deployKeyDir, "DE0CH__jarvis2.pub")); err == nil {
		t.Fatal("the dropped repo's key stayed")
	}
	if ks, _ := deployAgent.List(); len(ks) != 1 || ks[0].Comment != "DE0CH/claude-env" {
		t.Fatalf("the agent after the downgrade: %v", ks)
	}
	if got := getURL(t, "https://github.com/DE0CH/jarvis2.git"); got != "https://github.com/DE0CH/jarvis2.git" {
		t.Fatal("the dropped repo's rewrite stayed:", got)
	}
	cfg, _ = os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if strings.Count(string(cfg), sshConfigBegin) != 1 || strings.Contains(string(cfg), "jarvis2-de0ch-jarvis2") || !strings.Contains(string(cfg), "Host other\n") {
		t.Fatalf("ssh config after:\n%s", cfg)
	}
}

func TestCloneURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/DE0CH/x":     "https://github.com/DE0CH/x.git",
		"https://github.com/DE0CH/x.git": "https://github.com/DE0CH/x.git",
		"git@github.com:DE0CH/x.git":     "https://github.com/DE0CH/x.git",
		" https://gitlab.com/a/b.git ":   "https://gitlab.com/a/b.git",
	} {
		if got := cloneURL(in); got != want {
			t.Errorf("%q → %q", in, got)
		}
	}
}

// the supervisor's agent signs with the deploy keys it holds and takes no key from outside
func TestTheSupervisorsSSHAgent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	old := sshAgentSock
	defer func() { sshAgentSock = old }()
	sshAgentSock = filepath.Join(t.TempDir(), "a.sock")
	if err := setupDeployKeys(map[string]string{"GITHUB_DEPLOY_REPO_X": "DE0CH/x", "GITHUB_DEPLOY_KEY_X": testKey(t)}); err != nil {
		t.Fatal(err)
	}
	go serveSSHAgent()
	var conn net.Conn
	var err error
	for i := 0; i < 100; i++ {
		if conn, err = net.Dial("unix", sshAgentSock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ac := agent.NewClient(conn)
	ks, err := ac.List()
	if err != nil || len(ks) != 1 {
		t.Fatalf("%v %v", ks, err)
	}
	if _, err := ac.Sign(ks[0], []byte("data")); err != nil {
		t.Fatal(err)
	}
	if ac.RemoveAll() == nil {
		t.Fatal("the agent took a change from a caller")
	}
	if ks, _ := deployAgent.List(); len(ks) != 1 {
		t.Fatal("a caller removed a key")
	}
}
