package main

// Per-repo deploy keys (docs/DESIGN.md "Deploy keys"). A repo's store (github-<repo>, made by the core when Deyao
// added the repo in Settings) holds two values: GITHUB_DEPLOY_REPO_<SLUG> = "owner/name" and
// GITHUB_DEPLOY_KEY_<SLUG> = the base64 of an OpenSSH private key that GitHub accepts for that one repo only
// (read + push). The private keys never touch the disk: the supervisor holds them in RAM in its own ssh-agent
// (sshAgentSock; part of its secrets component, secrets.go), and every signature it makes is logged with the caller.
// For every such pair in the session's secrets the supervisor sets up:
//
//   - the key in its ssh-agent, and its PUBLIC half in ~/.ssh/jarvis2-deploy/<owner>__<name>.pub;
//   - an SSH host alias github.com-jarvis2-<slug> → github.com with that key only (IdentityFile = the public half,
//     IdentitiesOnly, IdentityAgent = the supervisor's agent) and GitHub's published host keys pinned
//     (StrictHostKeyChecking, its own known_hosts file);
//   - git rewrites from https://github.com/<owner>/<name>.git and git@github.com:<owner>/<name>.git to the alias,
//     so clone, pull and push of that repo go over SSH with its key, with no setup in the session.
//
// Nothing else reaches the alias: other repos keep plain HTTPS (no credentials). The set is rewritten whole
// whenever the supervisor's secrets change (boot, refresh, add-store, downgrade), so a dropped store's key and
// rewrites go with it at once.

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	deployRepoPrefix = "GITHUB_DEPLOY_REPO_"
	deployKeyPrefix  = "GITHUB_DEPLOY_KEY_"
	deployKeyDir     = ".ssh/jarvis2-deploy"
	githubKnownHosts = ".ssh/jarvis2-github-known-hosts"
	sshConfigBegin   = "# >>> jarvis2 deploy keys (jarvis-machine rewrites this block)"
	sshConfigEnd     = "# <<< jarvis2 deploy keys"
	aliasPrefix      = "github.com-jarvis2-"
)

// GitHub's SSH host keys, as published at https://api.github.com/meta (ssh_keys)
var githubHostKeys = []string{
	"github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
	"github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
	"github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
}

type deployKey struct {
	Repo  string // owner/name, as the store says
	Alias string // the SSH host alias
	Key   []byte // the OpenSSH private key file
}

// deployKeys: the repo/key pairs in the secrets, sorted by repo
func deployKeys(secrets map[string]string) []deployKey {
	out := []deployKey{}
	for k, repo := range secrets {
		slug, ok := strings.CutPrefix(k, deployRepoPrefix)
		if !ok || slug == "" || !validRepo(repo) {
			continue
		}
		key, err := base64.StdEncoding.DecodeString(secrets[deployKeyPrefix+slug])
		if err != nil || !strings.HasPrefix(string(key), "-----BEGIN OPENSSH PRIVATE KEY-----") {
			log.Printf("deploy key for %s: missing or not an OpenSSH key; skipped", repo)
			continue
		}
		out = append(out, deployKey{Repo: repo, Alias: aliasPrefix + strings.ToLower(strings.ReplaceAll(slug, "_", "-")), Key: key})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repo < out[j].Repo })
	return out
}

func validRepo(repo string) bool {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || owner == "" || name == "" || name == "." || strings.Contains(name, "..") {
		return false
	}
	for _, r := range owner + name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// setupDeployKeys: write the keys, the SSH aliases and git's rewrites for exactly the repos in `secrets`
// (and remove any earlier ones)
func setupDeployKeys(secrets map[string]string) error {
	home, _ := os.UserHomeDir()
	keys := deployKeys(secrets)
	dir := filepath.Join(home, deployKeyDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	os.Chmod(filepath.Join(home, ".ssh"), 0o700)
	old, _ := os.ReadDir(dir)
	for _, e := range old {
		shredWrite(filepath.Join(dir, e.Name()), nil, 0o600) // a key file an earlier image wrote, too
		os.Remove(filepath.Join(dir, e.Name()))
	}
	deployAgent.RemoveAll()
	if err := os.WriteFile(filepath.Join(home, githubKnownHosts), []byte(strings.Join(githubHostKeys, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	var block strings.Builder
	block.WriteString(sshConfigBegin + "\n")
	for _, k := range keys {
		priv, err := ssh.ParseRawPrivateKey(k.Key)
		if err != nil {
			log.Printf("deploy key for %s: %v; skipped", k.Repo, err)
			continue
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			log.Printf("deploy key for %s: %v; skipped", k.Repo, err)
			continue
		}
		if err := deployAgent.Add(agent.AddedKey{PrivateKey: priv, Comment: k.Repo}); err != nil {
			return err
		}
		f := filepath.Join(dir, strings.ReplaceAll(k.Repo, "/", "__")+".pub")
		if err := os.WriteFile(f, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(&block, "Host %s\n  HostName github.com\n  User git\n  IdentityFile %s\n  IdentitiesOnly yes\n  IdentityAgent %s\n  UserKnownHostsFile %s\n  StrictHostKeyChecking yes\n",
			k.Alias, f, sshAgentSock, filepath.Join(home, githubKnownHosts))
	}
	block.WriteString(sshConfigEnd + "\n")
	if err := writeSSHConfig(filepath.Join(home, ".ssh", "config"), block.String()); err != nil {
		return err
	}
	// git: drop the earlier rewrites, then one per repo URL form (exact `.git` URLs: a rewrite is a prefix match,
	// so a URL without `.git` would also catch <name>-something)
	if out, err := sessionCommand(nil, "git", "config", "--global", "--name-only", "--get-regexp", `^url\.git@`+strings.ReplaceAll(aliasPrefix, ".", `\.`)).Output(); err == nil {
		seen := map[string]bool{}
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			sec := strings.TrimSuffix(l, ".insteadof")
			if l != "" && !seen[sec] {
				seen[sec] = true
				sessionCommand(nil, "git", "config", "--global", "--remove-section", sec).Run()
			}
		}
	}
	for _, k := range keys {
		to := "url.git@" + k.Alias + ":" + k.Repo + ".git.insteadOf"
		forms := map[string]bool{}
		for _, r := range []string{k.Repo, strings.ToLower(k.Repo)} {
			forms["https://github.com/"+r+".git"] = true
			forms["git@github.com:"+r+".git"] = true
			forms["ssh://git@github.com/"+r+".git"] = true
		}
		for f := range forms {
			if err := sessionCommand(nil, "git", "config", "--global", "--add", to, f).Run(); err != nil {
				return fmt.Errorf("git config: %w", err)
			}
		}
	}
	if len(keys) > 0 {
		names := []string{}
		for _, k := range keys {
			names = append(names, k.Repo)
		}
		log.Printf("deploy keys: %s (SSH, GitHub's host keys pinned)", strings.Join(names, ", "))
	}
	return nil
}

// writeSSHConfig: our block first (ssh takes the first value it finds), the rest of the file as it was
func writeSSHConfig(path, block string) error {
	b, _ := os.ReadFile(path)
	rest := string(b)
	if i := strings.Index(rest, sshConfigBegin); i >= 0 {
		if j := strings.Index(rest[i:], sshConfigEnd); j >= 0 {
			rest = rest[:i] + strings.TrimPrefix(rest[i+j+len(sshConfigEnd):], "\n")
		}
	}
	return os.WriteFile(path, []byte(block+rest), 0o600)
}

// cloneURL: a GitHub repo as https://github.com/<owner>/<name>.git (the form git's rewrites match); others as given
func cloneURL(u string) string {
	u = strings.TrimSpace(u)
	for _, p := range []string{"https://github.com/", "git@github.com:"} {
		if rest, ok := strings.CutPrefix(u, p); ok {
			return "https://github.com/" + strings.TrimSuffix(strings.TrimSuffix(rest, "/"), ".git") + ".git"
		}
	}
	return u
}

// ---- the supervisor's ssh-agent ------------------------------------------------------------------------------

var (
	sshAgentSock = dir + "/ssh-agent.sock"
	deployAgent  = agent.NewKeyring().(agent.ExtendedAgent)
)

// loggedAgent: the keyring, with every signature logged (the key's repo and the caller, never the key)
type loggedAgent struct {
	agent.ExtendedAgent
	caller string
}

func (a loggedAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a loggedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	repo := "?"
	if ks, err := a.ExtendedAgent.List(); err == nil {
		for _, k := range ks {
			if string(k.Marshal()) == string(key.Marshal()) {
				repo = k.Comment
			}
		}
	}
	sig, err := a.ExtendedAgent.SignWithFlags(key, data, flags)
	log.Printf("ssh-agent: signed with the deploy key of %s for %s%s", repo, a.caller, map[bool]string{true: " (refused)", false: ""}[err != nil])
	return sig, err
}

// the agent accepts no key from outside: only the supervisor's own secrets put keys in it
func (a loggedAgent) Add(agent.AddedKey) error   { return errReadOnlyAgent }
func (a loggedAgent) Remove(ssh.PublicKey) error { return errReadOnlyAgent }
func (a loggedAgent) RemoveAll() error           { return errReadOnlyAgent }
func (a loggedAgent) Lock([]byte) error          { return errReadOnlyAgent }
func (a loggedAgent) Unlock([]byte) error        { return errReadOnlyAgent }
func (a loggedAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

var errReadOnlyAgent = fmt.Errorf("the supervisor's ssh-agent takes no changes")

// serveSSHAgent: the agent's socket (0600, user claude; started by supervise)
func serveSSHAgent() {
	os.Remove(sshAgentSock)
	ln, err := net.Listen("unix", sshAgentSock)
	if err != nil {
		log.Printf("ssh-agent: %v", err)
		return
	}
	os.Chmod(sshAgentSock, 0o600)
	for {
		conn, err := ln.Accept()
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		go func() {
			defer conn.Close()
			pid, uid, comm := peerOf(conn)
			if !sessionPeer(uid) {
				log.Printf("ssh-agent: refused a caller of uid %d (pid %d %s)", uid, pid, comm)
				return
			}
			agent.ServeAgent(loggedAgent{deployAgent, fmt.Sprintf("pid %d %s", pid, comm)}, conn)
		}()
	}
}
