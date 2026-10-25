// jarvis-machine: the session machine's side of Jarvis 4 (docs/DESIGN.md,
// "Machine side"). It is the image's entry point and its fixed init entry point:
//
//	jarvis-machine boot       ENTRYPOINT, as root: the keeper (keeper.go), Fly's main child for the machine's
//	                           whole life. It starts the boot steps (prepare), supervisor-core and
//	                           supervisor-normal and then the harness, each as its own child, restarts them when
//	                           they die, and turns Fly's stop signal into the priority teardown.
//	jarvis-machine prepare    the boot steps, as user claude (started by the keeper): make the machine's key
//	                           pairs, wait for init, then check the succession cert, restore the predecessor's
//	                           snapshot, have the supervisor pull the secrets, clone the repos and hand the
//	                           harness's env (no secret value) to the keeper. Any failed check → start nothing.
//	jarvis-machine init       what the core runs through Fly exec (no arguments): asks boot to go on.
//	jarvis-machine supervisor --core|--normal
//	                           started by the keeper once init asked: the machine's long-running processes that
//	                           talk to the router (supervisor.go). --core keeps the control plane alive, with the
//	                           guard (guard.go) in front of the commands that need it; --normal the reports and
//	                           watches. Root, with user claude's file access (keeper.go).
//	jarvis-machine stores [--json]
//	                           every store and the key NAMES it holds (never a value), to know which store to
//	                           ask for (stores.go).
//	jarvis-machine add-store <name>
//	                           asks Deyao to add one store to this session; on approval the supervisor
//	                           pulls the secrets again (RAM only).
//
// It trusts only what it can check: the core's public key arrives through Fly exec (written by the core at
// start), the cert and the secrets are core-signed, and the predecessor's snapshot is signed by the
// predecessor's own key, taken from the predecessor's core-signed cert. The router only relays.
package main

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	dir         = "/run/jarvis"
	keysPath    = dir + "/keys.json" // public halves, printed by init for the core (through Fly exec)
	coreKeyPath = dir + "/core-key"  // the core's key, from the machine's Fly config (the core set it)
	coreKeyEnv  = "JARVIS2_CORE_KEY" // the core that created this machine puts its signing key here
	goPath      = dir + "/init-requested"
	certPath    = dir + "/cert.json"
	bootedPath  = dir + "/booted"      // written once the boot is done (cert, snapshot, secrets, repos): the harness starts next
	clientPath  = dir + "/client.json" // the router URL + this machine's id, for later commands
)

// privPath: the private halves, never leave the machine (a var: tests point it away from a host that is itself a
// session machine, whose real key the client would otherwise sign with)
var privPath = dir + "/private.json"

var baseEntry = "/usr/local/bin/entrypoint.sh" // Jarvis 1's entrypoint: the harness (a var: the keeper's tests)

var b64 = base64.StdEncoding

type SignedDoc struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

type Machine struct {
	ID            string `json:"id"`
	Image         string `json:"image"`
	EncryptionKey string `json:"encryptionKey"`
	SigningKey    string `json:"signingKey"`
}

type Cert struct {
	Kind    string   `json:"kind"`
	PredID  string   `json:"predecessorId"`
	Machine *Machine `json:"machine"`
	Stores  []string `json:"stores"`
	Options struct {
		Harness        string `json:"harness"`
		PermissionMode string `json:"permissionMode"`
		Config         string `json:"config"` // the session's settings (vouch.go)
		Once           string `json:"once"`   // this machine's one-time inputs
	} `json:"options"`
	Phone     string `json:"phone"`
	Sensitive bool   `json:"sensitive"`
	Line      string `json:"line"`
	Snapshot  string `json:"snapshot"` // sha256 of the predecessor's snapshot, from the core's kill record
}

type private struct {
	Enc string `json:"enc"`
	Sig string `json:"sig"`
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("[jarvis] ")
	if len(os.Args) < 2 {
		log.Fatal("usage: jarvis-machine boot | init | stores [--json] | put-key <store> <key> [--explain <text>] < value | delete-key <store> <key> | add-store <name> | await-store <name> | downgrade --keep <store>… | --drop <store>… | --none | allow [<holder> <duration> | --remove <holder>] | supervisor")
	}
	var err error
	switch os.Args[1] {
	case "boot":
		err = keeper() // keeper.go
	case "prepare": // keeper.go starts it, as user claude
		err = prepareCmd()
	case "init":
		err = initCmd()
	case "add-store":
		if len(os.Args) != 3 {
			log.Fatal("usage: jarvis-machine add-store <name>")
		}
		err = addStore(os.Args[2])
	case "await-store": // after `jarvis-request add-store`: no second ask, only the wait and the pull
		if len(os.Args) != 3 {
			log.Fatal("usage: jarvis-machine await-store <name>")
		}
		err = awaitStore(os.Args[2])
	case "stores":
		err = storesCmd(os.Args[2:]) // stores.go
	case "put-key":
		err = putKeyCmd(os.Args[2:], false) // putkey.go
	case "delete-key":
		err = putKeyCmd(os.Args[2:], true)
	case "downgrade":
		var sp downgradeSpec
		if sp, err = downgradeArgs(os.Args[2:]); err == nil {
			err = downgrade(sp)
		}
	case "supervisor": // supervisor.go: supervisor-core and supervisor-normal, started (and restarted) by the keeper
		switch {
		case len(os.Args) == 3 && os.Args[2] == "--core":
			err = superviseCore()
		case len(os.Args) == 3 && os.Args[2] == "--normal":
			err = superviseNormal()
		default:
			log.Fatal("usage: jarvis-machine supervisor --core|--normal (the keeper starts them)")
		}
	case "unprotected": // keeper.go: a command for the session: back under the OOM killer, as user claude, then exec
		err = unprotected(os.Args[2:])
	case "signal-session": // keeper.go: a signal to every process of user claude (kill -1 as claude)
		err = signalSessionCmd(os.Args[2:])
	case "workers-hook":
		workersHook() // workers.go: a Claude Code hook; never fails
		return
	case "allow":
		err = allowCmd(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %s", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

// ---- boot -----------------------------------------------------------------------------------------

// prepareCmd: the boot steps, as user claude, a child of the keeper (which already threw away the env this machine
// was started with, keeping what the image, Fly and the core set: vouch.go). On success the harness's env (no secret
// value) goes to the keeper on fd 3 and this process ends; the keeper starts the harness.
func prepareCmd() error {
	if err := keygen(); err != nil {
		return fmt.Errorf("keygen: %w", err)
	}
	logToSupervisorLog() // supervisorlog.go: boot's lines are the first of the supervisor log
	log.Printf("keys ready; waiting for init")
	for {
		if _, err := os.Stat(goPath); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	spec, err := prepare()
	if err != nil {
		// any failed check → start nothing; the keeper keeps the machine (and the supervisor) up, so the failure stays
		// visible in its log. Not a select{}: with no other goroutine Go ends it as a deadlock, a stack dump in the log
		return fmt.Errorf("REFUSING TO START: %v", err)
	}
	out := os.NewFile(3, "harness-spec") // keeper.go startPrepare
	if out == nil {
		return errors.New("no fd 3 from the keeper")
	}
	defer out.Close()
	return json.NewEncoder(out).Encode(spec)
}

// initCmd: the one command the core runs through Fly (no arguments). It prints this machine's public keys
// (the core binds them into the cert) and lets boot go on.
func initCmd() error {
	var b []byte
	var err error
	for i := 0; i < 60; i++ { // boot makes the keys first
		if b, err = os.ReadFile(keysPath); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return fmt.Errorf("no keys yet: %w", err)
	}
	if err := os.WriteFile(goPath, []byte(time.Now().UTC().Format(time.RFC3339)), 0o644); err != nil {
		return err
	}
	_, err = os.Stdout.Write(b)
	return err
}

func keygen() error {
	if err := sudo("install", "-d", "-o", "claude", "-m", "755", dir); err != nil {
		return err
	}
	enc, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	sig, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	p, _ := json.Marshal(private{b64.EncodeToString(enc.Bytes()), b64.EncodeToString(sig.Bytes())})
	if err := os.WriteFile(privPath, p, 0o600); err != nil {
		return err
	}
	pub, _ := json.Marshal(map[string]string{"encryptionKey": b64.EncodeToString(enc.PublicKey().Bytes()), "signingKey": b64.EncodeToString(sig.PublicKey().Bytes())})
	return os.WriteFile(keysPath, pub, 0o644)
}

func sudo(args ...string) error {
	if os.Geteuid() == 0 {
		return exec.Command(args[0], args[1:]...).Run()
	}
	return exec.Command("sudo", append([]string{"-n"}, args...)...).Run()
}

func prepare() (spec harnessSpec, err error) {
	me := os.Getenv("FLY_MACHINE_ID")
	// the core: the one that created this machine. It sets its signing key in the machine's Fly config, and only
	// the core's Fly token (besides the setup session's org token) can create or change machines in this app —
	// the router's is read-only — so the key comes from the core through Fly, never from the router.
	coreKey := strings.TrimSpace(os.Getenv(coreKeyEnv))
	kernel := strings.TrimSpace(os.Getenv(kernelRootEnv)) != "" // kernelboot.go: the kernel's spawner started it
	if coreKey == "" && !kernel {
		return spec, errors.New("no core key in the machine's config (" + coreKeyEnv + ")")
	}
	keys, err := ownKeys()
	if err != nil {
		return spec, err
	}
	c, err := newClient()
	if err != nil {
		return spec, err
	}
	// 0. supervisor-core is the keeper's (keeper.go), up since init asked: it answers the router's commands at
	// every stage of this machine's life, so a pause or destroy never waits on a machine still booting (e.g. looping
	// on a locked store): until bootedPath exists a snapshot command gets "nothing to snapshot"
	os.Remove(bootedPath)

	// 1. this machine's succession cert: core-signed, naming this machine and its own keys (a kernel machine: its
	// kernel documents, kernelboot.go)
	var cert Cert
	var certs struct {
		Cert            *SignedDoc `json:"cert"`
		PredecessorCert *SignedDoc `json:"predecessorCert"`
	}
	if kernel {
		if cert, err = kernelBootCert(c, me, keys); err != nil {
			return spec, err
		}
	} else {
		for i := 0; ; i++ {
			err = c.json("GET", "/m/cert", nil, &certs)
			if err == nil && certs.Cert != nil {
				break
			}
			if i > 300 {
				return spec, fmt.Errorf("no cert: %v", err)
			}
			time.Sleep(2 * time.Second)
		}
		if err := os.WriteFile(coreKeyPath, []byte(coreKey), 0o644); err != nil {
			return spec, err
		}
		if err := verifyDoc(coreKey, certs.Cert, &cert); err != nil || cert.Kind != "succession-cert" || cert.Machine == nil {
			return spec, fmt.Errorf("the cert isn't a succession cert signed by the core (%v)", err)
		}
		if cert.Machine.ID != me || cert.Machine.EncryptionKey != keys["encryptionKey"] || cert.Machine.SigningKey != keys["signingKey"] {
			return spec, errors.New("the cert names another machine or other keys")
		}
		raw, _ := json.Marshal(certs.Cert)
		os.WriteFile(certPath, raw, 0o644)
	}
	log.Printf("cert ok: stores %v, harness %s, predecessor %q", cert.Stores, cert.Options.Harness, cert.PredID)

	v, err := vouch(cert) // vouch.go: what the cert vouches for
	if err != nil {
		return spec, err
	}
	v.Ex = fetchExceptions(c) // the few router values whose format can't carry an instruction
	writeVouched(v)
	firstMachine := cert.PredID == ""

	// 1b. the volume (volume.go): the state's directories onto it, before anything is restored there
	setupVolume()

	// 2. the predecessor's snapshot: the one whose hash the cert names, signed by the predecessor
	if kernel && cert.Snapshot != "" {
		if err := kernelRestore(c, cert.Snapshot); err != nil {
			return spec, fmt.Errorf("snapshot: %w", err)
		}
		restoredArchive = firstMachine // a new line restoring an archive: its line keys come with it (deliver.go)
	} else if kernel {
		if !firstMachine {
			log.Printf("the source names no snapshot of %s: starting with no predecessor state", cert.PredID)
		}
	} else if !firstMachine && cert.PredID != me {
		var pc Cert
		if err := verifyDoc(coreKey, certs.PredecessorCert, &pc); err != nil || pc.Kind != "succession-cert" || pc.Machine == nil || pc.Machine.ID != cert.PredID {
			return spec, fmt.Errorf("the predecessor's cert isn't core-signed for %s (%v)", cert.PredID, err)
		}
		if cert.Snapshot != "" {
			predecessorKey = pc.Machine.SigningKey
			if err := restore(c, pc.Machine.SigningKey, v); err != nil {
				return spec, fmt.Errorf("snapshot: %w", err)
			}
		} else if v.Config.Restore != nil {
			// a line whose machines never left a snapshot (an import stopped mid-way): the import its signed config
			// names again, Jarvis 1 imports only (restore.go reimportJarvis1)
			predecessorKey = pc.Machine.SigningKey
			if err := reimportJarvis1(c, v); err != nil {
				return spec, fmt.Errorf("re-import: %w", err)
			}
		} else {
			log.Printf("the cert names no snapshot of %s: starting with no predecessor state", cert.PredID)
		}
		if v.Once.Rollback != "" { // rollback.go: only a rollback the phone approved, on the verified snapshot
			applyRollback(v.Once.Rollback)
		}
	}
	// 2b. a new line restoring a destroyed session's archived snapshot (restore.go): only the one the cert names
	// (a kernel line's source names its archived snapshot by hash, restored above: the phone signed it)
	if !kernel {
		if err := restoreArchived(c, coreKey, me, &cert, v); err != nil {
			return spec, fmt.Errorf("restore: %w", err)
		}
	}
	trustLineKeys(cert) // deliver.go: this line's signing keys, for what it asked to be delivered later

	// 3. the secrets, sealed to this machine's encryption key: the supervisor pulls them and holds them in RAM
	// (secrets.go); boot takes them from it for the harness's env. A store still locked after the wait doesn't stop
	// the start: the session runs with none of its secrets (the lower-privilege state; the core seals all or nothing)
	// and gets them when Deyao's unlock goes through (the router's refresh-secrets)
	secrets := map[string]string{}
	if _, err := askSecrets(secretsReq{Op: "pull"}, 20*time.Minute); errors.Is(err, errStoresLocked) {
		log.Printf("%v: starting without secrets; the supervisor takes them once the store is unlocked (Unlock… in the app, or `jarvis-request unlock`)", err)
	} else if err != nil {
		return spec, err
	} else {
		awaitHarnessPID(10 * time.Second)                             // keeper.go: the keeper names this process first
		r, err := askSecrets(secretsReq{Op: "boot-env"}, time.Minute) // the repos and a task's env (the harness gets its own from the keeper)
		if err != nil {
			return spec, err
		}
		for k, v := range r.Secrets { // (an empty answer carries no map)
			secrets[k] = v
		}
	}
	log.Printf("secrets ok: %d keys (held by the supervisor, in RAM)", len(secrets))

	// 4. repos: each repo's deploy key is in the supervisor's ssh-agent (deploykeys.go), then the clones the cert names
	cloneRepos(reposToClone(v, secrets))
	placeImportedTranscripts()     // jarvis1import.go: an import's transcripts, under the working dir's project
	rearmJarvis1(c, sessionID(me)) // jarvis1import.go: its wakeups and crons, as this line's own requests

	// 5. booted: from now on a snapshot command gets a real snapshot; then the keeper runs Jarvis 1's entrypoint (the harness) —
	// unless a pause already took the predecessor's snapshot as this machine's (snapstream.go): it goes no further
	holdIfCarried()
	if err := os.WriteFile(bootedPath, []byte(time.Now().UTC().Format(time.RFC3339)), 0o644); err != nil {
		return spec, fmt.Errorf("booted marker: %w", err)
	}
	clean := os.Environ() // already the clean env (ensureCleanEnv)
	if t, ok := strings.CutPrefix(cert.Options.Harness, taskHarnessPrefix); ok {
		for _, kv := range taskVouchedEnv(v) { // task.go reads these from the process env
			k, val, _ := strings.Cut(kv, "=")
			os.Setenv(k, val)
		}
		runTask(c, t, secrets, cert.Stores, certMode(cert)) // task.go: the template instead of a harness; never returns
	}
	// 6. the harness's env, without the secrets: the keeper adds the ones the supervisor holds at each start
	spec = harnessSpec{Clean: clean, Fixed: harnessFixed(v, me, firstMachine), Fallback: map[string]string{}}
	// the Claude login (claudelogin.go): the pair of the session's Claude account, kept in step
	if account := sessionClaudeLogin(c); account != "" {
		spec.Fallback["CLAUDE_ACCOUNT"] = account // Jarvis 1's entrypoint merges it into ~/.claude.json (a store's own wins)
	}
	if !firstMachine && v.Once.Prompt != "" {
		home, _ := os.UserHomeDir()
		os.Remove(filepath.Join(home, ".claude", ".first-prompt-sent")) // the supervisor types the approved resume prompt
	}
	if firstMachine && len(v.Config.Attachments) > 0 {
		for _, kv := range fetchAttachments(c, coreKey, v.Config.Attachments) { // attachments.go: hash-checked against the cert
			if k, val, ok := strings.Cut(kv, "="); ok {
				spec.Fixed[k] = val
			}
		}
	}
	if runsClaudeCode(cert.Options.Harness) { // harnesses.go
		if home, err := os.UserHomeDir(); err == nil {
			if err := installWorkerHooks(home); err != nil { // workers.go: the subagent/background-job count
				log.Printf("workers hooks: %v", err)
			}
		}
	}
	waitAPIProxy(15 * time.Second) // the entrypoint's first calls ($JARVIS_URL: content-sync pull) need it up
	log.Printf("booted: the keeper starts the harness")
	return spec, nil
}

// waitAPIProxy: the supervisor starts the local Jarvis API once bootedPath exists (polled every second); the
// harness's entrypoint calls it at once (content-sync pull), so wait until it accepts connections (at most d)
func waitAPIProxy(d time.Duration) {
	addr := os.Getenv("JARVIS_API_ADDR")
	if addr == "" {
		addr = apiProxyAddr
	}
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			conn.Close()
			return
		}
	}
	log.Printf("the local Jarvis API on %s isn't up after %s: starting the harness anyway", addr, d)
}

func ownKeys() (map[string]string, error) {
	b, err := os.ReadFile(keysPath)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	return m, json.Unmarshal(b, &m)
}

func readTrim(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("%s is empty", p)
	}
	return s, nil
}

// pullTries × pullWait: how long a pull waits on a locked store before the machine starts without its secrets
var pullTries, pullWait = 300, 2 * time.Second

// errStoresLocked: a store of the cert is still locked after the wait (the core's 423)
var errStoresLocked = errors.New("a store this session's cert names is still locked")

// pullSecrets: the core seals the answer to this machine's encryption key, so it needs no other proof
func pullSecrets(c *client, coreKey, me string) (map[string]string, error) {
	var doc SignedDoc
	var lastErr error
	// a store may still be locked: the app shows which (the router notes the core's 423) and Deyao unlocks it on the
	// phone; the pull is retried every 2 s for 10 minutes, so the machine carries on within seconds of the unlock
	for i := 0; i < pullTries; i++ {
		if lastErr = c.json("POST", "/m/pull-secrets", map[string]string{}, &doc); lastErr == nil {
			break
		}
		if i%30 == 0 {
			log.Printf("pull secrets: %v (retrying)", lastErr)
		}
		time.Sleep(pullWait)
	}
	if lastErr != nil {
		if strings.Contains(lastErr.Error(), "HTTP 423") {
			return nil, fmt.Errorf("pull secrets: %w (%v)", errStoresLocked, lastErr)
		}
		return nil, fmt.Errorf("pull secrets: %w", lastErr)
	}
	var out struct {
		Kind    string `json:"kind"`
		Machine string `json:"machine"`
		Sealed  struct {
			E    string `json:"e"`
			Data string `json:"data"`
		} `json:"sealed"`
	}
	key, want := coreKey, me
	if t, ok := readKernelTrust(); ok { // kernelboot.go: signed by the kernel's secrets, for this machine's object
		key, want = t.Secrets, t.Machine
	}
	if err := verifyDoc(key, &doc, &out); err != nil || out.Kind != "secrets" || out.Machine != want {
		return nil, fmt.Errorf("the secrets answer isn't signed for this machine (%v)", err)
	}
	priv, err := loadPrivate()
	if err != nil {
		return nil, err
	}
	plain, err := openSealed(priv.enc, out.Sealed.E, out.Sealed.Data, "jarvis2/secrets")
	if err != nil {
		return nil, fmt.Errorf("the secrets don't decrypt with this machine's key: %w", err)
	}
	m := map[string]string{}
	return m, json.Unmarshal(plain, &m)
}

// cloneRepos: the repos the cert names (reposToClone) into ~/workspace. A repo whose deploy key is in the session's
// stores goes over SSH with that key (setupDeployKeys has already written git's rewrites for its https URL); any
// other is cloned anonymously over HTTPS from GitHub (public repos only).
func cloneRepos(repos []string) {
	home, _ := os.UserHomeDir()
	for _, url := range repos {
		url = cloneURL(url)
		if url == "" {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(url), ".git")
		dst := filepath.Join(home, "workspace", name)
		if _, err := os.Stat(filepath.Join(dst, ".git")); err == nil {
			continue // restored from the snapshot
		}
		cmd := sessionCommand(nil, "git", "clone", "-q", "--", url, dst)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("clone %s failed: %s", name, strings.TrimSpace(string(out)))
			continue
		}
		log.Printf("cloned %s", name)
	}
}

// ---- snapshots ------------------------------------------------------------------------------------

// what a snapshot holds (relative to $HOME): the conversation, the work, the artefacts, and the OpenCode/Paseo and
// OpenClaw harnesses' own state (Paseo's daemon identity and pairings, OpenCode's sessions, the OpenClaw gateway's
// state and device pairings; the CloudCLI harness's chat pictures in ~/.claude/cloudcli-assets), so their apps stay
// paired across a pause, as in Jarvis 1 (its lib/archive.js)
//
// In the order of what matters most (Deyao, 2026-10-21: the teardown uploads the most important first): the
// conversations and ~/.claude.json, the small records, the other harnesses' state, then the workspace and the
// artifacts last. The stream (snapstream.go) sends them in this order.
var snapshotPaths = []string{".claude/projects", ".claude.json", ".claude/.first-prompt-sent", ".claude/.paseo-agent",
	allowFile, changesFile, lineKeysFile, deliveredFile,
	".paseo", ".local/share/opencode", ".openclaw", ".claude/cloudcli-assets", "workspace", "artifacts"}

// snapshotSkip: what the snapshot leaves out under those roots (filepath.Match against the path relative to $HOME):
// the harnesses' logs, pid files, caches and downloaded binaries, which a successor rebuilds (Jarvis 1's excludes)
var snapshotSkip = []string{
	".paseo/models", ".paseo/runtime", ".paseo/paseo.pid", ".paseo/*.log", ".paseo/*.out", ".paseo/*.err",
	".local/share/opencode/log", ".local/share/opencode/bin",
	".openclaw/logs", ".openclaw/tmp", ".openclaw/*.out", ".openclaw/*.err", ".openclaw/.hold", ".openclaw/gateway.pid",
}

func skipInSnapshot(rel string) bool {
	for _, pat := range snapshotSkip {
		if ok, _ := filepath.Match(pat, rel); ok {
			return true
		}
	}
	return false
}

// makeSnapshot: the snapshot as a tar.gz written to path (streamed: a workspace can be several GB) → its sha256
func makeSnapshot(path string) (string, int64, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	sum, n, err := writeSnapshot(f)
	if err != nil {
		return "", 0, err
	}
	if err := f.Sync(); err != nil {
		return "", 0, err
	}
	return sum, n, nil
}

// writeSnapshot: the snapshot as a compressed tar (snapformat.go) into w (a file, the parts that go to the bucket:
// snapdirect.go, or the request body that streams it to the router: snapstream.go) → its sha256 and size
func writeSnapshot(w io.Writer) (string, int64, error) {
	home, _ := os.UserHomeDir()
	h := sha256.New()
	prog := curProgress.Load() // snapprogress.go: the running snapshot's numbers (nil: not counted)
	cw := &countWriter{w: io.MultiWriter(w, h), prog: prog}
	gz, err := newSnapWriter(cw)
	if err != nil {
		return "", 0, err
	}
	tw := tar.NewWriter(gz)
	copyBuf := make([]byte, 256<<10) // fewer reads of a large file than io.Copy's 32 KB
	for _, rel := range snapshotPaths {
		root := filepath.Join(home, rel)
		if _, err := os.Lstat(root); err != nil {
			continue
		}
		err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			name, _ := filepath.Rel(home, p)
			if skipInSnapshot(name) {
				if fi.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			link := ""
			if fi.Mode()&os.ModeSymlink != 0 {
				link, _ = os.Readlink(p)
			}
			h, err := tar.FileInfoHeader(fi, link)
			if err != nil {
				return nil
			}
			h.Name = name
			if fi.Mode().IsRegular() {
				f, err := os.Open(p)
				if err != nil {
					return nil
				}
				defer f.Close()
				if err := tw.WriteHeader(h); err != nil {
					return err
				}
				// a file that shrank while being read would break the archive: pad to the header's size
				var src io.Reader = f
				if prog != nil {
					src = countReader{f, prog}
				}
				n, err := io.CopyBuffer(tw, io.LimitReader(src, h.Size), copyBuf)
				if err == nil && n < h.Size {
					_, err = io.Copy(tw, io.LimitReader(zeros{}, h.Size-n))
				}
				return err
			}
			return tw.WriteHeader(h)
		})
		if err != nil {
			return "", 0, err
		}
		// each root in blocks of its own: the conversations and records go out whole before the workspace starts
		if err := tw.Flush(); err != nil {
			return "", 0, err
		}
		if err := gz.Flush(); err != nil {
			return "", 0, err
		}
	}
	if err := tw.Close(); err != nil {
		return "", 0, err
	}
	if err := gz.Close(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), cw.n, nil
}

type countWriter struct {
	w    io.Writer
	n    int64
	prog *snapProgress
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	if c.prog != nil {
		c.prog.sent.Store(c.n)
	}
	return n, err
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// restore: the predecessor's snapshot. The cert names its hash (the core took it from the predecessor's signed
// kill): exactly that one, or nothing starts.
// predecessorTmp: where the predecessor's snapshot lands while it is checked (a var: tests move it)
var predecessorTmp = dir + "/predecessor.tar.gz"

func restore(c *client, predSigningKey string, v Vouched) error {
	tmp := predecessorTmp
	defer os.Remove(tmp)
	sum, sig, err := fetchSnapshot(c, tmp) // snapdirect.go: from the bucket to disk, then hashed
	if err != nil {
		return err
	}
	if sum != v.Cert.Snapshot {
		return errors.New("the snapshot isn't the one the cert names")
	}
	if !verify(predSigningKey, []byte(sum), sig) {
		return errors.New("the snapshot isn't signed by the predecessor")
	}
	n, err := unpackFile(tmp)
	if err != nil {
		return err
	}
	log.Printf("restored the predecessor's snapshot (%d files)", n)
	return nil
}

// unpack: a snapshot (tar.gz relative to $HOME) into $HOME
func unpack(body []byte) (int, error) { return unpackReader(bytes.NewReader(body)) }

// unpackFile: a downloaded snapshot unpacked, its progress in the log
func unpackFile(p string) (int, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	prog := startRestoreLog("unpacking", 0)
	defer prog.stop()
	return unpackWith(f, &prog.done)
}

// unpackReader: a snapshot's files into $HOME
func unpackReader(r io.Reader) (int, error) {
	return unpackWith(r, nil)
}

// unpackWith: unpackReader, counting the uncompressed bytes into done (nil: not counted)
func unpackWith(r io.Reader, done *atomic.Int64) (int, error) {
	home, _ := os.UserHomeDir()
	zr, err := openSnapReader(r) // snapformat.go: S2, or gzip from before
	if err != nil {
		return 0, err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	dirs := map[string]bool{} // the directories made so far: one MkdirAll per directory, not per file
	buf := make([]byte, 1<<20)
	n := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return n, err
		}
		name := filepath.Clean(h.Name)
		if filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
			return n, fmt.Errorf("bad path in snapshot: %s", h.Name)
		}
		dst := filepath.Join(home, name)
		switch h.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(dst, os.FileMode(h.Mode)|0o700)
		case tar.TypeSymlink:
			os.MkdirAll(filepath.Dir(dst), 0o755)
			os.Remove(dst)
			os.Symlink(h.Linkname, dst)
		case tar.TypeReg:
			if d := filepath.Dir(dst); !dirs[d] {
				os.MkdirAll(d, 0o755)
				dirs[d] = true
			}
			f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(h.Mode)&0o777)
			if err != nil {
				return n, err
			}
			_, err = io.CopyBuffer(struct{ io.Writer }{f}, struct{ io.Reader }{tr}, buf) // 1 MB writes, not 32 KB
			f.Close()
			if err != nil {
				return n, err
			}
			os.Chtimes(dst, h.ModTime, h.ModTime) // git's index keeps trusting unchanged files
			if done != nil {
				done.Add(h.Size)
			}
			n++
		}
	}
	return n, nil
}

// ---- the snapshot (the supervisor's snapshot command: pause or destroy) ------------------------------

var booted = func() bool { _, err := os.Stat(bootedPath); return err == nil } // a var so tests can set it

// noSnapshot: the answer to a snapshot command while booting — nothing to snapshot, so the router kills at once
func noSnapshot(c *client) error {
	_, _, status, err := c.raw("POST", "/m/snapshot", nil, "X-Snapshot-None", "booting")
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("HTTP %d", status)
	}
	log.Printf("snapshot asked while booting: answered nothing to snapshot")
	return nil
}

// The snapshot is this machine's LAST state (R1 audit, 2026-10-11): the router asks for one only to pause or destroy
// the machine, and the core fixes the snapshot its kill names as what the successor restores. So the machine signs
// exactly one in its life: before taking it, it stops every process of the session (SIGSTOP), so nothing changes
// after it, and a later snapshot command gets that same one again. A router that keeps an earlier signed snapshot
// therefore has none to keep, and can't roll a successor back to a state from before the session's last work.
var (
	finalSnapshot    = dir + "/final-snapshot.tar.gz"
	finalSnapshotSig = dir + "/final-snapshot.sig"
	// snapshotKey: the machine's current signing key (re-read: a downgrade changes it under the supervisor)
	snapshotKey = func() (*ecdh.PrivateKey, error) { p, err := loadPrivate(); return p.sig, err }
)

var frozen atomic.Bool // the session is stopped for its final snapshot: no execs, no deliveries

func notFrozen() error {
	if frozen.Load() {
		return errors.New("the session is stopped for its final snapshot")
	}
	return nil
}

// finalSnapshotSum: the kept final snapshot's sha256 and signature ("" when there is none yet)
func finalSnapshotSum() (string, string, error) {
	sig, err := readTrim(finalSnapshotSig)
	if err != nil {
		return "", "", err
	}
	sum, err := readTrim(finalSnapshotSig + ".sha256")
	if err != nil {
		return "", "", err
	}
	return sum, sig, nil
}

// uploadSnapshotFile: the snapshot through a local file (a router from before snapshot streaming)
func uploadSnapshotFile(c *client) error {
	sum, sig, err := finalSnapshotSum()
	if err != nil { // the first: freeze, take, sign, keep
		frozen.Store(true)
		freezeSession()
		writeChanges() // restore.go: the repos' state, for the router's uncommitted-work check
		prog := startProgress(c)
		prog.setPhase("writing")
		sum, _, err = makeSnapshot(finalSnapshot)
		prog.end(err)
		if err != nil {
			return err
		}
		key, err := snapshotKey()
		if err != nil {
			return err
		}
		if sig, err = sign(key, []byte(sum)); err != nil {
			return err
		}
		if err := os.WriteFile(finalSnapshotSig+".sha256", []byte(sum), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(finalSnapshotSig, []byte(sig), 0o600); err != nil {
			return err
		}
	}
	status, n, err := c.upload("/m/snapshot", finalSnapshot, sum, "X-Snapshot-Sig", sig)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("HTTP %d", status)
	}
	log.Printf("snapshot uploaded (%d bytes)", n)
	return nil
}

// ---- add a store ----------------------------------------------------------------------------------

func addStore(name string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	if err := c.json("POST", "/m/add-store", map[string]string{"store": name}, nil); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "asked Deyao to add %s to this session (approval in the Jarvis 4 app)\n", name)
	return awaitStore(name)
}

// awaitStore: wait (up to 1 h) for a cert of this machine that holds the store, then pull the secrets. Also what
// `jarvis-request add-store` runs after its request, which asks by itself (with a reason) and so must not ask again.
func awaitStore(name string) error {
	if _, ok := readKernelTrust(); ok {
		return awaitStoreKernel(name)
	}
	coreKey, err := readTrim(coreKeyPath)
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "waiting up to 1 h for %s (Deyao's approval in the Jarvis 4 app)\n", name)
	me := c.me
	deadline := time.Now().Add(time.Hour)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		if !hasStore(certStores(c, coreKey, me), name) {
			continue
		}
		r, err := askSecrets(secretsReq{Op: "reload"}, 20*time.Minute)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "added %s: the supervisor holds it now (%d keys); `session-secret --keys K1,K2 --exec CMD` runs a command with the keys it needs\n", name, r.N)
		return nil
	}
	return errors.New("no approval within 1 h")
}

// awaitStoreKernel: a kernel machine's wait: the approval merges the store into this machine's grant and the router
// tells the supervisor to reload (refresh-secrets), which rewrites cert.json from the checked documents; once it names
// the store, one more reload makes sure the keys are held
func awaitStoreKernel(name string) error {
	fmt.Fprintf(os.Stderr, "waiting up to 1 h for %s (Deyao's approval in the Jarvis 4 app)\n", name)
	deadline := time.Now().Add(time.Hour)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		if cert, err := readCert(); err != nil || !hasStore(cert.Stores, name) {
			continue
		}
		r, err := askSecrets(secretsReq{Op: "reload"}, 20*time.Minute)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "added %s: the supervisor holds it now (%d keys); `session-secret --keys K1,K2 --exec CMD` runs a command with the keys it needs\n", name, r.N)
		return nil
	}
	return errors.New("no approval within 1 h")
}

// newestCert: the router's cert for this machine, when it is core-signed for this machine and its current keys (read
// per call: a downgrade replaces them)
func newestCert(c *client, coreKey, me string) (*SignedDoc, bool) {
	var certs struct {
		Cert *SignedDoc `json:"cert"`
	}
	if c.json("GET", "/m/cert", nil, &certs) != nil || certs.Cert == nil {
		return nil, false
	}
	keys, _ := ownKeys()
	var cert Cert
	if verifyDoc(coreKey, certs.Cert, &cert) != nil || cert.Kind != "succession-cert" || cert.Machine == nil ||
		cert.Machine.ID != me || cert.Machine.SigningKey != keys["signingKey"] {
		return nil, false
	}
	return certs.Cert, true
}

func certStores(c *client, coreKey, me string) []string {
	doc, ok := newestCert(c, coreKey, me)
	if !ok {
		return nil
	}
	var cert Cert
	json.Unmarshal([]byte(doc.Payload), &cert)
	return cert.Stores
}

func hasStore(stores []string, name string) bool {
	for _, s := range stores {
		if s == name {
			return true
		}
	}
	return false
}

// secretsLockPath: one pull into the supervisor's copy at a time (with the cert file and the deploy keys it implies)
func secretsLockPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".jarvis-secrets.lock")
}

// withSecretsLock: run fn holding the machine-wide secrets lock
func withSecretsLock(fn func() error) error {
	lock, err := os.OpenFile(secretsLockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}

// downgradeSpec: what `downgrade` was asked, before it is checked against the stores this session holds. The
// mode is always spelled out (Deyao, 2026-10-15): sessions twice passed the stores they meant to keep to a command
// that dropped what it was given (and the other way round), so bare names are refused and every name must be held.
type downgradeSpec struct {
	mode  string // keep | drop | none
	names []string
}

const downgradeUsage = "downgrade --keep STORE… (keep only these) | --drop STORE… (drop these, keep the rest) | --none (drop all)"

func downgradeArgs(args []string) (downgradeSpec, error) {
	if len(args) == 0 {
		return downgradeSpec{}, errors.New("say what to do: " + downgradeUsage)
	}
	var sp downgradeSpec
	switch args[0] {
	case "--keep":
		sp.mode = "keep"
	case "--drop":
		sp.mode = "drop"
	case "--none":
		if len(args) != 1 {
			return downgradeSpec{}, errors.New("--none takes no store names: " + downgradeUsage)
		}
		return downgradeSpec{mode: "none"}, nil
	default:
		return downgradeSpec{}, fmt.Errorf("%s: name the mode first: %s", args[0], downgradeUsage)
	}
	seen := map[string]bool{}
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			return downgradeSpec{}, fmt.Errorf("%s: one mode only, then store names: %s", a, downgradeUsage)
		}
		if !seen[a] {
			seen[a] = true
			sp.names = append(sp.names, a)
		}
	}
	if len(sp.names) == 0 {
		return downgradeSpec{}, fmt.Errorf("--%s needs store names: %s", sp.mode, downgradeUsage)
	}
	return sp, nil
}

// errNothingToDrop: --drop named only stores this session doesn't hold: what was asked already holds
var errNothingToDrop = errors.New("nothing to drop")

// keepFor: the stores to keep, from what this session holds now. --keep must name held stores (a typo would drop the
// real ones); --drop of a store not held is no refusal (it is already gone: noted on stderr), but a --drop that would
// leave nothing is refused: that is --none.
func (sp downgradeSpec) keepFor(held []string) ([]string, error) {
	if sp.mode == "none" {
		return []string{}, nil
	}
	gone := []string{}
	for _, n := range sp.names {
		if !hasStore(held, n) {
			if sp.mode == "keep" {
				return nil, fmt.Errorf("%s isn't held by this session (held: %s); nothing changed. --keep names only held stores", n, strings.Join(held, " "))
			}
			gone = append(gone, n)
		}
	}
	if len(gone) > 0 {
		fmt.Fprintf(os.Stderr, "not held by this session already: %s\n", strings.Join(gone, " "))
		if len(gone) == len(sp.names) {
			return nil, errNothingToDrop
		}
	}
	if sp.mode == "keep" {
		return append([]string{}, sp.names...), nil
	}
	keep := []string{}
	for _, h := range held {
		if !hasStore(sp.names, h) {
			keep = append(keep, h)
		}
	}
	if len(keep) == 0 {
		return nil, errors.New("--drop names every store this session holds; to drop them all, say --none")
	}
	return keep, nil
}

// downgrade: keep only the named stores, in place. A new key pair; the core's challenge signed with the old
// key; the new cert checked; only then the old keys and the secrets of the dropped stores are shredded (the
// old cert still pulls, but sealed to a key that no longer exists). Under the secrets lock, so an add-store's
// waiter neither pulls with the keys being replaced nor puts an older pull over the downgraded copy; an add-store answered
// between the challenge and its answer makes the challenge stale (the core takes only the newest cert), and the
// downgrade starts again from the new cert, with a new key pair (nothing was kept from the stale try).
func downgrade(sp downgradeSpec) error {
	if _, kernel := readKernelTrust(); kernel {
		return downgradeKernel(sp) // kernelboot.go
	}
	return withSecretsLock(func() error {
		var err error
		for try := 0; try < 3; try++ {
			if err = downgradeOnce(sp); err == nil || !strings.Contains(err.Error(), "newest") {
				return err
			}
			log.Printf("downgrade: the cert changed meanwhile (%v); again from the newest", err)
		}
		return err
	})
}

func downgradeOnce(sp downgradeSpec) error {
	coreKey, err := readTrim(coreKeyPath)
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	held := certStores(c, coreKey, c.me)
	if held == nil {
		return errors.New("couldn't read this session's cert, so the stores it holds aren't known; nothing changed")
	}
	keep, err := sp.keepFor(held)
	if errors.Is(err, errNothingToDrop) {
		fmt.Fprintf(os.Stderr, "nothing changed: this session holds %s\n", strings.Join(held, " "))
		return nil
	}
	if err != nil {
		return err
	}
	enc, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	sig, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	encPub, sigPub := b64.EncodeToString(enc.PublicKey().Bytes()), b64.EncodeToString(sig.PublicKey().Bytes())
	sort.Strings(keep)
	if keep == nil {
		keep = []string{}
	}
	var begin struct {
		Challenge *SignedDoc `json:"challenge"`
	}
	if err := c.json("POST", "/m/downgrade", map[string]any{"stores": keep, "newEncryptionKey": encPub, "newSigningKey": sigPub}, &begin); err != nil {
		return err
	}
	if err := checkDowngradeChallenge(coreKey, begin.Challenge, c.me, encPub, sigPub, keep); err != nil {
		return err
	}
	signature, err := sign(c.sig, []byte(begin.Challenge.Payload))
	if err != nil {
		return err
	}
	var fin struct {
		Cert *SignedDoc `json:"cert"`
	}
	if err := c.json("POST", "/m/downgrade/finish", map[string]any{"challenge": begin.Challenge, "signature": signature}, &fin); err != nil {
		return err
	}
	cert, err := checkDowngradeCert(coreKey, fin.Cert, c.me, encPub, sigPub, keep)
	if err != nil {
		return err
	}
	// the new cert is in hand: switch to the new keys, shred the old ones, re-pull the remaining secrets
	p, _ := json.Marshal(private{b64.EncodeToString(enc.Bytes()), b64.EncodeToString(sig.Bytes())})
	if err := shredWrite(privPath, p, 0o600); err != nil {
		return err
	}
	addLineKey(sigPub) // deliver.go: what this machine asks for from now on is signed with the new key
	pub, _ := json.Marshal(map[string]string{"encryptionKey": encPub, "signingKey": sigPub})
	os.WriteFile(keysPath, pub, 0o644)
	raw, _ := json.Marshal(fin.Cert)
	os.WriteFile(certPath, raw, 0o644)
	r, err := askSecrets(secretsReq{Op: "reload", Drop: true, Held: true}, 20*time.Minute) // the supervisor's RAM copy, at once
	if err != nil {
		r.N = 0 // locked or empty: nothing kept
	}
	fmt.Fprintf(os.Stderr, "downgraded to %v: old keys shredded, the supervisor holds %d keys. Values already loaded in running processes stay there until they exit.\n", cert.Stores, r.N)
	return nil
}

// checkDowngradeChallenge: what the old key signs is a core-signed downgrade of this machine to its new keys,
// keeping exactly the stores asked for (the router chooses the challenge's list: R1 audit)
func checkDowngradeChallenge(coreKey string, d *SignedDoc, me, encPub, sigPub string, keep []string) error {
	var ch struct {
		Kind    string `json:"kind"`
		Request struct {
			Downgrade bool     `json:"downgrade"`
			Machine   *Machine `json:"machine"`
			Stores    []string `json:"stores"`
		} `json:"request"`
	}
	if err := verifyDoc(coreKey, d, &ch); err != nil || ch.Kind != "challenge" || !ch.Request.Downgrade ||
		ch.Request.Machine == nil || ch.Request.Machine.ID != me || ch.Request.Machine.SigningKey != sigPub || ch.Request.Machine.EncryptionKey != encPub {
		return fmt.Errorf("the challenge isn't a core-signed downgrade of this machine to the new keys (%v)", err)
	}
	if !sameStores(ch.Request.Stores, keep) {
		return fmt.Errorf("the challenge keeps %v, not the %v asked for: not signed", ch.Request.Stores, keep)
	}
	return nil
}

// checkDowngradeCert: the new cert names this machine, its new keys and exactly the kept stores
func checkDowngradeCert(coreKey string, d *SignedDoc, me, encPub, sigPub string, keep []string) (Cert, error) {
	var cert Cert
	if err := verifyDoc(coreKey, d, &cert); err != nil || cert.Kind != "succession-cert" || cert.Machine == nil ||
		cert.Machine.ID != me || cert.Machine.SigningKey != sigPub || cert.Machine.EncryptionKey != encPub {
		return cert, fmt.Errorf("the new cert isn't core-signed for the new keys (%v)", err)
	}
	if !sameStores(cert.Stores, keep) {
		return cert, fmt.Errorf("the new cert names %v, not the %v asked for", cert.Stores, keep)
	}
	return cert, nil
}

// shredWrite: overwrite the file's old bytes before replacing its contents
func shredWrite(path string, data []byte, mode os.FileMode) error {
	if fi, err := os.Stat(path); err == nil {
		z := make([]byte, fi.Size())
		rand.Read(z)
		os.WriteFile(path, z, mode)
	}
	return os.WriteFile(path, data, mode)
}

// sameStores: the same set of store names
func sameStores(a, b []string) bool {
	x, y := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "\x00") == strings.Join(y, "\x00")
}

// ---- the router client (over Fly's private network; every request signed by this machine) -----------

type client struct {
	base, me string
	sig      *ecdh.PrivateKey
	http     *http.Client
}

type clientConf struct{ URL, Machine string }

// newClient: from the machine's env at boot (saved to clientPath, mode 600), from that file later
func newClient() (*client, error) {
	priv, err := loadPrivate()
	if err != nil {
		return nil, err
	}
	conf := clientConf{os.Getenv("JARVIS2_URL"), os.Getenv("FLY_MACHINE_ID")}
	if conf.URL != "" && conf.Machine != "" {
		b, _ := json.Marshal(conf)
		os.WriteFile(clientPath, b, 0o600)
	} else if b, err := os.ReadFile(clientPath); err == nil {
		json.Unmarshal(b, &conf)
	}
	if conf.URL == "" {
		return nil, errors.New("no router URL (JARVIS2_URL)")
	}
	base, tr := routerTransport(conf.URL) // routerdial.go: the gateways, the other one on a failed dial
	streamHTTP = &http.Client{Transport: tr.streaming()}
	return &client{base: base, me: conf.Machine, sig: priv.sig, http: &http.Client{Timeout: 10 * time.Minute, Transport: tr.plain()}}, nil
}

func (c *client) raw(method, path string, body []byte, hdr ...string) ([]byte, http.Header, int, error) {
	// the keys can change under a running process (a downgrade): sign with the current ones
	if k, err := loadPrivate(); err == nil {
		c.sig = k.sig
	}
	t := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256(body)
	sig, err := sign(c.sig, []byte(method+" "+path+" "+t+" "+hex.EncodeToString(sum[:])))
	if err != nil {
		return nil, nil, 0, err
	}
	req, _ := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	req.Header.Set("X-Machine", c.me)
	req.Header.Set("X-Time", t)
	req.Header.Set("X-Sig", sig)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return b, resp.Header, resp.StatusCode, err
}

// streamHTTP: for the multi-GB transfers (snapshots, an import's tarballs): no overall time limit
var streamHTTP = &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: 5 * time.Minute}}

func (c *client) signed(method, path, bodySum string) (map[string]string, error) {
	if k, err := loadPrivate(); err == nil {
		c.sig = k.sig
	}
	t := strconv.FormatInt(time.Now().Unix(), 10)
	sig, err := sign(c.sig, []byte(method+" "+path+" "+t+" "+bodySum))
	if err != nil {
		return nil, err
	}
	return map[string]string{"X-Machine": c.me, "X-Time": t, "X-Sig": sig}, nil
}

// download: a signed GET streamed into a file → the body's sha256 and the response headers (non-200 is an error)
func (c *client) download(path, dst string) (string, http.Header, error) {
	sum, hdr, _, err := c.downloadTo(path, func(r io.Reader) error {
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, r)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return err
	})
	return sum, hdr, err
}

// downloadTo: a signed GET whose body fn consumes as a stream → the sha256 and size of everything fn read (fn must
// read to the end; what it leaves is read here too, so the hash always covers the whole body)
func (c *client) downloadTo(path string, fn func(io.Reader) error) (string, http.Header, int64, error) {
	empty := sha256.Sum256(nil)
	h, err := c.signed("GET", path, hex.EncodeToString(empty[:]))
	if err != nil {
		return "", nil, 0, err
	}
	req, _ := http.NewRequest("GET", c.base+path, nil)
	for k, v := range h {
		req.Header.Set(k, v)
	}
	hc := c.http
	if c.http == nil || c.http.Timeout != 0 {
		hc = streamHTTP
		if c.http != nil && c.http.Transport != nil {
			hc = &http.Client{Transport: c.http.Transport} // tests: the fake router's own transport
		}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return "", resp.Header, 0, fmt.Errorf("GET %s: HTTP %d %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	sh := sha256.New()
	cw := &countWriter{w: sh}
	tee := io.TeeReader(resp.Body, cw)
	if err := fn(tee); err != nil {
		return "", resp.Header, cw.n, err
	}
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return "", resp.Header, cw.n, err
	}
	return hex.EncodeToString(sh.Sum(nil)), resp.Header, cw.n, nil
}

// upload: a file as a signed POST body, streamed (sum = the file's sha256, which the signature covers)
func (c *client) upload(path, file, sum string, hdr ...string) (int, int64, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	h, err := c.signed("POST", path, sum)
	if err != nil {
		return 0, 0, err
	}
	req, _ := http.NewRequest("POST", c.base+path, f)
	req.ContentLength = fi.Size()
	for k, v := range h {
		req.Header.Set(k, v)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	hc := streamHTTP
	if c.http != nil && c.http.Transport != nil {
		hc = &http.Client{Transport: c.http.Transport}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, fi.Size(), nil
}

func (c *client) json(method, path string, in, out any) error {
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
	}
	b, _, status, err := c.raw(method, path, body)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("%s %s: HTTP %d %s", method, path, status, strings.TrimSpace(string(b))[:min(200, len(strings.TrimSpace(string(b))))])
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// ---- crypto (the core's formats, core/crypto.go) -----------------------------------------------------

type keys struct{ enc, sig *ecdh.PrivateKey }

func loadPrivate() (keys, error) {
	b, err := os.ReadFile(privPath)
	if err != nil {
		return keys{}, err
	}
	var p private
	if err := json.Unmarshal(b, &p); err != nil {
		return keys{}, err
	}
	eb, _ := b64.DecodeString(p.Enc)
	sb, _ := b64.DecodeString(p.Sig)
	enc, err := ecdh.P256().NewPrivateKey(eb)
	if err != nil {
		return keys{}, err
	}
	sig, err := ecdh.P256().NewPrivateKey(sb)
	if err != nil {
		return keys{}, err
	}
	return keys{enc, sig}, nil
}

func ecdsaPriv(k *ecdh.PrivateKey) (*ecdsa.PrivateKey, error) {
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), k.Bytes())
}

func sign(k *ecdh.PrivateKey, payload []byte) (string, error) {
	e, err := ecdsaPriv(k)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(payload)
	s, err := ecdsa.SignASN1(rand.Reader, e, h[:])
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(s), nil
}

func verify(pubRaw string, payload []byte, sigB64 string) bool {
	b, err := b64.DecodeString(pubRaw)
	if err != nil {
		return false
	}
	pk, err := ecdh.P256().NewPublicKey(b)
	if err != nil {
		return false
	}
	der, _ := x509.MarshalPKIXPublicKey(pk)
	anyKey, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	k, ok := anyKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	sig, err := b64.DecodeString(sigB64)
	if err != nil {
		return false
	}
	h := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(k, h[:], sig)
}

func verifyDoc(pub string, d *SignedDoc, out any) error {
	if d == nil || !verify(pub, []byte(d.Payload), d.Sig) {
		return errors.New("bad signature")
	}
	return json.Unmarshal([]byte(d.Payload), out)
}

// openSealed: ephemeral ECDH + HKDF-SHA256 + AES-256-GCM (nonce ‖ ciphertext ‖ tag), as core.SealTo
func openSealed(priv *ecdh.PrivateKey, eB64, dataB64, info string) ([]byte, error) {
	eb, err := b64.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	e, err := ecdh.P256().NewPublicKey(eb)
	if err != nil {
		return nil, err
	}
	x, err := priv.ECDH(e)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, x, nil, info, 32)
	if err != nil {
		return nil, err
	}
	d, err := b64.DecodeString(dataB64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(d) < g.NonceSize()+g.Overhead() {
		return nil, errors.New("sealed data too short")
	}
	return g.Open(nil, d[:g.NonceSize()], d[g.NonceSize():], nil)
}

// certMode: the signed permission mode (it replaces the router's env value);
// a running session raised in place keeps bypass until its next cert, which then signs it
func certMode(c Cert) string {
	if c.Options.PermissionMode == "bypass" {
		return "bypass"
	}
	return "auto"
}

func withoutEnv(env []string, names ...string) []string {
	out := env[:0:0]
	for _, kv := range env {
		drop := false
		for _, n := range names {
			drop = drop || strings.HasPrefix(kv, n+"=")
		}
		if !drop {
			out = append(out, kv)
		}
	}
	return out
}
