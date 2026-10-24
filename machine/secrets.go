package main

// Secrets: a component of the supervisor (supervisor.go). The supervisor pulls the session's secrets from the core
// (sealed to this machine, through the router), holds them in RAM and serves them to the session's processes on
// request; no secret sits in plain text on disk (Deyao, 2026-10-16).
//
//   - Pulls: the supervisor alone pulls (/m/pull-secrets): at boot when boot asks (op "pull"), on the router's
//     refresh-secrets, and when a process of the session asks for one (`pull-secrets`, add-store's waiter, a
//     downgrade: op "reload": the router's newest cert, then a pull with it). A pull hands no value to anyone: its
//     answer is the key names and the cert's stores. The values it holds are always exactly what the core sealed
//     for the cert's stores.
//   - RAM only: the values live in supervisor-core's memory and in a memfd the keeper holds (secretsFD), so a restarted
//     supervisor-core has them again without a new pull (the core may have locked the stores again since). A memfd is anonymous
//     memory, not a file on any filesystem; nothing is written to ~/.secrets, /run/jarvis or the snapshot.
//   - Serving: the unix socket secretsSock (0600, user claude; root may connect too): one JSON request per
//     connection, {"op": "names" | "get" (with "keys") | "pull" | "reload" | "boot-env"}. A process gets values only
//     with "get", naming each key it needs: there is no request for all keys (answerSecrets). Asking never pulls;
//     pulling never answers values. Each request is logged in the supervisor log with its op, the key names (or a
//     count) and the caller's pid and command name (SO_PEERCRED), never a value. `session-secret` (asking),
//     `pull-secrets` (pulling) and boot use it. It needs no guard check: it carries no instruction, and it serves
//     only what the core sealed for this machine's cert.
//   - Deploy keys: the private keys of the repo stores stay in RAM too, in the supervisor's ssh-agent
//     (sshAgentSock, deploykeys.go); ~/.ssh holds only their public halves, which name the key for each repo's alias.
//   - The harness's env: boot builds the harness's environment from the values (RAM only), so `$VAR` works in the
//     agent's commands (op "boot-env", answered only to boot before the machine has booted); a later pull reaches a
//     process only through `session-secret --keys … --exec`.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	secretsSock  = dir + "/secrets.sock"
	secretsFDEnv = "JARVIS_SECRETS_FD" // supervisor-core's fd of the keeper's memfd
)

const sysMemfdCreate = 319 // linux/amd64

// heldSecrets: the supervisor's RAM copy
type heldSecrets struct {
	mu     sync.RWMutex
	vals   map[string]string
	pulled bool       // a pull succeeded at least once on this machine
	mem    *os.File   // the keeper's memfd (nil in tests: memory only)
	pullMu sync.Mutex // one pull at a time
}

var held = &heldSecrets{vals: map[string]string{}}

// newMemfd: an anonymous RAM file (the keeper's, handed to every supervisor-core)
func newMemfd() (*os.File, error) {
	name := []byte("jarvis-secrets\x00")
	fd, _, errno := syscall.Syscall(sysMemfdCreate, uintptr(unsafe.Pointer(&name[0])), 0, 0)
	if errno != 0 {
		return nil, errno
	}
	return os.NewFile(fd, "memfd:jarvis-secrets"), nil
}

// loadHeld: supervisor-core's start: the values the memfd holds (from an earlier one), if any
func (h *heldSecrets) loadHeld() {
	s := os.Getenv(secretsFDEnv)
	fd, err := strconv.Atoi(s)
	if err != nil || fd < 3 {
		return
	}
	h.mem = os.NewFile(uintptr(fd), "memfd:jarvis-secrets")
	b, err := io.ReadAll(io.NewSectionReader(h.mem, 0, 64<<20))
	if err != nil || len(b) == 0 {
		return
	}
	var st struct {
		Vals   map[string]string `json:"vals"`
		Pulled bool              `json:"pulled"`
	}
	if json.Unmarshal(b, &st) == nil && st.Vals != nil {
		h.mu.Lock()
		h.vals, h.pulled = st.Vals, st.Pulled
		h.mu.Unlock()
		log.Printf("secrets: %d keys kept in memory from the earlier supervisor-core", len(st.Vals))
	}
}

// set: the new values replace the old at once (RAM and memfd), and the deploy keys follow
func (h *heldSecrets) set(m map[string]string) {
	clean := map[string]string{}
	for k, v := range m {
		if envNameRE.MatchString(k) {
			clean[k] = v
		} else {
			log.Printf("secrets: left out a key that isn't an env name (%d bytes)", len(k))
		}
	}
	h.mu.Lock()
	h.vals, h.pulled = clean, true
	h.mu.Unlock()
	if h.mem != nil {
		b, _ := json.Marshal(map[string]any{"vals": clean, "pulled": true})
		h.mem.Truncate(0)
		h.mem.WriteAt(b, 0)
	}
	if err := setupDeployKeys(clean); err != nil {
		log.Printf("deploy keys: %v", err)
	}
}

func (h *heldSecrets) snapshot() map[string]string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make(map[string]string, len(h.vals))
	for k, v := range h.vals {
		out[k] = v
	}
	return out
}

// pull: one pull from the core (with pullSecrets' wait for a locked store) into RAM
func (h *heldSecrets) pull(c *client) (int, error) {
	h.pullMu.Lock()
	defer h.pullMu.Unlock()
	coreKey, err := readTrim(coreKeyPath)
	if _, kernel := readKernelTrust(); err != nil && !kernel {
		return 0, err
	}
	m, err := pullSecrets(c, coreKey, c.me)
	if err != nil {
		return 0, err
	}
	h.set(m)
	return len(m), nil
}

// reload: the newest cert from the router, then a pull with it (refresh-secrets, add-store, downgrade). With drop, a
// failed pull empties the RAM copy (a downgrade: what the old keys opened must not stay).
// lockHeld: the caller (a downgrade) holds the secrets lock already.
func (h *heldSecrets) reload(c *client, drop, lockHeld bool) (int, error) {
	if _, kernel := readKernelTrust(); kernel {
		return h.reloadKernel(c, drop, lockHeld)
	}
	coreKey, err := readTrim(coreKeyPath)
	if err != nil {
		return 0, err
	}
	refresh := refreshSecrets
	if lockHeld {
		refresh = refreshUnlocked
	}
	n, err := refresh(func() error {
		doc, ok := newestCert(c, coreKey, c.me)
		if !ok {
			return errors.New("the router has no cert for this machine")
		}
		raw, _ := json.Marshal(doc)
		return os.WriteFile(certPath, raw, 0o644)
	}, func() (map[string]string, error) {
		c2, err := newClient() // the keys may have changed (downgrade)
		if err != nil {
			return nil, err
		}
		h.pullMu.Lock()
		defer h.pullMu.Unlock()
		return pullSecrets(c2, coreKey, c2.me)
	})
	if err != nil && drop {
		h.set(map[string]string{})
	}
	return n, err
}

// refreshSecrets: under the lock, take the newest cert (prepare) and pull with it, then the RAM copy. Two waiters (two
// add-stores approved together) used to pull and write side by side, and the slower one could put an older pull over
// a newer one; under the lock each pull happens after the previous one is held, from the router's newest cert at that
// moment, so the copy is always the newest.
func refreshSecrets(prepare func() error, pull func() (map[string]string, error)) (int, error) {
	n := 0
	err := withSecretsLock(func() (err error) {
		n, err = refreshUnlocked(prepare, pull)
		return err
	})
	return n, err
}

// refreshUnlocked: refreshSecrets for a caller that holds the lock
func refreshUnlocked(prepare func() error, pull func() (map[string]string, error)) (int, error) {
	if err := prepare(); err != nil {
		return 0, err
	}
	m, err := pull()
	if err != nil {
		return 0, err
	}
	held.set(m)
	return len(m), nil
}

// ---- the socket -------------------------------------------------------------------------------------------

type secretsReq struct {
	Op   string   `json:"op"`
	Keys []string `json:"keys,omitempty"`
	Drop bool     `json:"drop,omitempty"` // reload: empty the copy if the pull fails
	Held bool     `json:"held,omitempty"` // reload: the caller holds the secrets lock (a downgrade)
}

type secretsResp struct {
	OK      bool              `json:"ok"`
	Error   string            `json:"error,omitempty"`
	Locked  bool              `json:"locked,omitempty"`
	Names   []string          `json:"names,omitempty"`
	Stores  []string          `json:"stores,omitempty"` // pull/reload: the stores of the cert the pull used
	Secrets map[string]string `json:"secrets,omitempty"`
	N       int               `json:"n,omitempty"`
}

// serveSecrets: the secrets socket (started by supervise)
func serveSecrets(c *client) {
	os.Remove(secretsSock)
	ln, err := net.Listen("unix", secretsSock)
	if err != nil {
		log.Printf("secrets: %v", err)
		return
	}
	os.Chmod(secretsSock, 0o600)
	for {
		conn, err := ln.Accept()
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		go handleSecrets(c, conn)
	}
}

func handleSecrets(c *client, conn net.Conn) {
	defer conn.Close()
	pid, uid, comm := peerOf(conn)
	if !sessionPeer(uid) {
		log.Printf("secrets: refused a caller of uid %d (pid %d %s)", uid, pid, comm)
		return
	}
	conn.SetDeadline(time.Now().Add(20 * time.Minute)) // a boot pull waits for a locked store
	var req secretsReq
	if err := json.NewDecoder(io.LimitReader(conn, 1<<16)).Decode(&req); err != nil {
		return
	}
	resp := answerSecrets(c, req, pid, uid, fmt.Sprintf("pid %d %s", pid, comm))
	json.NewEncoder(conn).Encode(resp)
}

// answerSecrets: one request, logged with the key names and the caller, never a value. Two kinds of request, kept
// strictly apart (Deyao, 2026-10-20):
//   - pulling ("pull", "reload"): the supervisor fetches the stores from the core into its RAM; the answer carries the
//     key names and the cert's stores, never a value.
//   - asking ("get"): a process gets exactly the keys it names, from what is held now (it never pulls). There is no
//     way to ask for every key: a request must name each key it needs (no "all" op, no empty list, no wildcard),
//     and a name not held is an error naming it.
//
// The one hand-over of every value is "boot-env": the harness's environment. Only to the keeper (root, supervisor-core's
// parent: it builds the harness's env at each start of the harness, keeper.go), and to the boot steps (the process
// the keeper named in harness.pid, a root-owned file) before bootedPath exists.
func answerSecrets(c *client, req secretsReq, pid, uid int, caller string) secretsResp {
	switch req.Op {
	case "names":
		m := held.snapshot()
		names := sortedKeys(m)
		log.Printf("secrets: names (%d) for %s", len(names), caller)
		return secretsResp{OK: true, Names: names}
	case "get":
		return answerGet(req.Keys, caller)
	case "boot-env":
		keeper := uid == 0 && pid == keeperPID() && pid > 1
		if !keeper && booted() {
			log.Printf("secrets: refused boot-env for %s: the machine has booted", caller)
			return secretsResp{Error: "boot-env is only for the boot, before the harness starts; ask for the keys a command needs (session-secret --keys K1,K2 …)"}
		}
		if s, _ := readTrim(harnessPIDPath); !keeper && s != strconv.Itoa(pid) {
			log.Printf("secrets: refused boot-env for %s: not the boot process", caller)
			return secretsResp{Error: "boot-env is only for the boot process"}
		}
		m := held.snapshot()
		log.Printf("secrets: boot-env (%d keys: %s) for %s", len(m), strings.Join(clipNames(sortedKeys(m)), " "), caller)
		return secretsResp{OK: true, Secrets: m}
	case "pull", "reload":
		var n int
		var err error
		if req.Op == "pull" {
			n, err = held.pull(c)
		} else {
			n, err = held.reload(c, req.Drop, req.Held)
		}
		log.Printf("secrets: %s for %s: %s", req.Op, caller, resultText(n, err))
		if err != nil {
			return secretsResp{Error: err.Error(), Locked: errors.Is(err, errStoresLocked)}
		}
		r := secretsResp{OK: true, N: n, Names: sortedKeys(held.snapshot())}
		if cert, err := currentCert(); err == nil {
			r.Stores = cert.Stores
		}
		return r
	}
	log.Printf("secrets: unknown op %q from %s", clip(req.Op, 20), caller)
	return secretsResp{Error: "unknown op"}
}

// answerGet: exactly the named keys, or an error; never all of them
func answerGet(keys []string, caller string) secretsResp {
	if len(keys) == 0 {
		log.Printf("secrets: refused get with no keys for %s", caller)
		return secretsResp{Error: "name the keys you need (session-secret --keys K1,K2 …); there is no request for all keys"}
	}
	for _, k := range keys {
		if !envNameRE.MatchString(k) || len(k) > 100 {
			log.Printf("secrets: refused get with a key that isn't an env name for %s", caller)
			return secretsResp{Error: fmt.Sprintf("%q isn't a key name", clip(k, 40))}
		}
	}
	m := held.snapshot()
	out := map[string]string{}
	var missing []string
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		} else if !slices.Contains(missing, k) {
			missing = append(missing, k)
		}
	}
	names := strings.Join(clipNames(keys), " ")
	if len(missing) > 0 {
		log.Printf("secrets: refused get %s for %s%s", names, caller, missingText(missing))
		return secretsResp{Error: "not held in this session: " + strings.Join(missing, ", ") + " (session-secret --names lists what it holds; `jarvis stores` shows which store has a key)"}
	}
	log.Printf("secrets: get %s for %s", names, caller)
	return secretsResp{OK: true, Secrets: out}
}

func resultText(n int, err error) string {
	if err != nil {
		return "failed: " + err.Error()
	}
	return fmt.Sprintf("%d keys", n)
}

func missingText(missing []string) string {
	if len(missing) == 0 {
		return ""
	}
	return " (not held: " + strings.Join(clipNames(missing), " ") + ")"
}

// clipNames: key names only as env names (anything else a caller sent is shown as ?), at most 60
func clipNames(ks []string) []string {
	out := []string{}
	for i, k := range ks {
		if i == 60 {
			out = append(out, fmt.Sprintf("… %d more", len(ks)-60))
			break
		}
		if envNameRE.MatchString(k) && len(k) <= 100 {
			out = append(out, k)
		} else {
			out = append(out, "?")
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// peerOf: the caller's pid, uid and command name (SO_PEERCRED)
func peerOf(conn net.Conn) (int, int, string) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, -1, "?"
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, -1, "?"
	}
	var cred *syscall.Ucred
	raw.Control(func(fd uintptr) {
		cred, _ = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if cred == nil {
		return 0, -1, "?"
	}
	comm, _ := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(int(cred.Pid)), "comm"))
	name := strings.TrimSpace(string(comm))
	if name == "exe" { // jarvis-machine started as /proc/self/exe: its subcommand says more
		if cl, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(int(cred.Pid)), "cmdline")); err == nil {
			if f := strings.Split(string(cl), "\x00"); len(f) > 1 {
				name = "jarvis-machine " + clip(f[1], 20)
			}
		}
	}
	return int(cred.Pid), int(cred.Uid), name
}

// ---- the client side (boot, the CLI) -----------------------------------------------------------------------

// askSecrets: one request to the supervisor's secrets component
func askSecrets(req secretsReq, timeout time.Duration) (secretsResp, error) {
	var resp secretsResp
	var conn net.Conn
	var err error
	for i := 0; i < 30; i++ { // the supervisor may be starting (or supervisor-core restarting)
		if conn, err = net.DialTimeout("unix", secretsSock, 2*time.Second); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return resp, fmt.Errorf("the supervisor's secrets aren't reachable: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return resp, err
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return resp, fmt.Errorf("the supervisor's secrets: %w", err)
	}
	if !resp.OK {
		if resp.Locked {
			return resp, fmt.Errorf("%w (%s)", errStoresLocked, resp.Error)
		}
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}
