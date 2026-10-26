package main

// The keeper (docs/DESIGN.md "The keeper"; DECISIONS 2026-10-21): `jarvis-machine boot`, the image's ENTRYPOINT, run
// as root. It is Fly's main child for the machine's whole life: Fly ends the machine when its main child ends, so
// nothing but the keeper's own exit can end it, and only root can signal it (Deyao, 2026-10-21: "The supervisor
// should be the main child. Nothing should be able to kill the supervisor other than a sigterm or sigkill from
// something with higher privilege."). Session s4a0dda11e231bdda's machine died on 2026-10-21 because the main child
// was the harness's launcher (a bash loop, user claude): a subagent's `ps aux | grep … | xargs kill` matched it, the
// SIGTERM ended the main child, Fly tore the VM down and the supervisor (and the final snapshot) went with it.
//
// Its children, each in its own session (setsid) so no process group of the session holds the keeper:
//
//	child                         identity                         restarted when it ends
//	prepare (the boot steps)      user claude                      no: it hands the harness's env over and ends
//	supervisor-core               root, with user claude's file    yes (backoff 1 s … 30 s)
//	(superviseCore, supervisor.go) access (fsuid/fsgid, groups),
//	                              pinned memory, OOM-protected
//	supervisor-normal             root, user claude's file access, yes (backoff 1 s … 1 min)
//	(superviseNormal)             the session's memory cgroup,
//	                              the default OOM score
//	the harness (entrypoint.sh    user claude                      yes (backoff 1 s … 1 min), with the same
//	→ harness-*.sh)                                                conversation resumed
//
// The split by uid: user claude (the session, with its sudo) can't signal a root process (kill(2) needs the sender's
// uid to match the target's real or saved uid), so `kill PID`, `pkill -f jarvis-machine`, `kill -TERM -1` and a
// process-group kill from the session all fail with EPERM on the keeper and both supervisors; root through sudo can (higher
// privilege: accepted). Root processes' /proc files (environ, mem, oom_score_adj) are root's too, and both are
// marked not dumpable, so the session can't read the supervisor's memory or change its OOM score. Both supervisors keep
// root's uid but takes user claude's file identity (setfsuid/setfsgid and claude's groups), so every file it reads or
// writes under ~ and /data, its sockets and /run/jarvis are exactly as before (owned by claude); every command it
// runs for the session goes through `jarvis-machine unprotected`, which drops to user claude for good (uid, gid,
// groups) and back to the default OOM score (sessionCommand).
//
// A dead harness never ends the machine: the keeper logs how it ended (exit code or signal) and its uptime, kills
// what is left of its process group, and starts it again after the backoff with the secrets the supervisor holds
// now (never more than it holds: a downgrade sticks) and JARVIS_HARNESS_START=n, so the entrypoint skips its
// one-time steps and harness-claude.sh adopts a Claude host still running in tmux (else resumes the newest
// conversation, as a reboot's resume would). Each start and end is in the supervisor log, and the status report
// carries the count (__HARNESS__, router/registry.go). No restart once the session is stopped for its final
// snapshot.
//
// Stop signals (SIGTERM, SIGINT: Fly's stop; SIGHUP, SIGQUIT) start the priority teardown, most important first, so
// a short kill timeout still saves what matters most: supervisor-normal is killed, supervisor-core (SIGUSR1, supervisor.go teardown) sends the
// transcripts that changed since their last copy (newest first, subagents after), then streams the final snapshot
// (the transcripts and ~/.claude.json first, the workspace, the artifacts last) and commits it; then the harness's
// process group gets SIGTERM, then SIGKILL, every other process of user claude too, and the keeper exits.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	keeperDir        = "/run/jarvis-keeper"        // root's (0755): what only the keeper writes
	harnessPIDPath   = keeperDir + "/harness.pid"  // the boot steps' pid, then the harness launcher's (each start)
	harnessStatePath = keeperDir + "/harness.json" // the harness's starts and last end (the status report)
	sessionUser      = "claude"

	stopSignals       = []os.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT}
	harnessBackoff0   = time.Second
	harnessBackoffMax = time.Minute
	harnessStable     = 10 * time.Minute // up this long: the backoff starts again at 1 s
	harnessGrace      = 5 * time.Second  // SIGTERM → SIGKILL for the harness's process group
	teardownMax       = 30 * time.Minute // supervisor-core's teardown, at most (Fly's kill timeout ends it sooner)
)

// ---- the session user ------------------------------------------------------------------------------------------

type sessionIDs struct {
	uid, gid int
	groups   []int
	home     string
}

var (
	sessionOnce sync.Once
	sessionIDv  sessionIDs
)

// session: user claude's ids (from /etc/passwd and /etc/group); off the image (tests) this process's own
func session() sessionIDs {
	sessionOnce.Do(func() {
		sessionIDv = sessionIDs{uid: os.Getuid(), gid: os.Getgid(), home: os.Getenv("HOME")}
		u, err := user.Lookup(sessionUser)
		if err != nil {
			return
		}
		uid, err1 := strconv.Atoi(u.Uid)
		gid, err2 := strconv.Atoi(u.Gid)
		if err1 != nil || err2 != nil {
			return
		}
		ids := sessionIDs{uid: uid, gid: gid, home: u.HomeDir}
		if gs, err := u.GroupIds(); err == nil {
			for _, g := range gs {
				if n, err := strconv.Atoi(g); err == nil {
					ids.groups = append(ids.groups, n)
				}
			}
		}
		if len(ids.groups) == 0 {
			ids.groups = []int{gid}
		}
		sessionIDv = ids
	})
	return sessionIDv
}

// sessionPeer: a socket caller the supervisor serves (secrets, ssh-agent): user claude, root, or this process's uid
func sessionPeer(uid int) bool { return uid == 0 || uid == session().uid || uid == os.Getuid() }

// privileged: this process runs as root (the keeper and both supervisors on the image)
var privileged = func() bool { return os.Geteuid() == 0 }

// sessionCommand: a command the supervisor runs for the session. As root it goes through `jarvis-machine
// unprotected`, which takes user claude's identity for good and the default OOM score, then execs it; otherwise (a
// CLI command, the tests) it runs as it is. ctx may be nil.
var sessionCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
	return unprotectedCommand(ctx, "", name, args...)
}

// rescueCommand: a command the router runs to look at or rescue the machine (a grant's exec, such as the terminal
// holder's; the status and screen readers): as sessionCommand, but in the rescue cgroup, outside the session's
// memory limit (oomguard.go), so it still runs on a machine the session has filled
var rescueCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
	return unprotectedCommand(ctx, "--rescue", name, args...)
}

func unprotectedCommand(ctx context.Context, flag, name string, args ...string) *exec.Cmd {
	if !privileged() {
		if ctx == nil {
			return exec.Command(name, args...)
		}
		return exec.CommandContext(ctx, name, args...)
	}
	argv := []string{"unprotected"}
	if flag != "" {
		argv = append(argv, flag)
	}
	argv = append(append(argv, "--", name), args...)
	if ctx == nil {
		return exec.Command("/proc/self/exe", argv...)
	}
	return exec.CommandContext(ctx, "/proc/self/exe", argv...)
}

// unprotected: back to the default OOM score (as root this also sets the floor, so the command can't take -1000
// back), then, as root, into the session's memory cgroup (--rescue: the rescue one) and user claude's uid, gid and
// groups for good; then exec the command
func unprotected(args []string) error {
	cgroup := sessionCgroup
	if len(args) > 0 && args[0] == "--rescue" {
		cgroup, args = rescueCgroup, args[1:]
	}
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return errors.New("usage: jarvis-machine unprotected [--rescue] -- <command> [args…]")
	}
	os.WriteFile("/proc/self/oom_score_adj", []byte("0\n"), 0o644)
	if privileged() {
		joinCgroup(cgroup) // oomguard.go: under the session's memory limit, or the rescue one's
		if err := dropToSession(); err != nil {
			return err
		}
	}
	path, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, args, os.Environ())
}

// dropToSession: this process becomes user claude (real, effective and saved ids; no way back)
func dropToSession() error {
	s := session()
	if s.uid == 0 {
		return errors.New("no session user " + sessionUser)
	}
	if err := syscall.Setgroups(s.groups); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setresgid(s.gid, s.gid, s.gid); err != nil {
		return fmt.Errorf("setresgid: %w", err)
	}
	if err := syscall.Setresuid(s.uid, s.uid, s.uid); err != nil {
		return fmt.Errorf("setresuid: %w", err)
	}
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		return errors.New("still root after the drop")
	}
	return nil
}

// sessionFileAccess: a supervisor's file identity becomes user claude's (fsuid, fsgid, groups) while its uid stays
// root: what it reads and writes is checked and owned as before; only the session can't signal it. Every thread.
func sessionFileAccess() error {
	s := session()
	if s.uid == 0 {
		return errors.New("no session user " + sessionUser)
	}
	if err := syscall.Setgroups(s.groups); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_SETFSGID, uintptr(s.gid), 0, 0); e != 0 {
		return fmt.Errorf("setfsgid: %w", e)
	}
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_SETFSUID, uintptr(s.uid), 0, 0); e != 0 {
		return fmt.Errorf("setfsuid: %w", e)
	}
	notDumpable()
	return nil
}

// notDumpable: /proc/<pid>/{environ,mem,…} stay root's (the session can't read the supervisor's memory)
func notDumpable() {
	syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0)
}

// signalSessionCmd: `jarvis-machine signal-session SIG`: kill(-1, SIG) as user claude, i.e. to every process of the
// session but this one; never to root's (the keeper, the supervisors, Fly's)
func signalSessionCmd(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: jarvis-machine signal-session STOP|CONT|TERM|KILL")
	}
	sig, ok := map[string]syscall.Signal{"STOP": syscall.SIGSTOP, "CONT": syscall.SIGCONT, "TERM": syscall.SIGTERM, "KILL": syscall.SIGKILL}[args[0]]
	if !ok {
		return errors.New("unknown signal " + args[0])
	}
	if os.Getuid() == 0 {
		return errors.New("refusing kill(-1) as root")
	}
	return syscall.Kill(-1, sig)
}

// signalSession: sig to every process of user claude. As root through a child that drops to claude first (kill(-1)
// as root would reach every process on the machine); as claude, kill(-1) itself (it spares the caller).
var signalSession = func(sig string) error {
	if !privileged() {
		n, ok := map[string]syscall.Signal{"STOP": syscall.SIGSTOP, "CONT": syscall.SIGCONT, "TERM": syscall.SIGTERM, "KILL": syscall.SIGKILL}[sig]
		if !ok {
			return errors.New("unknown signal " + sig)
		}
		return syscall.Kill(-1, n)
	}
	out, err := exec.Command("/proc/self/exe", "unprotected", "--", "/proc/self/exe", "signal-session", sig).CombinedOutput()
	if err != nil && len(out) > 0 {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return err
}

// ---- the keeper -------------------------------------------------------------------------------------------------

type keeperT struct {
	mu        sync.Mutex
	stopping  bool
	stopCh    chan struct{}
	core      *os.Process   // supervisor-core
	coreEnd   chan struct{} // closed when supervisor-core's loop has ended (stopping)
	normal    *os.Process   // supervisor-normal
	harness   *exec.Cmd
	state     harnessState
	secretsFn func() map[string]string // the secrets for a start of the harness (k.secrets; tests replace it)
	hlog      *harnessLog              // harnesslog.go: one for the machine's life, so its rate limit spans restarts
}

// harnessState: what the keeper tells the status report about the harness (harnessStatePath)
type harnessState struct {
	Starts     int    `json:"starts"`
	Running    bool   `json:"running"`
	PID        int    `json:"pid,omitempty"`
	StartedAt  string `json:"startedAt,omitempty"`
	LastExit   string `json:"lastExit,omitempty"` // "exit status 1", "signal: terminated", …
	LastExitAt string `json:"lastExitAt,omitempty"`
	LastUpSecs int64  `json:"lastUpSecs,omitempty"`
	NextStart  string `json:"nextStart,omitempty"`
}

func keeper() error {
	// first: the env this machine was started with is thrown away, except what the image, Fly and the core set
	// (vouch.go). Re-execs once.
	if err := ensureCleanEnv(); err != nil {
		log.Printf("REFUSING TO START: %v", err)
		select {}
	}
	k := newKeeper()
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, stopSignals...)
	signal.Ignore(syscall.SIGPIPE, syscall.SIGTTOU, syscall.SIGTTIN, syscall.SIGTSTP)
	if privileged() {
		if err := keeperDirs(); err != nil {
			log.Printf("REFUSING TO START: %v", err)
			select {}
		}
		protectFromOOM()
		makeCgroups()        // oomguard.go: the session's and the rescue memory limits, before the boot steps start
		lockMemory("keeper") // oomguard.go
		notDumpable()
	} else {
		log.Printf("the keeper isn't root: the session can signal it (an image whose USER isn't root?)")
	}
	logToSupervisorLog()
	log.Printf("keeper up (pid %d, uid %d): Fly's main child for this machine's life", os.Getpid(), os.Getuid())

	specCh := make(chan *harnessSpec, 1)
	if err := k.startPrepare(specCh); err != nil {
		log.Printf("REFUSING TO START: the boot steps: %v", err)
		select {}
	}
	go k.coreLoop()
	go k.normalLoop()
	go func() {
		if spec := <-specCh; spec != nil {
			k.harnessLoop(*spec)
		}
	}()
	s := <-sigs
	go func() { // a second stop signal while tearing down: logged, nothing more (Fly's SIGKILL ends it)
		for s2 := range sigs {
			log.Printf("%v during the teardown; carrying on", s2)
		}
	}()
	k.teardown(s)
	return nil
}

func newKeeper() *keeperT {
	k := &keeperT{stopCh: make(chan struct{}), coreEnd: make(chan struct{})}
	k.secretsFn = k.secrets
	return k
}

// keeperDirs: /run/jarvis (user claude's, as before) and the keeper's own /run/jarvis-keeper (root's). On a Fly
// machine /run/jarvis is a tmpfs of its own: the machine's key pair (private.json) lives there, in memory only, never
// on a disk (Fly's root overlay is on one) or the volume (DECISIONS 228).
func keeperDirs() error {
	s := session()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if os.Getenv("FLY_MACHINE_ID") != "" {
		if err := memoryDir(dir); err != nil {
			return fmt.Errorf("%s in memory: %w", dir, err)
		}
	}
	if err := os.Chown(dir, s.uid, s.gid); err != nil {
		return err
	}
	os.Chmod(dir, 0o755)
	if err := os.MkdirAll(keeperDir, 0o755); err != nil {
		return err
	}
	os.Chown(keeperDir, 0, 0)
	return os.Chmod(keeperDir, 0o755)
}

// memoryDir: a tmpfs on d, unless d is one already (the keeper started again in the same boot keeps what is there)
func memoryDir(d string) error {
	var fs syscall.Statfs_t
	var st, parent syscall.Stat_t
	if err := syscall.Statfs(d, &fs); err != nil {
		return err
	}
	if err := syscall.Stat(d, &st); err != nil {
		return err
	}
	if err := syscall.Stat(d+"/..", &parent); err != nil {
		return err
	}
	if fs.Type == 0x01021994 && st.Dev != parent.Dev { // TMPFS_MAGIC, mounted on d itself
		return nil
	}
	if err := syscall.Mount("tmpfs", d, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=755,size=256m"); err != nil {
		return err
	}
	log.Printf("%s: a tmpfs (the machine's keys live in memory only)", d)
	return nil
}

// protectFromOOM: oom_score_adj -1000 (never chosen by the OOM killer) for the keeper; supervisor-core inherits it (supervisor-normal sets its own back to 0).
// Only on a Fly machine.
var protectFromOOM = func() {
	if os.Getenv("FLY_MACHINE_ID") == "" {
		return
	}
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte(oomProtected+"\n"), 0o644); err != nil {
		log.Printf("OOM protection: %v", err)
		return
	}
	log.Printf("OOM protection on (oom_score_adj %s)", oomProtected)
}

func (k *keeperT) isStopping() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.stopping
}

// sleep: d, or less when the keeper starts stopping; false = stopping
func (k *keeperT) sleep(d time.Duration) bool {
	select {
	case <-k.stopCh:
		return false
	case <-time.After(d):
		return true
	}
}

// startPrepare: the boot steps as user claude (prepareCmd); the harness's env arrives on a pipe (fd 3), never on disk
func (k *keeperT) startPrepare(specCh chan<- *harnessSpec) error {
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd := sessionCommand(nil, "/proc/self/exe", "prepare")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{w} // fd 3
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		return err
	}
	w.Close()
	writeHarnessPID(cmd.Process.Pid) // boot-env: the boot steps ask for the secrets (secrets.go)
	go func() {
		var spec harnessSpec
		b, _ := io.ReadAll(r)
		r.Close()
		err := cmd.Wait()
		if jerr := json.Unmarshal(b, &spec); jerr != nil || len(spec.Clean) == 0 {
			log.Printf("the boot steps ended (%s) without the harness's env: no harness on this machine; the supervisor stays up for the router", exitText(err))
			specCh <- nil
			return
		}
		specCh <- &spec
	}()
	return nil
}

// coreLoop: supervisor-core, started once init asked (the boot steps have the keys then) and again whenever it
// exits; the secrets' memfd is the keeper's, so a new supervisor-core has them without a pull
func (k *keeperT) coreLoop() {
	defer close(k.coreEnd)
	if !k.waitInit() {
		return
	}
	mem, err := newMemfd() // secrets.go: the RAM copy of the secrets, kept across restarts
	if err != nil {
		log.Printf("secrets memfd: %v (a restarted supervisor-core pulls again)", err)
	}
	k.childLoop("supervisor-core", "--core", 30*time.Second, func(cmd *exec.Cmd) {
		if mem != nil {
			cmd.ExtraFiles = []*os.File{mem} // fd 3
			cmd.Env = append(cmd.Env, secretsFDEnv+"=3")
		}
	}, &k.core)
}

// normalLoop: supervisor-normal, started with supervisor-core and again whenever it exits (it lowers its own OOM
// protection and joins the session's memory cgroup, supervisor.go superviseNormal)
func (k *keeperT) normalLoop() {
	if !k.waitInit() {
		return
	}
	k.childLoop("supervisor-normal", "--normal", time.Minute, nil, &k.normal)
}

// waitInit: until init asked (false: the machine is stopping)
func (k *keeperT) waitInit() bool {
	for {
		if _, err := os.Stat(goPath); err == nil {
			return true
		}
		if !k.sleep(time.Second) {
			return false
		}
	}
}

// childLoop: `jarvis-machine supervisor FLAG` in its own session, started again (backoff 1 s … maxBackoff) until the
// machine stops; *slot holds the running process
func (k *keeperT) childLoop(name, flag string, maxBackoff time.Duration, prep func(*exec.Cmd), slot **os.Process) {
	backoff := time.Second
	for !k.isStopping() {
		started := time.Now()
		cmd := exec.Command("/proc/self/exe", "supervisor", flag)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		cmd.Env = os.Environ()
		if prep != nil {
			prep(cmd)
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		var err error
		if err = cmd.Start(); err != nil {
			log.Printf("%s: %v", name, err)
		} else {
			k.mu.Lock()
			*slot = cmd.Process
			if k.stopping && flag == "--core" { // the teardown began while it started: it gets the signal the teardown sent the last one
				cmd.Process.Signal(syscall.SIGUSR1)
			}
			k.mu.Unlock()
			err = cmd.Wait()
			k.mu.Lock()
			*slot = nil
			k.mu.Unlock()
		}
		if k.isStopping() {
			log.Printf("%s ended (%s)", name, exitText(err))
			return
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		log.Printf("%s exited (%s); starting it again in %s", name, exitText(err), backoff)
		if !k.sleep(backoff) {
			return
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// harnessLoop: the harness (Jarvis 1's entrypoint, then harness-*.sh), as user claude in its own session, started
// again whenever it ends
func (k *keeperT) harnessLoop(spec harnessSpec) {
	backoff := harnessBackoff0
	for n := 1; ; n++ {
		if k.isStopping() {
			return
		}
		if _, err := os.Stat(finalSnapshotSig); err == nil && n > 1 {
			log.Printf("the session is stopped for its final snapshot: the harness isn't started again")
			return
		}
		env := append(spec.env(k.secretsFn()), "JARVIS_HARNESS_START="+strconv.Itoa(n))
		cmd := sessionCommand(nil, baseEntry)
		cmd.Env = env
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		out, perr := harnessStdout(k.harnessLog()) // harnesslog.go: its tagged lines also go to the supervisor log
		if perr == nil {
			cmd.Stdout, cmd.Stderr = out, out
		}
		if fi, err := os.Stat(session().home); err == nil && fi.IsDir() {
			cmd.Dir = session().home
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // its own session and process group, never the keeper's
		k.mu.Lock()
		if k.stopping {
			k.mu.Unlock()
			return
		}
		err := cmd.Start()
		if err == nil {
			k.harness = cmd
		}
		k.mu.Unlock()
		if perr == nil {
			out.Close() // the harness holds it now; the reader ends once the harness and its loops are gone
		}
		env = nil
		if err != nil {
			log.Printf("the harness didn't start: %v; trying again in %s", err, backoff)
			if !k.sleep(backoff) {
				return
			}
			backoff = min(2*backoff, harnessBackoffMax)
			continue
		}
		pid := cmd.Process.Pid
		writeHarnessPID(pid)
		started := time.Now()
		k.setState(func(s *harnessState) {
			s.Starts, s.Running, s.PID, s.StartedAt, s.NextStart = n, true, pid, started.UTC().Format(time.RFC3339), ""
		})
		if n == 1 {
			log.Printf("harness started (pid %d)", pid)
		} else {
			log.Printf("harness started again (start %d, pid %d): the same conversation resumes", n, pid)
		}
		werr := cmd.Wait()
		up := time.Since(started)
		how := exitHow(werr, cmd.ProcessState)
		k.mu.Lock()
		k.harness = nil
		stopping := k.stopping
		k.mu.Unlock()
		k.killGroup(pid) // what is left of its process group (its loops, an api-proxy): the next start brings its own
		k.setState(func(s *harnessState) {
			s.Running, s.PID, s.LastExit, s.LastExitAt, s.LastUpSecs = false, 0, how, time.Now().UTC().Format(time.RFC3339), int64(up.Seconds())
		})
		if stopping {
			log.Printf("harness ended (%s) after %s", how, up.Round(time.Second))
			return
		}
		if up > harnessStable {
			backoff = harnessBackoff0
		}
		k.setState(func(s *harnessState) { s.NextStart = time.Now().Add(backoff).UTC().Format(time.RFC3339) })
		log.Printf("HARNESS ENDED (%s) after %s (start %d, pid %d); the machine stays up; starting it again in %s", how, up.Round(time.Second), n, pid, backoff)
		if !k.sleep(backoff) {
			return
		}
		backoff = min(2*backoff, harnessBackoffMax)
	}
}

// secrets: what the supervisor holds now, for the harness's env (boot-env, answered to the keeper only: secrets.go)
func (k *keeperT) secrets() map[string]string {
	r, err := askSecrets(secretsReq{Op: "boot-env"}, time.Minute)
	if err != nil {
		log.Printf("the harness starts without secrets: %v", err)
		return nil
	}
	return r.Secrets
}

// exitHow: how a process ended, in words: "exit status 1", "killed by SIGTERM", …
func exitHow(err error, ps *os.ProcessState) string {
	if ps != nil {
		if ws, ok := ps.Sys().(syscall.WaitStatus); ok {
			switch {
			case ws.Signaled():
				return "killed by " + signalName(ws.Signal())
			case ws.Exited():
				return fmt.Sprintf("exit status %d", ws.ExitStatus())
			}
		}
	}
	return exitText(err)
}

func signalName(s syscall.Signal) string {
	names := map[syscall.Signal]string{syscall.SIGTERM: "SIGTERM", syscall.SIGKILL: "SIGKILL", syscall.SIGINT: "SIGINT",
		syscall.SIGHUP: "SIGHUP", syscall.SIGQUIT: "SIGQUIT", syscall.SIGSEGV: "SIGSEGV", syscall.SIGABRT: "SIGABRT",
		syscall.SIGPIPE: "SIGPIPE", syscall.SIGUSR1: "SIGUSR1", syscall.SIGUSR2: "SIGUSR2", syscall.SIGBUS: "SIGBUS"}
	if n, ok := names[s]; ok {
		return n
	}
	return fmt.Sprintf("signal %d (%s)", int(s), s)
}

// killGroup: SIGTERM (with SIGCONT, in case it is stopped) to the process group, SIGKILL after the grace
func (k *keeperT) killGroup(pgid int) {
	if pgid <= 1 {
		return
	}
	if syscall.Kill(-pgid, syscall.SIGTERM) != nil {
		return // nothing left in it
	}
	syscall.Kill(-pgid, syscall.SIGCONT)
	for end := time.Now().Add(harnessGrace); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if syscall.Kill(-pgid, 0) != nil {
			return
		}
	}
	syscall.Kill(-pgid, syscall.SIGKILL)
}

func (k *keeperT) setState(f func(*harnessState)) {
	k.mu.Lock()
	f(&k.state)
	b, _ := json.Marshal(k.state)
	k.mu.Unlock()
	if !privileged() {
		return
	}
	tmp := harnessStatePath + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		os.Rename(tmp, harnessStatePath)
	}
}

func writeHarnessPID(pid int) {
	if !privileged() {
		return
	}
	tmp := harnessPIDPath + ".tmp"
	if os.WriteFile(tmp, []byte(strconv.Itoa(pid)), 0o644) == nil {
		os.Rename(tmp, harnessPIDPath)
	}
}

// awaitHarnessPID: the boot steps wait (at most d) until the keeper has named them in harness.pid
func awaitHarnessPID(d time.Duration) {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if harnessPID() == os.Getpid() {
			return
		}
	}
}

// readHarnessState: the keeper's harness record, for the status report (nil: none)
func readHarnessState() *harnessState {
	b, err := os.ReadFile(harnessStatePath)
	if err != nil {
		return nil
	}
	var s harnessState
	if json.Unmarshal(b, &s) != nil {
		return nil
	}
	return &s
}

// teardown: a stop signal. Most important first: supervisor-normal goes, supervisor-core uploads the transcripts that changed and then the final
// snapshot; then the harness's process group and the rest of the session are stopped; then the keeper exits (Fly
// ends the machine).
func (k *keeperT) teardown(s os.Signal) {
	log.Printf("%v: the teardown (the transcripts, then the final snapshot, then the session's processes)", s)
	start := time.Now()
	k.mu.Lock()
	k.stopping = true
	close(k.stopCh)
	w, n := k.core, k.normal
	k.mu.Unlock()
	if n != nil {
		n.Kill() // supervisor-normal holds nothing the teardown needs; it doesn't compete with it
	}
	if w != nil {
		w.Signal(syscall.SIGUSR1) // supervisor.go teardown; supervisor-core exits when it is done
	} else {
		log.Printf("no supervisor-core running (still booting, or between restarts)")
	}
	select {
	case <-k.coreEnd:
	case <-time.After(teardownMax):
		log.Printf("supervisor-core's teardown is still going after %s; going on without it", teardownMax)
		k.mu.Lock()
		if k.core != nil {
			k.core.Kill()
		}
		k.mu.Unlock()
	}
	k.mu.Lock()
	h := k.harness
	k.mu.Unlock()
	if h != nil {
		k.killGroup(h.Process.Pid)
	}
	if privileged() { // every other process of the session (kill(-1) as user claude; never as anyone else)
		if err := signalSession("CONT"); err != nil { // a frozen session: let it see the TERM
			log.Printf("%v", err)
		}
		signalSession("TERM")
		time.Sleep(time.Second)
		signalSession("KILL")
	}
	log.Printf("teardown done in %s; exiting", time.Since(start).Round(time.Millisecond))
	pushKeeperLog()
}

// pushKeeperLog: the keeper's last lines to the router (supervisor-core, which pushes the log, has ended)
func pushKeeperLog() {
	c, err := newClient()
	if err != nil {
		return
	}
	pushLogOnce(c)
}
