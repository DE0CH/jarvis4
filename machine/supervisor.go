package main

// The supervisor (docs/DESIGN.md "The supervisor and the guard"): two long-running processes that talk to the router,
// from the first second of boot to the kill, each a child of the keeper (keeper.go), started again whenever it exits
// (Deyao, 2026-10-24: the supervisor must not bloat; only the part that keeps the control plane alive is protected).
//
// supervisor-core keeps the control plane alive: whatever else fails, the router can still stop, snapshot, Upgrade,
// pause, rescue through a terminal grant, and the teardown still uploads. Its memory is pinned (oomguard.go) and the
// OOM killer leaves it alone (oom_score_adj -1000, the keeper's, inherited). Its components:
//
//	component                  file              guarded  what it does
//	the guard                  guard.go          —        checks execs and deliveries; lets through only what is vouched for
//	commands and deliveries    supervisor.go     execs, deliveries: yes; commands: no
//	                                                      reads /m/commands for the machine's life: execs (a router
//	                                                      feature's shell command, with its grant) and deliveries
//	                                                      (prompts into the harness) through the guard; the one-word
//	                                                      commands below run as they are
//	snapshot and freeze        snapstream.go,    no       the final snapshot (pause, destroy): the session stopped,
//	                           main.go                    the state taken, signed once; "nothing to snapshot" or the
//	                                                      predecessor's while booting; free before an Upgrade (memory.go)
//	teardown                   teardown.go       no       a stop signal: the changed transcripts, then the final snapshot
//	Claude pause and resume    supervisor.go     no       pause-harness / resume-harness: SIGSTOP / SIGCONT the Claude
//	                                                      process (launcher, tmux panes, their children); the freeze
//	                                                      starts with it
//	log                        supervisorlog.go  no       the supervisor log (both processes'), pushed to the router
//	secrets                    secrets.go,       no       pulls the cert's stores from the core, holds them in RAM
//	                           deploykeys.go              (never on disk) and serves them over its socket, every
//	                                                      request logged; the deploy keys in its ssh-agent;
//	                                                      refresh-secrets pulls again (putkey.go)
//
// supervisor-normal does the rest, none of which the control plane needs: no pinned memory, the default OOM score, in
// the session's memory cgroup, so a session that fills the machine may take it down and the keeper starts it again.
// Its components:
//
//	worker count               workers.go        no       subagents and background jobs, from the harness hook's
//	                                                      notifications (a count, never a command)
//	screen                     screen.go         no       the harness's pane for the read-only terminal (output only)
//	stall watchdog             stall.go          no       a nudge into its harness after 15 idle minutes with jobs
//	status, memory, disk       status.go,        no       the reports the router's card and watches read (output only)
//	                           memory.go, disk.go
//	API proxy                  apiproxy.go       —        $JARVIS_URL for the session's scripts, signed as this machine
//	live transcript sync       livesync.go       no       the transcripts to the Storage Box for search (output only)
//	Claude login sync          claudelogin.go    no       the session's Claude pair kept in step with the router's
//
// Both run as root with user claude's file access; the session (user claude) can't signal them. What either starts
// for the session (exec commands, the text into the harness, a watch's check, git, tmux) goes through sessionCommand:
// user claude, back at the default OOM score. A stop signal reaches the keeper, which kills supervisor-normal and asks
// supervisor-core for the teardown (SIGUSR1).

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const oomProtected = "-1000"

var harnessPausedPath = dir + "/harness-paused" // the pids pause-harness stopped, for resume-harness

func exitText(err error) string {
	if err == nil {
		return "exit 0"
	}
	return err.Error()
}

// superviseCore: supervisor-core, what keeps the control plane alive: the commands (stop, snapshot, Upgrade, pause),
// execs and deliveries through the guard, the secrets and deploy keys, the supervisor log and the teardown's uploads. While the machine boots it answers a snapshot with the predecessor's (or "nothing to
// snapshot"). Its memory is pinned and the OOM killer leaves it alone.
func superviseCore() error {
	logToSupervisorLog()
	if privileged() {
		lockMemory("supervisor-core")               // oomguard.go: mlock isn't inherited from the keeper
		if err := sessionFileAccess(); err != nil { // keeper.go: user claude's file access, root's uid
			return fmt.Errorf("supervisor-core's file access: %w", err)
		}
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)
	go func() { // the keeper's teardown (a stop signal): upload, most important first, then end
		<-usr1
		teardown(c)
		os.Exit(0)
	}()
	if _, _, err := finalSnapshotSum(); err == nil {
		frozen.Store(true) // an earlier supervisor-core of this machine took the final snapshot: nothing guarded runs again
	}
	held.loadHeld()         // secrets.go: what an earlier supervisor-core held
	go serveSecrets(c)      // secrets.go: the session's secrets, RAM only
	go serveSSHAgent()      // deploykeys.go: the deploy keys, RAM only
	go pushSupervisorLog(c) // supervisorlog.go
	log.Printf("supervisor-core up (pid %d)", os.Getpid())
	for {
		var out struct {
			Commands   []string   `json:"commands"`
			Execs      []Exec     `json:"execs"`
			Deliveries []Delivery `json:"deliveries"` // deliver.go: vouched, core-attested inputs
		}
		if err := c.json("GET", "/m/commands", nil, &out); err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		for _, e := range out.Execs { // guarded (guard.go guardExec)
			go runExec(c, e)
		}
		for _, d := range out.Deliveries { // guarded (guard.go guardDelivery)
			go runDelivery(c, d)
		}
		for _, cmd := range out.Commands {
			runCommand(c, cmd)
		}
	}
}

// superviseNormal: supervisor-normal, everything that can go missing for a while without losing the machine: the
// reports, the read-only terminal's pane, the stall watchdog, the worker count, the API proxy, the live transcript
// sync and the Claude login sync. No pinned memory and no OOM protection: it runs in the session's memory cgroup, and
// when it dies the keeper starts it again; supervisor-core never waits on it.
func superviseNormal() error {
	logToSupervisorLog()
	if privileged() {
		os.WriteFile("/proc/self/oom_score_adj", []byte("0\n"), 0o644) // the keeper's -1000 is for supervisor-core only
		joinCgroup(sessionCgroup)                                      // oomguard.go: charged with the session
		if err := sessionFileAccess(); err != nil {
			return fmt.Errorf("supervisor-normal's file access: %w", err)
		}
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	workers = newWorkerCount(workersState)
	go serveWorkerCount(workers) // workers.go: the hook's notifications
	for !booted() {
		time.Sleep(time.Second)
	}
	go statusReporter(c)        // status.go
	go memoryReporter(c)        // memory.go: RAM for the router's starvation watch
	go diskReporter(c)          // disk.go: the root disk and the volume, for the router's low-disk warning
	go screenReporter(c)        // screen.go: the pane for the read-only terminal
	go stallWatch()             // stall.go: the 15-minute watchdog on its own harness
	go serveAPIProxy(c)         // apiproxy.go: $JARVIS_URL for the session scripts
	go liveSync(c)              // livesync.go: the transcripts to the Storage Box (through the router) for search
	go startCredsSyncOnMarker() // claudelogin.go: the Claude login sync, once boot (or an account switch) leaves its marker
	log.Printf("supervisor-normal up (pid %d)", os.Getpid())
	select {}
}

// runCommand: the unguarded commands, which carry no instruction (a word each)
func runCommand(c *client, cmd string) {
	switch cmd {
	case "free": // memory.go: an Upgrade, before its snapshot
		if booted() && !frozen.Load() {
			log.Printf("free: stopping the session's processes for an Upgrade")
			freeMemory()
		}
	case "refresh-secrets": // putkey.go: an unlock for this cert went through
		if booted() {
			go refreshFromRouter(c)
		}
	case "claude-account": // claudelogin.go: the router switched the session's Claude account
		if booted() && !frozen.Load() {
			claudeAccountCmd()
		}
	case "pause-harness":
		if err := pauseHarness(); err != nil {
			log.Printf("pause-harness: %v", err)
		}
	case "resume-harness":
		if frozen.Load() {
			log.Printf("resume-harness refused: the session is stopped for its final snapshot")
		} else if err := resumeHarness(); err != nil {
			log.Printf("resume-harness: %v", err)
		}
	case "snapshot":
		if !booted() {
			if err := bootingSnapshot(c); err != nil { // snapstream.go: the predecessor's, carried over
				log.Printf("answering the snapshot while booting: %v", err)
			}
		} else if err := uploadSnapshot(c); err != nil {
			log.Printf("snapshot failed: %v", err)
			reportSnapshotFailed(c, err) // snapstream.go: the pause stops waiting, and nothing is lost
		}
	default:
		log.Printf("unknown command %q ignored", clip(cmd, 40))
	}
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ---- the Claude process: pause and resume -----------------------------------------------------------------

// harnessPID: the harness's launcher (the keeper names it: keeper.go), or the boot steps while booting
func harnessPID() int {
	s, _ := readTrim(harnessPIDPath)
	n, _ := strconv.Atoi(s)
	return n
}

// keeperPID: the keeper (the supervisors' parent), never stopped or killed by the supervisor itself
func keeperPID() int { return os.Getppid() }

// children: pid → its children, from /proc
var children = func() map[int][]int {
	out := map[int][]int{}
	ents, _ := os.ReadDir(procRoot)
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "stat"))
		if err != nil {
			continue
		}
		// pid (comm) state ppid …: comm may hold spaces and parentheses, so cut at the last ')'
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 2 {
			continue
		}
		ppid, _ := strconv.Atoi(f[1])
		out[ppid] = append(out[ppid], pid)
	}
	return out
}

// tmuxPanes: the pid of every pane's process (the Claude host runs in tmux session `claude`, whose server is not a
// child of the launcher)
var tmuxPanes = func() []int {
	out, err := sessionCommand(nil, "tmux", "list-panes", "-a", "-F", "#{pane_pid}").Output()
	if err != nil {
		return nil
	}
	var pids []int
	for _, l := range strings.Fields(string(out)) {
		if n, err := strconv.Atoi(l); err == nil {
			pids = append(pids, n)
		}
	}
	return pids
}

// harnessTree: the launcher, every tmux pane's process and all their descendants, parents first; never the
// supervisor (either half, or the keeper) or pid 1
func harnessTree() []int {
	kids := children()
	skip := map[int]bool{os.Getpid(): true, keeperPID(): true, 1: true, 0: true}
	seen := map[int]bool{}
	var order []int
	var walk func(int)
	walk = func(p int) {
		if seen[p] || skip[p] {
			return
		}
		seen[p] = true
		order = append(order, p)
		k := append([]int(nil), kids[p]...)
		sort.Ints(k)
		for _, c := range k {
			walk(c)
		}
	}
	if h := harnessPID(); h > 1 {
		walk(h)
	}
	for _, p := range tmuxPanes() {
		walk(p)
	}
	return order
}

// pauseHarness: SIGSTOP the Claude process (its launcher, the tmux panes and everything under them), parents first
// so nothing restarts a stopped child; the stopped pids are kept for resumeHarness
func pauseHarness() error {
	pids := harnessTree()
	if len(pids) == 0 {
		return errors.New("no harness process found")
	}
	stopped := []string{}
	for _, p := range pids {
		if signalProc(p, syscall.SIGSTOP) == nil {
			stopped = append(stopped, strconv.Itoa(p))
		}
	}
	if err := os.WriteFile(harnessPausedPath, []byte(strings.Join(stopped, "\n")), 0o600); err != nil {
		return err
	}
	log.Printf("pause-harness: stopped the Claude process (%d processes)", len(stopped))
	return nil
}

// resumeHarness: SIGCONT what pauseHarness stopped, children first
func resumeHarness() error {
	b, err := os.ReadFile(harnessPausedPath)
	if err != nil {
		return errors.New("the harness isn't paused")
	}
	pids := strings.Fields(string(b))
	n := 0
	for i := len(pids) - 1; i >= 0; i-- {
		if p, err := strconv.Atoi(pids[i]); err == nil && signalProc(p, syscall.SIGCONT) == nil {
			n++
		}
	}
	os.Remove(harnessPausedPath)
	log.Printf("resume-harness: let the Claude process go on (%d processes)", n)
	return nil
}

// ---- the whole session, for the final snapshot -------------------------------------------------------------

// freezeSession: the Claude process first (pauseHarness), then SIGSTOP to every other process of user claude
// (signalSession: never root's, so never the keeper or the supervisors). Only on a Fly machine.
var freezeSession = func() {
	if os.Getenv("FLY_MACHINE_ID") == "" {
		return
	}
	if err := pauseHarness(); err != nil {
		log.Printf("freezing the session: %v", err)
	}
	if err := signalSession("STOP"); err != nil {
		log.Printf("freezing the session: %v", err)
	}
	log.Printf("session stopped for the final snapshot")
}

// thawSession: SIGCONT to the session (the counterpart of freezeSession, after a failed snapshot); only on a Fly
// machine
var thawSession = func() {
	if os.Getenv("FLY_MACHINE_ID") == "" {
		return
	}
	if err := signalSession("CONT"); err != nil {
		log.Printf("thawing the session: %v", err)
	}
	os.Remove(harnessPausedPath)
	log.Printf("session let go on")
}
