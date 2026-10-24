package main

// Memory for the control plane (DECISIONS 221; Deyao, 2026-10-22: "only the supervisor needs to be protected, the rest
// dont matter", "The point is to keep control plane alive so we still can send restart command and also terminal grant
// to rescue"). oom_score_adj -1000 (keeper.go) keeps the OOM killer off the supervisor, but it doesn't stop the session
// from filling the machine: session s940709ec6ffdba71 ("YYC news monitor") reached 229 MB free of 3.8 GB on 2026-10-22
// 04:21, the machine (no swap) thrashed without the OOM killer ever running, and from 04:24 the router heard nothing,
// so no snapshot, Upgrade, pause or terminal command could reach it. Three guards:
//
//   - The session's memory cgroup: at boot the keeper makes sessionCgroup (cgroup v1 memory, root's) with
//     memory.limit_in_bytes = MemTotal - sessionReserve, and `unprotected` moves itself into it before it drops to
//     user claude, so everything the session runs (the boot steps, the harness, claude, its agents and browsers) is
//     charged there and its children inherit it. At the limit the kernel reclaims and OOM-kills inside the cgroup
//     only. Nothing is killed early: what the session does inside its limit is the session's own business.
//   - The rescue cgroup: `unprotected --rescue` (rescueCommand: a grant's exec such as the terminal holder's, the
//     status and screen readers) joins rescueCgroup instead, with its own limit (rescueLimit), so a rescue command
//     (kill the hog, restart Claude) runs with memory to spare on a machine the session has filled, and a runaway
//     rescue command can't fill it either. What it leaves running stays there (a Claude restarted through tmux runs
//     under the tmux server, in the session's cgroup).
//   - The supervisor's own pages pinned: the keeper and supervisor-core each mlockall(MCL_CURRENT|MCL_FUTURE|MCL_ONFAULT)
//     (with RLIMIT_MEMLOCK raised, as root), so their code is never dropped and read back from disk under pressure.
//     MCL_ONFAULT locks pages as they are touched, so the Go runtime's reserved arenas aren't filled in up front.
//     Locks aren't inherited across fork/exec: what they start is unlocked.
//
// What neither cgroup may take (sessionReserve - rescueLimit, 256 MB) is for the supervisor (27 MB measured: keeper
// 11, supervisor-core 16, before supervisor-normal was split off), Fly's init and hallpass, and the kernel (the network stack the reports go out on, the page cache of
// a snapshot). Only on a Fly machine as root, like protectFromOOM; a failure is logged and the machine boots without.

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

var (
	sessionCgroup  = "/sys/fs/cgroup/memory/jarvis-session"
	rescueCgroup   = "/sys/fs/cgroup/memory/jarvis-rescue"
	sessionReserve = int64(640 << 20) // bytes kept outside the session's limit
	rescueMax      = int64(384 << 20) // the rescue cgroup's limit (of the reserve)
)

// MCL_ONFAULT (linux/mman.h) and RLIMIT_MEMLOCK (asm-generic/resource.h), which package syscall doesn't name
const (
	mclOnfault    = 4
	rlimitMemlock = 8
)

// sessionLimit: the session cgroup's limit for a machine of totalKb (MemTotal), never under half the machine
func sessionLimit(totalKb int64) int64 {
	total := totalKb << 10
	return max(total-sessionReserve, total/2)
}

// rescueLimit: the rescue cgroup's, never over a quarter of the machine
func rescueLimit(totalKb int64) int64 {
	return min(rescueMax, (totalKb<<10)/4)
}

// makeCgroups: the keeper's, at boot (before the boot steps start)
var makeCgroups = func() {
	if os.Getenv("FLY_MACHINE_ID") == "" {
		return
	}
	if err := setupCgroups(); err != nil {
		log.Printf("memory limits: %v (the session can fill the machine)", err)
	}
}

func setupCgroups() error {
	s, err := readMemory()
	if err != nil {
		return err
	}
	for _, g := range []struct {
		dir   string
		limit int64
	}{{sessionCgroup, sessionLimit(s.TotalKb)}, {rescueCgroup, rescueLimit(s.TotalKb)}} {
		if err := os.MkdirAll(g.dir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(g.dir, "memory.limit_in_bytes"), []byte(strconv.FormatInt(g.limit, 10)), 0o644); err != nil {
			return fmt.Errorf("%s: %w", g.dir, err)
		}
		log.Printf("memory limit %d MB of %d MB for %s", g.limit>>20, s.TotalKb>>10, g.dir)
	}
	return nil
}

// joinCgroup: `unprotected`, as root before it drops: this process (and so everything it execs and starts) into
// the cgroup dir. No cgroup (not a Fly machine, a failed setup) = nothing to join.
func joinCgroup(dir string) {
	procs := filepath.Join(dir, "cgroup.procs")
	if _, err := os.Stat(procs); err != nil {
		return
	}
	if err := os.WriteFile(procs, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		log.Printf("memory limit: joining %s: %v", dir, err)
	}
}

// lockMemory: this process's pages stay in RAM (the keeper at boot, supervisor-core as it starts)
var lockMemory = func(who string) {
	if os.Getenv("FLY_MACHINE_ID") == "" {
		return
	}
	if err := mlockAll(); err != nil {
		log.Printf("%s: locking its memory: %v", who, err)
		return
	}
	log.Printf("%s: memory locked in RAM", who)
}

func mlockAll() error {
	inf := &syscall.Rlimit{Cur: ^uint64(0), Max: ^uint64(0)}
	if err := syscall.Setrlimit(rlimitMemlock, inf); err != nil {
		return fmt.Errorf("RLIMIT_MEMLOCK: %w", err)
	}
	return syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE | mclOnfault)
}
