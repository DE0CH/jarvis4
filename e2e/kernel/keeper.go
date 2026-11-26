package main

// On real Fly only (not the fabric: its machines are gVisor sandboxes, with no Fly exec and their own process model):
// the keeper (rust/machine/src/keeper.rs, DECISIONS 218), memory for the supervisor (rust/machine/src/oomguard.rs),
// the router's drain on a rollout (rust/router/src/drain.rs) and the machine's teardown on a stop signal
// (rust/machine/src/teardown.rs). Moved here from the old core's e2e (Deyao, 2026-11-26), which went with the Go router.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// flyExec: a command on a Fly machine through the Machines API (the run's own org token)
func flyExec(m string, cmd []string) (string, int, error) {
	body, _ := json.Marshal(map[string]any{"command": cmd, "timeout": 60})
	req, _ := http.NewRequest("POST", "https://api.machines.dev/v1/apps/jarvis4-sessions/machines/"+m+"/exec", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+os.Getenv("E2E_FLY_TOKEN"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", -1, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", -1, fmt.Errorf("HTTP %d %s", resp.StatusCode, b)
	}
	var out struct {
		Stdout   string `json:"stdout"`
		ExitCode int    `json:"exit_code"`
	}
	json.Unmarshal(b, &out)
	return out.Stdout, out.ExitCode, nil
}

// expectOnMachine: exit 0 and stdout (trimmed) exactly want, within ten tries
func expectOnMachine(m, cmd, want string) {
	var out string
	var code int
	var err error
	for i := 0; i < 10; i++ {
		out, code, err = flyExec(m, []string{"sh", "-c", cmd})
		if err == nil && code == 0 && strings.TrimSpace(out) == want {
			log.Printf("   on %s: %q → %q ok", m, cmd, want)
			return
		}
		time.Sleep(5 * time.Second)
	}
	log.Fatalf("on %s, %q gave %q (exit %d, %v), want %q", m, cmd, out, code, err, want)
}

// lastReport: when the machine last reported its status (the router's record)
func lastReport(id string) string {
	s, _ := readSession(id)
	if s == nil || s.Live == nil {
		return ""
	}
	return s.Live.LastReport
}

// waitReport: a status report newer than before
func waitReport(id, before, after string) {
	waitFor("a status report from the machine after "+after, 90*time.Second, func() bool {
		lr := lastReport(id)
		return lr != "" && lr != before
	})
}

// keeperStep: on a running session's machine m
func keeperStep(id, m string) {
	step("the keeper: Fly's main child is jarvis-machine boot as root; supervisor-core and supervisor-normal are root; the harness is claude's, in its own session")
	expectOnMachine(m, "k=$(pgrep -o -f 'jarvis-machine boot'); ps -o user=,ppid= -p $k | awk '{print $1, $2}'", "root 1")
	expectOnMachine(m, "ps -o user= -p $(pgrep -o -f 'supervisor --core')", "root")
	expectOnMachine(m, "ps -o user= -p $(pgrep -o -f 'supervisor --normal')", "root")
	expectOnMachine(m, "h=$(cat /run/jarvis-keeper/harness.pid); ps -o user=,sid= -p $h | awk -v h=$h '{print $1, ($2==h)}'", "claude 1")
	expectOnMachine(m, "cat /proc/$(pgrep -o -f 'jarvis-machine boot')/oom_score_adj /proc/$(pgrep -o -f 'supervisor --core')/oom_score_adj", "-1000\n-1000")

	step("memory for the supervisor: the session is under a memory limit below the machine's RAM, the rescue path under its own; the keeper's and supervisor-core's pages are locked, supervisor-normal is unprotected in the session's cgroup; a session hog over the limit is killed inside it and the supervisor reports on")
	expectOnMachine(m, "G=/sys/fs/cgroup/memory/jarvis-session; t=$(awk '/MemTotal/{print $2*1024}' /proc/meminfo); l=$(cat $G/memory.limit_in_bytes); "+
		"[ $l -lt $t ] && [ $((t-l)) -ge $((512<<20)) ] && echo limited", "limited")
	expectOnMachine(m, "R=/sys/fs/cgroup/memory/jarvis-rescue; [ $(cat $R/memory.limit_in_bytes) -le $((384<<20)) ] && echo limited", "limited")
	expectOnMachine(m, "/usr/local/bin/jarvis-machine unprotected --rescue -- cat /proc/self/cgroup | grep -o ':memory:.*'", ":memory:/jarvis-rescue")
	expectOnMachine(m, "G=/sys/fs/cgroup/memory/jarvis-session; grep -qx $(cat /run/jarvis-keeper/harness.pid) $G/cgroup.procs && echo in", "in")
	expectOnMachine(m, "for p in $(pgrep -o -f 'jarvis-machine boot') $(pgrep -o -f 'supervisor --core'); do awk '/VmLck/{print ($2>0)}' /proc/$p/status; done", "1\n1")
	expectOnMachine(m, "G=/sys/fs/cgroup/memory/jarvis-session; grep -qx $(pgrep -o -f 'supervisor --core') $G/cgroup.procs && echo in || echo out", "out")
	expectOnMachine(m, "N=$(pgrep -o -f 'supervisor --normal'); G=/sys/fs/cgroup/memory/jarvis-session; grep -qx $N $G/cgroup.procs && echo in; cat /proc/$N/oom_score_adj; awk '/VmLck/{print ($2>0)}' /proc/$N/status", "in\n0\n0")
	hogBefore := lastReport(id)
	expectOnMachine(m, "/usr/local/bin/jarvis-machine unprotected -- python3 -c 'a=[]\nwhile True: a.append(b\"x\"*(64<<20))' >/dev/null 2>&1; echo $?", "137")
	waitReport(id, hogBefore, "the session's hog")

	step("the session can't touch the supervisor: kill, pkill -f, a group kill, its OOM score and its environ all fail as claude")
	for _, c := range []string{
		"kill -TERM $K", "kill -KILL $K", "kill -TERM -$K", "kill -TERM $W", "kill -STOP $W",
		"echo 1000 > /proc/$K/oom_score_adj", "cat /proc/$W/environ",
	} {
		expectOnMachine(m, "K=$(pgrep -o -f 'jarvis-machine boot'); W=$(pgrep -o -f 'supervisor --core'); "+
			"su claude -s /bin/sh -c \""+c+"\" >/dev/null 2>&1 && echo worked || echo refused", "refused")
	}
	expectOnMachine(m, "K=$(pgrep -o -f 'jarvis-machine boot'); su claude -s /bin/sh -c 'pkill -f jarvis-machine'; sleep 1; kill -0 $K && pgrep -f 'supervisor --core' >/dev/null && echo up", "up")

	step("the incident of 2026-10-21: a session process SIGTERMs the harness's launcher → the machine stays up, the harness starts again")
	expectOnMachine(m, "su claude -s /bin/sh -c 'kill -TERM $(cat /run/jarvis-keeper/harness.pid)' && echo sent", "sent")
	expectOnMachine(m, "for i in $(seq 1 40); do grep -q '\"starts\":2,\"running\":true' /run/jarvis-keeper/harness.json && break; sleep 1; done; "+
		"grep -o '\"starts\":[0-9]*,\"running\":true' /run/jarvis-keeper/harness.json; grep -o '\"lastExit\":\"[^\"]*\"' /run/jarvis-keeper/harness.json",
		"\"starts\":2,\"running\":true\n\"lastExit\":\"killed by SIGTERM\"")
	expectOnMachine(m, "grep -c 'HARNESS ENDED (killed by SIGTERM)' /run/jarvis/supervisor.log", "1")

	step("kill -TERM -1 as claude: every session process ends, the keeper and the supervisors don't; the harness starts again")
	expectOnMachine(m, "su claude -s /bin/sh -c 'kill -TERM -1'; sleep 2; pgrep -o -f 'jarvis-machine boot' >/dev/null && pgrep -f 'supervisor --core' >/dev/null && echo up", "up")
	expectOnMachine(m, "for i in $(seq 1 60); do grep -q '\"starts\":3,\"running\":true' /run/jarvis-keeper/harness.json && break; sleep 1; done; "+
		"grep -o '\"starts\":[0-9]*,\"running\":true' /run/jarvis-keeper/harness.json", "\"starts\":3,\"running\":true")

	step("supervisor-normal dies (as a full session's OOM kill would end it): supervisor-core carries on, the keeper starts it again")
	expectOnMachine(m, "C=$(pgrep -o -f 'supervisor --core'); N=$(pgrep -o -f 'supervisor --normal'); kill -KILL $N; "+
		"for i in $(seq 1 20); do M=$(pgrep -o -f 'supervisor --normal'); [ -n \"$M\" ] && [ \"$M\" != $N ] && break; sleep 1; done; "+
		"[ \"$(pgrep -o -f 'supervisor --core')\" = $C ] && [ -n \"$M\" ] && [ \"$M\" != $N ] && echo restarted", "restarted")
	waitReport(id, lastReport(id), "the harness restarts") // supervisor-normal reports on through it all
}

// routerPID: the router's own process (E2E_ROUTER_BIN, not its m-gateway), as rust/e2e-kernel started it
func routerPID() int {
	bin := os.Getenv("E2E_ROUTER_BIN")
	ps, _ := filepath.Glob("/proc/[0-9]*")
	for _, p := range ps {
		if exe, _ := os.Readlink(p + "/exe"); exe != bin {
			continue
		}
		if cl, _ := os.ReadFile(p + "/cmdline"); strings.Contains(string(cl), "m-gateway") {
			continue
		}
		var pid int
		fmt.Sscan(filepath.Base(p), &pid)
		return pid
	}
	return 0
}

// drainPause: a router rollout while a pause is in flight. SIGTERM reaches the router right after the pause began: it
// goes on serving reads and the machine's snapshot, refuses a new action with 503 "router updating, try again shortly",
// lets the pause finish, then exits on its own; rust/e2e-kernel starts the next router, which finds the session paused
func drainPause(id string) {
	step("drain: SIGTERM with a pause in flight → reads served, new actions 503, the pause finishes, then the router exits and the next one takes over")
	pid := routerPID()
	if pid == 0 {
		log.Fatal("drain: no router process (E2E_ROUTER_BIN)")
	}
	must("POST", router+"/api/sessions/"+id+"/pause", map[string]any{}, nil)
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		log.Fatalf("SIGTERM to the router: %v", err)
	}
	if code, b := call("GET", router+"/api/state", nil); code != 200 {
		log.Fatalf("GET /api/state during the drain: %d %s", code, b)
	}
	code, b := call("POST", router+"/api/sessions/"+id+"/destroy", map[string]any{})
	if code != 503 || !strings.Contains(string(b), "router updating, try again shortly") {
		log.Fatalf("a new action during the drain: %d %s", code, b)
	}
	waitFor("the draining router to exit", 15*time.Minute, func() bool { return syscall.Kill(pid, 0) != nil })
	lb, _ := os.ReadFile(os.Getenv("E2E_ROUTER_LOG"))
	if !strings.Contains(string(lb), "drained") {
		log.Fatal("the router's log has no \"drained\"")
	}
	waitFor("the next router", 2*time.Minute, func() bool {
		if p := routerPID(); p == 0 || p == pid {
			return false
		}
		code, _ := callQuiet("GET", router+"/api/kernel")
		return code == 200
	})
	s, _ := readSession(id)
	if s == nil || s.State != "paused" {
		log.Fatalf("the in-flight pause ended %+v", s)
	}
}

// callQuiet: call, with a connection error as status 0 (a router not up yet)
func callQuiet(method, url string) (int, []byte) {
	req, _ := http.NewRequest(method, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// teardownStep: a stop signal to Fly's main child on machine m, as Fly's stop sends it → the changed transcripts reach
// the router first, then the final snapshot, committed, then the keeper exits; returns the transcript line written,
// for the resume to find
func teardownStep(id, m string) (file, line string) {
	step("a stop signal to Fly's main child: the transcript tail first, then the final snapshot, then the keeper's exit")
	tag := fmt.Sprintf("%x", time.Now().UnixNano())
	file = "/home/claude/.claude/projects/-e2e/0e2e0000-2222-4333-8444-" + tag[len(tag)-12:] + ".jsonl"
	line = "e2e tail " + tag
	expectOnMachine(m, "mkdir -p /home/claude/.claude/projects/-e2e && echo '{\"type\":\"user\",\"message\":{\"content\":\""+line+"\"}}' > "+file+
		" && chown -R claude /home/claude/.claude && kill -TERM $(pgrep -o -f 'jarvis-machine boot') && echo sent", "sent")
	waitFor("the teardown's log", 5*time.Minute, func() bool {
		var ev struct {
			Events []struct{ Text string } `json:"events"`
		}
		code, b := call("GET", router+"/api/sessions/"+id+"/events", nil)
		if code != 200 || json.Unmarshal(b, &ev) != nil {
			return false
		}
		var tail, committed, done bool
		for _, l := range ev.Events {
			tail = tail || strings.Contains(l.Text, "teardown 1/2:")
			committed = committed || strings.Contains(l.Text, "snapshot streamed and committed")
			done = done || strings.Contains(l.Text, "teardown done")
		}
		return tail && committed && done
	})
	return file, line
}
