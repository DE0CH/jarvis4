package main

// The keeper (machine/keeper.go, DECISIONS 218): jarvis-machine boot is Fly's main child for the machine's life,
// as root; the session (user claude) can't signal it or the supervisor's worker; a dead harness is started again with
// the machine staying up; a stop signal to the main child uploads the transcript tail, then the final snapshot.

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// keeperStep: on a running session's machine m
func keeperStep(id, m string) {
	step("the keeper: Fly's main child is jarvis-machine boot as root; supervisor-core and supervisor-normal are root; the harness is claude's, in its own session")
	expectOnMachine(m, "k=$(pgrep -o -f 'jarvis-machine boot'); ps -o user=,ppid= -p $k | awk '{print $1, $2}'", "root 1")
	expectOnMachine(m, "ps -o user= -p $(pgrep -o -f 'supervisor --core')", "root")
	expectOnMachine(m, "ps -o user= -p $(pgrep -o -f 'supervisor --normal')", "root")
	expectOnMachine(m, "h=$(cat /run/jarvis-keeper/harness.pid); ps -o user=,sid= -p $h | awk -v h=$h '{print $1, ($2==h)}'", "claude 1")
	expectOnMachine(m, "cat /proc/$(pgrep -o -f 'jarvis-machine boot')/oom_score_adj /proc/$(pgrep -o -f 'supervisor --core')/oom_score_adj", "-1000\n-1000")

	step("memory for the supervisor (machine/oomguard.go): the session is under a memory limit below the machine's RAM, the rescue path (terminal grants) under its own; the keeper's and supervisor-core's pages are locked, supervisor-normal is unprotected in the session's cgroup; a session hog over the limit is killed inside it and the supervisor reports on")
	expectOnMachine(m, "G=/sys/fs/cgroup/memory/jarvis-session; t=$(awk '/MemTotal/{print $2*1024}' /proc/meminfo); l=$(cat $G/memory.limit_in_bytes); "+
		"[ $l -lt $t ] && [ $((t-l)) -ge $((512<<20)) ] && echo limited", "limited")
	expectOnMachine(m, "R=/sys/fs/cgroup/memory/jarvis-rescue; [ $(cat $R/memory.limit_in_bytes) -le $((384<<20)) ] && echo limited", "limited")
	expectOnMachine(m, "/usr/local/bin/jarvis-machine unprotected --rescue -- cat /proc/self/cgroup | grep -o ':memory:.*'", ":memory:/jarvis-rescue")
	expectOnMachine(m, "G=/sys/fs/cgroup/memory/jarvis-session; for p in $(cat /run/jarvis-keeper/harness.pid) $(pgrep -o -x claude); do grep -qx $p $G/cgroup.procs && echo in; done | sort -u", "in")
	expectOnMachine(m, "for p in $(pgrep -o -f 'jarvis-machine boot') $(pgrep -o -f 'supervisor --core'); do awk '/VmLck/{print ($2>0)}' /proc/$p/status; done", "1\n1")
	expectOnMachine(m, "G=/sys/fs/cgroup/memory/jarvis-session; grep -qx $(pgrep -o -f 'supervisor --core') $G/cgroup.procs && echo in || echo out", "out")
	expectOnMachine(m, "N=$(pgrep -o -f 'supervisor --normal'); G=/sys/fs/cgroup/memory/jarvis-session; grep -qx $N $G/cgroup.procs && echo in; cat /proc/$N/oom_score_adj; awk '/VmLck/{print ($2>0)}' /proc/$N/status", "in\n0\n0")
	hogBefore, _ := session(id)["lastReport"].(string)
	expectOnMachine(m, "/usr/local/bin/jarvis-machine unprotected -- python3 -c 'a=[]\nwhile True: a.append(b\"x\"*(64<<20))' >/dev/null 2>&1; echo $?", "137")
	for i := 0; ; i++ {
		if lr, _ := session(id)["lastReport"].(string); lr != "" && lr != hogBefore {
			break
		}
		if i > 45 {
			log.Fatal("no status report from the machine after the session's hog")
		}
		time.Sleep(2 * time.Second)
	}

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
	// the status report goes on through it all (supervisor-normal reports)
	before, _ := session(id)["lastReport"].(string)
	for i := 0; ; i++ {
		if lr, _ := session(id)["lastReport"].(string); lr != "" && lr != before {
			break
		}
		if i > 45 {
			log.Fatal("no status report from the machine after the harness restarts")
		}
		time.Sleep(2 * time.Second)
	}
}

// keeperTeardownStep: a stop signal to the main child (as Fly's stop sends it) → the changed transcripts reach the
// router first, then the final snapshot, committed; the session pauses and resumes from it
func keeperTeardownStep(p *phone, secret string) {
	step("a stop signal to Fly's main child: the transcript tail first, then the final snapshot; the session resumes from it")
	s, b := call(router, "POST", "/api/sessions", map[string]any{"label": "e2e teardown", "stores": []string{}, "size": "small", "harness": "claude"}, nil)
	must(s, b, "create the teardown session")
	a := waitApproval("new-session", "")
	id := approve(p, a)
	waitState(id, "started", 6*time.Minute)
	m := machineOf(id)
	tname := "0e2e0000-2222-4333-8444-" + secret[:12] + ".jsonl"
	expectOnMachine(m, "mkdir -p /home/claude/.claude/projects/-e2e && echo '{\"type\":\"user\",\"message\":{\"content\":\"e2e tail "+secret[:8]+"\"}}' > /home/claude/.claude/projects/-e2e/"+tname+
		" && chown -R claude /home/claude/.claude && kill -TERM $(pgrep -o -f 'jarvis-machine boot') && echo sent", "sent")
	waitLiveSync(id, tname, 3*time.Minute)
	deadline := time.Now().Add(5 * time.Minute)
	for {
		var sl struct {
			Events []struct{ Source, Text string } `json:"events"`
		}
		call(router, "GET", "/api/sessions/"+id+"/events", nil, &sl)
		var tail, committed, done bool
		for _, l := range sl.Events {
			tail = tail || strings.Contains(l.Text, "teardown 1/2:")
			committed = committed || strings.Contains(l.Text, "snapshot streamed and committed")
			done = done || strings.Contains(l.Text, "keeper: teardown done")
		}
		if tail && committed && done {
			log.Printf("   the teardown: transcripts, then the snapshot, then the keeper's exit")
			break
		}
		if time.Now().After(deadline) {
			dumpState()
			log.Fatalf("the teardown's log never reached the router (tail %v, committed %v, done %v)", tail, committed, done)
		}
		time.Sleep(3 * time.Second)
	}
	if dd := os.Getenv("E2E_DATA_DIR"); dd != "" {
		if _, err := os.Stat(filepath.Join(dd, "snapshots", m+".tar.gz.sig")); err != nil {
			log.Fatalf("the router has no signed snapshot of %s after the teardown: %v", m, err)
		}
	}
	must2(call(router, "POST", "/api/sessions/"+id+"/pause", nil, nil))
	waitState(id, "paused", 12*time.Minute)
	must2(call(router, "POST", "/api/sessions/"+id+"/resume", map[string]bool{"upgrade": false}, nil))
	waitState(id, "started", 8*time.Minute)
	expectOnMachine(machineOf(id), "grep -c 'e2e tail "+secret[:8]+"' /home/claude/.claude/projects/-e2e/"+tname, "1")
	must2(call(router, "POST", "/api/sessions/"+id+"/destroy", nil, nil))
	deadline = time.Now().Add(12 * time.Minute)
	for {
		var recs struct {
			Records []map[string]any `json:"records"`
		}
		call(router, "GET", "/api/records", nil, &recs)
		if len(recs.Records) > 0 && recs.Records[0]["id"] == id {
			break
		}
		if time.Now().After(deadline) {
			log.Fatal("the teardown session's destroy didn't finish")
		}
		time.Sleep(3 * time.Second)
	}
}
