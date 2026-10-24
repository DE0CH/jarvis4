package main

// moveStep (E2E_ONLY=move): the router moves to another "box" (a second router process with its own /data, started
// by E2E_ROUTER_B_START with a MOVE_AT) while a real session machine on Fly runs, reaching the router over Fly's
// private network as production's machines do (the WireGuard peer moves with the router, router/move.go). The
// session keeps going (same machine, same boot, same supervisor); its calls through the router (the session API —
// /m/api — and a lease) are probed every 200 ms on the machine throughout; a wakeup is due inside the
// handover's gap; an app exec (a long poll on the old router, waiting for the machine's answer) is in flight at the
// freeze. Measured: the router's gap, each path's longest pause, the wakeup's lateness, how soon the machine's
// /m/commands long poll takes work again.

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

func moveStep(id, m string) {
	start := os.Getenv("E2E_ROUTER_B_START")
	routerB := os.Getenv("E2E_ROUTER_B")
	logA, logB := os.Getenv("E2E_ROUTER_LOG"), os.Getenv("E2E_ROUTER_B_LOG")
	if start == "" || routerB == "" || logB == "" {
		log.Fatal("E2E_ONLY=move needs E2E_ROUTER_B_START, E2E_ROUTER_B and E2E_ROUTER_B_LOG (infra/e2e.sh sets them)")
	}
	step("move: the session's identity before (Fly machine, boot, supervisor) and a terminal grant for the exec probe")
	ident := func() string {
		out, _, err := flyExec(m, []string{"sh", "-c", "cat /proc/sys/kernel/random/boot_id; pgrep -f harness-claude | head -1"})
		if err != nil {
			log.Fatalf("identity of %s: %v", m, err)
		}
		return strings.TrimSpace(out)
	}
	before := ident()
	expectOnMachine(m, "su - claude -c 'jarvis2 allow terminal 1h' && echo ok", "ok")
	expectExec(id, "echo before", "before")

	moveAt := time.Now().Add(75 * time.Second).Truncate(time.Second)
	step("move: router B starts as the candidate (MOVE_AT %s); the machine probes the session API and a lease every 200 ms", moveAt.UTC().Format(time.RFC3339))
	startProbe(m, id, 170)
	cmd := exec.Command(start, moveAt.UTC().Format(time.RFC3339))
	if err := cmd.Start(); err != nil {
		log.Fatalf("router B: %v", err)
	}
	waitLog(logB, "[move] candidate", time.Minute)

	step("move: a wakeup armed by the session, due 700 ms after MOVE_AT (inside the handover)")
	wakeAt := moveAt.Add(700 * time.Millisecond)
	expectOnMachine(m, sessionAPI("POST", "/api/sessions/"+id+"/wakeups", fmt.Sprintf(`{"prompt":"e2e move wake","at":%d,"name":"e2e-move"}`, wakeAt.UnixMilli()))+" | grep -c '\"ok\":true'", "1")

	// an app exec in flight at the freeze: on the old router, waiting for the machine's answer (sleep 8)
	execDone := make(chan string, 1)
	go func() {
		time.Sleep(time.Until(moveAt.Add(-2 * time.Second)))
		t0 := time.Now()
		var res struct {
			Stdout string
			Code   int
		}
		s, b := call(router, "POST", "/api/sessions/"+id+"/exec", map[string]any{"cmd": "sleep 8; echo slow", "timeout": 30}, &res)
		execDone <- fmt.Sprintf("HTTP %d after %s: %s", s, time.Since(t0).Round(time.Millisecond), strings.TrimSpace(string(b)))
	}()

	step("move: waiting for MOVE_AT and the handover")
	gapLine := waitLog(logB, "[move] MOVED", 4*time.Minute)
	movedAt := time.Now()
	log.Printf("   %s", gapLine)
	if strings.Contains(readFile(logB), "FAILED") {
		log.Fatalf("the move failed: %s", grepLines(logB, "[move]"))
	}

	step("move: the machine's /m/commands long poll takes work from router B at once (an exec through it)")
	t0 := time.Now()
	var res struct {
		Stdout string
		Code   int
	}
	s, b := call(routerB, "POST", "/api/sessions/"+id+"/exec", map[string]any{"cmd": "echo after", "timeout": 60}, &res)
	must(s, b, "exec after the move")
	if strings.TrimSpace(res.Stdout) != "after" {
		log.Fatalf("exec after the move: %q", res.Stdout)
	}
	execAfter := time.Since(movedAt)
	log.Printf("   exec through router B answered %s after the move (%s for the call)", execAfter.Round(time.Millisecond), time.Since(t0).Round(time.Millisecond))

	step("move: the wakeup due inside the handover is delivered exactly once")
	var lateness time.Duration
	for deadline := time.Now().Add(3 * time.Minute); ; {
		var wk struct{ Wakeups []map[string]any }
		call(routerB, "GET", "/api/sessions/"+id+"/wakeups", nil, &wk)
		if len(wk.Wakeups) == 0 && strings.Contains(readFile(logA)+readFile(logB), `[wakeup] `+id+` "e2e-move" delivered`) {
			lateness = time.Since(wakeAt)
			break
		}
		if time.Now().After(deadline) {
			log.Fatalf("the wakeup due in the handover was never delivered: %v", wk.Wakeups)
		}
		time.Sleep(100 * time.Millisecond)
	}
	nA := strings.Count(readFile(logA), `[wakeup] `+id+` "e2e-move" delivered`)
	nB := strings.Count(readFile(logB), `[wakeup] `+id+` "e2e-move" delivered`)
	if nA+nB != 1 {
		log.Fatalf("the wakeup was delivered %d times (old router %d, new %d)", nA+nB, nA, nB)
	}
	log.Printf("   delivered once (by the %s router), %s after it was due", map[bool]string{true: "old", false: "new"}[nA == 1], lateness.Round(time.Millisecond))

	execInFlight := <-execDone
	log.Printf("   the app exec in flight at the freeze: %s", execInFlight)

	step("move: the old router's address answers through the new one; the session is the same machine, boot and supervisor")
	var stB, stA map[string]any
	must2(call(routerB, "GET", "/api/state", nil, &stB))
	must2(call(router, "GET", "/api/state", nil, &stA))
	if fmt.Sprint(stA["sessions"]) != fmt.Sprint(stB["sessions"]) {
		log.Fatal("the old router's address doesn't answer with the new router's state")
	}
	if after := ident(); after != before {
		log.Fatalf("the session's machine changed across the move: %q → %q", before, after)
	}
	sess := map[string]any{}
	for _, x := range stB["sessions"].([]any) {
		if x.(map[string]any)["id"] == id {
			sess = x.(map[string]any)
		}
	}
	if sess["state"] != "started" || fmt.Sprint(sess["machineId"]) != m {
		log.Fatalf("the session after the move: %v %v", sess["state"], sess["machineId"])
	}

	step("move: the machine's status report reaches router B")
	var reportAfter time.Duration
	for deadline := time.Now().Add(6 * time.Minute); ; {
		var st map[string]any
		call(routerB, "GET", "/api/state", nil, &st)
		got := false
		for _, x := range st["sessions"].([]any) {
			s := x.(map[string]any)
			if s["id"] == id {
				if lr, _ := s["lastReport"].(string); lr != "" {
					if t, err := time.Parse(time.RFC3339Nano, lr); err == nil && t.After(movedAt.Add(-time.Second)) {
						got = true
					}
				}
			}
		}
		if got {
			reportAfter = time.Since(movedAt)
			break
		}
		if time.Now().After(deadline) {
			log.Printf("   no new status report within 6 min (the machine reports on a change or its heartbeat)")
			break
		}
		time.Sleep(time.Second)
	}

	step("move: the probes (wait for them to end)")
	time.Sleep(time.Until(moveAt.Add(100 * time.Second)))
	out, _, err := flyExec(m, []string{"cat", "/tmp/move-probe.log"})
	if err != nil {
		log.Fatalf("probe log: %v", err)
	}
	summary := probeSummary(out, moveAt)
	log.Printf("RESULTS (router move with a running session on Fly):\n  %s\n  %s\n  machine /m/commands long poll: an exec through router B answered %s after the move\n  wakeup due 700 ms after MOVE_AT: delivered once, %s after it was due\n  app exec in flight at the freeze: %s\n  machine status report on router B: %s after the move\n%s",
		gapLine, grepLines(logA, "[move] frozen"), execAfter.Round(time.Millisecond), lateness.Round(time.Millisecond), execInFlight, reportAfter.Round(time.Millisecond), summary)
	if strings.Contains(summary, "FAIL") {
		log.Fatal("a probe failed across the move")
	}
	log.Printf("E2E PASSED (the router move only)")
}

// startProbe: on the machine, the session API and a lease, every 200 ms for secs seconds
// (/tmp/move-probe.log: path, start ms, end ms, HTTP code)
func startProbe(m, id string, secs int) {
	probe := `end=$(( $(date +%s) + ` + strconv.Itoa(secs) + ` ))
run() { while [ $(date +%s) -lt $end ]; do s=$(date +%s%3N); c=$(curl -s -o /tmp/probe-$P.out -w %{http_code} --max-time 90 "$@"); e=$(date +%s%3N); echo "$P $s $e $c" >> /tmp/move-probe.log; [ "$c" = 200 ] || echo "$P $s body $(head -c 300 /tmp/probe-$P.out | tr '\n' ' ')" >> /tmp/move-probe.log; sleep 0.2; done; }
P=api run http://127.0.0.1:7171/api/sessions/` + id + `/wakeups &
P=lease run -X POST -H 'Content-Type: application/json' -d '{"purpose":"e2e-move","ttl":600}' http://127.0.0.1:7171/api/sessions/` + id + `/leases/e2e-move &
wait`
	expectOnMachine(m, "rm -f /tmp/move-probe.log; cat > /tmp/move-probe.sh <<'EOF'\n"+probe+"\nEOF\nchmod 755 /tmp/move-probe.sh; touch /tmp/move-probe.log; chown claude /tmp/move-probe.sh /tmp/move-probe.log; "+
		"su - claude -c 'nohup /tmp/move-probe.sh >/dev/null 2>&1 &'; echo ok", "ok")
}

// probeSummary: per path, the calls, the non-200s, and the longest call or pause between answers around the move
func probeSummary(log_ string, moveAt time.Time) string {
	type call struct {
		s, e int64
		code string
	}
	paths := map[string][]call{}
	var bodies strings.Builder
	sc := bufio.NewScanner(strings.NewReader(log_))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 3 && f[2] == "body" {
			fmt.Fprintf(&bodies, "    %s\n", sc.Text())
			continue
		}
		if len(f) != 4 {
			continue
		}
		s, _ := strconv.ParseInt(f[1], 10, 64)
		e, _ := strconv.ParseInt(f[2], 10, 64)
		paths[f[0]] = append(paths[f[0]], call{s, e, f[3]})
	}
	var names []string
	for n := range paths {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		cs := paths[n]
		bad := 0
		var longest, gap int64
		var longestAt int64
		for i, c := range cs {
			if c.code != "200" {
				bad++
			}
			if d := c.e - c.s; d > longest {
				longest, longestAt = d, c.s
			}
			if i > 0 && c.code == "200" {
				if d := c.e - cs[i-1].e; d > gap {
					gap = d
				}
			}
		}
		verdict := "ok"
		if bad > 0 {
			verdict = "FAIL"
		}
		for _, c := range cs {
			if c.code != "200" {
				fmt.Fprintf(&b, "    %s: HTTP %s at MOVE_AT%+d ms (%d ms)\n", n, c.code, c.s-moveAt.UnixMilli(), c.e-c.s)
			}
		}
		fmt.Fprintf(&b, "  probe %-6s %4d calls, %d not 200 (%s); longest call %d ms (at MOVE_AT%+d ms); longest time between answers %d ms\n",
			n, len(cs), bad, verdict, longest, longestAt-moveAt.UnixMilli(), gap)
	}
	return b.String() + bodies.String()
}

func readFile(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

func grepLines(p, sub string) string {
	var out []string
	for _, l := range strings.Split(readFile(p), "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return strings.Join(out, " | ")
}

// waitLog: the first line of p containing sub, waiting up to d
func waitLog(p, sub string, d time.Duration) string {
	deadline := time.Now().Add(d)
	for {
		for _, l := range strings.Split(readFile(p), "\n") {
			if strings.Contains(l, sub) {
				return l
			}
		}
		if time.Now().After(deadline) {
			log.Fatalf("no %q in %s within %s:\n%s", sub, p, d, tail(readFile(p), 30))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func tail(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

