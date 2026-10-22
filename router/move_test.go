package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func writeData(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readData(t *testing.T, dir, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return string(b)
}

type moveRig struct {
	r              *Router
	dirA, dirB     string
	lockA, lockB   *leaderLock
	pubA, pubB     *swapHandler
	srvA, srvB     *httptest.Server
	srvMove        *httptest.Server
	sender         *moveSender
	joiner         *moveJoiner
	wgPath         string
	wgStarted      atomic.Int32
	wgStopped      atomic.Int32
	serveA, serveB http.Handler
}

func newMoveRig(t *testing.T) *moveRig {
	g := &moveRig{r: newTestRouter(t)}
	g.dirA, g.dirB = g.r.cfg.DataDir, t.TempDir()
	var err error
	if g.lockA, err = openLeaderLock(g.dirA); err != nil || !g.lockA.tryLock() {
		t.Fatal("sender lock", err)
	}
	if g.lockB, err = openLeaderLock(g.dirB); err != nil || !g.lockB.tryLock() {
		t.Fatal("joiner lock", err)
	}
	serve := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			io.WriteString(w, name+":"+r.Method+":"+string(b))
		})
	}
	g.serveA, g.serveB = serve("A"), serve("B")
	g.pubA, g.pubB = &swapHandler{}, &swapHandler{}
	g.pubA.set(g.serveA)
	g.srvA, g.srvB = httptest.NewServer(g.pubA), httptest.NewServer(g.pubB)
	t.Cleanup(g.srvA.Close)
	t.Cleanup(g.srvB.Close)
	g.wgPath = filepath.Join(t.TempDir(), "wg.conf")
	os.WriteFile(g.wgPath, []byte("[Interface]\nPrivateKey = x\n"), 0o600)
	ld := &leadership{lock: g.lockA, self: g.srvA.URL, handler: g.pubA, stopWG: func() { g.wgStopped.Add(1) }}
	g.sender = &moveSender{r: g.r, st: g.r.st, ld: ld, lock: g.lockA, self: g.srvA.URL, public: g.pubA, dir: g.dirA, key: "k",
		wgPath: g.wgPath, drain: time.Second,
		startWG: func() (func(), func(), error) {
			g.wgStarted.Add(1)
			return func() { g.wgStopped.Add(1) }, func() {}, nil
		}}
	g.srvMove = httptest.NewServer(g.sender.Handler())
	t.Cleanup(g.srvMove.Close)
	g.joiner = &moveJoiner{dir: g.dirB, from: g.srvMove.URL, public: g.srvA.URL, self: g.srvB.URL, key: "k",
		every: 40 * time.Millisecond, http: http.DefaultClient}
	// what the old box's /data holds
	writeData(t, g.dirA, "input-log.jsonl", "line 1\n")
	writeData(t, g.dirA, "snapshots/m1.tar.gz", strings.Repeat("snap", 1000))
	writeData(t, g.dirA, "snapshots/m1.carry", "carry")
	writeData(t, g.dirA, "tmp/scratch", "never moves")
	return g
}

// The move in miniature: clients hit both boxes (cloudflared has connectors on both) while the new box pre-copies,
// freezes the old one, takes the delta and the peer and serves; the old box proxies to it. No request fails, and
// afterwards every answer comes from the new box.
func TestMoveAcrossBoxesNoFailedRequests(t *testing.T) {
	g := newMoveRig(t)
	g.joiner.at = time.Now().Add(400 * time.Millisecond)
	sig := make(chan os.Signal, 1)
	moved := make(chan struct{})
	go func() {
		if !g.joiner.candidate(g.lockB, g.srvB.URL, g.pubB, sig) {
			t.Error("candidate gave up")
			return
		}
		time.Sleep(100 * time.Millisecond) // LoadState, NewRouter, the peer
		g.pubB.set(g.serveB)
		g.joiner.finish()
		close(moved)
	}()
	// a change after the first pre-copy reaches the new box in the delta
	time.Sleep(150 * time.Millisecond)
	writeData(t, g.dirA, "input-log.jsonl", "line 1\nline 2\n")
	writeData(t, g.dirA, "snapshots/m2.carry", "carry 2")
	os.Remove(filepath.Join(g.dirA, "snapshots", "m1.carry"))

	var fails, total atomic.Int64
	var mu sync.Mutex
	seen := map[string]int{}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			base := g.srvB.URL
			if i%2 == 1 {
				base = g.srvA.URL
			}
			for {
				select {
				case <-stop:
					return
				default:
				}
				method, body := "GET", ""
				if i%4 == 3 {
					method, body = "POST", "x"
				}
				req, _ := http.NewRequest(method, base+"/api/thing", strings.NewReader(body))
				res, err := http.DefaultClient.Do(req)
				total.Add(1)
				if err != nil || res.StatusCode != 200 {
					fails.Add(1)
					if err == nil {
						b, _ := io.ReadAll(res.Body)
						t.Logf("%s %s -> %d %s", method, base, res.StatusCode, b)
						res.Body.Close()
					} else {
						t.Logf("%s %s -> %v", method, base, err)
					}
					continue
				}
				b, _ := io.ReadAll(res.Body)
				res.Body.Close()
				mu.Lock()
				seen[string(b[:1])]++
				mu.Unlock()
			}
		}(i)
	}
	select {
	case <-moved:
	case <-time.After(10 * time.Second):
		t.Fatal("no move")
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	seen = map[string]int{}
	mu.Unlock()
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
	if fails.Load() != 0 {
		t.Fatalf("%d of %d requests failed across the move", fails.Load(), total.Load())
	}
	if seen["A"] != 0 || seen["B"] == 0 {
		t.Fatalf("answers after the move: %v (want only B)", seen)
	}
	// the data
	if got := readData(t, g.dirB, "input-log.jsonl"); got != "line 1\nline 2\n" {
		t.Fatalf("delta missed: %q", got)
	}
	if readData(t, g.dirB, "snapshots/m2.carry") != "carry 2" || readData(t, g.dirB, "snapshots/m1.tar.gz") != strings.Repeat("snap", 1000) {
		t.Fatal("files missing on the new box")
	}
	if _, err := os.Stat(filepath.Join(g.dirB, "snapshots", "m1.carry")); err == nil {
		t.Fatal("a file deleted on the old box is still on the new one")
	}
	if readData(t, g.dirB, "input-log.jsonl") != readData(t, g.dirA, "input-log.jsonl") {
		t.Fatal("input-log.jsonl differs") // the records themselves are in Postgres (statedb.go): nothing to move
	}
	if _, err := os.Stat(filepath.Join(g.dirB, "tmp", "scratch")); err == nil {
		t.Fatal("tmp/ moved")
	}
	if readData(t, g.dirB, wgDataFile) != "[Interface]\nPrivateKey = x\n" {
		t.Fatal("the WireGuard peer didn't come along")
	}
	if wgConfigPath(g.dirB) != filepath.Join(g.dirB, wgDataFile) {
		t.Fatal("the moved peer must win over WG_CONFIG")
	}
	if g.wgStopped.Load() != 1 {
		t.Fatal("the old box's peer must stop")
	}
	if movedTo(g.dirA) != g.srvB.URL {
		t.Fatalf("router.moved = %q", movedTo(g.dirA))
	}
	if moveJoinerFromEnv(g.dirB) != nil {
		t.Fatal("a moved-in box must not join again")
	}
	if g.lockA.leaderAddr() != g.srvB.URL {
		t.Fatal("the old box's standby must proxy to the new box")
	}
	if st := moveStatusNow(); st.Phase != "serving" || st.GapMs <= 0 {
		t.Fatalf("status %+v", st)
	}
	t.Logf("%d requests across the move, none failed; gap %d ms", total.Load(), moveStatusNow().GapMs)
}

// A freeze that is aborted leaves the old box serving: state, peer and drain back.
func TestMoveAbortThaws(t *testing.T) {
	g := newMoveRig(t)
	if _, _, err := g.joiner.sync(nil); err != nil {
		t.Fatal(err)
	}
	var fz freezeAnswer
	if err := g.joiner.call("POST", "/move/freeze", map[string]bool{}, &fz); err != nil {
		t.Fatal(err)
	}
	if !g.r.draining() || g.r.st.mu.TryLock() {
		t.Fatal("frozen: draining and the state held")
	}
	if !strings.Contains(fz.WG, "PrivateKey") || len(fz.Files) == 0 {
		t.Fatalf("freeze answer %+v", fz)
	}
	if err := g.joiner.call("POST", "/move/abort", nil, nil); err != nil {
		t.Fatal(err)
	}
	if g.r.draining() {
		t.Fatal("still draining after the abort")
	}
	if !g.r.st.mu.TryLock() {
		t.Fatal("state still frozen after the abort")
	}
	g.r.st.mu.Unlock()
	if g.wgStarted.Load() != 1 {
		t.Fatal("the peer must come back")
	}
	res, err := http.Get(g.srvA.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	if !strings.HasPrefix(string(b), "A:") {
		t.Fatalf("after the abort the old box serves itself, got %q", b)
	}
	if movedTo(g.dirA) != "" {
		t.Fatal("no router.moved after an abort")
	}
}

func TestMoveAuthAndPaths(t *testing.T) {
	g := newMoveRig(t)
	for _, c := range []struct {
		key, path string
		want      int
	}{
		{"wrong", "/move/files", 401},
		{"", "/move/files", 401},
		{"k", "/move/files", 200},
		{"k", "/move/file?path=../etc/passwd", 400},
		{"k", "/move/file?path=/etc/passwd", 400},
		{"k", "/move/file?path=router.leader", 400},
		{"k", "/move/file?path=snapshots/../../x", 400},
		{"k", "/move/file?path=snapshots/m1.carry", 200},
	} {
		req, _ := http.NewRequest("GET", g.srvMove.URL+c.path, nil)
		if c.key != "" {
			req.Header.Set("Authorization", "Bearer "+c.key)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != c.want {
			t.Errorf("%s %s: %d, want %d", c.key, c.path, res.StatusCode, c.want)
		}
	}
}

// A router whose box moved stays a proxy to the new box, whatever restarts.
func TestMovedRouterIsOnlyAProxy(t *testing.T) {
	dir := t.TempDir()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "new box") }))
	defer target.Close()
	os.WriteFile(filepath.Join(dir, movedFile), []byte(target.URL+"\n"), 0o600)
	to := movedTo(dir)
	if to != target.URL {
		t.Fatalf("movedTo %q", to)
	}
	srv := httptest.NewServer(proxyTo("http://self", to))
	defer srv.Close()
	res, err := http.Post(srv.URL+"/api/x", "text/plain", bytes.NewReader([]byte("b")))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	if string(b) != "new box" {
		t.Fatalf("got %q", b)
	}
}

// A standby's move listener passes the calls on to the leader's (one Service may select every router pod).
func TestStandbyMoveListenerProxiesToLeader(t *testing.T) {
	leaderMove := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "leader "+r.URL.Path+" "+r.Header.Get("Authorization"))
	}))
	defer leaderMove.Close()
	port := leaderMove.URL[strings.LastIndex(leaderMove.URL, ":")+1:]
	t.Setenv("MOVE_ADDR", ":"+port)
	dir := t.TempDir()
	lock, _ := openLeaderLock(dir)
	lock.setAddr("http://127.0.0.1:1") // the leader's public address: same host, the move port
	srv := httptest.NewServer(moveLeaderProxy(lock, "http://127.0.0.2:8080"))
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/move/files", nil)
	req.Header.Set("Authorization", "Bearer k")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	if string(b) != "leader /move/files Bearer k" {
		t.Fatalf("got %q", b)
	}
}

func TestIsSynTo(t *testing.T) {
	v6 := func(flags byte, port uint16) []byte {
		p := make([]byte, 60)
		p[0], p[6] = 0x60, 6
		p[42], p[43], p[53] = byte(port>>8), byte(port), flags
		return p
	}
	if !isSynTo(v6(0x02, 8081), 8081) {
		t.Fatal("a SYN to 8081")
	}
	if isSynTo(v6(0x12, 8081), 8081) || isSynTo(v6(0x10, 8081), 8081) || isSynTo(v6(0x02, 22), 8081) {
		t.Fatal("SYN-ACK, ACK or another port are not dropped")
	}
	v4 := make([]byte, 40)
	v4[0], v4[9] = 0x45, 6
	v4[22], v4[23], v4[33] = 0x1f, 0x91, 0x02
	if !isSynTo(v4, 8081) {
		t.Fatal("an IPv4 SYN to 8081")
	}
}

// A freeze behind a proxy that times out (Cloudflare's 524 while the sender drains) is asked again, not aborted.
func TestFreezeRetriedThroughAProxyTimeout(t *testing.T) {
	g := newMoveRig(t)
	var n atomic.Int32
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/move/freeze" && n.Add(1) == 1 {
			w.WriteHeader(524)
			return
		}
		u := g.srvMove.URL + r.URL.RequestURI()
		req, _ := http.NewRequest(r.Method, u, r.Body)
		req.Header = r.Header
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		w.WriteHeader(res.StatusCode)
		io.Copy(w, res.Body)
	}))
	defer front.Close()
	g.joiner.from = front.URL
	g.joiner.at = time.Now()
	if !g.joiner.candidate(g.lockB, g.srvB.URL, g.pubB, make(chan os.Signal)) {
		t.Fatal("the move gave up on a proxy timeout")
	}
	if n.Load() < 2 {
		t.Fatal("the freeze wasn't asked again")
	}
	g.pubB.set(g.serveB)
	g.joiner.finish()
}
