package main

// Moving the router to another box with no gap (Deyao, 2026-10-15: the box redesign, layout A; docs/DESIGN.md "The
// box", DECISIONS). leader.go hands the state over between two pods on ONE node (an flock on the shared volume); this
// is the same handover between two boxes, over their private network:
//
//   - The SENDER is the old box's leader. With MOVE_KEY set it listens on MOVE_ADDR (":8082") for the move calls,
//     each with "Authorization: Bearer <MOVE_KEY>": GET /move/files (what /data holds: path, size, mtime),
//     GET /move/file?path=… (one file), POST /move/freeze (drain as for a rollout, take the Claude login's refresh in
//     flight, stop the WireGuard peer, save and freeze the state, answer the file list and the peer's wg.conf, and, when
//     asked, the current core's FINAL line state: POST /handoff, nextcore.go), POST /move/done {url} (from now on a proxy to that URL, for good:
//     /data/router.moved names it, so a restart stays a proxy and never loads the old state) and POST /move/abort
//     (thaw: state, peer and drain back as they were).
//   - The JOINER is the new box's router (MOVE_FROM, MOVE_PUBLIC, MOVE_SELF, MOVE_AT, MOVE_KEY). Until it has moved
//     (/data/router.moved-in), the pod holding the local flock is the CANDIDATE: it loads no state, proxies every
//     request to the sender (MOVE_PUBLIC), and copies /data every minute (only changed files). At MOVE_AT: a last
//     copy, freeze, the delta, the peer's wg.conf into /data (it wins over WG_CONFIG: the peer moves with the
//     leadership, so the machines' jarvis4-box._peer.internal keeps its address), then the normal leader start and
//     done. Requests that arrive in between wait in both boxes' proxies; the gap is logged and kept in the status.
//
// What still waits, as in any rollout: a new lifecycle action asked for during the sender's drain gets 503 "router
// updating, try again shortly"; a machine's /m call in flight when the peer moves is retried by the machine.

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	movedFile   = "router.moved"    // sender: the URL it moved to
	movedInFile = "router.moved-in" // joiner: the move is done, this /data is the router's own
	wgDataFile  = "wg.conf"         // the WireGuard peer that came with the move
)

// moveFile: one file of /data, as GET /move/files lists it
type moveFile struct {
	Path  string `json:"path"` // relative, slash-separated
	Size  int64  `json:"size"`
	Mtime int64  `json:"mtime"` // unix ns
}

// moveSkip: what never moves: the lock and the move's own markers, the peer's file (it travels in the freeze answer),
// scratch space
func moveSkip(rel string) bool {
	return strings.HasPrefix(rel, "router.leader") || rel == movedFile || rel == movedInFile || rel == wgDataFile ||
		rel == "tmp" || strings.HasPrefix(rel, "tmp/") || strings.HasSuffix(rel, ".move-tmp")
}

func listData(dir string) ([]moveFile, error) {
	var out []moveFile
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if moveSkip(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil // gone since the walk saw it
		}
		out = append(out, moveFile{Path: rel, Size: fi.Size(), Mtime: fi.ModTime().UnixNano()})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, err
}

// dataPath: rel inside dir, or an error for anything that would leave it
func dataPath(dir, rel string) (string, error) {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") {
		return "", errors.New("bad path")
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel)))
	if clean != rel || clean == ".." || strings.HasPrefix(clean, "../") || moveSkip(clean) {
		return "", errors.New("bad path")
	}
	return filepath.Join(dir, filepath.FromSlash(clean)), nil
}

// ---- status (both sides) --------------------------------------------------------------------------------------

type moveStatus struct {
	Role        string    `json:"role,omitempty"`  // sender | candidate | joined
	Phase       string    `json:"phase,omitempty"` // serving | precopying | freezing | frozen | moved | aborted | failed
	LastPrecopy time.Time `json:"lastPrecopy,omitempty"`
	Files       int       `json:"files,omitempty"`
	Bytes       int64     `json:"bytes,omitempty"`
	GapMs       int64     `json:"gapMs,omitempty"`
	To          string    `json:"to,omitempty"`
	Error       string    `json:"error,omitempty"`
	At          time.Time `json:"at,omitempty"`
}

var (
	moveMu   sync.Mutex
	moveInfo moveStatus
)

func setMove(f func(s *moveStatus)) {
	moveMu.Lock()
	f(&moveInfo)
	moveInfo.At = time.Now().UTC()
	moveMu.Unlock()
}

func moveStatusNow() moveStatus {
	moveMu.Lock()
	defer moveMu.Unlock()
	return moveInfo
}

// ---- the sender -----------------------------------------------------------------------------------------------

// moveSender: the old box's side. startWG brings the peer back on an abort.
type moveSender struct {
	r       *Router
	st      *State
	ld      *leadership
	lock    *leaderLock
	self    string
	public  *swapHandler
	dir     string
	key     string
	wgPath  string
	startWG func() (stop, quiesce func(), err error)
	drain   time.Duration
	handoff coreHandoff // nextcore.go: the current core's FINAL line state, when the joiner asks for it

	mu     sync.Mutex
	frozen bool
	doneTo string
	to     atomic.Value // doneTo for the held requests (read without mu: a freeze holds mu while it drains)
	held   http.Handler // the public handler before the freeze (an abort puts it back)
	heldAt time.Time    // when requests began to be held (the gap's start)
}

func (s *moveSender) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		if s.key == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.key)) != 1 {
			writeJSON(w, 401, map[string]string{"error": "move: bad key"})
			return
		}
		h(w, req)
	})
}

func (s *moveSender) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /move/files", s.auth(func(w http.ResponseWriter, req *http.Request) {
		fs, err := listData(s.dir)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"files": fs})
	}))
	mux.Handle("GET /move/file", s.auth(func(w http.ResponseWriter, req *http.Request) {
		p, err := dataPath(s.dir, req.URL.Query().Get("path"))
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		f, err := os.Open(p)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "no such file"})
			return
		}
		defer f.Close()
		fi, _ := f.Stat()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Mtime", strconv.FormatInt(fi.ModTime().UnixNano(), 10))
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
		io.Copy(w, f)
	}))
	mux.Handle("POST /move/freeze", s.auth(func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			FinalizeCore bool `json:"finalizeCore"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		out, err := s.freeze(in.FinalizeCore)
		if err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, out)
	}))
	mux.Handle("POST /move/done", s.auth(func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			URL string `json:"url"`
		}
		if json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in) != nil || !strings.HasPrefix(in.URL, "http") {
			writeJSON(w, 400, map[string]string{"error": "done needs the new router's url"})
			return
		}
		if err := s.done(in.URL); err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"moved": in.URL})
	}))
	mux.Handle("POST /move/abort", s.auth(func(w http.ResponseWriter, req *http.Request) {
		if err := s.abort(); err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"aborted": "serving again"})
	}))
	return mux
}

type freezeAnswer struct {
	Files     []moveFile      `json:"files"`
	WG        string          `json:"wg,omitempty"`
	CoreFinal json.RawMessage `json:"coreFinal,omitempty"`
	HeldMs    int64           `json:"heldMs"` // how long requests have been held here when this answer went
}

// freeze: drain, the login's refresh in flight, peer down, state saved and frozen. Requests that reach this pod from
// now on wait for done's URL (or the abort).
func (s *moveSender) freeze(finalizeCore bool) (*freezeAnswer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.doneTo != "" {
		return nil, errors.New("already moved to " + s.doneTo)
	}
	if !s.frozen {
		setMove(func(m *moveStatus) { m.Role, m.Phase, m.Error = "sender", "freezing", "" })
		log.Printf("[move] freeze: draining")
		prepared := time.Now()
		if s.ld.prepare != nil {
			s.ld.prepare() // wg.go: the machines' connections become one-shot while this router still serves
		}
		s.r.Drain(s.drain)
		s.r.drainLogins(20 * time.Second)
		if s.ld.prepare != nil {
			time.Sleep(time.Until(prepared.Add(oneShotLead))) // every pooled machine connection used once more, and closed
		}
		s.r.stopDeliveries(90 * time.Second) // movegate.go: no wakeup is lost or made twice across the move
		// the gap starts here: requests wait in the held proxy for the new router
		s.heldAt = time.Now()
		s.held = s.public.current()
		hold := &leaderProxy{self: s.self, wait: 120 * time.Second, tr: newLeaderProxy(s.lock, s.self, nil).tr, fixed: s.target}
		s.public.set(hold)
		if s.ld.quiesce != nil {
			s.ld.quiesce() // wg.go: no new machine connection opens here; the machines' dials wait for the new peer
		}
		s.r.freezeRequests(hold, 10*time.Second) // movegate.go: long polls in flight end at once
		if s.ld.stopWG != nil {
			s.ld.stopWG() // graceful: the machines' pooled connections get their FIN first (wg.go)
			s.ld.stopWG = nil
		}
		s.st.mu.Lock() // held until an abort; for good after done
		s.st.save()
		if s.r.lines != nil {
			go s.r.lines.flush() // linestate.go: the newest line state into the bucket too
		}
		s.frozen = true
		setMove(func(m *moveStatus) { m.Phase = "frozen" })
		log.Printf("[move] frozen in %s: state saved, peer down, requests held", time.Since(s.heldAt).Round(time.Millisecond))
		go s.r.BackupState("move freeze") // backup.go: the state as it leaves this box
	}
	files, err := listData(s.dir)
	if err != nil {
		return nil, err
	}
	out := &freezeAnswer{Files: files}
	defer func() { out.HeldMs = time.Since(s.heldAt).Milliseconds() }() // the gap so far, by this box's clock
	if s.wgPath != "" {
		if b, err := os.ReadFile(s.wgPath); err == nil {
			out.WG = string(b)
		}
	}
	if finalizeCore {
		if s.handoff == nil {
			return nil, errors.New("this router can't finalize its core")
		}
		fin, err := s.handoff.Finalize(s.r.core)
		if err != nil {
			return nil, fmt.Errorf("finalizing the core: %w", err)
		}
		out.CoreFinal = fin
	}
	return out, nil
}

// target: where held requests go: "" (wait) until done names the new router
func (s *moveSender) target() string {
	v, _ := s.to.Load().(string)
	return v
}

func (s *moveSender) done(url string) error {
	s.mu.Lock()
	if !s.frozen {
		s.mu.Unlock()
		return errors.New("not frozen")
	}
	if err := os.WriteFile(filepath.Join(s.dir, movedFile), []byte(url+"\n"), 0o600); err != nil {
		s.mu.Unlock()
		return err
	}
	s.doneTo = url
	s.to.Store(url)
	s.mu.Unlock()
	s.lock.setAddr(url) // this box's standby proxies there too; the flock stays held: nobody here leads again
	setMove(func(m *moveStatus) { m.Phase, m.To = "moved", url })
	log.Printf("[move] done: this router is a proxy to %s from now on", url)
	return nil
}

func (s *moveSender) moved() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doneTo != ""
}

func (s *moveSender) abort() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.doneTo != "" {
		return errors.New("already moved to " + s.doneTo)
	}
	if !s.frozen {
		s.r.resumeDeliveries()
		s.r.Undrain()
		return nil
	}
	if s.startWG != nil {
		stop, quiesce, err := s.startWG()
		if err != nil {
			log.Printf("[move] abort: WireGuard peer: %v", err)
		} else {
			s.ld.stopWG, s.ld.quiesce, s.ld.prepare = stop, quiesce, nil
		}
	}
	s.st.mu.Unlock()
	s.frozen = false
	if s.held != nil {
		s.public.set(s.held)
	}
	s.r.thawRequests()
	s.r.resumeDeliveries()
	s.r.Undrain()
	setMove(func(m *moveStatus) { m.Phase = "aborted" })
	log.Printf("[move] aborted: serving again")
	return nil
}

// oneShotLead: how long the machines' connections are one-shot before a handover freezes (the drain may already take
// longer): each pooled connection carries one more request and closes cleanly, instead of racing a FIN at the freeze
var oneShotLead = 3 * time.Second

// moveLeaderProxy: a standby's move listener — every call to the leader's (its public address, the move port)
func moveLeaderProxy(lock *leaderLock, self string) *leaderProxy {
	port := strings.TrimPrefix(env("MOVE_ADDR", ":8082"), ":")
	if i := strings.LastIndex(port, ":"); i >= 0 {
		port = port[i+1:]
	}
	withPort := func(u string) string {
		if i := strings.LastIndex(u, ":"); i > len("http://") {
			return u[:i+1] + port
		}
		return u
	}
	p := newLeaderProxy(lock, withPort(self), nil)
	p.fixed = func() string {
		a := lock.leaderAddr()
		if a == "" || a == self {
			return "" // no leader, or this pod leads and its sender takes the listener over in a moment
		}
		return withPort(a)
	}
	return p
}

// ---- a router that moved: only a proxy --------------------------------------------------------------------------

// movedTo: the URL this box's router moved to, "" if it never did
func movedTo(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, movedFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// proxyTo: a handler that sends everything (WebSockets and long polls too) to url
func proxyTo(self, url string) *leaderProxy {
	p := newLeaderProxy(nil, self, nil)
	p.fixed = func() string { return url }
	return p
}

// ---- the joiner -------------------------------------------------------------------------------------------------

type moveJoiner struct {
	dir      string
	from     string // the sender's move listener
	public   string // the sender's public listener
	self     string // this router's public URL as the sender reaches it
	key      string
	at       time.Time // zero: never
	every    time.Duration
	http     *http.Client
	handoff  coreHandoff
	core     *CoreClient // this box's core (the next core of a move that carries it)
	lastSync time.Time   // when the last complete sync began
	// what the freeze answered, for the leader start
	wg string
	// serveWG starts the moved peer (wg.go serveWG at port 8081; nil in tests): its machines' handler holds every
	// request until the router serves (machine.ready)
	serveWG func(path string, h http.Handler) (*wgServer, error)
	machine *holdHandler
	peer    *wgServer
}

func moveJoinerFromEnv(dir string) *moveJoiner {
	from := os.Getenv("MOVE_FROM")
	if from == "" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, movedInFile)); err == nil {
		return nil // moved in already: this /data is ours
	}
	j := &moveJoiner{dir: dir, from: strings.TrimSuffix(from, "/"), public: os.Getenv("MOVE_PUBLIC"), self: os.Getenv("MOVE_SELF"),
		key: os.Getenv("MOVE_KEY"), every: time.Minute, http: &http.Client{Timeout: 30 * time.Minute}}
	if at := os.Getenv("MOVE_AT"); at != "" {
		t, err := time.Parse(time.RFC3339, at)
		if err != nil {
			log.Printf("[move] MOVE_AT %q: %v (no move)", at, err)
		} else {
			j.at = t
		}
	}
	if j.public == "" || j.self == "" || j.key == "" {
		log.Printf("[move] MOVE_FROM needs MOVE_PUBLIC, MOVE_SELF and MOVE_KEY too: no move")
		return nil
	}
	return j
}

func (j *moveJoiner) call(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, j.from+path, rd)
	j.auth(req)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := j.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s %s: HTTP %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// sync: make /data match the sender's list (fetch what differs, delete what it no longer has). files = nil asks it.
// final: the delta after the freeze, which doesn't trust size+mtime for what may have changed within one mtime tick
// of a pre-copy: every file under 1 MB (state.json and the like) and every file touched since the last pre-copy began
// is fetched again.
func (j *moveJoiner) sync(files []moveFile, final ...bool) (fetched int, bytes int64, err error) {
	start := time.Now()
	since := j.lastSync.Add(-2 * time.Second)
	if files == nil {
		var l struct{ Files []moveFile }
		if err := j.call("GET", "/move/files", nil, &l); err != nil {
			return 0, 0, err
		}
		files = l.Files
	}
	local, err := listData(j.dir)
	if err != nil {
		return 0, 0, err
	}
	have := map[string]moveFile{}
	for _, f := range local {
		have[f.Path] = f
	}
	want := map[string]bool{}
	var todo []moveFile
	for _, f := range files {
		want[f.Path] = true
		if h, ok := have[f.Path]; ok && h.Size == f.Size && h.Mtime == f.Mtime &&
			!(len(final) > 0 && final[0] && (f.Size < 1<<20 || !time.Unix(0, f.Mtime).Before(since))) {
			continue
		}
		todo = append(todo, f)
	}
	// 8 at a time: the final delta is mostly many small files, and it is inside the gap
	var mu sync.Mutex
	var firstErr error
	work := make(chan moveFile)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range work {
				n, err := j.fetch(f)
				mu.Lock()
				if err != nil && firstErr == nil {
					firstErr = fmt.Errorf("%s: %w", f.Path, err)
				}
				if err == nil {
					fetched++
					bytes += n
				}
				mu.Unlock()
			}
		}()
	}
	for _, f := range todo {
		work <- f
	}
	close(work)
	wg.Wait()
	if firstErr != nil {
		return fetched, bytes, firstErr
	}
	for _, f := range local {
		if !want[f.Path] {
			if p, err := dataPath(j.dir, f.Path); err == nil {
				os.Remove(p)
			}
		}
	}
	j.lastSync = start
	return fetched, bytes, nil
}

func (j *moveJoiner) fetch(f moveFile) (int64, error) {
	p, err := dataPath(j.dir, f.Path)
	if err != nil {
		return 0, err
	}
	req, _ := http.NewRequest("GET", j.from+"/move/file?path="+urlQueryEscape(f.Path), nil)
	j.auth(req)
	resp, err := j.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		os.Remove(p) // gone since it was listed
		return 0, nil
	}
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return 0, err
	}
	tmp := p + ".move-tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, resp.Body)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return n, err
	}
	mt := f.Mtime
	if h := resp.Header.Get("X-Mtime"); h != "" {
		if v, err := strconv.ParseInt(h, 10, 64); err == nil {
			mt = v
		}
	}
	t := time.Unix(0, mt)
	os.Chtimes(tmp, t, t)
	return n, os.Rename(tmp, p)
}

// candidate: until the move (true) or a SIGTERM (false): every request to the sender, /data copied every minute.
// The caller holds the local flock.
func (j *moveJoiner) candidate(lock *leaderLock, self string, public *swapHandler, sig <-chan os.Signal) bool {
	setMove(func(m *moveStatus) { m.Role, m.Phase = "candidate", "precopying" })
	public.set(proxyTo(self, j.public))
	lock.setAddr(self) // this box's standby comes through here
	log.Printf("[move] candidate: proxying to %s, copying /data from %s; move at %v", j.public, j.from, j.at)
	tick := time.NewTimer(0)
	for {
		select {
		case <-sig:
			// the next local pod becomes the candidate
			lock.setAddr("")
			public.set(newLeaderProxy(lock, self, nil))
			lock.unlock()
			log.Printf("[move] candidate stopped before the move: the next pod takes over")
			return false
		case <-tick.C:
		}
		n, b, err := j.sync(nil)
		if err != nil {
			log.Printf("[move] pre-copy: %v", err)
			setMove(func(m *moveStatus) { m.Error = "pre-copy: " + err.Error() })
		} else {
			setMove(func(m *moveStatus) { m.LastPrecopy, m.Files, m.Bytes, m.Error = time.Now().UTC(), n, b, "" })
		}
		if !j.at.IsZero() && !time.Now().Before(j.at) {
			if j.move(self, public) {
				return true
			}
			j.at = time.Time{} // failed: no retry by itself (a new MOVE_AT does it)
		}
		next := j.every
		if !j.at.IsZero() && time.Until(j.at) < next {
			next = max(0, time.Until(j.at)) // the move starts at MOVE_AT, not at the next minute's copy
		}
		tick.Reset(next)
	}
}

// move: freeze the sender, take the delta and the peer, mark /data ours. Requests wait meanwhile.
func (j *moveJoiner) move(self string, public *swapHandler) bool {
	start := time.Now()
	hold := &leaderProxy{self: self, local: public, wait: 120 * time.Second, tr: newLeaderProxy(nil, self, nil).tr,
		fixed: func() string { return self }}
	var fz freezeAnswer
	// this box's core Recovered alongside (a standby): the core moves with the router — the sender hands its core off
	// in the freeze, and this box's core takes over before this router serves
	wantCore := false
	if j.handoff != nil && j.core != nil {
		if serving, _, err := coreServing(j.core); err == nil && serving == "standby" {
			wantCore = true
		}
	}
	setMove(func(m *moveStatus) { m.Phase = "freezing" })
	log.Printf("[move] freezing the sender (it drains first)")
	// the freeze drains first, which can outlast a proxy's timeout (Cloudflare answers 524 after 100 s): it is idempotent,
	// so a timeout or a proxy error is asked again (the sender is still draining, or answers the frozen state at once)
	err := j.call("POST", "/move/freeze", map[string]bool{"finalizeCore": wantCore}, &fz)
	for deadline := time.Now().Add(35 * time.Minute); err != nil && retriableFreeze(err) && time.Now().Before(deadline); {
		log.Printf("[move] freeze still going (%v): asking again", err)
		time.Sleep(2 * time.Second)
		err = j.call("POST", "/move/freeze", map[string]bool{"finalizeCore": wantCore}, &fz)
	}
	if err != nil {
		log.Printf("[move] FREEZE FAILED, aborting, still proxying: %v", err)
		j.call("POST", "/move/abort", nil, nil)
		setMove(func(m *moveStatus) { m.Phase, m.Error = "failed", "freeze: "+err.Error() })
		return false
	}
	frozenAt := time.Now().Add(-time.Duration(fz.HeldMs) * time.Millisecond) // the sender's hold began then
	public.set(hold)                                                         // from here requests wait for this router to serve
	fail := func(what string, err error) bool {
		log.Printf("[move] %s FAILED, aborting the move, still proxying: %v", what, err)
		if j.peer != nil { // the sender brings its own peer back
			j.peer.Stop()
			j.peer, j.machine = nil, nil
			os.Remove(filepath.Join(j.dir, wgDataFile))
		}
		public.set(proxyTo(self, j.public))
		if aerr := j.call("POST", "/move/abort", nil, nil); aerr != nil {
			log.Printf("[move] abort: %v", aerr)
		}
		setMove(func(m *moveStatus) { m.Phase, m.Error = "failed", what+": "+err.Error() })
		return false
	}
	// the peer comes up at once, in parallel with the delta and the leader's start: the machines' connections are
	// taken and wait in the holding handler until the router serves (their dials no longer wait for SYN retries)
	if fz.WG != "" {
		if err := os.WriteFile(filepath.Join(j.dir, wgDataFile), []byte(fz.WG), 0o600); err != nil {
			return fail("wg.conf", err)
		}
		if j.serveWG != nil {
			j.machine = newHoldHandler()
			peer, err := j.serveWG(filepath.Join(j.dir, wgDataFile), j.machine)
			if err != nil {
				os.Remove(filepath.Join(j.dir, wgDataFile))
				return fail("the WireGuard peer", err)
			}
			j.peer = peer
		}
	}
	n, b, err := j.sync(fz.Files, true)
	if err != nil {
		return fail("delta", err)
	}
	if len(fz.CoreFinal) > 0 {
		if err := j.handoff.Adopt(j.core, fz.CoreFinal); err != nil {
			// the old core is handed off for good: NO core serves until a takeover goes through. The final state is
			// kept here (and the old core repeats it on POST /handoff) for the retry.
			os.WriteFile(filepath.Join(j.dir, "core-final.json"), fz.CoreFinal, 0o600)
			log.Printf("[move] THIS BOX'S CORE REFUSED THE TAKEOVER: NO CORE SERVES; the final state is in core-final.json")
			return fail("this box's core taking the old core's final state over", err)
		}
	}
	if err := os.WriteFile(filepath.Join(j.dir, movedInFile), []byte(time.Now().UTC().Format(time.RFC3339)+" from "+j.from+"\n"), 0o600); err != nil {
		return fail("marker", err)
	}
	j.wg = fz.WG
	setMove(func(m *moveStatus) {
		m.Role, m.Phase, m.Files, m.Bytes = "joined", "starting", n, b
	})
	log.Printf("[move] delta %d files (%d bytes) in %s after a %s freeze; starting as the leader", n, b,
		time.Since(frozenAt).Round(time.Millisecond), frozenAt.Sub(start).Round(time.Millisecond))
	moveStarted = frozenAt
	return true
}

// retriableFreeze: a timeout or a proxy's error (502/503/504/520-524), not the sender's own refusal (401, 409)
func retriableFreeze(err error) bool {
	m := err.Error()
	for _, c := range []string{"HTTP 502", "HTTP 503", "HTTP 504", "HTTP 520", "HTTP 521", "HTTP 522", "HTTP 523", "HTTP 524", "Timeout", "timeout", "EOF", "connection reset"} {
		if strings.Contains(m, c) {
			return true
		}
	}
	return false
}

// moveStarted: when the sender froze (the gap starts there); finish ends it
var moveStarted time.Time

// finish: tell the sender where to send what still reaches it; the gap ends with this router serving
func (j *moveJoiner) finish() {
	gap := time.Since(moveStarted)
	if err := j.call("POST", "/move/done", map[string]string{"url": j.self}, nil); err != nil {
		log.Printf("[move] done: %v (the sender keeps holding requests: call it again)", err)
		setMove(func(m *moveStatus) { m.Error = "done: " + err.Error() })
	}
	setMove(func(m *moveStatus) { m.Phase, m.GapMs = "serving", gap.Milliseconds() })
	log.Printf("[move] MOVED: serving here; gap (sender frozen → this router serving) %s", gap.Round(time.Millisecond))
}

// holdHandler: the moved peer's handler until the router serves: every request waits (up to 2 min) for ready
type holdHandler struct {
	once  sync.Once
	ready chan struct{}
	h     http.Handler
}

func newHoldHandler() *holdHandler { return &holdHandler{ready: make(chan struct{})} }

func (h *holdHandler) serve(next http.Handler) {
	h.once.Do(func() { h.h = next; close(h.ready) })
}

func (h *holdHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	select {
	case <-h.ready:
		h.h.ServeHTTP(w, req)
	case <-req.Context().Done():
	case <-time.After(2 * time.Minute):
		w.Header().Set("Connection", "close")
		writeJSON(w, 503, map[string]any{"error": "router moving, try again shortly", "retry": true})
	}
}

// wgConfigPath: the peer that came with a move wins over the box's own
func wgConfigPath(dir string) string {
	p := filepath.Join(dir, wgDataFile)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return os.Getenv("WG_CONFIG")
}

func urlQueryEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_.~/", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// auth: the move key
func (j *moveJoiner) auth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+j.key)
}
