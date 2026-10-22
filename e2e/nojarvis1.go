package main

// Jarvis 4 runs without Jarvis 1 (Deyao, 2026-10-13): the whole test runs with every Jarvis 1 hostname unreachable.
//   - the router: infra/e2e.sh starts it in its own mount namespace whose /etc/hosts sends jarvis.deyaochen.com to
//     127.0.0.2, where a listener records every connection (E2E_J1_HITS); checkNoJarvis1 asserts it saw none;
//   - each session machine: blackholeMachines adds `0.0.0.0 jarvis.deyaochen.com` to its /etc/hosts as soon as Fly
//     lists it as started (and logs whether that was before the machine's boot finished: the machine boots on its own,
//     so the earliest machines may win that race; every later step of the machine runs blackholed).
// The router also gets stand-ins for the box's other services, so the session-facing flows that used to reach Jarvis 1
// run here too: transcript search (SEARCH_URL), the watch runner (WATCH_URL) and the Storage Box behind content stores
// (an in-memory WebDAV over TLS on 127.0.0.1, STORAGEBOX_HOST; its certificate is in the router's SSL_CERT_FILE).

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// jarvis1Hosts: every hostname Jarvis 1 answers on (its dashboard/API and every service behind it)
var jarvis1Hosts = []string{"jarvis.deyaochen.com"}

var blackholed = struct {
	sync.Mutex
	m map[string]string // machine → "before boot" | "after boot"
}{m: map[string]string{}}

// blackholeMachines: every started machine of this run's peer gets the Jarvis 1 hostnames sent nowhere
func blackholeMachines() {
	want := "http://" + os.Getenv("E2E_PEER") + "._peer.internal:8081"
	line := ""
	for _, h := range jarvis1Hosts {
		line += "0.0.0.0 " + h + "\n:: " + h + "\n" // both families: a v6 lookup must not fall through to DNS
	}
	cmd := fmt.Sprintf("grep -q '%s' /etc/hosts || printf '%%s' '%s' >> /etc/hosts; test -e /run/jarvis2/booted && echo after || echo before", jarvis1Hosts[0], line)
	for {
		req, _ := http.NewRequest("GET", "https://api.machines.dev/v1/apps/jarvis4-sessions/machines", nil)
		req.Header.Set("Authorization", "Bearer "+os.Getenv("E2E_FLY_TOKEN"))
		if resp, err := http.DefaultClient.Do(req); err == nil {
			var ms []struct {
				ID     string `json:"id"`
				State  string `json:"state"`
				Config struct {
					Env map[string]string `json:"env"`
				} `json:"config"`
			}
			json.NewDecoder(resp.Body).Decode(&ms)
			resp.Body.Close()
			for _, m := range ms {
				blackholed.Lock()
				done := blackholed.m[m.ID] != ""
				blackholed.Unlock()
				if done || m.State != "started" || m.Config.Env["JARVIS2_URL"] != want {
					continue
				}
				if out, code, err := flyExec(m.ID, []string{"sh", "-c", cmd}); err == nil && code == 0 {
					when := strings.TrimSpace(out)
					blackholed.Lock()
					blackholed.m[m.ID] = when + " boot"
					blackholed.Unlock()
					log.Printf("   jarvis 1 blackholed on %s (%s boot)", m.ID, when)
				}
			}
		}
		time.Sleep(time.Second)
	}
}

// expectBlackholed: the machine has the Jarvis 1 hostnames sent nowhere (waits for the blackholer)
func expectBlackholed(m string) {
	for i := 0; i < 60; i++ {
		blackholed.Lock()
		w := blackholed.m[m]
		blackholed.Unlock()
		if w != "" {
			expectOnMachine(m, "getent ahosts "+jarvis1Hosts[0]+" | awk '{print $1}' | LC_ALL=C sort -u | paste -sd' '", "0.0.0.0 ::")
			return
		}
		time.Sleep(time.Second)
	}
	log.Fatalf("machine %s was never blackholed", m)
}

// checkNoJarvis1: the router's Jarvis 1 listener saw no connection
func checkNoJarvis1(when string) {
	f := os.Getenv("E2E_J1_HITS")
	if f == "" {
		log.Fatal("no E2E_J1_HITS: infra/e2e.sh blackholes Jarvis 1 for the router")
	}
	b, err := os.ReadFile(f)
	if err != nil {
		log.Fatalf("the Jarvis 1 listener's log: %v", err)
	}
	if len(bytes.TrimSpace(b)) > 0 {
		log.Fatalf("%s: the router tried to reach Jarvis 1:\n%s", when, b)
	}
	blackholed.Lock()
	var ms []string
	for m, w := range blackholed.m {
		ms = append(ms, m+" ("+w+")")
	}
	blackholed.Unlock()
	sort.Strings(ms)
	log.Printf("   %s: no connection from the router to Jarvis 1; machines blackholed: %s", when, strings.Join(ms, ", "))
}

// ---- stand-ins for the box's services --------------------------------------------------------------------------

// searchRequests: what the search stand-in was asked (path + query)
var searchRequests = struct {
	sync.Mutex
	l []string
}{}

func serveStandIns() {
	if a := os.Getenv("E2E_SEARCH_ADDR"); a != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
			searchRequests.Lock()
			searchRequests.l = append(searchRequests.l, req.URL.RequestURI())
			searchRequests.Unlock()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"query":%q,"hits":[{"text":"e2e-search-hit"}]}`, req.URL.Query().Get("q"))
		})
		go func() { log.Fatal(http.ListenAndServe(a, mux)) }()
	}
	if a := os.Getenv("E2E_WATCH_ADDR"); a != "" {
		// the watch runner's contract (services/watch/runner.py): POST /run {script, name, timeout} → {exit, …}. The
		// stand-in doesn't run the script (the real runner is a pod that kills every other process in its container):
		// a check whose script contains "exit 0" is met, any other is "not yet"
		mux := http.NewServeMux()
		mux.HandleFunc("POST /run", func(w http.ResponseWriter, req *http.Request) {
			var in struct{ Script, Name string }
			json.NewDecoder(req.Body).Decode(&in)
			exit := 1
			if strings.Contains(in.Script, "exit 0") {
				exit = 0
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"exit":%d,"stdout":"","stderr":"","timedOut":false,"ms":1}`, exit)
		})
		go func() { log.Fatal(http.ListenAndServe(a, mux)) }()
	}
	if a := os.Getenv("E2E_DAV_ADDR"); a != "" {
		d := &fakeDAV{files: map[string][]byte{}, mods: map[string]time.Time{}, dirs: map[string]bool{"/": true}}
		go func() { log.Fatal(http.ListenAndServeTLS(a, os.Getenv("E2E_DAV_CERT"), os.Getenv("E2E_DAV_KEY"), d)) }()
	}
}

// fakeDAV: an in-memory WebDAV with what router/storagebox.go and router/content.go use (MKCOL, PUT, GET, HEAD,
// DELETE, PROPFIND Depth 0/1)
type fakeDAV struct {
	mu    sync.Mutex
	files map[string][]byte
	mods  map[string]time.Time // each file's PUT time: its getlastmodified (content-sync compares listings)
	dirs  map[string]bool
}

func (d *fakeDAV) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := req.URL.Path
	clean := "/" + strings.Trim(p, "/")
	dirKey := strings.TrimSuffix(clean, "/") + "/"
	if clean == "/" {
		dirKey = "/"
	}
	parents := func(f string) {
		parts := strings.Split(strings.Trim(f, "/"), "/")
		for i := 1; i < len(parts); i++ {
			d.dirs["/"+strings.Join(parts[:i], "/")+"/"] = true
		}
	}
	switch req.Method {
	case "MKCOL":
		if d.dirs[dirKey] {
			w.WriteHeader(405)
			return
		}
		parents(clean + "/x")
		w.WriteHeader(201)
	case "PUT":
		b, _ := io.ReadAll(req.Body)
		d.files[clean] = b
		d.mods[clean] = time.Now().UTC()
		parents(clean)
		w.WriteHeader(201)
	case "GET", "HEAD":
		b, ok := d.files[clean]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		w.WriteHeader(200)
		if req.Method == "GET" {
			w.Write(b)
		}
	case "DELETE":
		found := false
		if _, ok := d.files[clean]; ok {
			delete(d.files, clean)
			delete(d.mods, clean)
			found = true
		}
		for f := range d.files {
			if strings.HasPrefix(f, dirKey) {
				delete(d.files, f)
				found = true
			}
		}
		for k := range d.dirs {
			if strings.HasPrefix(k, dirKey) {
				delete(d.dirs, k)
				found = true
			}
		}
		if !found {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(204)
	case "PROPFIND":
		_, isFile := d.files[clean]
		if !d.dirs[dirKey] && !isFile {
			w.WriteHeader(404)
			return
		}
		type entry struct {
			href string
			dir  bool
			size int
			mod  time.Time
		}
		es := []entry{}
		if isFile {
			es = append(es, entry{clean, false, len(d.files[clean]), d.mods[clean]})
		} else {
			es = append(es, entry{dirKey, true, 0, time.Time{}})
			if req.Header.Get("Depth") == "1" {
				seen := map[string]bool{}
				for k := range d.dirs {
					if rest, ok := strings.CutPrefix(k, dirKey); ok && rest != "" && strings.Count(strings.TrimSuffix(rest, "/"), "/") == 0 && !seen[k] {
						seen[k] = true
						es = append(es, entry{k, true, 0, time.Time{}})
					}
				}
				for f, b := range d.files {
					if rest, ok := strings.CutPrefix(f, dirKey); ok && !strings.Contains(rest, "/") {
						es = append(es, entry{f, false, len(b), d.mods[f]})
					}
				}
			}
		}
		var out bytes.Buffer
		out.WriteString(`<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">`)
		for _, e := range es {
			mod := e.mod.UTC().Format(http.TimeFormat)
			var href bytes.Buffer
			xml.EscapeText(&href, []byte(e.href))
			rt := ""
			if e.dir {
				rt = "<D:collection/>"
			}
			fmt.Fprintf(&out, `<D:response><D:href>%s</D:href><D:propstat><D:prop><D:resourcetype>%s</D:resourcetype><D:getcontentlength>%d</D:getcontentlength><D:getlastmodified>%s</D:getlastmodified></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`, href.String(), rt, e.size, mod)
		}
		out.WriteString(`</D:multistatus>`)
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(207)
		w.Write(out.Bytes())
	default:
		w.WriteHeader(405)
	}
}

// callRaw: a raw body to the router (a content file upload)
func callRaw(method, path string, body []byte) (int, []byte) {
	req, _ := http.NewRequest(method, router+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// ---- the session-facing steps ------------------------------------------------------------------------------------

// sessionAPI: a call through the machine's local Jarvis API (what lease.py, transcript-search.py, … call), as user claude
func sessionAPI(method, path, body string) string {
	c := "curl -s -X " + method + " -H 'Content-Type: application/json'"
	if body != "" {
		c += " -d '" + body + "'"
	}
	return "su - claude -c \"" + strings.ReplaceAll(c, `"`, `\"`) + " http://127.0.0.1:7171" + path + "\""
}

// servicesStep: search, leases, watches and content from a running session, with Jarvis 1 out of reach
func servicesStep(id, m, secret string) {
	step("session services with Jarvis 1 unreachable: transcript search, a device lease, a watch, a content store")
	expectBlackholed(m)
	// transcript search: the box's own service (the stand-in), through the router
	expectOnMachine(m, sessionAPI("GET", "/api/search?q=e2e-"+secret[:6], "")+" | grep -c e2e-search-hit", "1")
	searchRequests.Lock()
	n := len(searchRequests.l)
	searchRequests.Unlock()
	if n == 0 {
		log.Fatal("the search stand-in got no request")
	}
	// a device lease: granted, listed in the app, returned
	expectOnMachine(m, sessionAPI("POST", "/api/sessions/"+id+"/leases/e2e-device", `{"purpose":"e2e"}`)+" | grep -o '\"status\":\"[a-z]*\"'", `"status":"granted"`)
	var l map[string]any
	must2(call(router, "GET", "/api/leases/e2e-device", nil, &l))
	if !strings.Contains(fmt.Sprint(l), id) {
		log.Fatalf("the app's lease view doesn't name the holder %s: %v", id, l)
	}
	expectOnMachine(m, sessionAPI("DELETE", "/api/sessions/"+id+"/leases/e2e-device", "")+" | grep -c '\"returned\":true'", "1")
	// a watch: armed by the session, checked by the runner (stand-in), met, delivered into the session
	expectOnMachine(m, sessionAPI("POST", "/api/sessions/"+id+"/watches", `{"name":"e2e-watch","script":"exit 0","prompt":"e2e watch met","interval":30,"maxSeconds":600}`)+" | grep -c '\"ok\":true'", "1")
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if lf := os.Getenv("E2E_ROUTER_LOG"); lf != "" {
			if b, _ := os.ReadFile(lf); bytes.Contains(b, []byte(`[watch] `+id+` "e2e-watch" delivered (watch)`)) {
				log.Printf("   watch e2e-watch: met and delivered")
				break
			}
		}
		if time.Now().After(deadline) {
			dumpState()
			log.Fatal("the watch was never delivered")
		}
		time.Sleep(3 * time.Second)
	}
	// content: the session pulled the store at boot (SESSION_CONTENT); a push from the session reaches the store
	expectOnMachine(m, "cat /home/claude/content/e2e-content/hello.txt", "content-"+secret)
	// (the harness's env, as jarvis2-machine sets it: a Fly exec's shell has none of it)
	env := "SESSION_CONTENT=e2e-content JARVIS_URL=http://127.0.0.1:7171 SESSION_API_TOKEN=jarvis2-local-proxy SESSION_ID=" + id
	expectOnMachine(m, "su - claude -c 'echo back-"+secret+" > ~/content/e2e-content/back.txt && "+env+" content-sync push e2e-content 2>&1 | tail -1'", "e2e-content: pushed 1 new, 0 changed, 0 deleted")
	s, b := callRaw("GET", "/api/content/e2e-content/file?path=back.txt", nil)
	if s != 200 || strings.TrimSpace(string(b)) != "back-"+secret {
		log.Fatalf("the session's push didn't reach the content store: %d %q", s, b)
	}
	checkNoJarvis1("after the session services")
}

// contentSetupStep: a content store with one file, before the first session (which names it)
func contentSetupStep(secret string) {
	step("a content store (on the Storage Box stand-in) with one file")
	must2(call(router, "POST", "/api/content", map[string]string{"name": "e2e-content"}, nil))
	s, b := callRaw("POST", "/api/content/e2e-content/file?path=hello.txt", []byte("content-"+secret+"\n"))
	must(s, b, "content upload")
}

// loginRefreshStep: a newer Claude pair (what the router's own refresh stores) reaches a running session's machine
// by itself (machine/claudelogin.go credsSync), with Jarvis 1 out of reach
func loginRefreshStep(m string) {
	step("the Claude login: a newer pair at the router reaches the running session's credentials file by itself")
	expectBlackholed(m)
	newer := strings.Replace(strings.Replace(fakePair, "e2e-fake-refresh", "e2e-fake-refresh-2", 1), "4102444800000", "4102444900000", 1)
	must2(call(router, "POST", "/peer/claude-login", map[string]any{"credentials": newer,
		"account": `{"oauthAccount":{"accountUuid":"e2e-account","emailAddress":"e2e@example.com"}}`, "relogin": true}, nil))
	expectOnMachine(m, "for i in $(seq 1 30); do grep -q e2e-fake-refresh-2 /home/claude/.claude/.credentials.json && break; sleep 2; done; grep -c e2e-fake-refresh-2 /home/claude/.claude/.credentials.json", "1")
	checkNoJarvis1("after the login refresh")
}
