package main

// The session-facing API, machine side. Jarvis 1's session scripts (schedule-wakeup.sh, schedule-cron.sh,
// lease.py, transcript-search.py, content-sync, retire-session.sh, …) call `$JARVIS_URL/api/...`
// with Cloudflare Access headers and the session's SESSION_API_TOKEN. In a Jarvis 4 session JARVIS_URL is this
// proxy (127.0.0.1:7171, served by the supervisor, `jarvis2-machine supervisor`): it drops those headers and forwards each request to
// the router as /m/api/<rest>, signed with the machine key like every other /m call.
//
// Two calls never leave the machine: GET …/secrets (refused: the supervisor serves the secrets on its own socket,
// secrets.go) and GET …/changes (the repos' uncommitted/unpushed work).
//
// A wakeup, cron or watch the session arms comes back as a delivery of its own signed request (deliver.go): no router
// feature gets a shell for it. In a session holding a sensitive store each such delivery waits for Deyao to approve
// that message on the phone, or for a standing rule he signed for its kind (messages.go).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	apiProxyAddr = "127.0.0.1:7171"
	apiMaxBody   = 64 << 20
)

// serveAPIProxy: runs for the supervisor's life
func serveAPIProxy(c *client) {
	addr := os.Getenv("JARVIS2_API_ADDR")
	if addr == "" {
		addr = apiProxyAddr
	}
	srv := &http.Server{Addr: addr, Handler: apiProxyHandler(c), ReadHeaderTimeout: 30 * time.Second}
	log.Printf("session API on http://%s (→ router /m/api)", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("session API stopped: %v", err)
	}
}

func apiProxyHandler(c *client) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/sessions/{id}/secrets", func(w http.ResponseWriter, req *http.Request) {
		if !ownSession(w, c, req.PathValue("id")) {
			return
		}
		// the secrets don't travel over HTTP: the supervisor serves them on its own socket (secrets.go, session-secret)
		writeJSONResp(w, 410, map[string]string{"error": "the session's secrets come from the supervisor: session-secret --names | --keys K1,K2 --exec CMD"})
	})
	mux.HandleFunc("GET /api/sessions/{id}/changes", func(w http.ResponseWriter, req *http.Request) {
		if !ownSession(w, c, req.PathValue("id")) {
			return
		}
		home, _ := os.UserHomeDir()
		writeJSONResp(w, 200, map[string]any{"checked": true, "repos": repoChanges(filepath.Join(home, "workspace")), "status": ""})
	})
	// a content file (content-sync, a task's script): taken only with the core's attestation of exactly these bytes
	mux.HandleFunc("GET /api/sessions/{id}/content/{name}/file", func(w http.ResponseWriter, req *http.Request) {
		if !ownSession(w, c, req.PathValue("id")) {
			return
		}
		status, hdr, body, err := forwardToRouter(c, req)
		if err != nil {
			writeJSONResp(w, 502, map[string]string{"error": "Jarvis 4 router unreachable: " + err.Error()})
			return
		}
		if status == 200 {
			if err := checkContentAttest(c.me, hdr.Get("X-Jarvis2-Attest"), body); err != nil {
				log.Printf("content: refused %s: %v", req.URL.Query().Get("path"), err)
				writeJSONResp(w, 502, map[string]string{"error": "content file refused: " + err.Error()})
				return
			}
		}
		copyResp(w, status, hdr, body)
	})
	for _, p := range []string{"POST /api/sessions/{id}/wakeup", "POST /api/sessions/{id}/wakeups", "POST /api/sessions/{id}/crons"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, req *http.Request) { armedNote(w, req, c) })
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, req *http.Request) {
		status, hdr, body, err := forwardToRouter(c, req)
		if err != nil {
			writeJSONResp(w, 502, map[string]string{"error": "Jarvis 4 router unreachable: " + err.Error()})
			return
		}
		copyResp(w, status, hdr, body)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		writeJSONResp(w, 404, map[string]string{"error": "only /api/… is served here"})
	})
	return mux
}

func writeJSONResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func copyResp(w http.ResponseWriter, status int, hdr http.Header, body []byte) {
	for _, h := range []string{"Content-Type", "Content-Range", "Content-Disposition"} {
		if v := hdr.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(status)
	w.Write(body)
}

// ownSession: Jarvis 1's scripts name the session by SESSION_ID (the router's id) or FLY_MACHINE_ID
func ownSession(w http.ResponseWriter, c *client, id string) bool {
	if id == sessionID(c.me) || id == c.me {
		return true
	}
	writeJSONResp(w, 403, map[string]string{"error": "this is session " + sessionID(c.me) + ", not " + id})
	return false
}

// forwardToRouter: the request as /m/api/<rest>; the signature covers the decoded path, as the router checks it
func forwardToRouter(c *client, req *http.Request) (int, http.Header, []byte, error) {
	body, err := io.ReadAll(io.LimitReader(req.Body, apiMaxBody+1))
	if err != nil {
		return 0, nil, nil, err
	}
	if len(body) > apiMaxBody {
		return 0, nil, nil, errors.New("request body too large")
	}
	return c.signedDo(req.Method, "/m"+req.URL.Path, "/m"+req.URL.EscapedPath(), req.URL.RawQuery, body, req.Header.Get("Content-Type"))
}

// signedDo: like client.raw, with a query string (unsigned: the router signs the path only) and an escaped path
func (c *client) signedDo(method, path, escaped, query string, body []byte, contentType string) (int, http.Header, []byte, error) {
	if k, err := loadPrivate(); err == nil {
		c.sig = k.sig
	}
	t := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256(body)
	sig, err := sign(c.sig, []byte(method+" "+path+" "+t+" "+hex.EncodeToString(sum[:])))
	if err != nil {
		return 0, nil, nil, err
	}
	u := c.base + escaped
	if query != "" {
		u += "?" + query
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("X-Machine", c.me)
	req.Header.Set("X-Time", t)
	req.Header.Set("X-Sig", sig)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b, err
}

// ---- changes (Jarvis 1's GET /api/sessions/:id/changes, archive.REPO_CHANGES_SH) ---------------------------

type repoChange struct {
	Name        string `json:"name"`
	Uncommitted int    `json:"uncommitted"`
	Unpushed    int    `json:"unpushed"` // -1: the branch has no upstream
}

func repoChanges(workspace string) []repoChange {
	out := []repoChange{}
	dirs, _ := filepath.Glob(filepath.Join(workspace, "*", ".git"))
	for _, g := range dirs {
		d := filepath.Dir(g)
		rc := repoChange{Name: filepath.Base(d)}
		if b, err := sessionCommand(nil, "git", "-C", d, "status", "--porcelain").Output(); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if strings.TrimSpace(l) != "" {
					rc.Uncommitted++
				}
			}
		}
		if sessionCommand(nil, "git", "-C", d, "rev-parse", "--abbrev-ref", "@{u}").Run() != nil {
			rc.Unpushed = -1
		} else if b, err := sessionCommand(nil, "git", "-C", d, "rev-list", "@{u}..HEAD", "--count").Output(); err == nil {
			rc.Unpushed, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		}
		out = append(out, rc)
	}
	return out
}

// ---- arming: the answer says how it will be delivered ------------------------------------------------------

func armedNote(w http.ResponseWriter, req *http.Request, c *client) {
	status, hdr, body, err := forwardToRouter(c, req)
	if err != nil {
		writeJSONResp(w, 502, map[string]string{"error": "Jarvis 4 router unreachable: " + err.Error()})
		return
	}
	var ans map[string]any
	if status != 200 || json.Unmarshal(body, &ans) != nil || ans["ok"] != true {
		copyResp(w, status, hdr, body)
		return
	}
	// the wakeup comes back as a delivery of this very request (deliver.go), checked against this line's keys and
	// attested by the core; nobody needs a shell for it
	ans["delivery"] = "delivered as this session's own signed request; no shell access granted"
	if cert, err := currentCert(); err == nil && cert.Sensitive {
		ans["note"] = "this session holds a sensitive store: when it is due, Deyao approves or denies that message on the phone (or a standing rule he signed for its kind delivers it); a denial comes back as an Inbox outcome"
	}
	writeJSONResp(w, 200, ans)
}

// readCoreKey: the core's key as boot wrote it (a var so tests can give their own)
var readCoreKey = attestKey

// checkContentAttest: the core's input-log entry (machine, "content", sha256 of the bytes) the router sent with a
// content file (router/content.go)
func checkContentAttest(me, header string, body []byte) error {
	coreKey, err := readCoreKey()
	if err != nil {
		return errors.New("no core key on this machine")
	}
	var d SignedDoc
	if header == "" || json.Unmarshal([]byte(header), &d) != nil {
		return errors.New("no core attestation (the input isn't in the core's log)")
	}
	return checkAttest(coreKey, me, "content", body, &d)
}
