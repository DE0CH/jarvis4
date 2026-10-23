package main

// Deyao's repo list and the GitHub picker (Jarvis 1's /api/repos, /api/github/repos).
//
// Every repo on the list is a GitHub repo with its own deploy key (Deyao, 2026-10-10): adding one in the app's
// Settings asks the core for a deploy key (docs/DESIGN.md "Deploy keys"), which the phone approves with Face ID;
// the core makes the key pair, adds the public half to the repo on GitHub and keeps the private half in the
// store github-<repo>. Removing one deletes both, the same way. The router only relays: it holds no GitHub
// token that can push or manage keys (the picker lists repos with GITHUB_READ_TOKEN, metadata read only), and
// it records an entry only from the core's answer. Sessions clone, pull and push a repo over SSH with its
// store's key (machine/deploykeys.go); the picker only fills New session's `repos`.
// The repo list is the router's own (repos.json, a row of router_docs in its database), shown in /api/state `repos`.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// RepoEntry: a repo on the list. Repo, URL and Store follow from the GitHub name; Sensitive, Fingerprint and
// KeyAt come from the core's answer when its deploy key was made.
type RepoEntry struct {
	Name        string `json:"name"`  // the clone's directory in ~/workspace
	URL         string `json:"url"`   // https://github.com/<owner>/<name>.git
	Repo        string `json:"repo"`  // <owner>/<name>
	Store       string `json:"store"` // the store holding its deploy key
	Sensitive   bool   `json:"sensitive"`
	Fingerprint string `json:"fingerprint,omitempty"`
	KeyAt       string `json:"keyAt,omitempty"`
}

var githubRepoRE = regexp.MustCompile(`^(?:https://github\.com/|git@github\.com:)?([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$`)

// parseGitHubRepo: "owner/name" from a GitHub URL or name ("" when it isn't one)
func parseGitHubRepo(s string) string {
	m := githubRepoRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil || m[2] == "." || m[2] == ".." || strings.Contains(m[2], "..") {
		return ""
	}
	return m[1] + "/" + m[2]
}

// repoStore: the core's RepoStore (core/deploykeys.go) — github-<name> for DE0CH's repos, else
// github-<owner>-<name>, lower case, anything outside [a-z0-9-] as "-"
func repoStore(repo string) string {
	owner, name, _ := strings.Cut(strings.ToLower(repo), "/")
	slug := name
	if owner != "de0ch" {
		slug = owner + "-" + name
	}
	b := []byte(slug)
	for i, ch := range b {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9') {
			b[i] = '-'
		}
	}
	return "github-" + strings.Trim(string(b), "-")
}

func repoEntry(repo string) RepoEntry {
	_, name, _ := strings.Cut(repo, "/")
	return RepoEntry{Name: name, URL: "https://github.com/" + repo + ".git", Repo: repo, Store: repoStore(repo)}
}

func (r *Router) Repos() []RepoEntry {
	r.ops.reposMu.Lock()
	defer r.ops.reposMu.Unlock()
	return r.readRepos()
}

// readRepos: the list; every entry is a GitHub repo, its derived fields recomputed from its URL
func (r *Router) readRepos() []RepoEntry {
	var raw []RepoEntry
	if b, ok := r.st.ReadDoc("repos.json"); ok {
		json.Unmarshal(b, &raw)
	}
	out := []RepoEntry{}
	for _, e := range raw {
		repo := parseGitHubRepo(e.URL)
		if repo == "" {
			log.Printf("repos: %q isn't a GitHub repo: left off the list", e.URL)
			continue
		}
		n := repoEntry(repo)
		n.Sensitive, n.Fingerprint, n.KeyAt = e.Sensitive, e.Fingerprint, e.KeyAt
		out = append(out, n)
	}
	return out
}

// updateRepos: read-modify-write under the lock (two adds at once used to drop one in Jarvis 1)
func (r *Router) updateRepos(fn func([]RepoEntry) []RepoEntry) error {
	r.ops.reposMu.Lock()
	defer r.ops.reposMu.Unlock()
	next := fn(r.readRepos())
	b, _ := json.MarshalIndent(next, "", " ")
	return r.st.WriteDoc("repos.json", b)
}

// keyAnswer: the core's answer to a finished deploy-key request, applied to the list
type keyAnswer struct {
	Kind        string `json:"kind"` // deploy-key-added | deploy-key-removed
	Repo        string `json:"repo"`
	Sensitive   bool   `json:"sensitive"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"` // the core from R2 answers the key, not its fingerprint
}

// sshFingerprint: "SHA256:<base64>" of an "ssh-ed25519 <base64 wire>" line ("" when it isn't one)
func sshFingerprint(pub string) string {
	_, b, ok := strings.Cut(pub, " ")
	w, err := base64.StdEncoding.DecodeString(b)
	if !ok || err != nil || len(w) == 0 {
		return ""
	}
	sum := sha256.Sum256(w)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// proof: the core's signed answer (outcomes.go: what vouches for "approved" to a session that asked for the key)
func (r *Router) applyKeyAnswer(a keyAnswer, proof *Doc) error {
	if a.Fingerprint == "" {
		a.Fingerprint = sshFingerprint(a.PublicKey)
	}
	repo := parseGitHubRepo(a.Repo)
	if repo == "" {
		return fmt.Errorf("the core's answer names no GitHub repo")
	}
	same := func(e RepoEntry) bool { return strings.EqualFold(e.Repo, repo) }
	// a pending request for the same thing is answered too (inbox.go)
	r.dropRequests(func(q *InboxRequest) bool {
		return q.Kind == requestKindRepo && strings.EqualFold(q.Params.Repo, repo) && (q.Params.Action == "add") == (a.Kind == "deploy-key-added")
	}, outcomeApproved, proof)
	return r.updateRepos(func(rs []RepoEntry) []RepoEntry {
		out := []RepoEntry{}
		for _, e := range rs {
			if !same(e) {
				out = append(out, e)
			}
		}
		if a.Kind == "deploy-key-added" {
			e := repoEntry(repo)
			e.Sensitive, e.Fingerprint, e.KeyAt = a.Sensitive, a.Fingerprint, time.Now().UTC().Format(time.RFC3339)
			out = append(out, e)
		}
		return out
	})
}

func init() {
	stateHooks = append(stateHooks, func(r *Router, out map[string]any) {
		if r != nil {
			out["repos"] = r.Repos()
		}
	})
}

// ---- deploy keys: the core's two calls, relayed; the list follows the core's signed answer ----------------

func (r *Router) registerDeployKeys(app appRoute) {
	app("POST /api/repos/key/begin", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Action    string `json:"action"`
			Repo      string `json:"repo"`
			Sensitive bool   `json:"sensitive"`
			// the app's key pair (R2): its store name and key title, the public key, and the store's keys holding the
			// private half (core/keys.go)
			Store     string          `json:"store,omitempty"`
			Title     string          `json:"title,omitempty"`
			PublicKey string          `json:"publicKey,omitempty"`
			Keys      json.RawMessage `json:"keys,omitempty"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in)
		repo := parseGitHubRepo(in.Repo)
		if repo == "" || (in.Action != "add" && in.Action != "remove") {
			writeJSON(w, 400, map[string]string{"error": "a GitHub repo (owner/name or its URL) and action add or remove"})
			return
		}
		// the key's title on GitHub is Jarvis 4's own: the secrets deletes the repo's keys with the same title before it
		// adds one, so Jarvis 2's title ("jarvis2 <store>") would take Jarvis 2's key away
		if in.Store != "" && in.Title != deployKeyTitle(in.Store) {
			writeJSON(w, 400, map[string]string{"error": "the deploy key's title must be " + deployKeyTitle(in.Store) + " (an older app sends Jarvis 2's: update the Jarvis 4 app)"})
			return
		}
		body := map[string]any{"action": in.Action, "repo": repo, "sensitive": in.Sensitive}
		if in.Store != "" {
			body["store"], body["title"], body["publicKey"] = in.Store, in.Title, in.PublicKey
			if len(in.Keys) > 0 {
				body["keys"] = in.Keys
			}
		}
		b, _ := json.Marshal(body)
		r.relayDeployKey(w, "/deploy-keys/begin", b, false)
	})
	// ?inbox=ID: the Inbox request this page answers; when a session asked for the repo, the answer names the add-store
	// approval that puts the repo's store into that session (followups), for the phone to sign under the same Face ID
	app("POST /api/repos/key/finish", func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<16))
		r.relayDeployKeyFor(w, "/deploy-keys/finish", b, true, req.URL.Query().Get("inbox"))
	})
}

// relayDeployKey: the core's answer unchanged; a finished add or remove also updates the list. A core from
// before deploy keys answers its mux's plain-text 404: say so plainly.
func (r *Router) relayDeployKey(w http.ResponseWriter, path string, body []byte, finish bool) {
	r.relayDeployKeyFor(w, path, body, finish, "")
}

func (r *Router) relayDeployKeyFor(w http.ResponseWriter, path string, body []byte, finish bool, inbox string) {
	status, b, err := r.deployKeyCall(path, body)
	if err != nil {
		log.Printf("deploy keys %s: %v", path, err)
		writeJSON(w, 503, map[string]any{"error": "the core isn't running", "coreDown": true})
		return
	}
	var d Doc
	if status == 404 && json.Unmarshal(b, &d) != nil {
		writeJSON(w, 501, map[string]string{"error": "the running core predates deploy keys: it makes them once it has been restarted with the new core image (then Recover)"})
		return
	}
	if status == 502 && json.Unmarshal(b, &d) == nil {
		// the core says only what GitHub said; a 403/404 means the token can't manage this repo's deploy keys
		// (the kernel's secrets answers the same signed error)
		var e struct{ Error string }
		if d.Decode(&e) == nil && (strings.HasPrefix(e.Error, "github: HTTP 403") || strings.HasPrefix(e.Error, "github: HTTP 404")) {
			writeJSON(w, 502, map[string]string{"error": "the GitHub token in github-deploy-keys can't manage this repo's deploy keys (" + e.Error +
				"): it needs a fine-grained token with Repository permission \"Administration: read and write\" (all repositories)"})
			return
		}
	}
	if finish && status == 200 && json.Unmarshal(b, &d) == nil {
		var a keyAnswer
		if d.Decode(&a) == nil && (a.Kind == "deploy-key-added" || a.Kind == "deploy-key-removed") {
			asked := r.repoAskers(a) // before the answer drops the requests
			if err := r.applyKeyAnswer(a, &d); err != nil {
				log.Printf("repos: %v", err)
			}
			if f := r.repoFollowups(a, asked, inbox); len(f) > 0 {
				// beside the core's document, not under its signature: the phone checks each approval itself
				writeJSON(w, 200, map[string]any{"payload": d.Payload, "sig": d.Sig, "followups": f})
				return
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

// deployKeyTitle: Jarvis 4's deploy keys' title on GitHub (the app's Checks.deployKeyTitle)
func deployKeyTitle(store string) string { return "jarvis4 " + store }

// deployKeyCall: a deploy-key call to whoever keeps the stores (storeCore): the kernel's serving secrets on a box with
// no core (kernel/secrets/deploykeys.go: the same calls and signed answers, under secrets' key), else the core
func (r *Router) deployKeyCall(path string, body []byte) (int, []byte, error) {
	return r.storeCore().Raw("POST", path, body)
}

// repoAsker: a session that asked for the repo (its request, as filed)
type repoAsker struct {
	request string
	session string
	origin  Origin
	expl    string
}

// repoAskers: the sessions whose pending requests an added key answers (each gets the repo's store)
func (r *Router) repoAskers(a keyAnswer) []repoAsker {
	repo := parseGitHubRepo(a.Repo)
	if a.Kind != "deploy-key-added" || repo == "" {
		return nil
	}
	out := []repoAsker{}
	r.st.Do(func(d *persisted) {
		for _, q := range d.Inbox {
			if q.Kind == requestKindRepo && q.Params.Action == "add" && q.Params.Session != "" && strings.EqualFold(q.Params.Repo, repo) {
				out = append(out, repoAsker{request: q.ID, session: q.Params.Session, origin: q.Origin, expl: q.Explanation})
			}
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].request < out[j].request })
	return out
}

// repoFollowups: the repo's store into each session that asked for the repo (Deyao, 2026-10-15: "one Face ID, not a
// repo-key approval followed by a separate add-store"; DECISIONS 182). An add-store approval per running session that
// doesn't hold the store yet, filed at once now that the store exists (the core makes a challenge only for a store it
// has). The one for the request this page answered (inbox) is returned: the phone showed it before Face ID ("then adds
// the store to session …") and signs it under the same Face ID, after checking it is exactly that. Any other asking
// session's approval waits in the Inbox on its own. A session that isn't running gets nothing (it asks for the store
// again when it runs). The approval's origin is the request's caller and call, without its signed filing: the
// session already hears the outcome of what it filed (the repo's), and its waiter pulls the store.
func (r *Router) repoFollowups(a keyAnswer, asked []repoAsker, inbox string) []string {
	store := repoStore(parseGitHubRepo(a.Repo))
	out := []string{}
	for _, q := range asked {
		var machine string
		held := false
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[q.session]; s != nil && s.State == "started" && s.hasLine() {
				machine, held = s.MachineID, slices.Contains(s.Stores, store)
			}
		})
		if machine == "" || held {
			log.Printf("repos: %s asked for %s; it isn't running (or holds %s already): no add-store", q.session, a.Repo, store)
			continue
		}
		o := q.origin
		o.Signed, o.Item, o.Batch = nil, 0, ""
		o.Call = APICall{Method: "POST", Path: "/api/repos/key/finish", Args: map[string]any{"repo": a.Repo, "store": store, "for": q.request}}
		id, err := r.addStoreApproval(machine, store, o, q.expl, "")
		if err != nil {
			log.Printf("repos: the add-store of %s for %s: %v", store, q.session, err)
			continue
		}
		log.Printf("repos: %s asked for %s: add-store %s filed (%s)", q.session, a.Repo, store, id)
		if q.request == inbox {
			out = append(out, id)
		}
	}
	return out
}

// ---- the GitHub picker -------------------------------------------------------------------------------------

type ghRepo struct {
	FullName    string `json:"fullName"`
	URL         string `json:"url"`
	HTMLURL     string `json:"htmlUrl"`
	Private     bool   `json:"private"`
	Fork        bool   `json:"fork"`
	Archived    bool   `json:"archived"`
	Description string `json:"description"`
	Language    string `json:"language"`
	PushedAt    string `json:"pushedAt"`
	Owner       string `json:"owner"`
}

type ghCache struct {
	at    time.Time
	repos []ghRepo
}

var githubAPI = "https://api.github.com"
var githubClient = &http.Client{Timeout: 20 * time.Second}

const ghTTL = 5 * time.Minute

// GitHubRepos: every repo the read token sees, newest push first; cached 5 minutes. The token never leaves.
func (r *Router) GitHubRepos(refresh bool) ([]ghRepo, time.Time, error) {
	tok := os.Getenv("GITHUB_READ_TOKEN")
	if tok == "" {
		return nil, time.Time{}, &httpStatusErr{503, "the router has no GITHUB_READ_TOKEN: it can't list your GitHub repos"}
	}
	r.ops.mu.Lock()
	c := r.ops.gh
	r.ops.mu.Unlock()
	if !refresh && c.repos != nil && time.Since(c.at) < ghTTL {
		return c.repos, c.at, nil
	}
	out := []ghRepo{}
	for page := 1; page <= 10; page++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/user/repos?per_page=100&page=%d&sort=pushed&direction=desc&affiliation=owner,collaborator,organization_member", githubAPI, page), nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "jarvis2-router/1")
		resp, err := githubClient.Do(req)
		if err != nil {
			return nil, time.Time{}, &httpStatusErr{502, "GitHub unreachable: " + err.Error()}
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, time.Time{}, &httpStatusErr{502, fmt.Sprintf("GitHub /user/repos: HTTP %d %s", resp.StatusCode, clip(string(b), 200))}
		}
		var items []struct {
			FullName    string `json:"full_name"`
			CloneURL    string `json:"clone_url"`
			HTMLURL     string `json:"html_url"`
			Private     bool   `json:"private"`
			Fork        bool   `json:"fork"`
			Archived    bool   `json:"archived"`
			Description string `json:"description"`
			Language    string `json:"language"`
			PushedAt    string `json:"pushed_at"`
			UpdatedAt   string `json:"updated_at"`
			Owner       struct {
				Login string `json:"login"`
			} `json:"owner"`
		}
		if err := json.Unmarshal(b, &items); err != nil {
			return nil, time.Time{}, &httpStatusErr{502, "GitHub /user/repos: " + err.Error()}
		}
		for _, it := range items {
			u := it.CloneURL
			if u == "" {
				u = "https://github.com/" + it.FullName + ".git"
			}
			p := it.PushedAt
			if p == "" {
				p = it.UpdatedAt
			}
			out = append(out, ghRepo{it.FullName, u, it.HTMLURL, it.Private, it.Fork, it.Archived, it.Description, it.Language, p, it.Owner.Login})
		}
		if len(items) < 100 {
			break
		}
	}
	now := time.Now()
	r.ops.mu.Lock()
	r.ops.gh = ghCache{now, out}
	r.ops.mu.Unlock()
	return out, now, nil
}

func (r *Router) registerRepos(app appRoute) {
	app("GET /api/repos", func(w http.ResponseWriter, req *http.Request) { writeJSON(w, 200, map[string]any{"repos": r.Repos()}) })
	r.registerDeployKeys(app)
	app("GET /api/github/repos", func(w http.ResponseWriter, req *http.Request) {
		configured := os.Getenv("GITHUB_READ_TOKEN") != ""
		repos, at, err := r.GitHubRepos(req.URL.Query().Get("refresh") == "1")
		if err != nil {
			st := 502
			if he, ok := err.(*httpStatusErr); ok {
				st = he.status
			}
			writeJSON(w, st, map[string]any{"error": err.Error(), "configured": configured})
			return
		}
		writeJSON(w, 200, map[string]any{"repos": repos, "cachedAt": at.UnixMilli(), "configured": configured})
	})
}
