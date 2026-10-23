package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// On a box with no core adding a repo goes to the kernel's serving secrets (kernel/secrets/deploykeys.go: the
// same calls and signed answers): begin and finish are relayed there, never to the core; the signed
// deploy-key-added puts the repo on the list; secrets' refusals come back with their status, a GitHub 403 explained.
func TestDeployKeysOnTheKernel(t *testing.T) {
	rg := newRig(t)
	rg.r.cfg.NoAccess = true
	sk := newTestKey()
	var mu sync.Mutex
	var calls []string
	finish := 200
	secrets := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		mu.Lock()
		calls = append(calls, req.URL.Path+" "+string(b))
		mu.Unlock()
		switch req.URL.Path {
		case "/deploy-keys/begin":
			writeJSON(w, 200, sk.doc(map[string]any{"kind": "deploy-key-begin", "pending": "p1", "repo": "DE0CH/jarvis4", "store": "github-jarvis4"}))
		case "/deploy-keys/finish":
			if finish == 502 {
				writeJSON(w, 502, sk.doc(map[string]any{"kind": "error", "error": "github: HTTP 403: Resource not accessible"}))
				return
			}
			writeJSON(w, 200, sk.doc(map[string]any{"kind": "deploy-key-added", "pending": "p1", "repo": "DE0CH/jarvis4", "store": "github-jarvis4",
				"sensitive": true, "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGQ2e3Hn7m0YkqNn3b0yQ1Bq0nqQ0P1n8n8n8n8n8n8n"}))
		default:
			w.WriteHeader(404)
		}
	}))
	defer secrets.Close()
	rg.r.cfg.NoCore = true
	rg.r.wireKernel(&KernelClient{url: func(role string) string { return secrets.URL }, http: http.DefaultClient, ids: map[string]sig.Identity{}})
	rg.r.st.Do(func(d *persisted) { d.KernelRoot = &gv.Signed{By: "root"} })
	coreCalls := func() int {
		rg.core.mu.Lock()
		defer rg.core.mu.Unlock()
		n := 0
		for _, c := range rg.core.calls {
			if strings.HasPrefix(c, "/deploy-keys") {
				n++
			}
		}
		return n
	}

	// Jarvis 2's title would make secrets delete Jarvis 2's key for the repo: refused before anything is asked
	code, out := appDo(t, rg.r, "POST", "/api/repos/key/begin", `{"action": "add", "repo": "DE0CH/jarvis4", "store": "github-jarvis4", "title": "jarvis2 github-jarvis4"}`)
	if code != 400 || len(calls) != 0 {
		t.Fatalf("Jarvis 2's title: %d %v", code, out)
	}
	code, out = appDo(t, rg.r, "POST", "/api/repos/key/begin", `{"action": "add", "repo": "https://github.com/DE0CH/jarvis4", "sensitive": true, "store": "github-jarvis4", "title": "jarvis4 github-jarvis4"}`)
	if code != 200 || out["payload"] == nil {
		t.Fatalf("begin: %d %v", code, out)
	}
	code, out = appDo(t, rg.r, "POST", "/api/repos/key/finish", `{"pending": "p1", "signature": "s", "share": {}}`)
	if code != 200 || out["payload"] == nil {
		t.Fatalf("finish: %d %v", code, out)
	}
	if coreCalls() != 0 {
		t.Fatal("the core was asked")
	}
	mu.Lock()
	if len(calls) != 2 || !strings.Contains(calls[0], `"repo":"DE0CH/jarvis4"`) || !strings.Contains(calls[0], `"title":"jarvis4 github-jarvis4"`) || !strings.HasPrefix(calls[1], "/deploy-keys/finish") {
		t.Fatalf("secrets got %v", calls)
	}
	mu.Unlock()
	repos := rg.r.Repos()
	if len(repos) != 1 || repos[0].Repo != "DE0CH/jarvis4" || !repos[0].Sensitive {
		t.Fatalf("repos %+v", repos)
	}

	// GitHub refused the token: secrets' 502, explained
	finish = 502
	code, out = appDo(t, rg.r, "POST", "/api/repos/key/finish", `{"pending": "p1"}`)
	if code != 502 || !strings.Contains(out["error"].(string), "Administration: read and write") {
		t.Fatalf("502: %d %v", code, out)
	}

	// a box with a core: the core keeps the deploy keys
	rg.r.secretsStores = nil
	appDo(t, rg.r, "POST", "/api/repos/key/begin", `{"action": "remove", "repo": "DE0CH/jarvis4"}`)
	if coreCalls() != 1 {
		t.Fatal("the core wasn't asked before the kernel serves")
	}
}
