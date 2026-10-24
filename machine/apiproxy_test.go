package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// a fake router: checks the machine signature the way requireMachine does (decoded path, no query)
func fakeRouter(t *testing.T, key tkey, handle func(w http.ResponseWriter, req *http.Request, body []byte)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		sum := sha256.Sum256(body)
		msg := req.Method + " " + req.URL.Path + " " + req.Header.Get("X-Time") + " " + hex.EncodeToString(sum[:])
		if req.Header.Get("X-Machine") != "m1" || !verify(key.pub(), []byte(msg), req.Header.Get("X-Sig")) {
			w.WriteHeader(401)
			return
		}
		handle(w, req, body)
	}))
}

func TestProxyForwardsSigned(t *testing.T) {
	t.Setenv("JARVIS2_SESSION_ID", "s1")
	key := newKey()
	var got *http.Request
	var gotBody string
	srv := fakeRouter(t, key, func(w http.ResponseWriter, req *http.Request, body []byte) {
		got, gotBody = req, string(body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hits":[]}`))
	})
	defer srv.Close()
	c := &client{base: srv.URL, me: "m1", sig: key.k, http: srv.Client()}
	p := httptest.NewServer(apiProxyHandler(c))
	defer p.Close()

	req, _ := http.NewRequest("PUT", p.URL+"/api/sessions/s1/content/my%20store/file?path=a%2Fb.txt", strings.NewReader("data"))
	req.Header.Set("CF-Access-Client-Id", "placeholder")
	req.Header.Set("Authorization", "Bearer placeholder")
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", err, resp)
	}
	if got.URL.Path != "/m/api/sessions/s1/content/my store/file" || got.URL.RawQuery != "path=a%2Fb.txt" || gotBody != "data" ||
		got.Header.Get("Authorization") != "" || got.Header.Get("CF-Access-Client-Id") != "" || got.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("forwarded %s ? %s %v %q", got.URL.Path, got.URL.RawQuery, got.Header, gotBody)
	}
	// secrets and changes for another session are refused locally
	resp, _ = http.Get(p.URL + "/api/sessions/sX/secrets")
	if resp.StatusCode != 403 {
		t.Fatal(resp.StatusCode)
	}
}

func TestProxyArmingGivesNoShell(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("JARVIS2_SESSION_ID", "s1")
	old := currentCert
	currentCert = func() (Cert, error) { return Cert{Line: "m1", Sensitive: true}, nil }
	t.Cleanup(func() { currentCert = old })
	key := newKey()
	at := time.Now().Add(2 * time.Hour).UnixMilli()
	srv := fakeRouter(t, key, func(w http.ResponseWriter, req *http.Request, body []byte) {
		switch req.URL.Path {
		case "/m/api/sessions/s1/wakeup":
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "wakeup": map[string]any{"name": "default", "at": at}})
		default:
			w.WriteHeader(404)
		}
	})
	defer srv.Close()
	c := &client{base: srv.URL, me: "m1", sig: key.k, http: srv.Client()}
	p := httptest.NewServer(apiProxyHandler(c))
	defer p.Close()
	resp, err := http.Post(p.URL+"/api/sessions/s1/wakeup", "application/json", strings.NewReader(`{"delaySeconds":7200,"prompt":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"ok":true`) || !strings.Contains(string(b), "no shell access granted") ||
		!strings.Contains(string(b), "approves or denies that message on the phone") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if l := readAllow(); len(l) != 0 {
		t.Fatalf("something was put on the allow list: %+v", l)
	}
}

func TestRepoChanges(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	ws := t.TempDir()
	d := filepath.Join(ws, "r")
	run := func(args ...string) {
		c := exec.Command("git", append([]string{"-C", d}, args...)...)
		c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	os.MkdirAll(d, 0o755)
	run("init", "-q")
	os.WriteFile(filepath.Join(d, "a"), []byte("x"), 0o644)
	got := repoChanges(ws)
	if len(got) != 1 || got[0].Name != "r" || got[0].Uncommitted != 1 || got[0].Unpushed != -1 {
		t.Fatalf("%+v", got)
	}
}

func TestProxyTakesAContentFileOnlyAttested(t *testing.T) {
	t.Setenv("JARVIS2_SESSION_ID", "s1")
	key, core := newKey(), newKey()
	old := readCoreKey
	readCoreKey = func() (string, error) { return core.pub(), nil }
	t.Cleanup(func() { readCoreKey = old })
	var attest *SignedDoc
	srv := fakeRouter(t, key, func(w http.ResponseWriter, req *http.Request, body []byte) {
		if req.URL.Path != "/m/api/sessions/m1/content/notes/file" || req.URL.Query().Get("path") != "a.txt" {
			w.WriteHeader(404)
			return
		}
		if attest != nil {
			b, _ := json.Marshal(attest)
			w.Header().Set("X-Jarvis2-Attest", string(b))
		}
		w.Write([]byte("hello"))
	})
	defer srv.Close()
	c := &client{base: srv.URL, me: "m1", sig: key.k, http: srv.Client()}
	p := httptest.NewServer(apiProxyHandler(c))
	defer p.Close()
	get := func() (int, string) {
		resp, err := http.Get(p.URL + "/api/sessions/m1/content/notes/file?path=a.txt")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	for _, a := range []*SignedDoc{nil, attestFor(core, "m2", "content", []byte("hello")), attestFor(core, "m1", "attachment", []byte("hello")),
		attestFor(core, "m1", "content", []byte("other")), attestFor(newKey(), "m1", "content", []byte("hello"))} {
		attest = a
		if code, _ := get(); code != 502 {
			t.Fatalf("taken without a matching attestation (%v): %d", a, code)
		}
	}
	attest = attestFor(core, "m1", "content", []byte("hello"))
	if code, body := get(); code != 200 || body != "hello" {
		t.Fatalf("%d %q", code, body)
	}
	if resp, _ := http.Get(p.URL + "/api/sessions/sX/content/notes/file?path=a.txt"); resp.StatusCode != 403 {
		t.Fatalf("another session: %d", resp.StatusCode)
	}
}

// jarvis-request batch: the batch reaches the router as /m/api/requests/batch, signed, body unchanged (the router
// names the session from the machine key)
func TestProxyForwardsABatch(t *testing.T) {
	t.Setenv("JARVIS2_SESSION_ID", "s1")
	key := newKey()
	var path, body string
	srv := fakeRouter(t, key, func(w http.ResponseWriter, req *http.Request, b []byte) {
		path, body = req.URL.Path, string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"b1","items":[]}`))
	})
	defer srv.Close()
	c := &client{base: srv.URL, me: "m1", sig: key.k, http: srv.Client()}
	p := httptest.NewServer(apiProxyHandler(c))
	defer p.Close()
	in := `{"summary":"two grants","items":[{"intent":"grant","holder":"status","minutes":5},{"intent":"grant","holder":"remote"}]}`
	resp, err := http.Post(p.URL+"/api/requests/batch", "application/json", strings.NewReader(in))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", err, resp)
	}
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if path != "/m/api/requests/batch" || body != in || out["id"] != "b1" {
		t.Fatalf("forwarded %s %q %v", path, body, out)
	}
}
