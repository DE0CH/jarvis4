package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// the fabric's operator page: the fabric hermit's /ops/ and its snapshot, asked with hermit's admin token, the page's
// own headers passed on; no token, no page
func TestFabricOpsPage(t *testing.T) {
	var seen []string
	hermit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		seen = append(seen, req.Method+" "+req.URL.RequestURI()+" "+req.Header.Get("Authorization")+" "+req.Header.Get("Aviary-Protocol"))
		switch req.URL.Path {
		case "/ops/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Security-Policy", "default-src 'none'")
			w.Write([]byte("<title>Jarvis 4 fabric Ops</title>"))
		case "/ops/snapshot":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"hosts":[]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer hermit.Close()
	t.Setenv("FABRIC_HERMIT_URL", hermit.URL)
	t.Setenv("FABRIC_HERMIT_ADMIN_TOKEN", "adm")
	r := newTestRouter(t)
	h := r.Handler()
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	w := get("/api/fabric/ops/")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "fabric Ops") || w.Header().Get("Content-Security-Policy") != "default-src 'none'" {
		t.Fatalf("%d %q %v", w.Code, w.Body.String(), w.Header())
	}
	w = get("/api/fabric/ops/snapshot?tz=Asia%2FHong_Kong")
	if b, _ := io.ReadAll(w.Body); w.Code != 200 || string(b) != `{"hosts":[]}` {
		t.Fatalf("%d %s", w.Code, b)
	}
	if strings.Join(seen, "|") != "GET /ops/ Bearer adm hermit-core=1|GET /ops/snapshot?tz=Asia%2FHong_Kong Bearer adm hermit-core=1" {
		t.Fatalf("%q", seen)
	}
	t.Setenv("FABRIC_HERMIT_ADMIN_TOKEN", "")
	if w := get("/api/fabric/ops/"); w.Code != 503 {
		t.Fatalf("no token: %d", w.Code)
	}
}
