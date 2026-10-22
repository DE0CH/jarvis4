package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestTheClaimsDeviceSignatureIsKeptForTheSetupSession(t *testing.T) {
	st, err := testState(t, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &Router{cfg: Config{DataDir: t.TempDir()}, st: st}
	r.keepClaimDevice([]byte(`{"statement":"{\"kind\":\"claim\"}","masterSig":"m","deviceKey":"k","deviceSig":"s"}`))
	r.keepClaimDevice([]byte(`{"statement":"x"}`)) // no countersignature: nothing kept
	got := r.claimDevices()
	if len(got) != 1 || got[0].DeviceKey != "k" || got[0].Statement != `{"kind":"claim"}` {
		t.Fatalf("got %v", got)
	}
}

// R1 audit: an approval for a CI build this router was given carries CI's signature; one for any other image carries none
func TestOnlyCIBuildsCarryTheirSignature(t *testing.T) {
	st, err := testState(t, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &Router{cfg: Config{SessionImage: "ghcr.io/de0ch/jarvis4-session:sha-1@sha256:aa", SessionImageSig: "c2ln"}, st: st}
	ch := func(img string) *Doc { return &Doc{Payload: `{"kind":"challenge","request":{"image":"` + img + `"}}`} }
	a := &Approval{Challenge: ch("ghcr.io/de0ch/jarvis4-session:sha-1@sha256:aa"), Origin: &Origin{}}
	r.addApproval(a)
	b := &Approval{Challenge: ch("ghcr.io/de0ch/jarvis4-session:x@sha256:bb"), Origin: &Origin{}}
	r.addApproval(b)
	if a.ImageSig != "c2ln" || b.ImageSig != "" {
		t.Fatalf("got %q and %q", a.ImageSig, b.ImageSig)
	}
	// a newer image is pinned: a resume on the old image gets the old signature from the list (the file images.yml keeps)
	f := filepath.Join(t.TempDir(), "sigs.txt")
	os.WriteFile(f, []byte("ghcr.io/de0ch/jarvis4-session:sha-1@sha256:aa c2ln\n"), 0o600)
	r2 := &Router{cfg: Config{SessionImage: "ghcr.io/de0ch/jarvis4-session:sha-2@sha256:cc", SessionImageSig: "bmV3", ImageSigs: loadImageSigs(f)}, st: st}
	c := &Approval{Challenge: ch("ghcr.io/de0ch/jarvis4-session:sha-1@sha256:aa"), Origin: &Origin{}}
	r2.addApproval(c)
	d := &Approval{Challenge: ch("ghcr.io/de0ch/jarvis4-session:sha-2@sha256:cc"), Origin: &Origin{}}
	r2.addApproval(d)
	e := &Approval{Challenge: ch("ghcr.io/de0ch/jarvis4-session:x@sha256:bb"), Origin: &Origin{}}
	r2.addApproval(e)
	if c.ImageSig != "c2ln" || d.ImageSig != "bmV3" || e.ImageSig != "" {
		t.Fatalf("got %q, %q and %q", c.ImageSig, d.ImageSig, e.ImageSig)
	}
}

// R2: the master's signature on the core is kept by the router from the claim the core accepted, and served for the
// running core only; a core claimed before (no kept claim) is asked for its own
func TestTheRouterKeepsTheClaimForTheRunningCore(t *testing.T) {
	var claimStatus = 200
	ck := newTestKey()
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/identity":
			writeJSON(w, 200, map[string]string{"signingKey": ck.pub(), "agreementKey": "a"})
		case "/claim":
			writeJSON(w, claimStatus, map[string]string{"payload": "{}", "sig": "x"})
		default:
			writeJSON(w, 404, map[string]string{"error": "no such route"})
		}
	}))
	defer core.Close()
	r := newTestRouter(t)
	r.cfg.NoAccess = true
	r.core = &CoreClient{base: core.URL, http: http.DefaultClient}
	if r.coreCert() != nil {
		t.Fatal("a cert before any claim")
	}
	stmt := func(key string) string {
		b, _ := json.Marshal(map[string]any{"kind": "claim", "core": map[string]string{"signingKey": key}})
		return string(b)
	}
	body := func(key string) string {
		b, _ := json.Marshal(map[string]string{"statement": stmt(key), "masterSig": "ms"})
		return string(b)
	}
	claimStatus = 403
	appDo(t, r, "POST", "/api/core/claim", body(ck.pub()))
	if r.coreCert() != nil {
		t.Fatal("kept a claim the core refused")
	}
	claimStatus = 200
	appDo(t, r, "POST", "/api/core/claim", body("another-core"))
	appDo(t, r, "POST", "/api/core/claim", body(ck.pub()))
	var mc MasterCert
	if json.Unmarshal(r.coreCert(), &mc) != nil || mc.Statement != stmt(ck.pub()) || mc.MasterSig != "ms" {
		t.Fatalf("got %+v", mc)
	}
}
