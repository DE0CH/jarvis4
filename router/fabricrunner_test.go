package main

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// A token hermit's own code signed (aviary crates/hermit-api src/token.rs: key(1, 7) and its test claims), with the
// key hermit publishes for it
const (
	hstVector    = "hst1.1.AQGQ9sIAAHAAgAAAAAAAAAEBkPbCAABwAIAAAAAAAAACwAACBwAAAABrSdIAc3RhZmZAZXhhbXBsZS5vcmc.BshwBoZfSVF4vOt5b_NYB4A4SfZg0n8_WcFTMZ49NdtMjJA09IOVy6j6Enpa8MdylPirxw7DNv7sj8ioCrHLCg"
	hstVectorKey = `{"keys":[{"kid":1,"alg":"Ed25519","publicKey":"p-Rs6z8KcdQsdkKo5b22-NQxDMOV-A1W1PEv19s0IRQ"}]}`
)

func TestVerifyHermitSandboxToken(t *testing.T) {
	keys, err := parseHermitKeys(strings.NewReader(hstVectorKey))
	if err != nil || len(keys) != 1 {
		t.Fatal(keys, err)
	}
	c, err := verifyHST(hstVector, keys, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if c.Sandbox != "0190f6c2-0000-7000-8000-000000000001" || c.Conversation != "0190f6c2-0000-7000-8000-000000000002" || c.Expires.Unix() != 1_800_000_000 {
		t.Fatalf("%+v", c)
	}
	if _, err := verifyHST(hstVector, keys, time.Unix(1_800_000_000, 0)); err == nil {
		t.Fatal("an expired token")
	}
	bad := []byte(hstVector)
	bad[len(bad)-3] ^= 1
	for _, tok := range []string{string(bad), strings.Replace(hstVector, "hst1.1.", "hst1.2.", 1), "hst1.1.AA.AA", "x", strings.Repeat("a", 700)} {
		if _, err := verifyHST(tok, keys, time.Unix(1_700_000_000, 0)); err == nil {
			t.Fatalf("taken: %.40s", tok)
		}
	}
}

// GET /fabric/env answers the env of the session whose machine is the token's sandbox and whose conversation is the
// token's, with the runner's names; nothing to anyone else
func TestFabricEnvEndpoint(t *testing.T) {
	t.Setenv("FABRIC_HERMIT_URL", "http://hermit")
	r := newTestRouter(t)
	addSession(r, "sF", "starting", "", false)
	ks, _ := parseHermitKeys(strings.NewReader(hstVectorKey))
	fetches := 0
	keys := &hermitKeys{get: func() (map[uint32]ed25519.PublicKey, error) { fetches++; return ks, nil }}
	h := r.FabricMachineHandler(keys)
	get := func(auth string) (int, string) {
		req := httptest.NewRequest("GET", "/fabric/env", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	// the token is good but no session's machine is its sandbox yet
	if code, _ := get("Bearer " + hstVector); code != 404 {
		t.Fatalf("no machine: %d", code)
	}
	fl, err := r.fabricLine("sF")
	if err != nil || len(fl.Conversation) != 36 {
		t.Fatal(fl, err)
	}
	if again, _ := r.fabricLine("sF"); again.Conversation != fl.Conversation {
		t.Fatal("a session's conversation changed")
	}
	// another conversation than the token's: refused
	r.setFabricMachine("sF", "x0190f6c2000070008000000000000001", map[string]string{"JARVIS2_SOURCE": "source-a", "JARVIS2_URL": "http://10.202.1.1:3128"})
	if code, _ := get("Bearer " + hstVector); code != 404 {
		t.Fatalf("another conversation: %d", code)
	}
	r.st.Do(func(d *persisted) { d.Sessions["sF"].Fabric.Conversation = "0190f6c2-0000-7000-8000-000000000002" })
	code, out := get("Bearer " + hstVector)
	if code != 200 || !strings.Contains(out, `"JARVIS2_SOURCE":"source-a"`) || !strings.Contains(out, `"JARVIS2_RUNNER":"fabric"`) ||
		!strings.Contains(out, `"JARVIS2_MACHINE_ID":"x0190f6c2000070008000000000000001"`) {
		t.Fatalf("%d %s", code, out)
	}
	for _, auth := range []string{"", "Basic x", "Bearer hst1.1.AA.AA"} {
		if code, _ := get(auth); code != 401 {
			t.Fatalf("%q: %d", auth, code)
		}
	}
	if fetches != 1 {
		t.Fatalf("hermit's keys fetched %d times", fetches)
	}
	// the runner is offered only with a fabric hermit, and fabric objects are named as the kernel names them
	if !validRunner("fabric") || kernelObject(&Session{Runner: "fabric"}, "x0190f6c2000070008000000000000001", "fly") != "fabric-x0190f6c2000070008000000000000001" {
		t.Fatal("the fabric runner")
	}
	// a fabric session's sources name the fabric image; the others the session image
	t.Setenv("FABRIC_SESSION_IMAGE", "ghcr.io/de0ch/jarvis4-session-fabric@sha256:"+strings.Repeat("c", 64))
	if r.sourceImage(&Session{Runner: "fabric"}) != os.Getenv("FABRIC_SESSION_IMAGE") || r.sourceImage(&Session{Runner: "fly"}) != r.cfg.SessionImage {
		t.Fatal("the source image by runner")
	}
	t.Setenv("FABRIC_HERMIT_URL", "")
	if validRunner("fabric") || len(sessionRunners()) != 2 {
		t.Fatal("the fabric offered without a hermit")
	}
	_ = http.StatusOK
}

// a destroyed fabric session's files: DELETE /v1/workspaces/{conversation} at hermit as caller magpie
func TestDeleteFabricFiles(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got = append(got, req.Method+" "+req.URL.Path+" "+req.Header.Get("Authorization")+" "+req.Header.Get("Aviary-Protocol"))
		if strings.HasSuffix(req.URL.Path, "/bad") {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	t.Setenv("FABRIC_HERMIT_URL", srv.URL+"/")
	t.Setenv("FABRIC_HERMIT_MAGPIE_TOKEN", "mt")
	if err := deleteFabricFiles("0190f6c2-0000-7000-8000-000000000002"); err != nil {
		t.Fatal(err)
	}
	if err := deleteFabricFiles("bad"); err == nil {
		t.Fatal("a 503 taken as deleted")
	}
	if got[0] != "DELETE /v1/workspaces/0190f6c2-0000-7000-8000-000000000002 Bearer mt hermit-core=1" {
		t.Fatal(got)
	}
}
