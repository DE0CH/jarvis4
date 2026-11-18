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
	// not offered on the New session page until a fabric session pauses and is destroyed as on the other runners
	for _, g := range sessionRunners() {
		if g.ID == "fabric" {
			t.Fatal("New session offers the fabric before its sessions can pause")
		}
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

// a fabric machine's state is hermit's word, not Fly's: the lost-machine check marked a fabric session lost 30 s after
// it booted, its machine being in neither Fly's nor AWS's list (2026-11-18)
func TestTheLostCheckAsksHermitForAFabricMachine(t *testing.T) {
	r := newTestRouter(t)
	const m = "x01a1ec41c22f71e49e50601a78aeffde"
	addSession(r, "s1", "started", m, false)
	r.st.Do(func(d *persisted) {
		d.Sessions["s1"].Runner = "fabric"
		d.Sessions["s1"].Fabric = &FabricLine{Conversation: "6bd76dff-094c-425f-b971-c9b531254b1e", Machine: m}
	})
	t.Setenv("FABRIC_HERMIT_URL", "http://hermit.invalid")
	oldFly, oldState := listFlyMachines, fabricMachineState
	t.Cleanup(func() { listFlyMachines, fabricMachineState = oldFly, oldState })
	listFlyMachines = func() ([]flyMachineDetail, error) { return nil, nil }
	hermit := "started"
	asked := ""
	fabricMachineState = func(conversation, machine string) (string, error) {
		asked = conversation + " " + machine
		return hermit, nil
	}
	seen := map[string]int{}
	r.lostTick(seen)
	r.lostTick(seen)
	if s := sessionByID(r, "s1"); s.Lost != nil || s.State != "started" {
		t.Fatalf("a running fabric machine was marked lost: %s %v", s.State, s.Error)
	}
	if asked != "6bd76dff-094c-425f-b971-c9b531254b1e "+m {
		t.Fatalf("asked hermit about %q", asked)
	}
	// hermit no longer has it: lost, said as the fabric's
	hermit = "released"
	r.lostTick(seen)
	r.lostTick(seen)
	s := sessionByID(r, "s1")
	if s.Lost == nil || s.State != "failed" || !strings.Contains(s.Error, "was released on the fabric") {
		t.Fatalf("a released fabric machine: %s %q", s.State, s.Error)
	}
}

// hermit's answer in the lost check's words: this machine's sandbox starting or ready is running; another sandbox of
// the conversation, none, or a gone one is released; one being released is destroying
func TestFabricMachineState(t *testing.T) {
	var answer string
	code := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/conversations/c1/sandbox" || req.Header.Get("Authorization") != "Bearer mt" || req.Header.Get("Aviary-Protocol") != "hermit-core=1" {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(answer))
	}))
	defer srv.Close()
	t.Setenv("FABRIC_HERMIT_URL", srv.URL+"/")
	t.Setenv("FABRIC_HERMIT_MAGPIE_TOKEN", "mt")
	const m = "x01a1ec41c22f71e49e50601a78aeffde"
	for _, c := range []struct {
		code      int
		body, out string
	}{
		{200, `{"id":"01a1ec41-c22f-71e4-9e50-601a78aeffde","state":"ready"}`, "started"},
		{202, `{"id":"01a1ec41-c22f-71e4-9e50-601a78aeffde","state":"starting"}`, "started"},
		{200, `{"id":"01a1ec41-c22f-71e4-9e50-601a78aeffde","state":"releasing"}`, "destroying"},
		{200, `{"id":"01a1ec41-c22f-71e4-9e50-601a78aeffde","state":"gone"}`, "released"},
		{200, `{"id":"01a1ffff-c22f-71e4-9e50-601a78aeffde","state":"ready"}`, "released"},
		{404, `{"code":"no_sandbox"}`, "released"},
	} {
		code, answer = c.code, c.body
		got, err := fabricMachineState("c1", m)
		if err != nil || got != c.out {
			t.Errorf("%d %s: %q %v, want %q", c.code, c.body, got, err, c.out)
		}
	}
	code, answer = 503, `{}`
	if _, err := fabricMachineState("c1", m); err == nil {
		t.Error("hermit unavailable: an error (the machine is not taken for lost)")
	}
}

func sessionByID(r *Router, id string) (s Session) {
	r.st.Do(func(d *persisted) { s = *d.Sessions[id] })
	return
}
