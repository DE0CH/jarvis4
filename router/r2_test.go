package main

// R2 (the core as small as it can be): what the core answers beside a cert — its input-log entry and the line's
// carry rebound — is kept by the router; the core keeps no log for reading and has no /carry/forward.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTheRouterKeepsWhatComesBesideACert(t *testing.T) {
	ck := newTestKey()
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/certify":
			d := ck.doc(map[string]any{"kind": "succession-cert", "predecessorId": "m1", "machine": map[string]string{"id": "m2"}})
			writeJSON(w, 200, map[string]any{"payload": d.Payload, "sig": d.Sig,
				"entry": ck.doc(map[string]any{"kind": "input", "seq": 0, "input": "cert", "machine": "m2"}), "carry": "BLOB-M2"})
		case "/attest":
			writeJSON(w, 200, ck.doc(map[string]any{"kind": "input", "seq": 1, "input": "wakeup", "machine": "m2"}))
		default: // no /input-log, no /carry/forward
			writeJSON(w, 404, map[string]string{"error": "no such route"})
		}
	}))
	defer core.Close()
	r := newTestRouter(t)
	r.core = &CoreClient{base: core.URL, http: http.DefaultClient}
	keptLogProbe.Lock()
	keptLogProbe.at = time.Time{}
	keptLogProbe.Unlock()
	t.Cleanup(func() { keptLogProbe.Lock(); keptLogProbe.at = time.Time{}; keptLogProbe.Unlock() })
	r.saveCarry("m1", "BLOB-M1")

	cert, ans, err := r.core.CallAnswer("/certify", map[string]any{"carry": r.readCarry("m1")})
	if err != nil || ans.Entry == nil || ans.Carry != "BLOB-M2" || strings.Contains(cert.Payload, "BLOB") {
		t.Fatalf("%v %+v", err, ans)
	}
	r.logInputs(ans.Entry)
	r.carryAfter("m1", "m2", cert, ans)
	if r.readCarry("m2") != "BLOB-M2" || r.readCarry("m1") != "" {
		t.Fatal("the rebound carry wasn't kept for the successor (or the predecessor's stayed)")
	}
	a, _ := r.core.Call("/attest", map[string]string{})
	r.logInputs(a)
	raw, _ := r.st.ReadLog("", logInput)
	lines := []string{}
	for _, l := range raw {
		lines = append(lines, string(l))
	}
	if len(lines) != 2 || !strings.Contains(lines[0], `\"input\":\"cert\"`) || !strings.Contains(lines[1], `\"input\":\"wakeup\"`) {
		t.Fatalf("input log %q", lines)
	}
}

// R2: the core takes exact values only, so the router fills in the defaults, sorts the stores and salts a new line
func TestTheRouterFillsInSuccessionDefaults(t *testing.T) {
	rg, vc := v2Rig(t)
	if _, err := rg.r.succession(nil, "", []string{"gmail", "default", "gmail"}, "", "", "img", "", ""); err != nil {
		t.Fatal(err)
	}
	b := vc.last("/succession")
	o := b["options"].(map[string]any)
	st := b["stores"].([]any)
	salt, _ := b["salt"].(string)
	if o["harness"] != "claude" || o["permissionMode"] != "auto" || len(st) != 2 || st[0] != "default" || st[1] != "gmail" || len(salt) < 16 {
		t.Fatalf("succession %v", b)
	}
	rg.r.succession(rg.cert, "", []string{"default"}, "claude", "bypass", "img", "", "")
	if b := vc.last("/succession"); b["salt"] != nil || b["options"].(map[string]any)["permissionMode"] != "bypass" {
		t.Fatalf("a successor: %v", b)
	}
}

// R2: the app's key pair passes through to the core; GitHub's refusal gets the token hint here, not in the core; the
// list's fingerprint comes from the public key the core answers
func TestDeployKeyRelayForTheAppsKeyPair(t *testing.T) {
	ck := newTestKey()
	var got map[string]any
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		json.NewDecoder(req.Body).Decode(&got)
		switch req.URL.Path {
		case "/deploy-keys/begin":
			writeJSON(w, 200, ck.doc(map[string]any{"kind": "deploy-key-begin"}))
		case "/deploy-keys/finish":
			writeJSON(w, 502, ck.doc(map[string]any{"kind": "error", "error": "github: HTTP 403: Resource not accessible"}))
		}
	}))
	defer core.Close()
	r := newTestRouter(t)
	r.cfg.NoAccess = true
	r.core = &CoreClient{base: core.URL, http: http.DefaultClient}
	// the app's per-key entries (core/keys.go) reach the core unchanged
	appDo(t, r, "POST", "/api/repos/key/begin", `{"action":"add","repo":"DE0CH/x","store":"github-x","title":"jarvis4 github-x","publicKey":"ssh-ed25519 AAAA","keys":[{"store":"github-x","key":"K","data":"d"}]}`)
	if ks, _ := got["keys"].([]any); got["store"] != "github-x" || got["publicKey"] != "ssh-ed25519 AAAA" || len(ks) != 1 || ks[0].(map[string]any)["key"] != "K" {
		t.Fatalf("relayed %v", got)
	}
	code, out := appDo(t, r, "POST", "/api/repos/key/finish", `{}`)
	if code != 502 || !strings.Contains(fmt.Sprint(out["error"]), "Administration: read and write") {
		t.Fatalf("%d %v", code, out)
	}
	if fp := sshFingerprint("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGjzWkhLdE9cqrkvb+MrbIBFxyF6Q9lXVddCSv5+R8gN"); !strings.HasPrefix(fp, "SHA256:") || len(fp) != 50 {
		t.Fatalf("fingerprint %q", fp)
	}
}
