package main

// The router's side of vouched inputs (vouch.go). The router isn't trusted, so these tests only check that it asks
// the core and the machine for the right things; the refusals that count are in core/vouch_test.go and
// machine/vouch_test.go.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// v2Core: a core with the input log; records each call's body
type v2Core struct {
	fakeCore
	mu     sync.Mutex
	bodies map[string][]map[string]any
	refuse string // approve_by_dead_machine answers 403 with this (the core's refusal)
	// /kill answers these first, one per call (failedsession_test.go): status and the core's error
	killErrs []coreRefusal
	order    []string // every path, in the order called
}

type coreRefusal struct {
	status int
	msg    string
}

func (c *v2Core) last(path string) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.bodies[path]
	if len(b) == 0 {
		return nil
	}
	return b[len(b)-1]
}

func (c *v2Core) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	raw, _ := io.ReadAll(req.Body)
	var b map[string]any
	json.Unmarshal(raw, &b)
	c.mu.Lock()
	if c.bodies == nil {
		c.bodies = map[string][]map[string]any{}
	}
	c.bodies[req.URL.Path] = append(c.bodies[req.URL.Path], b)
	c.order = append(c.order, req.URL.Path)
	c.mu.Unlock()
	switch req.URL.Path {
	case "/input-log":
		writeJSON(w, 200, map[string]any{"entries": []any{}, "head": c.key.doc(map[string]any{"kind": "input-log-head", "seq": 0})})
	case "/succession":
		writeJSON(w, 200, c.key.doc(map[string]any{"kind": "challenge", "nonce": strings.Repeat("a", 64), "request": b}))
	case "/approve/by-dead-machine":
		c.mu.Lock()
		refuse := c.refuse
		c.mu.Unlock()
		if refuse == "" {
			c.fakeCore.ServeHTTP(w, req)
			return
		}
		writeJSON(w, 403, c.key.doc(map[string]any{"error": refuse}))
	case "/kill":
		c.mu.Lock()
		var e *coreRefusal
		if len(c.killErrs) > 0 {
			e, c.killErrs = &c.killErrs[0], c.killErrs[1:]
		}
		c.mu.Unlock()
		if e != nil {
			writeJSON(w, e.status, c.key.doc(map[string]any{"error": e.msg}))
			return
		}
		writeJSON(w, 200, c.key.doc(map[string]any{"kind": "killed", "id": b["machine"]}))
	case "/attest":
		writeJSON(w, 200, c.key.doc(map[string]any{"kind": "input", "machine": b["machine"], "input": b["input"], "sha256": b["sha256"]}))
	default:
		c.fakeCore.ServeHTTP(w, req)
	}
}

func v2Rig(t *testing.T) (*rig, *v2Core) {
	rg := newRig(t)
	vc := &v2Core{fakeCore: fakeCore{key: rg.core.key}}
	cs := httptest.NewServer(vc)
	t.Cleanup(cs.Close)
	rg.r.core = &CoreClient{base: cs.URL, http: http.DefaultClient}
	keptLogProbe.Lock()
	keptLogProbe.at = time.Time{}
	keptLogProbe.Unlock()
	t.Cleanup(func() { keptLogProbe.Lock(); keptLogProbe.at = time.Time{}; keptLogProbe.Unlock() })
	return rg, vc
}

func v2Cert(rg *rig, machine, config string) *Doc {
	return rg.core.key.doc(map[string]any{"kind": "succession-cert", "line": "m1", "vouch": 2,
		"machine": map[string]string{"id": machine, "signingKey": rg.mkey.pub(), "image": "ghcr.io/de0ch/jarvis4-session@sha256:" + strings.Repeat("1", 64)},
		"stores":  []string{"claude", "default"}, "options": map[string]string{"harness": "claude", "permissionMode": "auto", "config": config}})
}

func TestTheSettingsGoIntoTheChallenge(t *testing.T) {
	rg, vc := v2Rig(t)
	sid, err := rg.r.CreateSession(NewSession{Label: "Refactor", Prompt: "please refactor", Harness: "claude", Repos: "https://github.com/DE0CH/claude-env.git", OneShot: true})
	if err != nil {
		t.Fatal(err)
	}
	opts, _ := vc.last("/succession")["options"].(map[string]any)
	var c SessionConfig
	if opts == nil || json.Unmarshal([]byte(opts["config"].(string)), &c) != nil {
		t.Fatalf("no config in %v", vc.last("/succession"))
	}
	if c.Prompt != "please refactor" || c.Label != "Refactor" || !c.OneShot || len(c.Repos) != 1 || c.Repos[0] != "https://github.com/DE0CH/claude-env.git" {
		t.Fatalf("config %+v", c)
	}
	waitFor(t, "approval", func() bool {
		ok := false
		rg.r.st.Do(func(d *persisted) {
			for _, a := range d.Approvals {
				ok = ok || a.Session == sid
			}
		})
		return ok
	})
}

func TestAnUnattendedResumeCarriesTheCertsConfigAndOnlyThat(t *testing.T) {
	rg, vc := v2Rig(t)
	conf := `{"v":1,"label":"x"}`
	rg.r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.Cert, s.Image, s.Prompt, s.Label = v2Cert(rg, "m1", conf), "ghcr.io/de0ch/jarvis4-session@sha256:"+strings.Repeat("1", 64), "a new prompt", "a new label"
	})
	if err := rg.r.Resume("s1", false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "dead-machine asked", func() bool { return vc.last("/approve/by-dead-machine") != nil })
	opts := vc.last("/succession")["options"].(map[string]any)
	if opts["config"] != conf || opts["once"] != nil {
		t.Fatalf("resume options %v", opts)
	}
	waitFor(t, "idle", func() bool { _, err := rg.r.lock("s1", "test-end"); return err == nil })
}

func TestAResumePromptOrRollbackNeedsThePhone(t *testing.T) {
	rg, vc := v2Rig(t)
	rg.r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.Cert = v2Cert(rg, "m1", `{"v":1}`)
		s.Ops = &SessionOps{Rollback: &RollbackMark{Marker: "uuid-1234", Pred: "m1"}}
	})
	rg.r.SetResumePrompt("s1", "carry on with the report")
	if err := rg.r.Resume("s1", false); err != nil {
		t.Fatal(err)
	}
	var a *Approval
	waitFor(t, "approval", func() bool {
		rg.r.st.Do(func(d *persisted) {
			for _, x := range d.Approvals {
				if x.Session == "s1" {
					a = x
				}
			}
		})
		return a != nil
	})
	if a.Kind != "resume-upgrade" || vc.last("/approve/by-dead-machine") != nil {
		t.Fatalf("a one-time input went unattended: %+v", a)
	}
	var once OnceInputs
	json.Unmarshal([]byte(vc.last("/succession")["options"].(map[string]any)["once"].(string)), &once)
	if once.Prompt != "carry on with the report" || once.Rollback != "uuid-1234" {
		t.Fatalf("once %+v", once)
	}
	rg.r.st.Do(func(d *persisted) {
		if d.Schedules["s1"].ResumePrompt != "" || d.Sessions["s1"].Ops.Rollback != nil {
			t.Fatal("the prompt or rollback would be delivered again another way")
		}
	})
}

func TestAKillNamesTheMachinesSnapshot(t *testing.T) {
	rg, vc := v2Rig(t)
	if _, err := rg.r.killMachine("m1", false); err != nil {
		t.Fatal(err)
	}
	snap, _ := vc.last("/kill")["snapshot"].(map[string]any)
	body := snapBytes(rg.r, "m1")
	sig := []byte(rg.r.snap("m1").Sig)
	sum := sha256.Sum256(body)
	if snap == nil || snap["sha256"] != hex.EncodeToString(sum[:]) || snap["sig"] != string(sig) || snap["required"] != false {
		t.Fatalf("kill %v", vc.last("/kill"))
	}
	// a pause asks the core to keep the machine rather than kill it without that snapshot
	rg.r.killMachine("m1", true)
	if snap, _ := vc.last("/kill")["snapshot"].(map[string]any); snap["required"] != true {
		t.Fatalf("kill %v", vc.last("/kill"))
	}
}

func TestDeliveriesToAVouchingMachine(t *testing.T) {
	rg, vc := v2Rig(t)
	r := rg.r
	r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.State, s.MachineID, s.Cert = "started", "m1", v2Cert(rg, "m1", `{"v":1}`)
	})
	// a wakeup made outside the session: nothing vouches for it (the router has no free-text delivery at all)
	r.st.Do(func(d *persisted) {
		sched(d, "s1").Wakeups["w"] = &Wakeup{Name: "w", At: 1, Prompt: "x", ArmedAt: 7}
	})
	if err := r.fireWakeup("s1", "w", 7); !errors.Is(err, errNotVouched) {
		t.Fatalf("an app-made wakeup: %v", err)
	}
	// the session's own: handed over with the core's attestation of exactly its body
	body := []byte(`{"name":"w","prompt":"check CI","delaySeconds":60}`)
	signed := &SignedRequest{Machine: "m1", Method: "POST", Path: "/m/api/sessions/s1/wakeup", At: "1", Body: base64.StdEncoding.EncodeToString(body), Sig: "s"}
	r.st.Do(func(d *persisted) { sched(d, "s1").Wakeups["w"].Signed = signed })
	got := make(chan Delivery, 1)
	go func() {
		b, _ := mqWaitKind(r, "m1", "delivery", 10*time.Second)
		var d Delivery
		json.Unmarshal(b, &d)
		got <- d
		r.mqAnswer(d.ID, DeliveryResult{ID: d.ID, OK: true})
	}()
	if err := r.fireWakeup("s1", "w", 7); err != nil {
		t.Fatal(err)
	}
	d := <-got
	sum := sha256.Sum256(body)
	at := vc.last("/attest")
	if d.Kind != "wakeup" || d.Request == nil || d.Request.Body != signed.Body || d.Attest == nil ||
		at["machine"] != "m1" || at["input"] != "wakeup" || at["sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("delivery %+v attest %v", d, at)
	}
}

func TestMachineConfigIsOnlyFormatExceptions(t *testing.T) {
	rg, _ := v2Rig(t)
	rg.r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.State, s.MachineID, s.Prompt, s.Label = "started", "m1", "secret instructions", "title"
	})
	out, err := rg.r.machineConfig("m1")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"sessionId": true, "discordChannel": true, "liveSyncSeconds": true, "taskRun": true, "taskTrigger": true, "tunnelProof": true}
	for k := range out {
		if !allowed[k] {
			t.Fatalf("/m/config carries %s", k)
		}
	}
}

// the app's resume with a prompt: the prompt is queued before the resume starts, so the resume's goroutine always
// carries it to the phone (queued after, it could start without it and the prompt reached the machine unsigned)
func TestResumeWithPromptAlwaysReachesThePhone(t *testing.T) {
	rg, vc := v2Rig(t)
	rg.r.st.Do(func(d *persisted) { d.Sessions["s1"].Cert = v2Cert(rg, "m1", `{"v":1}`) })
	if err := rg.r.resumeWithPrompt("s1", false, "carry on"); err != nil {
		t.Fatal(err)
	}
	var a *Approval
	waitFor(t, "approval", func() bool {
		rg.r.st.Do(func(d *persisted) {
			for _, x := range d.Approvals {
				if x.Session == "s1" {
					a = x
				}
			}
		})
		return a != nil
	})
	var once OnceInputs
	json.Unmarshal([]byte(vc.last("/succession")["options"].(map[string]any)["once"].(string)), &once)
	if a.Kind != "resume-upgrade" || once.Prompt != "carry on" {
		t.Fatalf("approval %+v once %+v", a, once)
	}
	// a refused resume (the session isn't paused now) leaves the earlier queued prompt as it was
	rg.r.SetResumePrompt("s1", "earlier")
	if err := rg.r.resumeWithPrompt("s1", false, "later"); err == nil {
		t.Fatal("resumed a session that isn't paused")
	}
	rg.r.st.Do(func(d *persisted) {
		if p := d.Schedules["s1"].ResumePrompt; p != "earlier" {
			t.Fatalf("queued prompt %q", p)
		}
	})
}

// An image attached on New session: its sha256 and size go into the signed config, the app can read the staged bytes
// back for the approval page, and the machine's listing carries the core's attestation of each file as it is now (the
// input log): a file swapped after the phone signed is attested under its own hash, which the machine refuses
// (machine/rollback_test.go TestFetchAttachments).
func TestAnAttachmentIsSignedByHashAndAttestedIntoTheInputLog(t *testing.T) {
	rg, vc := v2Rig(t)
	r := rg.r
	r.cfg.NoAccess = true
	// a core after R2: no /input-log, so the router keeps the entries itself
	cs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/input-log" {
			writeJSON(w, 404, map[string]string{"error": "no such route"})
			return
		}
		vc.ServeHTTP(w, req)
	}))
	t.Cleanup(cs.Close)
	r.core = &CoreClient{base: cs.URL, http: http.DefaultClient}

	photo := "\x89PNG the photo"
	if code, out := appDo(t, r, "POST", "/api/uploads", photo, "x-upload-id", "upA", "x-upload-name", "IMG 1.png"); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	code, out := appDo(t, r, "POST", "/api/sessions", `{"requestId":"rA","label":"look","prompt":"what is this?","harness":"claude",
		"attachments":{"uploadId":"upA","files":[{"name":"IMG 1.png"}]}}`)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	sid := out["id"].(string)
	waitFor(t, "succession", func() bool { return vc.last("/succession") != nil })
	var c SessionConfig
	json.Unmarshal([]byte(vc.last("/succession")["options"].(map[string]any)["config"].(string)), &c)
	sum := sha256.Sum256([]byte(photo))
	want := hex.EncodeToString(sum[:])
	if len(c.Attachments) != 1 || c.Attachments[0] != (AttachmentRef{Name: "IMG_1.png", Sha256: want, Size: int64(len(photo))}) || c.Prompt != "what is this?" {
		t.Fatalf("signed config %+v", c)
	}

	// the app reads the staged bytes back (the approval page hashes them against the signed config)
	h := r.Handler()
	get := func(target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", target, nil))
		return w
	}
	if w := get("/api/sessions/" + sid + "/attachments/IMG_1.png"); w.Code != 200 || w.Body.String() != photo {
		t.Fatalf("app read: %d %q", w.Code, w.Body.String())
	}
	if w := get("/api/sessions/" + sid + "/attachments/other.png"); w.Code != 404 {
		t.Fatalf("another name: %d", w.Code)
	}
	if w := get("/api/sessions/s1/attachments/IMG_1.png"); w.Code != 404 {
		t.Fatalf("another session: %d", w.Code)
	}

	// the session's machine lists them with the core's attestation; the attestation is in the router's input log
	r.st.Do(func(d *persisted) {
		d.Sessions[sid].MachineID, d.Sessions[sid].State = "mA", "initialising"
		d.Machines["mA"] = sid
	})
	mx := newTestMachine(r, "mA")
	mh := r.MachineHandler()
	listing := func() map[string]any {
		t.Helper()
		code, out := mx.do(t, mh, "GET", "/m/attachments", "")
		if code != 200 {
			t.Fatalf("%d %v", code, out)
		}
		return out
	}
	attested := func(out map[string]any) map[string]any {
		t.Helper()
		a, _ := out["attest"].(map[string]any)["IMG_1.png"].(map[string]any)
		var e map[string]any
		if a == nil || json.Unmarshal([]byte(a["payload"].(string)), &e) != nil {
			t.Fatalf("no attestation in %v", out)
		}
		return e
	}
	e := attested(listing())
	if e["machine"] != "mA" || e["input"] != "attachment" || e["sha256"] != want {
		t.Fatalf("attestation %v", e)
	}
	if at := vc.last("/attest"); at["origin"] != "cert" || at["sha256"] != want {
		t.Fatalf("attest asked %v", at)
	}
	ils, _ := r.st.ReadLog("", logInput)
	b := bytes.Join(ils, []byte("\n"))
	if !strings.Contains(string(b), `\"input\":\"attachment\"`) || !strings.Contains(string(b), want) {
		t.Fatalf("input log %q", b)
	}

	// swapped in the bucket after the phone signed: attested under the new bytes' hash, never the signed one
	var upID string
	r.st.Do(func(d *persisted) { upID = d.Sessions[sid].Ops.Upload })
	if err := r.objPutBytes(uploadKey(upID, "IMG_1.png"), []byte("another picture")); err != nil {
		t.Fatal(err)
	}
	if e := attested(listing()); e["sha256"] == want {
		t.Fatal("a swapped file was attested under the signed hash")
	}
}
