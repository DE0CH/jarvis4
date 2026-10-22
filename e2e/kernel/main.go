// e2e/kernel: a kernel line's whole life on real Fly machines (infra/e2e-kernel.sh runs it): a router and the eight
// kernel components on this session, the machines reaching the router over Fly's private network. It plays the
// iPhone with software keys: Recovers the kernel's secrets (the public TEST master key, e2e/testdata), signs the root
// grant with a root key, gives the spawner the Fly token, then a new session on the kernel (the phone signs its
// source), waits for its machine to boot from its kernel documents and pull its secrets, pauses it (its snapshot goes
// into the next source), resumes it (a new machine restores that snapshot), and destroys it (the source burns).
//
//	E2E_ROUTER (the router), E2E_SPAWNER (the spawner, direct), E2E_DATA_DIR (the router's state), E2E_MASTER_KEY_FILE,
//	E2E_FLY_TOKEN
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/DE0CH/jarvis4/e2e/routerdb"
	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/secrets"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

var router = os.Getenv("E2E_ROUTER")

func call(method, url string, body any) (int, []byte) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, rd)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func must(method, url string, body any, out any) {
	code, b := call(method, url, body)
	if code/100 != 2 {
		log.Fatalf("%s %s: HTTP %d %s", method, url, code, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			log.Fatalf("%s %s: %v (%s)", method, url, err, b)
		}
	}
}

func step(f string, a ...any) { log.Printf("==== "+f, a...) }

// session: the router's own record of it (its state file), kernel line included
type session struct {
	State     string `json:"state"`
	MachineID string `json:"machineId"`
	Booted    string `json:"booted"`
	Error     string `json:"error"`
	Kernel    *struct {
		Source     string   `json:"source"`
		SourceCert *sig.Doc `json:"sourceCert"`
		Burned     bool     `json:"burned"`
	} `json:"kernel"`
}

func readSession(id string) (*session, bool) {
	b, err := routerdb.StateJSON()
	if err != nil {
		return nil, false
	}
	var st struct {
		Sessions map[string]*session `json:"sessions"`
		Records  []struct {          // a record carries the session's own fields (router/state.go Record)
			ID     string `json:"id"`
			Kernel *struct {
				Burned bool `json:"burned"`
			} `json:"kernel"`
		} `json:"records"`
	}
	if json.Unmarshal(b, &st) != nil {
		return nil, false
	}
	if s := st.Sessions[id]; s != nil {
		return s, false
	}
	for _, r := range st.Records {
		if r.ID == id {
			return nil, r.Kernel != nil && r.Kernel.Burned
		}
	}
	return nil, false
}

func waitFor(what string, limit time.Duration, ok func() bool) {
	for end := time.Now().Add(limit); ; time.Sleep(3 * time.Second) {
		if ok() {
			return
		}
		if time.Now().After(end) {
			log.Fatalf("timed out after %s waiting for %s", limit, what)
		}
	}
}

func main() {
	log.SetFlags(log.Ltime)
	mk, err := os.ReadFile(os.Getenv("E2E_MASTER_KEY_FILE"))
	if err != nil {
		log.Fatal(err)
	}
	master, err := sig.SignerFromPEM(mk)
	if err != nil {
		log.Fatal(err)
	}
	phone, _ := sig.NewSigner()
	phoneAgree, _ := ecdh.P256().GenerateKey(rand.Reader)
	root, _ := sig.NewSigner()

	step("the kernel's secrets: a Reset with the test master key, naming the phone and the root key")
	var id struct{ SigningKey, AgreementKey string }
	must("GET", router+"/api/kernel/secrets/identity", nil, &id)
	bundle := []byte(`{"format":"keys"}`)
	sum := sha256.Sum256(bundle)
	st, _ := json.Marshal(map[string]any{"kind": "kernel-claim", "master": master.PublicKey(),
		"secrets": map[string]string{"signingKey": id.SigningKey, "agreementKey": id.AgreementKey},
		"phone":   map[string]string{"signingKey": phone.PublicKey(), "agreementKey": sig.B64.EncodeToString(phoneAgree.PublicKey().Bytes())},
		"root":    root.PublicKey(), "bundleSha256": hex.EncodeToString(sum[:])})
	ms, _ := master.Sign(st)
	sealed, err := secrets.SealTo(id.AgreementKey, bundle, "jarvis2/kernel-claim")
	if err != nil {
		log.Fatal(err)
	}
	must("POST", router+"/api/kernel/secrets/claim", map[string]any{"statement": string(st), "masterSig": ms, "bundle": sealed}, nil)

	step("the spawner's Fly token, sealed to it")
	var sd sig.Doc
	must("GET", os.Getenv("E2E_SPAWNER")+"/identity", nil, &sd)
	var sid sig.Identity
	json.Unmarshal([]byte(sd.Payload), &sid)
	tok, _ := json.Marshal(map[string]string{"FLY_API_TOKEN": os.Getenv("E2E_FLY_TOKEN")})
	ts, err := sig.SealTo(sid.AgreementKey, tok, "jarvis2/fly-token")
	if err != nil {
		log.Fatal(err)
	}
	must("POST", os.Getenv("E2E_SPAWNER")+"/fly-token", map[string]any{"sealed": ts}, nil)

	step("the root grant: ⊤ on the sink, signed by the root key")
	var draft struct{ Payload string }
	must("GET", router+"/api/kernel/root-grant/draft", nil, &draft)
	rs, _ := root.Sign([]byte(draft.Payload))
	must("POST", router+"/api/kernel/root-grant", map[string]any{"grant": map[string]string{"payload": draft.Payload, "sig": rs}}, nil)
	var ks struct{ Serves bool }
	must("GET", router+"/api/kernel", nil, &ks)
	if !ks.Serves {
		log.Fatal("the kernel doesn't serve new sessions after its root grant")
	}

	step("a new session on the kernel; the phone signs its source")
	var created struct{ ID string }
	must("POST", router+"/api/sessions", map[string]any{"label": "e2e on the kernel", "harness": "opencode", "size": "small"}, &created)
	var a struct {
		ID, Kind  string
		Challenge sig.Doc
	}
	waitFor("the approval", time.Minute, func() bool {
		var s struct {
			Approvals []struct {
				ID, Kind, Session string
				Challenge         sig.Doc
			} `json:"approvals"`
		}
		must("GET", router+"/api/state", nil, &s)
		for _, x := range s.Approvals {
			if x.Session == created.ID {
				a.ID, a.Kind, a.Challenge = x.ID, x.Kind, x.Challenge
			}
		}
		return a.ID != ""
	})
	if a.Kind != "kernel-source" {
		log.Fatalf("approval kind %s", a.Kind)
	}
	var c doc.Cert
	json.Unmarshal([]byte(a.Challenge.Payload), &c)
	log.Printf("source %s, image %s", c.Succ, c.Source.Image)
	ps, _ := phone.Sign([]byte(a.Challenge.Payload))
	must("POST", router+"/api/approvals/"+a.ID+"/respond", map[string]string{"signature": ps}, nil)

	running := func(what string) string {
		var m string
		waitFor(what, 15*time.Minute, func() bool {
			s, _ := readSession(created.ID)
			if s != nil && s.State == "failed" {
				log.Fatalf("%s: the session failed: %s", what, s.Error)
			}
			if s != nil && s.State == "started" && s.Booted == s.MachineID && s.MachineID != "" {
				m = s.MachineID
				return true
			}
			return false
		})
		return m
	}
	m1 := running("the first machine to boot from its kernel documents and pull its secrets")
	log.Printf("machine %s booted", m1)

	step("pause: the snapshot goes into the next source")
	must("POST", router+"/api/sessions/"+created.ID+"/pause", map[string]any{}, nil)
	var snap string
	waitFor("paused", 15*time.Minute, func() bool {
		s, _ := readSession(created.ID)
		if s != nil && s.State == "failed" {
			log.Fatalf("pause: the session failed: %s", s.Error)
		}
		if s == nil || s.State != "paused" || s.Kernel == nil || s.Kernel.SourceCert == nil {
			return false
		}
		sc, err := doc.PeekCert(*s.Kernel.SourceCert)
		if err == nil && sc.Pred == doc.Object("fly-"+m1) {
			snap = sc.Source.Snapshot
			return true
		}
		return false
	})
	if snap == "" {
		log.Fatal("the paused source names no snapshot")
	}
	log.Printf("paused into a source holding snapshot %s…", snap[:12])

	step("resume: a new machine from that source restores the snapshot")
	must("POST", router+"/api/sessions/"+created.ID+"/resume", map[string]any{}, nil)
	m2 := running("the second machine")
	if m2 == m1 {
		log.Fatal("the resume ran on the same machine")
	}
	log.Printf("machine %s booted from the snapshot", m2)

	step("destroy: archived, its source burned")
	must("POST", router+"/api/sessions/"+created.ID+"/destroy?force=1", map[string]any{}, nil)
	waitFor("the destroy", 15*time.Minute, func() bool {
		s, burned := readSession(created.ID)
		return s == nil && burned
	})
	fmt.Println("e2e kernel: ok")
}
