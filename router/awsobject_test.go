package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

const awsMachine = "i-0123456789abcdef0"

// machineCertOnto: a well-formed spawner cert (source → succ, ⊤), as PeekCert reads it (the signature isn't checked)
func machineCertOnto(t *testing.T, succ doc.Object) *sig.Doc {
	t.Helper()
	c := doc.Cert{Kind: "succession", Pred: doc.NewSource(make([]byte, 16)), Succ: succ, Pair: perm.Top(),
		Machine: &doc.Machine{Image: kernelImage}, Signer: "spawner", IssuedAt: doc.Now()}
	if err := c.Check(); err != nil {
		t.Fatal(err)
	}
	p, _ := json.Marshal(c)
	return &sig.Doc{Payload: string(p)}
}

// a kernel machine's object is "<runner>-<id>", as the machine checks it (machine/main.go machineObject): the
// spawner's cert onto it first, else the session's runner, else the default
func TestKernelObjectNamesTheRunner(t *testing.T) {
	awsCert := &Session{Runner: "aws", Kernel: &KernelLine{MachineCert: machineCertOnto(t, doc.Object("aws-"+awsMachine))}}
	flyCert := &Session{Kernel: &KernelLine{MachineCert: machineCertOnto(t, "fly-0123456789abcd")}}
	for _, c := range []struct {
		s                 *Session
		machine, fallback string
		want              doc.Object
	}{
		{awsCert, awsMachine, "fly", doc.Object("aws-" + awsMachine)},
		{flyCert, "0123456789abcd", "aws", "fly-0123456789abcd"},                                             // the cert wins over the default
		{flyCert, "fedcba9876543210", "fly", "fly-fedcba9876543210"},                                         // a cert for another machine: by runner
		{&Session{Runner: "aws", Kernel: &KernelLine{}}, awsMachine, "fly", doc.Object("aws-" + awsMachine)}, // no cert yet
		{&Session{Runner: "fly", Kernel: &KernelLine{}}, "0123456789abcd", "aws", "fly-0123456789abcd"},
		{&Session{Kernel: &KernelLine{}}, awsMachine, "aws", doc.Object("aws-" + awsMachine)}, // "" = the default
		{nil, "0123456789abcd", "fly", "fly-0123456789abcd"},
	} {
		if got := kernelObject(c.s, c.machine, c.fallback); got != c.want {
			t.Errorf("kernelObject(%+v, %s, %s) = %s, want %s", c.s, c.machine, c.fallback, got, c.want)
		}
	}
}

// recorder: the router's kernel calls, by path, with their bodies
type recorder struct {
	mu     sync.Mutex
	bodies map[string][]string
	next   http.RoundTripper
}

func (rc *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(b))
		rc.mu.Lock()
		rc.bodies[req.URL.Path] = append(rc.bodies[req.URL.Path], string(b))
		rc.mu.Unlock()
	}
	return rc.next.RoundTrip(req)
}

// an AWS session takes stores: the input attest is the notary's challenge over aws-<id> (it was fly-<id>, and the
// machine refused every added store: "the notary's challenge is for another input or machine"), and the downgrade's
// identity cert names aws-<id>
func TestAnAWSMachinesInputsAreAttestedUnderItsAWSName(t *testing.T) {
	rg, k := kernelRig(t)
	rc := &recorder{bodies: map[string][]string{}, next: http.DefaultTransport}
	rg.r.wireKernel(&KernelClient{url: k.URLFor, http: &http.Client{Transport: rc}, ids: map[string]sig.Identity{}})
	obj := doc.Object("aws-" + awsMachine)
	grant := gv.Signed{Grant: k.RootTop(), By: "root"}
	rg.r.st.Do(func(d *persisted) {
		d.Sessions["sAWS"] = &Session{ID: "sAWS", Runner: "aws", MachineID: awsMachine, State: "started",
			Kernel: &KernelLine{MachineCert: machineCertOnto(t, obj), Grant: &grant}}
		d.Machines[awsMachine] = "sAWS"
	})
	sum := strings.Repeat("ab", 32)
	a, err := rg.r.attestInput(awsMachine, "add-store", "cert", sum)
	if err != nil {
		t.Fatal(err)
	}
	var ch doc.Challenge
	if err := json.Unmarshal([]byte(a.Payload), &ch); err != nil {
		t.Fatal(err)
	}
	// machine/kernelboot.go KernelInputSubject over machineObject (aws-<id> on AWS)
	h := sha256.Sum256([]byte("jarvis2-input\n" + string(obj) + "\nadd-store\n" + sum))
	if ch.Subject != hex.EncodeToString(h[:]) || ch.About != "input" {
		t.Fatalf("challenge %+v: not over %s", ch, obj)
	}
	// the downgrade asks the identity signer for (aws-M, aws-M, P); the move then fails here only because the rig's
	// grant is the root's, not one on that machine
	rg.r.kernelDowngrade(awsMachine, nil)
	var signed []string
	rc.mu.Lock()
	for p, bs := range rc.bodies {
		if strings.HasSuffix(p, "/sign") {
			signed = append(signed, bs...)
		}
	}
	rc.mu.Unlock()
	if len(signed) != 1 {
		t.Fatalf("identity /sign calls: %v", signed)
	}
	var in struct {
		Machine doc.Object `json:"machine"`
	}
	if json.Unmarshal([]byte(signed[0]), &in) != nil || in.Machine != obj {
		t.Fatalf("identity /sign asked for %s", signed[0])
	}
}

// no other code names a kernel machine "fly-" by hand: kernelObject does (the AWS store bug was three such places)
func TestOnlyKernelObjectPrefixesFly(t *testing.T) {
	re := regexp.MustCompile(`"fly-"\s*\+|\+\s*"fly-"`)
	files, _ := os.ReadDir(".")
	for _, f := range files {
		n := f.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(n)
		for i, line := range strings.Split(string(b), "\n") {
			if re.MatchString(line) && !strings.Contains(line, `return doc.Object("fly-" + machine)`) {
				t.Errorf("%s:%d names a kernel machine by hand (use kernelObject): %s", n, i+1, strings.TrimSpace(line))
			}
		}
	}
}
