package kerneltest

// A Go copy's flip taken by a Rust copy (rust/kernel/tests/flip_go.rs): the kernel's cut is a copy flip from Go's
// components to Rust's, and a rollback is the flip back, so the Rust notarizer, spawner and secrets must take Go's
// handoffs whole and hand over the same state again. Blue (Go) runs a line, pauses it and resumes it, then hands over
// to a green roster whose keys this file makes and writes; a second roster (blue again, keys made here too) is what
// the Rust components hand over to. GEN_RUST_VECTORS=1 go test -run TestRustFlipVectors writes
// rust/kernel/tests/vectors/flip-handoff.json again; without it the file is only checked to parse.

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/sig"
)

const rustFlipVecPath = "../../rust/kernel/tests/vectors/flip-handoff.json"

// vecKeys: a component's keys, scalars included (base64)
type vecKeys struct {
	Role      string `json:"role"`
	Signing   string `json:"signing"`
	Agreement string `json:"agreement"`
}

type vecMachine struct {
	ID, Image, State, Volume, Source string
}

type rustFlipVectors struct {
	Root  string             `json:"root"`
	Green sig.Doc            `json:"green"`
	Next  sig.Doc            `json:"next"`
	Keys  map[string]vecKeys `json:"keys"`     // green's components (secrets: its boot keys)
	Next2 map[string]vecKeys `json:"nextKeys"` // the next roster's (agreement keys only matter)
	// the handoffs of blue's notarizer, spawner and secrets to green
	Handoffs map[string]sig.Doc `json:"handoffs"`
	Machines []vecMachine       `json:"machines"`
	Running  string             `json:"running"` // the line's machine
}

func vecComponent(t *testing.T, role string) (*sig.Component, vecKeys) {
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(ek)
	s, err := sig.SignerFromPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	ag, _ := ecdh.P256().GenerateKey(rand.Reader)
	c := &sig.Component{Role: role, Signer: s, Agreement: ag,
		Identity: sig.Identity{Role: role, SigningKey: s.PublicKey(), AgreementKey: sig.B64.EncodeToString(ag.PublicKey().Bytes())}}
	return c, vecKeys{role, sig.B64.EncodeToString(ek.D.FillBytes(make([]byte, 32))), sig.B64.EncodeToString(ag.Bytes())}
}

// a root-signed roster of copy: these members (secrets: the kit's, booting with boot), retiring retired
func vecRoster(t *testing.T, k *Kernel, copy string, cs map[string]*sig.Component, retired []sig.Identity) sig.Doc {
	r := sig.Roster{Copy: copy, Retired: retired}
	for _, role := range Roles {
		if role == "secrets" {
			r.Members = append(r.Members, k.Identity("secrets"))
			boot := cs["secrets"].Identity
			r.SecretsBoot = &boot
			continue
		}
		r.Members = append(r.Members, cs[role].Identity)
	}
	p, err := r.Payload()
	if err != nil {
		t.Fatal(err)
	}
	s, _ := k.Root.Sign([]byte(p))
	return sig.Doc{Payload: p, Sig: s}
}

func TestRustFlipVectors(t *testing.T) {
	if os.Getenv("GEN_RUST_VECTORS") != "1" {
		b, err := os.ReadFile(rustFlipVecPath)
		if err != nil {
			t.Fatal(err)
		}
		var v rustFlipVectors
		if err := json.Unmarshal(b, &v); err != nil || len(v.Handoffs) != 3 {
			t.Fatalf("%s: %v", rustFlipVecPath, err)
		}
		return
	}
	k := Start(t, map[string]string{"JARVIS2_URL": "http://router"})
	_, m1 := k.Line(t, "s1", testImage, json.RawMessage(`{"v":1}`), "default")
	// a pause and a resume: the notarizer holds a source with a successor, the spawner a killed machine and a live one
	kd, err := k.post("spawner", "/kill", map[string]string{"id": m1.ID})
	if err != nil {
		t.Fatal(err)
	}
	var kc struct{ Cert sig.Doc }
	json.Unmarshal([]byte(kd.Payload), &kc)
	knz := k.Notarize(t, kc.Cert)
	cr, err := k.post("spawner", "/spawn", map[string]any{"cert": kc.Cert, "notarized": knz, "notarizer": k.Identity("notarizer"), "region": "lhr", "size": "medium", "diskGb": 10})
	if err != nil {
		t.Fatal(err)
	}
	var c struct{ ID string }
	json.Unmarshal([]byte(cr.Payload), &c)
	mc, err := k.post("spawner", "/init", map[string]string{"id": c.ID})
	if err != nil {
		t.Fatal(err)
	}
	k.Notarize(t, mc)
	v := rustFlipVectors{Root: k.Root.PublicKey(), Keys: map[string]vecKeys{}, Next2: map[string]vecKeys{}, Handoffs: map[string]sig.Doc{}, Running: c.ID}
	green, next := map[string]*sig.Component{}, map[string]*sig.Component{}
	for _, role := range Roles {
		green[role], v.Keys[role] = vecComponent(t, role)
		next[role], v.Next2[role] = vecComponent(t, role)
	}
	var blueMembers, greenMembers []sig.Identity
	for _, role := range Roles[:8] {
		blueMembers = append(blueMembers, k.Identity(role))
		greenMembers = append(greenMembers, green[role].Identity)
	}
	v.Green = vecRoster(t, k, "green", green, blueMembers)
	v.Next = vecRoster(t, k, "blue", next, greenMembers)
	for _, role := range Roles {
		h, err := postTo(k.URL[role], "/handoff", map[string]any{"roster": v.Green})
		if err != nil {
			t.Fatalf("%s's handoff: %v", role, err)
		}
		if role == "notarizer" || role == "spawner" || role == "secrets" {
			v.Handoffs[role] = h
		}
	}
	for _, m := range k.Fly.List() {
		v.Machines = append(v.Machines, vecMachine{m.ID, m.Image, m.State, m.Volume, m.Source})
	}
	out, _ := json.MarshalIndent(v, "", " ")
	if err := os.WriteFile(rustFlipVecPath, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
