package kerneltest

// The documents a kernel machine boots from, for the Rust machine's tests (rust/machine/src/tests/kernelboot.rs): two lines on the blue copy, log-notary challenges, a roster another key signed,
// and the same kernel after a copy flip onto green. GEN_RUST_VECTORS=1 go test -run TestRustMachineVectors writes
// rust/machine/tests/vectors/kernelboot.json again; without it the file is only checked to parse.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/sig"
)

const rustVecPath = "../../rust/machine/tests/vectors/kernelboot.json"

type rustLine struct {
	Docs   map[string]any    `json:"docs"`
	ID     string            `json:"id"`
	Source string            `json:"source"`
	Keys   map[string]string `json:"keys"`
}

type rustMachineVectors struct {
	Root  string   `json:"root"`
	Phone string   `json:"phone"`
	Blue  sig.Doc  `json:"blue"` // the serving copy's roster
	A     rustLine `json:"a"`
	B     rustLine `json:"b"`
	// Input: the notary's challenge about "input" for line a's wakeup "wake up"; Cert: the same subject about "cert"
	Input sig.Doc `json:"input"`
	Cert  sig.Doc `json:"cert"`
	// OtherRoot signed OtherRoster (strangers in every role)
	OtherRoot   string  `json:"otherRoot"`
	OtherRoster sig.Doc `json:"otherRoster"`
	// after the flip onto green: green's roster, its identities and its notary's challenge for the same input
	Green      sig.Doc                 `json:"green"`
	GreenIDs   map[string]sig.Identity `json:"greenIds"`
	GreenInput sig.Doc                 `json:"greenInput"`
}

func rustLineOf(t *testing.T, k *Kernel, settings json.RawMessage, stores ...string) rustLine {
	m, fm := k.Line(t, "s1", testImage, settings, stores...)
	raw, _ := json.Marshal(m)
	var docs map[string]any
	json.Unmarshal(raw, &docs)
	return rustLine{Docs: docs, ID: fm.ID, Source: fm.Env["JARVIS2_SOURCE"],
		Keys: map[string]string{"signingKey": fm.Sig.PublicKey(), "encryptionKey": sig.B64.EncodeToString(fm.Enc.PublicKey().Bytes())}}
}

func inputSubject(machine, kind, sum string) string {
	h := sha256.Sum256([]byte("jarvis2-input\n" + machine + "\n" + kind + "\n" + sum))
	return hex.EncodeToString(h[:])
}

func TestRustMachineVectors(t *testing.T) {
	if os.Getenv("GEN_RUST_VECTORS") != "1" {
		b, err := os.ReadFile(rustVecPath)
		if err != nil {
			t.Skip("no vectors yet")
		}
		var v rustMachineVectors
		if err := json.Unmarshal(b, &v); err != nil || v.A.ID == "" {
			t.Fatal("kernelboot.json doesn't parse", err)
		}
		return
	}
	k := Start(t, map[string]string{"JARVIS2_URL": "http://router"})
	settings := json.RawMessage(`{"v":1,"harness":"claude","permissionMode":"auto","config":{"v":1,"label":"x","model":"claude-opus-5-5"}}`)
	var v rustMachineVectors
	v.Root, v.Phone = k.Root.PublicKey(), k.Phone.PublicKey()
	v.Blue, _ = k.Roster()
	v.A = rustLineOf(t, k, settings, "default", "tunnel")
	v.B = rustLineOf(t, k, settings, "default", "tunnel")
	sum := sha256.Sum256([]byte("wake up"))
	subj := inputSubject("fly-"+v.A.ID, "wakeup", hex.EncodeToString(sum[:]))
	v.Input = k.Challenge(t, subj, "input")
	v.Cert = k.Challenge(t, subj, "cert")
	other, _ := sig.NewSigner()
	strangers := []sig.Identity{}
	for _, r := range []string{"notary", "notarizer", "mover", "merger", "spawner", "secrets"} {
		c, _ := sig.NewComponent(r)
		strangers = append(strangers, c.Identity)
	}
	p, _ := sig.Roster{Copy: "blue", Members: strangers}.Payload()
	ps, _ := other.Sign([]byte(p))
	v.OtherRoot, v.OtherRoster = other.PublicKey(), sig.Doc{Payload: p, Sig: ps}
	k.Release(t)
	if err := k.SignRoster("green"); err != nil {
		t.Fatal(err)
	}
	k.Flip(t)
	v.Green, _ = k.Roster()
	v.GreenIDs = map[string]sig.Identity{}
	for _, r := range []string{"notary", "notarizer", "mover", "merger", "spawner", "secrets"} {
		v.GreenIDs[r] = k.Identity(r)
	}
	v.GreenInput = k.Challenge(t, subj, "input")
	b, _ := json.MarshalIndent(v, "", " ")
	if err := os.WriteFile(rustVecPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
