package secrets

// A Go secrets' copy flip, for the Rust secrets (rust/kernel/tests/secrets_go.rs): the kernel's cut is a copy flip
// whose serving secrets is Go's and whose taking-over one is Rust's, so the Rust one must take this handoff whole. A Go
// secrets claimed with a kit seed, store default unlocked, hands over to an empty secrets whose boot keys the vector
// carries (the Rust test serves with them); also its line state as the router keeps it. GEN_RUST_VECTORS=1 go test
// -run TestRustSecretsVectors writes rust/kernel/tests/vectors/secrets-handoff.json again; without it the file is only
// checked to parse.

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/internal/kt"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

const rustSecretsVecPath = "../../rust/kernel/tests/vectors/secrets-handoff.json"

type rustSecretsVectors struct {
	Root  string  `json:"root"`
	Blue  sig.Doc `json:"blue"`
	Green sig.Doc `json:"green"`
	// the taking-over secrets' boot keys (scalars, base64): the Rust test serves with them
	BootSigning   string        `json:"bootSigning"`
	BootAgreement string        `json:"bootAgreement"`
	Handoff       sig.Doc       `json:"handoff"`
	LineState     *LineStateDoc `json:"lineState"` // the serving secrets' line state before the handoff
	// what the takeover must come to: the derived identity, the claim's keys, the open unlock's values
	Derived     PublicKeys        `json:"derived"`
	Master      string            `json:"master"`
	Root2       string            `json:"rootKey"`
	Phone       PublicKeys        `json:"phone"`
	Unlocked    map[string]string `json:"unlocked"`
	Stores      []string          `json:"stores"`
	FinalSeq    int               `json:"finalSeq"`
	Seed        string            `json:"seed"`
	PhoneAgreeX string            `json:"phoneAgreement"` // the phone's agreement scalar (the Rust test unlocks again)
}

func TestRustSecretsVectors(t *testing.T) {
	if os.Getenv("GEN_RUST_VECTORS") != "1" {
		b, err := os.ReadFile(rustSecretsVecPath)
		if err != nil {
			t.Fatal(err)
		}
		var v rustSecretsVectors
		if err := json.Unmarshal(b, &v); err != nil || v.Handoff.Payload == "" {
			t.Fatalf("%s: %v", rustSecretsVecPath, err)
		}
		return
	}
	w := kt.New(t)
	master, p, root := newPhone(), newPhone(), newPhone()
	seed := make([]byte, 32)
	rand.Read(seed)
	a, _ := New(w.Root.PublicKey(), nil)
	seededClaim(t, a, master, p, root, seed, nil)
	rosterFor(t, w, a)
	writeStore(t, a, p, "gmail", map[string]string{"G": "secret"})
	unlock(t, a, p, "default")
	a.syncLine()
	line, err := a.LineState()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := New(w.Root.PublicKey(), nil)
	green := otherCopy(t, w, a, b)
	d, err := a.Handoff(green)
	if err != nil {
		t.Fatal(err)
	}
	k := a.Key()
	v := rustSecretsVectors{Root: w.Root.PublicKey(), Blue: *a.Roster(), Green: green,
		BootSigning: b64.EncodeToString(b.signer.key.D.FillBytes(make([]byte, 32))), BootAgreement: b64.EncodeToString(b.agreement.Bytes()),
		Handoff: d, LineState: line, Derived: PublicKeys{k["signingKey"], k["agreementKey"]}, Master: master.signingKey(),
		Root2: root.signingKey(), Phone: PublicKeys{p.signingKey(), p.agreementKey()}, Unlocked: testValues["default"],
		Stores: sortedKeys(a.stores), FinalSeq: a.LineSeq(), Seed: b64.EncodeToString(seed), PhoneAgreeX: b64.EncodeToString(p.agr.Bytes())}
	out, _ := json.MarshalIndent(v, "", " ")
	if err := os.WriteFile(rustSecretsVecPath, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
