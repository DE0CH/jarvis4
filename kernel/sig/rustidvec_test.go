package sig

// identity.go and storekey.go against the Rust port (rust/sig/src/identity.rs), byte for byte:
// rust/sig/tests/vectors/go-identity.json is what this package made, rust-identity.json what the Rust port made.
// GEN_RUST_VECTORS=1 go test -run TestRustIdentityVectors writes go-identity.json again.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type rustIdentityVectors struct {
	Root    string `json:"root"`    // the root key's public key
	Roster  Doc    `json:"roster"`  // a roster it signed, with retired members and a secretsBoot
	Payload string `json:"payload"` // Roster.Payload() of the roster given unsorted
	// Unsorted: the roster's members and retired out of order, as given to Payload
	Unsorted Roster `json:"unsorted"`
	// StoreKey: P + K
	Phone    string `json:"phone"`
	Secrets  string `json:"secrets"`
	StoreKey string `json:"storeKey"`
	// Escaped: json.Marshal of a string with the characters Go escapes
	Plain   string `json:"plain"`
	Escaped string `json:"escaped"`
}

func TestRustIdentityVectors(t *testing.T) {
	if os.Getenv("GEN_RUST_VECTORS") == "1" {
		root, _ := NewSigner()
		var cs []*Component
		for _, role := range []string{"secrets", "notary", "mover", "merger", "mover", "notary"} {
			c, _ := NewComponent(role)
			cs = append(cs, c)
		}
		un := Roster{Copy: "green", Members: []Identity{cs[2].Identity, cs[0].Identity, cs[1].Identity, cs[3].Identity},
			Retired: []Identity{cs[5].Identity, cs[4].Identity}}
		boot, _ := NewComponent("secrets")
		un.SecretsBoot = &boot.Identity
		p, err := un.Payload()
		if err != nil {
			t.Fatal(err)
		}
		s, _ := root.Sign([]byte(p))
		pk, _ := NewComponent("phone")
		sk, _ := NewComponent("secrets")
		c, err := StoreKey(pk.Identity.AgreementKey, sk.Identity.AgreementKey)
		if err != nil {
			t.Fatal(err)
		}
		plain := "a <b> & c \u2028\u2029 é"
		esc, _ := json.Marshal(plain)
		v := rustIdentityVectors{Root: root.PublicKey(), Roster: Doc{p, s}, Payload: p, Unsorted: un,
			Phone: pk.Identity.AgreementKey, Secrets: sk.Identity.AgreementKey, StoreKey: c, Plain: plain, Escaped: string(esc)}
		b, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(filepath.Join(vecDir, "go-identity.json"), append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// what the Rust port made opens here
	b, err := os.ReadFile(filepath.Join(vecDir, "rust-identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v rustIdentityVectors
	if err := StrictJSON(b, &v); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRoster(v.Roster, v.Root)
	if err != nil {
		t.Fatalf("the Rust roster doesn't open in Go: %v", err)
	}
	if p, _ := v.Unsorted.Payload(); p != v.Payload || p != v.Roster.Payload {
		t.Fatalf("Rust's roster payload differs from Go's:\n%s\n%s", p, v.Payload)
	}
	tr := NewTrust(v.Root)
	if err := tr.Set(v.Roster, nil); err != nil {
		t.Fatal(err)
	}
	if err := CheckIdentity(r.Retired[0], r.Retired[0].Role, tr); err != nil {
		t.Fatalf("a retired identity of the Rust roster: %v", err)
	}
	if c, _ := StoreKey(v.Phone, v.Secrets); c != v.StoreKey {
		t.Fatal("Rust's P + K differs from Go's")
	}
	if esc, _ := json.Marshal(v.Plain); string(esc) != v.Escaped {
		t.Fatalf("Rust's go_json escapes differently: %s vs %s", v.Escaped, esc)
	}
}
