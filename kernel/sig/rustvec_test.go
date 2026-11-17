package sig

// The Rust port (rust/sig) and this package must agree byte for byte: rust/sig/tests/vectors/go.json holds what this
// package made (signatures, documents, sealed data) for the Rust tests to check, and rust.json what the Rust port made,
// checked here. GEN_RUST_VECTORS=1 go test -run TestRustVectors writes go.json again.

import (
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type rustVectors struct {
	SigningKey string   `json:"signingKey"` // the signer's public key
	Payload    string   `json:"payload"`
	Sigs       []string `json:"sigs"` // several: Go doesn't normalise S, so some are high-S
	Doc        Doc      `json:"doc"`
	// sealed to a fixed recipient: its scalar (hex), the info string and the plain text
	RecipientScalar string `json:"recipientScalar"`
	Info            string `json:"info"`
	Plain           string `json:"plain"`
	Sealed          Sealed `json:"sealed"`
}

const vecDir = "../../rust/sig/tests/vectors"

// a fixed scalar for the sealing recipient (test only)
const vecRecipient = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"

func TestRustVectors(t *testing.T) {
	if os.Getenv("GEN_RUST_VECTORS") == "1" {
		s, _ := NewSigner()
		v := rustVectors{SigningKey: s.PublicKey(), Payload: `{"kind":"vector","n":1}`, RecipientScalar: vecRecipient, Info: "jarvis4 rust vectors", Plain: "the plain text"}
		for range 16 {
			g, _ := s.Sign([]byte(v.Payload))
			v.Sigs = append(v.Sigs, g)
		}
		v.Doc, _ = s.SignJSON(map[string]any{"a": 1, "b": "two"})
		v.Sealed, _ = SealTo(recipientPub(t), []byte(v.Plain), v.Info)
		b, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(filepath.Join(vecDir, "go.json"), append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// what the Rust port made opens here
	b, err := os.ReadFile(filepath.Join(vecDir, "rust.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v rustVectors
	if err := StrictJSON(b, &v); err != nil {
		t.Fatal(err)
	}
	for i, g := range v.Sigs {
		if !Verify(v.SigningKey, []byte(v.Payload), g) {
			t.Fatalf("Rust signature %d doesn't verify in Go", i)
		}
	}
	var d map[string]any
	if err := v.Doc.Open(v.SigningKey, &d); err != nil || d["b"] != "two" {
		t.Fatalf("Rust document doesn't open in Go: %v %v", err, d)
	}
	priv, err := ecdh.P256().NewPrivateKey(mustHex(t, v.RecipientScalar))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := OpenSealed(priv, v.Sealed, v.Info)
	if err != nil || string(plain) != v.Plain {
		t.Fatalf("Rust sealed data doesn't open in Go: %v %q", err, plain)
	}
}

func recipientPub(t *testing.T) string {
	priv, err := ecdh.P256().NewPrivateKey(mustHex(t, vecRecipient))
	if err != nil {
		t.Fatal(err)
	}
	return B64.EncodeToString(priv.PublicKey().Bytes())
}

func mustHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
