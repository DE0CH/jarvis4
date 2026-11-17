package doc

// The Rust port (rust/doc) reads and writes these documents byte for byte as this package does:
// rust/doc/tests/vectors/go.json holds payloads this package marshalled, which the Rust tests open, check and marshal
// again to the same bytes. GEN_RUST_VECTORS=1 go test -run TestRustDocVectors writes it again.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

func TestRustDocVectors(t *testing.T) {
	if os.Getenv("GEN_RUST_VECTORS") != "1" {
		t.Skip("GEN_RUST_VECTORS=1 writes rust/doc/tests/vectors/go.json")
	}
	src := Object("source-" + strings.Repeat("b", 32))
	img := "ghcr.io/de0ch/jarvis4-session:sha-1@sha256:" + strings.Repeat("c", 64)
	certs := []Cert{
		{Kind: "succession", Pred: "fly-0123456789abcd", Succ: src, Pair: perm.Pair{Allowed: perm.Only("shell", "store:a"), Conditions: []string{"session:s1"}},
			Source: &Source{Image: img, Settings: json.RawMessage(`{"label":"x","n":1}`), Snapshot: strings.Repeat("d", 64)}, Signer: ByIPhone, IssuedAt: "2026-11-17T14:00:00.123Z"},
		{Kind: "succession", Pred: src, Succ: "fly-89abcdef012345", Pair: perm.Top(),
			Machine: &Machine{Keys: Keys{SigningKey: "sk", EncryptionKey: "ek"}, Image: img}, Signer: BySpawner, IssuedAt: "2026-11-17T14:00:01Z"},
	}
	grant := Grant{Kind: "grant", Machine: "fly-89abcdef012345", Keys: Keys{SigningKey: "sk", EncryptionKey: "ek"}, Pair: perm.Pair{Allowed: perm.Except("shell"), Conditions: []string{}}, From: []string{"a", "b"}, At: "2026-11-17T14:00:02.5Z"}
	ch := Challenge{Kind: "challenge", Seq: 7, Prev: strings.Repeat("e", 64), At: "2026-11-17T14:00:03Z", Subject: strings.Repeat("f", 64), About: "cert", Nonce: "n0"}
	chDoc := sig.Doc{Payload: string(must(json.Marshal(ch))), Sig: "s"}
	nz := Notarized{Kind: "notarized", Cert: strings.Repeat("0", 64), Challenge: chDoc}
	out := map[string]any{}
	var cs []string
	for _, c := range certs {
		if err := c.Check(); err != nil {
			t.Fatal(err)
		}
		cs = append(cs, string(must(json.Marshal(c))))
	}
	out["certs"] = cs
	out["grant"] = string(must(json.Marshal(grant)))
	out["challenge"] = chDoc.Payload
	out["notarized"] = string(must(json.Marshal(nz)))
	b := must(json.MarshalIndent(out, "", "  "))
	if err := os.WriteFile("../../rust/doc/tests/vectors/go.json", append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
