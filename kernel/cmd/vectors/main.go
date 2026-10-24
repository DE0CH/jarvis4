// vectors: kernel documents as the Go side makes them, for the app's interop test (ios/interop Kernel): a new
// source's cert for session s1, an add-store's two certs, the payloads that must be refused, and store keys P + K
// (sig.StoreKey: the app computes its own). Not in the image.
package main

import (
	"crypto/ecdh"
	"encoding/json"
	"os"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// point: the public key of a small scalar (base64 X9.63)
func point(n byte) string {
	d := make([]byte, 32)
	d[31] = n
	k, err := ecdh.P256().NewPrivateKey(d)
	if err != nil {
		panic(err)
	}
	return sig.B64.EncodeToString(k.PublicKey().Bytes())
}

func storeKey(p, k string) string {
	c, err := sig.StoreKey(p, k)
	if err != nil {
		panic(err)
	}
	return c
}

func cert(c doc.Cert) string {
	if err := c.Check(); err != nil {
		panic(err)
	}
	b, _ := json.Marshal(c)
	return string(b)
}

func main() {
	const img = "ghcr.io/de0ch/jarvis4-session:sha-aaaaaaaaaaaa@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	settings := json.RawMessage(`{"config":{"label":"x","model":"claude-opus-5-5","prompt":"hi"},"harness":"claude","permissionMode":"auto","v":1}`)
	src := doc.Object("source-0123456789abcdef0123456789abcdef")
	add := doc.Object("source-fedcba9876543210fedcba9876543210")
	stores := perm.Pair{Allowed: perm.Only("store:default", "store:tunnel"), Conditions: []string{"session:s1"}}
	m := &doc.Machine{Keys: doc.Keys{SigningKey: "BAAA", EncryptionKey: "BAAB"}, Image: img}
	out := map[string]string{
		"source": cert(doc.Cert{Kind: "succession", Pred: doc.Sink, Succ: src, Pair: stores, Source: &doc.Source{Image: img, Settings: settings},
			Signer: doc.ByIPhone, IssuedAt: "2026-10-21T15:00:00Z"}),
		"restore": cert(doc.Cert{Kind: "succession", Pred: doc.Sink, Succ: src, Pair: stores,
			Source: &doc.Source{Image: img, Settings: settings, Snapshot: "e3025c921e4262bf368c224c3fbd893d113cdf58cd333b11806adc45e4f75c6f"},
			Signer: doc.ByIPhone, IssuedAt: "2026-10-21T15:00:00Z"}),
		"addFirst": cert(doc.Cert{Kind: "succession", Pred: doc.Sink, Succ: add, Pair: perm.Pair{Allowed: perm.Only("store:extra"), Conditions: []string{"session:s1"}},
			Source: &doc.Source{Image: img, Settings: settings}, Signer: doc.ByIPhone, IssuedAt: "2026-10-21T15:00:00Z"}),
		"addSecond": cert(doc.Cert{Kind: "succession", Pred: add, Succ: "fly-0123456789abcd", Pair: perm.Top(), Machine: m, Signer: doc.ByIPhone,
			IssuedAt: "2026-10-21T15:00:00Z"}),
		// refused: allows a shell, another session's, another repo's image
		"shell": cert(doc.Cert{Kind: "succession", Pred: doc.Sink, Succ: src, Pair: perm.Pair{Allowed: perm.Only("shell", "store:default"), Conditions: []string{"session:s1"}},
			Source: &doc.Source{Image: img, Settings: settings}, Signer: doc.ByIPhone, IssuedAt: "2026-10-21T15:00:00Z"}),
		"otherSession": cert(doc.Cert{Kind: "succession", Pred: doc.Sink, Succ: src, Pair: perm.Pair{Allowed: perm.Only("store:default"), Conditions: []string{"session:s2"}},
			Source: &doc.Source{Image: img, Settings: settings}, Signer: doc.ByIPhone, IssuedAt: "2026-10-21T15:00:00Z"}),
		"otherImage": cert(doc.Cert{Kind: "succession", Pred: doc.Sink, Succ: src, Pair: stores,
			Source: &doc.Source{Image: "ghcr.io/evil/x@sha256:1111111111111111111111111111111111111111111111111111111111111111", Settings: settings},
			Signer: doc.ByIPhone, IssuedAt: "2026-10-21T15:00:00Z"}),
		// the store key: 7G + 11G, and 5G + 5G (a doubling)
		"storeKeyPhone": point(7), "storeKeySecrets": point(11), "storeKey": storeKey(point(7), point(11)),
		"storeKeyTwice": point(5), "storeKeyDouble": storeKey(point(5), point(5)),
	}
	json.NewEncoder(os.Stdout).Encode(out)
}
