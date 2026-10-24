// Package kt: a kernel for tests — every component's identity and the root key's roster of them, the phone and root keys, secrets' signed
// keys statement, and certs made and signed as each signer would.
package kt

import (
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

type World struct {
	T           *testing.T
	Trust       *sig.Trust // holds the root key's roster of C
	Roster      sig.Doc
	C           map[string]*sig.Component // by role
	Phone, Root *sig.Signer
	KeysDoc     sig.Doc
}

var Roles = []string{"notary", "notarizer", "mover", "merger", "spawner", "identity", "gullible", "minter", "secrets"}

func New(t *testing.T) *World {
	w := &World{T: t, C: map[string]*sig.Component{}}
	ids := []sig.Identity{}
	for _, r := range Roles {
		c, err := sig.NewComponent(r)
		if err != nil {
			t.Fatal(err)
		}
		w.C[r] = c
		ids = append(ids, c.Identity)
	}
	w.Phone, _ = sig.NewSigner()
	w.Root, _ = sig.NewSigner()
	w.Roster = SignRoster(t, w.Root, sig.Roster{Copy: "blue", Members: ids})
	w.Trust = sig.NewTrust(w.Root.PublicKey())
	if err := w.Trust.Set(w.Roster, nil); err != nil {
		t.Fatal(err)
	}
	d, err := w.C["secrets"].Signer.SignJSON(map[string]string{"kind": "keys", "phone": w.Phone.PublicKey(), "root": w.Root.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	w.KeysDoc = d
	return w
}

// SignRoster: the root key's roster r
func SignRoster(t testing.TB, root *sig.Signer, r sig.Roster) sig.Doc {
	p, err := r.Payload()
	if err != nil {
		t.Fatal(err)
	}
	s, err := root.Sign([]byte(p))
	if err != nil {
		t.Fatal(err)
	}
	return sig.Doc{Payload: p, Sig: s}
}

func (w *World) ID(role string) *sig.Identity { id := w.C[role].Identity; return &id }

// Source: a fresh source name
func Source() doc.Object {
	b := make([]byte, 16)
	rand.Read(b)
	return doc.NewSource(b)
}

const Image = "ghcr.io/de0ch/jarvis4-session@sha256:1111111111111111111111111111111111111111111111111111111111111111"

// SourceContent: a source with settings {"title": title}
func SourceContent(title string) *doc.Source {
	b, _ := json.Marshal(map[string]string{"title": title})
	return &doc.Source{Image: Image, Settings: b}
}

// MachineKeys: a Fly machine's keys
func MachineKeys() (*sig.Signer, *doc.Machine) {
	s, _ := sig.NewSigner()
	e, _ := sig.NewSigner()
	return s, &doc.Machine{Keys: doc.Keys{SigningKey: s.PublicKey(), EncryptionKey: e.PublicKey()}, Image: Image}
}

// Cert: a cert signed as signer would sign it (the iPhone and root by their keys, the others by their component)
func (w *World) Cert(signer string, pred, succ doc.Object, p perm.Pair, src *doc.Source, m *doc.Machine) sig.Doc {
	c := doc.Cert{Kind: "succession", Pred: pred, Succ: succ, Pair: p, Source: src, Machine: m, Signer: signer,
		IssuedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	var s *sig.Signer
	switch signer {
	case doc.ByIPhone:
		s = w.Phone
	case doc.ByRoot:
		s = w.Root
	default:
		s = w.C[signer].Signer
	}
	d, err := s.SignJSON(c)
	if err != nil {
		w.T.Fatal(err)
	}
	return d
}

// Challenge: a notary challenge over subject (as the notary signs it, at the given time)
func (w *World) Challenge(subject, about string, at time.Time) sig.Doc {
	d, err := w.C["notary"].Signer.SignJSON(doc.Challenge{Kind: "challenge", Seq: 1, At: at.UTC().Format(time.RFC3339Nano),
		Subject: subject, About: about, Nonce: "00"})
	if err != nil {
		w.T.Fatal(err)
	}
	return d
}
