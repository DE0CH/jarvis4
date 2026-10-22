package sig

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestSignVerifyOpen(t *testing.T) {
	s, _ := NewSigner()
	d, err := s.SignJSON(map[string]string{"kind": "x"})
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Kind string `json:"kind"`
	}
	if err := d.Open(s.PublicKey(), &v); err != nil || v.Kind != "x" {
		t.Fatal(err, v)
	}
	var w struct{}
	if d.Open(s.PublicKey(), &w) == nil {
		t.Fatal("an unknown field was accepted")
	}
	o, _ := NewSigner()
	if d.Open(o.PublicKey(), &v) == nil {
		t.Fatal("another key's signature was accepted")
	}
	d.Payload = `{"kind":"y"}`
	if d.Open(s.PublicKey(), &v) == nil {
		t.Fatal("a changed payload was accepted")
	}
}

func TestSealOpen(t *testing.T) {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	s, err := SealTo(B64.EncodeToString(k.PublicKey().Bytes()), []byte("v"), "i")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := OpenSealed(k, s, "i"); err != nil || string(b) != "v" {
		t.Fatal(err)
	}
	if _, err := OpenSealed(k, s, "other"); err == nil {
		t.Fatal("opened under another info")
	}
}

func TestRoster(t *testing.T) {
	root, _ := NewSigner()
	c, err := NewComponent("notary")
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := NewComponent("spawner")
	signed := func(by *Signer, copy string, m ...Identity) Doc {
		p, err := RosterPayload(copy, m)
		if err != nil {
			t.Fatal(err)
		}
		s, _ := by.Sign([]byte(p))
		return Doc{Payload: p, Sig: s}
	}
	tr := NewTrust(root.PublicKey())
	if CheckIdentity(c.Identity, "notary", tr) != ErrNoRoster {
		t.Fatal("an identity passed before any roster")
	}
	other, _ := NewSigner()
	if tr.Set(signed(other, "blue", sp.Identity, c.Identity), &c.Identity) == nil {
		t.Fatal("a roster another key signed")
	}
	if tr.Set(signed(root, "blue", sp.Identity), &c.Identity) == nil {
		t.Fatal("a roster without this component's keys")
	}
	if tr.Set(signed(root, "purple", sp.Identity, c.Identity), &c.Identity) == nil {
		t.Fatal("a roster of no copy")
	}
	if err := tr.Set(signed(root, "blue", sp.Identity, c.Identity), &c.Identity); err != nil {
		t.Fatal(err)
	}
	if err := CheckIdentity(c.Identity, "notary", tr); err != nil {
		t.Fatal(err)
	}
	if CheckIdentity(c.Identity, "spawner", tr) == nil {
		t.Fatal("one role's identity passed as another's")
	}
	c2, _ := NewComponent("notary")
	if CheckIdentity(c2.Identity, "notary", tr) == nil {
		t.Fatal("keys the roster doesn't name")
	}
}
