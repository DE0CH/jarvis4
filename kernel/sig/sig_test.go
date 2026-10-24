package sig

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
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
		p, err := Roster{Copy: copy, Members: m}.Payload()
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

// a roster's retired keys: still the roster's for what they signed (CheckIdentity), never the member (Member, what is
// sealed to); never secrets, never also a member, sorted; secretsBoot lets an empty secrets take the roster
func TestRetired(t *testing.T) {
	root, _ := NewSigner()
	old, _ := NewComponent("mover")
	now, _ := NewComponent("mover")
	old2, _ := NewComponent("merger")
	sec, _ := NewComponent("secrets")
	boot, _ := NewComponent("secrets")
	sign := func(r Roster) Doc {
		p, err := r.Payload()
		if err != nil {
			t.Fatal(err)
		}
		s, _ := root.Sign([]byte(p))
		return Doc{Payload: p, Sig: s}
	}
	r := Roster{Copy: "green", Members: []Identity{sec.Identity, now.Identity}, Retired: []Identity{old2.Identity, old.Identity}}
	tr := NewTrust(root.PublicKey())
	if err := tr.Set(sign(r), &now.Identity); err != nil {
		t.Fatal(err)
	}
	if CheckIdentity(old.Identity, "mover", tr) != nil || CheckIdentity(now.Identity, "mover", tr) != nil {
		t.Fatal("the member and the retired mover both count")
	}
	if CheckIdentity(old.Identity, "merger", tr) == nil {
		t.Fatal("a retired mover passed as a merger")
	}
	if m, _ := tr.Member("mover"); m != now.Identity {
		t.Fatal("Member is the current one only", m)
	}
	if k := tr.SigningKeys("mover"); len(k) != 2 || k[0] != now.Identity.SigningKey || k[1] != old.Identity.SigningKey {
		t.Fatal(k)
	}
	if tr.Set(sign(r), &old.Identity) == nil {
		t.Fatal("a retired component took the roster as its own")
	}
	bad := func(what string, x Roster) {
		t.Helper()
		p, _ := x.Payload()
		s, _ := root.Sign([]byte(p))
		if _, err := OpenRoster(Doc{Payload: p, Sig: s}, root.PublicKey()); err == nil {
			t.Fatal(what)
		}
	}
	bad("secrets retired", Roster{Copy: "blue", Members: []Identity{now.Identity}, Retired: []Identity{sec.Identity}})
	bad("a member also retired", Roster{Copy: "blue", Members: []Identity{now.Identity}, Retired: []Identity{now.Identity}})
	bad("secretsBoot not a secrets", Roster{Copy: "blue", Members: []Identity{now.Identity}, SecretsBoot: &old.Identity})
	// unsorted: written by hand (Payload sorts)
	p := `{"kind":"kernel-roster","copy":"blue","members":[` + js(now.Identity) + `],"retired":[` + js(old.Identity) + `,` + js(old2.Identity) + `]}`
	ps, _ := root.Sign([]byte(p))
	if _, err := OpenRoster(Doc{Payload: p, Sig: ps}, root.PublicKey()); err == nil {
		t.Fatal("unsorted retired")
	}
	// an empty secrets takes a roster naming it as secretsBoot (the derived secrets is the member)
	rb := Roster{Copy: "green", Members: []Identity{sec.Identity, now.Identity}, SecretsBoot: &boot.Identity}
	if err := NewTrust(root.PublicKey()).Set(sign(rb), &boot.Identity); err != nil {
		t.Fatal(err)
	}
	if NewTrust(root.PublicKey()).Set(sign(rb), &old.Identity) == nil {
		t.Fatal("secretsBoot let a mover in")
	}
}

func js(i Identity) string {
	b, _ := json.Marshal(i)
	return string(b)
}
