package secrets

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/internal/kt"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// kernel: secrets Recovered in a kernel test world (same box key), with a machine to pull for
type kernel struct {
	t       *testing.T
	w       *kt.World
	c       *Secrets
	p, root *phone
	enc     *ecdh.PrivateKey // the machine's encryption key
	msig    *sig.Signer      // its signing key
}

func newKernel(t *testing.T) *kernel {
	w := kt.New(t)
	c, err := New(w.Root.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	master, p, root := newPhone(), newPhone(), newPhone()
	s, sg, b := claimFor(c, master, p, root, recoverBundle(t, c, p))
	pl(t)(c.Claim(s, sg, b))
	rosterFor(t, w, c)
	enc, _ := ecdh.P256().GenerateKey(rand.Reader)
	ms, _ := sig.NewSigner()
	return &kernel{t, w, c, p, root, enc, ms}
}

// rosterFor: the world's roster with c as its secrets, taken by c and by the world's trust
func rosterFor(t *testing.T, w *kt.World, c *Secrets) {
	t.Helper()
	ids := []sig.Identity{c.componentIdentity()}
	for _, r := range kt.Roles {
		if r != "secrets" {
			ids = append(ids, w.C[r].Identity)
		}
	}
	d := kt.SignRoster(t, w.Root, "blue", ids)
	if _, err := c.SetRoster(d); err != nil {
		t.Fatal(err)
	}
	if err := w.Trust.Set(d, nil); err != nil {
		t.Fatal(err)
	}
}

// grant: a mover-signed grant with this allowed set on the machine
func (k *kernel) grant(allowed perm.Set) gv.Signed {
	keys := doc.Keys{SigningKey: k.msig.PublicKey(), EncryptionKey: b64.EncodeToString(k.enc.PublicKey().Bytes())}
	d, _ := k.w.C["mover"].Signer.SignJSON(doc.Grant{Kind: "grant", Machine: "fly-aaaaaaaa01", Keys: keys,
		Pair: perm.Pair{Allowed: allowed, Conditions: []string{"session:s1"}}, From: []string{}, At: doc.Now()})
	return gv.Signed{Grant: d, By: "mover", Signer: k.w.ID("mover")}
}

// pull: the values the machine opens
func (k *kernel) pull(g gv.Signed) (map[string]string, map[string]any, error) {
	d, err := k.c.Pull(g)
	if err != nil {
		return nil, nil, err
	}
	var a struct {
		Sealed Sealed `json:"sealed"`
	}
	json.Unmarshal([]byte(d.Payload), &a)
	var m map[string]any
	json.Unmarshal([]byte(d.Payload), &m)
	plain, err := OpenSealed(k.enc, a.Sealed, "jarvis2/secrets")
	if err != nil {
		k.t.Fatal(err)
	}
	vals := map[string]string{}
	json.Unmarshal(plain, &vals)
	return vals, m, nil
}

// a finite grant pulls exactly its stores, each open; a locked one is 423 naming it; a cofinite grant pulls the open
// stores it doesn't exclude; the deploy-key token store is never served
func TestPullTakesAGrant(t *testing.T) {
	k := newKernel(t)
	unlock(t, k.c, k.p, "default")
	g := k.grant(perm.Only("store:default", "store:gmail", "shell"))
	if _, _, err := k.pull(g); err == nil || !strings.Contains(err.Error(), "store gmail is locked") {
		t.Fatal(err)
	}
	unlock(t, k.c, k.p, "gmail")
	vals, _, err := k.pull(g)
	if err != nil || vals["A"] != "1" || vals["G"] != "secret" || vals["OPENROUTER_API"] != "" {
		t.Fatal(err, vals)
	}
	vals, _, err = k.pull(k.grant(perm.Except("store:gmail")))
	if err != nil || vals["A"] != "1" || vals["G"] != "" {
		t.Fatal(err, vals)
	}
	writeStore(t, k.c, k.p, DeployKeyTokenStore, map[string]string{"T": "tok"})
	vals, m, err := k.pull(k.grant(perm.Only("store:default", "store:"+DeployKeyTokenStore)))
	if err != nil || vals["T"] != "" || len(m["stores"].([]any)) != 1 {
		t.Fatal(err, vals, m["stores"])
	}
}

// ✱ a grant not by the mover or merger: another role's key, an unvouched mover, the root key on anything but ⊤ on the
// sink, a changed grant
func TestPullRefusesOtherGrants(t *testing.T) {
	k := newKernel(t)
	unlock(t, k.c, k.p, "default")
	g := k.grant(perm.Only("store:default"))
	bad := g
	bad.Signer = k.w.ID("notary")
	if _, err := k.c.Pull(bad); err == nil {
		t.Fatal("a notary identity passed as the mover's")
	}
	m2, _ := sig.NewComponent("mover")
	var gr doc.Grant
	json.Unmarshal([]byte(g.Grant.Payload), &gr)
	d, _ := m2.Signer.SignJSON(gr)
	if _, err := k.c.Pull(gv.Signed{Grant: d, By: "mover", Signer: &m2.Identity}); err == nil {
		t.Fatal("a mover the roster doesn't name")
	}
	rd, _ := k.w.Root.SignJSON(gr)
	if _, err := k.c.Pull(gv.Signed{Grant: rd, By: "root"}); err == nil {
		t.Fatal("the root key's grant on a machine")
	}
	changed := g
	changed.Grant.Payload = strings.Replace(g.Grant.Payload, "store:default", "store:gmail", 1)
	if _, err := k.c.Pull(changed); err == nil {
		t.Fatal("a changed grant")
	}
}

// D1: a key written with its live value reaches the next pull; one written without it leaves the store behind (stale)
// until the phone unlocks again; a delete reaches it too. D2: nothing locks by itself; Lock ends it.
func TestWrittenKeysReachTheNextPull(t *testing.T) {
	k := newKernel(t)
	id := unlock(t, k.c, k.p, "default")
	g := k.grant(perm.Only("store:default"))
	x := sealKey(t, k.c, k.p, "default", "C", "3")
	live, _ := SealTo(k.c.Key()["agreementKey"], []byte("3"), infoLive+"\ndefault\nC")
	pl(t)(k.c.WriteKey(WriteKeyInput{Store: "default", Key: "C", Wrapped: x.Wrapped, Data: x.Data, Writer: "setup", Sig: "c2ln", Live: &live}))
	vals, m, err := k.pull(g)
	if err != nil || vals["C"] != "3" || len(m["stale"].([]any)) != 0 {
		t.Fatal(err, vals, m["stale"])
	}
	pl(t)(k.c.WriteKey(WriteKeyInput{Store: "default", Key: "A", Delete: true, Writer: "setup", Sig: "c2ln"}))
	if vals, _, _ = k.pull(g); vals["A"] != "" || vals["B"] != "2" {
		t.Fatal(vals)
	}
	pl(t)(setupWrite(k.c, sealKey(t, k.c, k.p, "default", "D", "4"))) // no live value
	vals, m, _ = k.pull(g)
	if vals["D"] != "" || len(m["stale"].([]any)) != 1 {
		t.Fatal(vals, m["stale"])
	}
	// ✱ a live value sealed for another key doesn't open as this one
	wrong, _ := SealTo(k.c.Key()["agreementKey"], []byte("x"), infoLive+"\ndefault\nOTHER")
	y := sealKey(t, k.c, k.p, "default", "E", "5")
	pl(t)(k.c.WriteKey(WriteKeyInput{Store: "default", Key: "E", Wrapped: y.Wrapped, Data: y.Data, Writer: "setup", Sig: "c2ln", Live: &wrong}))
	if vals, _, _ = k.pull(g); vals["E"] != "" {
		t.Fatal("a live value for another key was taken")
	}
	pl(t)(k.c.Lock(id))
	if _, _, err := k.pull(g); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatal(err)
	}
}

// a machine writes with the grant it holds, signed by that grant's machine key; ✱ another key, ✱ a grant on a source;
// the router writes only the Claude login stores
func TestWriters(t *testing.T) {
	k := newKernel(t)
	g := k.grant(perm.Only("store:default"))
	x := sealKey(t, k.c, k.p, "notes", "N", "n")
	text := WriterText("notes", "N", x.Wrapped.E, x.Data, "")
	good, _ := k.msig.Sign([]byte(text))
	out := pl(t)(k.c.WriteKey(WriteKeyInput{Store: "notes", Key: "N", Wrapped: x.Wrapped, Data: x.Data, Writer: "machine", Sig: good, Grant: &g}))
	if w := out["writer"].(map[string]any); w["by"] != "machine" || w["machine"] != "aaaaaaaa01" {
		t.Fatal(out)
	}
	other, _ := sig.NewSigner()
	bad, _ := other.Sign([]byte(text))
	if _, err := k.c.WriteKey(WriteKeyInput{Store: "notes", Key: "N", Wrapped: x.Wrapped, Data: x.Data, Writer: "machine", Sig: bad, Grant: &g}); err == nil {
		t.Fatal("another key wrote as the machine")
	}
	ik, _ := doc.IdealKeys(kt.Source())
	var gr doc.Grant
	json.Unmarshal([]byte(g.Grant.Payload), &gr)
	gr.Machine, gr.Keys = kt.Source(), ik
	sd, _ := k.w.C["mover"].Signer.SignJSON(gr)
	if _, err := k.c.WriteKey(WriteKeyInput{Store: "notes", Key: "N", Wrapped: x.Wrapped, Data: x.Data, Writer: "machine", Sig: good,
		Grant: &gv.Signed{Grant: sd, By: "mover", Signer: k.w.ID("mover")}}); err == nil {
		t.Fatal("a grant on a source wrote as a machine")
	}
	y := sealKey(t, k.c, k.p, "claude", "CLAUDE_CREDENTIALS", "new")
	pl(t)(k.c.WriteKey(WriteKeyInput{Store: "claude", Key: "CLAUDE_CREDENTIALS", Wrapped: y.Wrapped, Data: y.Data, Writer: "router"}))
	z := sealKey(t, k.c, k.p, "default", "A", "x")
	if _, err := k.c.WriteKey(WriteKeyInput{Store: "default", Key: "A", Wrapped: z.Wrapped, Data: z.Data, Writer: "router"}); err == nil {
		t.Fatal("the router wrote a store that isn't the Claude login's")
	}
}

// the claim names a root key of its own; the keys statement is what the notarizer and the mover read
func TestTheRootKey(t *testing.T) {
	c, master := newSecrets(t)
	p := newPhone()
	s, sg, b := claimFor(c, master, p, p, resetBundle) // the phone's key as the root key
	if _, err := c.Claim(s, sg, b); err == nil {
		t.Fatal("the phone's key taken as the root key")
	}
	k := newKernel(t)
	d := pl2(t)(k.c.KeysStatement())
	var ks struct{ Kind, Phone, Root string }
	if err := d.Open(k.c.Key()["signingKey"], &ks); err != nil || ks.Phone != k.p.signingKey() || ks.Root != k.root.signingKey() {
		t.Fatal(err, ks)
	}
	if _, err := gv.RootKey(&d, &sig.Identity{Role: "secrets", SigningKey: k.c.Key()["signingKey"], AgreementKey: k.c.Key()["agreementKey"]}, k.w.Trust); err != nil {
		t.Fatal(err)
	}
}

// seededClaim: a claim with secrets' seed (the same kit derives the same secrets), standby or not
func seededClaim(t *testing.T, c *Secrets, master, p, root *phone, seed []byte, standby bool, line *LineStateDoc) {
	t.Helper()
	dk, err := DeriveCoreKeys(seed)
	if err != nil {
		t.Fatal(err)
	}
	derived := b64.EncodeToString(dk.agreement.PublicKey().Bytes())
	rb := claimBundle{Format: "keys", Stores: []string{"default"}, SecretsSeed: b64.EncodeToString(seed), LineState: line}
	C := storeKey(t, p, derived) // the store key with the derived K, as the app wraps a Recover
	for _, k := range sortedKeys(testValues["default"]) {
		dkey := make([]byte, 32)
		rand.Read(dkey)
		wk, _ := WrapToPoint(C, dkey)
		rb.Keys = append(rb.Keys, KeyEntry{Store: "default", Key: k, Wrapped: wk, Data: b64.EncodeToString(gcmSeal(dkey, []byte(testValues["default"][k]), KeyAAD("default", k)))})
	}
	plain, _ := json.Marshal(rb)
	sum := sha256Hex(string(plain))
	var st claimStatement
	st.Kind, st.Master, st.Root, st.Standby = "kernel-claim", master.signingKey(), root.signingKey(), standby
	k := c.Key()
	st.Secrets.SigningKey, st.Secrets.AgreementKey = k["signingKey"], k["agreementKey"]
	st.Phone.SigningKey, st.Phone.AgreementKey = p.signingKey(), p.agreementKey()
	st.BundleSha256 = sum
	st.Identity = &struct {
		SigningKey   string `json:"signingKey"`
		AgreementKey string `json:"agreementKey"`
	}{dk.signer.PublicKey(), b64.EncodeToString(dk.agreement.PublicKey().Bytes())}
	sb, _ := json.Marshal(st)
	bundle, _ := SealTo(k["agreementKey"], plain, infoClaim)
	pl(t)(c.Claim(string(sb), master.sign(string(sb)), bundle))
}

// blue/green: a secrets Recovered on standby takes the serving one's final state, open unlocks included (they never
// end by themselves, so a flip mustn't drop them); the old one serves nothing after its handoff
func TestAHandoffKeepsTheOpenUnlocks(t *testing.T) {
	w := kt.New(t)
	master, p, root := newPhone(), newPhone(), newPhone()
	seed := make([]byte, 32)
	rand.Read(seed)
	a, _ := New(w.Root.PublicKey(), nil)
	seededClaim(t, a, master, p, root, seed, false, nil)
	rosterFor(t, w, a)
	unlock(t, a, p, "default")
	b, _ := New(w.Root.PublicKey(), nil)
	seededClaim(t, b, master, p, root, seed, true, nil)
	rosterFor(t, w, b)
	if b.Mode() != modeStandby || a.Key()["signingKey"] != b.Key()["signingKey"] {
		t.Fatal("the same kit didn't derive the same secrets, or b serves")
	}
	final, err := a.Handoff()
	if err != nil {
		t.Fatal(err)
	}
	if a.Mode() != modeHandedOff {
		t.Fatal("a still serves")
	}
	pl(t)(b.Takeover(final))
	k := &kernel{t: t, w: w, c: b, p: p, root: root}
	k.enc, _ = ecdh.P256().GenerateKey(rand.Reader)
	k.msig, _ = sig.NewSigner()
	vals, _, err := k.pull(k.grant(perm.Only("store:default")))
	if err != nil || vals["A"] != "1" {
		t.Fatal(err, vals)
	}
}
