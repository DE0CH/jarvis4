package secrets

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"os"
	"testing"
)

// secrets' diagnostics stay out of test output
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// a P-256 key holder: the iPhone (signing + the Enclave's key agreement, here in software), the master key, the root
// key, the setup key
type phone struct {
	sig *ecdsa.PrivateKey
	agr *ecdh.PrivateKey
}

func newPhone() *phone {
	s, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a, _ := ecdh.P256().GenerateKey(rand.Reader)
	return &phone{s, a}
}
func (p *phone) signingKey() string {
	k, _ := p.sig.PublicKey.ECDH()
	return b64.EncodeToString(k.Bytes())
}
func (p *phone) agreementKey() string { return b64.EncodeToString(p.agr.PublicKey().Bytes()) }
func (p *phone) sign(payload string) string {
	h := sha256.Sum256([]byte(payload))
	s, _ := ecdsa.SignASN1(rand.Reader, p.sig, h[:])
	return b64.EncodeToString(s)
}

// share: the phone's share of an unlock, x(p·E) per key, sealed to the one-off T
func (p *phone) share(begin SignedDoc) (string, map[string]Sealed) {
	var b struct {
		Pending, T string
		Keys       []struct{ Key, E string }
	}
	json.Unmarshal([]byte(begin.Payload), &b)
	out := map[string]Sealed{}
	for _, k := range b.Keys {
		out[k.Key] = p.shareOf(k.E, b.T)
	}
	return b.Pending, out
}

func (p *phone) shareOf(e, t string) Sealed {
	eb, _ := b64.DecodeString(e)
	E, _ := ecdh.P256().NewPublicKey(eb)
	x, _ := p.agr.ECDH(E)
	s, _ := SealTo(t, x, infoShare)
	return s
}

// pl(t)(c.Primitive(...)): the answer's payload, failing the test on an error
func pl(t *testing.T) func(SignedDoc, error) map[string]any {
	return func(d SignedDoc, err error) map[string]any {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		json.Unmarshal([]byte(d.Payload), &m)
		return m
	}
}

var testValues = map[string]map[string]string{
	"default":    {"A": "1", "B": "2"},
	"gmail":      {"G": "secret"},
	"claude":     {"CLAUDE_CREDENTIALS": "c"},
	"openrouter": {"OPENROUTER_API": "o"},
}

// sealKey: a writer's key, wrapped to the combined key P + K
func sealKey(t *testing.T, c *Secrets, p *phone, store, key, value string) KeyEntry {
	t.Helper()
	dk := make([]byte, 32)
	rand.Read(dk)
	w, err := WrapToCombined(p.agreementKey(), c.agreement.PublicKey().Bytes(), dk)
	if err != nil {
		t.Fatal(err)
	}
	return KeyEntry{Store: store, Key: key, Wrapped: w, Data: b64.EncodeToString(gcmSeal(dk, []byte(value), KeyAAD(store, key)))}
}

func setupWrite(c *Secrets, x KeyEntry) (SignedDoc, error) {
	return c.WriteKey(WriteKeyInput{Store: x.Store, Key: x.Key, Wrapped: x.Wrapped, Data: x.Data, Writer: "setup", Sig: "c2ln"})
}

func writeStore(t *testing.T, c *Secrets, p *phone, name string, vals map[string]string) (SignedDoc, error) {
	t.Helper()
	var d SignedDoc
	for _, k := range sortedKeys(vals) {
		var err error
		if d, err = setupWrite(c, sealKey(t, c, p, name, k, vals[k])); err != nil {
			return d, err
		}
	}
	return d, nil
}

func WrapToCombined(phoneAgreementRaw string, pub []byte, dataKey []byte) (WrappedKey, error) {
	pb, err := b64.DecodeString(phoneAgreementRaw)
	if err != nil {
		return WrappedKey{}, err
	}
	combined, err := AddPoints(pb, pub)
	if err != nil {
		return WrappedKey{}, err
	}
	return WrapToPoint(combined, dataKey)
}

func WrapToPoint(combined, dataKey []byte) (WrappedKey, error) {
	e, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return WrappedKey{}, err
	}
	shared, err := ScalarMult(e.Bytes(), combined)
	if err != nil {
		return WrappedKey{}, err
	}
	return WrappedKey{E: b64.EncodeToString(e.PublicKey().Bytes()), Wrapped: b64.EncodeToString(gcmSeal(kdf(xOf(shared), infoStore), dataKey, nil))}, nil
}

// storeKey: C = P + K, as the app computes it for its phone and a secrets' agreement key (base64 X9.63)
func storeKey(t *testing.T, p *phone, secretsAgreement string) []byte {
	t.Helper()
	k, err := b64.DecodeString(secretsAgreement)
	if err != nil {
		t.Fatal(err)
	}
	C, err := AddPoints(p.agr.PublicKey().Bytes(), k)
	if err != nil {
		t.Fatal(err)
	}
	return C
}

func appWrap(t *testing.T, c *Secrets, p *phone, name string, vals map[string]string) []KeyEntry {
	t.Helper()
	C := storeKey(t, p, c.Key()["agreementKey"])
	out := []KeyEntry{}
	for _, k := range sortedKeys(vals) {
		dk := make([]byte, 32)
		rand.Read(dk)
		w, err := WrapToPoint(C, dk)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, KeyEntry{Store: name, Key: k, Wrapped: w, Data: b64.EncodeToString(gcmSeal(dk, []byte(vals[k]), KeyAAD(name, k)))})
	}
	return out
}

// newSecrets: an empty secrets, and the master key
func newSecrets(t *testing.T) (*Secrets, *phone) {
	t.Helper()
	root, _ := NewSigner()
	c, err := New(root.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, newPhone()
}

// claimFor: the statement (master key, secrets, phone, root), signed by the master key, and the sealed bundle
func claimFor(c *Secrets, master, p, root *phone, rb any) (string, string, Sealed) {
	plain, _ := json.Marshal(rb)
	sum := sha256.Sum256(plain)
	var st claimStatement
	st.Kind, st.Master, st.Root = "kernel-claim", master.signingKey(), root.signingKey()
	k := c.Key()
	st.Secrets.SigningKey, st.Secrets.AgreementKey = k["signingKey"], k["agreementKey"]
	st.Phone.SigningKey, st.Phone.AgreementKey = p.signingKey(), p.agreementKey()
	st.BundleSha256 = hex.EncodeToString(sum[:])
	sb, _ := json.Marshal(st)
	bundle, _ := SealTo(k["agreementKey"], plain, infoClaim)
	return string(sb), master.sign(string(sb)), bundle
}

func recoverBundle(t *testing.T, c *Secrets, p *phone) claimBundle {
	t.Helper()
	rb := claimBundle{Format: "keys", NotSensitive: []string{"default", "claude", "openrouter"}}
	for _, n := range []string{"claude", "default", "gmail", "openrouter"} {
		rb.Stores = append(rb.Stores, n)
		rb.Keys = append(rb.Keys, appWrap(t, c, p, n, testValues[n])...)
	}
	return rb
}

var resetBundle = claimBundle{Format: "keys"}

// setup: secrets Recovered with the test stores; the phone and the root key
func setup(t *testing.T) (*Secrets, *phone, *phone) {
	t.Helper()
	c, master := newSecrets(t)
	p, root := newPhone(), newPhone()
	s, sig, b := claimFor(c, master, p, root, recoverBundle(t, c, p))
	pl(t)(c.Claim(s, sig, b))
	return c, p, root
}

func unlock(t *testing.T, c *Secrets, p *phone, store string) string {
	t.Helper()
	b, err := c.UnlockBegin(store)
	if err != nil {
		t.Fatal(err)
	}
	id, s := p.share(b)
	m := pl(t)(c.UnlockFinish(id, s))
	return m["id"].(string)
}

func pl2(t *testing.T) func(SignedDoc, error) SignedDoc {
	return func(d SignedDoc, err error) SignedDoc {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
}

func storeOf(t *testing.T, c *Secrets, p *phone, name string) map[string]string {
	t.Helper()
	return storeValues(t, c, p, name)
}
