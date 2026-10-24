// Package kerneltest: the whole kernel for other modules' tests (the router's, the machine's). Every component
// runs in-process on its own httptest server, on a fake Fly whose machines have real key pairs and a fake GitHub
// (the minter's), with a phone key and a root key the test holds, and secrets already claimed (Reset with a seed: no
// stores). Two copies, blue and green (docs/PLAN-cluster.md "Releases: the copy flip"): Start runs blue, which
// serves; Release starts green's components fresh, RosterFor/SignRoster sign a copy's roster (green's retires blue's
// members), Flip hands blue over to green as the router does.
package kerneltest

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/merger"
	"github.com/DE0CH/jarvis4/kernel/minter"
	"github.com/DE0CH/jarvis4/kernel/mover"
	"github.com/DE0CH/jarvis4/kernel/notarizer"
	"github.com/DE0CH/jarvis4/kernel/notary"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/secrets"
	"github.com/DE0CH/jarvis4/kernel/sig"
	"github.com/DE0CH/jarvis4/kernel/signers"
	"github.com/DE0CH/jarvis4/kernel/spawner"
)

// Roles: every kernel component (a copy has one of each)
var Roles = []string{"notary", "notarizer", "mover", "merger", "spawner", "identity", "gullible", "minter", "secrets"}

// Copy: one kernel copy's running components
type Copy struct {
	Name    string
	URL     map[string]string // role → base URL
	Secrets *secrets.Secrets
	dir     string
	// retired: the keys this copy's next roster names as retired (a component of it that restarted, or the other
	// copy's members once this copy takes over)
	retired []sig.Identity
}

// Kernel: the running copies and the keys a test signs with
type Kernel struct {
	Phone, Root *sig.Signer
	PhoneAgree  *ecdh.PrivateKey
	// URL: the serving copy's components (role → base URL); URLFor names a copy's own
	URL     map[string]string
	Copies  map[string]*Copy
	Active  string // the copy that serves
	Fly     *FakeFly
	GitHub  *FakeGitHub // the minter's
	Secrets *secrets.Secrets
	servers []*httptest.Server
	master  *sig.Signer
	seed    []byte
	env     map[string]string
	t       testing.TB
}

// URLFor: the base URL of a role in the serving copy, or of a Deployment "<role>-<copy>" (what the router's
// KERNEL_URL template gives)
func (k *Kernel) URLFor(name string) string {
	for c, cp := range k.Copies {
		if r, ok := strings.CutSuffix(name, "-"+c); ok {
			return cp.URL[r]
		}
	}
	return k.URL[name]
}

// Close: every server
func (k *Kernel) Close() {
	for _, s := range k.servers {
		s.Close()
	}
}

// Start: copy blue, serving; machineEnv is what spawned machines' Fly config env gets
func Start(t testing.TB, machineEnv map[string]string) *Kernel {
	phone, _ := sig.NewSigner()
	root, _ := sig.NewSigner()
	pa, _ := ecdh.P256().GenerateKey(rand.Reader)
	k := &Kernel{Phone: phone, Root: root, PhoneAgree: pa, Copies: map[string]*Copy{}, Fly: NewFakeFly(),
		GitHub: &FakeGitHub{Keys: map[string][]minter.DeployKey{}}, env: machineEnv, t: t, Active: "blue"}
	k.seed = make([]byte, 32)
	rand.Read(k.seed)
	blue := k.startCopy(t, "blue")
	k.URL, k.Secrets = blue.URL, blue.Secrets
	if err := k.ClaimSeeded(blue.Secrets, k.seed); err != nil {
		t.Fatal(err)
	}
	if err := k.SignRoster("blue"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	return k
}

// startCopy: fresh components for a copy (its volumes kept from an earlier run of it), none holding a roster
func (k *Kernel) startCopy(t testing.TB, name string) *Copy {
	cp := k.Copies[name]
	if cp == nil {
		cp = &Copy{Name: name, dir: t.TempDir()}
		k.Copies[name] = cp
	}
	cp.URL = map[string]string{}
	for _, role := range Roles[:8] {
		c, err := sig.NewComponent(role)
		if err != nil {
			t.Fatal(err)
		}
		trust := sig.NewTrust(k.Root.PublicKey())
		s := serve.New(c, trust)
		switch role {
		case "notary":
			n, err := notary.Open(filepath.Join(cp.dir, "notary"), c.Signer)
			if err != nil {
				t.Fatal(err)
			}
			notary.Register(s, n)
		case "notarizer":
			n, err := notarizer.Open(filepath.Join(cp.dir, "notarizer"), c.Signer, trust)
			if err != nil {
				t.Fatal(err)
			}
			notarizer.Register(s, n)
		case "mover":
			mover.Register(s, mover.New(c.Signer, trust))
		case "merger":
			merger.Register(s, merger.New(c.Signer, trust))
		case "spawner":
			sp, err := spawner.Open(filepath.Join(cp.dir, "spawner"), c, trust, k.Fly, k.env)
			if err != nil {
				t.Fatal(err)
			}
			spawner.Register(s, sp)
		case "identity":
			signers.RegisterIdentity(s)
		case "gullible":
			signers.RegisterGullible(s)
		case "minter":
			minter.Register(s, minter.New(c, trust, k.GitHub))
		}
		srv := httptest.NewServer(s.Mux)
		k.servers = append(k.servers, srv)
		cp.URL[role] = srv.URL
	}
	sc, err := secrets.New(k.Root.PublicKey(), minter.NewClient(cp.URL["minter"]))
	if err != nil {
		t.Fatal(err)
	}
	cp.Secrets = sc
	srv := httptest.NewServer(secrets.Handler(sc))
	k.servers = append(k.servers, srv)
	cp.URL["secrets"] = srv.URL
	return cp
}

// Retired, SetRetired: the keys the copy's next roster names as retired
func (c *Copy) Retired() []sig.Identity     { return append([]sig.Identity{}, c.retired...) }
func (c *Copy) SetRetired(r []sig.Identity) { c.retired = r }

// Serve: the copy serves from now on (a router's flip, as the test's helpers see it)
func (k *Kernel) Serve(copy string) {
	k.Active, k.URL, k.Secrets = copy, k.Copies[copy].URL, k.Copies[copy].Secrets
}

// Other: the copy that doesn't serve
func (k *Kernel) Other() string {
	if k.Active == "blue" {
		return "green"
	}
	return "blue"
}

// Release: a kernel release lands on the copy that doesn't serve: every one of its components starts again fresh (its
// volumes kept), its secrets empty; its roster (RosterFor) retires the serving copy's members
func (k *Kernel) Release(t testing.TB) *Copy {
	cp := k.startCopy(t, k.Other())
	cp.retired = nil
	for _, role := range Roles[:8] {
		cp.retired = append(cp.retired, k.identityAt(k.Active, role))
	}
	cp.retired = append(cp.retired, k.Copies[k.Active].retired...)
	return cp
}

// RosterFor: the root key's roster of a copy as its components answer now. The serving copy's names its retired keys
// (components that restarted); the other copy's names the secrets the kit derives (the serving one's keys), its own
// empty secrets as secretsBoot, and the serving copy's members as retired.
func (k *Kernel) RosterFor(copy string) (sig.Doc, error) {
	cp := k.Copies[copy]
	ids := []sig.Identity{}
	for _, role := range Roles {
		ids = append(ids, k.identityAt(copy, role))
	}
	r := sig.Roster{Copy: copy, Members: ids, Retired: cp.retired}
	if copy != k.Active {
		boot := ids[len(ids)-1]
		ids[len(ids)-1] = k.identityAt(k.Active, "secrets")
		r.SecretsBoot = &boot
	}
	p, err := r.Payload()
	if err != nil {
		return sig.Doc{}, err
	}
	s, err := k.Root.Sign([]byte(p))
	return sig.Doc{Payload: p, Sig: s}, err
}

// Roster: the serving copy's roster
func (k *Kernel) Roster() (sig.Doc, error) { return k.RosterFor(k.Active) }

// Trust: the serving copy's roster as a machine (or a test) holds it
func (k *Kernel) Trust() *sig.Trust {
	d, err := k.Roster()
	if err != nil {
		panic(err)
	}
	t := sig.NewTrust(k.Root.PublicKey())
	if err := t.Set(d, nil); err != nil {
		panic(err)
	}
	return t
}

// SignRoster: the copy's roster to each of its components
func (k *Kernel) SignRoster(copy string) error {
	d, err := k.RosterFor(copy)
	if err != nil {
		return err
	}
	for _, u := range k.Copies[copy].URL {
		if err := postRoster(u, d); err != nil {
			return err
		}
	}
	return nil
}

func postRoster(u string, d sig.Doc) error {
	b, _ := json.Marshal(map[string]sig.Doc{"roster": d})
	resp, err := http.Post(u+"/roster", "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s/roster: %d %s", u, resp.StatusCode, body)
	}
	return nil
}

// PostRoster: the serving copy's roster to its components (and to extra, another secrets' URL, if not "")
func (k *Kernel) PostRoster(extra string) error {
	if err := k.SignRoster(k.Active); err != nil {
		return err
	}
	if extra != "" {
		d, err := k.Roster()
		if err != nil {
			return err
		}
		return postRoster(extra, d)
	}
	return nil
}

// Flip: what the router does once the other copy's roster is signed: every serving component hands over (the
// stateful ones' state sealed to the other copy), the other copy's notarizer, spawner and secrets take it, and the
// other copy serves
func (k *Kernel) Flip(t testing.TB) {
	to := k.Other()
	d, err := k.RosterFor(to)
	if err != nil {
		t.Fatal(err)
	}
	from := k.Copies[k.Active]
	handoffs := map[string]sig.Doc{}
	for _, role := range Roles {
		h, err := postTo(from.URL[role], "/handoff", map[string]any{"roster": d})
		if err != nil {
			t.Fatalf("%s's handoff: %v", role, err)
		}
		handoffs[role] = h
	}
	for _, role := range []string{"notarizer", "spawner", "secrets"} {
		if _, err := postTo(k.Copies[to].URL[role], "/takeover", map[string]any{"handoff": handoffs[role]}); err != nil {
			t.Fatalf("%s's takeover: %v", role, err)
		}
	}
	k.Serve(to)
}

// postTo: one component's signed answer, or its error
func postTo(u, path string, body any) (sig.Doc, error) {
	b, _ := json.Marshal(body)
	resp, err := http.Post(u+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return sig.Doc{}, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	var d sig.Doc
	json.Unmarshal(out, &d)
	if resp.StatusCode != 200 {
		return d, fmt.Errorf("%s%s: HTTP %d %s", u, path, resp.StatusCode, d.Payload)
	}
	return d, nil
}

// identityAt: a component's identity in a copy (secrets: the keys it serves with now)
func (k *Kernel) identityAt(copy, role string) sig.Identity {
	return identityOf(k.Copies[copy].URL[role], role)
}

// RootTop: ⊤ on the sink, signed by the root key (what the app signs once after the claim)
func (k *Kernel) RootTop() sig.Doc {
	ik, _ := doc.IdealKeys(doc.Sink)
	d, _ := k.Root.SignJSON(doc.Grant{Kind: "grant", Machine: doc.Sink, Keys: ik, Pair: perm.Top(), From: []string{}, At: doc.Now()})
	return d
}

// ---- a fake GitHub (the minter's) ---------------------------------------------------------------------------------

// FakeGitHub: deploy keys per repo; Tokens holds every token it was called with
type FakeGitHub struct {
	mu     sync.Mutex
	n      int64
	Keys   map[string][]minter.DeployKey
	Tokens []string
}

func (g *FakeGitHub) AddDeployKey(token, repo, title, pub string) (minter.DeployKey, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	k := minter.DeployKey{ID: g.n, Title: title, Key: pub}
	g.Keys[repo], g.Tokens = append(g.Keys[repo], k), append(g.Tokens, token)
	return k, nil
}

func (g *FakeGitHub) DeleteDeployKey(token, repo string, id int64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []minter.DeployKey
	for _, k := range g.Keys[repo] {
		if k.ID != id {
			out = append(out, k)
		}
	}
	g.Keys[repo], g.Tokens = out, append(g.Tokens, token)
	return nil
}

// ---- a fake Fly -----------------------------------------------------------------------------------------------

// FakeMachine: one machine, with the key pairs its image made
type FakeMachine struct {
	ID, Image, State string
	Source           string // the source its Fly metadata names
	Volume           string
	Env              map[string]string
	Sig              *sig.Signer
	Enc              *ecdh.PrivateKey
}

type FakeFly struct {
	mu       sync.Mutex
	n        int
	Machines map[string]*FakeMachine
	vols     map[string]bool
	// Booting: new machines stay "starting" until Up
	Booting bool
	// Full: the next this-many creates answer that the volume's host is full (Fly's 412 volume_placement_capacity)
	Full int
	// Lose: the next this-many creates make the machine but answer an error (a lost answer)
	Lose int
	// StuckVolumes: volume deletes fail (Fly still holds the volume)
	StuckVolumes bool
}

func NewFakeFly() *FakeFly {
	return &FakeFly{Machines: map[string]*FakeMachine{}, vols: map[string]bool{}}
}

func (f *FakeFly) Configure(string) {}

func (f *FakeFly) CreateVolume(string, int, map[string]any) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	v := fmt.Sprintf("vol_%d", f.n)
	f.vols[v] = true
	return v, nil
}

func (f *FakeFly) Create(image, region string, guest map[string]any, env map[string]string, volume, source string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Full > 0 {
		f.Full--
		return "", &spawner.FlyError{HTTP: 412, Status: "volume_placement_capacity", Msg: "POST /machines: HTTP 412 insufficient resources to create new machine with existing volume " + volume}
	}
	f.n++
	id := fmt.Sprintf("%014x", f.n)
	s, _ := sig.NewSigner()
	e, _ := ecdh.P256().GenerateKey(rand.Reader)
	st := "started"
	if f.Booting {
		st = "starting"
	}
	f.Machines[id] = &FakeMachine{ID: id, Image: image, State: st, Env: env, Sig: s, Enc: e, Source: source, Volume: volume}
	if f.Lose > 0 {
		f.Lose--
		return "", fmt.Errorf("connection reset")
	}
	return id, nil
}

// Up: a booting machine is started
func (f *FakeFly) Up(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m := f.Machines[id]; m != nil {
		m.State = "started"
	}
}

// Machine: one by id
func (f *FakeFly) Machine(id string) *FakeMachine {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Machines[id]
}

// List: a copy of every machine, as Fly's machine list shows them to the router's read-only token
func (f *FakeFly) List() []FakeMachine {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []FakeMachine{}
	for _, m := range f.Machines {
		out = append(out, *m)
	}
	return out
}

// Volumes: the volumes Fly still has
func (f *FakeFly) Volumes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for v := range f.vols {
		out = append(out, v)
	}
	return out
}

func (f *FakeFly) Inspect(id string) (spawner.FlyMachine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.Machines[id]
	if m == nil {
		return spawner.FlyMachine{State: "destroyed"}, nil
	}
	return spawner.FlyMachine{State: m.State, Image: strings.Replace(m.Image, ":latest", "", 1), Volume: m.Volume, Source: m.Source}, nil
}

func (f *FakeFly) Init(id string) (spawner.MachineKeys, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.Machines[id]
	if m == nil {
		return spawner.MachineKeys{}, fmt.Errorf("no machine %s", id)
	}
	return spawner.MachineKeys{SigningKey: m.Sig.PublicKey(), EncryptionKey: sig.B64.EncodeToString(m.Enc.PublicKey().Bytes())}, nil
}

func (f *FakeFly) Destroy(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m := f.Machines[id]; m != nil {
		m.State = "destroyed"
	}
	return nil
}

func (f *FakeFly) DeleteVolume(v string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.StuckVolumes {
		return &spawner.FlyError{HTTP: 412, Msg: "DELETE /volumes/" + v + ": HTTP 412 volume is attached"}
	}
	delete(f.vols, v)
	return nil
}

// Stop: the machine stopped outside Jarvis (someone ran fly machine stop, or it exited)
func (f *FakeFly) Stop(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m := f.Machines[id]; m != nil {
		m.State = "stopped"
	}
}

// ClaimSeeded: a claim of sc with keys derived from seed (the same kit derives the same secrets), by the test's master
// key (one per Kernel)
func (k *Kernel) ClaimSeeded(sc *secrets.Secrets, seed []byte) error {
	if k.master == nil {
		k.master, _ = sig.NewSigner()
	}
	id, err := sc.Identity()
	if err != nil {
		return err
	}
	ds, da, err := secrets.SeedIdentity(seed)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(map[string]any{"format": "keys", "secretsSeed": sig.B64.EncodeToString(seed)})
	sum := sha256.Sum256(b)
	st := map[string]any{"kind": "kernel-claim", "master": k.master.PublicKey(),
		"secrets": map[string]string{"signingKey": id["signingKey"].(string), "agreementKey": id["agreementKey"].(string)},
		"phone":   map[string]string{"signingKey": k.Phone.PublicKey(), "agreementKey": sig.B64.EncodeToString(k.PhoneAgree.PublicKey().Bytes())},
		"root":    k.Root.PublicKey(), "bundleSha256": hex.EncodeToString(sum[:]),
		"identity": map[string]string{"signingKey": ds, "agreementKey": da}}
	sb, _ := json.Marshal(st)
	ms, _ := k.master.Sign(sb)
	sealed, err := secrets.SealTo(id["agreementKey"].(string), b, "jarvis2/kernel-claim")
	if err != nil {
		return err
	}
	_, err = sc.Claim(string(sb), ms, sealed)
	return err
}

// Restart: a stateless component (mover, merger, identity, gullible, minter) of the serving copy starts again as a
// crash restart does: fresh keys, no roster, on a new server (URLFor names it from now on; secrets keeps calling the
// minter it was started with). Its old keys go into the copy's next roster as retired.
func (k *Kernel) Restart(t testing.TB, role string) {
	cp := k.Copies[k.Active]
	cp.retired = append(cp.retired, k.identityAt(k.Active, role))
	c, err := sig.NewComponent(role)
	if err != nil {
		t.Fatal(err)
	}
	trust := sig.NewTrust(k.Root.PublicKey())
	s := serve.New(c, trust)
	switch role {
	case "mover":
		mover.Register(s, mover.New(c.Signer, trust))
	case "merger":
		merger.Register(s, merger.New(c.Signer, trust))
	case "identity":
		signers.RegisterIdentity(s)
	case "gullible":
		signers.RegisterGullible(s)
	case "minter":
		minter.Register(s, minter.New(c, trust, k.GitHub))
	default:
		t.Fatalf("Restart: %s keeps state; only mover, merger, identity, gullible and minter", role)
	}
	srv := httptest.NewServer(s.Mux)
	k.servers = append(k.servers, srv)
	cp.URL[role] = srv.URL
}
