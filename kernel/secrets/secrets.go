// Package secrets: the kernel's secrets (DESIGN "Target design"), carried over from the old core's store half
// (core/keys.go, deploykeys.go, continuity.go; same formats, so the app's store code serves both). It holds the
// stores, the unlocks and a signed list of open unlocks, and keeps nothing it doesn't need. It hands secrets out and
// never uses one (DECISIONS 230): a deploy key's GitHub call is the minter's (kernel/minter), and a store's earlier
// versions are the router's (a restore writes back an earlier key with its key-written receipt, keys.go). Given a
// grant (signed by the mover or the merger), it returns the stores the grant's allowed set names (store:x), sealed to
// the grant's machine and signed. An unlock is per store and never locks by itself (D2): it ends with a lock call, and
// the phone sees open ones. Any written key reaches the next pull, whoever wrote it (D1): a write carries its value
// sealed to secrets as well ("live"), which secrets uses only to update an open unlock of that store. It checks
// nothing about who may write: writing is protected only by the router.
package secrets

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/minter"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

type Err struct {
	Status int
	Msg    string
}

func (e *Err) Error() string                    { return e.Msg }
func fail(status int, f string, a ...any) error { return &Err{status, fmt.Sprintf(f, a...)} }

// SignedDoc: every answer
type SignedDoc = sig.Doc

type unlocked struct {
	values  map[string]string
	version string               // the store's version these values are (storeVersion)
	ids     map[string]time.Time // each open unlock of the store → since
}

type Secrets struct {
	mu        sync.Mutex
	signer    *Signer
	agreement *ecdh.PrivateKey // secrets' share K of every store's key
	MasterKey string           // the master public key it was claimed with ("" = empty)
	trust     *sig.Trust       // the root key's roster: the other components' identities (and its own) are checked with it
	exit      func()

	phoneSigning, phoneAgreement string
	root                         string // the root key (a separate key on the iPhone)

	stores       map[string]map[string]*KeyEntry
	notSensitive map[string]bool
	pending      map[string]pendingUnlock
	unlocked     map[string]*unlocked
	pendingKeys  map[string]pendingDeployKey
	repoOwner    map[string]string
	repoKeyID    map[string]int64 // a deploy-key store → the id GitHub gave its key (what a remove deletes)

	// continuity.go: the state key, the newest state's seq and hash and the sealed document; the mode (blue/green)
	lineKey     []byte
	lineSeq     int
	lineHash    string
	lineDoc     *LineStateDoc
	mode        string
	standbyFrom int

	minter Minter
	now    func() time.Time
}

type pendingUnlock struct {
	store   string
	entries map[string]KeyEntry
	version string
	t       *ecdh.PrivateKey
}

// New: an empty secrets with fresh keys; rootPub is the root key's public half (keys/root.pub), which the roster is
// checked against; m is where an approved deploy-key call goes (the minter)
func New(rootPub string, m Minter) (*Secrets, error) {
	s, err := NewSigner()
	if err != nil {
		return nil, err
	}
	a, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	c := &Secrets{signer: s, agreement: a, trust: sig.NewTrust(rootPub),
		stores: map[string]map[string]*KeyEntry{}, notSensitive: map[string]bool{}, pending: map[string]pendingUnlock{},
		unlocked: map[string]*unlocked{}, pendingKeys: map[string]pendingDeployKey{}, repoOwner: map[string]string{},
		repoKeyID: map[string]int64{}, minter: m, now: time.Now}
	return c, nil
}

// SetExit: what a wipe calls (the process exits)
func (c *Secrets) SetExit(f func()) { c.exit = f }

// SetRoster: the root key's roster, which must name the keys secrets serves with now (after a claim with a seed: the
// derived ones)
func (c *Secrets) SetRoster(d SignedDoc) (map[string]string, error) {
	self := c.componentIdentity()
	if err := c.trust.Set(d, &self); err != nil {
		return nil, fail(403, "%v", err)
	}
	c.logf("the root key's roster taken")
	return map[string]string{"kind": "roster-taken", "roster": d.ID()}, nil
}

// Roster: the roster held (nil: none yet)
func (c *Secrets) Roster() *SignedDoc { return c.trust.Doc() }

func (c *Secrets) logf(f string, a ...any) { log.Printf(f, a...) }

func (c *Secrets) sign(v any) (SignedDoc, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return SignedDoc{}, err
	}
	s, err := c.signer.Sign(b)
	if err != nil {
		return SignedDoc{}, err
	}
	return SignedDoc{Payload: string(b), Sig: s}, nil
}

// ---- identity ---------------------------------------------------------------------------------------------------

func (c *Secrets) Key() map[string]string {
	return map[string]string{"signingKey": c.signer.PublicKey(), "agreementKey": b64.EncodeToString(c.agreement.PublicKey().Bytes())}
}

// Identity: the keys (role "secrets"; the roster vouches for them), and the signed state: the
// master key it was claimed with, the phone's keys and the root key
func (c *Secrets) Identity() (map[string]any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := map[string]any{"kind": "secrets-state", "master": c.MasterKey, "phone": nil, "root": c.root, "lineSeq": c.lineSeq,
		"derived": c.lineKey != nil, "serving": map[string]string{modeServing: "serving", modeStandby: "standby", modeHandedOff: "handed-off"}[c.mode]}
	if c.phoneSigning != "" {
		st["phone"] = map[string]string{"signingKey": c.phoneSigning, "agreementKey": c.phoneAgreement}
	}
	d, err := c.sign(st)
	if err != nil {
		return nil, err
	}
	k := c.Key()
	return map[string]any{"role": "secrets", "signingKey": k["signingKey"], "agreementKey": k["agreementKey"],
		"state": d, "bundle": "keys", "continuity": 1}, nil
}

// KeysStatement: {kind: "keys", phone, root}, what the notarizer and the mover take the phone's and the root key from
func (c *Secrets) KeysStatement() (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey == "" {
		return SignedDoc{}, fail(409, "secrets isn't set up yet: Reset or Recover it in the app first")
	}
	return c.sign(map[string]string{"kind": "keys", "phone": c.phoneSigning, "root": c.root})
}

// ---- claim -------------------------------------------------------------------------------------------------------

const (
	infoClaim = "jarvis2/kernel-claim" // the claim's bundle, sealed to secrets by the phone
	infoLive  = "jarvis2/live-key"     // a written key's value, sealed to secrets (D1)
)

type claimStatement struct {
	Kind    string `json:"kind"`   // "kernel-claim"
	Master  string `json:"master"` // signs this statement; kept for life
	Secrets struct {
		SigningKey   string `json:"signingKey"`
		AgreementKey string `json:"agreementKey"`
	} `json:"secrets"`
	Phone struct {
		SigningKey   string `json:"signingKey"`
		AgreementKey string `json:"agreementKey"`
	} `json:"phone"`
	Root         string `json:"root"` // the root key's signing key
	BundleSha256 string `json:"bundleSha256"`
	Identity     *struct {
		SigningKey   string `json:"signingKey"`
		AgreementKey string `json:"agreementKey"`
	} `json:"identity,omitempty"`
	Standby bool `json:"standby,omitempty"`
}

// FlyStore: the old core's own Fly token store, a name secrets never holds (storeName refuses it; the spawner gets
// its token sealed by setup)
const FlyStore = "core"

type claimBundle struct {
	Format       string            `json:"format"` // "keys"
	Stores       []string          `json:"stores"`
	Keys         []KeyEntry        `json:"keys"`
	NotSensitive []string          `json:"notSensitive"`
	Owners       map[string]string `json:"owners"`
	SecretsSeed  string            `json:"secretsSeed,omitempty"`
	LineState    *LineStateDoc     `json:"lineState,omitempty"`
}

// Claim: once, on an empty secrets (Reset or Recover from the app), as the old core's claim, plus the root key
func (c *Secrets) Claim(statement, masterSig string, bundle Sealed) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey != "" {
		return SignedDoc{}, fail(409, "secrets is already set up: end it with its own kit (the app's wipe) first")
	}
	var st claimStatement
	if json.Unmarshal([]byte(statement), &st) != nil || st.Kind != "kernel-claim" {
		return SignedDoc{}, fail(400, "not a kernel claim statement")
	}
	if _, err := parseSigningKey(st.Master); err != nil {
		return SignedDoc{}, fail(400, "bad master key: %v", err)
	}
	if !VerifyWith(st.Master, []byte(statement), masterSig) {
		return SignedDoc{}, fail(403, "the claim isn't signed by the master key it names")
	}
	k := c.Key()
	if st.Secrets.SigningKey != k["signingKey"] || st.Secrets.AgreementKey != k["agreementKey"] {
		return SignedDoc{}, fail(403, "the claim names another secrets")
	}
	if _, err := parseSigningKey(st.Phone.SigningKey); err != nil {
		return SignedDoc{}, fail(400, "bad phone signing key: %v", err)
	}
	if _, err := parseSigningKey(st.Root); err != nil || st.Root == st.Phone.SigningKey {
		return SignedDoc{}, fail(400, "the root key: a P-256 key of its own (not the phone's)")
	}
	if b, err := b64.DecodeString(st.Phone.AgreementKey); err != nil || len(b) != 65 {
		return SignedDoc{}, fail(400, "bad phone agreement key")
	} else if _, err := ecdh.P256().NewPublicKey(b); err != nil {
		return SignedDoc{}, fail(400, "bad phone agreement key: %v", err)
	}
	plain, err := OpenSealed(c.agreement, bundle, infoClaim)
	if err != nil {
		return SignedDoc{}, fail(400, "can't open the bundle")
	}
	sum := sha256.Sum256(plain)
	if hex.EncodeToString(sum[:]) != st.BundleSha256 {
		return SignedDoc{}, fail(403, "the bundle isn't the one the master key signed")
	}
	var b claimBundle
	if json.Unmarshal(plain, &b) != nil || b.Format != "keys" {
		return SignedDoc{}, fail(400, "bad bundle")
	}
	stores := map[string]map[string]*KeyEntry{}
	owners := map[string]string{}
	for _, n := range b.Stores {
		if _, seen := stores[n]; !storeName(n) || seen {
			return SignedDoc{}, fail(400, "bad or repeated store %q in the bundle", n)
		}
		stores[n] = map[string]*KeyEntry{}
	}
	now := c.now().UTC().Format(time.RFC3339)
	for i := range b.Keys {
		x := b.Keys[i]
		keys, ok := stores[x.Store]
		if _, seen := keys[x.Key]; !ok || seen || !validEntry(&x, x.Store) {
			return SignedDoc{}, fail(400, "bad or repeated key %q of store %q in the bundle", x.Key, x.Store)
		}
		x.Writer, x.At, x.BackupSha256 = &EntryWriter{By: "core"}, now, ""
		keys[x.Key] = &x
	}
	for s, repo := range b.Owners {
		if _, ok := stores[s]; ok && minter.RepoOK(repo) {
			owners[s] = repo
		}
	}
	var dk *coreKeys
	var line *lineState
	if b.SecretsSeed != "" {
		seed, err := b64.DecodeString(b.SecretsSeed)
		if err != nil || len(seed) != 32 {
			return SignedDoc{}, fail(400, "secretsSeed: 32 bytes, base64")
		}
		if dk, err = DeriveCoreKeys(seed); err != nil {
			return SignedDoc{}, fail(400, "secretsSeed: %v", err)
		}
		if st.Identity == nil || st.Identity.SigningKey != dk.signer.PublicKey() || st.Identity.AgreementKey != b64.EncodeToString(dk.agreement.PublicKey().Bytes()) {
			return SignedDoc{}, fail(403, "the claim's identity isn't the keys its seed derives")
		}
		if b.LineState != nil {
			ls, err := openLineState(b.LineState, dk)
			if err != nil {
				return SignedDoc{}, err
			}
			line = &ls
		}
	} else if st.Identity != nil || b.LineState != nil || st.Standby {
		return SignedDoc{}, fail(400, "an identity or a state comes with a secretsSeed")
	}
	c.MasterKey, c.root = st.Master, st.Root
	c.repoOwner, c.repoKeyID = owners, map[string]int64{}
	c.phoneSigning, c.phoneAgreement = st.Phone.SigningKey, st.Phone.AgreementKey
	c.stores = stores
	c.notSensitive = map[string]bool{}
	for _, n := range b.NotSensitive {
		if _, ok := c.stores[n]; ok {
			c.notSensitive[n] = true
		}
	}
	restored := []string{}
	if dk != nil {
		c.signer, c.agreement, c.lineKey = dk.signer, dk.agreement, dk.state
		if line != nil {
			restored = c.restoreLine(*line, line.Final)
		}
		if st.Standby && (line == nil || !line.Final) {
			c.mode = modeStandby
			if line != nil {
				c.standbyFrom = line.Seq
			}
		}
		c.lineHash, c.lineDoc = "", nil
	}
	c.logf("claimed: master key, phone and root keys, %d stores, derived keys %v, state %v (deploy-key stores back: %v)",
		len(c.stores), dk != nil, line != nil, restored)
	out := map[string]any{"kind": "claimed", "stores": len(c.stores), "derived": dk != nil, "standby": c.mode == modeStandby}
	if line != nil {
		out["lineSeq"], out["repoStores"] = line.Seq, restored
	}
	return c.sign(out)
}

// Wipe: the current master key ends secrets (it answers, then exits; Kubernetes starts an empty one)
func (c *Secrets) Wipe(statement, masterSig string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey == "" {
		return c.sign(map[string]any{"kind": "wiping", "secrets": c.signer.PublicKey(), "alreadyEmpty": true})
	}
	if !VerifyWith(c.MasterKey, []byte(statement), masterSig) {
		return SignedDoc{}, fail(403, "the wipe isn't signed by this master key")
	}
	var st struct {
		Kind    string `json:"kind"`
		Secrets string `json:"secrets"`
	}
	if json.Unmarshal([]byte(statement), &st) != nil || st.Kind != "kernel-wipe" || st.Secrets != c.signer.PublicKey() {
		return SignedDoc{}, fail(403, "the wipe names another secrets")
	}
	d, err := c.sign(map[string]any{"kind": "wiping", "secrets": st.Secrets})
	if err == nil && c.exit != nil {
		go c.exit()
	}
	return d, err
}

// ---- stores --------------------------------------------------------------------------------------------------

// storeName: a store's name — lower case, digits and "-", never the old core's own store (the one reservation: every
// store secrets holds came through here)
func storeName(n string) bool {
	if n == "" || len(n) > 64 || n == FlyStore {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// CreateStore: once per name — an empty, non-sensitive store
func (c *Secrets) CreateStore(name string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey == "" {
		return SignedDoc{}, fail(409, "secrets isn't set up yet: Reset or Recover it in the app first")
	}
	if !storeName(name) || name == DeployKeyTokenStore {
		return SignedDoc{}, fail(400, "bad store name (%s is always sensitive)", DeployKeyTokenStore)
	}
	if _, ok := c.stores[name]; ok {
		return SignedDoc{}, fail(409, "store %s exists", name)
	}
	c.stores[name], c.notSensitive[name] = map[string]*KeyEntry{}, true
	return c.sign(map[string]any{"kind": "store-created", "name": name})
}

// MarkSensitive: the one-way upgrade
func (c *Secrets) MarkSensitive(name string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.notSensitive[name] {
		return c.sign(map[string]any{"kind": "marked-sensitive", "name": name, "already": true})
	}
	delete(c.notSensitive, name)
	return c.sign(map[string]any{"kind": "marked-sensitive", "name": name})
}

// Stores: the signed list (names, sensitivity, empty, unlocked, keys with writers, version)
func (c *Secrets) Stores(nonce string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	type row struct {
		Name      string   `json:"name"`
		Sensitive bool     `json:"sensitive"`
		Empty     bool     `json:"empty"`
		Unlocked  bool     `json:"unlocked"`
		Keys      []keyRow `json:"keys"`
		Version   string   `json:"version"`
	}
	out := []row{}
	for n, keys := range c.stores {
		out = append(out, row{n, !c.notSensitive[n], len(keys) == 0, c.unlocked[n] != nil, keyRows(keys), storeVersion(keys)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return c.sign(map[string]any{"kind": "stores", "nonce": nonce, "stores": out})
}

// ---- unlock (per store; never ends by itself: D2) --------------------------------------------------------------

func (c *Secrets) UnlockBegin(name string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if name == DeployKeyTokenStore {
		return SignedDoc{}, fail(403, "%s is opened only by a deploy-key call, never unlocked", DeployKeyTokenStore)
	}
	keys := c.stores[name]
	if len(keys) == 0 {
		return SignedDoc{}, fail(404, "no store %s with contents: write a key into it first (jarvis2 put-key)", name)
	}
	t, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return SignedDoc{}, err
	}
	type keyBegin struct {
		Key          string       `json:"key"`
		E            string       `json:"e"`
		Writer       *EntryWriter `json:"writer"`
		DataSha256   string       `json:"dataSha256"`
		BackupSha256 string       `json:"backupSha256"`
		At           string       `json:"at"`
	}
	entries := copyEntries(keys)
	rows := []keyBegin{}
	for _, k := range sortedKeys(entries) {
		x := entries[k]
		rows = append(rows, keyBegin{k, x.Wrapped.E, entryWriter(&x), sha256Hex(x.Data), x.BackupSha256, x.At})
	}
	id := randID()
	version := storeVersion(keys)
	c.pending[id] = pendingUnlock{store: name, entries: entries, version: version, t: t}
	return c.sign(map[string]any{"kind": "unlock-begin", "pending": id, "store": name, "t": b64.EncodeToString(t.PublicKey().Bytes()),
		"keys": rows, "version": version})
}

const infoShare = "jarvis2/unlock-share"

// UnlockFinish: the phone's share of every key unlock_begin named, each sealed to T (one try)
func (c *Secrets) UnlockFinish(pending string, shares map[string]Sealed) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pending[pending]
	if !ok {
		return SignedDoc{}, fail(404, "no such pending unlock")
	}
	delete(c.pending, pending)
	if len(shares) != len(p.entries) {
		return SignedDoc{}, fail(400, "one share for each of the %d keys", len(p.entries))
	}
	vals := map[string]string{}
	for k, x := range p.entries {
		sh, ok := shares[k]
		if !ok {
			return SignedDoc{}, fail(400, "no share for key %s", k)
		}
		px, err := OpenSealed(p.t, sh, infoShare)
		if err != nil {
			return SignedDoc{}, fail(400, "the share for %s isn't sealed to this unlock", k)
		}
		v, err := c.openEntry(&x, px)
		if err != nil {
			return SignedDoc{}, fail(403, "%v", err)
		}
		vals[k] = v
	}
	if cur := c.stores[p.store]; storeVersion(cur) != p.version {
		return SignedDoc{}, fail(409, "store %s changed during the unlock: unlock again", p.store)
	}
	u := c.unlocked[p.store]
	if u == nil {
		u = &unlocked{ids: map[string]time.Time{}}
		c.unlocked[p.store] = u
	}
	u.values, u.version = vals, p.version
	id := randID()
	u.ids[id] = c.now()
	c.logf("store %s unlocked (%s)", p.store, id)
	return c.sign(map[string]any{"kind": "unlocked", "id": id, "store": p.store, "version": p.version})
}

// Lock: one unlock ends; the store's plaintext goes with its last one
func (c *Secrets) Lock(id string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for name, u := range c.unlocked {
		if _, ok := u.ids[id]; ok {
			delete(u.ids, id)
			if len(u.ids) == 0 {
				delete(c.unlocked, name)
			}
			c.logf("unlock %s ended (%s)", id, name)
			return c.sign(map[string]any{"kind": "locked", "id": id, "store": name})
		}
	}
	return c.sign(map[string]any{"kind": "locked", "id": id, "already": true})
}

// ListUnlocked: the signed list of open unlocks (what the phone shows)
func (c *Secrets) ListUnlocked(nonce string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	type row struct {
		ID    string `json:"id"`
		Store string `json:"store"`
		Since string `json:"since"`
	}
	rows := []row{}
	for name, u := range c.unlocked {
		for id, since := range u.ids {
			rows = append(rows, row{id, name, since.UTC().Format(time.RFC3339)})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Since < rows[j].Since })
	return c.sign(map[string]any{"kind": "unlocked-list", "nonce": nonce, "unlocked": rows})
}

// liveUpdate: a written key's value (sealed to secrets) into an open unlock of its store, which stays current (D1;
// callers hold mu, after the write)
func (c *Secrets) liveUpdate(store, key string, deleted bool, live *Sealed, before string) {
	u := c.unlocked[store]
	if u == nil {
		return
	}
	current := u.version == before // the unlock had the store as it was just before this write
	if deleted {
		vals := map[string]string{}
		for k, x := range u.values {
			if k != key {
				vals[k] = x
			}
		}
		u.values = vals
		if current {
			u.version = storeVersion(c.stores[store])
		}
		return
	}
	if live == nil {
		return // the unlock is behind until the phone unlocks again
	}
	v, err := OpenSealed(c.agreement, *live, infoLive+"\n"+store+"\n"+key)
	if err != nil {
		c.logf("store %s: key %s's live value doesn't open; the unlock is behind", store, key)
		return
	}
	vals := map[string]string{}
	for k, x := range u.values {
		vals[k] = x
	}
	vals[key] = string(v)
	if current {
		u.version = storeVersion(c.stores[store])
	}
	u.values = vals
}

// ---- pull (a grant) ----------------------------------------------------------------------------------------------

// Pull: the stores the grant's allowed set names (store:x), each from its open unlock, sealed to the grant's machine.
// A finite set: every store it names must be open (else 423 naming it). A cofinite set: the open stores it doesn't
// exclude. The deploy-key token store is never served.
func (c *Secrets) Pull(in gv.Signed) (SignedDoc, error) {
	if in.By == "root" {
		k, err := c.KeysStatement()
		if err != nil {
			return SignedDoc{}, err
		}
		id := c.componentIdentity()
		in.Keys, in.Secrets = &k, &id
	}
	g, err := gv.Open(in, c.trust)
	if err != nil {
		return SignedDoc{}, fail(403, "%v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	served := func(n string) bool { return n != DeployKeyTokenStore }
	var names []string
	if g.Pair.Allowed.Only != nil {
		for _, s := range g.Pair.Allowed.Only {
			if n, ok := strings.CutPrefix(s, "store:"); ok && served(n) {
				names = append(names, n)
			}
		}
	} else {
		for n := range c.unlocked {
			if g.Pair.Allowed.Contains("store:"+n) && served(n) {
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	merged := map[string]string{}
	versions := map[string]string{}
	stale := []string{}
	for _, n := range names {
		u := c.unlocked[n]
		if u == nil {
			return SignedDoc{}, fail(423, "store %s is locked: the session waits for Deyao's unlock of it", n)
		}
		for k, v := range u.values {
			merged[k] = v
		}
		versions[n] = u.version
		if u.version != storeVersion(c.stores[n]) {
			stale = append(stale, n) // a key written without its live value: only a new unlock brings it
		}
	}
	plain, _ := json.Marshal(merged)
	sealed, err := SealTo(g.Keys.EncryptionKey, plain, "jarvis2/secrets")
	if err != nil {
		return SignedDoc{}, err
	}
	c.logf("pulled by %s: %v", g.Machine, names)
	return c.sign(map[string]any{"kind": "secrets", "machine": g.Machine, "grant": in.Grant.ID(), "stores": names,
		"versions": versions, "stale": stale, "sealed": sealed})
}

// componentIdentity: this secrets' identity as the other components check it
func (c *Secrets) componentIdentity() sig.Identity {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := c.Key()
	return sig.Identity{Role: "secrets", SigningKey: k["signingKey"], AgreementKey: k["agreementKey"]}
}

// ---- helpers -----------------------------------------------------------------------------------------------------

var hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func randID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// verifyOwn: the payload of a document only if secrets signed it
func (c *Secrets) verifyOwn(d *SignedDoc, out any) error {
	if d == nil || !VerifyWith(c.signer.PublicKey(), []byte(d.Payload), d.Sig) {
		return fail(400, "not a document secrets signed")
	}
	return json.Unmarshal([]byte(d.Payload), out)
}
