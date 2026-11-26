package main

// The secrets-controller core (docs/DESIGN.md). Every answer that leaves it is signed; all of its state
// lives in memory (a restart = a new, empty core, set up again from the iPhone: Reset or Recover). It accepts or rejects
// — the orchestration (which approval applies, retries, the session flows) lives in the router outside it.

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

type Err struct {
	Status int
	Msg    string
}

func (e *Err) Error() string                    { return e.Msg }
func fail(status int, f string, a ...any) error { return &Err{status, fmt.Sprintf(f, a...)} }

// SignedDoc: what every answer is — the exact JSON text and the core's signature over it
type SignedDoc struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
	// beside a cert only (not covered by Sig, each its own proof): the cert's input-log entry, signed (audit.go), and
	// the line's carried secrets rebound to the cert's machine (carry.go). Ignored when a document is read back.
	Entry *SignedDoc `json:"entry,omitempty"`
	Carry string     `json:"carry,omitempty"`
}

type StartedMachine struct {
	ID            string `json:"id"`
	Requested     string `json:"requested"`     // the image start was asked for (what an approval names)
	Image         string `json:"image"`         // what Fly reports the machine runs (ref@digest)
	EncryptionKey string `json:"encryptionKey"` // the machine's own keys, read through Fly exec
	SigningKey    string `json:"signingKey"`
	// Volume: the machine's Fly volume (volumes.go), mounted at its path: where the machine keeps its state
	Volume *VolumeInfo `json:"volume,omitempty"`
}

type Options struct {
	Harness string `json:"harness"`
	// the harness's permission mode (auto | bypass): signed, so a resume that changes it — above all raising to
	// bypass — isn't approved by a dead machine and needs the phone (Deyao, 2026-10-09)
	PermissionMode string `json:"permissionMode,omitempty"`
	// Config: the session's settings (first prompt, title, model, repos, …: a JSON object the core doesn't read),
	// fixed for the line: the phone approves it with a new line, an unattended resume carries it over unchanged.
	// Once: this one machine's one-time inputs (a resume's prompt, a rollback marker): only the phone approves one,
	// and a successor never inherits it (vouch.go).
	Config string `json:"config,omitempty"`
	Once   string `json:"once,omitempty"`
}

// a succession request, made before any machine exists. Machine is set only when a running machine succeeds
// itself with one more store.
type Request struct {
	Kind        string          `json:"kind"`
	Predecessor *SignedDoc      `json:"predecessor"` // the predecessor's succession cert; nil = new line
	PredID      string          `json:"predecessorId"`
	Line        string          `json:"line,omitempty"` // the line's first machine; "" = a new line
	Machine     *StartedMachine `json:"machine,omitempty"`
	Image       string          `json:"image,omitempty"` // the image the new machine runs
	Stores      []string        `json:"stores"`
	Options     Options         `json:"options"`
	AddedStore  string          `json:"addedStore,omitempty"` // set when the machine succeeds itself with one more store
	Downgrade   bool            `json:"downgrade,omitempty"`  // the machine succeeds itself with a subset of its stores and new keys
	// Salt: the caller's, on a new line only, so two identical new-session requests get different nonces (the nonce
	// is the request's MAC, and an approval nonce is used once: a repeated salt only gets its second approval refused);
	// a successor's nonce is already unique per predecessor
	Salt string `json:"salt,omitempty"`
}

// Approval: a challenge one of the approve_by_* primitives approved; certify() binds it to exactly one machine
type Approval struct {
	Kind    string  `json:"kind"` // "approval"
	Nonce   string  `json:"nonce"`
	Request Request `json:"request"`
	By      string  `json:"by"` // "phone" | "dead-machine"
}

type Cert struct {
	Kind     string          `json:"kind"` // "succession-cert"
	PredID   string          `json:"predecessorId"`
	Machine  *StartedMachine `json:"machine"`
	Stores   []string        `json:"stores"`
	Options  Options         `json:"options"`
	Nonce    string          `json:"nonce"`
	IssuedAt string          `json:"issuedAt"`
	// for the machine's own checks of grants (docs/DESIGN.md "Grants"): the phone's signing key, and whether
	// any of the stores is sensitive (then only a fresh phone grant opens a shell)
	Phone     string `json:"phone,omitempty"`
	Sensitive bool   `json:"sensitive"`
	Line      string `json:"line"` // the line's first machine: what grants name, stable across successions
	// Snapshot: sha256 of the snapshot the predecessor signed when it was killed ("" = it left none): the only one
	// the machine restores (vouch.go).
	Snapshot string `json:"snapshot,omitempty"`
	// PredCert: the nonce of the cert this one continues (the predecessor's newest, or this machine's previous one
	// for an add-store or a downgrade); "" on a new line. Carried secrets sealed under it open for this cert, older
	// ones don't (carry.go).
	PredCert string `json:"predecessorCert,omitempty"`
}

// succession: the cert for a machine on a line (callers hold c.mu)
func (c *Core) succession(r Request, m *StartedMachine, nonce, now string) Cert {
	sensitive := false
	for _, n := range r.Stores {
		sensitive = sensitive || !c.notSensitive[n]
	}
	line := r.Line
	if line == "" {
		line = m.ID
	}
	snap := ""
	if r.PredID != "" && r.PredID != m.ID {
		snap = c.killed[r.PredID]
	}
	predCert := ""
	if r.Predecessor != nil {
		var pc Cert
		json.Unmarshal([]byte(r.Predecessor.Payload), &pc) // already checked: this core signed it, and it is the newest
		predCert = pc.Nonce
	}
	return Cert{Kind: "succession-cert", PredID: r.PredID, Machine: m, Stores: r.Stores, Options: r.Options,
		Nonce: nonce, IssuedAt: now, Phone: c.phoneSigning, Sensitive: sensitive, Line: line, Snapshot: snap, PredCert: predCert}
}

type unlocked struct {
	values  map[string]string
	version string // the store's version these values are (storeVersion)
	ids     map[string]unlockHold
}

// unlockHold: one open unlock of a store. For = "" is a standing unlock (open to every cert that names the store
// until locked: the Stores page); otherwise the nonce of the one challenge or cert it was opened for (a Start, an
// add-store, a waiting session's Unlock…): only that cert's pull reads it, its pull releases it, and it lapses
// after scopedUnlockTTL (carry.go).
type unlockHold struct {
	since time.Time
	For   string
}

type Core struct {
	mu        sync.Mutex
	signer    *Signer
	agreement *ecdh.PrivateKey // the core's share K of every store's key
	nonceKey  []byte
	MasterKey string  // the master public key it was claimed with ("" = empty, waiting for Reset or Recover)
	BoxSig    string  // the box key's signature over this core's identity
	box       *Signer // the box key (main), to vouch for the derived keys a claim brings (continuity.go)
	exit      func()  // Wipe ends the process (main: os.Exit; tests: a stub)

	phoneSigning, phoneAgreement string

	approvalsUsed map[string]bool // approval nonces already certified, and self-succession challenges already answered
	// latest: a certified machine → the nonce of its newest cert (certify, then each add-store or downgrade). A
	// machine's older certs are superseded: they pull nothing, continue nothing and succeed to nothing, so a
	// downgrade (or an add-store answered again) can't be undone with a cert from before it.
	latest map[string]string

	// created: a machine this core created and hasn't initialised or killed yet → the image start asked for.
	// signing: a machine this core initialised and Fly hasn't destroyed → its current signing key (init, then a
	// downgrade's new key: what its kill's snapshot is checked with). Everything else about a machine lives in the
	// core-signed "started" document and the certs.
	created map[string]string
	signing map[string]string
	// killed: a machine Fly confirmed destroyed → sha256 of the snapshot it signed at its kill ("" = none; vouch.go);
	// its successor's cert names it. With used: approve_by_dead_machine's two sets.
	killed map[string]string
	used   map[string]bool
	// adopted: a machine an earlier core certified whose line this core took over at its kill (legacy.go) → that
	// cert, signed by this core
	adopted map[string]*SignedDoc

	auditHead string // audit.go: the input log's head and length (the router keeps the entries)
	auditSeq  int

	stores       map[string]map[string]*KeyEntry // a store → its keys (keys.go); an empty map = created, still empty
	notSensitive map[string]bool                 // the only sensitivity state: every store not in it is sensitive
	pending      map[string]pendingUnlock
	unlocked     map[string]*unlocked
	pendingKeys  map[string]pendingDeployKey // deploy-key adds/removes waiting for the phone (deploykeys.go)
	// repoOwner: a deploy-key store → the repo whose key it holds (deploykeys.go). Derived, not kept: set by the
	// add that wrote the store, or by a Recover from the bundle's owners (the app reads them from the stores)
	repoOwner map[string]string

	// history.go: each store's last historyMax versions, its version counter, and pending restores
	history    map[string][]*storeVersionRec
	historySeq map[string]int
	restores   map[string]*pendingRestore

	carryKey []byte // carry.go: the AES key of the sessions' carried secrets; made at start, never leaves the core

	// continuity.go: set when a claim brought the seed (the keys above are then the derived ones): the line-state key,
	// the newest line state's seq, the hash of what it holds, and the sealed, signed document
	lineKey  []byte
	lineSeq  int
	lineHash string
	lineDoc  *LineStateDoc
	// mode: serving (""), standby (Recovered to take over from a core that still serves) or handed-off; standbyFrom:
	// the line state seq a standing-by core was Recovered with (a takeover brings one at least as new)
	mode        string
	standbyFrom int
	vol         volState // volumes.go: each machine's Fly volume

	fly    Fly
	github GitHub // deploy keys only, with the token the phone unlocks for that one call
	now    func() time.Time
}

type pendingUnlock struct {
	store   string
	entries map[string]KeyEntry // the store's keys at begin: what the phone's shares open
	version string
	t       *ecdh.PrivateKey
	For     string // the challenge or cert nonce the unlock is for ("" = standing)
}

func NewCore(fly Fly) (*Core, error) {
	s, err := NewSigner()
	if err != nil {
		return nil, err
	}
	a, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	nk := make([]byte, 32)
	rand.Read(nk)
	ck := make([]byte, 32)
	if _, err := rand.Read(ck); err != nil {
		return nil, err
	}
	return &Core{signer: s, agreement: a, nonceKey: nk, carryKey: ck,
		approvalsUsed: map[string]bool{}, latest: map[string]string{},
		created: map[string]string{}, signing: map[string]string{}, killed: map[string]string{}, used: map[string]bool{}, adopted: map[string]*SignedDoc{},
		stores: map[string]map[string]*KeyEntry{}, notSensitive: map[string]bool{}, pending: map[string]pendingUnlock{}, unlocked: map[string]*unlocked{}, pendingKeys: map[string]pendingDeployKey{}, repoOwner: map[string]string{},
		vol: newVolState(), fly: fly, github: newGitHub(), now: time.Now}, nil
}

// logf: diagnostics to stdout only (the core keeps no log: every state change reaches the router as a signed answer)
func (c *Core) logf(f string, a ...any) { log.Printf(f, a...) }

func (c *Core) sign(v any) (SignedDoc, error) {
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

// verifyOwn: the payload of a document only if this core signed it
func (c *Core) verifyOwn(d *SignedDoc, out any) error {
	if d == nil || !VerifyWith(c.signer.PublicKey(), []byte(d.Payload), d.Sig) {
		return fail(400, "not a document this core signed")
	}
	return json.Unmarshal([]byte(d.Payload), out)
}

func (c *Core) mac(parts ...string) string {
	m := hmac.New(sha256.New, c.nonceKey)
	for _, p := range parts {
		m.Write([]byte(p))
		m.Write([]byte{0})
	}
	return hex.EncodeToString(m.Sum(nil))
}

// ---- identity ----------------------------------------------------------------------------------

func (c *Core) Key() map[string]string {
	pub := c.agreement.PublicKey().Bytes()
	return map[string]string{"signingKey": c.signer.PublicKey(), "agreementKey": b64.EncodeToString(pub)}
}

// IdentityText: what the box key signs (keys/box.pub checks it: the app, the setup session)
func IdentityText(signingKey, agreementKey string) string {
	return "jarvis2-core-identity " + signingKey + " " + agreementKey
}

// Identity: the core's public keys with the box key's signature over them (it travels as plain text), and
// the core's own signed state: the master public key it was claimed with ("" while empty) and the phone's
// keys. The app reads from it whether the core is empty and whose master key it holds; the setup session
// learns the master public key from it (after checking the box key, then this signature).
func (c *Core) Identity() (map[string]any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// lineSeq: the newest line state's number (continuity.go), which the app remembers as the least a Recover may bring
	// back; derived: the keys come from the master key's seed, so a Recover with the same kit brings this core back
	st := map[string]any{"kind": "core-state", "master": c.MasterKey, "phone": nil, "lineSeq": c.lineSeq, "derived": c.lineKey != nil,
		"serving": map[string]string{modeServing: "serving", modeStandby: "standby", modeHandedOff: "handed-off"}[c.mode]}
	if c.phoneSigning != "" {
		st["phone"] = map[string]string{"signingKey": c.phoneSigning, "agreementKey": c.phoneAgreement}
	}
	d, err := c.sign(st)
	if err != nil {
		return nil, err
	}
	k := c.Key()
	// bundle: the claim bundle format this core takes (keys.go: stores of keys), so the app wraps a Recover for it
	// continuity: this core takes a claim bundle's coreSeed and lineState (continuity.go)
	// sizeLadder: this core starts every size of the ladder (fly.go: small, medium, large, then 16gb, 32gb, …); a core
	// without it starts only small, medium and large, so the router offers no Upgrade past large (rust/router/src/memory.rs)
	return map[string]any{"signingKey": k["signingKey"], "agreementKey": k["agreementKey"], "boxSig": c.BoxSig, "state": d, "bundle": "keys", "continuity": 1, "sizeLadder": 1}, nil
}

// ---- claim: an empty core takes a master key (Reset or Recover, both from the app) ------------------------

const (
	infoClaim    = "jarvis2/claim"     // the claim's bundle, sealed to the core by the phone
	infoFlyToken = "jarvis2/fly-token" // the Fly token, sealed to the core by the setup session
)

type claimStatement struct {
	Kind   string `json:"kind"`   // "claim"
	Master string `json:"master"` // the master public key: it signs this statement; the core keeps it for its life
	Core   struct {
		SigningKey   string `json:"signingKey"`
		AgreementKey string `json:"agreementKey"`
	} `json:"core"`
	Phone struct {
		SigningKey   string `json:"signingKey"`
		AgreementKey string `json:"agreementKey"`
	} `json:"phone"`
	BundleSha256 string `json:"bundleSha256"`
	// Identity: the keys the bundle's coreSeed derives (continuity.go), named by the app and signed by the master key;
	// required with a seed, and the core refuses a claim whose seed derives other keys
	Identity *struct {
		SigningKey   string `json:"signingKey"`
		AgreementKey string `json:"agreementKey"`
	} `json:"identity,omitempty"`
	// Standby: this core serves nothing after the claim until a takeover gives it the final line state of the core
	// that still serves with the same keys (continuity.go, blue/green); with a seed only
	Standby bool `json:"standby,omitempty"`
}

// FlyStore: the key store holding the core's own Fly token (FLY_API_TOKEN). It arrives in a Recover bundle as
// flyToken (or through SetFlyToken); the core keeps only the token, for its whole life, and the store itself never
// exists for a session.
const FlyStore = "core"

// the claim bundle (Format "keys"): every store's name and every key already wrapped by the app to the store key
// (store_key), so the core never sees a store's plaintext; the names of the stores that are NOT sensitive — every
// other store comes back sensitive, since nothing can downgrade one later (the master key signed the bundle's hash);
// the deploy-key stores' repos (Owners); and the core's Fly token. A Reset's bundle has no stores. A core from before
// keys.go refuses the format rather than reading it as its whole-store blobs.
type claimBundle struct {
	Format       string            `json:"format"` // "keys"
	Stores       []string          `json:"stores"`
	Keys         []KeyEntry        `json:"keys"`
	NotSensitive []string          `json:"notSensitive"`
	Owners       map[string]string `json:"owners"` // a deploy-key store → its repo
	FlyToken     string            `json:"flyToken"`
	// continuity.go: the seed the app derived from the master key (base64, 32 bytes): this core's keys from now on;
	// and the line state an earlier core from the same seed left (the router kept it), taken back
	CoreSeed  string        `json:"coreSeed,omitempty"`
	LineState *LineStateDoc `json:"lineState,omitempty"`
}

// Claim: once per core, on an empty core. The statement names the master public key, this core and the
// phone, and is signed by that master key; from then on the core trusts that master key and that phone.
// The bundle, sealed to this core, carries the stores (Recover: every store from the backups, wrapped by the app,
// and the Fly token; Reset: none). Who may claim is the router's business (Deyao's logged-in app only); the app
// refuses a core claimed with a master key that isn't its own.
func (c *Core) Claim(statement, masterSig string, bundle Sealed) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey != "" {
		return SignedDoc{}, fail(409, "this core is already set up: end it with its own kit (the app's wipe), or empty it from git (RUNBOOK \"Emptying the core without its kit\"), then claim the new one")
	}
	var st claimStatement
	if json.Unmarshal([]byte(statement), &st) != nil || st.Kind != "claim" {
		return SignedDoc{}, fail(400, "not a claim statement")
	}
	if _, err := parseSigningKey(st.Master); err != nil {
		return SignedDoc{}, fail(400, "bad master key: %v", err)
	}
	if !VerifyWith(st.Master, []byte(statement), masterSig) {
		return SignedDoc{}, fail(403, "the claim isn't signed by the master key it names")
	}
	k := c.Key()
	if st.Core.SigningKey != k["signingKey"] || st.Core.AgreementKey != k["agreementKey"] {
		return SignedDoc{}, fail(403, "the claim names another core")
	}
	if _, err := parseSigningKey(st.Phone.SigningKey); err != nil {
		return SignedDoc{}, fail(400, "bad phone signing key: %v", err)
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
		if _, seen := stores[n]; !storeName(n) || n == FlyStore || seen {
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
		x.Writer, x.At, x.BackupSha256 = &EntryWriter{By: "core"}, now, "" // the master key signed the bundle
		keys[x.Key] = &x
	}
	for st, repo := range b.Owners {
		if _, ok := stores[st]; ok && repoRE.MatchString(repo) {
			owners[st] = repo
		}
	}
	var dk *coreKeys
	var line *lineState
	if b.CoreSeed != "" {
		seed, err := b64.DecodeString(b.CoreSeed)
		if err != nil || len(seed) != 32 {
			return SignedDoc{}, fail(400, "coreSeed: 32 bytes, base64")
		}
		if dk, err = DeriveCoreKeys(seed); err != nil {
			return SignedDoc{}, fail(400, "coreSeed: %v", err)
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
		return SignedDoc{}, fail(400, "an identity or a line state comes with a coreSeed")
	}
	token := b.FlyToken
	c.MasterKey = st.Master
	c.repoOwner = owners
	c.phoneSigning, c.phoneAgreement = st.Phone.SigningKey, st.Phone.AgreementKey
	c.stores = stores
	c.notSensitive = map[string]bool{} // exactly the bundle's: nothing from before the claim survives
	for _, n := range b.NotSensitive {
		if _, ok := c.stores[n]; ok {
			c.notSensitive[n] = true
		}
	}
	c.history, c.historySeq = nil, nil
	for _, n := range sortedKeys(c.stores) {
		c.record(n, VersionCause{Kind: "recover"})
	}
	if token != "" {
		c.fly.Configure(token)
	}
	restored := []string{}
	if dk != nil {
		// from now on this core is the one the seed derives (the boot keys only received this claim)
		c.signer, c.agreement, c.carryKey, c.nonceKey, c.lineKey = dk.signer, dk.agreement, dk.carry, dk.nonce, dk.state
		k := c.Key()
		if c.box != nil {
			if sig, err := c.box.Sign([]byte(IdentityText(k["signingKey"], k["agreementKey"]))); err == nil {
				c.BoxSig = sig
			}
		}
		if line != nil {
			restored = c.restoreLine(*line, line.Final) // a final state is newer than the backups: taken whole
		}
		if st.Standby && (line == nil || !line.Final) {
			c.mode = modeStandby
			if line != nil {
				c.standbyFrom = line.Seq
			}
		}
		c.lineHash, c.lineDoc = "", nil // syncLine seals the state as it is now, numbered on from the one taken back
	}
	c.logf("claimed: master key, phone keys, %d stores, Fly token %v, derived keys %v, line state %v (deploy-key stores back: %v)",
		len(c.stores), token != "", dk != nil, line != nil, restored)
	out := map[string]any{"kind": "claimed", "stores": len(c.stores), "derived": dk != nil, "standby": c.mode == modeStandby}
	if line != nil {
		out["lineSeq"], out["repoStores"] = line.Seq, restored
	}
	return c.sign(out)
}

// Wipe: the current master key (from Deyao's kit) ends this core: it answers, then exits, and Kubernetes
// starts a new, empty core in its place (new keys, nothing kept — the same as an infra restart). Without the
// current master key a set-up core is never emptied from the app.
func (c *Core) Wipe(statement, masterSig string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey == "" { // already empty: what a wipe makes; nothing to end
		return c.sign(map[string]any{"kind": "wiping", "core": c.signer.PublicKey(), "alreadyEmpty": true})
	}
	if !VerifyWith(c.MasterKey, []byte(statement), masterSig) {
		return SignedDoc{}, fail(403, "the wipe isn't signed by this core's master key")
	}
	var st struct {
		Kind string `json:"kind"`
		Core string `json:"core"` // the core's signing key
	}
	if json.Unmarshal([]byte(statement), &st) != nil || st.Kind != "wipe" || st.Core != c.signer.PublicKey() {
		return SignedDoc{}, fail(403, "the wipe names another core")
	}
	c.logf("wipe: the master key ends this core")
	d, err := c.sign(map[string]any{"kind": "wiping", "core": st.Core})
	if err == nil && c.exit != nil {
		go c.exit()
	}
	return d, err
}

// SetFlyToken: the core's Fly token, sealed to this core. Open: the core calls Fly only for its own app
// (FlyApp), which only Deyao's Fly org reaches, so a wrong token can only fail. The setup session sends it
// after a Reset; a Recover brings it in the bundle.
func (c *Core) SetFlyToken(sealed Sealed) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey == "" {
		return SignedDoc{}, fail(409, "this core isn't set up yet: Reset or Recover it in the app first")
	}
	plain, err := OpenSealed(c.agreement, sealed, infoFlyToken)
	if err != nil {
		return SignedDoc{}, fail(400, "can't open the Fly token")
	}
	var v struct {
		Token string `json:"FLY_API_TOKEN"`
	}
	if json.Unmarshal(plain, &v) != nil || v.Token == "" {
		return SignedDoc{}, fail(400, "no FLY_API_TOKEN")
	}
	c.fly.Configure(v.Token)
	c.logf("Fly token set")
	return c.sign(map[string]any{"kind": "fly-token-set"})
}

// StoreKey: the store key C = P + K for the phone agreement key P (open, public points only), signed: what the
// app wraps a store's data key to (a Recover's blobs, a deploy key's store) without adding points itself (CryptoKit
// has no point addition). The unwrap side is unchanged: the phone's share of P plus the core's of K.
// core: another core point K to add instead of this core's own (a Recover wraps to the derived keys the claim is about
// to give this core: continuity.go); the answer names it.
func (c *Core) StoreKey(phone, core string) (SignedDoc, error) {
	pb, err := b64.DecodeString(phone)
	if err != nil || len(pb) != 65 {
		return SignedDoc{}, fail(400, "phone: a P-256 public key (X9.63, base64)")
	}
	kb := c.agreement.PublicKey().Bytes()
	if core != "" {
		if kb, err = b64.DecodeString(core); err != nil || len(kb) != 65 {
			return SignedDoc{}, fail(400, "core: a P-256 public key (X9.63, base64)")
		}
	}
	sum, err := AddPoints(pb, kb)
	if err != nil {
		return SignedDoc{}, fail(400, "phone or core: %v", err)
	}
	out := map[string]any{"kind": "store-key", "phone": phone, "storeKey": b64.EncodeToString(sum)}
	if core != "" {
		out["core"] = core
	}
	return c.sign(out)
}

// ---- stores ----------------------------------------------------------------------------------------

func storeName(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// CreateStore: once per name — an empty, non-sensitive store (the only way a store is ever not sensitive,
// besides a Recover bundle)
func (c *Core) CreateStore(name string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey == "" {
		return SignedDoc{}, fail(409, "this core isn't set up yet: Reset or Recover it in the app first")
	}
	if !storeName(name) || name == FlyStore || name == DeployKeyTokenStore {
		return SignedDoc{}, fail(400, "bad store name (%s is always sensitive)", DeployKeyTokenStore)
	}
	if _, ok := c.stores[name]; ok {
		return SignedDoc{}, fail(409, "store %s exists", name)
	}
	c.stores[name], c.notSensitive[name] = map[string]*KeyEntry{}, true
	c.record(name, VersionCause{Kind: "created"})
	c.logf("store %s created (empty, not sensitive)", name)
	return c.sign(map[string]any{"kind": "store-created", "name": name})
}

// MarkSensitive: the one-way upgrade — the name leaves the non-sensitive set (anyone may: it only adds
// protection, and nothing puts a name back)
func (c *Core) MarkSensitive(name string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.notSensitive[name] { // already sensitive (or never made): what was asked for holds
		return c.sign(map[string]any{"kind": "marked-sensitive", "name": name, "already": true})
	}
	delete(c.notSensitive, name)
	c.logf("store %s marked sensitive", name)
	return c.sign(map[string]any{"kind": "marked-sensitive", "name": name})
}

// Stores: the signed list (names, sensitivity, empty, unlocked, each store's keys with who wrote them and when, its
// version) — the phone learns sensitivity from the core, and everyone the key names. unlocked = open for every session
// (a standing unlock); an unlock for one session doesn't count.
func (c *Core) Stores(nonce string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireScoped()
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
		out = append(out, row{n, !c.notSensitive[n], len(keys) == 0, c.standing(n), keyRows(keys), storeVersion(keys)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return c.sign(map[string]any{"kind": "stores", "nonce": nonce, "stores": out})
}

// ---- machines (the Fly API is used only here: start, kill) -----------------------------------------

type StartRequest struct {
	Image  string `json:"image"`
	Region string `json:"region"`
	Size   string `json:"size"`   // small | medium | large | 16gb | 32gb … (sizeGuest, fly.go)
	DiskGB int    `json:"diskGb"` // the machine's volume (volumes.go); 0 = defaultDiskGB
}

// Start: anyone may ask (normally the router): one Fly create, nothing more — a machine without a cert gets no
// secrets. Its config env is the core's alone (vouch.go machineEnv). The router then calls Init until the machine
// is up, and kills it if it never comes up.
func (c *Core) Start(r StartRequest) (SignedDoc, error) {
	if imageDigest(r.Image) == "" {
		return SignedDoc{}, fail(400, "start needs an image of %s pinned by digest", SessionRepo)
	}
	kind, cpus, memoryMB := sizeGuest(r.Size)
	if kind == "" {
		return SignedDoc{}, fail(400, "size: small, medium, large or a doubling past it (16gb, 32gb, …)")
	}
	guest := map[string]any{"cpu_kind": kind, "cpus": cpus, "memory_mb": memoryMB}
	env := c.machineEnv() // the machine's trust anchor and the router's address, set by the core, never the caller
	if env == nil {
		return SignedDoc{}, fail(503, "this core has no MACHINE_URL (its deployment's router address): it starts no machine")
	}
	id, vol, err := c.createMachine(r, guest, env) // volumes.go: with its own empty volume
	if err != nil {
		var e *Err
		if errors.As(err, &e) {
			return SignedDoc{}, err
		}
		return SignedDoc{}, fail(502, "fly create: %v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.created[id] = r.Image
	c.logf("machine %s created (%s)", id, r.Image)
	out := map[string]any{"kind": "created", "id": id, "image": r.Image}
	if vol != nil {
		out["volume"] = vol
	}
	return c.sign(out)
}

// Init: one try at reading a created machine's keys — Fly must report it started, then the image's init command
// prints them (Fly exec: their link to the machine is Fly's word). 409 while it isn't up yet (the router retries).
// The answer, the signed "started" document, is what certify takes.
func (c *Core) Init(id string) (SignedDoc, error) {
	c.mu.Lock()
	requested, ok := c.created[id]
	c.mu.Unlock()
	if !ok {
		return SignedDoc{}, fail(409, "machine %s isn't one this core created and hasn't initialised", id)
	}
	fm, err := c.fly.Inspect(id)
	if err != nil {
		return SignedDoc{}, fail(502, "fly: %v", err)
	}
	if fm.State != "started" {
		return SignedDoc{}, fail(409, "machine %s is %s, not started", id, fm.State)
	}
	keys, err := c.fly.Init(id)
	if err != nil {
		return SignedDoc{}, fail(502, "fly exec init: %v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.created[id]; !ok {
		return SignedDoc{}, fail(409, "machine %s was killed or initialised meanwhile", id)
	}
	delete(c.created, id)
	c.signing[id] = keys.SigningKey
	m := &StartedMachine{ID: id, Requested: requested, Image: fm.Image, EncryptionKey: keys.EncryptionKey, SigningKey: keys.SigningKey}
	if v := c.vol.live[id]; v != nil {
		vc := *v
		m.Volume = &vc
	}
	c.logf("machine %s started (%s)", id, fm.Image)
	return c.sign(map[string]any{"kind": "started", "machine": m})
}

// Certify: an approval + a started machine (Init's signed document) running the approved image → the succession
// cert (the machine's only permission). One machine per approval, one line per machine, one successor per
// predecessor. An approval for the null image takes no machine and burns the predecessor.
func (c *Core) Certify(approval, started *SignedDoc, carry string) (SignedDoc, error) {
	var a Approval
	if err := c.verifyOwn(approval, &a); err != nil || a.Kind != "approval" {
		return SignedDoc{}, fail(400, "not an approval this core signed")
	}
	r := a.Request
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.approvalsUsed[a.Nonce] {
		return SignedDoc{}, fail(409, "this approval was already used")
	}
	if r.PredID != "" && (!c.isKilled(r.PredID) || c.used[r.PredID]) {
		return SignedDoc{}, fail(409, "predecessor %s is not a killed, unused machine", r.PredID)
	}
	if err := c.isLatest(r.Predecessor); err != nil {
		return SignedDoc{}, err
	}
	now := c.now().UTC().Format(time.RFC3339)
	if r.Image == NullImage {
		if started != nil {
			return SignedDoc{}, fail(400, "a burn takes no machine")
		}
		c.approvalsUsed[a.Nonce], c.used[r.PredID] = true, true
		c.logf("burned %s (%s)", r.PredID, a.By)
		return c.sign(Cert{Kind: "burn-cert", PredID: r.PredID, Stores: []string{}, Nonce: a.Nonce, IssuedAt: now})
	}
	var st struct {
		Kind    string          `json:"kind"`
		Machine *StartedMachine `json:"machine"`
	}
	if err := c.verifyOwn(started, &st); err != nil || st.Kind != "started" || st.Machine == nil {
		return SignedDoc{}, fail(400, "not a started machine this core signed")
	}
	m, machine := st.Machine, st.Machine.ID
	if _, live := c.signing[machine]; !live || c.isKilled(machine) || c.latest[machine] != "" {
		return SignedDoc{}, fail(409, "machine %s is not a started machine without a line", machine)
	}
	if m.Requested != r.Image {
		return SignedDoc{}, fail(409, "machine %s runs %s, the approval is for %s", machine, m.Requested, r.Image)
	}
	if d := imageDigest(r.Image); d == "" || reportedDigest(m.Image) != d {
		return SignedDoc{}, fail(409, "machine %s runs %s, not the approved digest of %s", machine, m.Image, r.Image)
	}
	c.approvalsUsed[a.Nonce], c.latest[machine] = true, a.Nonce
	if r.PredID != "" {
		c.used[r.PredID] = true
	}
	c.logf("certified %s for %s (%s) %s → %v", machine, a.Nonce[:12], a.By, orNull(r.PredID), r.Stores)
	return c.signCert(c.succession(r, m, a.Nonce, now), a.By, carry)
}

// KillWithSnapshot: one Fly destroy, then Fly must report the machine destroyed (409 until it does: the router
// asks again) → killed. snapshot (optional): the sha256 of the snapshot the machine took and its signature over that
// hash with the machine's current signing key; its successor restores that one only. A claim that doesn't check (or
// none) doesn't stop the kill: the record names no snapshot (and says why in snapshotRefused), so the successor
// starts with no predecessor state — a kill needs no snapshot, only a successor's restore does. Only a caller that
// asks for it (snapshot.required: a pause, which would rather keep the machine than lose its state) gets the kill
// refused instead (409, the machine untouched). The first kill fixes the snapshot.
// A machine with a volume (volumes.go) has its volume deleted once Fly reports the machine destroyed; no volume
// snapshot is taken.
func (c *Core) KillWithSnapshot(id string, snapshot *SnapshotClaim) (SignedDoc, error) {
	return c.Kill(id, snapshot, nil)
}

// Kill: KillWithSnapshot, and for a machine an earlier core certified (legacy: its cert and the master key's claim of
// that core) the adoption of its line (legacy.go). A takeover that doesn't check is left out the same way as a
// snapshot that doesn't: the machine is killed, its line not taken over (unless snapshot.required).
func (c *Core) Kill(id string, snapshot *SnapshotClaim, legacy *LegacyCert) (SignedDoc, error) {
	if id == "" || id == "null" {
		return SignedDoc{}, fail(400, "kill takes a machine id (got %q)", id)
	}
	required := snapshot != nil && snapshot.Required
	c.mu.Lock()
	done, sum := c.isKilled(id), c.killed[id]
	key := c.signing[id]
	adopted := c.adopted[id]
	var adopt *Cert
	refused := "" // why the snapshot (or the takeover) isn't vouched for; the kill goes on without it
	if !done && key == "" && legacy != nil {
		cert, err := c.legacyCert(legacy)
		switch {
		case err != nil:
			refused = "the earlier core's cert doesn't check (" + err.Error() + ")"
		case cert.Machine.ID != id || c.latest[id] != "":
			refused = fmt.Sprintf("the earlier core's cert isn't for %s, or this core knows %s already", id, id)
		case snapshot == nil || snapshot.Sha256 == "":
			refused = "an earlier core's line is taken over only with the snapshot its current key signed, and none came"
		default:
			adopt, key = &cert, cert.Machine.SigningKey
		}
	}
	c.mu.Unlock()
	if done {
		c.mu.Lock()
		defer c.mu.Unlock()
		out := c.killedRecord(id)
		if adopted != nil {
			out["adopted"] = adopted
		}
		return c.sign(out)
	}
	if refused == "" && snapshot != nil && snapshot.Sha256 != "" {
		switch {
		case key == "":
			refused = fmt.Sprintf("machine %s isn't one this core knows (an earlier core's, with no cert of it), so its snapshot can't be checked", id)
		case !hex64RE.MatchString(snapshot.Sha256) || !VerifyWith(key, []byte(snapshot.Sha256), snapshot.Sig):
			refused = fmt.Sprintf("the snapshot isn't signed by machine %s's current key", id)
		default:
			sum = snapshot.Sha256
		}
	}
	if refused != "" {
		if required {
			return SignedDoc{}, fail(409, "machine %s is kept, not killed: %s, so a resume couldn't restore it. Destroy the session instead (a destroy needs no verified snapshot), or pause again once the machine sends a snapshot signed with its current key", id, refused)
		}
		adopt = nil
		c.logf("kill %s: %s; killed without naming a snapshot", id, refused)
	}
	fm, err := c.fly.Inspect(id)
	if err != nil {
		return SignedDoc{}, fail(502, "fly: %v", err)
	}
	if fm.State != "destroyed" {
		derr := c.fly.Destroy(id)
		if fm, err = c.fly.Inspect(id); err != nil {
			return SignedDoc{}, fail(502, "fly: %v", err)
		}
		if fm.State != "destroyed" {
			return SignedDoc{}, fail(409, "machine %s is %s, not destroyed yet (destroy: %v)", id, fm.State, derr)
		}
	}
	c.dropVolume(id)
	c.mu.Lock()
	defer c.mu.Unlock()
	var adoptedNow *SignedDoc
	if adopt != nil {
		if c.isKilled(id) || c.latest[id] != "" {
			return SignedDoc{}, fail(409, "machine %s was taken over meanwhile", id)
		}
		// the line goes on here: this core signs the earlier core's cert as its own (the same payload), so the
		// successor's machine, whatever its image, checks its predecessor's cert with this core's key
		sig, err := c.signer.Sign([]byte(legacy.Cert.Payload))
		if err != nil {
			return SignedDoc{}, err
		}
		d := &SignedDoc{Payload: legacy.Cert.Payload, Sig: sig}
		c.latest[id], c.adopted[id] = adopt.Nonce, d
		adoptedNow = d
		c.logf("machine %s taken over from an earlier core (line %s, snapshot %s)", id, adopt.Line, orNull(sum))
	}
	if !c.isKilled(id) {
		c.killed[id] = sum
	}
	delete(c.created, id)
	delete(c.signing, id)
	c.logf("machine %s killed (snapshot %s)", id, orNull(c.killed[id]))
	out := c.killedRecord(id)
	if adoptedNow != nil {
		out["adopted"] = adoptedNow
	}
	if refused != "" {
		out["snapshotRefused"] = refused
	}
	return c.sign(out)
}

// killedRecord: the kill's signed record — the snapshot its successor restores (callers hold c.mu)
func (c *Core) killedRecord(id string) map[string]any {
	return map[string]any{"kind": "killed", "id": id, "snapshot": c.killed[id]}
}

// NullImage: a succession to the null image burns the predecessor — start() makes no machine, only marks the
// predecessor used, so it can never be continued (what ending a session needs)
const NullImage = "null"

// ---- succession --------------------------------------------------------------------------------

type SuccessionInput struct {
	Predecessor *SignedDoc `json:"predecessor"` // nil = from null
	Machine     string     `json:"machine"`     // only when a running machine succeeds itself (add a store, downgrade)
	// downgrade only: the machine's new key pair
	NewEncryptionKey string   `json:"newEncryptionKey"`
	NewSigningKey    string   `json:"newSigningKey"`
	Image            string   `json:"image"`
	Stores           []string `json:"stores"` // sorted, each once
	Options          Options  `json:"options"`
	Salt             string   `json:"salt"` // a new line only: hex, 16–64 characters
}

// Succession: a challenge derived from the request (nothing stored), before any machine exists
func (c *Core) Succession(in SuccessionInput) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(in.Options.Config) > maxConfig || len(in.Options.Once) > maxOnce {
		return SignedDoc{}, fail(400, "config at most %d bytes, once at most %d", maxConfig, maxOnce)
	}
	req := Request{Kind: "succession", Predecessor: in.Predecessor, Options: in.Options}
	// the caller fills in defaults; the core takes the exact values or refuses (R2)
	if in.Image != NullImage && (req.Options.Harness == "" || req.Options.PermissionMode != "auto" && req.Options.PermissionMode != "bypass") {
		return SignedDoc{}, fail(400, "options: a harness, and permissionMode auto or bypass")
	}
	if !sort.StringsAreSorted(in.Stores) {
		return SignedDoc{}, fail(400, "stores: sorted, each once")
	}
	for i := 1; i < len(in.Stores); i++ {
		if in.Stores[i] == in.Stores[i-1] {
			return SignedDoc{}, fail(400, "stores: sorted, each once")
		}
	}
	var pc Cert
	if in.Predecessor != nil {
		if err := c.verifyOwn(in.Predecessor, &pc); err != nil || pc.Kind != "succession-cert" || pc.Machine == nil {
			return SignedDoc{}, fail(400, "predecessor is not a succession cert this core signed")
		}
		if c.latest[pc.Machine.ID] != pc.Nonce {
			return SignedDoc{}, fail(409, "the predecessor cert isn't %s's newest: an older cert continues nothing", pc.Machine.ID)
		}
		req.PredID, req.Line = pc.Machine.ID, pc.Line
	}
	if in.Image == NullImage {
		if req.PredID == "" || len(in.Stores) != 0 || in.Options != (Options{}) || in.Machine != "" {
			return SignedDoc{}, fail(400, "a burn is a predecessor with no stores, no options and the null image")
		}
		req.Image, req.Stores = NullImage, []string{}
		b, _ := json.Marshal(req)
		return c.sign(map[string]any{"kind": "challenge", "nonce": c.mac("challenge", string(b)), "request": req})
	}
	req.Stores = []string{}
	for _, n := range in.Stores {
		if keys, ok := c.stores[n]; !ok {
			return SignedDoc{}, fail(400, "unknown store %s: make it first (a key written into it makes it)", n)
		} else if len(keys) == 0 {
			// an empty store gets its sensitivity settled by its writer first (setup.py marks it before writing)
			return SignedDoc{}, fail(400, "store %s is empty, so there is nothing to unlock: write a key into it first (jarvis2 put-key), or leave it out", n)
		}
		if n == DeployKeyTokenStore {
			// its token is opened only by deploy_key_finish, for one phone-approved call (DESIGN "Deploy keys")
			return SignedDoc{}, fail(403, "%s never goes to a session", DeployKeyTokenStore)
		}
		req.Stores = append(req.Stores, n) // the phone reads each one's sensitivity from the signed store list
	}
	if in.Machine != "" {
		// a running machine succeeds itself from one of its certs: one more store (answered by the phone), or
		// a subset with a new key pair (a downgrade)
		if _, ok := c.signing[in.Machine]; !ok || req.PredID != in.Machine {
			return SignedDoc{}, fail(400, "a machine succeeds itself from its own cert")
		}
		if c.isKilled(in.Machine) || persistentOptions(pc.Options) != req.Options {
			return SignedDoc{}, fail(400, "the same live machine with the same options (and no one-time inputs)")
		}
		m := pc.Machine
		if in.NewEncryptionKey != "" || in.NewSigningKey != "" {
			if !subset(req.Stores, pc.Stores) {
				return SignedDoc{}, fail(400, "a downgrade keeps a subset of the stores")
			}
			if _, err := parseSigningKey(in.NewSigningKey); err != nil {
				return SignedDoc{}, fail(400, "bad new signing key")
			}
			if b, err := b64.DecodeString(in.NewEncryptionKey); err != nil || len(b) != 65 {
				return SignedDoc{}, fail(400, "bad new encryption key")
			}
			if in.NewSigningKey == m.SigningKey || in.NewEncryptionKey == m.EncryptionKey {
				return SignedDoc{}, fail(400, "a downgrade needs a new key pair")
			}
			nm := *m
			nm.EncryptionKey, nm.SigningKey = in.NewEncryptionKey, in.NewSigningKey
			req.Machine, req.Downgrade = &nm, true
		} else {
			added, err := oneMore(pc.Stores, req.Stores)
			if err != nil {
				return SignedDoc{}, err
			}
			req.Machine, req.AddedStore = m, added
		}
	} else {
		if in.Image == "" {
			return SignedDoc{}, fail(400, "a new machine needs an image")
		}
		req.Image = in.Image
		if req.PredID == "" {
			if b, err := hex.DecodeString(in.Salt); err != nil || len(b) < 8 || len(b) > 32 {
				return SignedDoc{}, fail(400, "salt: a new line takes the caller's random salt (hex, 16–64 characters)")
			}
			req.Salt = in.Salt
		}
	}
	b, _ := json.Marshal(req)
	return c.sign(map[string]any{"kind": "challenge", "nonce": c.mac("challenge", string(b)), "request": req})
}

// subset: every store of `a` is in `b`
func subset(a, b []string) bool {
	have := map[string]bool{}
	for _, n := range b {
		have[n] = true
	}
	for _, n := range a {
		if !have[n] {
			return false
		}
	}
	return true
}

// oneMore: `next` is `prev` plus exactly one store (both sorted, no duplicates) → that store
func oneMore(prev, next []string) (string, error) {
	have := map[string]bool{}
	for _, n := range prev {
		have[n] = true
	}
	added := ""
	for _, n := range next {
		if have[n] {
			delete(have, n)
		} else if added == "" {
			added = n
		} else {
			added = "\x00"
		}
	}
	if len(have) != 0 || added == "" || added == "\x00" {
		return "", fail(400, "a machine can succeed itself only with its store set plus exactly one store")
	}
	return added, nil
}

type challenge struct {
	Kind    string  `json:"kind"`
	Nonce   string  `json:"nonce"`
	Request Request `json:"request"`
}

func (c *Core) readChallenge(d *SignedDoc) (challenge, error) {
	var ch challenge
	if err := c.verifyOwn(d, &ch); err != nil || ch.Kind != "challenge" {
		return ch, fail(400, "not a challenge this core signed")
	}
	return ch, nil
}

// answer: what an approval turns a challenge into — for a machine succeeding itself the new cert at
// once, else an approval that certify() binds to one machine. current: for an add-store, the machine's newest cert
// (the router's copy; refused unless this core signed it and it is the newest), see addOnto.
func (c *Core) answer(ch challenge, by, carry string, current *SignedDoc) (SignedDoc, error) {
	r := ch.Request
	now := c.now().UTC().Format(time.RFC3339)
	if r.AddedStore != "" || r.Downgrade {
		// once per challenge: a saved challenge and signature answered again (or after a downgrade) gets nothing
		if r.Machine == nil || c.isKilled(r.Machine.ID) {
			return SignedDoc{}, fail(409, "the machine is gone")
		}
		if c.approvalsUsed[ch.Nonce] {
			return SignedDoc{}, fail(409, "this challenge was already answered")
		}
		if r.AddedStore != "" {
			// "add store X to this machine": always onto the machine's newest cert, which the caller sends
			var err error
			if r, err = c.addOnto(r, current); err != nil {
				return SignedDoc{}, err
			}
		} else if err := c.isLatest(r.Predecessor); err != nil {
			return SignedDoc{}, err // a downgrade continues exactly the cert its old key signed for
		}
		var pc Cert
		json.Unmarshal([]byte(r.Predecessor.Payload), &pc) // checked above: this core's, the machine's newest
		c.approvalsUsed[ch.Nonce], c.latest[r.Machine.ID] = true, ch.Nonce
		c.passUnlocks(pc.Nonce, ch.Nonce, r.Stores)
		if r.Downgrade {
			if _, ok := c.signing[r.Machine.ID]; ok { // its kill's snapshot is signed with the new key from now on
				c.signing[r.Machine.ID] = r.Machine.SigningKey
			}
		}
		return c.signCert(c.succession(r, r.Machine, ch.Nonce, now), by, carry)
	}
	return c.sign(Approval{Kind: "approval", Nonce: ch.Nonce, Request: r, By: by})
}

// addOnto: an add-store answered onto the machine's newest cert: its stores plus the added one, its keys, its options.
// One rule for every add-store (no fresh/stale branch: Deyao, 2026-10-13, "the core doesn't decide; a call made wrong
// is refused"). The challenge's predecessor is the cert the machine had when the store was asked for (it names the
// machine and line the phone approved); the cert the answer continues is the caller's `current`, taken only when this
// core signed it, it is that machine's newest (the core keeps only the nonce) and on the same line. The phone approved
// "add store X to this running machine"; every store already in the newest cert was approved for this machine before
// (by the phone, or kept by its own old key in a downgrade), so the answer grants nothing the phone didn't, and keeps
// what the newest cert says: a store a downgrade dropped stays dropped, a key pair a downgrade replaced stays replaced.
// Two add-stores filed before either is answered thus both end in the session, whatever order and timing the phone
// answers in (2026-10-13: identity and yyc; the second answer rebuilt the cert from the cert both were filed against,
// and identity's answer was lost). A store the newest cert already holds is no refusal: the answer is a cert with the
// same stores, which reads the add-store's unlock, so the session gets the store as it is now.
func (c *Core) addOnto(r Request, current *SignedDoc) (Request, error) {
	var stale, cur Cert
	if r.Predecessor == nil || c.verifyOwn(r.Predecessor, &stale) != nil || stale.Machine == nil {
		return r, fail(400, "predecessor is not a succession cert this core signed")
	}
	if current == nil {
		return r, fail(400, "an add-store takes the machine's newest cert as current")
	}
	if err := c.verifyOwn(current, &cur); err != nil || cur.Kind != "succession-cert" || cur.Machine == nil {
		return r, fail(400, "current is not a succession cert this core signed")
	}
	if cur.Machine.ID != r.Machine.ID || stale.Machine.ID != r.Machine.ID || cur.Line != stale.Line {
		return r, fail(409, "current is another machine's cert")
	}
	if c.latest[cur.Machine.ID] != cur.Nonce {
		return r, fail(409, "current isn't %s's newest cert", cur.Machine.ID)
	}
	if persistentOptions(cur.Options) != r.Options {
		return r, fail(409, "the machine's options changed since the challenge")
	}
	set := map[string]bool{r.AddedStore: true}
	for _, n := range cur.Stores { // a store it already holds: the same set, and the new cert reads the fresh unlock
		set[n] = true
	}
	stores := make([]string, 0, len(set))
	for n := range set {
		stores = append(stores, n)
	}
	sort.Strings(stores)
	c.logf("add-store %s for %s onto its newest cert %s", r.AddedStore, r.Machine.ID, cur.Nonce[:12])
	r.Predecessor, r.Machine, r.Stores = current, cur.Machine, stores
	return r, nil
}

// ApproveByPhone: the iPhone's Secure Enclave signature over exactly the challenge text. The phone is the
// highest privilege: whatever challenge it signs is answered.
func (c *Core) ApproveByPhone(d *SignedDoc, sig, carry string, current *SignedDoc) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, err := c.readChallenge(d)
	if err != nil {
		return SignedDoc{}, err
	}
	if c.phoneSigning == "" || !VerifyWith(c.phoneSigning, []byte(d.Payload), sig) {
		return SignedDoc{}, fail(403, "the iPhone's signature doesn't cover this challenge")
	}
	r := ch.Request
	c.logf("phone approved %s: %s → %v", ch.Nonce[:12], orNull(r.PredID), r.Stores)
	return c.answer(ch, "phone", carry, current)
}

// ApproveByDeadMachine: automatic — predecessor killed (Fly-confirmed) and never used, and store set, image and
// options identical. Its approval marks the predecessor used when start() makes the machine.
func (c *Core) ApproveByDeadMachine(d *SignedDoc) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, err := c.readChallenge(d)
	if err != nil {
		return SignedDoc{}, err
	}
	r := ch.Request
	if r.AddedStore != "" || r.Downgrade {
		return SignedDoc{}, fail(403, "a machine succeeding itself isn't approved by approve_by_dead_machine")
	}
	if r.PredID == "" || !c.isKilled(r.PredID) || c.used[r.PredID] {
		return SignedDoc{}, fail(403, "predecessor is not a killed, unused machine")
	}
	if r.Image == NullImage {
		c.logf("approve_by_dead_machine: burn of %s", r.PredID)
		return c.answer(ch, "dead-machine", "", nil)
	}
	var pc Cert
	if err := c.verifyOwn(r.Predecessor, &pc); err != nil {
		return SignedDoc{}, err
	}
	if err := c.isLatest(r.Predecessor); err != nil {
		return SignedDoc{}, err
	}
	if !equalStrings(pc.Stores, r.Stores) || persistentOptions(pc.Options) != r.Options || pc.Machine.Image != r.Image {
		return SignedDoc{}, fail(403, "store set, image or options differ from the predecessor's (or a one-time input is asked for)")
	}
	c.logf("approve_by_dead_machine: %s → a new machine", r.PredID)
	return c.answer(ch, "dead-machine", "", nil)
}

// ApproveByOldKey: automatic — a succession of a machine to itself with a subset of its stores and a new key
// pair, answered when it is signed with the signing key named in the predecessor cert (without that, anyone
// could name their own keys and pull the remaining stores). The predecessor cert must be the machine's newest, and
// the new cert supersedes it: the older certs pull and continue nothing (Core.latest).
func (c *Core) ApproveByOldKey(d *SignedDoc, sig, carry string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, err := c.readChallenge(d)
	if err != nil {
		return SignedDoc{}, err
	}
	r := ch.Request
	if !r.Downgrade {
		return SignedDoc{}, fail(400, "not a downgrade")
	}
	var pc Cert
	if err := c.verifyOwn(r.Predecessor, &pc); err != nil || pc.Machine == nil || !VerifyWith(pc.Machine.SigningKey, []byte(d.Payload), sig) {
		return SignedDoc{}, fail(403, "not signed by the key in the predecessor cert")
	}
	c.logf("downgrade: %s keeps %v, new keys", r.Machine.ID, r.Stores)
	return c.answer(ch, "machine", carry, nil)
}

// ---- unlock / lock -------------------------------------------------------------------------------

// UnlockBegin: a one-off key pair for this unlock; the phone computes its share of every key from that key's E (shown
// here, signed, with the store's name, who wrote each key and the sha256 of its data). forNonce: "" = a standing
// unlock (open to every session until locked); else the nonce of the one challenge or cert the unlock is for — only
// that cert's pull reads it, and its pull locks it again (carry.go). The unlock opens exactly the keys named here.
func (c *Core) UnlockBegin(name, forNonce string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if name == DeployKeyTokenStore {
		return SignedDoc{}, fail(403, "%s is opened only by a deploy-key call, never unlocked", DeployKeyTokenStore)
	}
	keys := c.stores[name]
	if len(keys) == 0 || name == FlyStore {
		return SignedDoc{}, fail(404, "no store %s with contents: write a key into it first (jarvis2 put-key)", name)
	}
	if forNonce != "" && !isNonce(forNonce) {
		return SignedDoc{}, fail(400, "for: not a challenge or cert nonce")
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
	c.pending[id] = pendingUnlock{store: name, entries: entries, version: version, t: t, For: forNonce}
	return c.sign(map[string]any{"kind": "unlock-begin", "pending": id, "store": name, "t": b64.EncodeToString(t.PublicKey().Bytes()),
		"for": forNonce, "keys": rows, "version": version})
}

const infoShare = "jarvis2/unlock-share"

// UnlockFinish: the phone's share of every key unlock_begin named, each sealed to T (one try: the one-off key is gone
// either way)
func (c *Core) UnlockFinish(pending string, shares map[string]Sealed) (SignedDoc, error) {
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
	u := c.unlocked[p.store]
	if u == nil {
		u = &unlocked{ids: map[string]unlockHold{}}
		c.unlocked[p.store] = u
	}
	u.values, u.version = vals, p.version // the newest unlock's values for every open id
	id := randID()
	u.ids[id] = unlockHold{since: c.now(), For: p.For}
	if p.For == "" {
		c.logf("store %s unlocked (%s, standing)", p.store, id)
	} else {
		c.logf("store %s unlocked (%s) for %s only", p.store, id, p.For[:12])
	}
	return c.sign(map[string]any{"kind": "unlocked", "id": id, "store": p.store, "for": p.For, "version": p.version})
}

func (c *Core) Lock(id string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireScoped()
	for name, u := range c.unlocked {
		if _, ok := u.ids[id]; ok {
			delete(u.ids, id)
			if len(u.ids) == 0 {
				delete(c.unlocked, name) // plaintext gone with the last id
			}
			c.logf("unlock %s released (%s)", id, name)
			return c.sign(map[string]any{"kind": "locked", "id": id, "store": name})
		}
	}
	// not open (locked already, lapsed, or never): what was asked for holds
	return c.sign(map[string]any{"kind": "locked", "id": id, "already": true})
}

func (c *Core) ListUnlocked(nonce string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireScoped()
	type row struct {
		ID    string `json:"id"`
		Store string `json:"store"`
		Since string `json:"since"`
		For   string `json:"for"` // "" = standing; else the one challenge or cert it is for
	}
	rows := []row{}
	for name, u := range c.unlocked {
		for id, h := range u.ids {
			rows = append(rows, row{id, name, h.since.UTC().Format(time.RFC3339), h.For})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Since < rows[j].Since })
	return c.sign(map[string]any{"kind": "unlocked-list", "nonce": nonce, "unlocked": rows})
}

// ---- pull secrets ---------------------------------------------------------------------------------

// PullSecrets: the answer is sealed to the machine's encryption key from the cert, so only that machine
// can open it and nothing else needs to authenticate the caller. Each store comes from an unlock open to this cert
// (a standing one, or one for this cert's nonce), else from the line's carried secrets (carry.go: the blob this
// core sealed at the machine's or its predecessor's last pull, which the router keeps with the snapshot); neither
// = 423. A pull that goes through locks the unlocks that were for this cert and answers a new carry blob for this
// machine.
func (c *Core) PullSecrets(certDoc *SignedDoc, carry string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireScoped()
	var cert Cert
	if err := c.verifyOwn(certDoc, &cert); err != nil || cert.Kind != "succession-cert" || cert.Machine == nil {
		return SignedDoc{}, fail(400, "not a succession cert this core signed")
	}
	if c.latest[cert.Machine.ID] != cert.Nonce {
		return SignedDoc{}, fail(409, "a superseded cert of %s: only its newest cert pulls (ask the router for the machine's newest cert and pull with that)", cert.Machine.ID)
	}
	carried, carriedVersions := c.openCarryFor(carry, &cert) // nil when absent, not this line's, or not this core's
	perStore := map[string]map[string]string{}
	versions := map[string]string{}
	merged := map[string]string{}
	fromCarry := []string{}
	stale := []string{}
	for _, n := range cert.Stores {
		vals, version, ok := c.openFor(n, cert.Nonce)
		if !ok {
			if vals, ok = carried[n]; ok {
				version = carriedVersions[n]
				fromCarry = append(fromCarry, n)
			}
		}
		if !ok {
			return SignedDoc{}, fail(423, "store %s is locked: the session waits for Deyao's unlock of it (Unlock… in the app, or an Inbox unlock request)", n)
		}
		if version != storeVersion(c.stores[n]) {
			stale = append(stale, n) // a key was written since: only a new unlock (the phone) brings it
		}
		perStore[n], versions[n] = vals, version
		for k, v := range vals {
			merged[k] = v
		}
	}
	plain, _ := json.Marshal(merged)
	sealed, err := SealTo(cert.Machine.EncryptionKey, plain, "jarvis2/secrets")
	if err != nil {
		return SignedDoc{}, err
	}
	next, err := c.sealCarry(&cert, perStore, versions)
	if err != nil {
		return SignedDoc{}, err
	}
	released := c.releaseFor(cert.Nonce)
	c.logf("secrets pulled by %s (%v; carried %v; behind %v; locked again %v)", cert.Machine.ID, cert.Stores, fromCarry, stale, released)
	// stale: the stores whose values are behind the store (keys written since they were unlocked), for the router to
	// ask the phone for a fresh unlock
	return c.sign(map[string]any{"kind": "secrets", "machine": cert.Machine.ID, "sealed": sealed, "carry": next, "stale": stale})
}

// ---- helpers ------------------------------------------------------------------------------------

// isLatest: the predecessor cert a request continues is its machine's newest (nil = a new line). Callers hold c.mu.
func (c *Core) isLatest(pred *SignedDoc) error {
	if pred == nil {
		return nil
	}
	var pc Cert
	if err := c.verifyOwn(pred, &pc); err != nil || pc.Machine == nil {
		return fail(400, "predecessor is not a succession cert this core signed")
	}
	if c.latest[pc.Machine.ID] != pc.Nonce {
		return fail(409, "the predecessor cert isn't %s's newest: an older cert continues nothing", pc.Machine.ID)
	}
	return nil
}

func randID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func orNull(s string) string {
	if s == "" {
		return "null"
	}
	return s
}

var _ = errors.New

// isKilled: Fly confirmed the machine destroyed (callers hold c.mu)
func (c *Core) isKilled(id string) bool {
	_, ok := c.killed[id]
	return ok
}
