package secrets

// Continuity, carried over from core/continuity.go for secrets alone:
//
//  1. Secrets' long-lived keys come from the master key: the app derives a 32-byte seed (its own label,
//     SecretsSeed, so these keys are never the old core's) and sends it in the claim bundle; from it secrets derives its
//     signing key, its store share K and the state key (DeriveCoreKeys). Every Recover with the same kit
//     brings back the same secrets, and the store key P + K stays the same.
//  2. The state: the stores as secrets holds them (each key wrapped to P + K), the deploy-key stores' repos and GitHub
//     key ids (they have no backup) and the stores that aren't sensitive, sealed under the state key and signed with a head {seq,
//     sha256}; every answer carries X-Line-Seq and the router keeps the newest. A Recover takes back the deploy-key
//     stores from it; the other kernel copy's secrets takes it whole in the copy flip (below: at most one secrets with
//     these keys serves).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/DE0CH/jarvis4/kernel/minter"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

const (
	coreKeyInfo   = "jarvis2/kernel-secrets/" // + signing | agreement | line-state (the app derives the seed: KernelContinuity.seed)
	lineStateAAD  = "jarvis2/kernel-secrets-state"
	lineSeqHeader = "X-Line-Seq"
)

// coreKeys: what DeriveCoreKeys makes
type coreKeys struct {
	signer    *Signer
	agreement *ecdh.PrivateKey
	state     []byte
}

// deriveScalar: a valid P-256 scalar for the label — the first of label, label/1, label/2, … that is one (the first
// is, but for a chance of about 2^-32)
func deriveScalar(seed []byte, label string) ([]byte, error) {
	for i := 0; i < 16; i++ {
		info := coreKeyInfo + label
		if i > 0 {
			info += "/" + strconv.Itoa(i)
		}
		d, err := hkdf.Key(sha256.New, seed, nil, info, 32)
		if err != nil {
			return nil, err
		}
		if _, err := ecdh.P256().NewPrivateKey(d); err == nil {
			return d, nil
		}
	}
	return nil, fmt.Errorf("no valid scalar for %s", label)
}

// DeriveCoreKeys: the core's keys from the seed (the app derives the same public keys: CoreCrypto.swift)
func DeriveCoreKeys(seed []byte) (*coreKeys, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("the seed is 32 bytes")
	}
	sd, err := deriveScalar(seed, "signing")
	if err != nil {
		return nil, err
	}
	sk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), sd)
	if err != nil {
		return nil, err
	}
	ad, err := deriveScalar(seed, "agreement")
	if err != nil {
		return nil, err
	}
	ak, err := ecdh.P256().NewPrivateKey(ad)
	if err != nil {
		return nil, err
	}
	st, err := hkdf.Key(sha256.New, seed, nil, coreKeyInfo+"line-state", 32)
	if err != nil {
		return nil, err
	}
	return &coreKeys{signer: &Signer{sk}, agreement: ak, state: st}, nil
}

// ---- the line state ------------------------------------------------------------------------------------------

// lineState: everything about lines (and the stores, wrapped to P + K as the core holds them) the core must not forget
// across a Recover or a handoff
type lineState struct {
	Seq          int                             `json:"seq"`
	Final        bool                            `json:"final,omitempty"` // a handoff's
	Phone        string                          `json:"phone"`
	Stores       map[string]map[string]*KeyEntry `json:"stores"`
	RepoOwner    map[string]string               `json:"repoOwner"`
	RepoKeyID    map[string]int64                `json:"repoKeyId,omitempty"` // a deploy-key store's GitHub key id
	NotSensitive []string                        `json:"notSensitive"`
	// a handoff's final state only: the open unlocks, so a blue/green flip keeps them (they never end by themselves)
	Unlocked map[string]*carriedUnlock `json:"unlocked,omitempty"`
}

type carriedUnlock struct {
	Values  map[string]string    `json:"values"`
	Version string               `json:"version"`
	IDs     map[string]time.Time `json:"ids"`
}

// LineStateDoc: the sealed state and the core's signed head over it (what the router keeps and the app hands back)
type LineStateDoc struct {
	Head   SignedDoc `json:"head"`
	Sealed string    `json:"sealed"` // base64(nonce ‖ AES-GCM ciphertext)
}

type lineHead struct {
	Kind   string `json:"kind"` // "line-state-head"
	Seq    int    `json:"seq"`
	Final  bool   `json:"final,omitempty"`
	Sha256 string `json:"sha256"` // of the sealed bytes (base64-decoded)
	At     string `json:"at"`
}

func setList(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// lineSnapshot: the current state with seq 0 (callers hold c.mu)
func (c *Secrets) lineSnapshot() lineState {
	return lineState{Phone: c.phoneAgreement, Stores: c.stores, RepoOwner: c.repoOwner, RepoKeyID: c.repoKeyID, NotSensitive: setList(c.notSensitive)}
}

// syncLine: after every call — when the line state changed, the next seq, sealed and signed (a serving core with
// derived keys only; callers don't hold c.mu)
func (c *Secrets) syncLine() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lineKey == nil || c.mode != modeServing {
		return
	}
	plain, err := json.Marshal(c.lineSnapshot())
	if err != nil {
		return
	}
	sum := sha256.Sum256(plain)
	h := hex.EncodeToString(sum[:])
	if h == c.lineHash && c.lineDoc != nil {
		return
	}
	if d, err := c.sealLine(false); err == nil {
		c.lineHash, c.lineDoc = h, d
	}
}

// sealLine: the state as it is now, numbered on (callers hold c.mu)
func (c *Secrets) sealLine(final bool) (*LineStateDoc, error) {
	st := c.lineSnapshot()
	st.Seq, st.Final = c.lineSeq+1, final
	if final {
		st.Unlocked = map[string]*carriedUnlock{}
		for n, u := range c.unlocked {
			st.Unlocked[n] = &carriedUnlock{u.values, u.version, u.ids}
		}
	}
	full, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	sealed, err := gcmSealRandom(c.lineKey, full, []byte(lineStateAAD))
	if err != nil {
		return nil, err
	}
	ss := sha256.Sum256(sealed)
	head, err := c.sign(lineHead{Kind: "line-state-head", Seq: st.Seq, Final: final, Sha256: hex.EncodeToString(ss[:]), At: c.now().UTC().Format(time.RFC3339)})
	if err != nil {
		return nil, err
	}
	c.lineSeq = st.Seq
	return &LineStateDoc{Head: head, Sealed: b64.EncodeToString(sealed)}, nil
}

// LineState: the newest sealed line state (404 on a core without derived keys)
func (c *Secrets) LineState() (*LineStateDoc, error) {
	c.syncLine()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lineDoc == nil {
		return nil, fail(404, "this core keeps no line state (it wasn't set up with a seed)")
	}
	return c.lineDoc, nil
}

// LineSeq: the seq of the newest line state (0: none)
func (c *Secrets) LineSeq() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lineSeq
}

// openLineState: a line state this core's keys made (callers hold c.mu; keys = the derived keys about to be taken)
func openLineState(d *LineStateDoc, k *coreKeys) (lineState, error) {
	var st lineState
	var h lineHead
	if !VerifyWith(k.signer.PublicKey(), []byte(d.Head.Payload), d.Head.Sig) || json.Unmarshal([]byte(d.Head.Payload), &h) != nil || h.Kind != "line-state-head" {
		return st, fail(403, "the line state isn't this core's (its head isn't signed by the derived key)")
	}
	sealed, err := b64.DecodeString(d.Sealed)
	if err != nil {
		return st, fail(400, "line state: not base64")
	}
	ss := sha256.Sum256(sealed)
	if hex.EncodeToString(ss[:]) != h.Sha256 {
		return st, fail(403, "the line state isn't the one its head names")
	}
	plain, err := gcmOpenRandom(k.state, sealed, []byte(lineStateAAD))
	if err != nil {
		return st, fail(403, "the line state doesn't open with the derived key")
	}
	if json.Unmarshal(plain, &st) != nil || st.Seq != h.Seq {
		return st, fail(400, "bad line state")
	}
	return st, nil
}

// restoreLine: a line state taken back (callers hold c.mu; the claim already took the stores from the bundle). all =
// a final state (a handoff): its stores replace the bundle's, as they are newer; otherwise only a deploy-key store the
// bundle didn't bring comes back. Stores come back only when they are wrapped for the phone of this claim.
func (c *Secrets) restoreLine(st lineState, all bool) []string {
	c.lineSeq = st.Seq
	back := []string{}
	if st.Phone == "" || st.Phone != c.phoneAgreement {
		return back
	}
	ns := map[string]bool{}
	for _, n := range st.NotSensitive {
		ns[n] = true
	}
	valid := func(s string, keys map[string]*KeyEntry) bool {
		if !storeName(s) {
			return false
		}
		for k, x := range keys {
			if x == nil || x.Key != k || !validEntry(x, s) {
				return false
			}
		}
		return true
	}
	if all {
		stores := map[string]map[string]*KeyEntry{}
		owners := map[string]string{}
		ids := map[string]int64{}
		notSensitive := map[string]bool{}
		for s, keys := range st.Stores {
			if !valid(s, keys) {
				continue
			}
			if keys == nil {
				keys = map[string]*KeyEntry{}
			}
			stores[s] = keys
			if repo := st.RepoOwner[s]; repo != "" && minter.RepoOK(repo) {
				owners[s] = repo
				if id := st.RepoKeyID[s]; id > 0 {
					ids[s] = id
				}
			}
			if ns[s] {
				notSensitive[s] = true
			}
			back = append(back, s)
		}
		c.stores, c.repoOwner, c.repoKeyID, c.notSensitive = stores, owners, ids, notSensitive
		c.unlocked = map[string]*unlocked{}
		for n, u := range st.Unlocked {
			if _, ok := c.stores[n]; ok && u != nil && len(u.IDs) > 0 {
				c.unlocked[n] = &unlocked{values: u.Values, version: u.Version, ids: u.IDs}
			}
		}
		sort.Strings(back)
		return back
	}
	for s, repo := range st.RepoOwner {
		keys := st.Stores[s]
		if _, have := c.stores[s]; have || len(keys) == 0 || !minter.RepoOK(repo) || !valid(s, keys) {
			continue
		}
		c.stores[s], c.repoOwner[s] = keys, repo
		if id := st.RepoKeyID[s]; id > 0 {
			c.repoKeyID[s] = id
		}
		if ns[s] {
			c.notSensitive[s] = true
		}
		back = append(back, s)
	}
	sort.Strings(back)
	return back
}

// ---- the copy flip: at most one secrets with these keys serves (docs/PLAN-cluster.md "Releases: the copy flip") ---
//
// Both kernel copies' rosters name the same secrets (the keys the kit derives). A release lands on the copy that
// doesn't serve, whose secrets starts empty with boot keys of its own; that copy's roster names them as secretsBoot.
// Once the root key signed it, the router asks the serving secrets to hand over:
//   - handoff (the serving secrets): the other copy's root-signed roster, naming this secrets as its secrets and
//     an empty one as secretsBoot → the seed, the claim's keys (master, phone, root) and a FINAL line state (the open
//     unlocks included), sealed to secretsBoot's agreement key and signed with the derived key; from then on it
//     refuses every call but identity, roster, line-state and the same handoff again;
//   - takeover (the empty secrets of the other copy): a handoff for exactly the roster it holds, sealed to its boot
//     key and signed by the secrets that roster names → it derives the keys from the seed (they must be the ones the
//     roster names), takes the final state whole and serves. The same handoff again answers the same; any other, or
//     a secrets already set up, is refused.
// A crash (the serving secrets restarted, its memory gone) is a Recover with the kit, from the newest state the router
// kept: there the guarantee is the old secrets being gone (docs/DESIGN.md "Core continuity").

const (
	modeServing   = ""
	modeHandedOff = "handed-off"
	infoHandoff   = "jarvis2/kernel-handoff/secrets" // internal/serve HandoffInfo + "secrets"
)

// handoffDoc: the signed handoff (internal/serve Handoff's shape, role "secrets")
type handoffDoc struct {
	Kind   string  `json:"kind"`
	Role   string  `json:"role"`
	From   string  `json:"from"`
	Roster string  `json:"roster"`
	To     string  `json:"to"`
	Sealed *Sealed `json:"sealed,omitempty"`
}

// handedSecrets: what is sealed to the successor
type handedSecrets struct {
	Seed      string        `json:"seed"`
	Master    string        `json:"master"`
	Root      string        `json:"root"`
	Phone     PublicKeys    `json:"phone"`
	LineState *LineStateDoc `json:"lineState"`
}

// PublicKeys: a signing and an agreement key
type PublicKeys struct {
	SigningKey   string `json:"signingKey"`
	AgreementKey string `json:"agreementKey"`
}

// Handoff: to the other copy's secrets, as its root-signed roster names it; this secrets serves nothing after it
// (again for the same roster: the same handoff)
func (c *Secrets) Handoff(roster SignedDoc) (SignedDoc, error) {
	self := c.componentIdentity()
	own := c.trust.Roster()
	c.mu.Lock()
	defer c.mu.Unlock()
	id := roster.ID()
	switch {
	case c.mode == modeHandedOff && c.handedTo == id:
		return *c.handoff, nil
	case c.mode == modeHandedOff:
		return SignedDoc{}, fail(409, "this secrets already handed over to another roster: a final state goes to one roster only")
	case c.lineKey == nil || c.MasterKey == "" || c.seed == nil:
		return SignedDoc{}, fail(409, "only a secrets set up from the kit's seed hands over")
	case own == nil:
		return SignedDoc{}, fail(503, "%v", sig.ErrNoRoster)
	}
	r, err := sig.OpenRoster(roster, c.trust.Root())
	if err != nil {
		return SignedDoc{}, fail(403, "%v", err)
	}
	if r.Copy == own.Copy {
		return SignedDoc{}, fail(409, "a handoff goes to the other kernel copy (this is %s's secrets)", own.Copy)
	}
	if m, ok := r.Member("secrets"); !ok || m != self || r.SecretsBoot == nil {
		return SignedDoc{}, fail(403, "the %s roster doesn't name this secrets as its secrets and an empty one to take over", r.Copy)
	}
	final, err := c.sealLine(true)
	if err != nil {
		return SignedDoc{}, err
	}
	plain, _ := json.Marshal(handedSecrets{Seed: b64.EncodeToString(c.seed), Master: c.MasterKey, Root: c.root,
		Phone: PublicKeys{c.phoneSigning, c.phoneAgreement}, LineState: final})
	sealed, err := SealTo(r.SecretsBoot.AgreementKey, plain, infoHandoff)
	if err != nil {
		return SignedDoc{}, err
	}
	d, err := c.sign(handoffDoc{Kind: "handoff", Role: "secrets", From: own.Copy, Roster: id, To: r.SecretsBoot.AgreementKey, Sealed: &sealed})
	if err != nil {
		return SignedDoc{}, err
	}
	c.mode, c.handedTo, c.handoff, c.lineDoc, c.lineHash = modeHandedOff, id, &d, final, ""
	c.unlocked, c.pending, c.pendingKeys = map[string]*unlocked{}, map[string]pendingUnlock{}, map[string]pendingDeployKey{}
	c.logf("handed over to the %s copy: final line state %d; serving nothing from now on", r.Copy, c.lineSeq)
	return d, nil
}

// Takeover: an empty secrets takes its predecessor's handoff (for the roster it holds, sealed to its boot key, signed
// by the secrets that roster names) and serves with the keys the seed derives
func (c *Secrets) Takeover(d SignedDoc) (SignedDoc, error) {
	held := c.trust.Doc()
	r := c.trust.Roster()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey != "" {
		if c.took == d.ID() {
			return c.sign(map[string]any{"kind": "took-over", "role": "secrets", "handoff": d.ID(), "lineSeq": c.lineSeq, "again": true})
		}
		return SignedDoc{}, fail(409, "this secrets is set up: it takes no handoff")
	}
	if held == nil || r == nil {
		return SignedDoc{}, fail(503, "%v", sig.ErrNoRoster)
	}
	var h handoffDoc
	if err := sig.StrictJSON([]byte(d.Payload), &h); err != nil || h.Kind != "handoff" || h.Role != "secrets" || h.Sealed == nil {
		return SignedDoc{}, fail(400, "not a secrets handoff")
	}
	boot := PublicKeys{c.signer.PublicKey(), b64.EncodeToString(c.agreement.PublicKey().Bytes())}
	m, _ := r.Member("secrets")
	switch {
	case r.SecretsBoot == nil || r.SecretsBoot.SigningKey != boot.SigningKey || r.SecretsBoot.AgreementKey != boot.AgreementKey:
		return SignedDoc{}, fail(403, "the roster this secrets holds doesn't name it to take over")
	case h.Roster != held.ID():
		return SignedDoc{}, fail(403, "a handoff to another roster than the one this secrets holds")
	case h.To != boot.AgreementKey:
		return SignedDoc{}, fail(403, "a handoff sealed to other keys than this secrets' boot keys")
	case !VerifyWith(m.SigningKey, []byte(d.Payload), d.Sig):
		return SignedDoc{}, fail(403, "the handoff isn't signed by the secrets the roster names")
	}
	plain, err := OpenSealed(c.agreement, *h.Sealed, infoHandoff)
	if err != nil {
		return SignedDoc{}, fail(403, "the handoff doesn't open with this secrets' boot key")
	}
	var hs handedSecrets
	if err := sig.StrictJSON(plain, &hs); err != nil || hs.LineState == nil {
		return SignedDoc{}, fail(400, "the handed state: %v", err)
	}
	seed, err := b64.DecodeString(hs.Seed)
	if err != nil || len(seed) != 32 {
		return SignedDoc{}, fail(400, "the handed seed")
	}
	dk, err := DeriveCoreKeys(seed)
	if err != nil {
		return SignedDoc{}, fail(400, "the handed seed: %v", err)
	}
	if dk.signer.PublicKey() != m.SigningKey || b64.EncodeToString(dk.agreement.PublicKey().Bytes()) != m.AgreementKey {
		return SignedDoc{}, fail(403, "the handed seed derives other keys than the roster's secrets")
	}
	st, err := openLineState(hs.LineState, dk)
	if err != nil {
		return SignedDoc{}, err
	}
	if !st.Final {
		return SignedDoc{}, fail(403, "not a final line state")
	}
	c.MasterKey, c.root, c.phoneSigning, c.phoneAgreement = hs.Master, hs.Root, hs.Phone.SigningKey, hs.Phone.AgreementKey
	c.signer, c.agreement, c.lineKey, c.seed = dk.signer, dk.agreement, dk.state, seed
	stores := c.restoreLine(st, true)
	c.mode, c.lineHash, c.lineDoc, c.took = modeServing, "", nil, d.ID()
	c.logf("took over from the %s copy at line state %d (%d stores); serving", h.From, st.Seq, len(stores))
	return c.sign(map[string]any{"kind": "took-over", "role": "secrets", "handoff": d.ID(), "lineSeq": st.Seq, "stores": len(stores)})
}

// allowedIn: what a secrets that handed over still answers
func allowedIn(mode, pattern string) bool {
	switch pattern {
	case "GET /identity", "GET /line-state", "POST /wipe", "GET /roster", "POST /roster", "POST /handoff":
		return true
	}
	return false
}

// ---- AES-GCM with a random nonce in front -----------------------------------------------------------------------

func gcmSealRandom(key, plain, aad []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	n := make([]byte, g.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return g.Seal(n, n, plain, aad), nil
}

func gcmOpenRandom(key, sealed, aad []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize() {
		return nil, fmt.Errorf("short")
	}
	return g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], aad)
}

// Mode: serving ("") or handed-off
func (c *Secrets) Mode() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mode
}

// SeedIdentity: the public keys a seed derives (what a claim with that seed names as its identity)
func SeedIdentity(seed []byte) (signing, agreement string, err error) {
	k, err := DeriveCoreKeys(seed)
	if err != nil {
		return "", "", err
	}
	return k.signer.PublicKey(), b64.EncodeToString(k.agreement.PublicKey().Bytes()), nil
}
