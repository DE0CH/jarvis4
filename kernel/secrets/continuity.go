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
//     stores from it; a takeover (blue/green: at most one secrets with these keys serves) takes it whole.

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
	if c.mode == modeStandby {
		return nil, fail(409, "this core is standing by: it keeps no line state of its own yet")
	}
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

// ---- handoff: at most one core with these keys serves (blue/green; Deyao, 2026-10-15) ---------------------------
//
// The router may run a second core and have Deyao Recover it with the same kit while the first still serves. Two
// cores with one identity must never both serve, or an untrusted router could fork a line or answer one approval
// twice. So the cores themselves hand over:
//   - handoff (the serving core, on the router's call): seals a FINAL line state, signs its head, and from then on
//     refuses every call but identity, line-state and handoff again (which answers the same final state);
//   - a Recover whose statement says standby (the master key signed it) serves nothing after its claim until takeover
//     gives it a final state, sealed by these keys, whose seq is at least the one it was Recovered with; it takes that
//     state whole (the lines and every store) and serves;
//   - a Recover whose bundle already carries a final state takes it whole and serves at once (the old core handed off
//     first). A Recover that is neither (a crash: the old core is gone and sealed nothing final) serves at once, from the
//     newest state the router kept: there the guarantee is the old core being gone (docs/DESIGN.md "Core continuity").

const (
	modeServing   = ""
	modeStandby   = "standby"
	modeHandedOff = "handed-off"
)

// Handoff: the final line state; this core serves nothing after it (idempotent: a second call answers the same)
func (c *Secrets) Handoff() (*LineStateDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.mode == modeHandedOff:
		return c.lineDoc, nil
	case c.lineKey == nil || c.MasterKey == "":
		return nil, fail(409, "only a secrets set up from the master key's seed hands off")
	case c.mode != modeServing:
		return nil, fail(409, "this core is standing by: it has nothing to hand off")
	}
	d, err := c.sealLine(true)
	if err != nil {
		return nil, err
	}
	c.mode, c.lineDoc, c.lineHash = modeHandedOff, d, ""
	c.unlocked, c.pending, c.pendingKeys = map[string]*unlocked{}, map[string]pendingUnlock{}, map[string]pendingDeployKey{}
	c.logf("handed off: final line state %d; serving nothing from now on", c.lineSeq)
	return d, nil
}

// Takeover: a standing-by core takes the final state its predecessor sealed (same keys, seq at least the one it was
// Recovered with) and serves
func (c *Secrets) Takeover(d *LineStateDoc) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mode != modeStandby {
		return SignedDoc{}, fail(409, "this core isn't standing by")
	}
	if d == nil {
		return SignedDoc{}, fail(400, "takeover takes the final line state")
	}
	st, err := openLineState(d, &coreKeys{signer: c.signer, state: c.lineKey})
	if err != nil {
		return SignedDoc{}, err
	}
	if !st.Final {
		return SignedDoc{}, fail(403, "not a final line state: the serving core hands off first")
	}
	if st.Seq < c.standbyFrom {
		return SignedDoc{}, fail(403, "the final line state %d is older than the one this core was Recovered with (%d)", st.Seq, c.standbyFrom)
	}
	stores := c.restoreLine(st, true)
	c.mode, c.lineHash, c.lineDoc = modeServing, "", nil
	c.logf("took over at line state %d (%d stores); serving", st.Seq, len(stores))
	return c.sign(map[string]any{"kind": "took-over", "lineSeq": st.Seq, "stores": len(stores)})
}

// allowedIn: what a core that doesn't serve still answers
func allowedIn(mode, pattern string) bool {
	switch pattern {
	case "GET /identity", "GET /line-state", "POST /wipe", "GET /roster", "POST /roster":
		return true
	case "POST /handoff":
		return mode == modeHandedOff
	case "POST /takeover":
		return mode == modeStandby
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

// Mode: serving, standby or handed-off
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
