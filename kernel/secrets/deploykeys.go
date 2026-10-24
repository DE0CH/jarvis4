package secrets

// Deploy keys (Deyao, 2026-10-10): adding a repo in the app's Settings adds an SSH public key to that one repo on
// GitHub as a read/write deploy key, and keeps the private half in a store of its own (`github-<repo>`), which
// sessions include to clone, pull and push that repo — and no other. The app makes the key pair and wraps the
// private half's store to the store key P + K, so secrets never sees it. Removing the repo deletes the deploy key on
// GitHub (by the id GitHub gave it at the add) and the store.
//
// Both are phone-approved, and the box alone can never make a key: the GitHub token that may manage deploy keys lives
// only in the sensitive store `github-deploy-keys` (a fine-grained PAT with Repository "Administration: read and
// write" and nothing else). DeployKeyBegin answers, signed, exactly what will happen (the repo, the store, its
// sensitivity, add or remove, the key id a remove deletes) with the token store's E and a one-off T, as an unlock
// does. The phone shows it, and under one Face ID signs that text and computes its share of the token store;
// DeployKeyFinish checks the signature and opens the token store with the share for this call only (it never joins the
// unlocked set). Secrets never uses the token (DECISIONS 230): it seals it to the minter's agreement key (the root
// key's roster names it) and hands the minter the phone-signed request, drops the plaintext, and takes back the
// minter's signed answer; then it writes or deletes the repo's store. No other store is touched.

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"strings"
	"time"

	"github.com/DE0CH/jarvis4/kernel/minter"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

const (
	// DeployKeyTokenStore: the store whose GitHub token may manage deploy keys; the only store this flow opens
	DeployKeyTokenStore = "github-deploy-keys"
	DeployKeyTokenKey   = "GITHUB_DEPLOY_KEYS_TOKEN"
)

// Minter: where an approved deploy-key call goes (kernel/minter: over HTTP in the cluster, in-process in tests)
type Minter interface {
	Mint(minter.Request) (SignedDoc, error)
}

// Store names can collide (DE0CH/foo-bar and foo/bar both make github-foo-bar). Secrets knows which repo owns a
// deploy-key store (repoOwner) and refuses an add or a remove for another repo with 409, so a second repo never
// silently replaces the first one's key. Re-adding the owning repo (a rotation) still works.

// ownerClash: another repo owns the store (callers hold c.mu)
func (c *Secrets) ownerClash(store, repo string) error {
	if o := c.repoOwner[store]; o != "" && !strings.EqualFold(o, repo) {
		return fail(409, "store %s belongs to %s", store, o)
	}
	return nil
}

type pendingDeployKey struct {
	begin     SignedDoc // the signed begin document: what the phone signs, and what the minter checks
	action    string    // "add" | "remove"
	repo      string
	store     string
	keyID     int64                // remove: the GitHub key it deletes (0: none known, GitHub isn't called)
	orphan    bool                 // remove: only that key goes; the store stays
	keys      map[string]*KeyEntry // add: the store's keys holding the private half, wrapped by the app to the store key
	sensitive bool
	token     KeyEntry // the token key as it was at begin (its E is what the phone answers)
	t         *ecdh.PrivateKey
}

type deployKeyBegin struct {
	Kind      string `json:"kind"` // "deploy-key-begin"
	Pending   string `json:"pending"`
	Action    string `json:"action"`
	Repo      string `json:"repo"`
	Store     string `json:"store"`
	Sensitive bool   `json:"sensitive"`
	Replaces  bool   `json:"replaces"` // add: the store exists and its contents are replaced
	Title     string `json:"title"`    // the deploy key's title on GitHub
	// add: the app's key pair — the public key GitHub gets, and the store's keys holding the private half (each one's
	// name, E and the sha256 of its data), so the phone's signature covers exactly what secrets adds and stores
	PublicKey string          `json:"publicKey,omitempty"`
	Keys      []deployKeyItem `json:"keys,omitempty"`
	// remove: the GitHub key it deletes (the id recorded at the add, or an orphan the router found: Orphan, the store
	// stays); 0 = none known, only the store goes
	KeyID      int64  `json:"keyId,omitempty"`
	Orphan     bool   `json:"orphan,omitempty"`
	TokenStore string `json:"tokenStore"`
	// TokenWriter / TokenDataSha256 / TokenBackupSha256: who wrote the token key, as in unlock_begin (the phone checks it)
	TokenWriter       *EntryWriter `json:"tokenWriter"`
	TokenDataSha256   string       `json:"tokenDataSha256"`
	TokenBackupSha256 string       `json:"tokenBackupSha256"`
	TokenKey          string       `json:"tokenKey"`
	E                 string       `json:"e"`
	T                 string       `json:"t"`
}

type deployKeyItem struct {
	Key        string `json:"key"`
	E          string `json:"e"`
	DataSha256 string `json:"dataSha256"`
}

// DeployKeyRequest: deploy_key_begin's input. The app names the store and the key's title, and for an add brings
// the key pair: PublicKey ("ssh-ed25519 <base64>") and Keys, the store's keys (the private half and the repo) each
// wrapped to the store key; the phone checks the begin document echoes exactly these, and the title, before it signs.
// Sensitivity is what the app asks for (the app itself insists on it for Jarvis's own repos); secrets only keeps an
// existing sensitive store sensitive. KeyID (a remove only): an orphan key the router found on the repo, deleted by
// id; the store stays.
type DeployKeyRequest struct {
	Action    string     `json:"action"`
	Repo      string     `json:"repo"`
	Sensitive bool       `json:"sensitive"`
	Store     string     `json:"store"`
	Title     string     `json:"title"`
	PublicKey string     `json:"publicKey"`
	Keys      []KeyEntry `json:"keys"`
	KeyID     int64      `json:"keyId"`
}

// DeployKeyBegin: a pending add or remove for one repo, signed, with the token store's E and a one-off T
func (c *Secrets) DeployKeyBegin(in DeployKeyRequest) (SignedDoc, error) {
	action, repo, sensitive := in.Action, in.Repo, in.Sensitive
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phoneSigning == "" {
		return SignedDoc{}, fail(409, "secrets isn't set up yet: Reset or Recover it in the app first")
	}
	if action != "add" && action != "remove" {
		return SignedDoc{}, fail(400, "action: add or remove")
	}
	if !minter.RepoOK(repo) {
		return SignedDoc{}, fail(400, "repo: owner/name")
	}
	store := in.Store
	if !storeName(store) || store == DeployKeyTokenStore {
		return SignedDoc{}, fail(400, "store: %q isn't allowed", store)
	}
	keys := map[string]*KeyEntry{}
	for i := range in.Keys {
		x := in.Keys[i]
		if _, seen := keys[x.Key]; seen || !validEntry(&x, store) {
			return SignedDoc{}, fail(400, "bad or repeated key %q for store %s", x.Key, store)
		}
		keys[x.Key] = &x
	}
	if action == "add" && (in.PublicKey == "" || len(keys) == 0 || in.KeyID != 0) {
		return SignedDoc{}, fail(400, "an add brings the key pair: publicKey and the store's keys for %s", store)
	}
	tok := c.stores[DeployKeyTokenStore][DeployKeyTokenKey]
	if tok == nil {
		return SignedDoc{}, fail(404, "no store %s with contents: the setup session writes its GitHub token (%s)", DeployKeyTokenStore, DeployKeyTokenKey)
	}
	if err := c.ownerClash(store, repo); err != nil {
		return SignedDoc{}, err
	}
	old, exists := c.stores[store]
	keyID, orphan := int64(0), false
	if action == "remove" {
		sensitive = exists && !c.notSensitive[store]
		keyID = c.repoKeyID[store]
		if in.KeyID < 0 {
			return SignedDoc{}, fail(400, "keyId: GitHub's id of the key")
		}
		if in.KeyID != 0 && in.KeyID != keyID {
			keyID, orphan = in.KeyID, true
		}
	} else {
		sensitive = sensitive || (exists && !c.notSensitive[store]) // an existing sensitive store stays sensitive
	}
	t, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return SignedDoc{}, err
	}
	id := randID()
	b := deployKeyBegin{Kind: "deploy-key-begin", Pending: id, Action: action, Repo: repo, Store: store, Sensitive: sensitive,
		Replaces: action == "add" && exists && len(old) != 0, Title: in.Title, KeyID: keyID, Orphan: orphan, TokenStore: DeployKeyTokenStore,
		E: tok.Wrapped.E, T: b64.EncodeToString(t.PublicKey().Bytes()), TokenWriter: entryWriter(tok), TokenDataSha256: sha256Hex(tok.Data),
		TokenBackupSha256: tok.BackupSha256, TokenKey: DeployKeyTokenKey}
	if action == "add" {
		b.PublicKey = in.PublicKey
		for _, k := range sortedKeys(keys) {
			b.Keys = append(b.Keys, deployKeyItem{k, keys[k].Wrapped.E, sha256Hex(keys[k].Data)})
		}
	} else {
		keys = nil
	}
	d, err := c.sign(b)
	if err != nil {
		return SignedDoc{}, err
	}
	c.pendingKeys[id] = pendingDeployKey{begin: d, action: action, repo: repo, store: store, keyID: keyID, orphan: orphan,
		keys: keys, sensitive: sensitive, token: *tok, t: t}
	return d, nil
}

// DeployKeyFinish: the phone's signature over the begin document and its share of the token store, sealed to
// T. One try: the pending and its one-off key are gone either way.
func (c *Secrets) DeployKeyFinish(pending string, share Sealed, phoneSig string) (SignedDoc, error) {
	p, sealed, err := c.openDeployKeyToken(pending, share, phoneSig)
	if err != nil {
		return SignedDoc{}, err
	}
	keyID := p.keyID
	if p.action == "add" || keyID != 0 {
		// the minter is called without secrets' lock (GitHub may take seconds); it gets the token sealed to it alone
		m, err := c.mint(p, phoneSig, sealed)
		if err != nil {
			return SignedDoc{}, err
		}
		keyID = m.KeyID
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if p.action == "remove" {
		if p.orphan {
			c.logf("deploy key: orphan key %d of %s deleted on GitHub; store %s kept", keyID, p.repo, p.store)
			return c.sign(map[string]any{"kind": "deploy-key-removed", "pending": pending, "repo": p.repo, "store": p.store, "deleted": 1, "keyId": keyID, "orphan": true})
		}
		delete(c.stores, p.store)
		delete(c.notSensitive, p.store)
		delete(c.unlocked, p.store)
		delete(c.repoOwner, p.store)
		delete(c.repoKeyID, p.store)
		deleted := 0
		if keyID != 0 {
			deleted = 1
		}
		c.logf("deploy key: %s removed (GitHub key %d), store %s deleted", p.repo, keyID, p.store)
		return c.sign(map[string]any{"kind": "deploy-key-removed", "pending": pending, "repo": p.repo, "store": p.store, "deleted": deleted, "keyId": keyID})
	}
	if err := c.ownerClash(p.store, p.repo); err != nil {
		// another repo's add finished first while the minter called GitHub: the key just added is an orphan
		c.logf("deploy key: %s lost %s to %s; GitHub key %d is an orphan", p.repo, p.store, c.repoOwner[p.store], keyID)
		return SignedDoc{}, fail(409, "%v: GitHub key %d on %s is an orphan now (remove it by id)", err, keyID, p.repo)
	}
	_, existed := c.stores[p.store]
	replaced := c.repoKeyID[p.store]
	now := c.now().UTC().Format(time.RFC3339)
	for _, x := range p.keys {
		x.Writer, x.At, x.BackupSha256 = &EntryWriter{By: "core"}, now, "" // stored only after GitHub took the phone-signed key: secrets vouches (no backup)
	}
	c.stores[p.store] = p.keys
	c.repoOwner[p.store], c.repoKeyID[p.store] = p.repo, keyID
	delete(c.unlocked, p.store) // an earlier key's plaintext
	if p.sensitive {
		delete(c.notSensitive, p.store)
	} else if !existed {
		c.notSensitive[p.store] = true
	}
	c.logf("deploy key: %s added (GitHub key %d), store %s (sensitive=%v)", p.repo, keyID, p.store, !c.notSensitive[p.store])
	out := map[string]any{"kind": "deploy-key-added", "pending": pending, "repo": p.repo, "store": p.store,
		"sensitive": !c.notSensitive[p.store], "title": p.title(), "publicKey": p.publicKey(), "keyId": keyID}
	if replaced != 0 && replaced != keyID {
		out["replacedKeyId"] = replaced // the earlier key stays on GitHub until a remove by its id (an orphan)
	}
	return c.sign(out)
}

func (p pendingDeployKey) beginDoc() deployKeyBegin {
	var b deployKeyBegin
	json.Unmarshal([]byte(p.begin.Payload), &b)
	return b
}
func (p pendingDeployKey) title() string     { return p.beginDoc().Title }
func (p pendingDeployKey) publicKey() string { return p.beginDoc().PublicKey }

// mint: the minter's one GitHub call for this approval, its signed answer checked against the roster's minter
func (c *Secrets) mint(p pendingDeployKey, phoneSig string, token Sealed) (minter.Minted, error) {
	var m minter.Minted
	keys, err := c.KeysStatement()
	if err != nil {
		return m, err
	}
	mid, err := c.trust.Member("minter")
	if err != nil {
		return m, fail(503, "the minter: %v", err)
	}
	if c.minter == nil {
		return m, fail(503, "no minter configured (KERNEL_MINTER_URL)")
	}
	d, err := c.minter.Mint(minter.Request{Begin: p.begin, PhoneSig: phoneSig, Keys: keys, Token: sig.Sealed(token)})
	if err != nil {
		c.logf("deploy key: %s %s failed at the minter: %v", p.action, p.repo, err)
		if e, ok := err.(*minter.Error); ok {
			return m, fail(e.Status, "%s", e.Msg)
		}
		return m, fail(502, "the minter: %v", err)
	}
	if !VerifyWith(mid.SigningKey, []byte(d.Payload), d.Sig) || json.Unmarshal([]byte(d.Payload), &m) != nil ||
		m.Kind != "deploy-key-minted" || m.Pending != p.beginDoc().Pending || m.Action != p.action || m.Repo != p.repo || (p.action == "remove" && m.KeyID != p.keyID) || m.KeyID <= 0 {
		return m, fail(502, "the minter's answer isn't the roster's minter's for this request")
	}
	return m, nil
}

// openDeployKeyToken: the pending's checks (the phone signed exactly the begin document) and the token store opened
// with the phone's share — its plaintext only sealed to the minter, for this request
func (c *Secrets) openDeployKeyToken(pending string, share Sealed, phoneSig string) (pendingDeployKey, Sealed, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pendingKeys[pending]
	if !ok {
		return p, Sealed{}, fail(404, "no such pending deploy-key request")
	}
	delete(c.pendingKeys, pending)
	if err := c.ownerClash(p.store, p.repo); err != nil {
		return p, Sealed{}, err
	}
	if c.phoneSigning == "" || !VerifyWith(c.phoneSigning, []byte(p.begin.Payload), phoneSig) {
		return p, Sealed{}, fail(403, "the iPhone's signature doesn't cover this request")
	}
	x, err := OpenSealed(p.t, share, infoShare)
	if err != nil {
		return p, Sealed{}, fail(400, "the share isn't sealed to this request")
	}
	tok, err := c.openEntry(&p.token, x)
	if err != nil {
		return p, Sealed{}, fail(403, "the token key doesn't decrypt: %v", err)
	}
	if tok == "" {
		return p, Sealed{}, fail(400, "the store %s holds no %s", DeployKeyTokenStore, DeployKeyTokenKey)
	}
	if p.action == "remove" && p.keyID == 0 {
		return p, Sealed{}, nil // no GitHub key known: nothing for the minter
	}
	mid, err := c.trust.Member("minter")
	if err != nil {
		return p, Sealed{}, fail(503, "the minter: %v", err)
	}
	sealed, err := SealTo(mid.AgreementKey, []byte(tok), minter.TokenInfo+pending)
	tok = ""
	if err != nil {
		return p, Sealed{}, fail(500, "sealing the token to the minter: %v", err)
	}
	c.logf("deploy key: %s %s approved by the phone; %s opened and sealed to the minter", p.action, p.repo, DeployKeyTokenStore)
	return p, sealed, nil
}
