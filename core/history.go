package main

// Earlier versions of each store, and putting one back (Deyao, 2026-10-13: a restore "needs to go through the core and
// be signed, because I don't want to randomly lose my master key"). A store is a set of keys (keys.go), and every
// change to it — a Recover, create_store, a key written or deleted, a deploy key, a restore — makes a new version: the
// store's keys as they then were. The core keeps the last historyMax versions of each store, in memory like
// everything else (the KeyEntry values, which are sealed to P + K, so a version reveals nothing the store didn't).
//
// Restoring store S to version V is phone-approved and never needs the master key's private half:
//
//	restore_begin(S, V)   the signed document of exactly what changes: the version it starts from (the store as it is
//	                      now) and the one it puts back, each key put back (name, E, data hash, writer) and each removed,
//	                      with a one-off T for the phone's shares
//	restore_finish(P, sig, shares)
//	                      the phone's signature over that document and its share of every key put back, sealed to T
//	                      (one Face ID). The core opens each put-back key (proving it intact), seals its value to the
//	                      master PUBLIC key as that key's backup (the same format as a writer's backup), drops the
//	                      plaintext, and answers the backups with a signed receipt naming each one's hash. Nothing in
//	                      the store changes yet.
//	restore_commit(P)     after the router wrote those backups to the bucket (a key never changes in the core before
//	                      its backup exists): the store becomes the version put back, if it is still exactly the version
//	                      the phone saw. The restore is itself a new version, so it can be undone the same way.
//
// The entries put back are the very ones the core held (their writer, time and backup hash unchanged), so an unlock
// shows the phone who wrote each key, as before. Sessions holding the store are behind until a new unlock (the store's
// version moved), exactly as after a write. A new core starts with no history: its first version of each store is
// what the Recover brought; the master-key-sealed bucket backups stay the disaster path.

import (
	"crypto/ecdh"
	"crypto/rand"
	"sort"
	"time"
)

const (
	historyMax = 50               // versions kept per store
	restoreTTL = 10 * time.Minute // a begin, and an approved restore, lapse after this (the Inbox's 10 minutes)
	// infoBackup: what a key's backup is sealed under (to the master key), as every writer seals it
	infoBackup = "jarvis2/backup"
)

// VersionCause: what made a version
type VersionCause struct {
	Kind   string       `json:"kind"` // recover | created | write | delete | deploy-key | restore
	Key    string       `json:"key,omitempty"`
	Writer *EntryWriter `json:"writer,omitempty"` // write, delete: who (a setup writer without its signature)
	From   int          `json:"from,omitempty"`   // restore: the version put back
}

type storeVersionRec struct {
	Seq     int
	At      string
	Version string
	Cause   VersionCause
	Keys    map[string]*KeyEntry // the store's keys then (entries are never changed in place, so sharing is safe)
}

type pendingRestore struct {
	payload  string // the signed begin document: what the phone signs
	store    string
	from     string // the store's version at begin
	fromSeq  int
	to       *storeVersionRec
	put      []string // keys put back (their shares come with finish)
	remove   []string
	t        *ecdh.PrivateKey
	expires  time.Time
	approved bool // finish went through: commit applies it
}

// record: a new version of a store, from its keys as they are now (callers hold c.mu)
func (c *Core) record(store string, cause VersionCause) {
	if c.history == nil {
		c.history = map[string][]*storeVersionRec{}
		c.historySeq = map[string]int{}
	}
	keys := map[string]*KeyEntry{}
	for k, x := range c.stores[store] {
		keys[k] = x
	}
	if w := cause.Writer; w != nil && w.By == "setup" {
		cause.Writer = &EntryWriter{By: "setup"}
	}
	c.historySeq[store]++
	h := append(c.history[store], &storeVersionRec{Seq: c.historySeq[store], At: c.now().UTC().Format(time.RFC3339),
		Version: storeVersion(keys), Cause: cause, Keys: keys})
	if len(h) > historyMax {
		h = append([]*storeVersionRec(nil), h[len(h)-historyMax:]...)
	}
	c.history[store] = h
}

// forget: a store that went (a deploy-key remove) leaves no history
func (c *Core) forget(store string) {
	delete(c.history, store)
	delete(c.historySeq, store)
}

type versionKeyRow struct {
	Name         string       `json:"name"`
	E            string       `json:"e"`
	DataSha256   string       `json:"dataSha256"`
	BackupSha256 string       `json:"backupSha256,omitempty"`
	At           string       `json:"at"`
	Writer       *EntryWriter `json:"writer"`
}

func versionRows(keys map[string]*KeyEntry) []versionKeyRow {
	out := []versionKeyRow{}
	for _, k := range sortedKeys(keys) {
		x := keys[k]
		w := entryWriter(x)
		if w.By == "setup" {
			w = &EntryWriter{By: "setup"} // the list carries no signatures (restore_begin does)
		}
		out = append(out, versionKeyRow{k, x.Wrapped.E, sha256Hex(x.Data), x.BackupSha256, x.At, w})
	}
	return out
}

// Versions: a store's kept versions, newest first, signed (each: its number, when, what made it, its keys' names, Es,
// data hashes and writers — never a value)
func (c *Core) Versions(store, nonce string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey == "" {
		return SignedDoc{}, fail(409, "this core isn't set up yet: Reset or Recover it in the app first")
	}
	if _, ok := c.stores[store]; !ok {
		return SignedDoc{}, fail(404, "no store %s", store)
	}
	type row struct {
		Seq     int             `json:"seq"`
		At      string          `json:"at"`
		Version string          `json:"version"`
		Cause   VersionCause    `json:"cause"`
		Keys    []versionKeyRow `json:"keys"`
	}
	h := c.history[store]
	out := []row{}
	for i := len(h) - 1; i >= 0; i-- {
		out = append(out, row{h[i].Seq, h[i].At, h[i].Version, h[i].Cause, versionRows(h[i].Keys)})
	}
	return c.sign(map[string]any{"kind": "store-versions", "nonce": nonce, "store": store,
		"current": storeVersion(c.stores[store]), "sensitive": !c.notSensitive[store], "versions": out})
}

func (c *Core) expireRestores() {
	now := c.now()
	for id, p := range c.restores {
		if now.After(p.expires) {
			delete(c.restores, id)
		}
	}
}

type restoreKey struct {
	Key          string       `json:"key"`
	E            string       `json:"e"`
	DataSha256   string       `json:"dataSha256"`
	BackupSha256 string       `json:"backupSha256"`
	At           string       `json:"at"`
	Writer       *EntryWriter `json:"writer"` // with a setup writer's signature, which the phone checks (keys/setup.pub)
}

// RestoreBegin: the signed document of putting version seq of a store back. Refused for a store whose keys come only
// from a phone-approved deploy-key call (a repo's: its key on GitHub is gone; make it again), for the core store, for
// a version no longer kept, and when the store already is that version.
func (c *Core) RestoreBegin(store string, seq int) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireRestores()
	if c.MasterKey == "" || c.phoneSigning == "" {
		return SignedDoc{}, fail(409, "this core isn't set up yet: Reset or Recover it in the app first")
	}
	cur, ok := c.stores[store]
	if !ok || store == FlyStore {
		return SignedDoc{}, fail(404, "no store %s", store)
	}
	if c.repoOwner[store] != "" {
		return SignedDoc{}, fail(403, "store %s holds %s's deploy key: a repo's key is made again, not restored", store, c.repoOwner[store])
	}
	var to *storeVersionRec
	for _, v := range c.history[store] {
		if v.Seq == seq {
			to = v
		}
	}
	if to == nil {
		return SignedDoc{}, fail(404, "store %s keeps no version %d", store, seq)
	}
	from := storeVersion(cur)
	if to.Version == from {
		return SignedDoc{}, fail(409, "store %s already is version %d", store, seq)
	}
	put, remove, keep := []restoreKey{}, []string{}, []string{}
	putNames := []string{}
	for _, k := range sortedKeys(to.Keys) {
		x := to.Keys[k]
		if y := cur[k]; y != nil && y.Wrapped.E == x.Wrapped.E && y.Data == x.Data {
			keep = append(keep, k)
			continue
		}
		put = append(put, restoreKey{k, x.Wrapped.E, sha256Hex(x.Data), x.BackupSha256, x.At, entryWriter(x)})
		putNames = append(putNames, k)
	}
	for _, k := range sortedKeys(cur) {
		if to.Keys[k] == nil {
			remove = append(remove, k)
		}
	}
	t, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return SignedDoc{}, err
	}
	fromSeq := 0
	if h := c.history[store]; len(h) != 0 {
		fromSeq = h[len(h)-1].Seq
	}
	id := randID()
	d, err := c.sign(map[string]any{"kind": "store-restore-begin", "pending": id, "store": store, "sensitive": !c.notSensitive[store],
		"from": map[string]any{"seq": fromSeq, "version": from},
		"to":   map[string]any{"seq": to.Seq, "version": to.Version, "at": to.At},
		"put":  put, "remove": remove, "keep": keep, "t": b64.EncodeToString(t.PublicKey().Bytes())})
	if err != nil {
		return SignedDoc{}, err
	}
	if c.restores == nil {
		c.restores = map[string]*pendingRestore{}
	}
	c.restores[id] = &pendingRestore{payload: d.Payload, store: store, from: from, fromSeq: fromSeq, to: to, put: putNames, remove: remove,
		t: t, expires: c.now().Add(restoreTTL)}
	return d, nil
}

// KeyBackup: one key's backup sealed to the master key (what a writer's backup holds), and its hash as WriterText
// names it
type KeyBackup struct {
	E      string `json:"e"`
	Data   string `json:"data"`
	Sha256 string `json:"sha256"`
}

// sealBackup: a value sealed to the master public key under infoBackup with the store's and key's names as associated
// data — the format of every writer's backup (infra/setup.py key_write, rust/machine/src/putkey.rs)
func sealBackup(master, store, key, value string) (KeyBackup, error) {
	rb, err := b64.DecodeString(master)
	if err != nil {
		return KeyBackup{}, err
	}
	r, err := ecdh.P256().NewPublicKey(rb)
	if err != nil {
		return KeyBackup{}, err
	}
	e, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return KeyBackup{}, err
	}
	x, err := e.ECDH(r)
	if err != nil {
		return KeyBackup{}, err
	}
	be := b64.EncodeToString(e.PublicKey().Bytes())
	bd := b64.EncodeToString(gcmSeal(kdf(x, infoBackup), []byte(value), KeyAAD(store, key)))
	return KeyBackup{be, bd, sha256Hex(be + "\n" + bd)}, nil
}

// RestoreFinish: the phone's signature over the begin document and its share of every key put back. The core opens
// each (one try: the shares and T are spent either way), seals its backup to the master key, and answers the backups
// beside a signed receipt (kind "store-restore-approved": the begin document, the phone's signature over it, and each
// key's new backup hash), which the router writes to the bucket before it commits.
func (c *Core) RestoreFinish(pending, sig string, shares map[string]Sealed) (map[string]any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireRestores()
	p := c.restores[pending]
	if p == nil || p.approved {
		return nil, fail(404, "no such pending restore")
	}
	delete(c.restores, pending) // one try
	if !VerifyWith(c.phoneSigning, []byte(p.payload), sig) {
		return nil, fail(403, "the iPhone's signature doesn't cover this restore")
	}
	if storeVersion(c.stores[p.store]) != p.from {
		return nil, fail(409, "store %s changed since this restore was asked for: review it again", p.store)
	}
	if len(shares) != len(p.put) {
		return nil, fail(400, "one share for each of the %d keys put back", len(p.put))
	}
	backups := map[string]KeyBackup{}
	rows := []map[string]string{}
	for _, k := range p.put {
		sh, ok := shares[k]
		if !ok {
			return nil, fail(400, "no share for key %s", k)
		}
		px, err := OpenSealed(p.t, sh, infoShare)
		if err != nil {
			return nil, fail(400, "the share for %s isn't sealed to this restore", k)
		}
		x := *p.to.Keys[k]
		v, err := c.openEntry(&x, px)
		if err != nil {
			return nil, fail(403, "%v", err)
		}
		b, err := sealBackup(c.MasterKey, p.store, k, v)
		v = ""
		if err != nil {
			return nil, fail(500, "the backup of %s: %v", k, err)
		}
		backups[k] = b
		rows = append(rows, map[string]string{"key": k, "e": x.Wrapped.E, "dataSha256": sha256Hex(x.Data), "backupSha256": b.Sha256})
	}
	receipt, err := c.sign(map[string]any{"kind": "store-restore-approved", "pending": pending, "store": p.store,
		"from": p.fromSeq, "to": p.to.Seq, "put": rows, "remove": p.remove, "begin": p.payload, "phoneSig": sig,
		"at": c.now().UTC().Format(time.RFC3339)})
	if err != nil {
		return nil, err
	}
	p.approved, p.t, p.expires = true, nil, c.now().Add(restoreTTL)
	c.restores[pending] = p
	c.logf("store %s: restore to version %d approved by the phone (%d keys back, %d removed); waiting for its backups", p.store, p.to.Seq, len(p.put), len(p.remove))
	return map[string]any{"receipt": receipt, "backups": backups}, nil
}

// RestoreCommit: the approved restore applied — the store becomes the version put back, if it is still exactly the
// version the phone approved it from (a write in between: refused, nothing changes; ask again)
func (c *Core) RestoreCommit(pending string) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireRestores()
	p := c.restores[pending]
	if p == nil || !p.approved {
		return SignedDoc{}, fail(404, "no approved restore %s", pending)
	}
	delete(c.restores, pending)
	if storeVersion(c.stores[p.store]) != p.from {
		return SignedDoc{}, fail(409, "store %s changed since this restore was approved: nothing restored, review it again", p.store)
	}
	keys := map[string]*KeyEntry{}
	for k, x := range p.to.Keys {
		keys[k] = x
	}
	c.stores[p.store] = keys
	c.record(p.store, VersionCause{Kind: "restore", From: p.to.Seq})
	h := c.history[p.store]
	seq := h[len(h)-1].Seq
	c.logf("store %s: version %d put back as version %d", p.store, p.to.Seq, seq)
	names := sortedKeys(keys)
	sort.Strings(names)
	return c.sign(map[string]any{"kind": "store-restored", "pending": pending, "store": p.store, "from": p.to.Seq, "seq": seq,
		"version": storeVersion(keys), "keys": names, "put": p.put, "remove": p.remove})
}
