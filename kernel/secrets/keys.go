package secrets

// A store is a set of keys, each sealed on its own (Deyao, 2026-10-13: "writing one key by name is allowed, and it
// doesn't just overwrite the whole key store"). Each key's value is under its own data key (the store's and the key's
// names as associated data, so a value doesn't decrypt under another name), and that data key is wrapped to the
// combined key P + K (phone + core) — the public store key, so anyone can write a key and nobody but the phone and the
// core together can read one. Writing a key replaces that key only; the store's other keys are never read or sent.
//
// write_key is open, like create_store: a write can't reveal a secret, and the router decides who may write (secrets
// checks nothing about who may: DESIGN "Target design"). What secrets records is who wrote each key, which unlock_begin
// shows the phone before it gives its share:
//   - setup: the setup key's signature over WriterText; secrets holds no setup key and passes it on (the phone checks
//     it against keys/setup.pub);
//   - machine: a session machine, named by the grant it holds now and its signature over WriterText with that
//     grant's machine key (checked here);
//   - router: the router (unsigned, named for what it is: the Claude login stores);
//   - core: secrets' own wrapping (a Recover's bundle, a deploy key).
// A write may carry the value sealed to secrets as well (live): secrets uses it only to keep an open unlock of the
// store current, so the key reaches the next pull (D1), and never stores it.

import (
	"crypto/sha256"

	"encoding/hex"
	"github.com/DE0CH/jarvis4/kernel/gv"
	"regexp"
	"sort"
	"strings"
	"time"
)

// routerStoreRE: the stores the router writes (the Claude accounts, router/claudeaccounts.go)
var routerStoreRE = regexp.MustCompile(`^claude(-[a-z0-9]+)*$`)

// reservedStore: names a machine's write never makes (a repo's deploy-key store is made by its deploy-key call)
func reservedStore(name string) bool {
	return name == DeployKeyTokenStore || strings.HasPrefix(name, "github-")
}

// KeyEntry: one key of a store
type KeyEntry struct {
	Store   string     `json:"store"`
	Key     string     `json:"key"`
	Wrapped WrappedKey `json:"wrapped"` // the data key, to phone + core
	Data    string     `json:"data"`    // AES-GCM(value) under the data key, KeyAAD(store, key) as associated data
	// set by the core from the write, never taken from a bundle: who wrote it, when, and the sha256 of its backup (what
	// the writer signed, so the phone can check a setup signature)
	Writer       *EntryWriter `json:"writer,omitempty"`
	At           string       `json:"at,omitempty"`
	BackupSha256 string       `json:"backupSha256,omitempty"`
}

// EntryWriter: who wrote a key (see the file comment)
type EntryWriter struct {
	By      string `json:"by"`                // "setup" | "machine" | "core"
	Sig     string `json:"sig,omitempty"`     // setup: its signature over WriterText (the phone checks it)
	Machine string `json:"machine,omitempty"` // machine: the session machine (the core checked its signature)
}

// KeyAAD: a key's value is bound to its store and its name
func KeyAAD(store, key string) []byte { return []byte(store + "\n" + key) }

// WriterText: what a key's writer signs — the store, the key, its E and the sha256 of its data ("" and "" for a
// delete), and the sha256 of the key's backup ("" when it has none)
func WriterText(store, key, e, data, backupSha256 string) string {
	sum := ""
	if data != "" {
		sum = sha256Hex(data)
	}
	return "jarvis2-store-key\n" + store + "\n" + key + "\n" + e + "\n" + sum + "\n" + backupSha256
}

var keyNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// storeVersion: one store's contents as a hash (each key's name, E and data hash): an unlock and a carried copy are
// "current" while the store's version is the one they were taken at
func storeVersion(keys map[string]*KeyEntry) string {
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, k := range names {
		h.Write([]byte(k + "\t" + keys[k].Wrapped.E + "\t" + sha256Hex(keys[k].Data) + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// validEntry: a key as a writer or a bundle brings it (callers set Writer and At)
func validEntry(x *KeyEntry, store string) bool {
	return x != nil && x.Store == store && keyNameRE.MatchString(x.Key) && x.Wrapped.E != "" && x.Wrapped.Wrapped != "" && x.Data != ""
}

// WriteKeyInput: write_key's input. Delete: the key goes (no wrapped/data). Writer "setup" brings Sig; writer
// "machine" brings Sig and Cert, the machine's newest cert.
type WriteKeyInput struct {
	Store        string     `json:"store"`
	Key          string     `json:"key"`
	Delete       bool       `json:"delete"`
	Wrapped      WrappedKey `json:"wrapped"`
	Data         string     `json:"data"`
	BackupSha256 string     `json:"backupSha256"`
	Writer       string     `json:"writer"`
	Sig          string     `json:"sig"`
	Grant        *gv.Signed `json:"grant"` // writer "machine": the grant the machine holds now
	Live         *Sealed    `json:"live"`  // the value sealed to secrets (infoLive + "\n" + store + "\n" + key)
}

// WriteKey: one key written (or deleted). A writer's first key of a name the core doesn't have makes that store
// (sensitive, as every store create_store didn't make; a new store reaches no session without the phone); a machine
// never writes the deploy-key token store or a repo's deploy-key store (their keys come only from a phone-approved
// deploy-key call), nor makes a github-* store; the router writes only claude-* stores.
// The core's own store is never written. Unlocked plaintext of the store stays as it was until locked (the store's
// version tells it is behind).
func (c *Secrets) WriteKey(in WriteKeyInput) (SignedDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MasterKey == "" {
		return SignedDoc{}, fail(409, "this core isn't set up yet: Reset or Recover it in the app first")
	}
	keys, exists := c.stores[in.Store]
	if !storeName(in.Store) || in.Store == FlyStore {
		return SignedDoc{}, fail(400, "store: %q isn't one a key is written to", in.Store)
	}
	if !keyNameRE.MatchString(in.Key) {
		return SignedDoc{}, fail(400, "key: letters, digits and _, not starting with a digit")
	}
	if in.BackupSha256 != "" && !hex64RE.MatchString(in.BackupSha256) {
		return SignedDoc{}, fail(400, "backupSha256: hex sha256")
	}
	e := ""
	if in.Delete {
		if _, ok := keys[in.Key]; !ok { // (a missing store has no keys)
			return SignedDoc{}, fail(404, "store %s has no key %s", in.Store, in.Key)
		}
		in.Wrapped, in.Data = WrappedKey{}, ""
	} else {
		x := &KeyEntry{Store: in.Store, Key: in.Key, Wrapped: in.Wrapped, Data: in.Data}
		if !validEntry(x, in.Store) {
			return SignedDoc{}, fail(400, "not a sealed key: wrapped {e, wrapped} and data")
		}
		e = in.Wrapped.E
	}
	text := WriterText(in.Store, in.Key, e, in.Data, in.BackupSha256)
	var w EntryWriter
	switch in.Writer {
	case "setup":
		if in.Sig == "" {
			return SignedDoc{}, fail(400, "a setup write carries the setup key's signature")
		}
		w = EntryWriter{By: "setup", Sig: in.Sig}
	case "machine":
		if in.Grant == nil {
			return SignedDoc{}, fail(400, "a machine write carries the grant the machine holds")
		}
		g, err := gv.Open(*in.Grant, c.trust)
		if err != nil || g.Machine.Kind() != "fly" {
			return SignedDoc{}, fail(403, "a machine write's grant: %v", err)
		}
		if !VerifyWith(g.Keys.SigningKey, []byte(text), in.Sig) {
			return SignedDoc{}, fail(403, "not signed by the key of the grant's machine")
		}
		if in.Store == DeployKeyTokenStore || c.repoOwner[in.Store] != "" {
			return SignedDoc{}, fail(403, "store %s's keys come only from a phone-approved deploy-key call", in.Store)
		}
		if !exists && reservedStore(in.Store) {
			return SignedDoc{}, fail(403, "store %s doesn't exist and a session doesn't make it: github-* stores come only from a repo's deploy key (Settings → Repos)", in.Store)
		}
		w = EntryWriter{By: "machine", Machine: g.Machine.FlyID()}
	case "router":
		// the router's own writes: only the Claude account stores, whose pair it refreshes with nobody there (DECISIONS
		// 185, 188). Unsigned: the core can't tell the router from anything else on the box, so the writer is named
		// as what it is, "router", and the phone shows it on every unlock; the router holds the pair in the clear anyway.
		if !routerStoreRE.MatchString(in.Store) {
			return SignedDoc{}, fail(403, "the router writes only the Claude login stores (claude, claude-<name>), not %s", in.Store)
		}
		w = EntryWriter{By: "router"}
	default:
		return SignedDoc{}, fail(400, "writer: setup, machine or router")
	}
	now := c.now().UTC().Format(time.RFC3339)
	before := storeVersion(keys)
	if !exists { // a writer's first key makes the store, sensitive (create_store is the only way to a non-sensitive one)
		keys = map[string]*KeyEntry{}
		c.stores[in.Store] = keys
	}
	if in.Delete {
		delete(keys, in.Key)
	} else {
		keys[in.Key] = &KeyEntry{Store: in.Store, Key: in.Key, Wrapped: in.Wrapped, Data: in.Data, Writer: &w, At: now, BackupSha256: in.BackupSha256}
	}
	c.record(in.Store, VersionCause{Kind: map[bool]string{true: "delete", false: "write"}[in.Delete], Key: in.Key, Writer: &w})
	c.liveUpdate(in.Store, in.Key, in.Delete, in.Live, before)
	c.logf("store %s: key %s %s by %s %s", in.Store, in.Key, map[bool]string{true: "deleted", false: "written"}[in.Delete], w.By, w.Machine)
	sum := ""
	if in.Data != "" {
		sum = sha256Hex(in.Data)
	}
	return c.sign(map[string]any{"kind": "key-written", "store": in.Store, "key": in.Key, "deleted": in.Delete, "e": e,
		"dataSha256": sum, "backupSha256": in.BackupSha256, "writer": w, "at": now,
		"sensitive": !c.notSensitive[in.Store], "version": storeVersion(keys)})
}

// keyRows: a store's keys as the signed store list shows them (names and writers, never values)
type keyRow struct {
	Name   string       `json:"name"`
	At     string       `json:"at"`
	Writer *EntryWriter `json:"writer"`
}

func keyRows(keys map[string]*KeyEntry) []keyRow {
	out := make([]keyRow, 0, len(keys))
	for k, x := range keys {
		w := x.Writer
		if w != nil && w.By == "setup" {
			w = &EntryWriter{By: "setup"} // the list doesn't carry signatures (unlock_begin does)
		}
		out = append(out, keyRow{k, x.At, w})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// openEntry: one key's value, with the phone's share x(p·E) and the core's k
func (c *Secrets) openEntry(x *KeyEntry, phoneShareX []byte) (string, error) {
	dk, err := UnwrapWithShares(x.Wrapped, phoneShareX, c.agreement)
	if err != nil {
		return "", err
	}
	data, _ := b64.DecodeString(x.Data)
	plain, err := gcmOpen(dk, data, KeyAAD(x.Store, x.Key))
	if err != nil {
		return "", fail(403, "key %s of %s doesn't decrypt (a wrong or altered entry)", x.Key, x.Store)
	}
	return string(plain), nil
}

// entryWriter: unlock_begin's writer field for a key ({by, sig} | {by, machine, line} | {by: "core"})
func entryWriter(x *KeyEntry) *EntryWriter {
	if x.Writer == nil {
		return &EntryWriter{By: "core"}
	}
	return x.Writer
}

// copyEntries: a snapshot of a store's keys (an unlock opens exactly what it began with)
func copyEntries(keys map[string]*KeyEntry) map[string]KeyEntry {
	out := make(map[string]KeyEntry, len(keys))
	for k, x := range keys {
		out[k] = *x
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var _ = strings.TrimSpace
