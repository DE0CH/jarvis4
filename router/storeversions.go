package main

// Each store's earlier versions on a box with no core (NO_CORE=1; DECISIONS 230: the kernel's secrets keeps nothing
// it doesn't need, so no history). The router keeps them in Postgres (store_versions): after every key write secrets
// took, the store's keys as they now are — each entry the router saw written (wrapped to P + K: it reveals nothing),
// secrets' signed key-written receipt for it and the backup object the router wrote for it — and null for a key the
// router never saw written (a Recover's). A restore writes each earlier entry back to secrets with its receipt
// (writer "replay": secrets checks the receipt is its own for exactly that entry and keeps the writer it names), and
// deletes the keys the earlier version didn't have; the put-back keys' backups go back into the bucket first.
//
//	POST /api/core/stores/versions {store, nonce}     the router's list (the app checks each key's receipt)
//	POST /api/core/stores/restore/begin {store, seq}  what putting version seq back changes: put (with receipts),
//	                                                  remove, keep, cannot (keys whose earlier value the router never
//	                                                  saw); pending for 10 minutes
//	POST /api/stores/restore/finish {pending}         the app's Allow: the writes, then sessions holding the store are
//	                                                  asked to refresh
//	POST /setup/stores/versions                       the list for the setup session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	storeVersionsKept = 50
	restorePendingTTL = 10 * time.Minute
)

// verEntry: one key of a version as the router saw it written
type verEntry struct {
	Wrapped      json.RawMessage `json:"wrapped"`
	Data         string          `json:"data"`
	BackupSha256 string          `json:"backupSha256,omitempty"`
	Receipt      *Doc            `json:"receipt"`
	Backup       json.RawMessage `json:"backup,omitempty"` // the bucket's keys/<store>/<key>.json as the router wrote it
}

// keyReceipt: what secrets' key-written receipt says
type keyReceipt struct {
	Kind         string          `json:"kind"`
	Store        string          `json:"store"`
	Key          string          `json:"key"`
	Deleted      bool            `json:"deleted"`
	E            string          `json:"e"`
	DataSha256   string          `json:"dataSha256"`
	BackupSha256 string          `json:"backupSha256"`
	Writer       json.RawMessage `json:"writer"`
	At           string          `json:"at"`
	Version      string          `json:"version"`
}

func (e *verEntry) receipt() keyReceipt {
	var k keyReceipt
	if e != nil && e.Receipt != nil {
		e.Receipt.Decode(&k)
	}
	return k
}

type verCause struct {
	Kind string `json:"kind"` // write | delete | restore
	Key  string `json:"key,omitempty"`
	From int    `json:"from,omitempty"` // restore: the version put back
	// write, delete: who (as secrets' receipt names it, a setup writer without its signature)
	Writer json.RawMessage `json:"writer,omitempty"`
}

type storeVer struct {
	Seq     int
	At      time.Time
	Version string
	Cause   verCause
	Keys    map[string]*verEntry
}

func (r *Router) versionsDB() *DB {
	if r.st == nil || r.st.sdb == nil {
		return nil
	}
	return r.st.sdb.db
}

// storeVersions: a store's kept versions, newest first
func (r *Router) storeVersions(ctx context.Context, store string) ([]storeVer, error) {
	db := r.versionsDB()
	if db == nil {
		return nil, errors.New("no database")
	}
	rows, err := db.pool.Query(ctx, "SELECT seq, at, version, cause, keys FROM store_versions WHERE store = $1 ORDER BY seq DESC", store)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []storeVer{}
	for rows.Next() {
		var v storeVer
		var cause, keys []byte
		if err := rows.Scan(&v.Seq, &v.At, &v.Version, &cause, &keys); err != nil {
			return nil, err
		}
		json.Unmarshal(cause, &v.Cause)
		json.Unmarshal(keys, &v.Keys)
		if v.Keys == nil {
			v.Keys = map[string]*verEntry{}
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// addVersion: the next version of a store; the oldest beyond storeVersionsKept go
func (r *Router) addVersion(ctx context.Context, store, version string, cause verCause, keys map[string]*verEntry) (int, error) {
	db := r.versionsDB()
	if db == nil {
		return 0, errors.New("no database")
	}
	cb, _ := json.Marshal(cause)
	kb, _ := json.Marshal(keys)
	seq := 0
	err := pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext('store-versions:' || $1))", store); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "SELECT coalesce(max(seq), 0) + 1 FROM store_versions WHERE store = $1", store).Scan(&seq); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO store_versions (store, seq, version, cause, keys) VALUES ($1, $2, $3, $4, $5)", store, seq, version, cb, kb); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "DELETE FROM store_versions WHERE store = $1 AND seq <= $2", store, seq-storeVersionsKept)
		return err
	})
	return seq, err
}

// secretsStore: one store's row of secrets' signed list (its key names and version)
func (r *Router) secretsStore(store string) (names []string, version string, sensitive, ok bool, err error) {
	d, err := r.storeCore().Call("/stores", map[string]string{"nonce": "versions-" + randID()})
	if err != nil {
		return nil, "", false, false, err
	}
	var list struct {
		Stores []coreStoreRow `json:"stores"`
	}
	if err := d.Decode(&list); err != nil {
		return nil, "", false, false, err
	}
	for _, s := range list.Stores {
		if s.Name == store {
			for _, k := range s.Keys {
				names = append(names, k.Name)
			}
			return names, s.Version, s.Sensitive, true, nil
		}
	}
	return nil, "", false, false, nil
}

// currentKeys: the newest version's keys, for exactly the names the store has now (a name the router never saw
// written is null); and whether that version is the store as it is (else every key counts as unseen)
func currentKeys(latest *storeVer, names []string, version string) map[string]*verEntry {
	keys := map[string]*verEntry{}
	for _, n := range names {
		keys[n] = nil
		if latest != nil && latest.Version == version {
			keys[n] = latest.Keys[n]
		}
	}
	return keys
}

// recordKeyWrite: after secrets took a write on a box with no core, the store's new version (best effort: the write
// stands either way; a version the router missed only makes its keys unseen)
func (r *Router) recordKeyWrite(store, key string, entry *verEntry, receipt *Doc) {
	if r.secretsStores == nil || r.versionsDB() == nil || receipt == nil {
		return
	}
	var rc keyReceipt
	if receipt.Decode(&rc) != nil || rc.Kind != "key-written" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := r.recordVersion(ctx, store, key, entry, receipt, rc); err != nil {
		log.Printf("store %s: the version after %s wasn't kept: %v", store, key, err)
	}
}

func (r *Router) recordVersion(ctx context.Context, store, key string, entry *verEntry, receipt *Doc, rc keyReceipt) error {
	names, _, _, _, err := r.secretsStore(store)
	if err != nil {
		return err
	}
	vs, err := r.storeVersions(ctx, store)
	if err != nil {
		return err
	}
	// the version before this write: the newest kept one, if this write is the only change since (else unseen keys)
	var latest *storeVer
	if len(vs) > 0 {
		latest = &vs[0]
	}
	keys := map[string]*verEntry{}
	for _, n := range names {
		if latest != nil {
			keys[n] = latest.Keys[n]
		} else {
			keys[n] = nil
		}
	}
	cause := verCause{Kind: "write", Key: key, Writer: stripSig(rc.Writer)}
	if rc.Deleted {
		delete(keys, key)
		cause.Kind = "delete"
	} else {
		if entry != nil {
			entry.Receipt = receipt
		}
		keys[key] = entry
	}
	_, err = r.addVersion(ctx, store, rc.Version, cause, keys)
	return err
}

// stripSig: a writer without a setup signature (the list doesn't carry signatures; each key's receipt does)
func stripSig(w json.RawMessage) json.RawMessage {
	var m map[string]any
	if json.Unmarshal(w, &m) != nil {
		return nil
	}
	delete(m, "sig")
	b, _ := json.Marshal(m)
	return b
}

// ---- the list, a restore's plan and the restore itself ---------------------------------------------------------

type verKeyRow struct {
	Name         string          `json:"name"`
	E            string          `json:"e"`
	DataSha256   string          `json:"dataSha256"`
	BackupSha256 string          `json:"backupSha256,omitempty"`
	At           string          `json:"at,omitempty"`
	Writer       json.RawMessage `json:"writer,omitempty"`
	Receipt      *Doc            `json:"receipt,omitempty"` // secrets' signed receipt (null: a key the router never saw written)
}

func keyRows(keys map[string]*verEntry) []verKeyRow {
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	out := []verKeyRow{}
	for _, k := range names {
		e := keys[k]
		rc := e.receipt()
		row := verKeyRow{Name: k, E: rc.E, DataSha256: rc.DataSha256, BackupSha256: rc.BackupSha256, At: rc.At, Writer: rc.Writer}
		if e != nil {
			row.Receipt = e.Receipt
		}
		out = append(out, row)
	}
	return out
}

// KernelStoreVersions: the router's list of a store's versions (StoreVersionsDoc's shape, unsigned: each key's receipt
// is secrets')
func (r *Router) KernelStoreVersions(store, nonce string) (map[string]any, error) {
	_, version, sensitive, ok, err := r.secretsStore(store)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &CoreError{Status: 404, Msg: "no store " + store}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	vs, err := r.storeVersions(ctx, store)
	if err != nil {
		return nil, err
	}
	rows := []map[string]any{}
	for _, v := range vs {
		rows = append(rows, map[string]any{"seq": v.Seq, "at": v.At.UTC().Format(time.RFC3339), "version": v.Version, "cause": v.Cause, "keys": keyRows(v.Keys)})
	}
	return map[string]any{"kind": "store-versions", "nonce": nonce, "store": store, "current": version, "sensitive": sensitive, "versions": rows}, nil
}

type restorePlan struct {
	Store   string
	From    int // the newest kept version (0: none)
	To      storeVer
	Current string // the store's version at begin
	Put     []string
	Remove  []string
	Expires time.Time
}

var (
	restoreMu      sync.Mutex
	restorePending = map[string]*restorePlan{}
)

// KernelRestoreBegin: what putting version seq back changes (RestoreBegin's shape, unsigned; "replay": true)
func (r *Router) KernelRestoreBegin(store string, seq int) (map[string]any, error) {
	names, version, sensitive, ok, err := r.secretsStore(store)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &CoreError{Status: 404, Msg: "no store " + store}
	}
	if isRepoStore(r, store) {
		return nil, &forbidden{fmt.Sprintf("store %s holds a repo's deploy key: a repo's key is made again, not restored", store)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	vs, err := r.storeVersions(ctx, store)
	if err != nil {
		return nil, err
	}
	var to *storeVer
	for i := range vs {
		if vs[i].Seq == seq {
			to = &vs[i]
		}
	}
	if to == nil {
		return nil, &CoreError{Status: 404, Msg: fmt.Sprintf("store %s keeps no version %d", store, seq)}
	}
	var latest *storeVer
	if len(vs) > 0 {
		latest = &vs[0]
	}
	cur := currentKeys(latest, names, version)
	put, remove, keep, cannot := []map[string]any{}, []string{}, []string{}, []string{}
	putNames := []string{}
	for _, row := range keyRows(to.Keys) {
		k, want := row.Name, to.Keys[row.Name]
		have, present := cur[k]
		switch {
		case want == nil && present && have == nil:
			keep = append(keep, k) // never seen written, still there
		case want == nil:
			cannot = append(cannot, k) // its value then is one the router never saw
		case present && have != nil && have.receipt().E == want.receipt().E && have.receipt().DataSha256 == want.receipt().DataSha256:
			keep = append(keep, k)
		default:
			put = append(put, map[string]any{"key": k, "e": row.E, "dataSha256": row.DataSha256, "backupSha256": row.BackupSha256, "at": row.At,
				"writer": row.Writer, "receipt": row.Receipt})
			putNames = append(putNames, k)
		}
	}
	for _, k := range sortedNames(cur) {
		if _, ok := to.Keys[k]; !ok {
			remove = append(remove, k)
		}
	}
	if len(putNames) == 0 && len(remove) == 0 {
		return nil, &CoreError{Status: 409, Msg: fmt.Sprintf("store %s already is version %d (as far as the router saw it written)", store, seq)}
	}
	from := 0
	if latest != nil {
		from = latest.Seq
	}
	id := randID()
	restoreMu.Lock()
	for p, x := range restorePending {
		if time.Now().After(x.Expires) {
			delete(restorePending, p)
		}
	}
	restorePending[id] = &restorePlan{Store: store, From: from, To: *to, Current: version, Put: putNames, Remove: remove, Expires: time.Now().Add(restorePendingTTL)}
	restoreMu.Unlock()
	return map[string]any{"kind": "store-restore-begin", "pending": id, "store": store, "sensitive": sensitive, "replay": true,
		"from": map[string]any{"seq": from, "version": version},
		"to":   map[string]any{"seq": to.Seq, "version": to.Version, "at": to.At.UTC().Format(time.RFC3339)},
		"put":  put, "remove": remove, "keep": keep, "cannot": cannot, "t": ""}, nil
}

func sortedNames(m map[string]*verEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isRepoStore: a repo's deploy-key store (its keys come only from a phone-approved deploy-key call)
func isRepoStore(r *Router, store string) bool {
	for _, e := range r.Repos() {
		if e.Store == store {
			return true
		}
	}
	return false
}

// KernelRestoreFinish: the plan applied — each backup back into the bucket, then each entry replayed (or deleted) in
// secrets, if the store is still exactly as the plan saw it; one new version
func (r *Router) KernelRestoreFinish(pending string) (map[string]any, error) {
	restoreMu.Lock()
	p := restorePending[pending]
	delete(restorePending, pending)
	restoreMu.Unlock()
	if p == nil || time.Now().After(p.Expires) {
		return nil, &CoreError{Status: 404, Msg: "no such pending restore"}
	}
	names, version, _, ok, err := r.secretsStore(p.Store)
	if err != nil {
		return nil, err
	}
	if !ok || version != p.Current {
		return nil, &CoreError{Status: 409, Msg: fmt.Sprintf("store %s changed since this restore was asked for: review it again", p.Store)}
	}
	b := backupBucketFromEnv()
	if b == nil {
		return nil, errors.New("the router has no backup credential (BACKUP_READ_ACCESS_KEY): nothing is restored without its backups")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	vs, err := r.storeVersions(ctx, p.Store)
	if err != nil {
		return nil, err
	}
	var latest *storeVer
	if len(vs) > 0 {
		latest = &vs[0]
	}
	keys := currentKeys(latest, names, version)
	sc := r.storeCore()
	// the backups first: no key changes in secrets before its backup is in the bucket (each key put back gets the very
	// backup object written with it, which the app's Recover checks as it did then). A key the restore removes keeps
	// its last backup: a delete marker would need a writer the app's backup check takes, and secrets' receipt isn't one
	// (CoreSetup.checkKeyBackup), so a Recover from the bucket alone brings such a key back.
	for _, k := range p.Put {
		e := p.To.Keys[k]
		if len(e.Backup) != 0 {
			if err := b.put("keys/"+p.Store+"/"+k+".json", e.Backup); err != nil {
				return nil, fmt.Errorf("the backups weren't written, so nothing was restored: %v", err)
			}
		}
	}
	last := version
	for _, k := range p.Put {
		e := p.To.Keys[k]
		rc := e.receipt()
		d, err := sc.Call("/stores/write-key", map[string]any{"store": p.Store, "key": k, "wrapped": e.Wrapped, "data": e.Data,
			"backupSha256": rc.BackupSha256, "writer": "replay", "receipt": e.Receipt})
		if err != nil {
			return nil, fmt.Errorf("putting %s back: %w", k, err)
		}
		var nr keyReceipt
		d.Decode(&nr)
		last = nr.Version
		keys[k] = &verEntry{Wrapped: e.Wrapped, Data: e.Data, BackupSha256: e.BackupSha256, Receipt: d, Backup: e.Backup}
	}
	for _, k := range p.Remove {
		d, err := sc.Call("/stores/write-key", map[string]any{"store": p.Store, "key": k, "delete": true, "writer": "replay"})
		if err != nil {
			return nil, fmt.Errorf("removing %s: %w", k, err)
		}
		var nr keyReceipt
		d.Decode(&nr)
		last = nr.Version
		delete(keys, k)
	}
	seq, err := r.addVersion(ctx, p.Store, last, verCause{Kind: "restore", From: p.To.Seq}, keys)
	if err != nil {
		log.Printf("store %s: the restored version wasn't kept: %v", p.Store, err)
	}
	log.Printf("store %s: version %d put back as version %d (%d keys back, %d removed)", p.Store, p.To.Seq, seq, len(p.Put), len(p.Remove))
	r.dropRequests(func(q *InboxRequest) bool { return q.Kind == requestKindRestore && q.Params.Store == p.Store }, outcomeApproved, nil)
	asked := r.refreshHolders(p.Store, fmt.Sprintf("Store %s was restored to its version %d. Unlock gives these sessions the store as it is now.", p.Store, p.To.Seq))
	return map[string]any{"ok": true, "restored": map[string]any{"kind": "store-restored", "pending": pending, "store": p.Store,
		"from": p.To.Seq, "seq": seq, "version": last}, "refreshAsked": asked}, nil
}
