package main

// Restoring a store to an earlier version (docs/DESIGN.md "Restoring a store"; core/history.go). The core keeps each
// store's last versions; putting one back is the phone's signature over the core's exact begin document plus its
// shares of the keys put back, under one Face ID — no kit, no plaintext outside the core. The router's part:
//
//	POST /api/core/stores/versions {store, nonce}     the core's signed list, relayed (app, web)
//	POST /api/core/stores/restore/begin {store, seq}  the core's signed begin document, relayed (the app's review page)
//	POST /api/stores/restore/finish {pending, signature, shares}
//	    the app, after Face ID: the core checks the phone's signature, opens the keys put back and seals each one's
//	    backup to the master key; the router writes those backups (keys/<store>/<key>.json, writer "restore" with the
//	    core's signed receipt) and only then commits; then every running session holding the store is asked to
//	    refresh, as after a write
//	POST /setup/stores/versions                       the same list for the setup session
//	…/requests/restore {store, seq, explanation}      an Inbox request (web page, app, setup session; never a
//	                                                  session): it opens the app's restore review

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const requestKindRestore = "restore"

// restoreApproved: what the core's finish answers
type restoreApproved struct {
	Receipt *Doc `json:"receipt"`
	Backups map[string]struct {
		E      string `json:"e"`
		Data   string `json:"data"`
		Sha256 string `json:"sha256"`
	} `json:"backups"`
}

type restoreReceipt struct {
	Kind    string `json:"kind"`
	Pending string `json:"pending"`
	Store   string `json:"store"`
	To      int    `json:"to"`
	Put     []struct {
		Key          string `json:"key"`
		E            string `json:"e"`
		DataSha256   string `json:"dataSha256"`
		BackupSha256 string `json:"backupSha256"`
	} `json:"put"`
	Remove []string `json:"remove"`
}

// FinishRestore: the phone's approval through the core, the backups into the bucket, then the commit
func (r *Router) FinishRestore(body []byte) (map[string]any, error) {
	var in struct {
		Pending   string          `json:"pending"`
		Signature string          `json:"signature"`
		Shares    json.RawMessage `json:"shares"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Pending == "" || in.Signature == "" {
		return nil, &badRequest{"pending, signature and shares (the phone's)"}
	}
	b := backupBucketFromEnv()
	if b == nil {
		return nil, errors.New("the router has no backup credential (BACKUP_READ_ACCESS_KEY): nothing is restored without its backups")
	}
	sc := r.storeCore()
	status, raw, err := sc.Raw("POST", "/stores/restore/finish", body)
	if err != nil {
		return nil, fmt.Errorf("%s /stores/restore/finish: %w", sc.who(), err)
	}
	if status != 200 {
		return nil, &CoreError{Status: status, Body: raw, Msg: "core: the restore was refused"}
	}
	var ap restoreApproved
	var rc restoreReceipt
	if json.Unmarshal(raw, &ap) != nil || ap.Receipt == nil || ap.Receipt.Decode(&rc) != nil || rc.Kind != "store-restore-approved" || rc.Pending != in.Pending {
		return nil, errors.New("the core's restore answer isn't readable")
	}
	idStatus, ident, err := sc.Raw("GET", "/identity", nil)
	if err != nil || idStatus != 200 {
		return nil, fmt.Errorf("the core's identity isn't readable: %v", err)
	}
	storeDocsMu.Lock()
	docs := r.readStoreDocs()[rc.Store]
	storeDocsMu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	put := func(key string, obj map[string]any) error {
		obj["kind"], obj["store"], obj["key"], obj["core"], obj["explanation"], obj["at"] = "key-backup", rc.Store, key, json.RawMessage(ident), docs.Keys[key], now
		obj["writer"] = map[string]any{"by": "restore", "receipt": ap.Receipt}
		j, _ := json.Marshal(obj)
		return b.put("keys/"+rc.Store+"/"+key+".json", j)
	}
	// the backups first: the core changes the store only once they are in the bucket
	for _, x := range rc.Put {
		bk, ok := ap.Backups[x.Key]
		if !ok || bk.Sha256 != x.BackupSha256 || backupSha(bk.E, bk.Data) != x.BackupSha256 {
			return nil, fmt.Errorf("the core's backup of %s doesn't match its receipt: nothing restored", x.Key)
		}
		if err := put(x.Key, map[string]any{"deleted": false, "sealed": map[string]string{"e": bk.E, "data": bk.Data}, "backupSha256": x.BackupSha256,
			"e": x.E, "dataSha256": x.DataSha256}); err != nil {
			return nil, fmt.Errorf("the backups weren't written, so nothing was restored: %v", err)
		}
	}
	for _, k := range rc.Remove {
		if err := put(k, map[string]any{"deleted": true, "sealed": nil, "backupSha256": "", "e": "", "dataSha256": ""}); err != nil {
			return nil, fmt.Errorf("the backups weren't written, so nothing was restored: %v", err)
		}
	}
	done, err := sc.Call("/stores/restore/commit", map[string]string{"pending": in.Pending})
	if err != nil {
		return nil, err
	}
	log.Printf("store %s: version %d put back (phone-approved; %d keys back, %d removed)", rc.Store, rc.To, len(rc.Put), len(rc.Remove))
	r.dropRequests(func(q *InboxRequest) bool { return q.Kind == requestKindRestore && q.Params.Store == rc.Store }, outcomeApproved, nil)
	asked := r.refreshHolders(rc.Store, fmt.Sprintf("Store %s was restored to its version %d (approved on the phone). Unlock gives these sessions the store as it is now.", rc.Store, rc.To))
	return map[string]any{"ok": true, "restored": done, "refreshAsked": asked}, nil
}

func (r *Router) registerRestore(app appRoute, mux *http.ServeMux) {
	for _, p := range []string{"stores/versions", "stores/restore/begin"} {
		path := "/" + p
		app("POST /api/core"+path, func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			r.relayStores(w, req, "POST", path, b)
		})
	}
	app("POST /api/stores/restore/finish", func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		out, err := r.FinishRestore(b)
		if err != nil {
			writeWriteErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	setup := func(pattern string, fn func(w http.ResponseWriter, req *http.Request, body []byte)) {
		mux.Handle(pattern, r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 4<<20))
			if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), b); err != nil {
				writeJSON(w, 401, map[string]string{"error": err.Error()})
				return
			}
			fn(w, req, b)
		}))
	}
	setup("POST /setup/stores/versions", func(w http.ResponseWriter, req *http.Request, b []byte) {
		r.relayTo(w, r.storeCore(), "POST", "/stores/versions", b)
	})
}
