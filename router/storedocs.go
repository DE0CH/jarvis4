package main

// Stores, their keys and what each key is for (Deyao, 2026-10-11: "the names of the keys should be visible through the
// api"; 2026-10-13: the explanation of each key is surfaced on the web and iPhone portal, and writing one key by name
// is allowed without overwriting the store).
//
// Key names and who wrote each key come from the core's signed store list (a store is a set of keys, core/keys.go).
// What a store and each key are for is the router's own record (store-docs.json, a row of router_docs in its database): not a secret and
// not part of any trust decision, written by whoever writes a key (a new key name needs its explanation), by the setup
// session (`POST /setup/store-docs`) and by Deyao in the app. Every key's backup carries its explanation too, so a
// Recover brings them back.
//
// Writing a key (no approval: Deyao, 2026-10-13, "any session with a valid machine key … writing a key is perfectly
// safe (has backup, so can't overwrite, and also can't read)"): the writer seals the value to the store key P + K and,
// for the backup, to the master key, and signs both (core.WriterText). The router writes the backup first
// (keys/<store>/<key>.json in the versioned bucket), then the key into the core, records the explanation, and asks
// the phone to refresh every running session that holds the store (its copy is behind until a new unlock: the core
// can't open the new value without the phone).
//
//	GET /api/stores, GET /m/stores, GET /setup/stores/keys → {stores: [StoreRow], signed}
//	GET /m/store-key, GET /setup/store-key → {identity, storeKey}: what a writer seals to (the core's signed identity,
//	    naming the master key, and its signed store key for the claimed phone)
//	POST /m/stores/{store}/keys/{key}      a session writes or deletes one key (machine-signed: core.WriterText)
//	POST /setup/stores/{store}/keys/{key}  the same as the setup session (setup-key signed)
//	POST /setup/store-docs, PUT /api/stores/{store}/docs {about?, keys: {KEY: text}} → {ok}

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// KeyWriter: who wrote a key, as the core signed it, with the session the router knows that line as
type KeyWriter struct {
	By           string `json:"by"`
	Machine      string `json:"machine,omitempty"`
	Line         string `json:"line,omitempty"`
	Session      string `json:"session,omitempty"`
	SessionLabel string `json:"sessionLabel,omitempty"`
}

// KeyRow: one key as listed (never a value)
type KeyRow struct {
	Name        string     `json:"name"`
	Explanation string     `json:"explanation"`
	At          string     `json:"at,omitempty"`
	Writer      *KeyWriter `json:"writer,omitempty"`
}

// StoreRow: one store as listed
type StoreRow struct {
	Name      string `json:"name"`
	Sensitive bool   `json:"sensitive"`
	Empty     bool   `json:"empty"`
	Unlocked  bool   `json:"unlocked"`
	About     string `json:"about"`
	Version   string `json:"version,omitempty"`
	// Keys: the key names, the shape every session image reads; KeyInfo: the same keys with what each is for and who
	// wrote it
	Keys     []string `json:"keys"`
	KeyInfo  []KeyRow `json:"keyInfo"`
	KeysFrom string   `json:"keysFrom"` // core: the names are the core's own signed list
}

// StoreDoc: what a store and its keys are for
type StoreDoc struct {
	About string            `json:"about,omitempty"`
	Keys  map[string]string `json:"keys,omitempty"`
}

var keyNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

const docMax = 2000 // characters of one explanation

var storeDocsMu sync.Mutex

func (r *Router) readStoreDocs() map[string]StoreDoc {
	m := map[string]StoreDoc{}
	if b, ok := r.st.ReadDoc("store-docs.json"); ok {
		json.Unmarshal(b, &m)
	}
	return m
}

// cleanDoc: an explanation as plain text (cleanExplanation's rules, longer)
func cleanDoc(s string) (string, error) {
	s = strings.ReplaceAll(s, "\n", " ")
	out, err := plainLines(s)
	if err != nil {
		return "", err
	}
	if n := len([]rune(out)); n > docMax {
		return "", fmt.Errorf("explanation longer than %d characters (%d)", docMax, n)
	}
	return out, nil
}

// SetStoreDocs: a store's about text (nil = unchanged) and explanations of its keys ("" removes one)
func (r *Router) SetStoreDocs(store string, about *string, keys map[string]string) error {
	if !storeNameOK(store) {
		return fmt.Errorf("bad store name %q", store)
	}
	clean := map[string]string{}
	for k, v := range keys {
		if !keyNameRE.MatchString(k) {
			return fmt.Errorf("bad key name %q", k)
		}
		c, err := cleanDoc(v)
		if err != nil {
			return fmt.Errorf("%s: %v", k, err)
		}
		clean[k] = c
	}
	var ab string
	if about != nil {
		var err error
		if ab, err = cleanDoc(*about); err != nil {
			return fmt.Errorf("about: %v", err)
		}
	}
	storeDocsMu.Lock()
	defer storeDocsMu.Unlock()
	m := r.readStoreDocs()
	d := m[store]
	if d.Keys == nil {
		d.Keys = map[string]string{}
	}
	if about != nil {
		d.About = ab
	}
	for k, v := range clean {
		if v == "" {
			delete(d.Keys, k)
		} else {
			d.Keys[k] = v
		}
	}
	m[store] = d
	b, _ := json.MarshalIndent(m, "", " ")
	return r.st.WriteDoc("store-docs.json", b)
}

func storeNameOK(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// envSlug: the core's EnvSlug (core/deploykeys.go) — OWNER_NAME, upper case, anything outside [A-Z0-9] as "_"
func envSlug(repo string) string {
	b := []byte(strings.ToUpper(repo))
	for i, ch := range b {
		if !(ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
			b[i] = '_'
		}
	}
	return string(b)
}

// coreStoreRow: one row of the core's signed list
type coreStoreRow struct {
	Name      string `json:"name"`
	Sensitive bool   `json:"sensitive"`
	Empty     bool   `json:"empty"`
	Unlocked  bool   `json:"unlocked"`
	Version   string `json:"version"`
	Keys      []struct {
		Name   string     `json:"name"`
		At     string     `json:"at"`
		Writer *KeyWriter `json:"writer"`
	} `json:"keys"`
}

// StoreList: the core's signed list with each store's keys, who wrote them and what they are for
func (r *Router) StoreList() ([]StoreRow, *Doc, error) {
	d, err := r.core.Call("/stores", map[string]string{"nonce": "store-keys-" + randID()})
	if err != nil {
		return nil, nil, err
	}
	var list struct {
		Kind   string         `json:"kind"`
		Stores []coreStoreRow `json:"stores"`
	}
	if err := d.Decode(&list); err != nil || list.Kind != "stores" {
		return nil, nil, fmt.Errorf("the core's store list isn't readable")
	}
	storeDocsMu.Lock()
	docs := r.readStoreDocs()
	storeDocsMu.Unlock()
	lines := map[string][2]string{} // line → session id, label
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if l := certLine(s.Cert); l != "" {
				lines[l] = [2]string{s.ID, s.Label}
			}
		}
		for _, rec := range d.Records {
			if l := certLine(rec.Session.Cert); l != "" {
				if _, ok := lines[l]; !ok {
					lines[l] = [2]string{rec.Session.ID, rec.Session.Label}
				}
			}
		}
	})
	rows := make([]StoreRow, 0, len(list.Stores))
	for _, s := range list.Stores {
		doc := docs[s.Name]
		row := StoreRow{Name: s.Name, Sensitive: s.Sensitive, Empty: s.Empty, Unlocked: s.Unlocked, About: doc.About, Version: s.Version}
		row.KeysFrom, row.Keys, row.KeyInfo = "core", []string{}, []KeyRow{}
		for _, k := range s.Keys {
			kr := KeyRow{Name: k.Name, Explanation: doc.Keys[k.Name], At: k.At, Writer: k.Writer}
			if w := kr.Writer; w != nil && w.Line != "" {
				w.Session, w.SessionLabel = lines[w.Line][0], lines[w.Line][1]
			}
			row.Keys, row.KeyInfo = append(row.Keys, k.Name), append(row.KeyInfo, kr)
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, d, nil
}

func certLine(c *Doc) string {
	if c == nil {
		return ""
	}
	var x struct {
		Line string `json:"line"`
	}
	c.Decode(&x)
	return x.Line
}

func (r *Router) serveStoreList(w http.ResponseWriter) {
	rows, d, err := r.StoreList()
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"stores": rows, "signed": d})
}

// storeKeyFor: what a writer seals to — the core's identity (its keys, the box key's signature, its signed state
// naming the master key and the phone) and its signed store key for that phone
func (r *Router) storeKeyFor() (map[string]any, error) {
	status, b, err := r.core.Raw("GET", "/identity", nil)
	if err != nil || status != 200 {
		return nil, fmt.Errorf("the core's identity isn't readable (HTTP %d, %v)", status, err)
	}
	var id struct {
		State *Doc `json:"state"`
	}
	json.Unmarshal(b, &id)
	var st struct {
		Phone struct {
			AgreementKey string `json:"agreementKey"`
		} `json:"phone"`
	}
	if id.State == nil || id.State.Decode(&st) != nil || st.Phone.AgreementKey == "" {
		return nil, errors.New("the core isn't set up (no phone in its signed state)")
	}
	sk, err := r.core.Call("/store-key", map[string]string{"phone": st.Phone.AgreementKey})
	if err != nil {
		return nil, err
	}
	return map[string]any{"identity": json.RawMessage(b), "storeKey": sk}, nil
}

// keyWriteIn: a writer's request (core.WriteKeyInput's sealed parts, the backup and the explanation)
type keyWriteIn struct {
	Delete  bool `json:"delete"`
	Wrapped *struct {
		E       string `json:"e"`
		Wrapped string `json:"wrapped"`
	} `json:"wrapped"`
	Data         string `json:"data"`
	BackupSha256 string `json:"backupSha256"`
	Backup       *struct {
		E    string `json:"e"`
		Data string `json:"data"`
	} `json:"backup"`
	Sig         string `json:"sig"`
	Explanation string `json:"explanation"`
}

// backupSha: what WriterText names for a key's backup — sha256 of its sealed parts
func backupSha(e, data string) string {
	h := sha256.Sum256([]byte(e + "\n" + data))
	return hex.EncodeToString(h[:])
}

func wrappedE(in keyWriteIn) string {
	if in.Wrapped == nil {
		return ""
	}
	return in.Wrapped.E
}

func dataSha(data string) string {
	if data == "" {
		return ""
	}
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// WriteKey: one key written by a session's machine (writer "machine") or the setup session (writer "setup")
func (r *Router) WriteKey(writer, machine, store, key string, in keyWriteIn) (map[string]any, error) {
	if !storeNameOK(store) || !keyNameRE.MatchString(key) {
		return nil, &badRequest{"store: lower-case letters, digits and -; key: letters, digits and _"}
	}
	// the core's own store never; the deploy-key token store only by the setup session (the core refuses a machine's
	// write there too: its keys otherwise come only from a phone-approved deploy-key call)
	if store == flyStore || (store == deployKeyTokenStore && writer != "setup") {
		return nil, &forbidden{fmt.Sprintf("store %s isn't written this way: the core's Fly token goes through `infra/setup.py backup-core`, the deploy-key token through `infra/setup.py write %s` from the setup session", store, store)}
	}
	expl, err := cleanDoc(in.Explanation)
	if err != nil {
		return nil, &badRequest{err.Error()}
	}
	storeDocsMu.Lock()
	documented := r.readStoreDocs()[store].Keys[key] != ""
	storeDocsMu.Unlock()
	if !in.Delete && expl == "" && !documented {
		return nil, &badRequest{fmt.Sprintf("%s has no explanation yet: say what the key is for (explanation)", key)}
	}
	if in.Sig == "" {
		return nil, &badRequest{"sig: the writer's signature over core.WriterText"}
	}
	var sealed any
	if !in.Delete {
		if in.Wrapped == nil || in.Data == "" || in.Backup == nil || in.Backup.E == "" || in.Backup.Data == "" {
			return nil, &badRequest{"a write carries wrapped, data and its backup (sealed to the master key)"}
		}
		if in.BackupSha256 != backupSha(in.Backup.E, in.Backup.Data) {
			return nil, &badRequest{"backupSha256 isn't the backup's"}
		}
		sealed = in.Backup
	} else if in.BackupSha256 != "" {
		return nil, &badRequest{"a delete has no backup"}
	}
	core := map[string]any{"store": store, "key": key, "delete": in.Delete, "data": in.Data, "backupSha256": in.BackupSha256,
		"writer": writer, "sig": in.Sig}
	if in.Wrapped != nil {
		core["wrapped"] = in.Wrapped
	}
	if writer == "machine" {
		var cert *Doc
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine && s.State == "started" {
				cert = s.Cert
			}
		})
		if cert == nil {
			return nil, &forbidden{"only a running session writes a key"}
		}
		core["cert"] = cert
	}
	idStatus, ident, err := r.core.Raw("GET", "/identity", nil)
	if err != nil || idStatus != 200 {
		return nil, fmt.Errorf("the core's identity isn't readable: %v", err)
	}
	// the backup first: a key never reaches the core without one (Deyao: "has backup, so can't overwrite")
	b := backupBucketFromEnv()
	if b == nil {
		return nil, errors.New("the router has no backup credential (BACKUP_READ_ACCESS_KEY): no key is written without its backup. The setup session installs it with infra/backup-read-key.py install (RUNBOOK, the router's secrets)")
	}
	obj := map[string]any{"kind": "key-backup", "store": store, "key": key, "deleted": in.Delete, "sealed": sealed,
		"backupSha256": in.BackupSha256, "e": wrappedE(in), "dataSha256": dataSha(in.Data), "writer": map[string]any{"by": writer, "sig": in.Sig, "cert": core["cert"]},
		"core": json.RawMessage(ident), "explanation": expl, "at": time.Now().UTC().Format(time.RFC3339)}
	raw, _ := json.Marshal(obj)
	if err := b.put("keys/"+store+"/"+key+".json", raw); err != nil {
		return nil, fmt.Errorf("the backup wasn't written, so the key wasn't either: %v", err)
	}
	receipt, err := r.core.Call("/stores/write-key", core)
	if err != nil {
		return nil, err
	}
	if expl != "" {
		if err := r.SetStoreDocs(store, nil, map[string]string{key: expl}); err != nil {
			log.Printf("store %s: the explanation of %s wasn't kept: %v", store, key, err)
		}
	}
	// no Inbox request: a session holding the store gets the key at its next pull with a new cert (Deyao, 2026-10-22)
	return map[string]any{"ok": true, "receipt": receipt}, nil
}

// refreshHolders: every running session whose cert names the store gets an unlock request (one batch when several),
// so the phone gives them the store as it is now; their machines pull again once it is unlocked (unlockArrived)
func (r *Router) refreshHolders(store, why string) []string {
	sids := []string{}
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if s.State == "started" && s.MachineID != "" && containsString(s.Stores, store) {
				sids = append(sids, s.ID)
			}
		}
	})
	sort.Strings(sids)
	r.fileRefresh(sids, why)
	return sids
}

// fileRefresh: the unlock requests that bring sessions their stores as they are now (filed by the router)
func (r *Router) fileRefresh(sids []string, why string) {
	o := Origin{Caller: Caller{Kind: "router"}, Call: APICall{Method: "POST", Path: "/router/refresh"}}
	switch {
	case len(sids) == 1:
		if _, _, err := r.FileRequest(requestKindUnlock, RequestParams{Session: sids[0]}, why, o); err != nil {
			log.Printf("refresh %s: %v", sids[0], err)
		}
	case len(sids) > 1:
		for i := 0; i < len(sids); i += batchMaxItems {
			part := sids[i:min(i+batchMaxItems, len(sids))]
			items := []map[string]any{}
			for _, sid := range part {
				items = append(items, map[string]any{"intent": "unlock", "session": sid, "explanation": why})
			}
			if code, out := r.FileBatch(o.Caller, "POST", "/router/refresh", mustJSON(map[string]any{"summary": why, "items": items}), nil); code != 200 {
				log.Printf("refresh %v: %d %v", part, code, out)
			}
		}
	}
}

// unlockArrived: an unlock for one cert went through (the phone's unlock_finish): when that cert is a running,
// booted machine's newest, the machine's supervisor pulls again so it holds the store as it is now
func (r *Router) unlockArrived(answer []byte) {
	var a struct {
		Payload string `json:"payload"`
	}
	var x struct {
		Kind string `json:"kind"`
		For  string `json:"for"`
	}
	if json.Unmarshal(answer, &a) != nil || json.Unmarshal([]byte(a.Payload), &x) != nil || x.Kind != "unlocked" || x.For == "" {
		return
	}
	var machine string
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if s.State == "started" && s.MachineID != "" && s.Booted == s.MachineID && certNonce(s.Cert) == x.For {
				machine = s.MachineID
			}
		}
	})
	if machine != "" {
		r.send(machine, "refresh-secrets")
	}
}

func certNonce(c *Doc) string {
	if c == nil {
		return ""
	}
	var x struct {
		Nonce string `json:"nonce"`
	}
	c.Decode(&x)
	return x.Nonce
}

// ---- routes -------------------------------------------------------------------------------------------------

func writeWriteErr(w http.ResponseWriter, err error) {
	var ce *CoreError
	if errors.As(err, &ce) {
		writeJSON(w, ce.Status, map[string]string{"error": ce.Msg})
		return
	}
	writeRequestErr(w, err)
}

func (r *Router) registerStoreDocs(app appRoute, m machineRoute, mux *http.ServeMux) {
	app("GET /api/stores", func(w http.ResponseWriter, req *http.Request) { r.serveStoreList(w) })
	app("PUT /api/stores/{store}/docs", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			About *string           `json:"about"`
			Keys  map[string]string `json:"keys"`
		}
		if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
			return
		}
		if err := r.SetStoreDocs(req.PathValue("store"), in.About, in.Keys); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	// every session may see every store's names (not only its own): it needs them to know which store to ask for
	m("GET /m/stores", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) { r.serveStoreList(w) })
	m("GET /m/store-key", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		out, err := r.storeKeyFor()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	m("POST /m/stores/{store}/keys/{key}", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in keyWriteIn
		if err := json.Unmarshal(body, &in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
			return
		}
		out, err := r.WriteKey("machine", machine, req.PathValue("store"), req.PathValue("key"), in)
		if err != nil {
			writeWriteErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	setup := func(pattern string, fn func(w http.ResponseWriter, req *http.Request, body []byte)) {
		mux.Handle(pattern, r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
			if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), b); err != nil {
				writeJSON(w, 401, map[string]string{"error": err.Error()})
				return
			}
			fn(w, req, b)
		}))
	}
	setup("GET /setup/stores/keys", func(w http.ResponseWriter, req *http.Request, _ []byte) { r.serveStoreList(w) })
	setup("GET /setup/store-key", func(w http.ResponseWriter, req *http.Request, _ []byte) {
		out, err := r.storeKeyFor()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	setup("POST /setup/stores/{store}/keys/{key}", func(w http.ResponseWriter, req *http.Request, b []byte) {
		var in keyWriteIn
		if err := json.Unmarshal(b, &in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
			return
		}
		out, err := r.WriteKey("setup", "", req.PathValue("store"), req.PathValue("key"), in)
		if err != nil {
			writeWriteErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	setup("POST /setup/store-docs", func(w http.ResponseWriter, req *http.Request, b []byte) {
		var in struct {
			Store string            `json:"store"`
			About *string           `json:"about"`
			Keys  map[string]string `json:"keys"`
		}
		if err := json.Unmarshal(b, &in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
			return
		}
		if err := r.SetStoreDocs(in.Store, in.About, in.Keys); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
}
