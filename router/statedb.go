package main

// The router's records in Postgres (docs/STATE.md step 3). The router still holds them in memory under one lock
// (State.Do, one router process: the flock), loaded from the database at start; after every Do the records its
// closure changed are written in one transaction: each record is marshalled, compared with what the database last
// took, and only the differences go (upserts and deletes). A failed write keeps the difference, which the next Do (or
// the retry every few seconds) writes again; /setup/status shows the error meanwhile.
//
// Several replicas: every Do takes the state_version row, and a replica whose copy is older reads again only the
// records the others changed since (catchUp, from the state_changes list every write adds to), never all of them
// unless a version's changes aren't listed. A fn that only looks is a Read (state.go): no marshal, no write. The
// log says once a minute what the Do's cost and who asked most (statestats.go).
//
// Where each field of persisted goes: stateTables (a map → its table, one row per key; Records → records, one row per
// position; anything else → a settings row named after its JSON key). state.json is read once, at the first start
// against an empty database (the import), then renamed state.json.imported.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// stateTables: persisted's JSON key → its table (maps; and records); every other field is a settings row
var stateTables = map[string]string{
	"sessions": "sessions", "approvals": "approvals", "records": "records", "started": "machines",
	"certs": "machine_certs", "machines": "machine_sessions", "sessionCerts": "session_certs", "grants": "grants",
	"schedules": "schedules", "devices": "devices", "uploads": "uploads", "inbox": "inbox", "batches": "batches",
	"callResults": "call_results", "outcomes": "outcomes", "messages": "messages", "messageRules": "message_rules",
}

// stateImported: the settings row that says state.json was imported (or there was none)
const stateImported = "router.stateImported"

type stateField struct {
	index int
	key   string // the JSON key (settings row name)
	table string // "" = a settings row
}

var stateFields = func() []stateField {
	t := reflect.TypeOf(persisted{})
	var fs []stateField
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		key, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if key == "" || key == "-" {
			panic("persisted." + f.Name + " has no JSON key")
		}
		table := stateTables[key]
		switch {
		case f.Type.Kind() == reflect.Map && f.Type.Key().Kind() == reflect.String && table == "":
			panic("persisted." + f.Name + ": a map with no table in stateTables (and migrations/)")
		case table != "" && f.Type.Kind() != reflect.Map && key != "records":
			panic("persisted." + f.Name + ": stateTables names a table for a field that isn't a map")
		}
		fs = append(fs, stateField{i, key, table})
	}
	return fs
}()

// rows: what the database holds (or is about to): table ("" = settings) → id → the record's JSON
type rows map[string]map[string]string

// rowsOf: d as rows
func rowsOf(d *persisted) (rows, error) {
	v := reflect.ValueOf(d).Elem()
	out := rows{"": {}}
	for _, f := range stateFields {
		fv := v.Field(f.index)
		if f.table != "" {
			m, err := rowsOfField(f, fv)
			if err != nil {
				return nil, err
			}
			out[f.table] = m
			continue
		}
		if fv.IsZero() {
			continue // no row: the zero value (omitempty in state.json)
		}
		b, err := json.Marshal(fv.Interface())
		if err != nil {
			return nil, err
		}
		out[""]["state."+f.key] = string(b)
	}
	return out, nil
}

// rowsOfField: the rows of one field that has a table (a map, or the records list by position)
func rowsOfField(f stateField, fv reflect.Value) (map[string]string, error) {
	m := map[string]string{}
	if f.key == "records" {
		for i := 0; i < fv.Len(); i++ {
			b, err := json.Marshal(fv.Index(i).Interface())
			if err != nil {
				return nil, err
			}
			m[strconv.Itoa(i)] = string(b)
		}
		return m, nil
	}
	it := fv.MapRange()
	for it.Next() {
		b, err := json.Marshal(it.Value().Interface())
		if err != nil {
			return nil, err
		}
		m[it.Key().String()] = string(b)
	}
	return m, nil
}

// stateDB: the database side of State
type stateDB struct {
	db      *DB
	written rows  // what the database holds, as last written or read
	ver     int64 // the state_version that copy is of (-1: none yet, reload)
	mu      sync.Mutex
	lastErr error
	errAt   time.Time
}

// OpenState: the records from the database (state.json imported first if this is its first start), the snapshots
// directory under dir
func OpenState(ctx context.Context, db *DB, dir string, seal *Sealer) (*State, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := importStateFile(ctx, db, dir); err != nil {
		return nil, err
	}
	renameImported(dir)
	if err := importDocFiles(ctx, db, dir); err != nil {
		return nil, err
	}
	if err := importLogFiles(ctx, db, dir); err != nil {
		return nil, err
	}
	s := &State{dir: dir, sdb: &stateDB{db: db, ver: -1}, seal: seal}
	if err := s.importSealedFiles(dir); err != nil {
		return nil, err
	}
	if err := s.resealOld(ctx); err != nil {
		return nil, err
	}
	if err := s.reload(ctx, db.pool); err != nil {
		return nil, err
	}
	return s, nil
}

func initMaps(d *persisted) {
	v := reflect.ValueOf(d).Elem()
	for _, f := range stateFields {
		fv := v.Field(f.index)
		if fv.Kind() == reflect.Map && fv.IsNil() {
			fv.Set(reflect.MakeMap(fv.Type()))
		}
	}
}

// querier: the pool, or a transaction
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func (sd *stateDB) load(ctx context.Context, q querier, d *persisted) error {
	v := reflect.ValueOf(d).Elem()
	settings := map[string][]byte{}
	rs, err := q.Query(ctx, "SELECT key, value FROM settings WHERE key LIKE 'state.%'")
	if err != nil {
		return err
	}
	for rs.Next() {
		var k string
		var b []byte
		if err := rs.Scan(&k, &b); err != nil {
			rs.Close()
			return err
		}
		settings[k] = b
	}
	rs.Close()
	for _, f := range stateFields {
		fv := v.Field(f.index)
		switch {
		case f.key == "records":
			if err := loadRecords(ctx, q, fv); err != nil {
				return err
			}
		case f.table != "":
			rs, err := q.Query(ctx, "SELECT id, doc FROM "+f.table)
			if err != nil {
				return err
			}
			m := reflect.MakeMap(fv.Type())
			for rs.Next() {
				var id string
				var b []byte
				if err := rs.Scan(&id, &b); err != nil {
					rs.Close()
					return err
				}
				e := reflect.New(fv.Type().Elem())
				if err := json.Unmarshal(b, e.Interface()); err != nil {
					rs.Close()
					return fmt.Errorf("%s %s: %v", f.table, id, err)
				}
				m.SetMapIndex(reflect.ValueOf(id), e.Elem())
			}
			rs.Close()
			if err := rs.Err(); err != nil {
				return err
			}
			fv.Set(m)
		default:
			if b, ok := settings["state."+f.key]; ok {
				p := reflect.New(fv.Type())
				if err := json.Unmarshal(b, p.Interface()); err != nil {
					return fmt.Errorf("settings state.%s: %v", f.key, err)
				}
				fv.Set(p.Elem())
			}
		}
	}
	return nil
}

// loadRecords: the records list (fv) as the database has it
func loadRecords(ctx context.Context, q querier, fv reflect.Value) error {
	rs, err := q.Query(ctx, "SELECT doc FROM records ORDER BY ord")
	if err != nil {
		return err
	}
	sl := reflect.MakeSlice(fv.Type(), 0, 0)
	for rs.Next() {
		var b []byte
		if err := rs.Scan(&b); err != nil {
			rs.Close()
			return err
		}
		e := reflect.New(fv.Type().Elem())
		if err := json.Unmarshal(b, e.Interface()); err != nil {
			rs.Close()
			return fmt.Errorf("records: %v", err)
		}
		sl = reflect.Append(sl, e.Elem())
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return err
	}
	fv.Set(sl)
	return nil
}

// writeTx: the differences between d and what the database holds, queued on tx → the rows as they are now, and whether
// anything changed
func (sd *stateDB) writeTx(ctx context.Context, tx pgx.Tx, d *persisted, next int64) (rows, bool, error) {
	now, err := rowsOf(d)
	if err != nil {
		return nil, false, err
	}
	b := &pgx.Batch{}
	for table, m := range now {
		old := sd.written[table]
		var dels, touched []string
		for id := range old {
			if _, ok := m[id]; !ok {
				dels = append(dels, id)
			}
		}
		if len(dels) > 0 {
			switch table {
			case "":
				b.Queue("DELETE FROM settings WHERE key = ANY($1)", dels)
			case "records":
				ords := make([]int, len(dels))
				for i, id := range dels {
					ords[i], _ = strconv.Atoi(id)
				}
				b.Queue("DELETE FROM records WHERE ord = ANY($1)", ords)
			default:
				b.Queue("DELETE FROM "+table+" WHERE id = ANY($1)", dels)
			}
		}
		for id, doc := range m {
			if old[id] == doc {
				continue
			}
			touched = append(touched, id)
			switch table {
			case "":
				b.Queue("INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, now()) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = now()", id, doc)
			case "records":
				ord, _ := strconv.Atoi(id)
				b.Queue("INSERT INTO records (ord, doc) VALUES ($1, $2) ON CONFLICT (ord) DO UPDATE SET doc = excluded.doc", ord, doc)
			default:
				b.Queue("INSERT INTO "+table+" (id, doc) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET doc = excluded.doc", id, doc)
			}
		}
		if touched = append(touched, dels...); len(touched) > 0 { // what the other replicas read again (catchUp)
			b.Queue("INSERT INTO state_changes (v, tbl, id) SELECT $1, $2, unnest($3::text[])", next, table, touched)
		}
	}
	if b.Len() == 0 {
		return now, false, nil
	}
	b.Queue("INSERT INTO state_changes (v, tbl, id) VALUES ($1, $2, '')", next, changesMarker)
	b.Queue("DELETE FROM state_changes WHERE v <= $1", next-changesKept)
	return now, true, tx.SendBatch(ctx, b).Close()
}

// changesMarker: the state_changes row every version has (tbl); changesKept: how many versions back the table goes
// (a replica further behind takes all the records again); catchUpMost: the most records a catch-up reads one by one
const (
	changesMarker = "*"
	changesKept   = 5000
	catchUpMost   = 2000
)

// catchUp: the records another replica changed between versions from (this copy's) and to (the database's), read
// again in place: the rows state_changes lists, a deleted one gone, the records list whole when it changed. false:
// not every version in between listed its changes (a router from before state_changes wrote one, or they are older
// than the table keeps), or too many to be worth it: the caller reloads everything. The copy is only as good as the
// database's when this returns true with no error.
func (s *State) catchUp(ctx context.Context, q querier, from, to int64) (bool, error) {
	if from < 0 || to <= from || to-from > changesKept {
		return false, nil
	}
	rs, err := q.Query(ctx, "SELECT v, tbl, id FROM state_changes WHERE v > $1 AND v <= $2", from, to)
	if err != nil {
		return false, err
	}
	marked, changed, n := map[int64]bool{}, map[string]map[string]bool{}, 0
	for rs.Next() {
		var v int64
		var tbl, id string
		if err := rs.Scan(&v, &tbl, &id); err != nil {
			rs.Close()
			return false, err
		}
		if tbl == changesMarker {
			marked[v] = true
			continue
		}
		if changed[tbl] == nil {
			changed[tbl] = map[string]bool{}
		}
		if !changed[tbl][id] {
			changed[tbl][id] = true
			n++
		}
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return false, err
	}
	if int64(len(marked)) != to-from || n > catchUpMost {
		return false, nil
	}
	d, w := &s.data, s.sdb.written
	v := reflect.ValueOf(d).Elem()
	for _, f := range stateFields {
		fv := v.Field(f.index)
		table := f.table
		ids := make([]string, 0, len(changed[table]))
		for id := range changed[table] {
			if f.table != "" || id == "state."+f.key {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			continue
		}
		switch {
		case f.key == "records": // a list: a record taken out moves every one after it
			if err := loadRecords(ctx, q, fv); err != nil {
				return false, err
			}
			m, err := rowsOfField(f, fv)
			if err != nil {
				return false, err
			}
			w[table] = m
		case f.table != "":
			rs, err := q.Query(ctx, "SELECT id, doc FROM "+f.table+" WHERE id = ANY($1)", ids)
			if err != nil {
				return false, err
			}
			found := map[string]bool{}
			for rs.Next() {
				var id string
				var b []byte
				if err := rs.Scan(&id, &b); err != nil {
					rs.Close()
					return false, err
				}
				e := reflect.New(fv.Type().Elem())
				if err := json.Unmarshal(b, e.Interface()); err != nil {
					rs.Close()
					return false, fmt.Errorf("%s %s: %v", f.table, id, err)
				}
				doc, err := json.Marshal(e.Elem().Interface())
				if err != nil {
					rs.Close()
					return false, err
				}
				fv.SetMapIndex(reflect.ValueOf(id), e.Elem())
				if w[table] == nil {
					w[table] = map[string]string{}
				}
				w[table][id] = string(doc)
				found[id] = true
			}
			rs.Close()
			if err := rs.Err(); err != nil {
				return false, err
			}
			for _, id := range ids {
				if !found[id] {
					fv.SetMapIndex(reflect.ValueOf(id), reflect.Value{})
					delete(w[table], id)
				}
			}
		default:
			var b []byte
			err := q.QueryRow(ctx, "SELECT value FROM settings WHERE key = $1", ids[0]).Scan(&b)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				fv.Set(reflect.Zero(fv.Type()))
				delete(w[""], ids[0])
			case err != nil:
				return false, err
			default:
				p := reflect.New(fv.Type())
				if err := json.Unmarshal(b, p.Interface()); err != nil {
					return false, fmt.Errorf("settings %s: %v", ids[0], err)
				}
				fv.Set(p.Elem())
				doc, err := json.Marshal(fv.Interface())
				if err != nil {
					return false, err
				}
				w[""][ids[0]] = string(doc)
			}
		}
	}
	for id, x := range d.Sessions { // as reload: a session's cert is its session_certs row
		x.Cert = d.SessCerts[id]
	}
	return true, nil
}

// reload: the records as the database has them now (another replica changed them)
func (s *State) reload(ctx context.Context, q querier) error {
	var d persisted
	if err := s.sdb.load(ctx, q, &d); err != nil {
		return err
	}
	initMaps(&d)
	for id, c := range d.SessCerts {
		if x := d.Sessions[id]; x != nil {
			x.Cert = c
		}
	}
	w, err := rowsOf(&d)
	if err != nil {
		return err
	}
	s.data, s.sdb.written = d, w
	return nil
}

// importStateFile: state.json into the empty database, once (the router's first start on Postgres); the file is then
// renamed so nothing reads it again. A database that imported already ignores (and renames) a state.json beside it.
func importStateFile(ctx context.Context, db *DB, dir string) error {
	path := filepath.Join(dir, "state.json")
	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "LOCK TABLE settings IN EXCLUSIVE MODE"); err != nil {
			return err
		}
		var done bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM settings WHERE key = $1)", stateImported).Scan(&done); err != nil {
			return err
		}
		b, ferr := os.ReadFile(path)
		if done {
			if ferr == nil {
				log.Printf("state: the database has the records already: %s ignored, renamed .stale", path)
				os.Rename(path, path+".stale")
			}
			return nil
		}
		note := `{"from":"none"}`
		if ferr == nil {
			var d persisted
			if err := json.Unmarshal(b, &d); err != nil {
				return fmt.Errorf("%s: %v", path, err)
			}
			initMaps(&d)
			now, err := rowsOf(&d)
			if err != nil {
				return err
			}
			n := 0
			for table, m := range now {
				for id, doc := range m {
					var err error
					switch table {
					case "":
						_, err = tx.Exec(ctx, "INSERT INTO settings (key, value) VALUES ($1, $2)", id, doc)
					case "records":
						ord, _ := strconv.Atoi(id)
						_, err = tx.Exec(ctx, "INSERT INTO records (ord, doc) VALUES ($1, $2)", ord, doc)
					default:
						_, err = tx.Exec(ctx, "INSERT INTO "+table+" (id, doc) VALUES ($1, $2)", id, doc)
					}
					if err != nil {
						return fmt.Errorf("import %s %s: %v", table, id, err)
					}
					n++
				}
			}
			note = fmt.Sprintf(`{"from":"state.json","rows":%d,"at":%q}`, n, time.Now().UTC().Format(time.RFC3339))
			log.Printf("state: imported %s into the database (%d rows)", path, n)
		} else if !os.IsNotExist(ferr) {
			return ferr
		}
		if _, err := tx.Exec(ctx, "INSERT INTO settings (key, value) VALUES ($1, $2)", stateImported, note); err != nil {
			return err
		}
		return nil
	})
}

// renameImported: after the import's commit, the file is renamed (a crash before it: the next start sees the database
// imported and renames it .stale)
func renameImported(dir string) {
	p := filepath.Join(dir, "state.json")
	if _, err := os.Stat(p); err == nil {
		os.Rename(p, p+".imported")
	}
}

// StoreError: the last failed write and since when (nil when the database has every record)
func (s *State) StoreError() (error, time.Time) {
	if s == nil || s.sdb == nil {
		return nil, time.Time{}
	}
	s.sdb.mu.Lock()
	defer s.sdb.mu.Unlock()
	return s.sdb.lastErr, s.sdb.errAt
}

// ---- the router's small documents (docs/STATE.md step 4) --------------------------------------------------------

// routerDocs: the files that were on the volume and now are rows of router_docs (imported once, then renamed)
var routerDocs = []string{"store-docs.json", "repos.json", "claim-device.json", "core-certs.json", "line-state.json", "kernel-line-state.json",
	"backups-fallback.json"}

// docStore: where a small document is read and written (the State's database)
type docStore interface {
	ReadDoc(name string) ([]byte, bool)
	WriteDoc(name string, b []byte) error
}

// ReadDoc: the document, and whether there is one (a database error reads as none, and is logged)
func (s *State) ReadDoc(name string) ([]byte, bool) {
	if s == nil || s.sdb == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var b []byte
	err := s.sdb.db.pool.QueryRow(ctx, "SELECT body FROM router_docs WHERE name = $1", name).Scan(&b)
	if err != nil {
		if err != pgx.ErrNoRows {
			log.Printf("docs: reading %s: %v", name, err)
		}
		return nil, false
	}
	return b, true
}

// WriteDoc: the document replaced
func (s *State) WriteDoc(name string, b []byte) error {
	if s == nil || s.sdb == nil {
		return fmt.Errorf("docs: no database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := s.sdb.db.pool.Exec(ctx, `INSERT INTO router_docs (name, body, updated_at) VALUES ($1, $2, now())
		ON CONFLICT (name) DO UPDATE SET body = excluded.body, updated_at = now()`, name, b)
	return err
}

// DeleteDoc: the document gone
func (s *State) DeleteDoc(name string) {
	if s == nil || s.sdb == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := s.sdb.db.pool.Exec(ctx, "DELETE FROM router_docs WHERE name = $1", name); err != nil {
		log.Printf("docs: deleting %s: %v", name, err)
	}
}

// importDocFiles: each document's file on the volume into router_docs, once (a row already there wins), then renamed;
// the Jarvis 1 imports' small files (jarvis1-imports/<id>/<file>) the same way, under their path
func importDocFiles(ctx context.Context, db *DB, dir string) error {
	j1 := filepath.Join(dir, "jarvis1-imports")
	if _, err := os.Stat(j1); err == nil {
		err := filepath.WalkDir(j1, func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() || strings.HasSuffix(p, ".tmp") {
				return err
			}
			rel, _ := filepath.Rel(dir, p)
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			_, err = db.pool.Exec(ctx, "INSERT INTO router_docs (name, body) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING", filepath.ToSlash(rel), b)
			return err
		})
		if err != nil {
			return fmt.Errorf("import %s: %v", j1, err)
		}
		os.Rename(j1, j1+".imported")
		log.Printf("docs: %s imported into the database", j1)
	}
	for _, name := range routerDocs {
		p := filepath.Join(dir, name)
		b, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		tag, err := db.pool.Exec(ctx, "INSERT INTO router_docs (name, body) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING", name, b)
		if err != nil {
			return fmt.Errorf("import %s: %v", name, err)
		}
		if tag.RowsAffected() == 1 {
			log.Printf("docs: imported %s into the database", p)
			os.Rename(p, p+".imported")
		} else {
			log.Printf("docs: the database has %s already: %s set aside (.stale)", name, p)
			os.Rename(p, p+".stale")
		}
	}
	return nil
}
