package main

// The router's records in Postgres (docs/STATE.md step 3). The router still holds them in memory under one lock
// (State.Do, one router process: the flock), loaded from the database at start; after every Do the records its
// closure changed are written in one transaction: each record is marshalled, compared with what the database last
// took, and only the differences go (upserts and deletes). A failed write keeps the difference, which the next Do (or
// the retry every few seconds) writes again; /setup/status shows the error meanwhile.
//
// Where each field of persisted goes: stateTables (a map → its table, one row per key; Records → records, one row per
// position; anything else → a settings row named after its JSON key). state.json is read once, at the first start
// against an empty database (the import), then renamed state.json.imported.

import (
	"context"
	"encoding/json"
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
		switch {
		case f.key == "records":
			m := map[string]string{}
			for i := 0; i < fv.Len(); i++ {
				b, err := json.Marshal(fv.Index(i).Interface())
				if err != nil {
					return nil, err
				}
				m[strconv.Itoa(i)] = string(b)
			}
			out[f.table] = m
		case f.table != "":
			m := map[string]string{}
			it := fv.MapRange()
			for it.Next() {
				b, err := json.Marshal(it.Value().Interface())
				if err != nil {
					return nil, err
				}
				m[it.Key().String()] = string(b)
			}
			out[f.table] = m
		default:
			if fv.IsZero() {
				continue // no row: the zero value (omitempty in state.json)
			}
			b, err := json.Marshal(fv.Interface())
			if err != nil {
				return nil, err
			}
			out[""]["state."+f.key] = string(b)
		}
	}
	return out, nil
}

// stateDB: the database side of State
type stateDB struct {
	db      *DB
	written rows // what the database holds, as last written or read
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
	s := &State{dir: dir, sdb: &stateDB{db: db}, seal: seal}
	if err := s.importSealedFiles(dir); err != nil {
		return nil, err
	}
	if err := s.resealOld(ctx); err != nil {
		return nil, err
	}
	if err := s.sdb.load(ctx, &s.data); err != nil {
		return nil, err
	}
	d := &s.data
	initMaps(d)
	for id, c := range d.SessCerts {
		if x := d.Sessions[id]; x != nil {
			x.Cert = c
		}
	}
	w, err := rowsOf(d)
	if err != nil {
		return nil, err
	}
	s.sdb.written = w // as Go marshals what was read (jsonb doesn't keep the text)
	go s.retryLoop()
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

func (sd *stateDB) load(ctx context.Context, d *persisted) error {
	v := reflect.ValueOf(d).Elem()
	settings := map[string][]byte{}
	rs, err := sd.db.pool.Query(ctx, "SELECT key, value FROM settings WHERE key LIKE 'state.%'")
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
			rs, err := sd.db.pool.Query(ctx, "SELECT doc FROM records ORDER BY ord")
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
		case f.table != "":
			rs, err := sd.db.pool.Query(ctx, "SELECT id, doc FROM "+f.table)
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

// write: the differences between now and what the database holds, in one transaction (callers hold State.mu)
func (sd *stateDB) write(d *persisted) error {
	now, err := rowsOf(d)
	if err != nil {
		return err
	}
	type up struct{ table, id, doc string }
	var ups []up
	dels := map[string][]string{}
	for table, m := range now {
		old := sd.written[table]
		for id, doc := range m {
			if old[id] != doc {
				ups = append(ups, up{table, id, doc})
			}
		}
		for id := range old {
			if _, ok := m[id]; !ok {
				dels[table] = append(dels[table], id)
			}
		}
	}
	if len(ups) == 0 && len(dels) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = pgx.BeginFunc(ctx, sd.db.pool, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		for table, ids := range dels {
			switch table {
			case "":
				b.Queue("DELETE FROM settings WHERE key = ANY($1)", ids)
			case "records":
				ords := make([]int, len(ids))
				for i, id := range ids {
					ords[i], _ = strconv.Atoi(id)
				}
				b.Queue("DELETE FROM records WHERE ord = ANY($1)", ords)
			default:
				b.Queue("DELETE FROM "+table+" WHERE id = ANY($1)", ids)
			}
		}
		for _, u := range ups {
			switch u.table {
			case "":
				b.Queue("INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, now()) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = now()", u.id, u.doc)
			case "records":
				ord, _ := strconv.Atoi(u.id)
				b.Queue("INSERT INTO records (ord, doc) VALUES ($1, $2) ON CONFLICT (ord) DO UPDATE SET doc = excluded.doc", ord, u.doc)
			default:
				b.Queue("INSERT INTO "+u.table+" (id, doc) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET doc = excluded.doc", u.id, u.doc)
			}
		}
		return tx.SendBatch(ctx, b).Close()
	})
	if err != nil {
		return err
	}
	sd.written = now
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

// retryLoop: a write that failed is tried again every few seconds, so a database blip doesn't wait for the next Do
func (s *State) retryLoop() {
	for {
		select {
		case <-s.sdb.db.done:
			return
		case <-time.After(3 * time.Second):
		}
		s.sdb.mu.Lock()
		failed := s.sdb.lastErr != nil
		s.sdb.mu.Unlock()
		if !failed {
			continue
		}
		if !s.mu.TryLock() {
			continue
		}
		s.save()
		s.mu.Unlock()
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
