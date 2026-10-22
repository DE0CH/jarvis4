package main

// Machines' snapshots in object storage (docs/STATE.md 2.2, step 5): the tarball is the object snapshots/<machine>.tar.gz
// of jarvis4-snapshots-de0ch (objstore.go), streamed straight in as the machine sends it (no copy on the router's disk,
// no growth in its memory beyond the upload's parts), hashed and read for its facts on the way; the row of `snapshots`
// says whether it is pending (streamed, unsigned) or committed (the machine signed its sha256). A booting machine whose
// state is its predecessor's snapshot gets a row naming the predecessor's object. The carried secrets beside it
// (carry.go) are rows of router_docs (carry/<machine>).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
)

// Snap: a machine's snapshot row
type Snap struct {
	Machine, Key, Sha256, Sig, State string
	Bytes                            int64
	Facts                            *snapshotFacts
	CommittedAt                      time.Time
}

func snapKey(machine string) string { return "snapshots/" + machine + ".tar.gz" }

func (r *Router) pool() *DB { return r.st.sdb.db }

// snap: the machine's snapshot row (nil: none)
func (r *Router) snap(machine string) *Snap {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var s Snap
	var facts []byte
	var at *time.Time
	err := r.pool().pool.QueryRow(ctx, `SELECT machine_id, object_key, sha256, sig, state, bytes, facts, committed_at FROM snapshots
		WHERE machine_id = $1`, machine).Scan(&s.Machine, &s.Key, &s.Sha256, &s.Sig, &s.State, &s.Bytes, &facts, &at)
	if err != nil {
		if err != pgx.ErrNoRows {
			log.Printf("snapshots: %s: %v", machine, err)
		}
		return nil
	}
	if at != nil {
		s.CommittedAt = *at
	}
	if len(facts) > 0 && string(facts) != "null" {
		s.Facts = &snapshotFacts{}
		json.Unmarshal(facts, s.Facts)
	}
	return &s
}

// haveSnap: the machine has a committed (signed) snapshot
func (r *Router) haveSnap(machine string) bool {
	s := r.snap(machine)
	return s != nil && s.State == "committed"
}

// snapStream: body into the machine's snapshot object, hashed and read for its facts on the way → pending
func (r *Router) snapStream(ctx context.Context, machine string, body io.Reader) (string, int64, error) {
	key := snapKey(machine)
	h := sha256.New()
	var n int64
	pr, pw := io.Pipe()
	factsDone := make(chan *snapshotFacts, 1)
	go func() {
		f, err := readSnapshotFactsFrom(pr)
		if err != nil {
			f = nil
		}
		io.Copy(io.Discard, pr) // whatever the reader left: the upload must not stall on the pipe
		factsDone <- f
	}()
	tee := io.TeeReader(io.LimitReader(body, snapshotMax+1), io.MultiWriter(h, pw, writerFunc(func(p []byte) { n += int64(len(p)) })))
	err := r.objects.Put(ctx, key, tee, -1)
	pw.Close()
	facts := <-factsDone
	if err == nil && n > snapshotMax {
		err = fmt.Errorf("body over %d bytes", int64(snapshotMax))
	}
	if err != nil {
		return "", n, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	fb, _ := json.Marshal(facts)
	if facts == nil {
		fb = nil
	}
	dctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = r.pool().pool.Exec(dctx, `INSERT INTO snapshots (machine_id, object_key, sha256, sig, bytes, state, facts) VALUES ($1, $2, $3, '', $4, 'pending', $5)
		ON CONFLICT (machine_id) DO UPDATE SET object_key = excluded.object_key, sha256 = excluded.sha256, sig = '', bytes = excluded.bytes,
		state = 'pending', facts = excluded.facts, committed_at = NULL`, machine, key, sum, n, fb)
	return sum, n, err
}

type writerFunc func(p []byte)

func (f writerFunc) Write(p []byte) (int, error) { f(p); return len(p), nil }

// snapCommit: the pending snapshot with this sha256, signed by the machine → committed
func (r *Router) snapCommit(machine, sum, sig string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tag, err := r.pool().pool.Exec(ctx, `UPDATE snapshots SET state = 'committed', sig = $3, committed_at = now() WHERE machine_id = $1 AND sha256 = $2`,
		machine, sum, sig)
	if err == nil && tag.RowsAffected() != 1 {
		err = errNoSnap
	}
	return err
}

var errNoSnap = errors.New("no streamed snapshot with that sha256")

// snapCarry: the machine's snapshot is its predecessor's object (a booting machine's state), signed by the machine
func (r *Router) snapCarry(machine, pred, sum, sig string) error {
	p := r.snap(pred)
	if p == nil || p.State != "committed" || p.Sha256 != sum {
		return fmt.Errorf("the predecessor %s has no committed snapshot with that sha256", pred)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := r.pool().pool.Exec(ctx, `INSERT INTO snapshots (machine_id, object_key, sha256, sig, bytes, state, facts, committed_at)
		SELECT $1, object_key, sha256, $2, bytes, 'committed', facts, now() FROM snapshots WHERE machine_id = $3
		ON CONFLICT (machine_id) DO UPDATE SET object_key = excluded.object_key, sha256 = excluded.sha256, sig = excluded.sig,
		bytes = excluded.bytes, state = 'committed', facts = excluded.facts, committed_at = now()`, machine, sig, pred)
	return err
}

// snapPutWhole: a whole committed snapshot from a reader (the older POST /m/snapshot, imports, tests)
func (r *Router) snapPutWhole(machine string, body io.Reader, sig string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	sum, _, err := r.snapStream(ctx, machine, body)
	if err != nil {
		return err
	}
	return r.snapCommit(machine, sum, sig)
}

// snapOpen: the snapshot's bytes
func (r *Router) snapOpen(ctx context.Context, s *Snap) (objectReader, error) {
	return r.objects.Get(ctx, s.Key)
}

// snapFacts: what the snapshot holds (read when it streamed in; read now from the object when it wasn't)
func (r *Router) snapFacts(s *Snap) (*snapshotFacts, error) {
	if s.Facts != nil {
		return s.Facts, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	rd, err := r.snapOpen(ctx, s)
	if err != nil {
		return nil, err
	}
	defer rd.Close()
	f, err := readSnapshotFactsFrom(rd)
	if err != nil {
		return nil, err
	}
	fb, _ := json.Marshal(f)
	r.pool().pool.Exec(ctx, "UPDATE snapshots SET facts = $2 WHERE object_key = $1", s.Key, fb)
	return f, nil
}

// snapToFile: the snapshot copied to a scratch file, its signature beside it (.sig) (the archive walks it several
// times); the caller removes both
func (r *Router) snapToFile(s *Snap, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "snap-*.tar.gz")
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	rd, err := r.snapOpen(ctx, s)
	if err == nil {
		_, err = io.Copy(f, rd)
		rd.Close()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.WriteFile(f.Name()+".sig", []byte(s.Sig), 0o600) // the archive copies it beside (jarvis2/snapshot.sig)
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// snapDrop: the machine's snapshot row gone, and its object once no other row names it
func (r *Router) snapDrop(machine string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var key string
	err := r.pool().pool.QueryRow(ctx, "DELETE FROM snapshots WHERE machine_id = $1 RETURNING object_key", machine).Scan(&key)
	if err != nil {
		if err != pgx.ErrNoRows {
			log.Printf("snapshots: dropping %s: %v", machine, err)
		}
		return
	}
	var others bool
	r.pool().pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM snapshots WHERE object_key = $1)", key).Scan(&others)
	if !others {
		if err := r.objects.Delete(ctx, key); err != nil {
			log.Printf("snapshots: deleting %s: %v", key, err)
		}
	}
}

// importSnapshotFiles: the volume's snapshots/ (committed ones: a .tar.gz with its .sig) into the bucket and the table,
// once; then the directory is set aside (.imported)
func (r *Router) importSnapshotFiles() error {
	d := snapDirOnVolume(r)
	ents, err := os.ReadDir(d)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	n := 0
	for _, e := range ents {
		name := e.Name()
		if len(name) <= len(".tar.gz") || name[len(name)-len(".tar.gz"):] != ".tar.gz" {
			continue
		}
		m := name[:len(name)-len(".tar.gz")]
		sig, err := os.ReadFile(d + "/" + m + ".tar.gz.sig")
		if err != nil || r.snap(m) != nil {
			continue
		}
		f, err := os.Open(d + "/" + name)
		if err != nil {
			return err
		}
		err = r.snapPutWhole(m, f, string(trimSpace(sig)))
		f.Close()
		if err != nil {
			return fmt.Errorf("import snapshot %s: %v", m, err)
		}
		n++
	}
	for _, e := range ents {
		name := e.Name()
		if len(name) > len(".carry") && name[len(name)-len(".carry"):] == ".carry" {
			if b, err := os.ReadFile(d + "/" + name); err == nil {
				r.saveCarry(name[:len(name)-len(".carry")], string(b))
			}
		}
	}
	if err := os.Rename(d, d+".imported"); err != nil {
		return err
	}
	log.Printf("snapshots: %s: %d committed snapshots into the bucket", d, n)
	return nil
}

func snapDirOnVolume(r *Router) string { return r.cfg.DataDir + "/snapshots" }

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// snapFactsOf: the facts of the machine's snapshot
func (r *Router) snapFactsOf(machine string) (*snapshotFacts, error) {
	s := r.snap(machine)
	if s == nil {
		return nil, fmt.Errorf("no snapshot of %s", machine)
	}
	return r.snapFacts(s)
}

// snapsLike: the machine ids of rows that start with prefix (the restores' rows)
func (r *Router) snapsLike(prefix string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := r.pool().pool.Query(ctx, "SELECT machine_id FROM snapshots WHERE starts_with(machine_id, $1)", prefix)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var m string
		if rows.Scan(&m) == nil {
			out = append(out, m)
		}
	}
	return out
}
