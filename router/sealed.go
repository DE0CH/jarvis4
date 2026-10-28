package main

// The router's secrets in the database, sealed (docs/STATE.md 2.3): the Claude accounts (claude-accounts/accounts.json
// and each account's OAuth pair claude-accounts/claude-<name>.json, claudeaccounts.go, claudelogin.go) and the holder
// keys (holders/<name>.key, grants.go). The router holds them in plaintext (it refreshes the logins, it signs as the
// holders), but the database and its S3 backups only ever see AES-256-GCM ciphertext under the seal key: ROUTER_SEAL_KEY
// (base64, 32 bytes; Secret router-seal, infra/router-secrets.py --part seal; JARVIS4_ROUTER_SEAL_KEY in the infra
// store). Each row names its key (key_id = the key's sha256, first 16 hex) and binds its name as additional data, so a
// row can't be moved to another name. A rotation: ROUTER_SEAL_KEY the new key, ROUTER_SEAL_KEY_OLD the previous one;
// rows under the old key are read with it and resealed under the new one at start.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type sealKey struct {
	id   string
	aead cipher.AEAD
}

// Sealer: the current seal key and the previous one (a rotation)
type Sealer struct {
	cur, old *sealKey
}

func newSealKey(raw []byte) (*sealKey, error) {
	if len(raw) != 32 {
		return nil, fmt.Errorf("a seal key is 32 bytes, not %d", len(raw))
	}
	b, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(raw)
	return &sealKey{id: hex.EncodeToString(h[:8]), aead: g}, nil
}

// sealerFromEnv: ROUTER_SEAL_KEY (and ROUTER_SEAL_KEY_OLD); a throwaway router (ROUTER_THROWAWAY=1) with none gets a
// random key for its life
func sealerFromEnv() (*Sealer, error) {
	cur := os.Getenv("ROUTER_SEAL_KEY")
	if cur == "" {
		if os.Getenv("ROUTER_THROWAWAY") != "1" {
			return nil, errors.New("ROUTER_SEAL_KEY is required (Secret router-seal), or ROUTER_THROWAWAY=1 for a throwaway router")
		}
		return randomSealer(), nil
	}
	s := &Sealer{}
	for _, x := range []struct {
		v  string
		to **sealKey
	}{{cur, &s.cur}, {os.Getenv("ROUTER_SEAL_KEY_OLD"), &s.old}} {
		if x.v == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(x.v))
		if err != nil {
			return nil, fmt.Errorf("seal key: not base64")
		}
		if *x.to, err = newSealKey(raw); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func randomSealer() *Sealer {
	raw := make([]byte, 32)
	rand.Read(raw)
	k, _ := newSealKey(raw)
	return &Sealer{cur: k}
}

func (s *Sealer) seal(name string, plain []byte) (keyID string, nonce, body []byte) {
	nonce = make([]byte, s.cur.aead.NonceSize())
	rand.Read(nonce)
	return s.cur.id, nonce, s.cur.aead.Seal(nil, nonce, plain, []byte(name))
}

func (s *Sealer) open(name, keyID string, nonce, body []byte) ([]byte, error) {
	for _, k := range []*sealKey{s.cur, s.old} {
		if k != nil && k.id == keyID {
			return k.aead.Open(nil, nonce, body, []byte(name))
		}
	}
	return nil, fmt.Errorf("sealed %s: under key %s, which this router doesn't have", name, keyID)
}

// ---- on the State ------------------------------------------------------------------------------------------------

// ReadSealed: a sealed document, opened (ok false: none)
func (s *State) ReadSealed(name string) ([]byte, bool, error) {
	if s == nil || s.sdb == nil || s.seal == nil {
		return nil, false, errors.New("sealed: no database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var kid string
	var nonce, body []byte
	err := s.sdb.db.pool.QueryRow(ctx, "SELECT key_id, nonce, body FROM sealed_docs WHERE name = $1", name).Scan(&kid, &nonce, &body)
	if err == pgx.ErrNoRows {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	b, err := s.seal.open(name, kid, nonce, body)
	return b, err == nil, err
}

// WriteSealed: a document sealed and stored (replacing)
func (s *State) WriteSealed(name string, plain []byte) error {
	if s == nil || s.sdb == nil || s.seal == nil {
		return errors.New("sealed: no database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	kid, nonce, body := s.seal.seal(name, plain)
	_, err := s.sdb.db.pool.Exec(ctx, `INSERT INTO sealed_docs (name, key_id, nonce, body, updated_at) VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (name) DO UPDATE SET key_id = excluded.key_id, nonce = excluded.nonce, body = excluded.body, updated_at = now()`, name, kid, nonce, body)
	return err
}

// notifyMQ: a notification on the mq channel (mq.go), for the other replica's waiters; best effort
func (s *State) notifyMQ(payload string) {
	if s == nil || s.sdb == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := s.sdb.db.pool.Exec(ctx, "SELECT pg_notify('mq', $1)", payload); err != nil {
		log.Printf("mq: notify %s: %v", payload, err)
	}
}

// DeleteSealed: gone
func (s *State) DeleteSealed(name string) error {
	if s == nil || s.sdb == nil {
		return errors.New("sealed: no database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := s.sdb.db.pool.Exec(ctx, "DELETE FROM sealed_docs WHERE name = $1", name)
	return err
}

// ListSealed: the names under prefix
func (s *State) ListSealed(prefix string) ([]string, error) {
	if s == nil || s.sdb == nil {
		return nil, errors.New("sealed: no database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := s.sdb.db.pool.Query(ctx, "SELECT name FROM sealed_docs WHERE starts_with(name, $1) ORDER BY name", prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			out = append(out, n)
		}
	}
	return out, rows.Err()
}

// resealOld: rows under the previous key, resealed under the current one (a rotation's second half)
func (s *State) resealOld(ctx context.Context) error {
	if s.seal.old == nil {
		return nil
	}
	rows, err := s.sdb.db.pool.Query(ctx, "SELECT name FROM sealed_docs WHERE key_id <> $1", s.seal.cur.id)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			names = append(names, n)
		}
	}
	rows.Close()
	for _, n := range names {
		b, ok, err := s.ReadSealed(n)
		if err != nil || !ok {
			return fmt.Errorf("reseal %s: %v", n, err)
		}
		if err := s.WriteSealed(n, b); err != nil {
			return err
		}
	}
	if len(names) > 0 {
		log.Printf("sealed: %d documents resealed under key %s", len(names), s.seal.cur.id)
	}
	return nil
}

// importSealedFiles: claude-accounts/ and holders/ on the volume, sealed into the database once (a name already there
// wins), then the plaintext files removed
func (s *State) importSealedFiles(dir string) error {
	for _, sub := range []string{"claude-accounts", "holders"} {
		d := filepath.Join(dir, sub)
		if _, err := os.Stat(d); os.IsNotExist(err) {
			continue
		}
		n := 0
		err := filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() || strings.HasSuffix(e.Name(), ".tmp") {
				return err
			}
			rel, _ := filepath.Rel(dir, p)
			name := filepath.ToSlash(rel)
			if _, ok, err := s.ReadSealed(name); err != nil || ok {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			n++
			return s.WriteSealed(name, b)
		})
		if err != nil {
			return fmt.Errorf("import %s: %v", d, err)
		}
		if err := os.RemoveAll(d); err != nil {
			return err
		}
		log.Printf("sealed: %s: %d files sealed into the database, the plaintext removed", d, n)
	}
	return nil
}
