package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sealed documents: never in the clear in the database, bound to their name, read under the previous key and resealed
// under the new one after a rotation; the volume's files sealed in once and their plaintext removed
func TestSealedDocs(t *testing.T) {
	url := testDBURL(t)
	ctx := context.Background()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "holders"), 0o700)
	os.WriteFile(filepath.Join(dir, "holders", "a.key"), []byte("holder-key-bytes"), 0o600)
	k1, k2 := make([]byte, 32), make([]byte, 32)
	rand.Read(k1)
	rand.Read(k2)
	t.Setenv("ROUTER_SEAL_KEY", base64.StdEncoding.EncodeToString(k1))
	s1, err := sealerFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	db, err := OpenDB(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, err := OpenState(ctx, db, dir, s1)
	if err != nil {
		t.Fatal(err)
	}
	if b, ok, err := st.ReadSealed("holders/a.key"); !ok || err != nil || string(b) != "holder-key-bytes" {
		t.Fatalf("imported: %q %v %v", b, ok, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "holders")); !os.IsNotExist(err) {
		t.Fatal("the plaintext holder keys stayed on the volume")
	}
	st.WriteSealed("claude-accounts/claude-main.json", []byte(`{"refreshToken":"sk-ant-ort-secret"}`))
	var body []byte
	var kid string
	db.pool.QueryRow(ctx, "SELECT key_id, body FROM sealed_docs WHERE name = 'claude-accounts/claude-main.json'").Scan(&kid, &body)
	if strings.Contains(string(body), "secret") || kid != s1.cur.id {
		t.Fatal("the row isn't sealed under the current key")
	}
	// a row moved to another name doesn't open
	db.pool.Exec(ctx, "UPDATE sealed_docs SET name = 'claude-accounts/claude-x.json' WHERE name = 'claude-accounts/claude-main.json'")
	if _, ok, err := st.ReadSealed("claude-accounts/claude-x.json"); ok || err == nil {
		t.Fatal("a row opened under another name")
	}
	db.pool.Exec(ctx, "UPDATE sealed_docs SET name = 'claude-accounts/claude-main.json' WHERE name = 'claude-accounts/claude-x.json'")
	// a rotation: the new key current, the old one beside it; every row resealed at start
	t.Setenv("ROUTER_SEAL_KEY", base64.StdEncoding.EncodeToString(k2))
	t.Setenv("ROUTER_SEAL_KEY_OLD", base64.StdEncoding.EncodeToString(k1))
	s2, _ := sealerFromEnv()
	st2, err := OpenState(ctx, db, dir, s2)
	if err != nil {
		t.Fatal(err)
	}
	var old int
	db.pool.QueryRow(ctx, "SELECT count(*) FROM sealed_docs WHERE key_id <> $1", s2.cur.id).Scan(&old)
	if b, ok, _ := st2.ReadSealed("claude-accounts/claude-main.json"); !ok || old != 0 || !strings.Contains(string(b), "sk-ant-ort-secret") {
		t.Fatalf("after the rotation: %q, %d rows under another key", b, old)
	}
	// without the old key now: still readable (all resealed)
	t.Setenv("ROUTER_SEAL_KEY_OLD", "")
	s3, _ := sealerFromEnv()
	st3, _ := OpenState(ctx, db, dir, s3)
	if _, ok, _ := st3.ReadSealed("holders/a.key"); !ok {
		t.Fatal("a row is still under the old key")
	}
	// no key and not a throwaway router: refused
	t.Setenv("ROUTER_SEAL_KEY", "")
	if _, err := sealerFromEnv(); err == nil {
		t.Fatal("no seal key was taken")
	}
}
