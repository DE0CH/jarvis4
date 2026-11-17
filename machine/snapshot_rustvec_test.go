package main

// Whole snapshots against the Rust port (rust/machine/src/tests/snapvectors.rs), both ways: a Go machine's snapshot
// restores on a Rust machine (a Rust successor of a Go predecessor, and every snapshot already stored) and a Rust
// machine's on a Go one (a rollback). rust/machine/tests/vectors/go-snapshot.bin is writeSnapshot of the fixture home
// below, rust-snapshot.bin what the Rust port wrote of the same home; each side unpacks the other's and compares the
// tree. GEN_RUST_VECTORS=1 writes go-snapshot.bin again.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// snapFixture: a home with what a tar writer must get right: long names (over 100 bytes, and a 255-byte file name),
// non-ASCII, an executable, a symlink, an empty directory, a file over several blocks, fixed modification times
func snapFixture(t *testing.T, home string) {
	mt := time.Unix(1791700000, 0)
	long := filepath.Join("workspace", "repo", strings.Repeat("d", 60), strings.Repeat("e", 60), strings.Repeat("f", 255))
	big := make([]byte, 300<<10)
	x := uint32(7)
	for i := range big {
		x = x*1664525 + 1013904223
		big[i] = byte(x >> 24)
	}
	files := []struct {
		rel  string
		body []byte
		mode os.FileMode
	}{
		{"workspace/repo/a.txt", []byte("hello\n"), 0o644},
		{"workspace/repo/tool.bin", []byte("\x7fELF not really\n"), 0o755},
		{"workspace/repo/名前 with space.txt", []byte("unicode\n"), 0o600},
		{long, []byte("deep\n"), 0o644},
		{".claude/projects/p/c.jsonl", []byte("{\"type\":\"user\"}\n"), 0o600},
		{".claude.json", []byte("{}"), 0o600},
		{"artifacts/big.bin", big, 0o644},
	}
	for _, f := range files {
		p := filepath.Join(home, f.rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, f.body, f.mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, f.mode)
		os.Chtimes(p, mt, mt)
	}
	os.MkdirAll(filepath.Join(home, "workspace", "empty"), 0o755)
	os.Symlink("a.txt", filepath.Join(home, "workspace", "repo", "link"))
}

// snapManifest: every entry under home, one line each: path, kind, mode, size, sha256 and time (files), target (links)
func snapManifest(home string) string {
	var lines []string
	filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == home {
			return nil
		}
		rel, _ := filepath.Rel(home, p)
		fi, _ := os.Lstat(p)
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			l, _ := os.Readlink(p)
			lines = append(lines, fmt.Sprintf("%s link %s", rel, l))
		case fi.IsDir():
			lines = append(lines, fmt.Sprintf("%s dir", rel))
		default:
			b, _ := os.ReadFile(p)
			s := sha256.Sum256(b)
			lines = append(lines, fmt.Sprintf("%s file %o %d %s %d", rel, fi.Mode().Perm(), fi.Size(), hex.EncodeToString(s[:8]), fi.ModTime().Unix()))
		}
		return nil
	})
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func TestSnapshotRustVectors(t *testing.T) {
	src := t.TempDir()
	snapFixture(t, src)
	want := snapManifest(src)
	if os.Getenv("GEN_RUST_VECTORS") == "1" {
		t.Setenv("HOME", src)
		f, err := os.Create(filepath.Join(snapVecDir, "go-snapshot.bin"))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := writeSnapshot(f); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	for _, name := range []string{"go-snapshot.bin", "rust-snapshot.bin"} {
		dst := t.TempDir()
		t.Setenv("HOME", dst)
		f, err := os.Open(filepath.Join(snapVecDir, name))
		if err != nil {
			t.Fatal(err)
		}
		_, err = unpackReader(f)
		f.Close()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := snapManifest(dst); got != want {
			t.Fatalf("%s restores as\n%s\nwant\n%s", name, got, want)
		}
	}
}
