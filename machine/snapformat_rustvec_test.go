package main

// The snapshot format against the Rust port (rust/machine/src/snapformat.rs), both ways: rust/machine/tests/vectors/
// go-s2.bin is an S2 stream this package wrote (flushed mid-way, as writeSnapshot flushes after each root), checked
// by the Rust tests; rust-s2.bin what the Rust port wrote, read here. GEN_RUST_VECTORS=1 writes go-s2.bin again.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const snapVecDir = "../rust/machine/tests/vectors"

// snapVecContent: the plain bytes both sides compress: text with repeats (S2's repeat offsets), then 64 KB from an
// LCG (literals), then text again; the Rust test makes the same bytes
func snapVecContent() []byte {
	var b bytes.Buffer
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&b, "line %d of the snapshot vector %s\n", i, strings.Repeat("ab", i%37))
	}
	x := uint32(1)
	for i := 0; i < 65536; i++ {
		x = x*1664525 + 1013904223
		b.WriteByte(byte(x >> 24))
	}
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&b, "tail %d %s\n", i, strings.Repeat("xyz", i%11))
	}
	return b.Bytes()
}

func TestSnapFormatRustVectors(t *testing.T) {
	plain := snapVecContent()
	if os.Getenv("GEN_RUST_VECTORS") == "1" {
		var out bytes.Buffer
		w, _ := newSnapWriter(&out)
		half := len(plain) / 2
		w.Write(plain[:half])
		w.Flush()
		w.Write(plain[half:])
		w.Close()
		if err := os.WriteFile(filepath.Join(snapVecDir, "go-s2.bin"), out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256(plain)
	b, err := os.ReadFile(filepath.Join(snapVecDir, "rust-s2.bin"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := openSnapReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("the Rust S2 stream doesn't read in Go: %v", err)
	}
	if g := sha256.Sum256(got); hex.EncodeToString(g[:]) != hex.EncodeToString(sum[:]) {
		t.Fatalf("the Rust S2 stream reads as other bytes (%d of %d)", len(got), len(plain))
	}
}
