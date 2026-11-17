package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/doc"
)

// A fabric machine (docs/PLAN-fabric.md): its object is fabric-<its id>, its keys line goes to the sandbox's console,
// and its snapshot carries the Jarvis records and the other small files only: the directories stay on the fabric's
// network filesystem, and a restore writes the signed records over the shared disk's copies without touching the rest.
func TestFabricMachine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("JARVIS2_RUNNER", "fabric")
	t.Setenv("JARVIS2_MACHINE_ID", "x0190f6c25b1e7a3c9d4e1f2a3b4c5d6e")
	if !onFabric() || onAWS() || machineID() != "x0190f6c25b1e7a3c9d4e1f2a3b4c5d6e" {
		t.Fatal("not a fabric machine")
	}
	if o := machineObject(machineID()); o != "fabric-x0190f6c25b1e7a3c9d4e1f2a3b4c5d6e" || o.Kind() != "machine" || o.Runner() != "fabric" {
		t.Fatalf("object %q", o)
	}
	if keysConsole() != fabricConsolePath {
		t.Fatalf("keys line to %s", keysConsole())
	}
	for _, rel := range statePaths() {
		if !snapshotFiles[rel] {
			t.Fatalf("%s in a fabric snapshot", rel)
		}
	}
	for _, rel := range []string{allowFile, lineKeysFile, deliveredFile, changesFile, ".claude.json"} {
		found := false
		for _, p := range statePaths() {
			found = found || p == rel
		}
		if !found {
			t.Fatalf("%s not in a fabric snapshot", rel)
		}
	}
	os.MkdirAll(filepath.Join(home, "workspace", "repo"), 0o755)
	os.WriteFile(filepath.Join(home, "workspace", "repo", "f.txt"), []byte("on the network filesystem"), 0o644)
	os.MkdirAll(filepath.Join(home, ".claude", "projects", "p"), 0o755)
	os.WriteFile(filepath.Join(home, ".claude", "projects", "p", "t.jsonl"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(home, allowFile), []byte(`{"signed":"grant"}`), 0o600)
	os.WriteFile(filepath.Join(home, deliveredFile), []byte(`["d1"]`), 0o600)
	var snap bytes.Buffer
	if _, _, err := writeSnapshot(&snap); err != nil {
		t.Fatal(err)
	}
	// the shared disk's copies change after the snapshot (another writer, an older copy): the restore puts the signed
	// records back and leaves the directories as the disk has them
	os.WriteFile(filepath.Join(home, allowFile), []byte(`{"forged":"grant"}`), 0o600)
	os.WriteFile(filepath.Join(home, deliveredFile), []byte(`[]`), 0o600)
	os.WriteFile(filepath.Join(home, "workspace", "repo", "f.txt"), []byte("newer work"), 0o644)
	n, err := unpack(snap.Bytes())
	if err != nil || n != 2 {
		t.Fatalf("restored %d files: %v", n, err)
	}
	for rel, want := range map[string]string{allowFile: `{"signed":"grant"}`, deliveredFile: `["d1"]`, "workspace/repo/f.txt": "newer work"} {
		if b, _ := os.ReadFile(filepath.Join(home, rel)); string(b) != want {
			t.Fatalf("%s: %q", rel, b)
		}
	}

	// the other runners keep the whole snapshot
	t.Setenv("JARVIS2_RUNNER", "")
	if len(statePaths()) != len(snapshotPaths) || machineObject("abc123") != doc.Object("fly-abc123") || keysConsole() != consolePath {
		t.Fatal("a Fly machine changed")
	}
	t.Setenv("JARVIS2_RUNNER", "aws")
	if len(statePaths()) != len(snapshotPaths) || machineObject("i-0abc") != doc.Object("aws-i-0abc") {
		t.Fatal("an AWS machine changed")
	}
}
