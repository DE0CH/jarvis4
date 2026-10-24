package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// every path the snapshot holds goes onto the volume: directories bind-mounted, single files mirrored
func TestTheVolumeHoldsEverySnapshotPath(t *testing.T) {
	dirs, files := volumeSplit()
	if len(dirs)+len(files) != len(snapshotPaths) {
		t.Fatalf("%d + %d of %d", len(dirs), len(files), len(snapshotPaths))
	}
	for _, f := range []string{".claude.json", allowFile, deliveredFile} {
		if !strings.Contains(strings.Join(files, " "), f) {
			t.Fatalf("%s isn't mirrored: %v", f, files)
		}
	}
	for _, d := range []string{"workspace", "artifacts", ".claude/projects"} {
		if !strings.Contains(strings.Join(dirs, " "), d) {
			t.Fatalf("%s isn't bind-mounted: %v", d, dirs)
		}
	}
}

// with /data mounted, boot puts the state directories onto it (the image's files copied first) and mirrors the files
func TestSetupVolumeBindMountsTheState(t *testing.T) {
	home, data := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	mi := filepath.Join(t.TempDir(), "mountinfo")
	oldRoot, oldMI, oldRun, oldTmp := volumeRoot, mountsFile, runPriviled, predecessorTmp
	defer func() { volumeRoot, mountsFile, runPriviled, predecessorTmp = oldRoot, oldMI, oldRun, oldTmp }()
	volumeRoot, mountsFile = data, mi
	var cmds []string
	runPriviled = func(args ...string) error { cmds = append(cmds, strings.Join(args, " ")); return nil }
	if setupVolume() {
		t.Fatal("a volume without a mount")
	}
	os.WriteFile(mi, []byte("36 35 0:1 / "+data+" rw - ext4 /dev/vdb rw\n"), 0o644)
	os.MkdirAll(filepath.Join(home, "artifacts"), 0o755)
	os.WriteFile(filepath.Join(home, "artifacts", "from-image"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"a":1}`), 0o644)
	if !setupVolume() {
		t.Fatal("no volume set up")
	}
	if b, _ := os.ReadFile(filepath.Join(data, "home", "artifacts", "from-image")); string(b) != "x" {
		t.Fatal("the image's files weren't copied onto the volume")
	}
	if !strings.Contains(strings.Join(cmds, "\n"), "mount --bind "+filepath.Join(data, "home", "workspace")+" "+filepath.Join(home, "workspace")) {
		t.Fatalf("commands %v", cmds)
	}
	mirrorVolumeFiles()
	if b, _ := os.ReadFile(filepath.Join(data, "home", ".claude.json")); string(b) != `{"a":1}` {
		t.Fatal("~/.claude.json isn't mirrored")
	}
	if predecessorTmp != filepath.Join(data, ".predecessor.tar.gz") {
		t.Fatal(predecessorTmp)
	}
}

// /run/jarvis on a Fly machine: a tmpfs of its own, so the machine's key pair is in memory only (DECISIONS 228); the
// keeper started again in the same boot leaves it (and the keys in it) as they are. Needs root (mount): skipped otherwise.
func TestMemoryDirIsATmpfs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to mount")
	}
	d := t.TempDir()
	if err := memoryDir(d); err != nil {
		t.Fatal(err)
	}
	defer syscall.Unmount(d, 0)
	var fs syscall.Statfs_t
	syscall.Statfs(d, &fs)
	if fs.Type != 0x01021994 {
		t.Fatalf("not a tmpfs: %x", fs.Type)
	}
	os.WriteFile(filepath.Join(d, "private.json"), []byte("k"), 0o600)
	if err := memoryDir(d); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "private.json")); string(b) != "k" {
		t.Fatal("mounted again over the keys")
	}
}
