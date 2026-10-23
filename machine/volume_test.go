package main

import (
	"os"
	"path/filepath"
	"strings"
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
	if setupVolume(false) {
		t.Fatal("a volume without a mount")
	}
	os.WriteFile(mi, []byte("36 35 0:1 / "+data+" rw - ext4 /dev/vdb rw\n"), 0o644)
	os.MkdirAll(filepath.Join(home, "artifacts"), 0o755)
	os.WriteFile(filepath.Join(home, "artifacts", "from-image"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"a":1}`), 0o644)
	if !setupVolume(false) {
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

// the same machine started again on its own volume: its kept keys are its own (another machine's are not), the image's
// files don't go over the session's state, and the single files come back from the volume
func TestStartedAgainOnItsVolume(t *testing.T) {
	home, data := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("FLY_MACHINE_ID", "m1")
	mi := filepath.Join(t.TempDir(), "mountinfo")
	oldRoot, oldMI, oldRun, oldTmp := volumeRoot, mountsFile, runPriviled, predecessorTmp
	defer func() { volumeRoot, mountsFile, runPriviled, predecessorTmp = oldRoot, oldMI, oldRun, oldTmp }()
	volumeRoot, mountsFile = data, mi
	runPriviled = func(args ...string) error {
		if args[0] == "install" { // install -d … DIR
			return os.MkdirAll(args[len(args)-1], 0o700)
		}
		return nil
	}
	keepOwnKeys([]byte("priv"), []byte("pub"))
	if _, _, ok := keptOwnKeys(); ok {
		t.Fatal("keys kept without a volume")
	}
	os.WriteFile(mi, []byte("36 35 0:1 / "+data+" rw - ext4 /dev/vdb rw\n"), 0o644)
	keepOwnKeys([]byte("priv"), []byte("pub"))
	if priv, pub, ok := keptOwnKeys(); !ok || string(priv) != "priv" || string(pub) != "pub" {
		t.Fatal("the machine's own kept keys weren't found")
	}
	if fi, err := os.Stat(selfDir()); err != nil || !strings.HasPrefix(selfDir(), data) || fi.Mode().Perm() != 0o700 {
		t.Fatal(err)
	}
	t.Setenv("FLY_MACHINE_ID", "m2")
	if _, _, ok := keptOwnKeys(); ok {
		t.Fatal("another machine's keys were taken")
	}
	// the session's state on the volume; the image has its own copy of the same paths
	os.MkdirAll(filepath.Join(data, "home", "artifacts"), 0o755)
	os.WriteFile(filepath.Join(data, "home", "artifacts", "work"), []byte("mine"), 0o644)
	os.WriteFile(filepath.Join(data, "home", ".claude.json"), []byte(`{"session":1}`), 0o600)
	os.MkdirAll(filepath.Join(home, "artifacts"), 0o755)
	os.WriteFile(filepath.Join(home, "artifacts", "work"), []byte("image"), 0o644)
	os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"image":1}`), 0o644)
	if !setupVolume(true) {
		t.Fatal("no volume set up")
	}
	if b, _ := os.ReadFile(filepath.Join(data, "home", "artifacts", "work")); string(b) != "mine" {
		t.Fatalf("the image's files went over the session's: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(home, ".claude.json")); string(b) != `{"session":1}` {
		t.Fatalf("~/.claude.json didn't come back from the volume: %q", b)
	}
}
