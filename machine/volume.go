package main

// The machine's volume (core/volumes.go): a machine the core made with a Fly volume finds it mounted at /data. The
// session's state — what the snapshot holds — lives on it: each of the snapshot's directories is bind-mounted from
// /data/home/<path> onto ~/<path> (the paths stay the same for every program, so Claude's project directory names
// don't change), and the snapshot's single files (~/.claude.json and the Jarvis records), which programs replace by
// rename and so can't be bind-mounted, are copied to /data/home/ every minute and right before the final snapshot.
//
// The volume is always new and empty at boot: no resume reads it (a successor's state is its predecessor's signed
// snapshot, restored onto the bind-mounted paths, so onto its own volume). Whatever the image put at those paths is
// copied onto the volume first. Without a volume nothing changes. The bind mounts need root: the image's claude has
// passwordless sudo.

import (
	"bufio"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	volumeRoot  = "/data"
	mountsFile  = "/proc/self/mountinfo"
	runPriviled = func(args ...string) error { // sudo: the bind mounts and the volume's owner
		out, err := exec.Command("sudo", append([]string{"-n"}, args...)...).CombinedOutput()
		if err != nil {
			return &cmdErr{strings.Join(args, " "), strings.TrimSpace(string(out)), err}
		}
		return nil
	}
	mirrorEvery = time.Minute
)

type cmdErr struct {
	cmd, out string
	err      error
}

func (e *cmdErr) Error() string { return e.cmd + ": " + e.err.Error() + " " + e.out }

// hasVolume: /data is a mount point (Fly mounts the volume there; nothing else does)
func hasVolume() bool {
	f, err := os.Open(mountsFile)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fs := strings.Fields(sc.Text()); len(fs) > 4 && fs[4] == volumeRoot {
			return true
		}
	}
	return false
}

// volumeSplit: the snapshot's paths that are directories (bind-mounted) and files (mirrored)
func volumeSplit() (dirs, files []string) {
	single := map[string]bool{".claude.json": true, ".claude/.first-prompt-sent": true, ".claude/.paseo-agent": true,
		allowFile: true, changesFile: true, lineKeysFile: true, deliveredFile: true}
	for _, rel := range snapshotPaths {
		if single[rel] {
			files = append(files, rel)
		} else {
			dirs = append(dirs, rel)
		}
	}
	return
}

// setupVolume: at boot, before the predecessor's snapshot is restored: the state's directories onto the volume.
// false: no volume (or it couldn't be set up: logged, and the machine runs on its root disk as before).
func setupVolume() bool {
	if !hasVolume() {
		return false
	}
	home, _ := os.UserHomeDir()
	if err := runPriviled("chown", strconv.Itoa(os.Getuid())+":"+strconv.Itoa(os.Getgid()), volumeRoot); err != nil {
		log.Printf("volume: %v; the state stays on the root disk", err)
		return false
	}
	dirs, _ := volumeSplit()
	n := 0
	for _, rel := range dirs {
		src, dst := filepath.Join(volumeRoot, "home", rel), filepath.Join(home, rel)
		if err := os.MkdirAll(src, 0o755); err != nil {
			log.Printf("volume: %s: %v", rel, err)
			continue
		}
		if err := os.MkdirAll(dst, 0o755); err != nil {
			log.Printf("volume: %s: %v", rel, err)
			continue
		}
		// what the image has there goes onto the volume first (cp -a keeps modes, links and times)
		if ents, _ := os.ReadDir(dst); len(ents) > 0 {
			if out, err := sessionCommand(nil, "cp", "-a", dst+"/.", src+"/").CombinedOutput(); err != nil {
				log.Printf("volume: copying the image's %s: %v %s", rel, err, out)
				continue
			}
		}
		if err := runPriviled("mount", "--bind", src, dst); err != nil {
			log.Printf("volume: %v", err)
			continue
		}
		n++
	}
	predecessorTmp = filepath.Join(volumeRoot, ".predecessor.tar.gz") // a multi-GB download lands on the volume
	log.Printf("volume: %d of %d state directories on %s", n, len(dirs), volumeRoot)
	go func() {
		for ; ; time.Sleep(mirrorEvery) {
			mirrorVolumeFiles()
		}
	}()
	return true
}

// mirrorVolumeFiles: the snapshot's single files copied onto the volume (only on a machine with one)
func mirrorVolumeFiles() {
	if !hasVolume() {
		return
	}
	home, _ := os.UserHomeDir()
	_, files := volumeSplit()
	for _, rel := range files {
		b, err := os.ReadFile(filepath.Join(home, rel))
		if err != nil {
			continue
		}
		dst := filepath.Join(volumeRoot, "home", rel)
		if old, err := os.ReadFile(dst); err == nil && string(old) == string(b) {
			continue
		}
		os.MkdirAll(filepath.Dir(dst), 0o755)
		tmp := dst + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			os.Rename(tmp, dst)
		}
	}
}
