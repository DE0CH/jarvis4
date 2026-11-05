package main

// An AWS machine's own logs to Grafana (router/awslogs.go; docs/PLAN-aws.md "Logs"). On Fly, Fly reads the machine's
// stdout and stderr on its platform and the Fly app jarvis2-log-shipper takes them to Grafana; an EC2 instance's
// container output goes only to the instance's journal, so on AWS the machine sends it itself, through the router:
//
//   - its output: the keeper (PID 1) makes fd 1 and 2 a pipe at its start (teeOutput), so its own lines and every
//     child's that inherits them (the boot steps, both supervisors, the harness's console lines) pass through it; each
//     line goes on to the original stdout (the journal, as before) and into outputLogPath;
//   - the host's journal (shipHostJournal): the instance's systemd units (the session unit's image pull and start,
//     docker, networkd's WireGuard, journald), read with journalctl from the host's disk, which the keeper mounts read
//     only (the container is privileged: it is root on the instance, as on Fly; the mount adds no access the session's
//     sudo doesn't have, and sits under a directory only root can enter). The kernel's messages are left out: the
//     router reads them from the serial console, also for a machine that never got this far. With a kernel that
//     binds the journal into the container (/run/jarvis-host/journal: docs/PLAN-aws.md "Logs") that is read
//     instead of the disk.
//
// supervisor-core pushes both files (pushOutputs), like the supervisor log, to POST /m/machine-output, signed with
// the machine's key: the router puts the instance id on the lines and passes them to the shipper. Every value the
// supervisor holds is replaced first (secretRedactor), and the shipper replaces secret shapes again. What the
// instance writes after the container has ended (the unit's exit, the power-off) has no machine left to send it:
// the router's lifecycle log has EC2's word on the shutdown instead.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	outputLogPath   = dir + "/output.log"
	journalLogPath  = dir + "/journal.log"
	hostJournalBind = "/run/jarvis-host/journal" // the spawner's bind of the host's journal (docs/PLAN-aws.md "Logs")
	hostRootDir     = keeperDir + "/host"        // 0700: only root goes in
	hostRootMount   = hostRootDir + "/root"      // the host's ROOT partition, read only
	sysBlock        = "/sys/class/block"         // where the ROOT partition is looked for
	shipFileCap     = int64(32 << 20)            // a file this far ahead of its push takes no more lines (two fit /run/jarvis, 256 MB)
	outputPushEvery = 2 * time.Second
	keeperStarted   = time.Now()
)

// shipFile: one {"at","text"} line file supervisor-core pushes to /m/machine-output as source
type shipFile struct {
	path, source string
	mu           sync.Mutex // the writer's (the keeper's tee and journal reader)
	dropped      int
}

var (
	outputShip  = &shipFile{source: "machine"}
	journalShip = &shipFile{source: "journal"}
)

func init() {
	outputShip.path, journalShip.path = outputLogPath, journalLogPath
}

func (f *shipFile) sentPath() string { return f.path + ".sent" }

// add: one line at at (the file goes to user claude, as the supervisor log does: supervisor-core reads and rotates it
// with claude's file access). Past shipFileCap unpushed, lines are counted, not kept; the count is the next line.
func (f *shipFile) add(at time.Time, text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, err := os.Stat(f.path)
	if err == nil && st.Size()-readOffsetOf(f.sentPath()) > shipFileCap {
		f.dropped++
		return
	}
	var b []byte
	if f.dropped > 0 {
		b, _ = json.Marshal(logLine{At: at.UTC().Format(time.RFC3339Nano), Text: fmt.Sprintf("[jarvis] %d %s lines not sent: the router didn't take them in time", f.dropped, f.source)})
		b = append(b, '\n')
	}
	l, _ := json.Marshal(logLine{At: at.UTC().Format(time.RFC3339Nano), Text: text})
	b = append(append(b, l...), '\n')
	fh, err := os.OpenFile(f.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return // the directory isn't there yet (the keeper's first lines): the journal has them
	}
	defer fh.Close()
	if privileged() {
		fh.Chown(session().uid, session().gid)
	}
	if _, err := fh.Write(b); err == nil {
		f.dropped = 0
	}
}

func readOffsetOf(p string) int64 {
	s, _ := readTrim(p)
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

// pushOnce: what is new in the file, pushed; rotated once all of it is pushed and it is big (as pushLogOnce)
func (f *shipFile) pushOnce(c *client) error {
	off := readOffsetOf(f.sentPath())
	n, err := pushLinesFrom(c, f.path, off, "/m/machine-output", map[string]any{"source": f.source})
	off += n
	os.WriteFile(f.sentPath(), []byte(strconv.FormatInt(off, 10)), 0o600)
	if err != nil {
		return err
	}
	if st, err := os.Stat(f.path); err == nil && st.Size() >= supervisorLogRoll && off >= st.Size() {
		old := f.path + ".old"
		if os.Rename(f.path, old) == nil {
			time.Sleep(50 * time.Millisecond) // a line the keeper's writer opened the old file for just before
			pushLinesFrom(c, old, off, "/m/machine-output", map[string]any{"source": f.source})
			os.Remove(old)
			os.WriteFile(f.sentPath(), []byte("0"), 0o600)
		}
	}
	return nil
}

var pushOutputsMu sync.Mutex

// pushOutputsOnce: both files, now (the loop's round, and the teardown's last)
func pushOutputsOnce(c *client) {
	if !onAWS() {
		return
	}
	pushOutputsMu.Lock()
	defer pushOutputsMu.Unlock()
	outputShip.pushOnce(c)
	journalShip.pushOnce(c)
}

// pushOutputs: supervisor-core's push loop for an AWS machine's output and host journal
func pushOutputs(c *client) {
	for ; ; time.Sleep(outputPushEvery) {
		pushOutputsOnce(c)
	}
}

// ---- the keeper's tee -----------------------------------------------------------------------------------------

// teeOutput: fd 1 and 2 of the keeper become a pipe; each line goes on to the original stdout and into outputShip.
// Children started after this inherit the pipe. A write to the original that fails (the unit's docker client gone)
// is dropped; the file still takes the line. The keeper's own crash (a Go panic) reaches the journal but not
// Grafana: the container ends with it.
func teeOutput() error {
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	orig, err := syscall.Dup(1)
	if err != nil {
		r.Close()
		w.Close()
		return err
	}
	syscall.CloseOnExec(orig)
	if err := syscall.Dup3(int(w.Fd()), 1, 0); err != nil {
		return err
	}
	if err := syscall.Dup3(int(w.Fd()), 2, 0); err != nil {
		return err
	}
	w.Close()
	out := os.NewFile(uintptr(orig), "stdout")
	// a crash's trace goes straight to the journal too: the tee dies with this process, before it could pass it on
	debug.SetCrashOutput(out, debug.CrashOptions{})
	go teeLines(r, out, outputShip)
	return nil
}

// teeLines: each line of r to out and into f (a line longer than 16 KB is cut into pieces)
func teeLines(r io.Reader, out io.Writer, f *shipFile) {
	br := bufio.NewReaderSize(r, 16<<10)
	for {
		b, err := br.ReadSlice('\n')
		if len(b) > 0 {
			out.Write(b)
			if t := strings.TrimRight(string(b), "\r\n"); t != "" {
				f.add(time.Now(), t)
			}
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return
		}
	}
}

// ---- the host's journal -----------------------------------------------------------------------------------------

// hostJournal: the directory with the host's journal: the kernel's bind, else the host's ROOT partition mounted read
// only ("" when neither: not an AWS instance, or no partition named ROOT)
func hostJournal() (string, error) {
	if st, err := os.Stat(hostJournalBind); err == nil && st.IsDir() {
		return hostJournalBind, nil
	}
	dev, err := rootPartition()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(hostRootMount, 0o700); err != nil {
		return "", err
	}
	os.Chmod(hostRootDir, 0o700)
	if _, err := os.Stat(filepath.Join(hostRootMount, "var/log/journal")); err != nil { // not mounted yet
		if err := mountReadOnly(dev, hostRootMount); err != nil {
			return "", err
		}
	}
	return filepath.Join(hostRootMount, "var/log/journal"), nil
}

// mountReadOnly: dev on dir, read only. The host has it mounted read-write, and the kernel refuses a read-only
// mount of a filesystem that is mounted read-write (EBUSY: the superblock is shared), so it is mounted as the host
// has it and the mount itself then made read only (a bind remount: only this mount, not the host's)
func mountReadOnly(dev, dir string) error {
	const flags = syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC
	var last error
	for _, fs := range []string{"ext4", "btrfs", "xfs"} {
		if last = syscall.Mount(dev, dir, fs, flags|syscall.MS_RDONLY, ""); last == nil {
			return nil
		}
		if last == syscall.EBUSY {
			if last = syscall.Mount(dev, dir, fs, flags, ""); last == nil {
				if err := syscall.Mount("", dir, "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY|flags, ""); err != nil {
					syscall.Unmount(dir, syscall.MNT_DETACH)
					return fmt.Errorf("making %s read only: %w", dir, err)
				}
				return nil
			}
		}
	}
	return fmt.Errorf("mounting %s read only: %w", dev, last)
}

// rootPartition: the device of the partition named ROOT (Flatcar's root filesystem, where its journal is)
func rootPartition() (string, error) {
	ents, err := os.ReadDir(sysBlock)
	if err != nil {
		return "", err
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(sysBlock, e.Name(), "uevent"))
		if err != nil {
			continue
		}
		var name, devname string
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "PARTNAME="); ok {
				name = v
			}
			if v, ok := strings.CutPrefix(l, "DEVNAME="); ok {
				devname = v
			}
		}
		if name == "ROOT" && devname != "" {
			return "/dev/" + devname, nil
		}
	}
	return "", errors.New("no partition named ROOT")
}

// journalEntry: the fields of journalctl -o json the shipper uses
type journalEntry struct {
	Cursor    string          `json:"__CURSOR"`
	Realtime  string          `json:"__REALTIME_TIMESTAMP"` // µs
	Message   json.RawMessage `json:"MESSAGE"`              // a string, or an array of bytes when it isn't UTF-8
	Unit      string          `json:"_SYSTEMD_UNIT"`
	Ident     string          `json:"SYSLOG_IDENTIFIER"`
	Comm      string          `json:"_COMM"`
	Transport string          `json:"_TRANSPORT"`
}

// journalLine: an entry as one shipped line ("" = left out): the kernel's (the console has them) and the session
// unit's docker client from the keeper's start on (that is the container's output, which outputShip has)
func journalLine(e journalEntry, since time.Time) (time.Time, string) {
	us, _ := strconv.ParseInt(e.Realtime, 10, 64)
	at := time.UnixMicro(us)
	if e.Transport == "kernel" {
		return at, ""
	}
	if e.Unit == "jarvis4-session.service" && e.Comm == "docker" && !at.Before(since) {
		return at, ""
	}
	var msg string
	if json.Unmarshal(e.Message, &msg) != nil {
		var bs []byte
		var ints []int
		if json.Unmarshal(e.Message, &ints) == nil {
			for _, i := range ints {
				bs = append(bs, byte(i))
			}
		}
		msg = strings.ToValidUTF8(string(bs), "�")
	}
	if msg = strings.TrimRight(msg, "\r\n"); msg == "" {
		return at, ""
	}
	who := orDefault(e.Ident, e.Comm)
	if e.Unit != "" && e.Unit != "init.scope" {
		who = e.Unit + " " + who
	}
	return at, who + ": " + msg
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

var journalctl = "journalctl"

// shipHostJournal: the keeper's reader of the host's journal from this boot's start, followed for the machine's life;
// a reader that ends starts again after its last entry
func (k *keeperT) shipHostJournal() {
	jdir, err := hostJournal()
	if err != nil {
		log.Printf("the host's journal: %v (not sent; the router still reads the console)", err)
		return
	}
	log.Printf("the host's journal: sending what %s holds of this boot", jdir)
	cursor := ""
	for !k.isStopping() {
		args := []string{"-D", jdir, "-b", "-f", "--no-tail", "-o", "json", "--no-pager",
			"--output-fields=MESSAGE,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_COMM,_TRANSPORT"}
		if cursor != "" {
			args = append(args, "--after-cursor="+cursor)
		}
		cmd := exec.Command(journalctl, args...)
		cmd.Stderr = os.Stderr
		out, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err != nil {
			log.Printf("the host's journal: %v", err)
			return
		}
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var e journalEntry
			if json.Unmarshal(sc.Bytes(), &e) != nil {
				continue
			}
			if e.Cursor != "" {
				cursor = e.Cursor
			}
			if at, t := journalLine(e, keeperStarted); t != "" {
				journalShip.add(at, t)
			}
		}
		cmd.Wait()
		k.sleep(5 * time.Second)
	}
}
