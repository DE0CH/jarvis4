package main

// Inputs Jarvis 4 delivers into a running session after it started (docs/DESIGN.md "Inputs to a machine"): a
// wakeup's or cron's prompt, a "continue" after a re-login (the 15-minute watchdog is the supervisor's own, stall.go). Each arrives in
// /m/commands as a delivery and is taken only when it is
//
//   - vouched for: a wakeup or cron is the session's OWN request (the machine-signed POST the session made to
//     /m/api/sessions/<id>/wakeup or /crons, which the router keeps as it was), checked against this line's signing
//     keys (lineKeysFile: every machine of the line adds its key; the file travels in the signed snapshot); the
//     "continue" and the other notes are texts built into this image, so the router chooses only when, never what;
//   - and logged: it carries the core's attestation over (this machine, the kind, the sha256 of the input), so
//     every input is in the core's hash-chained input log (core/audit.go).
//
// A delivery missing either is refused, and so is one into a session holding a sensitive store that the phone didn't
// approve (messages.go). The machine sends the text into the harness itself (the Jarvis channel, the Claude host's
// inbox socket, or harness-send for OpenCode/OpenClaw); the router never runs a command for it.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// lineKeysFile: this line's machines' signing keys (relative to $HOME; in snapshotPaths)
const lineKeysFile = ".jarvis2-line-keys.json"

var lineKeysMu sync.Mutex

func readLineKeys() []string {
	home, _ := os.UserHomeDir()
	var keys []string
	if b, err := os.ReadFile(filepath.Join(home, lineKeysFile)); err == nil {
		json.Unmarshal(b, &keys)
	}
	return keys
}

func addLineKey(k string) {
	if k == "" {
		return
	}
	lineKeysMu.Lock()
	defer lineKeysMu.Unlock()
	keys := readLineKeys()
	for _, x := range keys {
		if x == k {
			return
		}
	}
	keys = append(keys, k)
	home, _ := os.UserHomeDir()
	b, _ := json.Marshal(keys)
	os.WriteFile(filepath.Join(home, lineKeysFile), b, 0o600)
}

// trustLineKeys: at boot, after the predecessor's verified snapshot (which carried the file) is restored. A new
// line's first machine starts the file (an archived restore brings the old line's keys: the phone approved that
// snapshot). Also the predecessor's own key, from its core-signed cert.
func trustLineKeys(cert Cert) {
	if cert.PredID == "" && !restoredArchive {
		home, _ := os.UserHomeDir()
		os.Remove(filepath.Join(home, lineKeysFile))
	}
	if predecessorKey != "" {
		addLineKey(predecessorKey)
	}
	if cert.Machine != nil {
		addLineKey(cert.Machine.SigningKey)
	}
}

var (
	predecessorKey  string // set by prepare from the predecessor's core-signed cert
	restoredArchive bool   // set by restoreArchived
)

// deliveredFile: what this line's own requests have already delivered (relative to $HOME; in snapshotPaths, so a
// successor knows too): a one-time wakeup's request once, a cron's request once per run, in order and no faster
// than half its period (R1 audit: the router kept a signed request and could deliver it again and again)
const deliveredFile = ".jarvis2-delivered.json"

type delivered struct {
	Run int   `json:"run"`
	At  int64 `json:"at"` // unix seconds
}

var deliveredMu sync.Mutex

// deliverOrderMu: held by deliver from the replay check to the record
var deliverOrderMu sync.Mutex

// notReplayed: records the delivery, or refuses a repeat of one already made (wakeup, cron); other kinds pass
// notReplayed: check AND record (tests, and any caller with nothing to do between)
func notReplayed(d Delivery, now time.Time) error { return replayGuard(d, now, true) }

// replayGuard: refuse a delivery already made; with record, also mark it made. deliver checks first, sends into the
// harness, and records only after the harness took it: a resumed session's harness that is still booting answers
// "target session not found", the router tries again, and that retry must not find the wakeup already burned
// (2026-10-15, the legacy + move rehearsal).
func replayGuard(d Delivery, now time.Time, record bool) error {
	if d.Kind == "request-outcome" && d.Request != nil {
		return outcomeNotReplayed(d, now, record)
	}
	if (d.Kind != "wakeup" && d.Kind != "cron" && d.Kind != "watch" && d.Kind != "watch-fail") || d.Request == nil {
		return nil
	}
	deliveredMu.Lock()
	defer deliveredMu.Unlock()
	home, _ := os.UserHomeDir()
	p := filepath.Join(home, deliveredFile)
	seen := map[string]delivered{}
	if b, err := os.ReadFile(p); err == nil {
		json.Unmarshal(b, &seen)
	}
	key := d.Kind + " " + d.Request.Sig
	if d.Kind == "watch" || d.Kind == "watch-fail" {
		key = "watch " + d.Request.Sig // met or given up: one of the two, once
	}
	last, ok := seen[key]
	if d.Kind == "wakeup" && ok {
		return errors.New("this wakeup was already delivered")
	}
	if strings.HasPrefix(key, "watch ") && ok {
		return errors.New("this watch was already delivered")
	}
	if d.Kind == "cron" && ok {
		every := int64(24 * 60 * 60)
		if body, err := base64.StdEncoding.DecodeString(d.Request.Body); err == nil {
			var b struct {
				Every int64 `json:"everySeconds"`
			}
			if json.Unmarshal(body, &b) == nil && b.Every > 0 {
				every = max(b.Every, 15*60)
			}
		}
		if d.Run <= last.Run {
			return fmt.Errorf("cron run %d was already delivered (last %d)", d.Run, last.Run)
		}
		if now.Unix()-last.At < every/2 {
			return errors.New("this cron ran less than half its period ago")
		}
	}
	if !record {
		return nil
	}
	seen[key] = delivered{Run: d.Run, At: now.Unix()}
	if len(seen) > 2000 { // keep the newest
		type kv struct {
			k string
			v delivered
		}
		all := make([]kv, 0, len(seen))
		for k, v := range seen {
			all = append(all, kv{k, v})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].v.At > all[j].v.At })
		seen = map[string]delivered{}
		for _, x := range all[:2000] {
			seen[x.k] = x.v
		}
	}
	b, _ := json.Marshal(seen)
	return os.WriteFile(p, b, 0o600)
}

// SignedRequest: a request this line's machine made to the router, exactly as signed (client.raw)
type SignedRequest struct {
	Machine string `json:"machine"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	At      string `json:"at"`
	Body    string `json:"body"` // base64
	Sig     string `json:"sig"`
}

type Delivery struct {
	ID      string         `json:"id"`
	Kind    string         `json:"kind"` // wakeup | cron | watch | watch-fail | continue | upgraded | lease-* | request-outcome | peer | resume-prompt
	Request *SignedRequest `json:"request,omitempty"`
	Run     int            `json:"run,omitempty"`     // a cron's run number (a number)
	Minutes int            `json:"minutes,omitempty"` // a granted lease's length (a number)
	From    string         `json:"from,omitempty"`    // upgraded: the old size (small | medium | large)
	To      string         `json:"to,omitempty"`      // upgraded: the new size
	// a lease (leases.go): the device (a lease name), and whether Deyao had taken it over (and interrupted this
	// session); a granted lease also carries this session's own signed acquire request (its prompt) and the lease's
	// length in Minutes
	Device      string `json:"device,omitempty"`
	Handover    bool   `json:"handover,omitempty"`
	Interrupted bool   `json:"interrupted,omitempty"`
	// request-outcome (outcomes.go): the decided items of this session's own filing (Request)
	Outcomes []OutcomeItem `json:"outcomes,omitempty"`
	// peer (peer.go): another session's message, with its verified sender and direction
	Peer *PeerNote `json:"peer,omitempty"`
	// resume-prompt: Deyao's words from the app, delivered only under the phone's approval of exactly them
	Text string `json:"text,omitempty"`
	// messages.go: the phone's approval of this message (a batch it is in, or a rule for its kind)
	Approval *SignedDoc `json:"approval,omitempty"`
	// Preview: render the text and answer it; nothing is checked against the core, sent or recorded (the router shows
	// Deyao the exact text before he approves it)
	Preview bool       `json:"preview,omitempty"`
	Attest  *SignedDoc `json:"attest"`
}

// ownRequestBody: the body of a request one of this line's machines signed (a wakeup or cron it asked for)
func ownRequestBody(r *SignedRequest, keys []string) ([]byte, error) {
	if r == nil {
		return nil, errors.New("no request")
	}
	body, err := base64.StdEncoding.DecodeString(r.Body)
	if err != nil {
		return nil, errors.New("bad body")
	}
	sum := sha256.Sum256(body)
	payload := []byte(r.Method + " " + r.Path + " " + r.At + " " + hex.EncodeToString(sum[:]))
	for _, k := range keys {
		if verify(k, payload, r.Sig) {
			return body, nil
		}
	}
	return nil, errors.New("not signed by a machine of this line")
}

// deliveryText: the text a delivery puts into the harness, and the bytes the core attested
func deliveryText(d Delivery, keys []string) (text string, attested []byte, err error) {
	switch d.Kind {
	case "wakeup", "cron":
		body, err := ownRequestBody(d.Request, keys)
		if err != nil {
			return "", nil, err
		}
		want := map[string]string{"wakeup": "/wakeup", "cron": "/crons"}[d.Kind]
		if d.Request.Method != "POST" || !strings.HasPrefix(d.Request.Path, "/m/api/sessions/") ||
			!(strings.HasSuffix(d.Request.Path, want) || (d.Kind == "wakeup" && strings.HasSuffix(d.Request.Path, "/wakeups"))) {
			return "", nil, fmt.Errorf("the signed request isn't a %s", d.Kind)
		}
		var b struct {
			Name   any    `json:"name"`
			Prompt string `json:"prompt"`
		}
		if json.Unmarshal(body, &b) != nil || strings.TrimSpace(b.Prompt) == "" {
			return "", nil, errors.New("the signed request has no prompt")
		}
		name := strings.TrimSpace(fmt.Sprint(b.Name))
		if b.Name == nil || name == "" {
			name = "default"
		}
		prompt := strings.Join(strings.Fields(b.Prompt), " ")
		if d.Kind == "wakeup" {
			if name == "default" {
				return prompt, body, nil
			}
			return fmt.Sprintf("[scheduled wakeup %q] %s", name, prompt), body, nil
		}
		return fmt.Sprintf("[recurring wakeup %q — run %d] %s", name, max(1, d.Run), prompt), body, nil
	case "continue":
		return "continue", []byte("continue"), nil
	case "resume-prompt":
		t := resumePromptText(d.Text)
		if t == "" {
			return "", nil, errors.New("resume-prompt: empty or longer than 4000 characters")
		}
		return t, []byte(t), nil
	case "request-outcome":
		return outcomeText(d, keys)
	case "peer":
		cert, err := currentCert()
		if err != nil {
			return "", nil, err
		}
		return peerText(d.Peer, sortedCopy(cert.Stores), liveMode(cert))
	case "watch", "watch-fail":
		w, body, err := ownWatch(d.Request, keys)
		if err != nil {
			return "", nil, err
		}
		if d.Kind == "watch" {
			return fmt.Sprintf("[watch %q met] %s", w.Name, w.Prompt), body, nil
		}
		if w.FailPrompt != "" {
			return fmt.Sprintf("[watch %q gave up] %s", w.Name, w.FailPrompt), body, nil
		}
		return fmt.Sprintf("[watch %q gave up] Conditional wakeup %q gave up (its check said to give up, or its time ran out without the condition being met). Decide what to do next.", w.Name, w.Name), body, nil
	case "lease-granted", "lease-taken", "lease-back":
		t, err := leaseText(d, keys)
		if err != nil {
			return "", nil, err
		}
		return t, []byte(t), nil
	case "upgraded":
		t, err := upgradedText(d.From, d.To)
		if err != nil {
			return "", nil, err
		}
		return t, []byte(t), nil
	}
	return "", nil, fmt.Errorf("unknown delivery kind %q", d.Kind)
}

// checkAttest: the core's input-log entry for exactly this input on this machine
func checkAttest(coreKey, me, kind string, attested []byte, d *SignedDoc) error {
	if t, ok := readKernelTrust(); ok { // kernelboot.go: the log notary's challenge over the same facts
		return checkKernelAttest(t, me, kind, attested, d)
	}
	var e struct {
		Kind    string `json:"kind"`
		Machine string `json:"machine"`
		Input   string `json:"input"`
		Sha256  string `json:"sha256"`
	}
	if err := verifyDoc(coreKey, d, &e); err != nil || e.Kind != "input" {
		return errors.New("no core attestation (the input isn't in the core's log)")
	}
	sum := sha256.Sum256(attested)
	if e.Machine != me || e.Input != kind || e.Sha256 != hex.EncodeToString(sum[:]) {
		return errors.New("the core's attestation is for another input or machine")
	}
	return nil
}

type DeliveryResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Text: a preview's text; also a refused delivery's text, when the phone signed another (messages.go)
	Text string `json:"text,omitempty"`
	// NeedsApproval: refused only for want of the phone's approval of this message (the router files it for Deyao)
	NeedsApproval bool `json:"needsApproval,omitempty"`
}

func runDelivery(c *client, d Delivery) {
	res := DeliveryResult{ID: d.ID}
	if d.Preview {
		res.Text, res.Error = previewDelivery(d)
		res.OK = res.Error == ""
		if err := c.json("POST", "/m/delivery-result", res, nil); err != nil {
			log.Printf("delivery preview result not sent: %v", err)
		}
		return
	}
	text, err := deliver(c, d)
	if errors.Is(err, errTextDiffers) {
		res.Text = text
	}
	res.NeedsApproval = errors.Is(err, errNeedsApproval) || errors.Is(err, errTextDiffers)
	if err != nil {
		res.Error = err.Error()
		log.Printf("delivery %s (%s) refused: %v", d.ID, d.Kind, err)
	} else {
		res.OK = true
		log.Printf("delivery %s (%s) delivered", d.ID, d.Kind)
	}
	if err := c.json("POST", "/m/delivery-result", res, nil); err != nil {
		log.Printf("delivery result not sent: %v", err)
	}
}

// previewDelivery: the text this delivery would put into the harness (before a watch's re-run check output), or why it
// would be refused; nothing runs, is sent or recorded
func previewDelivery(d Delivery) (string, string) {
	d.Approval, d.Attest = nil, nil
	text, _, _, _, err := renderDelivery(d) // guard.go
	if err != nil {
		return "", err.Error()
	}
	return text, ""
}

// deliver: the delivery's text into the harness, once the guard let it through (the text also comes back when the
// phone approved another text, so the router can show Deyao this one)
func deliver(c *client, d Delivery) (string, error) {
	text, d, cert, approved, err := guardDelivery(c, d) // guard.go
	if err != nil {
		return text, err
	}
	deliverOrderMu.Lock() // one delivery at a time between the check and the record
	defer deliverOrderMu.Unlock()
	now := time.Now()
	if err := replayGuard(d, now, false); err != nil {
		return "", err
	}
	if d.Kind == "watch" || d.Kind == "watch-fail" {
		// the check once more, here, with the session's own env: its output is the context (the runner's never is)
		if w, _, err := ownWatch(d.Request, readLineKeys()); err == nil {
			text += rerunCheck(w)
		}
	}
	if err := sendToHarness(cert.Options.Harness, liveMode(cert), deliveryFrom(d), text); err != nil {
		return "", err
	}
	if err := recordApproved(approved, now); err != nil { // messages.go: the phone's approval is used up
		return "", err
	}
	return "", replayGuard(d, now, true)
}

// deliveryFrom: the sender the harness shows: "deyao" for a resume prompt (Deyao's own words from the app, delivered
// only under the phone's approval of exactly them), so Claude takes it as his message; "jarvis" for everything else
func deliveryFrom(d Delivery) string {
	if d.Kind == "resume-prompt" {
		return "deyao"
	}
	return "jarvis"
}

// resumePromptText: Deyao's resume prompt as the router keeps it (router/sessionapi.go cleanResumePrompt): CRLF → LF,
// trimmed, at most 4000 characters; "" when empty or longer
func resumePromptText(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(p, "\r\n", "\n"), "\r", "\n"))
	if p == "" || len([]rune(p)) > 4000 {
		return ""
	}
	return p
}

// modeFile: the in-place permission mode (session-image set-permission-mode writes it, harness-claude.sh launches
// claude in it); relative to claudeHome
var modeFile = ".claude/.permission-mode"

// liveMode: the mode claude actually runs in, decided exactly as harness-claude.sh decides it: the in-place file when
// there is one, else the cert's. A session raised to bypass in place keeps its older cert (auto), so sending as the
// cert's mode put the message in the "prompting" class while claude bypasses, and Claude Code held every Jarvis message
// ("the sending session's permission mode class doesn't match this session's", 2026-10-20).
func liveMode(cert Cert) string {
	b, err := os.ReadFile(filepath.Join(claudeHome, modeFile))
	if err != nil {
		return certMode(cert)
	}
	if strings.TrimSpace(string(b)) == "bypass" {
		return "bypass"
	}
	return "auto"
}

// the Jarvis channel's sender and config (session-image/Dockerfile); seams for tests
var (
	channelSend   = "/usr/local/bin/jarvis-channel-send"
	channelConfig = "/etc/claude-code/jarvis-channel.json"
)

func sortedCopy(ss []string) []string {
	out := append([]string{}, ss...)
	sort.Strings(out)
	return out
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// sendToHarness: the text into the harness (the same as the router's old exec path, run here)
func sendToHarness(harness, mode, from, text string) error {
	var cmd *exec.Cmd
	if viaHarnessSend(harness) { // harnesses.go
		cmd = sessionCommand(nil, "/usr/local/bin/harness-send", "--queue")
		cmd.Stdin = strings.NewReader(text)
	} else if channelSend != "" && fileExists(channelSend) && fileExists(channelConfig) {
		// the Jarvis channel (session-image/bin/jarvis-channel): the image refuses every cross-session peer message, so
		// Jarvis's own messages go in through its channel, whatever the session's permission mode
		cmd = sessionCommand(nil, channelSend, "--from", from)
		cmd.Stdin = strings.NewReader(text)
	} else { // an image before the channel: the peer socket, in the mode class claude runs in
		fm := "prompting"
		if mode == "bypass" {
			fm = "bypass"
		}
		cmd = sessionCommand(nil, "python3", "-I", "-c", peerPy, base64.StdEncoding.EncodeToString([]byte(text)), "", fm, from)
	}
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		return errors.New("the harness didn't take the message within 30 s")
	}
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// the in-machine sender (router/peer.go's, the same program). argv: base64 text, target name ("" = the one live
// session), from-mode, from-name.
const peerPy = `
import base64, glob, hashlib, json, os, socket, sys, uuid
text = base64.b64decode(sys.argv[1]).decode("utf-8", "replace")
name, mode, sender = sys.argv[2], sys.argv[3], sys.argv[4]
sess = os.path.expanduser("~/.claude/sessions")
def done(ok, message, **kw):
    print(json.dumps({"success": ok, "message": message, **kw})); sys.exit(0 if ok else 1)
def alive(pid):
    try: os.kill(int(pid), 0); return True
    except Exception: return False
live = []
for f in sorted(glob.glob(os.path.join(sess, "*.json"))):
    try: d = json.load(open(f))
    except Exception: continue
    p = d.get("messagingSocketPath")
    if not p or not os.path.exists(p) or not alive(d.get("pid")): continue
    if d.get("kind", "interactive") != "interactive": continue
    live.append(d)
named = [d for d in live if name and d.get("name") == name]
if len(named) == 1: t = named[0]
elif not named and len(live) == 1: t = live[0]
else:
    done(False, "target session not found: %s (live interactive sessions: %s)" % (name or "(unnamed)", ", ".join(str(d.get("name") or d.get("pid")) for d in live) or "none"))
if t.get("peerProtocol") != 1:
    done(False, "host %s speaks peerProtocol %r, this sender speaks 1" % (t.get("name"), t.get("peerProtocol")))
sock_path = t["messagingSocketPath"]
token = None
for f in glob.glob(os.path.join(sess, "*.%s.key" % hashlib.sha256(sock_path.lower().encode()).hexdigest())):
    try: token = json.load(open(f)).get("peerToken"); break
    except Exception: pass
body = '<cross-session-message from="uds:%s" from-name="%s" from-mode="%s">\n%s\n</cross-session-message>' % (sender, sender, mode, text)
frames = ([json.dumps({"type": "auth", "token": token})] if token else []) + [json.dumps({
    "msgV": 1, "msg_id": str(uuid.uuid4()), "type": "user",
    "message": {"role": "user", "content": body}, "priority": "next", "from": "uds:" + sender})]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect(sock_path)
    s.sendall(("\n".join(frames) + "\n").encode())
except Exception as e:
    done(False, "inbox socket %s: %s" % (sock_path, e))
s.settimeout(2)
try: ack = s.recv(65536).decode("utf-8", "replace")
except Exception: ack = ""
s.close()
done(True, "delivered to %s (pid %s)" % (t.get("name") or "?", t.get("pid")), target=t.get("name") or "", ack=ack[:500])
`

// ---- machine sizes (the same block is in router/sizes.go, core/fly.go and machine/deliver.go, and its guest part in kernel/spawner/fly.go; TestSizeBlocksMatch) ----

// The sizes: small (2 GB), medium (4 GB), large (8 GB), then every doubling past large, named by its memory ("16gb",
// "32gb", …). Upgrade moves a session one step up, and there is no last step: a guest Fly can't make is Fly's to
// refuse, with its own error.
var namedSizes = map[string]int{"small": 2, "medium": 4, "large": 8}

// sizeMemGB: the size's memory in GB; 0 = not a size (the 1<<20 bound only keeps memory_mb an ordinary int)
func sizeMemGB(size string) int {
	if gb := namedSizes[size]; gb != 0 {
		return gb
	}
	n, err := strconv.Atoi(strings.TrimSuffix(size, "gb"))
	if err != nil || n < 16 || n > 1<<20 || n&(n-1) != 0 || strconv.Itoa(n)+"gb" != size {
		return 0
	}
	return n
}

// sizeGuest: the size's Fly guest. Fly takes at most 2 GB per shared CPU and 8 GB per performance CPU
// (fly.io/docs/machines/guides-examples/machine-sizing). The named three have one shared CPU per GB; 16 GB is the
// most a shared guest holds (8 CPUs × 2 GB); past it the guest is performance, with large's 8 CPUs or, once the
// memory needs more (8 GB each), memory/8 CPUs.
func sizeGuest(size string) (cpuKind string, cpus, memoryMB int) {
	gb := sizeMemGB(size)
	switch {
	case gb == 0:
		return "", 0, 0
	case gb <= 8:
		return "shared", gb, gb * 1024
	case gb <= 16:
		return "shared", 8, gb * 1024
	}
	return "performance", max(8, gb/8), gb * 1024
}

// nextSize: the size Upgrade moves to, twice the memory (a session with no size runs medium)
func nextSize(size string) string {
	gb := sizeMemGB(size)
	if gb == 0 {
		gb = namedSizes["medium"]
	}
	for name, n := range namedSizes {
		if n == 2*gb {
			return name
		}
	}
	return strconv.Itoa(2*gb) + "gb"
}

// sizeText: "large (8 GB)", "16 GB"
func sizeText(size string) string {
	if gb := namedSizes[size]; gb != 0 {
		return fmt.Sprintf("%s (%d GB)", size, gb)
	}
	return fmt.Sprintf("%d GB", sizeMemGB(size))
}

// ---- end of the machine sizes block ----

// upgradedText: after an Upgrade (router/memory.go), the first message on the bigger machine. The router names only
// the two sizes (sizeMemGB); the same text is built in router/memory.go upgradedText.
func upgradedText(from, to string) (string, error) {
	if sizeMemGB(from) == 0 || sizeMemGB(to) == 0 {
		return "", errors.New("upgraded: not a machine size")
	}
	return fmt.Sprintf("Jarvis: this session ran out of memory and was moved from a %s to a %s machine. ", sizeText(from), sizeText(to)) +
		"To free memory for the move, every process of the old machine was stopped: Claude itself, background jobs, builds, dev servers, browsers. " +
		"Their list is in ~/artifacts/jarvis-upgrade-freed.txt. Check which of them the task still needs, restart only those, then carry on with the task as before: the bigger machine has the room, so do not cut back on parallel work. " +
		"This is an automated message from Jarvis.", nil
}

// ---- leases (router/leases.go builds the same texts) ------------------------------------------------------------

var (
	leaseNameRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	leaseSpaceRE = regexp.MustCompile(`\s+`)
	leasePathRE  = regexp.MustCompile(`^/m/api/sessions/[^/]+/leases/([a-z0-9][a-z0-9-]{0,40})$`)
)

// leaseText: the wake text for a lease delivery. The router names only the device (a lease name), two flags and a
// number; a granted lease's note is this session's own, from its signed acquire request, whose path names the device.
func leaseText(d Delivery, keys []string) (string, error) {
	if !leaseNameRE.MatchString(d.Device) {
		return "", errors.New("lease: not a device name")
	}
	dev := d.Device
	switch d.Kind {
	case "lease-taken":
		return fmt.Sprintf("[lease %q taken over] Deyao has taken the shared device %q himself. Stop using it now: every device action is refused while he has it. ", dev, dev) +
			"You are first in the queue; when he hands it back you'll be woken. Then look at the device first: it will be in whatever state he left it. " +
			"This is an automated message from Jarvis.", nil
	case "lease-back":
		return fmt.Sprintf("[lease %q handed back] Deyao has handed the shared device %q back. Earlier this session found it taken over: that no longer applies. ", dev, dev) +
			fmt.Sprintf("Run scripts/lease.py status %s to see whether it is free or who holds it now, and acquire it if this session still needs it (scripts/lease.py acquire %s --purpose \"…\"). ", dev, dev) +
			"If you told Deyao or planned around it being unavailable, reconsider now. It is in whatever state he left it: look at it first. " +
			"This is an automated message from Jarvis.", nil
	}
	prompt := ""
	if d.Request != nil {
		body, err := ownRequestBody(d.Request, keys)
		if err != nil {
			return "", err
		}
		m := leasePathRE.FindStringSubmatch(d.Request.Path)
		if d.Request.Method != "POST" || m == nil || m[1] != dev {
			return "", errors.New("the signed request isn't this session's acquire of that device")
		}
		var b struct {
			Prompt string `json:"prompt"`
		}
		json.Unmarshal(body, &b)
		prompt = strings.TrimSpace(leaseSpaceRE.ReplaceAllString(b.Prompt, " "))
		if r := []rune(prompt); len(r) > 2000 {
			prompt = string(r[:2000])
		}
	}
	if d.Minutes < 1 || d.Minutes > 6*60 {
		return "", errors.New("lease: not a lease length")
	}
	t := fmt.Sprintf("[lease %q granted] This session now holds the shared device %q (you were queued for it). ", dev, dev) +
		fmt.Sprintf("It is yours for %d min, renewed automatically by the device helpers on every action; return it when done (scripts/lease.py return %s). ", d.Minutes, dev)
	if d.Handover {
		t += fmt.Sprintf("Deyao had taken %q over himself", dev)
		if d.Interrupted {
			t += " (interrupting you: your earlier steps may no longer apply)"
		}
		t += fmt.Sprintf(" and has handed it back; his notes are in scripts/lease.py status %s. The device is in whatever state he left it: look at it first (screenshot / UI tree) and continue from there.", dev)
	} else {
		t += "The previous holder may have left it in any state: inspect it first."
	}
	if prompt != "" {
		t += " Your note: " + prompt
	}
	return t, nil
}

// ---- watches (router/watches.go) -------------------------------------------------------------------------------

type watchReq struct {
	Name       string `json:"name"`
	Script     string `json:"script"`
	Prompt     string `json:"prompt"`
	FailPrompt string `json:"failPrompt"`
}

var watchNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)

// ownWatch: the watch this line's machine armed (its signed POST …/watches)
func ownWatch(r *SignedRequest, keys []string) (*watchReq, []byte, error) {
	body, err := ownRequestBody(r, keys)
	if err != nil {
		return nil, nil, err
	}
	if r.Method != "POST" || !strings.HasPrefix(r.Path, "/m/api/sessions/") || !strings.HasSuffix(r.Path, "/watches") {
		return nil, nil, errors.New("the signed request isn't a watch")
	}
	var w watchReq
	if json.Unmarshal(body, &w) != nil || strings.TrimSpace(w.Prompt) == "" || !watchNameRE.MatchString(strings.TrimSpace(w.Name)) {
		return nil, nil, errors.New("the signed request has no watch")
	}
	w.Name = strings.TrimSpace(w.Name)
	w.Prompt = strings.Join(strings.Fields(w.Prompt), " ")
	w.FailPrompt = strings.Join(strings.Fields(w.FailPrompt), " ")
	return &w, body, nil
}

var rerunTimeout = 40 * time.Second

// rerunCheck: the watch's check run here (a login shell: the session's env and secrets) in a throwaway directory,
// within rerunTimeout (the router waits 60 s for the delivery's answer); its stdout, capped, as the prompt's context
func rerunCheck(w *watchReq) string {
	dir, err := os.MkdirTemp("", "watch-")
	if err != nil {
		return ""
	}
	defer os.RemoveAll(dir)
	f := filepath.Join(dir, "check.sh")
	if os.WriteFile(f, []byte(w.Script), 0o700) != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), rerunTimeout)
	defer cancel()
	cmd := sessionCommand(ctx, "bash", "-l", f)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "WATCH_NAME="+w.Name)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	var out bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &out, n: 6000}
	err = cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		code = -1
	}
	s := strings.TrimSpace(out.String())
	if ctx.Err() != nil {
		return fmt.Sprintf("\n\n[watch %q check output] (the check, run again on this machine, didn't finish within %s) %s", w.Name, rerunTimeout, s)
	}
	if s == "" {
		return ""
	}
	return fmt.Sprintf("\n\n[watch %q check output] (run again on this machine just now, exit %d)\n%s", w.Name, code, s)
}

type limitedWriter struct {
	w *bytes.Buffer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if room := l.n - l.w.Len(); room > 0 {
		if len(p) > room {
			l.w.Write(p[:room])
		} else {
			l.w.Write(p)
		}
	}
	return len(p), nil
}
