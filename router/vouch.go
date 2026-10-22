package main

// The router's part of "only vouched inputs shape a machine that gets secrets" (docs/DESIGN.md "Inputs to a
// machine"; machine/vouch.go and machine/deliver.go do the checking, core/vouch.go and core/audit.go the signing).
// The router is untrusted: nothing here is a check anyone relies on. It
//
//   - puts the session's settings into the succession challenge (Options.Config: title, first prompt, model,
//     repos, one-shot, API proxy, attachments by hash, the task's parameters, what a restore restores), so the
//     phone signs them and the cert carries them; an unattended resume passes the cert's own config unchanged;
//   - puts a resume's one-time inputs (a prompt, a rollback) into Options.Once, which only the phone approves;
//   - kills a machine with the hash and signature of its last snapshot, so its successor's cert names it;
//   - serves the few values whose format can't carry an instruction (/m/config), and
//   - delivers wakeups, crons and its own canned texts as deliveries the machine checks (the session's own signed
//     request, or a text built into the image) and the core attests (the input log), instead of running a
//     command under a grant.
//
// The held core (before Vouch 2) ignores Config and Once and has no input log: then everything stays as before
// (the machine, for its part, takes none of those settings from such a cert).

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SessionConfig: Options.Config (machine/vouch.go reads it strictly; the app's shell shows and checks it)
type SessionConfig struct {
	V           int             `json:"v"`
	Label       string          `json:"label,omitempty"`
	Prompt      string          `json:"prompt,omitempty"`
	Model       string          `json:"model,omitempty"`
	Repos       []string        `json:"repos,omitempty"`
	Content     []string        `json:"content,omitempty"` // content stores (content.go): ~/content/<name>/ through the router
	OneShot     bool            `json:"oneShot,omitempty"`
	APIProxy    bool            `json:"apiProxy,omitempty"`
	Attachments []AttachmentRef `json:"attachments,omitempty"`
	Restore     *RestoreRef     `json:"restore,omitempty"`
	Task        *TaskConfig     `json:"task,omitempty"`
	// the session's Claude account (claudeaccounts.go), shown on the phone; only with SIGN_CLAUDE_ACCOUNT=1 (an app
	// build that knows the key: older ones refuse settings they can't show). The machine takes the router's word anyway.
	ClaudeAccount string `json:"claudeAccount,omitempty"`
}

type AttachmentRef struct {
	Name   string `json:"name"`
	Sha256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type RestoreRef struct {
	Machine string `json:"machine"`
	Sha256  string `json:"sha256"`
}

type TaskConfig struct {
	Instance string         `json:"instance"`
	Name     string         `json:"name"`
	Params   map[string]any `json:"params"`
}

// OnceInputs: Options.Once
type OnceInputs struct {
	Prompt   string `json:"prompt,omitempty"`
	Rollback string `json:"rollback,omitempty"`
}

// certOptions: the cert's Config and Once
func certOptions(c *Doc) (config, once string) {
	if c == nil {
		return "", ""
	}
	var x struct {
		Options struct {
			Config string `json:"config"`
			Once   string `json:"once"`
		} `json:"options"`
	}
	c.Decode(&x)
	return x.Options.Config, x.Options.Once
}

// ---- the session's config ---------------------------------------------------------------------------------

func splitRepos(s string) []string {
	out := []string{}
	for _, u := range strings.Split(s, ",") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// sessionConfig: the settings a new line's cert carries (the first machine is the only one that uses the prompt,
// the attachments and the restore; the rest hold for the whole line)
func (r *Router) sessionConfig(s *Session) (string, error) {
	c := SessionConfig{V: 1, Label: s.Label, Prompt: s.Prompt, Model: s.Model, Repos: splitRepos(s.Repos), Content: s.Content}
	if os.Getenv("SIGN_CLAUDE_ACCOUNT") == "1" {
		c.ClaudeAccount = s.ClaudeAccount
	}
	if len(c.Repos) == 0 {
		c.Repos = nil
	}
	if s.Live != nil {
		c.OneShot = s.Live.OneShot
	}
	if s.Ops != nil {
		c.APIProxy = s.Ops.APIProxy
		for _, f := range s.Ops.Attach {
			sum, size, err := r.objSha256(uploadKey(s.Ops.Upload, f.Name))
			if err != nil {
				return "", fmt.Errorf("attachment %s: %v", f.Name, err)
			}
			c.Attachments = append(c.Attachments, AttachmentRef{Name: f.Name, Sha256: sum, Size: size})
		}
	}
	if s.RestoreCert != nil {
		var oc struct {
			Machine *struct {
				ID string `json:"id"`
			} `json:"machine"`
		}
		var sum string
		var err error
		if rs := r.snap(restoreSnap(s.ID)); rs != nil {
			sum = rs.Sha256
		} else {
			err = errors.New("its snapshot isn't here")
		}
		if err != nil || s.RestoreCert.Decode(&oc) != nil || oc.Machine == nil {
			return "", fmt.Errorf("the restore's snapshot or cert: %v", err)
		}
		c.Restore = &RestoreRef{Machine: oc.Machine.ID, Sha256: sum}
	}
	if s.ImportFrom != "" { // jarvis1import.go: the Jarvis 1 session id (its first machine's) and the import manifest's hash
		c.Restore = &RestoreRef{Machine: s.ImportFrom, Sha256: s.ImportSha}
	}
	if s.taskConfig != nil {
		c.Task = s.taskConfig
	} else if isTaskHarness(s.Harness) {
		r.st.Do(func(d *persisted) {
			if i := instanceBySession(tasksOf(d), s.ID); i != nil {
				c.Task = &TaskConfig{Instance: i.ID, Name: i.Name, Params: map[string]any{}}
				for k, v := range i.Params {
					c.Task.Params[k] = v
				}
			}
		})
	}
	b, err := json.Marshal(c)
	return string(b), err
}

func fileSha256(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// lineConfig: what a successor's challenge carries: the cert's own config (an unattended resume keeps it exactly),
// or, for a line from a core that doesn't vouch, nothing
func lineConfig(s *Session) string {
	c, _ := certOptions(s.Cert)
	return c
}

// resumeOnce: a resume's one-time inputs — the pending resume prompt and the rollback asked for this predecessor —
// when the core vouches (they then need the phone; the old paths deliver neither); "" = none
func (r *Router) resumeOnce(s *Session) string {
	var o OnceInputs
	r.st.Do(func(d *persisted) {
		if sc := d.Schedules[s.ID]; sc != nil {
			o.Prompt = sc.ResumePrompt
		}
	})
	if s.Ops != nil && s.Ops.Rollback != nil && s.Ops.Rollback.Marker != "" && certMachine(s.Cert) == s.Ops.Rollback.Pred {
		o.Rollback = s.Ops.Rollback.Marker
	}
	if o == (OnceInputs{}) {
		return ""
	}
	b, _ := json.Marshal(o)
	return string(b)
}

// onceTaken: the approved resume carried them in its cert: nothing delivers them again
func (r *Router) onceTaken(sid string) {
	r.st.Do(func(d *persisted) {
		if sc := d.Schedules[sid]; sc != nil {
			sc.ResumePrompt = ""
		}
		if s := d.Sessions[sid]; s != nil && s.Ops != nil {
			s.Ops.Rollback = nil
		}
	})
}

// ---- kill with the snapshot -----------------------------------------------------------------------------------

// killMachine: kill, naming the machine's last snapshot (its sha256 and the machine's signature over it) so the
// successor's cert names exactly that one. requireSnapshot (a pause): the core keeps the machine (409) rather than
// kill it without vouching for that snapshot; without it (a destroy, a takeover of a long-dead machine) a snapshot
// the core can't check doesn't stop the kill, it just isn't named (core.go Kill, DECISIONS 190).
func (r *Router) killMachine(machine string, requireSnapshot bool) (*Doc, error) {
	in := map[string]any{"machine": machine}
	if s := r.snap(machine); s != nil && s.State == "committed" {
		in["snapshot"] = map[string]any{"sha256": s.Sha256, "sig": s.Sig, "required": requireSnapshot}
	}
	if key, err := r.core.Key(); err == nil {
		if l := r.legacyFor(machine, key["signingKey"]); l != nil {
			in["legacy"] = l // legacy.go: an earlier core's machine, its line taken over at this kill
		}
	}
	kd, err := r.killUntilDestroyed(in)
	if err == nil {
		r.adopted(machine, kd)
	}
	return kd, err
}

// ---- the values the machine takes from the router alone (each a strict format) --------------------------------

func (r *Router) machineConfig(machine string) (map[string]any, error) {
	sid, err := r.machineSession(machine)
	if err != nil {
		return nil, err
	}
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[sid]; x != nil {
			s = *x
		}
	})
	e := r.machineEnv(&s) // the same hooks as the env (Discord channel, task run, live sync)
	out := map[string]any{"sessionId": s.ID, "discordChannel": e["LOBSTER_CHANNEL"], "taskRun": e["JARVIS2_TASK_RUN"], "taskTrigger": e["TASK_TRIGGER"]}
	if n, err := strconv.Atoi(e["JARVIS2_LIVE_SYNC_SECONDS"]); err == nil {
		out["liveSyncSeconds"] = n
	}
	if p := tunnelProof(os.Getenv("JARVIS2_TUNNEL_KEY"), sid); p != "" {
		out["tunnelProof"] = p
	}
	return out, nil
}

// ---- deliveries ----------------------------------------------------------------------------------------------

// SignedRequest: a machine's request exactly as it signed it (machine/deliver.go checks it against its line's keys)
type SignedRequest struct {
	Machine string `json:"machine"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	At      string `json:"at"`
	Body    string `json:"body"` // base64
	Sig     string `json:"sig"`
}

func signedRequestOf(req *http.Request, machine string, body []byte) *SignedRequest {
	return &SignedRequest{Machine: machine, Method: req.Method, Path: req.URL.Path, At: req.Header.Get("X-Time"),
		Body: base64.StdEncoding.EncodeToString(body), Sig: req.Header.Get("X-Sig")}
}

type Delivery struct {
	ID      string         `json:"id"`
	Kind    string         `json:"kind"` // wakeup | cron | watch | watch-fail | nudge | continue | upgraded | lease-* | request-outcome | peer | resume-prompt
	Request *SignedRequest `json:"request,omitempty"`
	Run     int            `json:"run,omitempty"`
	Minutes int            `json:"minutes,omitempty"`
	Jobs    int            `json:"jobs,omitempty"`
	From    string         `json:"from,omitempty"` // upgraded: the old and new size (memory.go)
	To      string         `json:"to,omitempty"`
	// leases.go: the device (a lease name), whether Deyao had taken it over and the holder was interrupted by that
	Device      string `json:"device,omitempty"`
	Handover    bool   `json:"handover,omitempty"`
	Interrupted bool   `json:"interrupted,omitempty"`
	// outcomes.go: request-outcome — the decided items of the session's own filing (Request)
	Outcomes []OutcomeItem `json:"outcomes,omitempty"`
	// peermsg.go: a peer message, with its verified sender and direction
	Peer *PeerNote `json:"peer,omitempty"`
	// resume-prompt: Deyao's words from the app (machine/deliver.go takes them only under the phone's approval)
	Text string `json:"text,omitempty"`
	// messages.go: the phone's approval of this very message (a signed batch it is in, or a rule for its kind)
	Approval *Doc `json:"approval,omitempty"`
	// Preview: the machine only renders the text and answers it (messages.go previewText)
	Preview bool `json:"preview,omitempty"`
	Attest  *Doc `json:"attest"`
}

type DeliveryResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Text: a preview's text, or the machine's own text when the phone signed another (messages.go)
	Text string `json:"text,omitempty"`
	// NeedsApproval: refused only for want of the phone's approval of this message
	NeedsApproval bool `json:"needsApproval,omitempty"`
}

var deliveries = struct {
	sync.Mutex
	queues  map[string]chan Delivery
	results map[string]chan DeliveryResult
}{queues: map[string]chan Delivery{}, results: map[string]chan DeliveryResult{}}

func deliveryQueue(machine string) chan Delivery {
	deliveries.Lock()
	defer deliveries.Unlock()
	q := deliveries.queues[machine]
	if q == nil {
		q = make(chan Delivery, 16)
		deliveries.queues[machine] = q
	}
	return q
}

// attested: what the core attests for a delivery (the machine recomputes it the same way)
func attested(d Delivery) ([]byte, string, error) {
	switch d.Kind {
	case "wakeup", "cron", "watch", "watch-fail":
		if d.Request == nil {
			return nil, "", errors.New("no signed request")
		}
		b, err := base64.StdEncoding.DecodeString(d.Request.Body)
		return b, "session-signed:" + d.Request.Machine, err
	case "continue":
		return []byte("continue"), "image-text", nil
	case "resume-prompt":
		p, err := cleanResumePrompt(d.Text)
		if err != nil || p == "" {
			return nil, "", errors.New("resume-prompt: empty or too long")
		}
		return []byte(p), "deyao", nil
	case "request-outcome":
		b, err := outcomeAttested(d)
		if err != nil {
			return nil, "", err
		}
		return b, "session-signed:" + d.Request.Machine, nil
	case "lease-granted", "lease-taken", "lease-back":
		if !leaseNameRE.MatchString(d.Device) {
			return nil, "", errors.New("lease: not a device name")
		}
		switch d.Kind {
		case "lease-taken":
			return []byte(leaseTakenText(d.Device)), "image-text", nil
		case "lease-back":
			return []byte(leaseBackText(d.Device)), "image-text", nil
		}
		origin := "image-text"
		if d.Request != nil {
			origin = "session-signed:" + d.Request.Machine
		}
		return []byte(leaseGrantedText(d.Device, int64(d.Minutes), d.Handover, d.Interrupted, signedPrompt(d.Request))), origin, nil
	case "peer":
		return peerAttested(d.Peer)
	case "nudge":
		return []byte(nudgeText(d.Jobs, time.Duration(d.Minutes)*time.Minute)), "image-text", nil
	case "upgraded":
		if sizeMemGB(d.From) == 0 || sizeMemGB(d.To) == 0 {
			return nil, "", errors.New("upgraded: not a machine size")
		}
		return []byte(upgradedText(d.From, d.To)), "image-text", nil
	}
	return nil, "", fmt.Errorf("unknown delivery %s", d.Kind)
}

var errNotVouched = errors.New("this wasn't asked for by the session itself (no session-signed request), and nothing else vouches for it: not delivered")

// deliverVouched: resume the session when it is paused, wait for it, then hand the machine the delivery with the
// core's attestation and wait for its answer. A message that waits for Deyao's approval (messages.go) counts as handed
// over: the approval queue delivers it, or tells whoever asked.
func (r *Router) deliverVouched(sid string, d Delivery) error {
	return handedOver(r.deliverVouchedOpts(sid, d, true, nil))
}

// deliverVouchedRunning: only into a running session (errSkip otherwise): nothing is started for it (outcomes.go)
func (r *Router) deliverVouchedRunning(sid string, d Delivery) error {
	return handedOver(r.deliverVouchedOpts(sid, d, false, nil))
}

func handedOver(err error) error {
	if errors.Is(err, errAwaitingApproval) {
		return nil
	}
	return err
}

// deliverVouchedOpts: o is who is told when a held message is denied, lapses or fails (messages.go messageOrigin
// covers the session's own wakeups, crons and watches); errAwaitingApproval = held for Deyao
func (r *Router) deliverVouchedOpts(sid string, d Delivery, boot bool, o *Origin) error {
	done, err := r.beginDelivery() // movegate.go: none begins once a handover started; the next leader makes it
	if err != nil {
		return err
	}
	defer done()
	// messages.go: into a session holding a sensitive store (and any resume prompt) only as the phone approved it
	gated := d.Approval == nil && r.needsApproval(sid, d)
	if gated {
		if rule := r.ruleFor(sid, d.Kind); rule != nil {
			d.Approval, gated = rule, false
		}
	}
	state, _ := r.sessionState(sid)
	if gated && state != "started" && !previewOnly(d.Kind) {
		// held without starting anything: the router renders this kind itself
		text, from, note, ok := messageText(d)
		if !ok {
			return fmt.Errorf("a %s delivery the router can't render: not delivered", d.Kind)
		}
		if _, err := r.holdMessage(sid, d, text, from, note, o); err != nil {
			return err
		}
		return errAwaitingApproval
	}
	if !boot && state != "started" {
		if state == "" {
			return errNoSession
		}
		return fmt.Errorf("%w: the session is %s", errSkip, state)
	}
	switch state {
	case "":
		return errNoSession
	case "paused":
		if err := r.Resume(sid, false); err != nil {
			if errors.Is(err, errBusy) {
				return errSkip
			}
			return err
		}
	case "pausing", "destroying", "approval":
		return fmt.Errorf("%w: the session is %s", errSkip, state)
	case "failed":
		return errors.New("the session has failed: Restart it (or Resume) and it gets this")
	}
	if err := r.waitStarted(sid); err != nil {
		return err
	}
	if gated { // the running machine renders the exact text Deyao sees
		text, err := r.previewText(sid, d)
		note := messageNote(d)
		if errors.Is(err, errNoPreview) { // an image from before message approvals: Jarvis's rendering (messages.go)
			t, ok := oldImageText(d)
			if !ok {
				return fmt.Errorf("a %s delivery into a machine that can't preview it, and the router can't render it: not delivered (restart the session onto the newest image)", d.Kind)
			}
			text, note, err = t, strings.TrimSpace(note+" "+noPreviewNote), nil
		}
		if err != nil {
			return err
		}
		if _, err := r.holdMessage(sid, d, text, messageFrom(d), note, o); err != nil {
			return err
		}
		return errAwaitingApproval
	}
	input, origin, err := attested(d)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(input)
	deadline := time.Now().Add(harnessUpMax)
	for {
		var machine string
		r.st.Do(func(p *persisted) {
			if s := p.Sessions[sid]; s != nil {
				machine = s.MachineID
			}
		})
		if machine == "" {
			return errors.New("the session has no running machine")
		}
		a, err := r.attestInput(machine, d.Kind, origin, hex.EncodeToString(sum[:])) // kernelline.go: the core's or the notary's log
		if err != nil {
			return err
		}
		d.ID, d.Attest = randID(), a
		res := make(chan DeliveryResult, 1)
		deliveries.Lock()
		deliveries.results[d.ID] = res
		deliveries.Unlock()
		deliveryQueue(machine) <- d
		var out DeliveryResult
		select {
		case out = <-res:
		case <-time.After(60 * time.Second):
			out = DeliveryResult{ID: d.ID, Error: "the machine didn't answer within 60 s"}
		}
		deliveries.Lock()
		delete(deliveries.results, d.ID)
		deliveries.Unlock()
		if out.OK {
			return nil
		}
		// the harness may still be booting: retry while nobody listens yet
		// (quick at first: a resumed harness is usually up within seconds, and the input lands soon after it is)
		if strings.Contains(out.Error, "target session not found") && time.Now().Before(deadline) {
			step := harnessRetryFast
			if time.Until(deadline) < harnessUpMax-20*time.Second {
				step = scheduleWaitStep
			}
			time.Sleep(step)
			continue
		}
		if out.NeedsApproval && out.Text != "" { // the machine renders another text than the phone signed: Deyao sees it
			d.Approval = nil
			if _, err := r.holdMessage(sid, d, out.Text, messageFrom(d), messageNote(d), o); err != nil {
				return err
			}
			return errAwaitingApproval
		}
		return errors.New("the machine refused or failed: " + out.Error)
	}
}

// ---- the input log, persisted --------------------------------------------------------------------------------
//
// Every entry is core-signed and names the hash of the one before. A core from R2 on keeps none: each entry arrives in
// the answer that made it (attest's answer; beside each cert), and the router appends it to DATA_DIR/input-log.jsonl.
// A new core's chain begins again at seq 0 with no previous hash (the router's file shows where). The core before R2
// kept its entries for reading (POST /input-log): with it the router reads them instead, as before.

var inputLog struct {
	sync.Mutex
	next    int  // the core before R2: the next seq to fetch
	chained bool // the core before R2: its log was started from the persisted head (or there was none)
}

var keptLogProbe struct {
	sync.Mutex
	at  time.Time
	yes bool
}

// coreKeepsInputLog: the running core is one from before R2 (it answers POST /input-log). Re-checked every minute:
// a core restart is a new core, possibly another version.
func (r *Router) coreKeepsInputLog() bool {
	keptLogProbe.Lock()
	defer keptLogProbe.Unlock()
	if time.Since(keptLogProbe.at) < time.Minute {
		return keptLogProbe.yes
	}
	st, _, err := r.core.Raw("POST", "/input-log", []byte(`{"from":1099511627776}`))
	if err != nil {
		return keptLogProbe.yes // unreachable: keep the last answer
	}
	keptLogProbe.yes, keptLogProbe.at = st == 200, time.Now()
	return keptLogProbe.yes
}

// logInputs: entries from the core's answers, appended (nil ones skipped). With a core that keeps its own log, that
// log is read instead.
func (r *Router) logInputs(entries ...*Doc) {
	if r.coreKeepsInputLog() {
		r.persistInputLog()
		return
	}
	inputLog.Lock()
	defer inputLog.Unlock()
	var rows [][]byte
	for _, e := range entries {
		if e == nil || e.Payload == "" {
			continue
		}
		b, _ := json.Marshal(e)
		rows = append(rows, b)
	}
	if err := r.st.AppendLog("", logInput, rows...); err != nil {
		log.Printf("[input-log] %v", err)
	}
}

// persistInputLog: the core before R2 — its new entries, read from it (POST /input-log); a new core of that kind
// first continues from the last persisted entry (chain_from)
func (r *Router) persistInputLog() {
	inputLog.Lock()
	defer inputLog.Unlock()
	var out struct {
		Entries []Doc `json:"entries"`
		Head    Doc   `json:"head"`
	}
	st, b, err := r.core.Raw("POST", "/input-log", []byte(fmt.Sprintf(`{"from":%d}`, inputLog.next)))
	if err != nil || st != 200 || json.Unmarshal(b, &out) != nil {
		return
	}
	var head struct {
		Seq int `json:"seq"`
	}
	out.Head.Decode(&head)
	if head.Seq < inputLog.next { // a new core: its log starts again at 0
		inputLog.next, inputLog.chained = 0, false
		r.persistInputLogLocked(0)
		return
	}
	r.appendInputLog(out.Entries)
}

func (r *Router) persistInputLogLocked(from int) {
	if !inputLog.chained {
		inputLog.chained = true
		if last := r.lastInputLine(); last != "" {
			var d Doc
			if json.Unmarshal([]byte(last), &d) == nil && d.Payload != "" {
				sum := sha256.Sum256([]byte(d.Payload))
				if _, err := r.core.Call("/input-log/chain-from", map[string]string{"head": hex.EncodeToString(sum[:])}); err != nil {
					log.Printf("[input-log] chain_from: %v", err)
				}
			}
		}
	}
	var out struct {
		Entries []Doc `json:"entries"`
	}
	st, b, err := r.core.Raw("POST", "/input-log", []byte(fmt.Sprintf(`{"from":%d}`, from)))
	if err == nil && st == 200 && json.Unmarshal(b, &out) == nil {
		r.appendInputLog(out.Entries)
	}
}

func (r *Router) appendInputLog(entries []Doc) {
	if len(entries) == 0 {
		return
	}
	var rows [][]byte
	next := inputLog.next
	for _, e := range entries {
		var x struct {
			Seq int `json:"seq"`
		}
		e.Decode(&x)
		if x.Seq < next {
			continue
		}
		b, _ := json.Marshal(e)
		rows = append(rows, b)
		next = x.Seq + 1
	}
	if err := r.st.AppendLog("", logInput, rows...); err != nil {
		log.Printf("[input-log] %v", err)
		return
	}
	inputLog.next = next
}

// lastInputLine: the input log's newest entry ("" when none)
func (r *Router) lastInputLine() string {
	l, _ := r.st.TailLog("", logInput, 1)
	if len(l) == 0 {
		return ""
	}
	return string(l[0])
}

// inputLogTick: every minute, for the core before R2 (it logs certs by itself, without a router call)
func (r *Router) inputLogTick() {
	if !r.coreKeepsInputLog() {
		return
	}
	inputLog.Lock()
	first := !inputLog.chained
	inputLog.Unlock()
	if first {
		inputLog.Lock()
		r.persistInputLogLocked(0)
		inputLog.Unlock()
		return
	}
	r.persistInputLog()
}

// ---- routes ---------------------------------------------------------------------------------------------------

func (r *Router) registerVouch(app appRoute, m machineRoute) {
	m("GET /m/config", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		out, err := r.machineConfig(machine)
		if err != nil {
			writeJSON(w, 403, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, out)
	})
	m("GET /m/restore-cert", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		var cert *Doc
		var cc *MasterCert
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine {
				cert, cc = s.RestoreCert, s.RestoreCoreCert
			}
		})
		if cert == nil {
			writeJSON(w, 404, map[string]string{"error": "no restore for this session"})
			return
		}
		out := map[string]any{"cert": cert}
		if cc != nil { // machine/restore.go: an earlier core's cert, through the master key's claim of it
			out["coreCert"], out["coreState"] = cc, r.coreStateDoc()
		}
		writeJSON(w, 200, out)
	})
	m("POST /m/delivery-result", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var res DeliveryResult
		json.Unmarshal(body, &res)
		deliveries.Lock()
		ch := deliveries.results[res.ID]
		deliveries.Unlock()
		if ch != nil {
			select {
			case ch <- res:
			default:
			}
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	app("GET /api/input-log", func(w http.ResponseWriter, req *http.Request) {
		n, _ := strconv.Atoi(req.URL.Query().Get("last"))
		if n <= 0 || n > 2000 {
			n = 200
		}
		lines, err := r.st.TailLog("", logInput, n)
		if err != nil {
			writeErr(w, err)
			return
		}
		out := []json.RawMessage{}
		for _, l := range lines {
			out = append(out, json.RawMessage(l))
		}
		writeJSON(w, 200, map[string]any{"entries": out})
	})
}

func (r *Router) inputLogLoop() {
	for {
		r.inputLogTick()
		time.Sleep(time.Minute)
	}
}

// ---- a pause right after a start --------------------------------------------------------------------------------

var bootGrace = 90 * time.Second

var pulledMachines sync.Map // machine → its secrets pull went through (it is about to finish booting)

func markPulled(machine string)     { pulledMachines.Store(machine, true) }
func hasPulled(machine string) bool { _, ok := pulledMachines.Load(machine); return ok }
