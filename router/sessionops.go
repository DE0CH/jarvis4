package main

// The session operations Jarvis 1 has beyond create/pause/resume/destroy (docs/PARITY.md "Session lifecycle"):
//
//   permission mode   POST /api/sessions/:id/permission-mode {mode}: running → in place, Jarvis 1's
//                     set-permission-mode through the "terminal" holder (a grant, standing rule or the
//                     session's allow list); paused → the next start's SESSION_PERMISSION_MODE
//   resume options    POST /api/sessions/:id/resume {size, model, apiProxy}: applied before the resume.
//                     None of them is in the core's Options (only the harness is), so the dead-machine rule
//                     still approves the resume: they are the router's unsigned word, like at New session.
//   restart           POST /api/sessions/:id/restart {env, rollback: {dropFromMarker}, prompt, upgrade}: pause (if
//                     running) + resume on the same image (upgrade: the newest, through its resume-upgrade approval). `env` patches the machine env with NON-secret
//                     keys only (secrets come from stores); a rollback is applied by the next machine to the
//                     snapshot it has verified (machine/rollback.go), since the router can't edit a
//                     machine-signed snapshot.
//   API proxy         New session / resume {apiProxy}: SESSION_API_PROXY=1 in the machine env
//   idempotent create the New Session form's requestId: a repeat answers the session it already made
//   busy              /api/state: the lifecycle action holding a session ({kind, since}); `wake`: the last
//                     permission-mode / restart job ({kind, phase, error, finishedAt})

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SessionOps: the per-session settings of these operations (Session.Ops, persisted)
type SessionOps struct {
	APIProxy bool              `json:"apiProxy,omitempty"`
	Env      map[string]string `json:"env,omitempty"`      // non-secret env patch, kept for every later start
	Rollback *RollbackMark     `json:"rollback,omitempty"` // for the next start only (see rollbackEnv)
	Upload   string            `json:"upload,omitempty"`   // first-prompt attachments (uploads.go)
	Attach   []AttachFile      `json:"attachments,omitempty"`
	// a switch to bypass that waits on a terminal grant in the Inbox (askModeGrant): it runs once the phone signs it
	ModeAfterGrant *ModeAfterGrant `json:"modeAfterGrant,omitempty"`
	// accountswap.go: a switch of a paused session's Claude account asked for "continue": typed into its chat once its
	// next start's Claude host is up and idle (autopilot.go)
	ContinueAfterStart bool `json:"continueAfterStart,omitempty"`
}

// ModeAfterGrant: raising a running session to bypass needs a fresh phone grant for the terminal. Asked for where no
// Face ID sheet can open (the web page, an approved API call, a session's actions), the router files that grant in
// the Inbox and keeps the switch here; when the phone signs the grant (answering request Inbox), AddGrant runs it.
type ModeAfterGrant struct {
	Mode  string    `json:"mode"`
	Inbox string    `json:"inbox"` // the grant request
	Until time.Time `json:"until"` // the request's expiry
}

// RollbackMark: drop every transcript line from the first one containing Marker, in the snapshot of machine
// Pred (the machine the next start succeeds)
type RollbackMark struct {
	Marker string `json:"dropFromMarker"`
	Pred   string `json:"predecessor"`
}

// opsState: in memory only (a router restart forgets running jobs, as Jarvis 1 does)
type opsState struct {
	mu   sync.Mutex
	busy map[string]busyMark
	wake map[string]*wakeJob

	uploadMu sync.Mutex // uploads.go: one writer of an upload's files at a time
	reposMu  sync.Mutex // repos.go: the repo list file
	gh       ghCache
}

type busyMark struct {
	Kind  string    `json:"kind"`
	Since time.Time `json:"since"`
}

type wakeJob struct {
	Kind       string     `json:"kind"`
	Phase      string     `json:"phase"`
	Error      string     `json:"error,omitempty"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
}

func (o *opsState) setBusy(id, kind string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.busy == nil {
		o.busy = map[string]busyMark{}
	}
	if kind == "" {
		delete(o.busy, id)
		return
	}
	o.busy[id] = busyMark{kind, time.Now().UTC()}
}

func (o *opsState) busyOf(id string) *busyMark {
	o.mu.Lock()
	defer o.mu.Unlock()
	if b, ok := o.busy[id]; ok {
		return &b
	}
	return nil
}

// startJob: one permission-mode / restart job per session at a time
func (o *opsState) startJob(id, kind string) (*wakeJob, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.wake == nil {
		o.wake = map[string]*wakeJob{}
	}
	if j := o.wake[id]; j != nil && j.FinishedAt == nil {
		return nil, errBusy
	}
	j := &wakeJob{Kind: kind, Phase: "starting", StartedAt: time.Now().UTC()}
	o.wake[id] = j
	return j, nil
}

// note: something the job's outcome should say although it goes on (shown as its error)
func (o *opsState) note(j *wakeJob, text string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	j.Error = text
}

func (o *opsState) phase(j *wakeJob, phase string, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	j.Phase = phase
	if err != nil {
		j.Error = err.Error()
	}
	if phase == "done" || phase == "failed" {
		now := time.Now().UTC()
		j.FinishedAt = &now
	}
}

func (o *opsState) jobView(id string) map[string]any {
	o.mu.Lock()
	defer o.mu.Unlock()
	j := o.wake[id]
	if j == nil || (j.FinishedAt != nil && time.Since(*j.FinishedAt) > 10*time.Minute) {
		return nil
	}
	return map[string]any{"kind": j.Kind, "phase": j.Phase, "error": nullIfEmpty(j.Error), "startedAt": j.StartedAt, "finishedAt": j.FinishedAt}
}

func init() {
	envHooks = append(envHooks, func(_ *Router, s *Session, e map[string]string) { opsEnv(s, e) })
	stateHooks = append(stateHooks, func(r *Router, out map[string]any) {
		ss, _ := out["sessions"].([]map[string]any)
		if r == nil {
			return
		}
		for _, v := range ss {
			id, _ := v["id"].(string)
			if b := r.ops.busyOf(id); b != nil {
				v["busy"] = b
			}
			if j := r.ops.jobView(id); j != nil {
				v["wake"] = j
			}
		}
	})
}

// opsEnv: the machine env these settings make (a start and a resume; flows.go machineEnv)
func opsEnv(s *Session, e map[string]string) {
	o := s.Ops
	if o == nil {
		return
	}
	for k, v := range o.Env {
		if envKeyAllowed(k) == nil {
			e[k] = v
		}
	}
	if o.APIProxy {
		e["SESSION_API_PROXY"] = "1"
	}
	rollbackEnv(s, e)
	attachEnv(s, e)
}

// rollbackEnv: only for the start that succeeds the machine the rollback was asked against. While a session
// is paused its cert is the predecessor's, so a later start (another predecessor) never repeats it.
func rollbackEnv(s *Session, e map[string]string) {
	rb := s.Ops.Rollback
	if rb == nil || rb.Marker == "" {
		return
	}
	var c struct {
		Machine struct {
			ID string `json:"id"`
		} `json:"machine"`
	}
	if s.Cert == nil || s.Cert.Decode(&c) != nil || c.Machine.ID != rb.Pred {
		return
	}
	e["JARVIS2_ROLLBACK"], e["JARVIS2_ROLLBACK_PRED"] = rb.Marker, rb.Pred
}

// opsOptions: what the phone sees on the new-session approval
func opsOptions(s *Session, o map[string]string) {
	if s.Ops == nil {
		return
	}
	if s.Ops.APIProxy {
		o["apiProxy"] = "on"
	}
	if n := len(s.Ops.Attach); n > 0 {
		o["attachments"] = fmt.Sprintf("%d file(s)", n)
	}
}

func opsView(s *Session, v map[string]any) {
	v["apiProxy"] = "off"
	if s.Ops == nil {
		return
	}
	v["apiProxy"] = onOff(!s.Ops.APIProxy)
	if m := s.Ops.ModeAfterGrant; m != nil && time.Now().Before(m.Until) {
		v["modeAfterGrant"] = map[string]any{"mode": m.Mode, "inbox": m.Inbox, "until": m.Until}
	}
	if len(s.Ops.Env) > 0 {
		keys := make([]string, 0, len(s.Ops.Env))
		for k := range s.Ops.Env {
			keys = append(keys, k)
		}
		v["envKeys"] = keys
	}
}

// ---- idempotent create -------------------------------------------------------------------------------------

// admitSession: under the state lock, before a new session is stored. A requestId seen on a live session
// answers that session (dup); attachments are bound to this session (uploads.go).
func admitSession(d *persisted, s *Session, in NewSession) (dup string, err error) {
	if in.RequestID != "" {
		for _, x := range d.Sessions {
			if x.RequestID == in.RequestID {
				return x.ID, nil
			}
		}
	}
	s.Ops = &SessionOps{APIProxy: in.APIProxy}
	if in.Attachments != nil && len(in.Attachments.Files) > 0 {
		files, err := bindUpload(d, s.ID, in.AttachOwner, in.Attachments)
		if err != nil {
			return "", err
		}
		s.Ops.Upload, s.Ops.Attach = in.Attachments.UploadID, files
	}
	return "", nil
}

// ---- permission mode ----------------------------------------------------------------------------------------

const setPermissionModeCmd = "/usr/local/bin/set-permission-mode "

// SetPermissionMode: running → in place (the supervisor relaunches claude --resume in the new mode within
// ~5 s; nothing else restarts); paused → the next start. Runs in the background; the job is the session's
// `wake` in /api/state.
func (r *Router) SetPermissionMode(id, mode string) (map[string]any, error) {
	if mode != "bypass" {
		mode = "auto"
	}
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	if s.ID == "" {
		return nil, errNoSession
	}
	if s.PermissionMode == mode {
		return map[string]any{"ok": true, "permissionMode": mode, "unchanged": true}, nil
	}
	if s.MachineID == "" { // no machine: the mode applies at its next start (a paused or failed session)
		if s.State != "paused" && s.State != "failed" {
			return nil, fmt.Errorf("session is %s: set the mode once it is running, paused or failed", s.State)
		}
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				x.PermissionMode = mode
			}
		})
		return map[string]any{"ok": true, "permissionMode": mode, "nextStart": true}, nil
	}
	// raising a running session to bypass needs a fresh phone grant (Deyao, 2026-10-09), checked here and by
	// the machine (ExecPhone)
	if mode == "bypass" && !r.HasPhoneGrant(id, "terminal") {
		return nil, &GrantNeeded{Holder: "terminal", Phone: true}
	}
	unlock, err := r.lockArgs(id, "mode", map[string]string{"mode": mode})
	if err != nil {
		return nil, err
	}
	j, err := r.ops.startJob(id, "permission-mode")
	if err != nil {
		unlock()
		return nil, err
	}
	go r.modeRun(id, mode, j, unlock)
	return map[string]any{"started": true, "kind": "permission-mode", "permissionMode": mode, "inPlace": true}, nil
}

// modeRun: the running session's switch to mode, under its job (jobs.go: a replica carrying the job on runs it again:
// setting the mode the session already has is a no-op on the machine)
func (r *Router) modeRun(id, mode string, j *wakeJob, unlock func()) {
	func() {
		defer unlock()
		r.ops.phase(j, "switching", nil)
		exec := r.Exec
		if mode == "bypass" {
			exec = r.ExecPhone
		}
		res, err := exec(id, "terminal", setPermissionModeCmd+mode, 30*time.Second)
		if err == nil && res.Code != 0 {
			err = fmt.Errorf("set-permission-mode exited %d: %s", res.Code, clip(res.Stderr+res.Stdout, 200))
		}
		if err != nil {
			r.markRefused(id, "terminal", err)
			r.ops.phase(j, "failed", err)
			return
		}
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				x.PermissionMode = mode
			}
		})
		r.ops.phase(j, "done", nil)
	}()
}

// askModeGrant: the switch to mode waits on a fresh phone grant for holder: a grant request (10 minutes) goes into
// the Inbox, filed as the caller's, and the switch is kept on the session until that request lapses
func (r *Router) askModeGrant(req *http.Request, id, mode, holder string) (map[string]any, error) {
	o := Origin{Caller: appCaller(req), Call: APICall{Method: req.Method, Path: req.URL.Path, Args: map[string]any{"mode": mode}}, ViaCall: viaCall(req)}
	title := id
	r.st.Do(func(d *persisted) { title = inboxSessionName(d, id) })
	// says what asked and for what: the caller is named from its credential (callerText), this names the session
	why := fmt.Sprintf("Switch session “%s” (%s) to %s permission mode: Claude relaunches in it at once. Raising it to bypass needs this fresh 10-minute terminal grant; the switch runs as soon as it is signed.", title, id, mode)
	q, dup, err := r.FileRequest(requestKindGrant, RequestParams{Session: id, Holder: holder, Minutes: 10}, why, o)
	if err != nil {
		return nil, err
	}
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[id]; s != nil {
			if s.Ops == nil {
				s.Ops = &SessionOps{}
			}
			s.Ops.ModeAfterGrant = &ModeAfterGrant{Mode: mode, Inbox: q.ID, Until: q.Expires}
		}
		// an approved API call's review sheet follows the grant it brought about (apicalls.go)
		if x := d.CallResults[o.ViaCall]; x != nil {
			if !containsString(x.Followups, q.ID) {
				x.Followups = append(x.Followups, q.ID)
			}
			x.Awaiting = nil
		}
	})
	return map[string]any{"waiting": "inbox", "inboxId": q.ID, "duplicate": dup, "needsGrant": holder, "phoneGrant": true, "permissionMode": mode}, nil
}

// modeAfterGrant: the switch kept for the grant request just answered, if a phone grant answered it (answered: request
// id → by a grant, not a rule); taken off the session once answered or lapsed. Inside st.Do.
func modeAfterGrant(s *Session, answered map[string]bool, now time.Time) string {
	if s == nil || s.Ops == nil || s.Ops.ModeAfterGrant == nil {
		return ""
	}
	m := s.Ops.ModeAfterGrant
	phone, hit := answered[m.Inbox]
	if !hit && now.Before(m.Until) {
		return ""
	}
	s.Ops.ModeAfterGrant = nil // answered (a standing rule doesn't allow bypass: nothing runs) or lapsed
	if !phone {
		return ""
	}
	return m.Mode
}

// runModeAfterGrant: the switch a signed grant was waiting for; its outcome is the session's `wake` job, as when
// it is asked for directly
func (r *Router) runModeAfterGrant(id, mode string) {
	if _, err := r.SetPermissionMode(id, mode); err != nil {
		log.Printf("session %s: the switch to %s after the grant: %v", id, mode, err)
		if j, e := r.ops.startJob(id, "permission-mode"); e == nil {
			r.ops.phase(j, "failed", err)
		}
	}
}

// markRefused: a grant refusal shows as the session's needsGrant, so the app offers a grant
func (r *Router) markRefused(id, holder string, err error) {
	if !isGrantRefusal(err) {
		return
	}
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			if x.Live == nil {
				x.Live = &Liveness{}
			}
			x.Live.NeedsGrant = holder
		}
	})
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---- resume options -----------------------------------------------------------------------------------------

type ResumeOptions struct {
	Size     string `json:"size"`
	Model    string `json:"model"`
	APIProxy *bool  `json:"apiProxy"`
}

func (o ResumeOptions) check() error {
	if o.Size != "" && sizeMemGB(o.Size) == 0 {
		return fmt.Errorf("size is small, medium, large or a doubling past it (16gb, 32gb, …)")
	}
	return nil
}

// resumeModel: a model of the session's own harness (harness.go's catalogue)
func resumeModel(harness, model string) error {
	if m, err := sessionModel(harness, model); err != nil || m != model {
		return fmt.Errorf("%q isn't a model of the %s harness (GET /api/models?harness=%s)", model, harness, harness)
	}
	return nil
}

// applyResumeOptions: only to a paused session (they reach the machine through the next start's env and
// /start's size)
func (r *Router) applyResumeOptions(id string, o ResumeOptions) error {
	if err := o.check(); err != nil {
		return err
	}
	if o.Size == "" && o.Model == "" && o.APIProxy == nil {
		return nil
	}
	var err error
	r.st.Do(func(d *persisted) {
		s := d.Sessions[id]
		switch {
		case s == nil:
			err = errNoSession
		case s.State != "paused" && s.State != "failed":
			err = fmt.Errorf("session %s is %s: its next start's options are set while it is paused or failed", id, s.State)
		case o.Model != "" && resumeModel(s.Harness, o.Model) != nil:
			err = resumeModel(s.Harness, o.Model)
		default:
			if o.Size != "" {
				s.Size = o.Size
			}
			if o.Model != "" {
				s.Model = o.Model
			}
			if o.APIProxy != nil {
				if s.Ops == nil {
					s.Ops = &SessionOps{}
				}
				s.Ops.APIProxy = *o.APIProxy
			}
		}
	})
	return err
}

// ---- restart: pause + resume, with an env patch and a transcript rollback -----------------------------------

type RestartRequest struct {
	Env      map[string]any `json:"env"`
	Rollback *struct {
		DropFromMarker string `json:"dropFromMarker"`
	} `json:"rollback"`
	Prompt string `json:"prompt"`
	// Upgrade: resume on the newest session image (its resume-upgrade approval in the Inbox, one Face ID) instead of
	// the same image, e.g. to bring a fixed supervisor to a running session (2026-10-20)
	Upgrade bool `json:"upgrade"`
	ResumeOptions
}

// env keys a patch may never set: the router's and the harness's own settings, the session-API placeholders,
// the loader's
var envReserved = regexp.MustCompile(`^(JARVIS2?_|SESSION_|FLY_|CF_ACCESS_|LOBSTER_|CLAUDE_|ANTHROPIC_|LD_|HOME$|PATH$|USER$|SHELL$|TERM$)`)

// env keys that name a secret: those come only from stores (core-sealed), never the unsigned machine env
var envSecretish = regexp.MustCompile(`(?i)(TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|COOKIE|WEBHOOK|ACCESS_?KEY|API_?KEY|(^|_)(PASS|PWD|AUTH|KEY|API|DSN|SIG|SIGNATURE|SALT|OTP|TOTP|PIN|CERT)(_|$))`)

var envKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

func envKeyAllowed(k string) error {
	switch {
	case !envKeyRE.MatchString(k):
		return fmt.Errorf("bad env name %q", k)
	case envReserved.MatchString(k):
		return fmt.Errorf("%s is set by Jarvis itself", k)
	case envSecretish.MatchString(k):
		return fmt.Errorf("%s looks like a secret: secrets go in a store, never the machine env", k)
	}
	return nil
}

// normalizeEnvPatch: string/number/bool values, at most 32 keys, 2000 characters each; "" or null removes
func normalizeEnvPatch(in map[string]any) (map[string]*string, error) {
	if len(in) > 32 {
		return nil, errors.New("at most 32 env keys")
	}
	out := map[string]*string{}
	for k, v := range in {
		if err := envKeyAllowed(k); err != nil {
			return nil, err
		}
		var s string
		switch x := v.(type) {
		case nil:
			out[k] = nil
			continue
		case string:
			s = x
		case bool, float64:
			s = fmt.Sprint(x)
		default:
			return nil, fmt.Errorf("env %s: a string value", k)
		}
		if len(s) > 2000 || strings.ContainsRune(s, 0) {
			return nil, fmt.Errorf("env %s: at most 2000 characters, no NUL", k)
		}
		if s == "" {
			out[k] = nil
		} else {
			out[k] = &s
		}
	}
	return out, nil
}

// Restart: a running session is paused (its signed snapshot), then the patch and the rollback are recorded,
// then it resumes on the same image (the dead-machine rule). A paused one just resumes.
func (r *Router) Restart(id string, in RestartRequest) (map[string]any, error) {
	patch, err := normalizeEnvPatch(in.Env)
	if err != nil {
		return nil, err
	}
	if err := in.ResumeOptions.check(); err != nil {
		return nil, err
	}
	marker := ""
	if in.Rollback != nil {
		marker = strings.TrimSpace(in.Rollback.DropFromMarker)
		if len(marker) < 4 || len(marker) > 500 || strings.ContainsAny(marker, "\n\r\x00") {
			return nil, errors.New("rollback.dropFromMarker: 4–500 characters on one line")
		}
	}
	prompt, err := cleanResumePrompt(in.Prompt)
	if err != nil {
		return nil, err
	}
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[id]; x != nil {
			s = *x
		}
	})
	if s.ID == "" {
		return nil, errNoSession
	}
	// paused or failed (Resume finishes a failed one's pause first), or running on its machine
	if s.State != "paused" && s.State != "failed" && (s.MachineID == "" || (s.State != "started" && s.State != "initialising")) {
		return nil, fmt.Errorf("session is %s: restart it once it is running, paused or failed", s.State)
	}
	// the whole job is one tracked lifecycle action (drain.go): its pause and resume go on during a drain
	endJob, err := r.beginJob(id, "restart")
	if err != nil {
		return nil, err
	}
	j, err := r.ops.startJob(id, "restart")
	if err != nil {
		endJob()
		return nil, err
	}
	r.ops.setBusy(id, "restarting")
	op := r.lcBeginJob(id, "restart") // lifecycle.go: its pause and resume are this one operation
	op.machine(s.MachineID)
	go func() {
		defer endJob()
		defer r.ops.setBusy(id, "")
		fail := func(err error) {
			r.cancelSpare(id, "the restart failed")
			r.ops.phase(j, "failed", err)
			op.endJob(err)
		}
		if s.MachineID != "" {
			// handover.go: an unattended restart (no prompt, no rollback: those go to the phone) starts its next
			// machine as soon as the old one is told to stop
			var next *nextMachine
			if prompt == "" && marker == "" && !in.Upgrade { // a spare runs the same image: not for an upgrade
				next = r.handoverNext(s, in.ResumeOptions.Size, 0)
			}
			r.ops.phase(j, "snapshotting", nil)
			if err := r.pauseWith(id, next); err != nil {
				fail(err)
				return
			}
			if err := r.waitActionEnd(id, "paused"); err != nil {
				fail(err)
				return
			}
		}
		r.ops.phase(j, "patching", nil)
		var perr error
		r.st.Do(func(d *persisted) {
			x := d.Sessions[id]
			if x == nil || (x.State != "paused" && x.State != "failed") {
				perr = errors.New("the session isn't paused any more (another action started it): restart it again")
				return
			}
			if x.Ops == nil {
				x.Ops = &SessionOps{}
			}
			for k, v := range patch {
				if x.Ops.Env == nil {
					x.Ops.Env = map[string]string{}
				}
				if v == nil {
					delete(x.Ops.Env, k)
				} else {
					x.Ops.Env[k] = *v
				}
			}
			x.Ops.Rollback = nil
			if marker != "" {
				x.Ops.Rollback = &RollbackMark{Marker: marker, Pred: certMachine(x.Cert)}
			}
		})
		if perr == nil {
			perr = r.applyResumeOptions(id, in.ResumeOptions)
		}
		if perr != nil {
			fail(perr)
			return
		}
		r.ops.phase(j, "resuming", nil)
		if err := r.handoverResume(id, prompt, in.Upgrade); err != nil {
			fail(err)
			return
		}
		r.ops.phase(j, "done", nil)
		op.endJob(nil)
	}()
	keys := []string{}
	for k := range patch {
		keys = append(keys, k)
	}
	return map[string]any{"started": true, "kind": "restart", "env": keys, "rollback": marker != "", "upgrade": in.Upgrade}, nil
}

func certMachine(c *Doc) string {
	var x struct {
		Machine struct {
			ID string `json:"id"`
		} `json:"machine"`
	}
	if c == nil || c.Decode(&x) != nil {
		return ""
	}
	return x.Machine.ID
}

// waitState: polls until the session reaches state (or fails / disappears) AND the action that got it there has
// ended. An action sets its end state a moment before it releases the session's lock (its lifecycle record and
// unlock run after), so returning on the state alone let the caller's next action (the resume after a pause) meet
// errBusy, and work of the ended action still run after the caller moved on.
func (r *Router) waitState(id, want string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var st, msg string
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				st, msg = x.State, x.Error
			}
		})
		busy := r.busy(id)
		switch {
		case st == want && !busy:
			return nil
		case st == "":
			return errNoSession
		case st == "failed" && !busy:
			return fmt.Errorf("the session failed: %s", msg)
		case time.Now().After(deadline):
			if busy {
				return fmt.Errorf("the session is %s and its action hasn't ended", st)
			}
			return fmt.Errorf("the session is still %s", st)
		}
		time.Sleep(opsPoll)
	}
}

var opsPoll = 500 * time.Millisecond

// waitActionEnd: a job's step (a pause it began, which holds the session's lock) has ended, with no deadline of its
// own: the action ends by itself (a pause once its snapshot arrives, stalls or its machine goes silent: snapwait.go,
// then the kill's own limit). want = the state it should end in; failed or anything else is the error.
func (r *Router) waitActionEnd(id, want string) error {
	for {
		var st, msg string
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[id]; x != nil {
				st, msg = x.State, x.Error
			}
		})
		switch {
		case st == "":
			return errNoSession
		case r.busy(id):
		case st == want:
			return nil
		case st == "failed":
			return fmt.Errorf("the session failed: %s", msg)
		default:
			return fmt.Errorf("the session is %s", st)
		}
		time.Sleep(opsPoll)
	}
}

// ---- routes -------------------------------------------------------------------------------------------------

func (r *Router) registerSessionOps(app appRoute, m machineRoute) {
	app("POST /api/sessions/{id}/permission-mode", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Mode string `json:"mode"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in)
		out, err := r.SetPermissionMode(req.PathValue("id"), in.Mode)
		// the iPhone app opens its own grant review on the 403 and switches again once it is signed; everyone else
		// (the web page, an approved API call) gets the grant filed in the Inbox, with the switch run when it is signed
		var gn *GrantNeeded
		if errors.As(err, &gn) && gn.Phone && appCaller(req).Kind != "app" {
			out, err = r.askModeGrant(req, req.PathValue("id"), in.Mode, gn.Holder)
		}
		if err != nil {
			scheduleErr(w, err)
			return
		}
		code := 200
		if out["started"] == true || out["waiting"] == "inbox" {
			code = 202
		}
		writeJSON(w, code, out)
	})
	app("POST /api/sessions/{id}/restart", func(w http.ResponseWriter, req *http.Request) {
		var in RestartRequest
		if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in); err != nil && err != io.EOF {
			writeErr(w, fmt.Errorf("bad JSON: %v", err))
			return
		}
		out, err := r.Restart(req.PathValue("id"), in)
		if err != nil {
			scheduleErr(w, err)
			return
		}
		writeJSON(w, 202, out)
	})
	// Jarvis 1's env patch = a restart with only env
	app("POST /api/sessions/{id}/env", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Env map[string]any `json:"env"`
		}
		json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in)
		if len(in.Env) == 0 {
			writeJSON(w, 400, map[string]string{"error": "body.env must be a non-empty object"})
			return
		}
		out, err := r.Restart(req.PathValue("id"), RestartRequest{Env: in.Env})
		if err != nil {
			scheduleErr(w, err)
			return
		}
		writeJSON(w, 202, out)
	})
	r.registerAccountSwitch(app) // accountswap.go
	r.registerUploads(app, m)    // uploads.go
	r.registerRepos(app)         // repos.go: repo list, GitHub picker, usage
}
