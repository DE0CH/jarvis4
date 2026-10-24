package main

// Only vouched inputs shape this machine (docs/DESIGN.md "Inputs to a machine", Deyao 2026-10-11). The machine
// gets secrets, so everything that decides what it runs or what its agent reads at its entry points (start,
// resume, restore, and what Jarvis 4 delivers later) must be vouched for by one of:
//
//	(a) the cert: what the phone approved, or what an unattended resume carried over unchanged;
//	(b) the predecessor machine's signature (its snapshot, whose hash the cert names);
//	(c) this line's own signature (what a machine of this line asked for itself: wakeups, crons; deliver.go);
//	(d) a trusted provider over an authenticated channel (GitHub, over SSH with the repo's deploy key).
//
// Nothing the router says on its own reaches a program or the agent, except a few values whose strict format
// can't carry an instruction (formatExceptions). So:
//
//   - the env: the machine throws away whatever env it was started with and keeps only the image's own, Fly's
//     FLY_* values, the core's key and the router's address (cleanEnv), before anything else runs;
//   - the settings come from the cert (Options.Config / Options.Once); a cert without a config vouches for none: no
//     prompt, title, model, rollback, restore, one-shot, API proxy or task parameters; the repos are only those whose
//     deploy-key store the cert names.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const imageEnvFile = "/opt/jarvis/image.env" // the image's own ENV, written at build (session-image/Dockerfile)

// what Fly itself sets in a machine (values only: they never name code)
var flyEnv = []string{"FLY_MACHINE_ID", "FLY_APP_NAME", "FLY_REGION", "FLY_PRIVATE_IP", "FLY_PUBLIC_IP", "FLY_IMAGE_REF",
	"FLY_ALLOC_ID", "FLY_VM_MEMORY_MB", "PRIMARY_REGION"}

var (
	flyValueRE = regexp.MustCompile(`^[A-Za-z0-9:._@/+-]{0,200}$`)
	b64KeyRE   = regexp.MustCompile(`^[A-Za-z0-9+/]{60,120}={0,2}$`)
	routerRE   = regexp.MustCompile(`^http://[A-Za-z0-9][A-Za-z0-9._-]{0,200}(:[0-9]{1,5})?/?$`)
	// JARVIS2_URL: one router address, or several comma-separated (the gateways, routerdial.go): each one as routerRE
	// a GitHub owner/name: an owner never starts with a dot, a name is never . or ..
	sourceRE = regexp.MustCompile(`^source-[0-9a-f]{32}$`)
	ghRepoRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}$`)
)

// cleanEnv: the env this machine runs with, from the env it was started with: the image's ENV (imageEnv, fixed by
// the image digest), Fly's values, the core's key and the router's address. Everything else is dropped.
func cleanEnv(started []string, imageEnv []string) ([]string, error) {
	m := map[string]string{}
	for _, kv := range imageEnv {
		if k, v, ok := strings.Cut(kv, "="); ok && envNameRE.MatchString(k) {
			m[k] = v
		}
	}
	if m["PATH"] == "" {
		m["PATH"] = "/home/claude/.local/bin:/usr/local/bin:/usr/bin:/bin"
	}
	m["HOME"], m["USER"], m["LOGNAME"], m["SHELL"] = "/home/claude", "claude", "claude", "/bin/bash"
	if m["LANG"] == "" {
		m["LANG"] = "C.UTF-8"
	}
	got := map[string]string{}
	for _, kv := range started {
		if k, v, ok := strings.Cut(kv, "="); ok {
			got[k] = v
		}
	}
	for _, k := range flyEnv {
		if v, ok := got[k]; ok && flyValueRE.MatchString(v) {
			m[k] = v
		}
	}
	key, root := strings.TrimSpace(got[coreKeyEnv]), strings.TrimSpace(got[kernelRootEnv])
	switch {
	case b64KeyRE.MatchString(key):
		m[coreKeyEnv] = key
	case b64KeyRE.MatchString(root) && json.Valid([]byte(got[kernelRosterEnv])) && sourceRE.MatchString(strings.TrimSpace(got[kernelSourceEnv])):
		// kernelboot.go: the kernel's spawner started it: the root key, its roster and the source, from its Fly config
		// (the roster is checked against the root key at boot)
		m[kernelRootEnv], m[kernelRosterEnv], m[kernelSourceEnv] = root, got[kernelRosterEnv], strings.TrimSpace(got[kernelSourceEnv])
	default:
		return nil, errors.New("no core key (" + coreKeyEnv + ") or kernel root key, roster and source (" + kernelRootEnv + ", " + kernelRosterEnv + ", " + kernelSourceEnv + ") in the machine's config")
	}
	if u := strings.TrimSpace(got["JARVIS2_URL"]); routerURLsOK(u) {
		m["JARVIS2_URL"] = u
	}
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out, nil
}

func readImageEnv() []string {
	b, err := os.ReadFile(imageEnvFile)
	if err != nil {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// ensureCleanEnv: boot's first step. When the env isn't already the clean one, re-exec with it (so even the Go
// runtime's own variables, read before main, come from the clean env).
func ensureCleanEnv() error {
	clean, err := cleanEnv(os.Environ(), readImageEnv())
	if err != nil {
		return err
	}
	cur := append([]string(nil), os.Environ()...)
	sort.Strings(cur)
	if strings.Join(cur, "\x00") == strings.Join(clean, "\x00") {
		return nil
	}
	dropped := []string{}
	keep := map[string]bool{}
	for _, kv := range clean {
		k, _, _ := strings.Cut(kv, "=")
		keep[k] = true
	}
	for _, kv := range cur {
		if k, _, _ := strings.Cut(kv, "="); !keep[k] {
			dropped = append(dropped, k)
		}
	}
	if len(dropped) > 0 {
		log.Printf("env: dropping what the core didn't set: %s", strings.Join(dropped, " "))
	}
	return syscall.Exec("/proc/self/exe", os.Args, clean)
}

// ---- the settings the cert vouches for ------------------------------------------------------------------------

// SessionConfig: Options.Config (router/vouch.go builds it, the app's shell shows and checks it before Face ID)
type SessionConfig struct {
	V           int             `json:"v"`
	Label       string          `json:"label,omitempty"`
	Prompt      string          `json:"prompt,omitempty"`
	Model       string          `json:"model,omitempty"`
	Repos       []string        `json:"repos,omitempty"`
	Content     []string        `json:"content,omitempty"` // content stores: content-sync pulls each into ~/content/<name>/ through the router
	OneShot     bool            `json:"oneShot,omitempty"`
	APIProxy    bool            `json:"apiProxy,omitempty"`
	Attachments []AttachmentRef `json:"attachments,omitempty"`
	Restore     *RestoreRef     `json:"restore,omitempty"`
	Task        *TaskConfig     `json:"task,omitempty"`
	// the session's Claude account (router/claudeaccounts.go), signed for the phone to show; the login itself comes
	// from the router (claudelogin.go), which this doesn't check (DECISIONS 185)
	ClaudeAccount string `json:"claudeAccount,omitempty"`
}

type AttachmentRef struct {
	Name   string `json:"name"`
	Sha256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// RestoreRef: the archived snapshot a new line starts from: the old line's machine and the snapshot's hash
type RestoreRef struct {
	Machine string `json:"machine"`
	Sha256  string `json:"sha256"`
}

type TaskConfig struct {
	Instance string         `json:"instance"`
	Name     string         `json:"name"`
	Params   map[string]any `json:"params"`
}

// OnceInputs: Options.Once — this machine's one-time inputs (approved on the phone, never carried over)
type OnceInputs struct {
	Prompt   string `json:"prompt,omitempty"`   // a resume's prompt: typed into the resumed conversation
	Rollback string `json:"rollback,omitempty"` // drop every transcript line from the first containing it
}

// Vouched: what this machine may use, each piece with its voucher
type Vouched struct {
	Cert   Cert
	Config SessionConfig
	Once   OnceInputs
	Ex     FormatExceptions
}

var (
	modelRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:\[\]-]{0,99}$`)
	sha256RE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	machineIDRE = regexp.MustCompile(`^[a-z0-9]{1,40}$`)
	contentRE   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$`)
)

// vouch: the cert's settings, strictly read. A field the machine doesn't know refuses the whole config (the phone
// showed it; this machine must not silently skip what Deyao approved).
func vouch(cert Cert) (Vouched, error) {
	v := Vouched{Cert: cert}
	if s := cert.Options.Config; s != "" {
		d := json.NewDecoder(strings.NewReader(s))
		d.DisallowUnknownFields()
		if err := d.Decode(&v.Config); err != nil {
			return v, fmt.Errorf("the cert's config: %w", err)
		}
		c := &v.Config
		if c.Model != "" && !modelRE.MatchString(c.Model) {
			return v, fmt.Errorf("the cert's model %q", c.Model)
		}
		for _, r := range c.Repos {
			if rp := repoOfURL(r); !ghRepoRE.MatchString(rp) || strings.HasSuffix(rp, "/.") || strings.HasSuffix(rp, "/..") || !validRepo(rp) {
				return v, fmt.Errorf("the cert's repo %q isn't a GitHub repo", r)
			}
		}
		for _, n := range c.Content {
			if !contentRE.MatchString(n) {
				return v, fmt.Errorf("the cert's content store %q", n)
			}
		}
		for _, a := range c.Attachments {
			if !plainName(a.Name) || !sha256RE.MatchString(a.Sha256) || a.Size < 0 {
				return v, fmt.Errorf("the cert's attachment %q", a.Name)
			}
		}
		if r := c.Restore; r != nil && (!machineIDRE.MatchString(r.Machine) || !sha256RE.MatchString(r.Sha256)) {
			return v, errors.New("the cert's restore")
		}
		if t := c.Task; t != nil && !taskTemplateRE.MatchString(t.Instance) && t.Instance != "" {
			return v, errors.New("the cert's task instance")
		}
	}
	if s := cert.Options.Once; s != "" {
		d := json.NewDecoder(strings.NewReader(s))
		d.DisallowUnknownFields()
		if err := d.Decode(&v.Once); err != nil {
			return v, fmt.Errorf("the cert's one-time inputs: %w", err)
		}
		if v.Once.Rollback != "" && len(v.Once.Rollback) < 4 {
			return v, errors.New("the cert's rollback marker is too short")
		}
	}
	return v, nil
}

// repoOfURL: owner/name of a GitHub https or ssh URL ("" otherwise)
func repoOfURL(u string) string {
	u = strings.TrimSpace(u)
	for _, p := range []string{"https://github.com/", "git@github.com:", "ssh://git@github.com/"} {
		if rest, ok := strings.CutPrefix(u, p); ok {
			return strings.TrimSuffix(strings.TrimSuffix(rest, "/"), ".git")
		}
	}
	return ""
}

// reposToClone: the cert's repos, or, from a cert that names none, each repo whose deploy-key store
// the cert gives this machine (the store names the repo; the core wrote it). Never the router's list.
func reposToClone(v Vouched, secrets map[string]string) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(repo string) {
		if ghRepoRE.MatchString(repo) && validRepo(repo) && !seen[strings.ToLower(repo)] {
			seen[strings.ToLower(repo)] = true
			out = append(out, "https://github.com/"+repo+".git")
		}
	}
	if v.Config.Repos != nil {
		for _, r := range v.Config.Repos {
			add(repoOfURL(r))
		}
		return out
	}
	for _, k := range deployKeys(secrets) {
		add(k.Repo)
	}
	return out
}

// ---- values the router may give on its own (their format can't carry an instruction) -----------------------

// FormatExceptions: GET /m/config. Every one is listed in docs/DESIGN.md "Inputs to a machine".
type FormatExceptions struct {
	SessionID       string `json:"sessionId"`       // the router's id for the session: s + hex
	DiscordChannel  string `json:"discordChannel"`  // a Discord channel id: digits
	LiveSyncSeconds int    `json:"liveSyncSeconds"` // how often the transcripts go to the search index
	TaskRun         string `json:"taskRun"`         // the run a task line's machine is started for: an id
	TaskTrigger     string `json:"taskTrigger"`     // what started it: a word
	TunnelProof     string `json:"tunnelProof"`     // the router's proof for the cf-tunnel Worker: a token
}

var (
	sessionIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	digitsRE    = regexp.MustCompile(`^[0-9]{1,32}$`)
	wordRE      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	tokenRE     = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{1,512}$`)
)

// checkExceptions: each value in its format, or dropped
func checkExceptions(in FormatExceptions) FormatExceptions {
	out := FormatExceptions{}
	if sessionIDRE.MatchString(in.SessionID) {
		out.SessionID = in.SessionID
	}
	if digitsRE.MatchString(in.DiscordChannel) {
		out.DiscordChannel = in.DiscordChannel
	}
	if in.LiveSyncSeconds >= 5 && in.LiveSyncSeconds <= 86400 {
		out.LiveSyncSeconds = in.LiveSyncSeconds
	}
	if sessionIDRE.MatchString(in.TaskRun) {
		out.TaskRun = in.TaskRun
	}
	if wordRE.MatchString(in.TaskTrigger) {
		out.TaskTrigger = in.TaskTrigger
	}
	if tokenRE.MatchString(in.TunnelProof) {
		out.TunnelProof = in.TunnelProof
	}
	return out
}

func fetchExceptions(c *client) FormatExceptions {
	var ex FormatExceptions
	if err := c.json("GET", "/m/config", nil, &ex); err != nil {
		log.Printf("config: none from the router (%v)", err)
	}
	if ex.TunnelProof == "" {
		ex.TunnelProof = tunnelProof(c) // tunnelproof.go (an older router serves it on its own)
	}
	return checkExceptions(ex)
}

// ---- the harness's env, built from vouched values only --------------------------------------------------------

// harnessEnv: the clean env plus exactly what the cert, the secrets and the format exceptions give.
// firstMachine: the first machine of a new line (the first prompt and its attachments are its alone).
func harnessEnv(clean []string, v Vouched, me string, firstMachine bool, secrets map[string]string) []string {
	return harnessSpec{Clean: clean, Fixed: harnessFixed(v, me, firstMachine)}.env(secrets)
}

// harnessSpec: the harness's env without any secret value, as boot hands it to the keeper (keeper.go), which adds the
// secrets the supervisor holds at each start of the harness: the clean env, then the secrets over it, then Fallback
// where neither set the key, then Fixed over everything.
type harnessSpec struct {
	Clean    []string          `json:"clean"`
	Fixed    map[string]string `json:"fixed"`
	Fallback map[string]string `json:"fallback,omitempty"`
}

func (h harnessSpec) env(secrets map[string]string) []string {
	m := map[string]string{}
	for _, kv := range h.Clean {
		if k, val, ok := strings.Cut(kv, "="); ok {
			m[k] = val
		}
	}
	for k, val := range secrets { // the secrets in the harness's env (RAM only; the supervisor holds them, secrets.go)
		if envNameRE.MatchString(k) {
			m[k] = val
		}
	}
	for k, val := range h.Fallback {
		if _, ok := m[k]; !ok {
			m[k] = val
		}
	}
	for k, val := range h.Fixed {
		m[k] = val
	}
	out := make([]string, 0, len(m))
	for k, val := range m {
		out = append(out, k+"="+val)
	}
	sort.Strings(out)
	return out
}

// harnessFixed: what the cert and the format exceptions set in the harness's env (over the clean env and the secrets)
func harnessFixed(v Vouched, me string, firstMachine bool) map[string]string {
	m := map[string]string{}
	sid := v.Ex.SessionID
	if sid == "" {
		sid = me
	}
	m["SESSION_HARNESS"], m["SESSION_PERMISSION_MODE"] = v.Cert.Options.Harness, certMode(v.Cert)
	m["SESSION_ID"], m["JARVIS2_SESSION_ID"], m["TUNNEL_ID"] = sid, sid, sid
	m["JARVIS_URL"], m["SESSION_API_TOKEN"] = "http://"+apiProxyAddr, "jarvis2-local-proxy"
	if !viaHarnessSend(v.Cert.Options.Harness) {
		// Jarvis 1's scripts insist on these before calling the local API; the Paseo and OpenClaw harnesses take them as
		// "publish the web UI through the tunnel" (the router's old sessionAPIEnv rule)
		m["CF_ACCESS_CLIENT_ID"], m["CF_ACCESS_CLIENT_SECRET"] = "jarvis2-local-proxy", "jarvis2-local-proxy"
	}
	if v.Ex.DiscordChannel != "" {
		m["LOBSTER_CHANNEL"] = v.Ex.DiscordChannel
	}
	if v.Ex.TunnelProof != "" {
		m["TUNNEL_AGENT_SECRET"] = v.Ex.TunnelProof
	}
	c := v.Config
	if c.Label != "" {
		m["SESSION_LABEL"] = c.Label
	}
	if c.Model != "" {
		m["SESSION_MODEL"] = c.Model
	}
	if c.OneShot {
		m["SESSION_ONE_SHOT"] = "1"
	}
	if c.APIProxy {
		m["SESSION_API_PROXY"] = "1"
	}
	if len(c.Content) > 0 {
		// Jarvis 1's entrypoint runs `content-sync pull` at every boot; content-sync talks to $JARVIS_URL (apiproxy.go)
		m["SESSION_CONTENT"] = strings.Join(c.Content, ",")
	}
	switch {
	case firstMachine && c.Prompt != "":
		m["SESSION_PROMPT"] = c.Prompt
	case !firstMachine && v.Once.Prompt != "":
		m["SESSION_PROMPT"] = v.Once.Prompt
	}
	return m
}

// vouchedPath: what the supervisor process (started before the cert is read) needs of the vouched values
var vouchedPath = dir + "/vouched.json" // a var so tests can move it

func writeVouched(v Vouched) {
	b, _ := json.Marshal(map[string]any{"liveSyncSeconds": v.Ex.LiveSyncSeconds, "sessionId": v.Ex.SessionID})
	os.WriteFile(vouchedPath, b, 0o644)
}

// sessionID: the router's id for this session (a format exception), else the machine id
func sessionID(me string) string {
	b, err := os.ReadFile(vouchedPath)
	if err == nil {
		var m struct {
			SessionID string `json:"sessionId"`
		}
		if json.Unmarshal(b, &m) == nil && sessionIDRE.MatchString(m.SessionID) {
			return m.SessionID
		}
	}
	return me
}

func readVouchedInt(k string) int {
	b, err := os.ReadFile(vouchedPath)
	if err != nil {
		return 0
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	f, _ := m[k].(float64)
	return int(f)
}

// taskVouchedEnv: a task line's values for task.go (which reads TASK_* / PARAM_* from the process env): the
// instance and its parameters from the cert, the run id and trigger as format exceptions
func taskVouchedEnv(v Vouched) []string {
	sid := v.Ex.SessionID
	if sid == "" {
		sid = v.Cert.Machine.ID
	}
	out := []string{"SESSION_ID=" + sid, "JARVIS2_SESSION_ID=" + sid, "JARVIS_URL=http://" + apiProxyAddr, "SESSION_API_TOKEN=jarvis2-local-proxy"}
	if v.Ex.DiscordChannel != "" {
		out = append(out, "LOBSTER_CHANNEL="+v.Ex.DiscordChannel)
	}
	if v.Ex.TaskRun != "" {
		out = append(out, "JARVIS2_TASK_RUN="+v.Ex.TaskRun, "TASK_RUN="+v.Ex.TaskRun, "TASK_TRIGGER="+v.Ex.TaskTrigger)
	}
	t := v.Config.Task
	if t == nil {
		return append(out, "TASK_PARAMS={}")
	}
	pj, _ := json.Marshal(t.Params)
	out = append(out, "TASK_INSTANCE="+t.Instance, "TASK_NAME="+t.Name, "TASK_PARAMS="+string(pj))
	for k, val := range t.Params {
		name := "PARAM_" + strings.ToUpper(k)
		if envNameRE.MatchString(name) {
			out = append(out, name+"="+paramValue(val))
		}
	}
	return out
}

// paramValue: router/tasks.go paramEnv
func paramValue(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case []any:
		parts := []string{}
		for _, e := range x {
			parts = append(parts, fmt.Sprint(e))
		}
		return strings.Join(parts, ",")
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case string:
		return x
	}
	b, _ := json.Marshal(v)
	return string(b)
}
