package main

// Task lines (router/tasks.go, DECISIONS 32-37): a machine whose signed harness is "task:<template>" runs that
// template from the image (/opt/jarvis/tasks/<template>, fixed by the cert's image digest) instead of a harness,
// reports the result to /m/task-result, and waits to be paused. No AI is in the loop unless the template is a
// prompt (claude -p). No shell grant is involved, so a line holding a sensitive store runs unattended too.
//
// The script's environment is built here, not inherited: a fixed base (PATH, HOME, …), the router's
// TASK_* / PARAM_* values (not secret, unsigned: the script treats them as data), the run's paths, and the
// line's store values last (the router can't override them). Store values are redacted from the log and the
// output before they leave the machine or reach the snapshot.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	taskHarnessPrefix = "task:"
	taskKeepLogs      = 20
	taskLogMax        = 256 << 10
	taskOutputMax     = 64 << 10
)

var (
	tasksRoot      = "/opt/jarvis/tasks" // baked into the session image (session-image/Dockerfile)
	taskTemplateRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	envNameRE      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	taskReportWait = 10 * time.Second
	taskReportFor  = 30 * time.Minute
)

type taskSpec struct {
	Run            string   `json:"run"`
	Prompt         string   `json:"prompt"`
	TimeoutSeconds *float64 `json:"timeoutSeconds"`
	Model          string   `json:"model"`
}

// TaskResult: as router/tasks.go reads it
type TaskResult struct {
	Run        string    `json:"run"`
	ExitCode   int       `json:"exitCode"`
	TimedOut   bool      `json:"timedOut"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	Log        string    `json:"log"`
	Output     string    `json:"output"`
}

// loadTaskSpec: the template's task.json, with the router's defaults (run.py / run.sh / run.js, else prompt.md)
func loadTaskSpec(dir string) (taskSpec, time.Duration, error) {
	var s taskSpec
	b, err := os.ReadFile(filepath.Join(dir, "task.json"))
	if err != nil {
		return s, 0, fmt.Errorf("no template here: %v", err)
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, 0, fmt.Errorf("task.json: %v", err)
	}
	exists := func(f string) bool { _, err := os.Stat(filepath.Join(dir, f)); return f != "" && err == nil }
	if s.Run == "" && s.Prompt == "" {
		for _, f := range []string{"run.py", "run.sh", "run.js"} {
			if exists(f) {
				s.Run = f
				break
			}
		}
		if s.Run == "" && exists("prompt.md") {
			s.Prompt = "prompt.md"
		}
	}
	for _, f := range []string{s.Run, s.Prompt} {
		if f != "" && (strings.Contains(f, "/") || !exists(f)) {
			return s, 0, fmt.Errorf("%q is not a file of the template", f)
		}
	}
	if s.Run == "" && s.Prompt == "" {
		return s, 0, errors.New("the template has no run file and no prompt")
	}
	timeout := 600 * time.Second
	if s.TimeoutSeconds != nil && *s.TimeoutSeconds >= 10 {
		timeout = time.Duration(*s.TimeoutSeconds * float64(time.Second))
	}
	return s, timeout, nil
}

// taskCommand: Jarvis 1's runner by extension (python3 -u / bash / node / the file itself); a prompt runs
// claude -p in the cert's permission mode with the prompt on stdin ({{field}} filled from TASK_PARAMS)
func taskCommand(dir string, s taskSpec, mode, params string) ([]string, string, error) {
	if s.Run != "" {
		p := filepath.Join(dir, s.Run)
		switch {
		case strings.HasSuffix(p, ".py"):
			return []string{"python3", "-u", p}, "", nil
		case strings.HasSuffix(p, ".sh"):
			return []string{"bash", p}, "", nil
		case strings.HasSuffix(p, ".js"), strings.HasSuffix(p, ".mjs"), strings.HasSuffix(p, ".cjs"):
			return []string{"node", p}, "", nil
		}
		return []string{p}, "", nil
	}
	b, err := os.ReadFile(filepath.Join(dir, s.Prompt))
	if err != nil {
		return nil, "", err
	}
	text := fillPrompt(string(b), params)
	args := []string{"claude", "-p", "--output-format", "text"}
	if mode == "bypass" {
		args = append(args, "--dangerously-skip-permissions")
	} else {
		args = append(args, "--permission-mode", "auto")
	}
	if s.Model != "" {
		args = append(args, "--model", s.Model)
	}
	return args, text, nil
}

var placeholderRE = regexp.MustCompile(`\{\{\s*([a-z][a-z0-9_]*)\s*\}\}`)

// fillPrompt: {{field}} → the parameter's value (lists comma-joined); an unknown field stays as written
func fillPrompt(text, params string) string {
	p := map[string]any{}
	json.Unmarshal([]byte(params), &p)
	return placeholderRE.ReplaceAllStringFunc(text, func(m string) string {
		k := placeholderRE.FindStringSubmatch(m)[1]
		v, ok := p[k]
		if !ok {
			return m
		}
		switch x := v.(type) {
		case nil:
			return ""
		case []any:
			parts := []string{}
			for _, e := range x {
				parts = append(parts, fmt.Sprint(e))
			}
			return strings.Join(parts, ",")
		}
		return fmt.Sprint(v)
	})
}

// taskEnviron: base → passed-through session values → the router's TASK_*/PARAM_* → the run's paths → the
// stores' values (last: the router's env can't replace a secret)
func taskEnviron(osEnv []string, secrets map[string]string, fixed map[string]string) []string {
	m := map[string]string{"LANG": "C.UTF-8", "SHELL": "/bin/bash", "USER": "claude", "LOGNAME": "claude"}
	pass := map[string]bool{"PATH": true, "HOME": true, "TZ": true, "JARVIS_URL": true, "SESSION_API_TOKEN": true,
		"SESSION_ID": true, "JARVIS2_SESSION_ID": true, "LOBSTER_CHANNEL": true, "FLY_MACHINE_ID": true}
	var router [][2]string
	for _, kv := range osEnv {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch {
		case pass[k]:
			m[k] = v
		case (strings.HasPrefix(k, "TASK_") || strings.HasPrefix(k, "PARAM_")) && envNameRE.MatchString(k):
			router = append(router, [2]string{k, v})
		}
	}
	if m["PATH"] == "" {
		m["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	for _, kv := range router {
		m[kv[0]] = kv[1]
	}
	for k, v := range fixed {
		m[k] = v
	}
	for k, v := range secrets {
		if envNameRE.MatchString(k) {
			m[k] = v
		}
	}
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// redact: every store value of 6+ characters, longest first, as [secret NAME]
func redact(text string, secrets map[string]string) string {
	type kv struct{ k, v string }
	var list []kv
	for k, v := range secrets {
		if len(v) >= 6 {
			list = append(list, kv{k, v})
		}
	}
	sort.Slice(list, func(i, j int) bool { return len(list[i].v) > len(list[j].v) })
	for _, e := range list {
		text = strings.ReplaceAll(text, e.v, "[secret "+e.k+"]")
	}
	return text
}

func tailBytes(b []byte, n int) []byte {
	if len(b) > n {
		return b[len(b)-n:]
	}
	return b
}

// execTask: one run of the command, its output into logPath, killed (with its process group) at timeout
func execTask(args []string, stdin string, env []string, dir, logPath string, timeout time.Duration) (code int, timedOut bool, err error) {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return -1, false, err
	}
	defer f.Close()
	cmd := sessionCommand(nil, args[0], args[1:]...)
	cmd.Env, cmd.Dir, cmd.Stdout, cmd.Stderr = env, dir, f, f
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return -1, false, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-time.After(timeout):
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		err = <-done
		timedOut = true
	}
	if err == nil {
		return 0, timedOut, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), timedOut, nil
	}
	return -1, timedOut, err
}

// pruneLogs: the newest taskKeepLogs runs' files stay in ~/artifacts/task-runs (they travel in the snapshot)
func pruneLogs(dir string) {
	ents, _ := os.ReadDir(dir)
	type f struct {
		run string
		at  time.Time
	}
	runs := map[string]time.Time{}
	for _, e := range ents {
		run := strings.TrimSuffix(strings.TrimSuffix(e.Name(), ".log"), ".output")
		if fi, err := e.Info(); err == nil && fi.ModTime().After(runs[run]) {
			runs[run] = fi.ModTime()
		}
	}
	var list []f
	for k, v := range runs {
		list = append(list, f{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].at.After(list[j].at) })
	for _, x := range list[min(len(list), taskKeepLogs):] {
		os.Remove(filepath.Join(dir, x.run+".log"))
		os.Remove(filepath.Join(dir, x.run+".output"))
	}
}

// claudeLoginForPrompt: a prompt task needs a Claude login: the pair of the line's Claude account (as a session's,
// claudelogin.go), else the store's CLAUDE_CREDENTIALS. Returns what was written, to push a refreshed pair back
// afterwards, and whether it is the router's (then a refreshed pair goes back to it).
func claudeLoginForPrompt(secrets map[string]string) (creds []byte, fromRouter bool) {
	{
		c, err := newClient()
		var l routerLogin
		if err == nil {
			l, err = fetchLogin(c, 0, 0, 0)
		}
		if err == nil && l.Credentials == "" {
			err = errors.New("the router holds no Claude login")
		}
		if err == nil {
			creds, fromRouter = []byte(l.Credentials), true
			home, _ := os.UserHomeDir()
			if _, err := os.Stat(filepath.Join(home, ".claude.json")); err != nil && l.Account != "" {
				os.WriteFile(filepath.Join(home, ".claude.json"), []byte(l.Account), 0o600)
			}
		} else if !errors.Is(err, errNoAccount) {
			log.Printf("task: Claude login: %v", err)
		}
	}
	if creds == nil && secrets["CLAUDE_CREDENTIALS"] != "" {
		creds = []byte(secrets["CLAUDE_CREDENTIALS"])
	}
	if creds != nil {
		os.MkdirAll(filepath.Dir(credsPath()), 0o700)
		os.WriteFile(credsPath(), creds, 0o600)
	}
	return creds, fromRouter
}

// runTask: the task line's boot after the checks (prepare): run the template once for JARVIS2_TASK_RUN (none:
// just report ready), report, and wait for the router's pause. Never returns.
func runTask(c *client, template string, secrets map[string]string, stores []string, mode string) {
	run := os.Getenv("JARVIS2_TASK_RUN")
	res := TaskResult{Run: run, StartedAt: time.Now().UTC()}
	if run != "" {
		res = doRun(template, run, secrets, stores, mode)
	} else {
		log.Printf("task %s: no run asked for (the line's first boot): reporting ready", template)
		res.FinishedAt = time.Now().UTC()
	}
	deadline := time.Now().Add(taskReportFor)
	for {
		err := c.json("POST", "/m/task-result", res, nil)
		if err == nil {
			log.Printf("task %s: run %q reported (exit %d)", template, run, res.ExitCode)
			break
		}
		if time.Now().After(deadline) {
			log.Printf("task %s: the result could not be reported: %v", template, err)
			break
		}
		time.Sleep(taskReportWait)
	}
	select {} // the router pauses this machine (snapshot through the supervisor, then the core's kill)
}

func doRun(template, run string, secrets map[string]string, stores []string, mode string) TaskResult {
	res := TaskResult{Run: run, StartedAt: time.Now().UTC()}
	fail := func(msg string) TaskResult {
		res.Error, res.ExitCode, res.FinishedAt = msg, -1, time.Now().UTC()
		return res
	}
	if !taskTemplateRE.MatchString(template) {
		return fail(fmt.Sprintf("bad template name %q", template))
	}
	dir := filepath.Join(tasksRoot, template)
	spec, timeout, err := loadTaskSpec(dir)
	if err != nil {
		return fail(fmt.Sprintf("template %s in this image: %v", template, err))
	}
	home, _ := os.UserHomeDir()
	work, state, runs := filepath.Join(home, "task-work"), filepath.Join(home, "workspace", "task-state"), filepath.Join(home, "artifacts", "task-runs")
	os.RemoveAll(work)
	for _, d := range []string{work, state, runs} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fail(err.Error())
		}
	}
	logPath, outPath := filepath.Join(runs, run+".log"), filepath.Join(runs, run+".output")
	args, stdin, err := taskCommand(dir, spec, mode, os.Getenv("TASK_PARAMS"))
	if err != nil {
		return fail(err.Error())
	}
	var creds []byte
	credsFromRouter := false
	if spec.Prompt != "" {
		creds, credsFromRouter = claudeLoginForPrompt(secrets)
	}
	env := taskEnviron(os.Environ(), secrets, map[string]string{"TASK_DIR": dir, "TASK_TEMPLATE": template, "TASK_RUN": run,
		"TASK_OUTPUT": outPath, "TASK_STATE_DIR": state, "TASK_WORK": work, "TASK_TIMEOUT": fmt.Sprint(int(timeout.Seconds()))})
	log.Printf("task %s: run %s: %s (timeout %s)", template, run, strings.Join(args[:min(len(args), 2)], " "), timeout)
	res.StartedAt = time.Now().UTC()
	code, timedOut, err := execTask(args, stdin, env, work, logPath, timeout)
	res.FinishedAt, res.ExitCode, res.TimedOut = time.Now().UTC(), code, timedOut
	if err != nil {
		res.Error = "could not run: " + err.Error()
	}
	if creds != nil { // claude may have refreshed (rotated) the pair: the router keeps the newest
		if now, err := os.ReadFile(credsPath()); err == nil && !bytes.Equal(now, creds) && credsFromRouter {
			var out map[string]any
			c, err := newClient()
			if err == nil {
				err = c.json("POST", "/m/claude-login", map[string]string{"credentials": string(now)}, &out)
			}
			if err != nil {
				log.Printf("task: pushing the refreshed Claude login: %v", err)
			}
		}
	}
	// redact on disk too: the logs travel in the snapshot and the archive
	logb, _ := os.ReadFile(logPath)
	logs := redact(string(logb), secrets)
	os.WriteFile(logPath, []byte(logs), 0o600)
	res.Log = string(tailBytes([]byte(logs), taskLogMax))
	if f, err := os.Open(outPath); err == nil {
		ob, _ := io.ReadAll(io.LimitReader(f, taskOutputMax))
		f.Close()
		out := redact(string(ob), secrets)
		os.WriteFile(outPath, []byte(out), 0o600)
		res.Output = out
	}
	pruneLogs(runs)
	return res
}
