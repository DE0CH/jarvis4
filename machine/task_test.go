package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTemplate(t *testing.T, root, name, spec string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "task.json"), []byte(spec), 0o644)
	for f, body := range files {
		os.WriteFile(filepath.Join(dir, f), []byte(body), 0o755)
	}
	return dir
}

func TestLoadTaskSpecAndCommand(t *testing.T) {
	root := t.TempDir()
	d := writeTemplate(t, root, "a", `{"title":"A","timeoutSeconds":30}`, map[string]string{"run.sh": "echo"})
	s, timeout, err := loadTaskSpec(d)
	if err != nil || s.Run != "run.sh" || timeout != 30*time.Second {
		t.Fatalf("%+v %v %v", s, timeout, err)
	}
	args, stdin, _ := taskCommand(d, s, "auto", "")
	if strings.Join(args, " ") != "bash "+filepath.Join(d, "run.sh") || stdin != "" {
		t.Fatalf("%v", args)
	}
	for f, want := range map[string]string{"x.py": "python3 -u", "x.js": "node", "x": filepath.Join(d, "x")} {
		a, _, _ := taskCommand(d, taskSpec{Run: f}, "auto", "")
		if !strings.HasPrefix(strings.Join(a, " "), want) {
			t.Errorf("%s: %v", f, a)
		}
	}
	p := writeTemplate(t, root, "p", `{"title":"P","model":"claude-fable-5-2"}`, map[string]string{"prompt.md": "Summarise {{topic}} for {{ who }}; keep {{unknown}}."})
	s, timeout, err = loadTaskSpec(p)
	if err != nil || s.Prompt != "prompt.md" || timeout != 600*time.Second {
		t.Fatalf("%+v %v", s, err)
	}
	args, stdin, err = taskCommand(p, s, "bypass", `{"topic":"the news","who":["a","b"]}`)
	if err != nil || stdin != "Summarise the news for a,b; keep {{unknown}}." ||
		strings.Join(args, " ") != "claude -p --output-format text --dangerously-skip-permissions --model claude-fable-5-2" {
		t.Fatalf("%v %q %v", args, stdin, err)
	}
	args, _, _ = taskCommand(p, s, "auto", "")
	if !strings.Contains(strings.Join(args, " "), "--permission-mode auto") {
		t.Fatalf("%v", args)
	}
	for _, spec := range []string{`{"run":"missing.sh"}`, `{"run":"../x"}`, `{}`, `not json`} {
		d := writeTemplate(t, root, "bad", spec, nil)
		if _, _, err := loadTaskSpec(d); err == nil {
			t.Errorf("accepted %s", spec)
		}
		os.RemoveAll(d)
	}
}

func TestTaskEnviron(t *testing.T) {
	osEnv := []string{"PATH=/bin", "HOME=/home/claude", "LD_PRELOAD=/evil.so", "BASH_ENV=/evil", "TASK_PARAMS={}", "PARAM_MSG=hi",
		"PARAM_TOKEN=router", "SESSION_PROMPT=x", "JARVIS_URL=http://127.0.0.1:7171", "TASK_OUTPUT=/router/says"}
	env := strings.Join(taskEnviron(osEnv, map[string]string{"PARAM_TOKEN": "store", "API_KEY": "k", "bad name": "x"},
		map[string]string{"TASK_OUTPUT": "/real"}), "\n") + "\n"
	for _, want := range []string{"PATH=/bin\n", "HOME=/home/claude\n", "PARAM_MSG=hi\n", "TASK_PARAMS={}\n", "API_KEY=k\n",
		"PARAM_TOKEN=store\n", "TASK_OUTPUT=/real\n", "JARVIS_URL=http://127.0.0.1:7171\n", "LANG=C.UTF-8\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, not := range []string{"LD_PRELOAD", "BASH_ENV", "SESSION_PROMPT", "bad name", "/router/says"} {
		if strings.Contains(env, not) {
			t.Errorf("leaked %q", not)
		}
	}
}

func TestRedact(t *testing.T) {
	s := redact("key=abcdef123 short=abc long=abcdef123456", map[string]string{"A": "abcdef123", "B": "abcdef123456", "S": "abc"})
	if s != "key=[secret A] short=abc long=[secret B]" {
		t.Fatal(s)
	}
}

func TestExecTask(t *testing.T) {
	dir := t.TempDir()
	logp := filepath.Join(dir, "log")
	code, to, err := execTask([]string{"bash", "-c", "echo out; echo err >&2; exit 4"}, "", os.Environ(), dir, logp, 5*time.Second)
	b, _ := os.ReadFile(logp)
	if code != 4 || to || err != nil || string(b) != "out\nerr\n" {
		t.Fatalf("%d %v %v %q", code, to, err, b)
	}
	code, _, _ = execTask([]string{"bash", "-c", "cat"}, "from stdin", os.Environ(), dir, logp, 5*time.Second)
	if b, _ := os.ReadFile(logp); code != 0 || string(b) != "from stdin" {
		t.Fatalf("%q", b)
	}
	// the timeout kills the whole process group (a child that ignores the parent's death too)
	marker := filepath.Join(dir, "late")
	start := time.Now()
	code, to, _ = execTask([]string{"bash", "-c", "(sleep 1; touch " + marker + ") & sleep 30"}, "", os.Environ(), dir, logp, 200*time.Millisecond)
	if !to || time.Since(start) > 5*time.Second {
		t.Fatalf("no timeout: %d %v", code, to)
	}
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a child outlived the timeout")
	}
	if _, _, err := execTask([]string{filepath.Join(dir, "nope")}, "", nil, dir, logp, time.Second); err == nil {
		t.Fatal("a missing program ran")
	}
}

func TestDoRun(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	old := tasksRoot
	tasksRoot = t.TempDir()
	t.Cleanup(func() { tasksRoot = old })
	writeTemplate(t, tasksRoot, "job", `{"title":"Job","timeoutSeconds":20}`, map[string]string{"run.sh": `
n=$(( $(cat "$TASK_STATE_DIR/n" 2>/dev/null || echo 0) + 1 )); echo $n > "$TASK_STATE_DIR/n"
echo "run $n msg=$PARAM_MSG secret=$API_KEY cwd=$(pwd)"
echo "result $n $API_KEY" > "$TASK_OUTPUT"
[ "$PARAM_FAIL" = true ] && exit 2
exit 0`})
	t.Setenv("PARAM_MSG", "hi")
	t.Setenv("TASK_PARAMS", `{"msg":"hi"}`)
	secrets := map[string]string{"API_KEY": "s3cr3t-value"}
	res := doRun("job", "r1", secrets, nil, "auto")
	if res.Error != "" || res.ExitCode != 0 || res.Run != "r1" {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(res.Log, "run 1 msg=hi secret=[secret API_KEY] cwd="+filepath.Join(home, "task-work")) || res.Output != "result 1 [secret API_KEY]\n" {
		t.Fatalf("%q %q", res.Log, res.Output)
	}
	disk, _ := os.ReadFile(filepath.Join(home, "artifacts", "task-runs", "r1.log"))
	if strings.Contains(string(disk), "s3cr3t") {
		t.Fatal("the log on disk keeps the secret")
	}
	if _, err := os.Stat(filepath.Join(home, ".secrets")); err == nil {
		t.Fatal("~/.secrets written: secrets stay in RAM")
	}
	t.Setenv("PARAM_FAIL", "true")
	res = doRun("job", "r2", secrets, nil, "auto")
	if res.ExitCode != 2 || !strings.Contains(res.Log, "run 2") {
		t.Fatalf("%+v", res) // the state dir carried the count over
	}
	if res := doRun("nope", "r3", secrets, nil, "auto"); res.Error == "" || res.ExitCode != -1 {
		t.Fatalf("%+v", res)
	}
	if res := doRun("../etc", "r4", secrets, nil, "auto"); !strings.Contains(res.Error, "bad template name") {
		t.Fatalf("%+v", res)
	}
}

func TestPruneLogs(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-time.Hour)
	for k := 0; k < taskKeepLogs+3; k++ {
		for _, ext := range []string{".log", ".output"} {
			p := filepath.Join(dir, fmt.Sprintf("r%02d%s", k, ext))
			os.WriteFile(p, []byte("x"), 0o600)
			os.Chtimes(p, base.Add(time.Duration(k)*time.Minute), base.Add(time.Duration(k)*time.Minute))
		}
	}
	pruneLogs(dir)
	ents, _ := os.ReadDir(dir)
	if len(ents) != 2*taskKeepLogs {
		t.Fatalf("%d files", len(ents))
	}
	if _, err := os.Stat(filepath.Join(dir, "r00.log")); err == nil {
		t.Fatal("the oldest stayed")
	}
}
