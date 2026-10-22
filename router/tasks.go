package main

// Tasks (Jarvis 1's lib/tasks.js, DECISIONS 29 and 32-37): templates instantiated with values into INSTANCES,
// run on a click or on a daily SCHEDULE. In Jarvis 4 an instance is a session LINE:
//
//   template  tasks/<name>/task.json + its files, in this repo. Baked into the session image
//             (/opt/jarvis2/tasks) and the router image (/tasks, for the forms). task.json: {title, description?,
//             run? ("run.py" | "run.sh" | "run.js" | any executable) or prompt? ("prompt.md": claude -p),
//             stores? [...], timeoutSeconds? (600), size? ("small"), fields: [{name, label?, type
//             (text|textarea|number|select|multiselect|checkbox), required?, default?, options?, optionsFrom?
//             (stores|content|sizes|models), help?, placeholder?}]}. A (multi)select with optionsFrom "stores" adds
//             the picked store(s) to the line; with "content", the picked content store(s) (content.go: signed in the
//             line's config, so the task's machine may read and write them through the router).
//   instance  {id, template, name, params, size, stores, session}: a new session whose harness is
//             "task:<template>" (signed in the cert's options), approved ONCE on the phone like any new session.
//   run       a resume of that line (approve_by_dead_machine: same stores, options and image, no phone) whose
//             machine runs the template instead of a harness (machine/task.go), reports the result to
//             /m/task-result, and is paused again (snapshot kept: ~/workspace/task-state survives runs).
//   schedule  {id, instance, time "HH:MM", tz, enabled, since}: the router's own daily tick starts a run.
//
// No delivery and no grant is involved: the code that runs is fixed by the cert (image digest + harness), so a
// line holding a sensitive store runs unattended too. Parameters are not secret (they travel in the machine's
// unsigned env as TASK_PARAMS / PARAM_<FIELD>); secrets come only from the line's stores.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	taskHarnessPrefix = "task:"
	taskKeepRuns      = 20
	taskMaxQueued     = 3
	taskScheduleGrace = 2 * time.Hour    // a slot missed by more than this (router down) is skipped
	taskResultGrace   = 15 * time.Minute // a running run past its timeout + this, with no result, is stopped
	taskIdleStarted   = 15 * time.Minute // a started task line with no run and no result is paused after this
	taskStartMax      = 30 * time.Minute // a run whose machine isn't up by then fails (a locked store, a stuck start)
	taskTickEvery     = 15 * time.Second
	taskLogMax        = 256 << 10
	taskOutputMax     = 64 << 10
)

var (
	taskTemplateRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	taskFieldRE    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
	taskStoreRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$`)
	taskTypes      = map[string]bool{"text": true, "textarea": true, "number": true, "select": true, "multiselect": true, "checkbox": true}
	taskSources    = map[string]bool{"stores": true, "content": true, "sizes": true, "models": true}
	taskSizes      = []string{"small", "medium", "large"}
	// tasksDir: the templates as the router image carries them (the session image has its own copy)
	tasksDir = env("TASKS_DIR", "/tasks")
)

func init() {
	envHooks = append(envHooks, taskEnv)
	taskKick = func(r *Router) { go r.tasksTick(time.Now()) }
}

func isTaskHarness(h string) bool { return strings.HasPrefix(h, taskHarnessPrefix) }

// ---- templates ------------------------------------------------------------------------------------------

type TaskOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Sub   string `json:"sub,omitempty"`
}

type TaskField struct {
	Name        string       `json:"name"`
	Label       string       `json:"label"`
	Type        string       `json:"type"`
	Required    bool         `json:"required"`
	Help        string       `json:"help,omitempty"`
	Placeholder string       `json:"placeholder,omitempty"`
	Options     []TaskOption `json:"options,omitempty"`
	OptionsFrom string       `json:"optionsFrom,omitempty"`
	Default     any          `json:"default,omitempty"`
}

type TaskTemplate struct {
	Name           string      `json:"name"`
	Title          string      `json:"title"`
	Description    string      `json:"description"`
	Run            string      `json:"run,omitempty"`
	Prompt         string      `json:"prompt,omitempty"`
	Stores         []string    `json:"stores"`
	TimeoutSeconds int         `json:"timeoutSeconds"`
	Size           string      `json:"size"`
	Fields         []TaskField `json:"fields"`
	Files          []string    `json:"files"`
	Source         string      `json:"source,omitempty"`
	Error          string      `json:"error,omitempty"`
}

func isSelect(t string) bool { return t == "select" || t == "multiselect" }

func parseOption(raw json.RawMessage) (TaskOption, error) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return TaskOption{Value: s, Label: s}, nil
	}
	var o struct {
		Value any    `json:"value"`
		Label string `json:"label"`
		Sub   string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &o); err != nil || o.Value == nil {
		return TaskOption{}, errors.New("an option is a string or {value, label?, sub?}")
	}
	v := fmt.Sprint(o.Value)
	if o.Label == "" {
		o.Label = v
	}
	return TaskOption{Value: v, Label: o.Label, Sub: o.Sub}, nil
}

// parseTemplate: a task.json (+ the dir's file list) → the template, or an error for a bad spec
func parseTemplate(name string, spec []byte, files []string) (*TaskTemplate, error) {
	if !taskTemplateRE.MatchString(name) {
		return nil, fmt.Errorf("template dir name %q must be lowercase letters/digits/dashes", name)
	}
	var s struct {
		Title          string            `json:"title"`
		Description    string            `json:"description"`
		Run            string            `json:"run"`
		Prompt         string            `json:"prompt"`
		Stores         []string          `json:"stores"`
		TimeoutSeconds *float64          `json:"timeoutSeconds"`
		Size           string            `json:"size"`
		Fields         []json.RawMessage `json:"fields"`
	}
	if err := json.Unmarshal(spec, &s); err != nil {
		return nil, fmt.Errorf("task.json: %v", err)
	}
	t := &TaskTemplate{Name: name, Title: strings.TrimSpace(s.Title), Description: s.Description, Files: files, Stores: []string{}, Fields: []TaskField{}}
	if t.Title == "" {
		return nil, errors.New("title is required")
	}
	has := func(f string) bool {
		for _, x := range files {
			if x == f {
				return true
			}
		}
		return false
	}
	t.Run, t.Prompt = s.Run, s.Prompt
	if t.Run == "" && t.Prompt == "" {
		for _, f := range []string{"run.py", "run.sh", "run.js"} {
			if has(f) {
				t.Run = f
				break
			}
		}
		if t.Run == "" && has("prompt.md") {
			t.Prompt = "prompt.md"
		}
	}
	switch {
	case t.Run != "" && t.Prompt != "":
		return nil, errors.New("give run or prompt, not both")
	case t.Run == "" && t.Prompt == "":
		return nil, errors.New(`no run file ("run.py", "run.sh", "run.js") and no prompt ("prompt.md")`)
	case t.Run != "" && !has(t.Run):
		return nil, fmt.Errorf("run file %q is not in the template dir", t.Run)
	case t.Prompt != "" && !has(t.Prompt):
		return nil, fmt.Errorf("prompt file %q is not in the template dir", t.Prompt)
	}
	for _, st := range s.Stores {
		if !taskStoreRE.MatchString(st) || st == flyStore {
			return nil, fmt.Errorf("bad store name %q", st)
		}
		t.Stores = append(t.Stores, st)
	}
	t.TimeoutSeconds = 600
	if s.TimeoutSeconds != nil {
		t.TimeoutSeconds = int(math.Round(*s.TimeoutSeconds))
	}
	if t.TimeoutSeconds < 10 || t.TimeoutSeconds > 6*3600 {
		return nil, errors.New("timeoutSeconds must be 10–21600")
	}
	t.Size = s.Size
	if t.Size == "" {
		t.Size = "small"
	}
	if !validSize(t.Size) {
		return nil, errors.New("size must be small, medium or large")
	}
	seen := map[string]bool{}
	for _, raw := range s.Fields {
		var f struct {
			Name        string            `json:"name"`
			Label       string            `json:"label"`
			Type        string            `json:"type"`
			Required    bool              `json:"required"`
			Help        string            `json:"help"`
			Placeholder string            `json:"placeholder"`
			Options     []json.RawMessage `json:"options"`
			OptionsFrom string            `json:"optionsFrom"`
			Default     any               `json:"default"`
			SecretKeys  any               `json:"secretKeys"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("a field: %v", err)
		}
		if !taskFieldRE.MatchString(f.Name) {
			return nil, fmt.Errorf("field name %q must be lowercase letters/digits/_", f.Name)
		}
		if seen[f.Name] {
			return nil, fmt.Errorf("field %s is defined twice", f.Name)
		}
		seen[f.Name] = true
		if f.Type == "" {
			f.Type = "text"
		}
		if !taskTypes[f.Type] {
			return nil, fmt.Errorf("field %s: type must be one of text, textarea, number, select, multiselect, checkbox", f.Name)
		}
		if f.SecretKeys != nil {
			return nil, fmt.Errorf("field %s: secretKeys is Jarvis 1's; in Jarvis 4 a picked store brings all its keys", f.Name)
		}
		out := TaskField{Name: f.Name, Label: f.Label, Type: f.Type, Required: f.Required, Help: f.Help, Placeholder: f.Placeholder, Default: f.Default}
		if out.Label == "" {
			out.Label = f.Name
		}
		if isSelect(f.Type) {
			if f.OptionsFrom != "" {
				if !taskSources[f.OptionsFrom] {
					return nil, fmt.Errorf("field %s: optionsFrom must be stores, content, sizes or models", f.Name)
				}
				out.OptionsFrom = f.OptionsFrom
			} else {
				for _, o := range f.Options {
					opt, err := parseOption(o)
					if err != nil {
						return nil, fmt.Errorf("field %s: %v", f.Name, err)
					}
					out.Options = append(out.Options, opt)
				}
				if len(out.Options) == 0 {
					return nil, fmt.Errorf("field %s: a %s needs options or optionsFrom", f.Name, f.Type)
				}
			}
		}
		t.Fields = append(t.Fields, out)
	}
	return t, nil
}

func validSize(s string) bool {
	for _, x := range taskSizes {
		if x == s {
			return true
		}
	}
	return false
}

// readTemplates: every tasks/*/task.json; a broken one is listed with its error rather than dropped
func readTemplates(root string) []*TaskTemplate {
	ents, err := os.ReadDir(root)
	if err != nil {
		return []*TaskTemplate{}
	}
	out := []*TaskTemplate{}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		name, dir := e.Name(), filepath.Join(root, e.Name())
		spec, err := os.ReadFile(filepath.Join(dir, "task.json"))
		if err != nil {
			continue // not a template
		}
		files := []string{}
		fs, _ := os.ReadDir(dir)
		for _, f := range fs {
			if !f.IsDir() && f.Name() != "task.json" {
				files = append(files, f.Name())
			}
		}
		sort.Strings(files)
		t, err := parseTemplate(name, spec, files)
		if err != nil {
			out = append(out, &TaskTemplate{Name: name, Title: name, Error: err.Error(), Fields: []TaskField{}, Files: files, Stores: []string{}})
			continue
		}
		main := t.Run
		if main == "" {
			main = t.Prompt
		}
		if b, err := os.ReadFile(filepath.Join(dir, main)); err == nil {
			t.Source = string(b[:min(len(b), 100000)])
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// withOptions: the option lists the router knows (sizes, models); "stores" stays empty — the app lists the
// stores from the core itself
func withOptions(t *TaskTemplate) *TaskTemplate {
	c := *t
	c.Fields = append([]TaskField{}, t.Fields...)
	for i, f := range c.Fields {
		switch f.OptionsFrom {
		case "sizes":
			c.Fields[i].Options = []TaskOption{{"small", sizeLabel("small"), ""}, {"medium", sizeLabel("medium"), ""}, {"large", sizeLabel("large"), ""}}
		case "models":
			c.Fields[i].Options = nil
			for _, m := range modelCatalog {
				c.Fields[i].Options = append(c.Fields[i].Options, TaskOption{m.ID, m.Label, m.Harness})
			}
		case "stores", "content":
			c.Fields[i].Options = []TaskOption{} // the app lists them (the core's stores, GET /api/content)
		}
	}
	return &c
}

func templateByName(name string) (*TaskTemplate, error) {
	for _, t := range readTemplates(tasksDir) {
		if t.Name == name {
			if t.Error != "" {
				return nil, fmt.Errorf("template %q is broken: %s", name, t.Error)
			}
			return withOptions(t), nil
		}
	}
	return nil, fmt.Errorf("no template %q in tasks/", name)
}

// checkParams: the values against the fields — unknown keys dropped, defaults filled in, types coerced
// (numbers as numbers, checkboxes as booleans, multiselects as string lists, the rest strings)
func checkParams(t *TaskTemplate, in map[string]any) (map[string]any, error) {
	out := map[string]any{}
	empty := func(v any) bool { return v == nil || v == "" }
	allowed := func(f TaskField, v string) bool {
		if f.OptionsFrom == "stores" {
			return taskStoreRE.MatchString(v) && v != flyStore
		}
		if f.OptionsFrom == "content" {
			return contentNameRE.MatchString(v)
		}
		for _, o := range f.Options {
			if o.Value == v {
				return true
			}
		}
		return false
	}
	values := func(f TaskField) string {
		vs := []string{}
		for _, o := range f.Options {
			vs = append(vs, o.Value)
		}
		return strings.Join(vs, ", ")
	}
	for _, f := range t.Fields {
		v, ok := in[f.Name]
		if !ok || empty(v) {
			v = f.Default
		}
		switch f.Type {
		case "checkbox":
			out[f.Name] = v == true || v == "true"
			continue
		case "multiselect":
			var list []string
			switch x := v.(type) {
			case []any:
				for _, e := range x {
					list = append(list, strings.TrimSpace(fmt.Sprint(e)))
				}
			case []string:
				list = x
			case string:
				list = strings.Split(x, ",")
			}
			seen, clean := map[string]bool{}, []string{}
			for _, e := range list {
				e = strings.TrimSpace(e)
				if e == "" || seen[e] {
					continue
				}
				if !allowed(f, e) {
					if f.OptionsFrom == "stores" || f.OptionsFrom == "content" {
						return nil, bad("“%s”: %q is not a store name", f.Label, e)
					}
					return nil, bad("“%s”: %q is not one of %s", f.Label, e, values(f))
				}
				seen[e] = true
				clean = append(clean, e)
			}
			if f.Required && len(clean) == 0 {
				return nil, bad("“%s” needs at least one choice", f.Label)
			}
			out[f.Name] = clean
			continue
		}
		if empty(v) {
			if f.Required {
				return nil, bad("“%s” is required", f.Label)
			}
			if f.Type == "number" {
				out[f.Name] = nil
			} else {
				out[f.Name] = ""
			}
			continue
		}
		switch f.Type {
		case "number":
			n, ok := number(v)
			if !ok {
				return nil, bad("“%s” must be a number", f.Label)
			}
			out[f.Name] = n
		case "select":
			s := fmt.Sprint(v)
			if !allowed(f, s) {
				if f.OptionsFrom == "stores" || f.OptionsFrom == "content" {
					return nil, bad("“%s”: %q is not a store name", f.Label, s)
				}
				return nil, bad("“%s” must be one of %s", f.Label, values(f))
			}
			out[f.Name] = s
		default:
			out[f.Name] = fmt.Sprint(v)
		}
	}
	return out, nil
}

// lineStores: the template's stores plus the ones picked in its store fields (sorted, unique)
func lineStores(t *TaskTemplate, params map[string]any) []string {
	return pickedIn(t, params, "stores", t.Stores)
}

// lineContent: the content stores picked in its content fields (sorted, unique; nil for none)
func lineContent(t *TaskTemplate, params map[string]any) []string {
	out := pickedIn(t, params, "content", nil)
	if len(out) == 0 {
		return nil
	}
	return out
}

func pickedIn(t *TaskTemplate, params map[string]any, source string, fixed []string) []string {
	set := map[string]bool{}
	for _, s := range fixed {
		set[s] = true
	}
	for _, f := range t.Fields {
		if f.OptionsFrom != source {
			continue
		}
		switch v := params[f.Name].(type) {
		case string:
			if v != "" {
				set[v] = true
			}
		case []string:
			for _, s := range v {
				set[s] = true
			}
		}
	}
	out := []string{}
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// paramEnv: a value as its PARAM_<FIELD> string
func paramEnv(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case []string:
		return strings.Join(x, ",")
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
	}
	return fmt.Sprint(v)
}

// ---- records ---------------------------------------------------------------------------------------------

type TaskInstance struct {
	ID        string         `json:"id"`
	Template  string         `json:"template"`
	Name      string         `json:"name"`
	Params    map[string]any `json:"params"`
	Size      string         `json:"size"`
	Stores    []string       `json:"stores"`                  // the line's stores (template + picked), fixed for the line
	Content   []string       `json:"content,omitempty"`       // the content stores picked, fixed for the line (signed in its config)
	Account   string         `json:"claudeAccount,omitempty"` // a prompt template's Claude account (claudeaccounts.go), fixed
	Session   string         `json:"session"`                 // the line; "" once it is gone
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt *time.Time     `json:"updatedAt,omitempty"`
	Active    string         `json:"active,omitempty"` // the run in progress
	Runs      []*TaskRun     `json:"runs"`             // newest first, taskKeepRuns kept

	PauseWanted  bool       `json:"pauseWanted,omitempty"`  // the machine reported: pause the line
	StartedIdle  *time.Time `json:"startedIdle,omitempty"`  // first seen started with no run
	ReadyAt      *time.Time `json:"readyAt,omitempty"`      // the line's first machine reported ready
	SessionError string     `json:"sessionError,omitempty"` // the line failed or went
}

type TaskRun struct {
	ID         string     `json:"id"`
	Instance   string     `json:"instance"`
	Template   string     `json:"template"`
	Trigger    string     `json:"trigger"` // manual | schedule
	Schedule   string     `json:"schedule,omitempty"`
	Slot       *time.Time `json:"slot,omitempty"`
	Upgrade    bool       `json:"upgrade,omitempty"`
	Phase      string     `json:"phase"` // queued | starting | running | succeeded | failed | timedout | stopped | lost
	CreatedAt  time.Time  `json:"createdAt"`
	ResumedAt  *time.Time `json:"resumedAt,omitempty"`  // the line's resume was asked for
	StartedAt  *time.Time `json:"startedAt,omitempty"`  // the machine is up (its secrets pulled)
	RanAt      *time.Time `json:"ranAt,omitempty"`      // the script started (machine clock)
	FinishedAt *time.Time `json:"finishedAt,omitempty"` // the script ended (machine clock) or the router gave up
	ExitCode   *int       `json:"exitCode,omitempty"`
	Reason     string     `json:"reason,omitempty"`
	Waiting    string     `json:"waiting,omitempty"`
	Tail       string     `json:"tail,omitempty"` // the log's last lines
	LogBytes   int        `json:"logBytes"`
	OutBytes   int        `json:"outputBytes"`
	Machine    string     `json:"machine,omitempty"`
	Image      string     `json:"image,omitempty"`
}

type TaskSchedule struct {
	ID        string    `json:"id"`
	Instance  string    `json:"instance"`
	Time      string    `json:"time"`
	TZ        string    `json:"tz"`
	Enabled   bool      `json:"enabled"`
	Since     int64     `json:"since"` // ms: a change never fires a slot already past
	CreatedAt time.Time `json:"createdAt"`
	LastSlot  int64     `json:"lastSlot,omitempty"` // ms: the slot last fired (or tried)
}

type TaskState struct {
	Instances map[string]*TaskInstance `json:"instances"`
	Schedules map[string]*TaskSchedule `json:"schedules"`
	Doomed    []string                 `json:"doomed,omitempty"` // lines of deleted instances, destroyed by the tick
}

func tasksOf(d *persisted) *TaskState {
	if d.Tasks == nil {
		d.Tasks = &TaskState{}
	}
	if d.Tasks.Instances == nil {
		d.Tasks.Instances = map[string]*TaskInstance{}
	}
	if d.Tasks.Schedules == nil {
		d.Tasks.Schedules = map[string]*TaskSchedule{}
	}
	return d.Tasks
}

func instanceBySession(ts *TaskState, sid string) *TaskInstance {
	for _, i := range ts.Instances {
		if i.Session == sid && sid != "" {
			return i
		}
	}
	return nil
}

func (i TaskInstance) run(id string) *TaskRun {
	for _, r := range i.Runs {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func (i TaskInstance) queued() []*TaskRun {
	var out []*TaskRun
	for k := len(i.Runs) - 1; k >= 0; k-- { // oldest first
		if i.Runs[k].Phase == "queued" {
			out = append(out, i.Runs[k])
		}
	}
	return out
}

func finished(phase string) bool {
	switch phase {
	case "succeeded", "failed", "timedout", "stopped", "lost":
		return true
	}
	return false
}

// prune: keep taskKeepRuns runs (never an unfinished one); their files go with them
func (r *Router) pruneRuns(i *TaskInstance) {
	var keep []*TaskRun
	n := 0
	for _, x := range i.Runs {
		if !finished(x.Phase) || n < taskKeepRuns {
			keep = append(keep, x)
			if finished(x.Phase) {
				n++
			}
			continue
		}
		r.removeRunFiles(x.ID)
	}
	i.Runs = keep
}

// a run's log and output are objects task-runs/<run>.log and .output (objstore.go)
func runKey(id, ext string) string { return "task-runs/" + id + ext }

func (r *Router) removeRunFiles(id string) {
	ctx, cancel := objCtx()
	defer cancel()
	r.objects.Delete(ctx, runKey(id, ".log"))
	r.objects.Delete(ctx, runKey(id, ".output"))
}

// ---- views ---------------------------------------------------------------------------------------------

func runView(x *TaskRun, inst *TaskInstance) map[string]any {
	b, _ := json.Marshal(x)
	v := map[string]any{}
	json.Unmarshal(b, &v)
	v["name"] = x.ID // Jarvis 1 calls a run by its Job name
	if inst != nil {
		v["instanceName"] = inst.Name
	}
	return v
}

// instanceState: what the card shows
func instanceState(i *TaskInstance, s *Session) (state, detail string) {
	switch {
	case s == nil:
		return "gone", i.SessionError
	case s.State == "approval" && s.Cert == nil:
		return "approval", "waiting for the phone"
	case i.Active != "":
		return "running", ""
	case s.State == "paused":
		return "ready", s.Error
	case s.State == "failed":
		return "failed", s.Error
	}
	return "busy", s.State
}

func instanceView(i *TaskInstance, d *persisted) map[string]any {
	s := d.Sessions[i.Session]
	state, detail := instanceState(i, s)
	v := map[string]any{"id": i.ID, "template": i.Template, "name": i.Name, "params": i.Params, "size": i.Size, "claudeAccount": nullIfEmpty(i.Account),
		"stores": i.Stores, "content": orEmptyS(i.Content), "session": nullIfEmpty(i.Session), "createdAt": i.CreatedAt, "updatedAt": i.UpdatedAt,
		"state": state, "detail": detail, "lastRun": nil, "activeRun": nil, "schedules": 0, "image": nil}
	if s != nil {
		v["sessionState"], v["image"] = s.State, nullIfEmpty(s.Image)
	}
	for _, x := range i.Runs {
		if finished(x.Phase) {
			v["lastRun"] = runView(x, i)
			break
		}
	}
	if a := i.run(i.Active); a != nil {
		v["activeRun"] = runView(a, i)
	}
	v["queued"] = len(i.queued())
	n := 0
	for _, sc := range tasksOf(d).Schedules {
		if sc.Instance == i.ID {
			n++
		}
	}
	v["schedules"] = n
	return v
}

func scheduleViewT(s *TaskSchedule, now time.Time) map[string]any {
	v := map[string]any{"id": s.ID, "instance": s.Instance, "time": s.Time, "tz": s.TZ, "enabled": s.Enabled,
		"since": s.Since, "createdAt": s.CreatedAt, "nextAt": nil}
	if s.Enabled {
		if t, err := nextSlot(s, now); err == nil {
			v["nextAt"] = t.UnixMilli()
		}
	}
	return v
}

// ---- schedules ----------------------------------------------------------------------------------------

func slotParts(s *TaskSchedule) (int, int, *time.Location, error) {
	m := hhmmRE.FindStringSubmatch(strings.TrimSpace(s.Time))
	if m == nil {
		return 0, 0, nil, bad("time must be HH:MM (24-hour)")
	}
	hh, _ := strconv.Atoi(m[1])
	mm, _ := strconv.Atoi(m[2])
	if hh > 23 || mm > 59 {
		return 0, 0, nil, bad("time must be HH:MM (24-hour)")
	}
	loc, err := time.LoadLocation(s.TZ)
	if err != nil || s.TZ == "" || s.TZ == "Local" {
		return 0, 0, nil, bad("unknown time zone %q", s.TZ)
	}
	return hh, mm, loc, nil
}

func nextSlot(s *TaskSchedule, now time.Time) (time.Time, error) {
	hh, mm, loc, err := slotParts(s)
	if err != nil {
		return time.Time{}, err
	}
	return nextTimeOfDay(hh, mm, loc, now), nil
}

// lastSlot: the latest daily slot at or before now
func lastSlot(s *TaskSchedule, now time.Time) (time.Time, bool) {
	hh, mm, loc, err := slotParts(s)
	if err != nil {
		return time.Time{}, false
	}
	t := nextTimeOfDay(hh, mm, loc, now.Add(-26*time.Hour))
	if t.After(now) {
		return time.Time{}, false
	}
	for {
		n := nextTimeOfDay(hh, mm, loc, t)
		if n.After(now) {
			return t, true
		}
		t = n
	}
}

// dueSlot: the slot the schedule should fire for at now, or false: the latest slot, after `since`, missed by no
// more than the grace period, and not fired already
func dueSlot(s *TaskSchedule, now time.Time) (time.Time, bool) {
	if !s.Enabled {
		return time.Time{}, false
	}
	t, ok := lastSlot(s, now)
	if !ok || t.UnixMilli() < s.Since || now.Sub(t) > taskScheduleGrace || t.UnixMilli() <= s.LastSlot {
		return time.Time{}, false
	}
	return t, true
}

// ---- lifecycle seams (tests replace them) ----------------------------------------------------------------

var taskOps = struct {
	create  func(r *Router, in NewSession) (string, error)
	resume  func(r *Router, id string, upgrade bool) error
	pause   func(r *Router, id string) error
	destroy func(r *Router, id string) error
	reject  func(r *Router, approval string) error
}{
	create:  (*Router).CreateSession,
	resume:  (*Router).Resume,
	pause:   (*Router).Pause,
	destroy: (*Router).Destroy,
	reject:  (*Router).Reject,
}

// ---- the API -------------------------------------------------------------------------------------------

type taskErr struct {
	status int
	msg    string
}

func (e *taskErr) Error() string { return e.msg }

func notFound(format string, a ...any) error { return &taskErr{404, fmt.Sprintf(format, a...)} }
func conflict(format string, a ...any) error { return &taskErr{409, fmt.Sprintf(format, a...)} }

func taskWriteErr(w http.ResponseWriter, err error) {
	var te *taskErr
	if errors.As(err, &te) {
		writeJSON(w, te.status, map[string]string{"error": te.msg})
		return
	}
	writeErr(w, err)
}

type instanceIn struct {
	Template  string         `json:"template"`
	Name      string         `json:"name"`
	Params    map[string]any `json:"params"`
	Size      string         `json:"size"`
	Hide      []string       `json:"hide"`
	RequestID string         `json:"requestId"`
	Account   string         `json:"account"` // a prompt template's Claude account; "" = the default
}

func readJSON(req *http.Request, v any) error {
	if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(v); err != nil && err != io.EOF {
		return bad("bad JSON: %v", err)
	}
	return nil
}

// CreateTask: a new instance = a new session line on harness task:<template>, approved on the phone
func (r *Router) CreateTask(in instanceIn) (map[string]any, error) {
	name := strings.TrimSpace(in.Name)
	if len([]rune(name)) > 80 {
		name = string([]rune(name)[:80])
	}
	if name == "" {
		return nil, bad("a name is required")
	}
	if len(in.Hide) > 0 {
		return nil, bad("hidden values are Jarvis 1's; in Jarvis 4 secrets go in a store the task picks")
	}
	t, err := templateByName(in.Template)
	if err != nil {
		return nil, bad("%v", err)
	}
	params, err := checkParams(t, in.Params)
	if err != nil {
		return nil, err
	}
	size := in.Size
	if size == "" {
		size = t.Size
	}
	if !validSize(size) {
		return nil, bad("size must be small, medium or large")
	}
	account, err := r.accounts().resolve(in.Account, t.Prompt != "") // claude -p runs on a Claude account
	if err != nil {
		return nil, bad("%v", err)
	}
	inst := &TaskInstance{ID: randID()[:8], Template: t.Name, Name: name, Params: params, Size: size,
		Stores: lineStores(t, params), Content: lineContent(t, params), Account: account, CreatedAt: time.Now().UTC(), Runs: []*TaskRun{}}
	if in.RequestID != "" {
		var dup *TaskInstance
		r.st.Do(func(d *persisted) {
			for _, x := range tasksOf(d).Instances {
				if x.Session != "" && d.Sessions[x.Session] != nil && d.Sessions[x.Session].RequestID == in.RequestID {
					dup = x
				}
			}
		})
		if dup != nil {
			var v map[string]any
			r.st.Do(func(d *persisted) { v = instanceView(dup, d) })
			return v, nil
		}
	}
	if err := r.newTaskLine(inst, in.RequestID); err != nil {
		return nil, err
	}
	var v map[string]any
	r.st.Do(func(d *persisted) {
		tasksOf(d).Instances[inst.ID] = inst
		v = instanceView(inst, d)
	})
	log.Printf("[tasks] instance %s (%s, template %s) made: session %s waits for the phone", inst.ID, inst.Name, inst.Template, inst.Session)
	return v, nil
}

// newTaskLine: the instance's session line (the phone approves it as a new session)
func (r *Router) newTaskLine(inst *TaskInstance, requestID string) error {
	off := false
	tc := &TaskConfig{Instance: inst.ID, Name: inst.Name, Params: map[string]any{}}
	for k, v := range inst.Params {
		tc.Params[k] = v
	}
	sid, err := taskOps.create(r, NewSession{RequestID: requestID, Label: "Task: " + inst.Name, Harness: taskHarnessPrefix + inst.Template,
		Stores: inst.Stores, Content: inst.Content, Account: inst.Account, NeedsAccount: inst.Account != "", Size: inst.Size, AutoPause: &off,
		PermissionMode: "bypass", Task: tc})
	if err != nil {
		return err
	}
	inst.Session, inst.SessionError, inst.ReadyAt = sid, "", nil
	return nil
}

// UpdateTask: name, params, size. The line's stores are fixed: a change of picked stores needs a new task.
func (r *Router) UpdateTask(id string, in instanceIn) (map[string]any, error) {
	if len(in.Hide) > 0 {
		return nil, bad("hidden values are Jarvis 1's; in Jarvis 4 secrets go in a store the task picks")
	}
	var tmpl string
	var cur map[string]any
	r.st.Do(func(d *persisted) {
		if i := tasksOf(d).Instances[id]; i != nil {
			tmpl, cur = i.Template, i.Params
		}
	})
	if tmpl == "" {
		return nil, notFound("no such task instance: %s", id)
	}
	t, err := templateByName(tmpl)
	if err != nil {
		return nil, bad("%v", err)
	}
	given := in.Params
	if given == nil {
		given = cur
	}
	params, err := checkParams(t, given)
	if err != nil {
		return nil, err
	}
	if in.Size != "" && !validSize(in.Size) {
		return nil, bad("size must be small, medium or large")
	}
	stores, content := lineStores(t, params), lineContent(t, params)
	// new stores or content stores: they are approved with the line, so the change files a new line for the phone
	// (as Reapprove does) and keeps the instance, its runs and schedules; the old line goes once the new one exists
	var relined *TaskInstance
	err = nil
	r.st.Do(func(d *persisted) {
		i := tasksOf(d).Instances[id]
		if i == nil {
			err = notFound("no such task instance: %s", id)
			return
		}
		if reflect.DeepEqual(content, i.Content) && reflect.DeepEqual(stores, i.Stores) {
			return
		}
		if i.Active != "" {
			err = conflict("a run is in progress: change the task's stores once it has finished")
			return
		}
		c := *i
		c.Stores, c.Content, c.Params = stores, content, params
		if n := strings.TrimSpace(in.Name); n != "" {
			c.Name = n
		}
		if in.Size != "" {
			c.Size = in.Size
		}
		relined = &c
	})
	if err != nil {
		return nil, err
	}
	old := ""
	if relined != nil {
		old = relined.Session
		if err := r.newTaskLine(relined, ""); err != nil {
			return nil, err
		}
	}
	var v map[string]any
	r.st.Do(func(d *persisted) {
		ts := tasksOf(d)
		i := ts.Instances[id]
		if i == nil {
			err = notFound("no such task instance: %s", id)
			return
		}
		if relined != nil {
			i.Stores, i.Content = relined.Stores, relined.Content
			i.Session, i.SessionError, i.ReadyAt, i.PauseWanted, i.StartedIdle = relined.Session, "", nil, false, nil
			if old != "" && d.Sessions[old] != nil {
				ts.Doomed = append(ts.Doomed, old)
			}
		}
		if n := strings.TrimSpace(in.Name); n != "" {
			i.Name = n
		}
		i.Params = params
		if in.Size != "" {
			i.Size = in.Size
			if s := d.Sessions[i.Session]; s != nil {
				s.Size = in.Size // unsigned: the next start takes it
			}
		}
		now := time.Now().UTC()
		i.UpdatedAt = &now
		v = instanceView(i, d)
	})
	return v, err
}

// DeleteTask: the instance, its schedules and runs go; its line is destroyed (archived like any session) by
// the tick, or its approval dropped
func (r *Router) DeleteTask(id string) error {
	var inst *TaskInstance
	var approval string
	r.st.Do(func(d *persisted) {
		ts := tasksOf(d)
		inst = ts.Instances[id]
		if inst == nil {
			return
		}
		delete(ts.Instances, id)
		for k, s := range ts.Schedules {
			if s.Instance == id {
				delete(ts.Schedules, k)
			}
		}
		if s := d.Sessions[inst.Session]; s != nil {
			if s.State == "approval" && s.Cert == nil {
				for _, a := range d.Approvals {
					if a.Session == s.ID && a.Kind == "new-session" {
						approval = a.ID
					}
				}
			}
			if approval == "" {
				ts.Doomed = append(ts.Doomed, s.ID)
			}
		}
	})
	if inst == nil {
		return notFound("no such task instance: %s", id)
	}
	for _, x := range inst.Runs {
		r.removeRunFiles(x.ID)
	}
	if approval != "" {
		if err := taskOps.reject(r, approval); err != nil {
			log.Printf("[tasks] %s: dropping its approval: %v", id, err)
		}
	}
	taskKick(r)
	return nil
}

// Reapprove: a new line for an instance whose line is gone or failed (the old one, if any, is destroyed)
func (r *Router) Reapprove(id string) (map[string]any, error) { return r.reapprove(id, false) }

// reapprove: Reapprove; destroying: a line being destroyed is replaced too (a run asked for meanwhile)
func (r *Router) reapprove(id string, destroying bool) (map[string]any, error) {
	var inst TaskInstance
	var old string
	var err error
	r.st.Do(func(d *persisted) {
		i := tasksOf(d).Instances[id]
		if i == nil {
			err = notFound("no such task instance: %s", id)
			return
		}
		s := d.Sessions[i.Session]
		switch {
		case i.Active != "":
			err = conflict("a run is in progress")
		case s != nil && s.State != "failed" && !(destroying && s.State == "destroying"):
			err = conflict("the task's session is %s; only a gone or failed one is replaced", s.State)
		default:
			inst = *i
			if s != nil {
				old = s.ID
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if err := r.newTaskLine(&inst, ""); err != nil {
		return nil, err
	}
	var v map[string]any
	r.st.Do(func(d *persisted) {
		ts := tasksOf(d)
		if i := ts.Instances[id]; i != nil {
			i.Session, i.SessionError, i.ReadyAt, i.PauseWanted, i.StartedIdle = inst.Session, "", nil, false, nil
			v = instanceView(i, d)
		}
		if old != "" && !destroying {
			ts.Doomed = append(ts.Doomed, old)
		}
	})
	return v, nil
}

// StartRun: queue a run; the tick starts it when the line is paused (now, for an idle line). A line that waits for
// the phone keeps the run queued until it is approved; a line that is gone or being destroyed gets its new line filed
// for the phone (Reapprove) and the run waits for it.
func (r *Router) StartRun(id, trigger, schedule string, slot *time.Time, upgrade bool) (*TaskRun, error) {
	run := &TaskRun{ID: "r" + randID(), Instance: id, Trigger: trigger, Schedule: schedule, Slot: slot, Upgrade: upgrade,
		Phase: "queued", CreatedAt: time.Now().UTC()}
	var err error
	reline, destroying := false, false
	r.st.Do(func(d *persisted) {
		i := tasksOf(d).Instances[id]
		if i == nil {
			err = notFound("no such task instance: %s", id)
			return
		}
		if len(i.queued()) >= taskMaxQueued {
			err = conflict("%d runs are already queued: wait for them, or stop one", taskMaxQueued)
			return
		}
		s := d.Sessions[i.Session]
		reline = s == nil || s.State == "destroying"
		destroying = s != nil
	})
	if err != nil {
		return nil, err
	}
	if reline {
		if _, err := r.reapprove(id, destroying); err != nil {
			return nil, fmt.Errorf("the task's line is gone and a new one couldn't be filed: %w", err)
		}
		log.Printf("[tasks] %s: its line was gone: a new one waits for the phone; run %s waits for it", id, run.ID)
	}
	r.st.Do(func(d *persisted) {
		i := tasksOf(d).Instances[id]
		if i == nil {
			err = notFound("no such task instance: %s", id)
			return
		}
		run.Template = i.Template
		i.Runs = append([]*TaskRun{run}, i.Runs...)
	})
	if err != nil {
		return nil, err
	}
	log.Printf("[tasks] %s: run %s queued (%s)", id, run.ID, trigger)
	taskKick(r)
	return run, nil
}

// StopRun: a queued run is dropped; a starting or running one is stopped and its line paused
func (r *Router) StopRun(runID string) error {
	var err error
	found := false
	r.st.Do(func(d *persisted) {
		for _, i := range tasksOf(d).Instances {
			x := i.run(runID)
			if x == nil {
				continue
			}
			found = true
			if finished(x.Phase) { // already over: what was asked for holds
				return
			}
			now := time.Now().UTC()
			x.Phase, x.FinishedAt, x.Reason = "stopped", &now, "stopped by Deyao"
			if i.Active == runID {
				i.Active = ""
				i.PauseWanted = true // the tick pauses the line once it is up
			}
			return
		}
	})
	if !found {
		return notFound("no such run: %s", runID)
	}
	if err == nil {
		taskKick(r)
	}
	return err
}

func (r *Router) runDetail(runID string) (map[string]any, error) {
	var v map[string]any
	r.st.Do(func(d *persisted) {
		for _, i := range tasksOf(d).Instances {
			if x := i.run(runID); x != nil {
				v = map[string]any{"run": runView(x, i)}
			}
		}
	})
	if v == nil {
		return nil, notFound("no such run: %s", runID)
	}
	logb, _ := r.objGetBytes(runKey(runID, ".log"))
	out, _ := r.objGetBytes(runKey(runID, ".output"))
	v["log"], v["output"] = string(logb), string(out)
	return v, nil
}

func (r *Router) saveSchedule(id string, b map[string]any) (map[string]any, error) {
	var v map[string]any
	var err error
	now := time.Now()
	r.st.Do(func(d *persisted) {
		ts := tasksOf(d)
		var cur *TaskSchedule
		if id != "" {
			if cur = ts.Schedules[id]; cur == nil {
				err = notFound("no such schedule: %s", id)
				return
			}
		}
		s := &TaskSchedule{ID: randID()[:8], TZ: "Europe/London", Enabled: true, CreatedAt: now.UTC()}
		if cur != nil {
			c := *cur
			s = &c
		} else {
			s.Instance, _ = b["instance"].(string)
		}
		if ts.Instances[s.Instance] == nil {
			err = notFound("no such task instance: %s", s.Instance)
			return
		}
		if t, ok := b["time"]; ok && t != nil {
			s.Time = fmt.Sprint(t)
		}
		if tz, ok := b["tz"].(string); ok && tz != "" {
			s.TZ = tz
		}
		if e, ok := b["enabled"].(bool); ok {
			s.Enabled = e
		}
		hh, mm, _, perr := slotParts(s)
		if perr != nil {
			err = perr
			return
		}
		s.Time = fmt.Sprintf("%02d:%02d", hh, mm)
		s.Since = now.UnixMilli() // a change never fires a slot that has already passed
		ts.Schedules[s.ID] = s
		v = scheduleViewT(s, now)
	})
	return v, err
}

func (r *Router) registerTasks(app appRoute, m machineRoute) {
	app("GET /api/tasks", func(w http.ResponseWriter, req *http.Request) {
		templates := []*TaskTemplate{}
		for _, t := range readTemplates(tasksDir) {
			templates = append(templates, withOptions(t))
		}
		now := time.Now()
		instances, schedules := []map[string]any{}, []map[string]any{}
		r.st.Do(func(d *persisted) {
			ts := tasksOf(d)
			for _, i := range ts.Instances {
				instances = append(instances, instanceView(i, d))
			}
			for _, s := range ts.Schedules {
				schedules = append(schedules, scheduleViewT(s, now))
			}
		})
		sort.Slice(instances, func(a, b int) bool {
			return instances[a]["createdAt"].(time.Time).Before(instances[b]["createdAt"].(time.Time))
		})
		sort.Slice(schedules, func(a, b int) bool {
			return schedules[a]["createdAt"].(time.Time).Before(schedules[b]["createdAt"].(time.Time))
		})
		writeJSON(w, 200, map[string]any{"sessionImage": r.cfg.SessionImage, "templates": templates, "instances": instances, "schedules": schedules})
	})
	app("POST /api/tasks/instances", func(w http.ResponseWriter, req *http.Request) {
		var in instanceIn
		if err := readJSON(req, &in); err != nil {
			taskWriteErr(w, err)
			return
		}
		v, err := r.CreateTask(in)
		if err != nil {
			taskWriteErr(w, err)
			return
		}
		writeJSON(w, 200, v)
	})
	app("PUT /api/tasks/instances/{id}", func(w http.ResponseWriter, req *http.Request) {
		var in instanceIn
		if err := readJSON(req, &in); err != nil {
			taskWriteErr(w, err)
			return
		}
		v, err := r.UpdateTask(req.PathValue("id"), in)
		if err != nil {
			taskWriteErr(w, err)
			return
		}
		writeJSON(w, 200, v)
	})
	app("DELETE /api/tasks/instances/{id}", func(w http.ResponseWriter, req *http.Request) {
		if err := r.DeleteTask(req.PathValue("id")); err != nil {
			taskWriteErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	app("POST /api/tasks/instances/{id}/approve", func(w http.ResponseWriter, req *http.Request) {
		v, err := r.Reapprove(req.PathValue("id"))
		if err != nil {
			taskWriteErr(w, err)
			return
		}
		writeJSON(w, 200, v)
	})
	app("POST /api/tasks/instances/{id}/run", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Upgrade bool `json:"upgrade"`
		}
		if err := readJSON(req, &in); err != nil {
			taskWriteErr(w, err)
			return
		}
		run, err := r.StartRun(req.PathValue("id"), "manual", "", nil, in.Upgrade)
		if err != nil {
			taskWriteErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"name": run.ID, "run": runView(run, nil)})
	})
	app("GET /api/tasks/instances/{id}/runs", func(w http.ResponseWriter, req *http.Request) {
		var runs []map[string]any
		found := false
		r.st.Do(func(d *persisted) {
			if i := tasksOf(d).Instances[req.PathValue("id")]; i != nil {
				found = true
				runs = []map[string]any{}
				for _, x := range i.Runs {
					runs = append(runs, runView(x, i))
				}
			}
		})
		if !found {
			taskWriteErr(w, notFound("no such task instance: %s", req.PathValue("id")))
			return
		}
		writeJSON(w, 200, map[string]any{"runs": runs})
	})
	app("GET /api/tasks/runs/{id}", func(w http.ResponseWriter, req *http.Request) {
		v, err := r.runDetail(req.PathValue("id"))
		if err != nil {
			taskWriteErr(w, err)
			return
		}
		writeJSON(w, 200, v)
	})
	app("POST /api/tasks/runs/{id}/stop", func(w http.ResponseWriter, req *http.Request) {
		if err := r.StopRun(req.PathValue("id")); err != nil {
			taskWriteErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	app("POST /api/tasks/schedules", func(w http.ResponseWriter, req *http.Request) {
		b := map[string]any{}
		if err := readJSON(req, &b); err != nil {
			taskWriteErr(w, err)
			return
		}
		if _, ok := b["time"]; !ok {
			taskWriteErr(w, bad("time must be HH:MM (24-hour)"))
			return
		}
		v, err := r.saveSchedule("", b)
		if err != nil {
			taskWriteErr(w, err)
			return
		}
		writeJSON(w, 200, v)
	})
	app("PUT /api/tasks/schedules/{id}", func(w http.ResponseWriter, req *http.Request) {
		b := map[string]any{}
		if err := readJSON(req, &b); err != nil {
			taskWriteErr(w, err)
			return
		}
		v, err := r.saveSchedule(req.PathValue("id"), b)
		if err != nil {
			taskWriteErr(w, err)
			return
		}
		writeJSON(w, 200, v)
	})
	app("DELETE /api/tasks/schedules/{id}", func(w http.ResponseWriter, req *http.Request) {
		found := false
		r.st.Do(func(d *persisted) {
			ts := tasksOf(d)
			if ts.Schedules[req.PathValue("id")] != nil {
				found = true
				delete(ts.Schedules, req.PathValue("id"))
			}
		})
		if !found {
			taskWriteErr(w, notFound("no such schedule: %s", req.PathValue("id")))
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	m("POST /m/task-result", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		var in TaskResult
		if err := json.Unmarshal(body, &in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad JSON"})
			return
		}
		if err := r.taskResult(machine, in); err != nil {
			taskWriteErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
}

// ---- the machine's env and its result -----------------------------------------------------------------

// taskEnv: a task line's machine gets the run it is for and the instance's (non-secret) parameters
func taskEnv(r *Router, s *Session, e map[string]string) {
	if !isTaskHarness(s.Harness) {
		return
	}
	r.st.Do(func(d *persisted) {
		i := instanceBySession(tasksOf(d), s.ID)
		if i == nil {
			return
		}
		e["TASK_INSTANCE"], e["TASK_NAME"] = i.ID, i.Name
		pj, _ := json.Marshal(i.Params)
		e["TASK_PARAMS"] = string(pj)
		for k, v := range i.Params {
			e["PARAM_"+strings.ToUpper(k)] = paramEnv(v)
		}
		if a := i.run(i.Active); a != nil && a.Phase == "starting" {
			e["JARVIS2_TASK_RUN"], e["TASK_RUN"], e["TASK_TRIGGER"] = a.ID, a.ID, a.Trigger
		}
	})
}

// TaskResult: what the machine reports once its run ended (machine/task.go); Run "" = a boot with no run
// (the line's first machine, or a run stopped before it started)
type TaskResult struct {
	Run        string    `json:"run"`
	ExitCode   int       `json:"exitCode"`
	TimedOut   bool      `json:"timedOut"`
	Error      string    `json:"error"` // the runner itself failed (no template, …)
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	Log        string    `json:"log"`    // tail, the store's values redacted by the machine
	Output     string    `json:"output"` // $TASK_OUTPUT, redacted
}

func (r *Router) taskResult(machine string, in TaskResult) error {
	if len(in.Log) > taskLogMax {
		in.Log = in.Log[len(in.Log)-taskLogMax:]
	}
	if len(in.Output) > taskOutputMax {
		in.Output = in.Output[:taskOutputMax]
	}
	var sid string
	var done *TaskRun
	var inst TaskInstance
	var err error
	r.st.Do(func(d *persisted) {
		sid = d.Machines[machine]
		s := d.Sessions[sid]
		if s == nil || s.MachineID != machine || !isTaskHarness(s.Harness) {
			err = &taskErr{403, "this machine isn't a running task line"}
			return
		}
		i := instanceBySession(tasksOf(d), sid)
		if i == nil {
			err = notFound("no task instance for this session")
			return
		}
		i.PauseWanted = true
		now := time.Now().UTC()
		if i.ReadyAt == nil {
			i.ReadyAt = &now
		}
		x := i.run(in.Run)
		if in.Run == "" || x == nil || i.Active != in.Run {
			return // a boot with no run, or a run stopped meanwhile: just pause
		}
		code := in.ExitCode
		x.ExitCode, x.Machine, x.Image = &code, machine, s.Image
		if !in.StartedAt.IsZero() {
			t := in.StartedAt.UTC()
			x.RanAt = &t
		}
		fin := now
		if !in.FinishedAt.IsZero() {
			fin = in.FinishedAt.UTC()
		}
		x.FinishedAt = &fin
		switch {
		case in.Error != "":
			x.Phase, x.Reason = "failed", in.Error
		case in.TimedOut:
			x.Phase, x.Reason = "timedout", "the run went past the template's timeout"
		case code != 0:
			x.Phase, x.Reason = "failed", fmt.Sprintf("exit code %d", code)
		default:
			x.Phase = "succeeded"
		}
		x.Tail, x.LogBytes, x.OutBytes = logTail(in.Log), len(in.Log), len(in.Output)
		i.Active = ""
		c := *x
		done, inst = &c, *i
		r.pruneRuns(i)
	})
	if err != nil {
		return err
	}
	if done != nil {
		if err := r.objPutBytes(runKey(done.ID, ".log"), []byte(in.Log)); err != nil {
			log.Printf("[tasks] run %s: its log: %v", done.ID, err)
		}
		if in.Output != "" {
			if err := r.objPutBytes(runKey(done.ID, ".output"), []byte(in.Output)); err != nil {
				log.Printf("[tasks] run %s: its output: %v", done.ID, err)
			}
		}
		log.Printf("[tasks] %s: run %s %s", inst.ID, done.ID, done.Phase)
		r.notifyRun(&inst, done)
	}
	go func() {
		if err := taskOps.pause(r, sid); err != nil {
			log.Printf("[tasks] %s: pause after the run: %v (the tick retries)", sid, err)
		}
	}()
	return nil
}

// logTail: the last 15 lines, at most 1200 characters (Jarvis 1's failure DM)
func logTail(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	t := strings.Join(lines, "\n")
	if len(t) > 1200 {
		t = t[len(t)-1200:]
	}
	return t
}

// notifyRun: Jarvis 1's DM for a scheduled run that failed
func (r *Router) notifyRun(i *TaskInstance, x *TaskRun) {
	if x.Trigger != "schedule" || x.Phase == "succeeded" || x.Phase == "stopped" {
		return
	}
	what := map[string]string{"failed": "failed", "timedout": "timed out", "lost": "was lost"}[x.Phase]
	if what == "" {
		what = x.Phase
	}
	sched := ""
	r.st.Do(func(d *persisted) {
		if s := tasksOf(d).Schedules[x.Schedule]; s != nil {
			sched = fmt.Sprintf(" (daily %s %s)", s.Time, s.TZ)
		}
	})
	msg := fmt.Sprintf("Scheduled task “%s”%s %s", i.Name, sched, what)
	if x.Reason != "" {
		msg += " — " + x.Reason
	}
	msg += "."
	if x.Tail != "" {
		msg += "\n```\n" + strings.ReplaceAll(x.Tail, "```", "'''") + "\n```"
	}
	r.DM(msg)
}

// ---- the tick ----------------------------------------------------------------------------------------------

var taskTicking sync.Mutex

// taskKick: an API change runs a tick at once rather than within taskTickEvery (tests turn it off)
var taskKick func(r *Router)

func (r *Router) tasksLoop() {
	for {
		time.Sleep(taskTickEvery)
		awaitLead() // leaderlease.go
		r.tasksTick(time.Now())
	}
}

type taskAct struct {
	kind     string // fire | resume | pause | destroy | dm
	instance string
	session  string
	run      string
	upgrade  bool
	schedule string
	slot     time.Time
	text     string
}

// tasksTick: schedules fire, runs advance with their line's state, queued runs start, finished lines pause,
// deleted instances' lines go. Decisions under the state lock, actions outside it.
func (r *Router) tasksTick(now time.Time) {
	if !taskTicking.TryLock() {
		return
	}
	defer taskTicking.Unlock()
	var acts []taskAct
	var ended []struct {
		inst TaskInstance
		run  TaskRun
	}
	r.st.Do(func(d *persisted) {
		ts := tasksOf(d)
		finish := func(i *TaskInstance, x *TaskRun, phase, reason string) {
			t := now.UTC()
			x.Phase, x.Reason, x.FinishedAt, x.Waiting = phase, reason, &t, ""
			if i.Active == x.ID {
				i.Active = ""
			}
			ended = append(ended, struct {
				inst TaskInstance
				run  TaskRun
			}{*i, *x})
		}
		for _, s := range ts.Schedules {
			if slot, ok := dueSlot(s, now); ok {
				s.LastSlot = slot.UnixMilli()
				acts = append(acts, taskAct{kind: "fire", instance: s.Instance, schedule: s.ID, slot: slot})
			}
		}
		var doomed []string
		for _, sid := range ts.Doomed {
			s := d.Sessions[sid]
			if s == nil {
				continue
			}
			doomed = append(doomed, sid)
			if s.State != "destroying" && !r.busy(sid) {
				acts = append(acts, taskAct{kind: "destroy", session: sid})
			}
		}
		ts.Doomed = doomed
		for _, i := range ts.Instances {
			s := d.Sessions[i.Session]
			if s == nil {
				if i.Session != "" {
					i.SessionError = "the task's session is gone"
					i.Session = ""
				}
				for _, x := range i.Runs {
					if !finished(x.Phase) {
						finish(i, x, "failed", "the task's session is gone")
					}
				}
				continue
			}
			busy := r.busy(s.ID)
			if a := i.run(i.Active); a != nil {
				switch a.Phase {
				case "starting":
					switch s.State {
					case "started":
						t := now.UTC()
						a.Phase, a.StartedAt, a.Waiting = "running", &t, ""
					case "paused", "failed":
						if !busy {
							reason := s.Error
							if reason == "" {
								reason = "the start was rejected"
							}
							finish(i, a, "failed", "the session didn't start: "+reason)
						}
					case "approval":
						a.Waiting = "waiting for the phone to approve the newer session image"
					default:
						a.Waiting = s.State
						if s.State == "initialising" {
							a.Waiting = "the machine waits for its secrets (a locked store needs unlocking on the phone)"
						}
						if a.ResumedAt != nil && now.Sub(*a.ResumedAt) > taskStartMax {
							finish(i, a, "failed", fmt.Sprintf("the machine wasn't up after %s (%s)", taskStartMax, a.Waiting))
							i.PauseWanted = true
						}
					}
				case "running":
					timeout := 600
					if t, err := templateByName(i.Template); err == nil {
						timeout = t.TimeoutSeconds
					}
					switch {
					case s.State == "paused" || s.State == "failed":
						if !busy {
							finish(i, a, "lost", "the session stopped before the run reported (a pause, the budget cap or a crash)")
						}
					case a.StartedAt != nil && now.Sub(*a.StartedAt) > time.Duration(timeout)*time.Second+taskResultGrace:
						finish(i, a, "timedout", "no result from the machine")
						i.PauseWanted = true
					}
				default:
					i.Active = "" // a finished run left as active
				}
			}
			if i.Active != "" {
				continue
			}
			switch {
			case (s.State == "started" || s.State == "initialising") && s.MachineID != "":
				if i.StartedIdle == nil {
					t := now.UTC()
					i.StartedIdle = &t
				}
				if !busy && (i.PauseWanted || now.Sub(*i.StartedIdle) > taskIdleStarted) {
					acts = append(acts, taskAct{kind: "pause", instance: i.ID, session: s.ID})
				}
				continue
			case s.State == "paused":
				i.PauseWanted, i.StartedIdle = false, nil
			case s.State == "failed" && s.MachineID == "" && s.Cert != nil:
				i.PauseWanted, i.StartedIdle = false, nil
			default:
				continue
			}
			q := i.queued()
			if len(q) == 0 || busy {
				continue
			}
			x := q[0]
			if s.State == "failed" {
				s.State = "paused" // a failed start left no machine: the line is still there to resume
			}
			t := now.UTC()
			x.Phase, x.Waiting, x.ResumedAt = "starting", "", &t
			i.Active = x.ID
			acts = append(acts, taskAct{kind: "resume", instance: i.ID, session: s.ID, run: x.ID, upgrade: x.Upgrade})
		}
	})
	for _, e := range ended {
		log.Printf("[tasks] %s: run %s %s: %s", e.inst.ID, e.run.ID, e.run.Phase, e.run.Reason)
		r.notifyRun(&e.inst, &e.run)
	}
	for _, a := range acts {
		r.taskAct(a, now)
	}
	r.st.Do(func(d *persisted) {
		for _, i := range tasksOf(d).Instances {
			r.pruneRuns(i)
		}
	})
}

func (r *Router) taskAct(a taskAct, now time.Time) {
	switch a.kind {
	case "fire":
		slot := a.slot.UTC()
		if _, err := r.StartRun(a.instance, "schedule", a.schedule, &slot, false); err != nil {
			name := a.instance
			r.st.Do(func(d *persisted) {
				if i := tasksOf(d).Instances[a.instance]; i != nil {
					name = i.Name
				}
			})
			log.Printf("[tasks] schedule %s could not start: %v", a.schedule, err)
			r.DM(fmt.Sprintf("Scheduled task “%s” could not start: %v", name, err))
		}
	case "resume":
		err := taskOps.resume(r, a.session, a.upgrade)
		if err == nil {
			log.Printf("[tasks] %s: run %s starting (session %s)", a.instance, a.run, a.session)
			return
		}
		var ended *TaskRun
		var inst TaskInstance
		r.st.Do(func(d *persisted) {
			i := tasksOf(d).Instances[a.instance]
			if i == nil {
				return
			}
			x := i.run(a.run)
			if x == nil || i.Active != a.run {
				return
			}
			i.Active = ""
			if errors.Is(err, errBusy) {
				x.Phase = "queued" // another action holds the line: the next tick tries again
				return
			}
			t := time.Now().UTC()
			x.Phase, x.Reason, x.FinishedAt = "failed", "resume: "+err.Error(), &t
			c := *x
			ended, inst = &c, *i
		})
		if ended != nil {
			r.notifyRun(&inst, ended)
		}
	case "pause":
		if err := taskOps.pause(r, a.session); err != nil && !errors.Is(err, errBusy) {
			log.Printf("[tasks] %s: pause: %v", a.session, err)
		}
	case "destroy":
		if err := taskOps.destroy(r, a.session); err != nil && !errors.Is(err, errBusy) {
			log.Printf("[tasks] destroying %s: %v", a.session, err)
		}
	}
}
