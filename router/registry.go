package main

// A session's live status, reported by its own machine (Jarvis 1 read it by Fly exec: readRegistry in
// server.js, lib/stall.js normalize, lib/claudelogin.js parse, lib/downgrade.js parse). The machine runs the
// registry command (machine/status.go) every ~10 s and POSTs the raw text to /m/status when it changes and at
// least once a minute; the router parses it here. Nothing in it is a secret: claude's registry files, ai-title
// lines, background-job counts, the one-shot marker, the ids of transcripts ending on "Please run /login", the
// credentials file's expiry time, the transcripts' refusal entries and the subagent/background-job counts.

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Refusal: a safeguard refusal or a refusal fallback found in a transcript (lib/downgrade.js)
type Refusal struct {
	Kind     string `json:"kind"` // fallback | refusal
	At       int64  `json:"at"`   // ms
	UUID     string `json:"uuid"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Model    string `json:"model,omitempty"`
	Category string `json:"category,omitempty"`
}

// Registry: Jarvis 1's readRegistry view, field names as in its /api/state
type Registry struct {
	LiveName        string    `json:"liveName"`
	NameSource      string    `json:"nameSource"`
	AiTitle         string    `json:"aiTitle"`
	Status          string    `json:"status"` // busy | idle | waiting | … ("shell" folds into idle + bgTasks)
	BgTasks         int       `json:"bgTasks"`
	StatusUpdatedAt int64     `json:"statusUpdatedAt"` // ms; changes on every turn
	BridgeSessionID string    `json:"bridgeSessionId"`
	HostPid         int64     `json:"hostPid,omitempty"` // the host's pid: a new one = the harness restarted it (accountswap.go)
	SessionID       string    `json:"sessionId"`         // claude's conversation id
	AuthFailed      string    `json:"authFailed"`        // uuid of a "Please run /login" reply ending the host's transcript
	CredsExpiresAt  int64     `json:"credsExpiresAt"`
	SessionsInside  int       `json:"sessionsInside"`
	OneShotDone     bool      `json:"oneShotDone"`
	Refusals        []Refusal `json:"refusals"`
	Workers         *Workers  `json:"workers"` // nil: the machine doesn't count them (an image from before)
	// accountswap.go: the account Anthropic named for the token installed by an account switch
	// (machine/claudelogin.go afterSwitch); AccountSection: the image reports it at all
	AccountProof   string `json:"accountProof,omitempty"`
	AccountSection bool   `json:"accountSection,omitempty"`
	// the keeper's record of the harness (machine/keeper.go): how often it was started on this machine and how it
	// last ended; nil: an image from before the keeper
	Harness *HarnessRun `json:"harness,omitempty"`
	// when Deyao last sent the host conversation a prompt (ms; 0 = none in the transcript's tail); HumanSection: the
	// image reports it at all (machine/status.go __HUMAN__, images from 2026-11-02 on)
	LastHumanAt  int64 `json:"lastHumanAt,omitempty"`
	HumanSection bool  `json:"humanSection,omitempty"`
}

// parseHuman: the __HUMAN__ section → conversation id → its last human prompt (ms)
func parseHuman(section string) map[string]int64 {
	out := map[string]int64{}
	for _, l := range strings.Split(section, "\n") {
		f := strings.Fields(l)
		if len(f) != 2 || !transcriptID.MatchString(f[0]) {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, f[1]); err == nil {
			out[f[0]] = t.UnixMilli()
		}
	}
	return out
}

// HarnessRun: the __HARNESS__ section (machine/keeper.go harnessState). Starts > 1: the harness's launcher died and
// the keeper started it again, the machine staying up.
type HarnessRun struct {
	Starts     int    `json:"starts"`
	Running    bool   `json:"running"`
	LastExit   string `json:"lastExit,omitempty"`
	LastExitAt string `json:"lastExitAt,omitempty"`
	LastUpSecs int64  `json:"lastUpSecs,omitempty"`
}

// parseHarness: the __HARNESS__ section's line
func parseHarness(section string) *HarnessRun {
	for _, e := range jsonLines(section) {
		h := &HarnessRun{Starts: int(min(max(num(e, "starts"), 0), 1<<20)), LastExit: clip(str(e, "lastExit"), 80),
			LastExitAt: clip(str(e, "lastExitAt"), 40), LastUpSecs: max(num(e, "lastUpSecs"), 0)}
		h.Running, _ = e["running"].(bool)
		return h
	}
	return nil
}

// Workers: what the host conversation's harness has running besides itself (machine/workers.go, from Claude
// Code's hooks): subagents (foreground and background) and every other background job by Claude Code's own type
// label (shell, monitor, workflow, teammate, …)
type Workers struct {
	Subagents int            `json:"subagents"`
	Jobs      map[string]int `json:"jobs"`
	At        int64          `json:"at"` // ms, its last change
}

var workerType = regexp.MustCompile(`^[a-z][a-z _-]{0,30}$`)

// parseWorkers: the __WORKERS__ section's line for conversation sid
func parseWorkers(section, sid string) *Workers {
	for _, e := range jsonLines(section) {
		if sid == "" || str(e, "workersOf") != sid {
			continue
		}
		w := &Workers{Subagents: int(min(max(num(e, "subagents"), 0), 1000)), Jobs: map[string]int{}, At: num(e, "at")}
		if jobs, ok := e["jobs"].(map[string]any); ok {
			for k, v := range jobs {
				if n, ok := v.(float64); ok && n > 0 && workerType.MatchString(k) && len(w.Jobs) < 20 {
					w.Jobs[k] = int(min(n, 1000))
				}
			}
		}
		return w
	}
	return nil
}

// normalize: claude's "shell" (the turn ended while background shells run) is idle + bgTasks ≥ 1
func normalize(status string, bg int) (string, int) {
	if bg < 0 {
		bg = 0
	}
	if status == "shell" {
		return "idle", max(bg, 1)
	}
	return status, bg
}

func jsonLines(s string) []map[string]any {
	var out []map[string]any
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "{") {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func num(m map[string]any, k string) int64 {
	f, _ := m[k].(float64)
	return int64(f)
}

// cut: the text before sep and after it ("" after when sep is missing), like JS split(sep) with [a, rest=""]
func cut(s, sep string) (string, string) {
	a, b, _ := strings.Cut(s, sep)
	return a, b
}

var transcriptID = regexp.MustCompile(`(?i)^[0-9a-f-]{8,}$`)

// parseLogin: the text after __AUTH__ → transcript id → uuid, and the credentials file's expiry (ms)
func parseLogin(text string) (map[string]string, int64) {
	authPart, credsPart := cut(text, "__CREDS__")
	failed := map[string]string{}
	for _, l := range strings.Split(authPart, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && transcriptID.MatchString(f[0]) {
			failed[f[0]] = f[1]
		}
	}
	exp, _ := strconv.ParseInt(strings.TrimSpace(credsPart), 10, 64)
	return failed, exp
}

var safeguardModel = regexp.MustCompile(`(?:^|:\s*)([^:\n]{1,60}?)'s safeguards flagged`)

func modelFromText(text string) string {
	if m := safeguardModel.FindStringSubmatch(text); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// parseRefusals: lib/downgrade.js parse
func parseRefusals(section string) []Refusal {
	var out []Refusal
	for _, e := range jsonLines(section) {
		at := int64(0)
		if t, err := time.Parse(time.RFC3339Nano, str(e, "timestamp")); err == nil {
			at = t.UnixMilli()
		}
		first := func(ks ...string) string {
			for _, k := range ks {
				if v := str(e, k); v != "" {
					return v
				}
			}
			return ""
		}
		msg, _ := e["message"].(map[string]any)
		switch {
		case str(e, "type") == "system" && str(e, "subtype") == "model_refusal_fallback":
			out = append(out, Refusal{Kind: "fallback", At: at, UUID: str(e, "uuid"), From: first("originalModel", "original_model"),
				To: first("fallbackModel", "fallback_model"), Category: first("apiRefusalCategory", "api_refusal_category")})
		case str(e, "type") == "assistant" && msg != nil && str(msg, "stop_reason") == "refusal":
			var texts []string
			if cs, ok := msg["content"].([]any); ok {
				for _, c := range cs {
					if cm, ok := c.(map[string]any); ok {
						texts = append(texts, str(cm, "text"))
					}
				}
			}
			model := str(msg, "model")
			if model == "" || model == "<synthetic>" {
				model = modelFromText(strings.Join(texts, " "))
			}
			cat := ""
			if sd, ok := msg["stop_details"].(map[string]any); ok {
				cat = str(sd, "category")
			}
			out = append(out, Refusal{Kind: "refusal", At: at, UUID: str(e, "uuid"), Model: model, Category: cat})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At < out[j].At })
	return out
}

// parseRegistry: the raw registry output → the view, or nil when there is no live claude inside (and no
// finished one-shot)
func parseRegistry(raw string) *Registry {
	regPart, rest := cut(raw, "__TITLES__")
	titlePart, rest2 := cut(rest, "__BG__")
	bgPart, rest3 := cut(rest2, "__ONESHOT__")
	oneShotPart, rest4 := cut(rest3, "__AUTH__")
	authPart, rest5 := cut(rest4, "__REFUSAL__")
	refusalPart, workersPart := cut(rest5, "__WORKERS__")
	workersPart, harnessPart := cut(workersPart, "__HARNESS__")                     // images from 2026-10-21 on (the keeper)
	refusalPart, accountPart, hasAccount := strings.Cut(refusalPart, "__ACCOUNT__") // images from 2026-10-20 on
	accountPart, humanPart, hasHuman := strings.Cut(accountPart, "__HUMAN__")       // images from 2026-11-02 on
	proof := ""
	for _, e := range jsonLines(accountPart) {
		proof = str(e, "accountUuid")
	}
	failed, credsExp := parseLogin(authPart)
	refusals := parseRefusals(refusalPart)
	oneShotDone := regexp.MustCompile(`(?m)^done\b`).MatchString(strings.TrimSpace(oneShotPart))

	entries := jsonLines(regPart)
	sort.SliceStable(entries, func(i, j int) bool { return num(entries[i], "startedAt") < num(entries[j], "startedAt") })
	titles, lastTitle := map[string]string{}, ""
	for _, t := range jsonLines(titlePart) {
		if str(t, "type") == "ai-title" && str(t, "aiTitle") != "" {
			titles[str(t, "sessionId")] = str(t, "aiTitle")
			lastTitle = str(t, "aiTitle")
		}
	}
	bg := map[string]int{}
	for _, l := range strings.Split(bgPart, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 {
			n, _ := strconv.Atoi(f[1])
			bg[f[0]] = n
		}
	}
	var host map[string]any
	for _, e := range entries {
		if str(e, "bridgeSessionId") != "" {
			host = e
			break
		}
	}
	if host == nil && len(entries) > 0 {
		host = entries[0]
	}
	if host == nil {
		if oneShotDone {
			return &Registry{OneShotDone: true, AiTitle: lastTitle, Refusals: refusals}
		}
		return nil
	}
	sid := str(host, "sessionId")
	status, n := normalize(str(host, "status"), bg[strconv.FormatInt(num(host, "pid"), 10)])
	return &Registry{
		LiveName: str(host, "name"), NameSource: str(host, "nameSource"), AiTitle: titles[sid],
		Status: status, BgTasks: n, StatusUpdatedAt: num(host, "statusUpdatedAt"),
		BridgeSessionID: str(host, "bridgeSessionId"), HostPid: num(host, "pid"), SessionID: sid,
		AuthFailed: failed[sid], CredsExpiresAt: credsExp, SessionsInside: len(entries),
		OneShotDone: oneShotDone, Refusals: refusals, Workers: parseWorkers(workersPart, sid),
		AccountSection: hasAccount, AccountProof: proof, Harness: parseHarness(harnessPart),
		LastHumanAt: parseHuman(humanPart)[sid], HumanSection: hasHuman,
	}
}
