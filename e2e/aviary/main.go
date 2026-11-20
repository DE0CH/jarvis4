// e2e/aviary: the aviary harness end to end on real Fly machines (rust/e2e-kernel E2E_HARNESS=aviary runs it, with the chat stack
// and the kernel's line beside it). It plays the iPhone with software keys as e2e/kernel does, serves the stand-in
// model and the machines' front to hermit-jarvis's gateway listener, and checks every step through the router's
// records and magpie's admin API:
//
//   - the kernel set up from the TEST master key, with the store `aviary-gw` (the gateway's Access pair as dummies, and
//     AVIARY_GW_URL / AVIARY_MODEL_URL naming this run's chat peer);
//
//   - a Claude account with a fake login (the machine's gateway sends its token to the stand-in model only);
//
//   - a session with the harness aviary and a first prompt with a screenshot attached; the phone signs its source;
//
//   - the machine boots, its gateway boots a sandbox through hermit-jarvis (signed with the machine key, checked with
//     the router), the supervisor starts Claude Code on magpie's ~/.claude, the first prompt arrives through magpie;
//     its screenshot is the message's image (uploaded for the owner through the gateway), never a path in its text;
//
//   - Claude Code's model calls reach the stand-in model through the machine's gateway: a Bash tool call that writes
//     ~/artifacts/e2e-aviary.txt and arms a wakeup with the session's schedule-wakeup, then an answer naming the
//     tool's output (so the command ran in the sandbox); the tool also leaves jarvis-request waiting 45 s on a
//     request no one decides, and the conversation is marked as needing Deyao meanwhile (magpie's waitingOnPerson);
//
//   - the wakeup arrives as a later turn: in an aviary sandbox schedule-wakeup arms a magpie schedule, whose fire is
//     the turn (<scheduled-message …>), answered by the stand-in;
//
//   - a message to a paused session (Deyao, 2026-11-20): the session is paused as the app pauses it, its conversation
//     stays open, a message sent in the chat (as pigeon sends it) resumes the session on a new machine with no prompt
//     and no approval in the Inbox, and the message is answered there;
//
//   - a conversation begun in the chat (Deyao, 2026-11-18: New chat starts its own session): the driver creates it in
//     magpie as pigeon does, with a first message; hermit-jarvis proposes a session through the router, which waits in
//     the Inbox while magpie holds the message and says the start waits for the person's approval
//     (`sandboxWaiting: approval`); approved, the session's machine boots that conversation's sandbox and the held
//     message is answered; a second one, denied, leaves the chat (magpie's `deletedAt`), its message with it;
//
//   - destroy: the source burns, the record stays.
//
//     E2E_ROUTER, E2E_SPAWNER, E2E_DATA_DIR, E2E_MASTER_KEY_FILE, E2E_FLY_TOKEN, E2E_RUNNER (as e2e/kernel); E2E_FRONT_ADDR (where
//     the chat peer's m-gateway sends), E2E_HERMIT_GW (hermit-jarvis's gateway listener), E2E_CHAT_URL (the chat peer
//     as the machines know it), E2E_MAGPIE + E2E_MAGPIE_ADMIN (magpie and its admin token), E2E_MAGPIE_PIGEON (the
//     token magpie takes from pigeon: the chat's own calls), E2E_OWNER (hermit-jarvis's person)
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DE0CH/jarvis4/e2e/routerdb"
	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/secrets"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

var (
	router = os.Getenv("E2E_ROUTER")
	b64    = base64.StdEncoding
	token  = hex.EncodeToString(randBytes(6)) // this run's marker: in the prompt, the tool's output, the answers
)

func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

func call(method, u string, body any, hdr ...string) (int, []byte) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, u, rd)
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("%s %s: %v", method, u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func must(method, u string, body any, out any) {
	code, b := call(method, u, body)
	if code/100 != 2 {
		log.Fatalf("%s %s: HTTP %d %s", method, u, code, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			log.Fatalf("%s %s: %v (%s)", method, u, err, b)
		}
	}
}

func step(f string, a ...any) { log.Printf("==== "+f, a...) }

func waitFor(what string, limit time.Duration, ok func() bool) {
	for end := time.Now().Add(limit); ; time.Sleep(3 * time.Second) {
		if ok() {
			return
		}
		if time.Now().After(end) {
			log.Fatalf("timed out after %s waiting for %s", limit, what)
		}
	}
}

// ---- the router's records (as e2e/kernel)

type session struct {
	State     string `json:"state"`
	MachineID string `json:"machineId"`
	Booted    string `json:"booted"`
	Error     string `json:"error"`
	AiTitle   string `json:"aiTitle"`
	Harness   string `json:"harness"`
}

func readSession(id string) (*session, bool) {
	b, err := routerdb.StateJSON()
	if err != nil {
		return nil, false
	}
	var st struct {
		Sessions map[string]*session `json:"sessions"`
		Records  []struct {
			ID     string `json:"id"`
			Kernel *struct {
				Burned bool `json:"burned"`
			} `json:"kernel"`
		} `json:"records"`
	}
	if json.Unmarshal(b, &st) != nil {
		return nil, false
	}
	if s := st.Sessions[id]; s != nil {
		return s, false
	}
	for _, r := range st.Records {
		if r.ID == id {
			return nil, r.Kernel != nil && r.Kernel.Burned
		}
	}
	return nil, false
}

// ---- a store key as the app writes it: the value under its own data key, that key wrapped to P + K (kernel/secrets
// keys.go; WrapToPoint in its tests)

func gcmSeal(key, plain, aad []byte) []byte {
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	nonce := randBytes(g.NonceSize())
	return append(nonce, g.Seal(nil, nonce, plain, aad)...)
}

func wrapKey(combined []byte, store, key, value string) secrets.KeyEntry {
	dk := randBytes(32)
	e, _ := ecdh.P256().GenerateKey(rand.Reader)
	shared, err := secrets.ScalarMult(e.Bytes(), combined)
	if err != nil {
		log.Fatal(err)
	}
	kek, _ := hkdf.Key(sha256.New, shared[1:33], nil, "jarvis2/store-data-key", 32)
	return secrets.KeyEntry{Store: store, Key: key,
		Wrapped: secrets.WrappedKey{E: b64.EncodeToString(e.PublicKey().Bytes()), Wrapped: b64.EncodeToString(gcmSeal(kek, dk, nil))},
		Data:    b64.EncodeToString(gcmSeal(dk, []byte(value), secrets.KeyAAD(store, key)))}
}

// ---- the stand-in model (Anthropic's Messages API, streamed or not) and the chat peer's front

type modelLog struct {
	sync.Mutex
	calls []string // one line per call: what it answered
	// CLAUDE_CODE_MAX_CONTEXT_TOKENS in the sandbox ("none": unset), from the tool call's output: what the supervisor
	// asked Claude Code for, which is not the window Claude Code runs at (magpieContextWindow)
	context string
	// where the tool call ran, from its output: "aviary" = in the root of aviary's sandbox image (the image's own
	// setup files are there, the session image's harness script is not) with Jarvis's session commands on the PATH
	root string
	// the first prompt's message held an image block: its attached screenshot reached the model as an image
	image bool
	// the time machine's tool result (a fabric run): "Back after …: <why>"
	timeMachine string
	// the wakeup's turn was magpie's schedule firing (<scheduled-message rule="…">): schedule-wakeup in an aviary
	// sandbox arms a magpie schedule (Deyao, 2026-11-17), not a router wakeup
	scheduled bool
}

var models modelLog

// runner: the run's runner (E2E_RUNNER): on the fabric the wakeup's turn also goes into the time machine
var runner string

// systemText: a request's system prompt as one string (a string, or text blocks).
func systemText(req map[string]any) string {
	switch s := req["system"].(type) {
	case string:
		return s
	case []any:
		var out []string
		for _, b := range s {
			if m, _ := b.(map[string]any); m != nil {
				t, _ := m["text"].(string)
				out = append(out, t)
			}
		}
		return strings.Join(out, "\n")
	}
	return ""
}

// reply: what the stand-in answers. The first prompt (E2E-RUN) gets a Bash tool call; the turn with its result gets an
// answer quoting the result; the wakeup (E2E-WAKEUP) gets its own answer; magpie's title call (hermit-jarvis's title
// instructions) gets the title; anything else (summaries) "ok".
func reply(req map[string]any) (kind string, content []map[string]any) {
	msgs, _ := req["messages"].([]any)
	text := func(m any) string { b, _ := json.Marshal(m); return string(b) }
	var last string
	var lastUser map[string]any
	for i := len(msgs) - 1; i >= 0; i-- {
		if m, _ := msgs[i].(map[string]any); m != nil && m["role"] == "user" {
			lastUser, last = m, text(m)
			break
		}
	}
	_ = lastUser
	if tools, _ := req["tools"].([]any); len(tools) == 0 { // a side call (a title, a summary): never the agent's turn
		if strings.Contains(systemText(req), "Write a short title") {
			return "title", []map[string]any{{"type": "text", "text": "E2E-TITLE " + token}}
		}
		return "other", []map[string]any{{"type": "text", "text": "ok"}}
	}
	switch {
	case strings.Contains(last, "tool_result") && strings.Contains(last, "E2E-OUT-"+token):
		if i := strings.Index(last, "E2E-CTX="); i >= 0 { // Claude Code's context window, as the sandbox's shell saw it
			ctx := last[i+len("E2E-CTX="):]
			if j := strings.Index(ctx, "."); j >= 0 {
				models.Lock()
				models.context = ctx[:j]
				models.Unlock()
			}
		}
		if i := strings.Index(last, "E2E-ROOT="); i >= 0 {
			root := last[i+len("E2E-ROOT="):]
			if j := strings.Index(root, "."); j >= 0 {
				models.Lock()
				models.root = root[:j]
				models.Unlock()
			}
		}
		return "answer", []map[string]any{{"type": "text", "text": "E2E-DONE " + token + ": the command printed E2E-OUT-" + token}}
	case strings.Contains(last, "tool_result") && strings.Contains(last, "Back after"):
		// the time machine's answer (a fabric run): the session was frozen 20 s and came back at its time
		models.Lock()
		models.timeMachine = last
		models.Unlock()
		return "wakeup", []map[string]any{{"type": "text", "text": "E2E-WOKE " + token}}
	case strings.Contains(last, "E2E-WAKEUP "+token):
		if strings.Contains(last, "scheduled-message rule=") {
			models.Lock()
			models.scheduled = true
			models.Unlock()
		}
		if runner == "fabric" { // a fabric session waits in the time machine before it answers
			return "tool", []map[string]any{{"type": "tool_use", "id": "toolu_e2e_tm_" + token, "name": "Bash",
				"input": map[string]any{"command": "time-machine 20s", "description": "e2e: wait 20 s frozen"}}}
		}
		return "wakeup", []map[string]any{{"type": "text", "text": "E2E-WOKE " + token}}
	case strings.Contains(last, "tool_result") && strings.Contains(last, "E2E-SILENCED-"+token):
		return "answer", []map[string]any{{"type": "text", "text": "E2E-STILL-HERE " + token}}
	case strings.Contains(last, "E2E-AFTER "+token):
		return "answer", []map[string]any{{"type": "text", "text": "E2E-AFTERED " + token}}
	case strings.Contains(last, "E2E-SILENT "+token):
		// aviary's supervisor stopped 150 s, as a final snapshot stops it (supervisor.rs freeze_session): past the
		// fabric hermit's 90 s silence and two of its janitor passes, so a hermit that judges silence releases it
		// the supervisor runs as the sandbox's root (aviary's image), so the tool's user stops it through sudo
		cmd := "sudo -n true && (setsid sh -c 'sleep 3; sudo -n pkill -STOP -x supervisor; sleep 150; sudo -n pkill -CONT -x supervisor' > /dev/null 2>&1 &) && echo E2E-SILENCED-" + token
		return "tool", []map[string]any{{"type": "tool_use", "id": "toolu_e2e_silent_" + token, "name": "Bash",
			"input": map[string]any{"command": cmd, "description": "e2e: stop the supervisor 150 s"}}}
	case strings.Contains(last, "E2E-FREEZE "+token):
		// a fabric session that waits frozen for an hour: its destroy (no force) must thaw it for its final snapshot
		return "tool", []map[string]any{{"type": "tool_use", "id": "toolu_e2e_freeze_" + token, "name": "Bash",
			"input": map[string]any{"command": "time-machine 1h", "description": "e2e: wait an hour frozen"}}}
	case strings.Contains(last, "E2E-PAUSED "+token):
		return "resumed", []map[string]any{{"type": "text", "text": "E2E-RESUMED " + token}}
	case strings.Contains(last, "E2E-CHAT "+token):
		return "chat", []map[string]any{{"type": "text", "text": "E2E-CHATTED " + token}}
	case strings.Contains(last, "E2E-RUN "+token):
		if strings.Contains(last, `"type":"image"`) {
			models.Lock()
			models.image = true
			models.Unlock()
		}
		cmd := "echo E2E-OUT-" + token + " | tee ~/artifacts/e2e-aviary.txt && echo E2E-CTX=${CLAUDE_CODE_MAX_CONTEXT_TOKENS:-none}. && " +
			"echo E2E-ROOT=$(test -e /opt/image-setup/Dockerfile && ! test -e /usr/local/bin/harness-aviary.sh && command -v jarvis > /dev/null && echo aviary || echo machine). && " +
			"schedule-wakeup --name e2e 60s 'E2E-WAKEUP " + token + "' && " +
			// a command that waits on Deyao (an Inbox request no one decides), 45 s in the background: the conversation
			// needs him meanwhile (Deyao, 2026-11-18: the chat's yellow mark)
			"(setsid jarvis-request wait e2e-person-wait-" + token + " --timeout 45 > /dev/null 2>&1 &)"
		return "tool", []map[string]any{{"type": "tool_use", "id": "toolu_e2e_" + token, "name": "Bash",
			"input": map[string]any{"command": cmd, "description": "e2e: write the marker and arm the wakeup"}}}
	}
	return "other", []map[string]any{{"type": "text", "text": "ok"}}
}

func sse(w io.Writer, typ string, data any) {
	b, _ := json.Marshal(data)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", typ, b)
}

// sessionModel: the model the run's session starts on (E2E_MODEL): by default the newest Claude model of the menu,
// the one a pinned Claude Code is the likeliest not to recognise (2.1.304 ran Fable 5.2 at 200k, 2026-11-16); an
// OpenRouter one (aviary/z-ai/glm-5.3) sends the agent's turns to the stand-in OpenRouter, the title call still to
// the Claude one.
func sessionModel() string {
	if m := os.Getenv("E2E_MODEL"); m != "" {
		return m
	}
	return "aviary/claude-fable-5-2"
}

// openRouterKey: the OPENROUTER_API of the run's store, which only the stand-in OpenRouter takes.
const openRouterKey = "e2e-openrouter"

// writeJSON and jsonError answer as Anthropic's API does, with Content-Type application/json: Claude Code parses a
// non-streamed body by its content type (Go's sniffed text/plain failed its model check, main_test.go).
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, body string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	io.WriteString(w, body)
}

func serveModel(w http.ResponseWriter, req *http.Request) {
	openRouter := strings.HasPrefix(req.URL.Path, "/openrouter/")
	p := strings.TrimPrefix(strings.TrimPrefix(req.URL.Path, "/openrouter"), "/model")
	if openRouter && strings.HasSuffix(p, "/count_tokens") { // OpenRouter has no count_tokens (404, 2026-11-12)
		jsonError(w, `{"error":{"message":"Not Found","code":404}}`, 404)
		return
	}
	if strings.HasSuffix(p, "/count_tokens") {
		writeJSON(w, map[string]int{"input_tokens": 10})
		return
	}
	if req.Method != http.MethodPost || !strings.HasSuffix(p, "/v1/messages") {
		jsonError(w, `{"type":"error","error":{"type":"not_found_error","message":"e2e stand-in"}}`, 404)
		return
	}
	var in map[string]any
	if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	model, _ := in["model"].(string)
	if openRouter {
		// As OpenRouter: its own key (never the Claude login), an OpenRouter model id, the model's hosts named
		// (DE0CH/aviary jarvis/hermit/src/machine.rs for_openrouter), and no thinking switched off (its hosts answer that 400).
		provider, _ := in["provider"].(map[string]any)
		order, _ := provider["order"].([]any)
		thinking, _ := in["thinking"].(map[string]any)
		if req.Header.Get("Authorization") != "Bearer "+openRouterKey || !strings.Contains(model, "/") || len(order) == 0 || thinking["type"] == "disabled" {
			log.Printf("openrouter: refused (auth %q, model %q, provider %v, thinking %v)", req.Header.Get("Authorization"), model, provider, thinking)
			jsonError(w, `{"type":"error","error":{"type":"invalid_request_error","message":"e2e stand-in OpenRouter"}}`, 400)
			return
		}
	} else if strings.Contains(model, "/") || req.Header.Get("Authorization") == "Bearer "+openRouterKey {
		log.Printf("model: refused, an OpenRouter call reached the Claude stand-in (model %q)", model)
		jsonError(w, `{"type":"error","error":{"type":"invalid_request_error","message":"e2e: not a Claude call"}}`, 400)
		return
	}
	// As Anthropic treats a subscription login: a call whose system prompt does not begin with Claude Code's identity
	// is refused 429 (2026-11-12: every title call, so no conversation had a title). Claude Code's own calls carry it;
	// the gateway puts it first on any other (the supervisor's title call).
	if sys := systemText(in); !openRouter && !strings.HasPrefix(req.UserAgent(), "claude-cli/") &&
		!strings.HasPrefix(sys, "You are Claude Code") && !strings.HasPrefix(sys, "You are a Claude agent") {
		log.Printf("model: refused, no Claude Code identity (user agent %q)", req.UserAgent())
		jsonError(w, `{"type":"error","error":{"type":"rate_limit_error","message":"Error"}}`, 429)
		return
	}
	kind, content := reply(in)
	stop := "end_turn"
	if kind == "tool" {
		stop = "tool_use"
	}
	models.Lock()
	if openRouter {
		models.calls = append(models.calls, "openrouter:"+kind)
	} else {
		models.calls = append(models.calls, kind)
	}
	models.Unlock()
	log.Printf("model: %s (openrouter %v, auth %q)", kind, openRouter, req.Header.Get("Authorization"))
	if kind == "other" { // what the stand-in did not recognise: enough to see why (a side call, or a turn whose shape changed)
		msgs, _ := in["messages"].([]any)
		tools, _ := in["tools"].([]any)
		last := ""
		if n := len(msgs); n > 0 {
			b, _ := json.Marshal(msgs[n-1])
			last = string(b)
		}
		if len(last) > 1500 {
			last = last[len(last)-1500:]
		}
		sys := systemText(in)
		if len(sys) > 300 {
			sys = sys[:300]
		}
		log.Printf("model: other: model %v, %d tools, %d messages, system %q, last message %s", in["model"], len(tools), len(msgs), sys, last)
	}
	id := "msg_e2e_" + hex.EncodeToString(randBytes(6))
	// the agent's turns read the most input: the supervisor takes the conversation's context window from the model
	// that did (a `result`'s modelUsage), never from a side call's model
	usage := map[string]int{"input_tokens": 10, "output_tokens": 5}
	if kind == "tool" || kind == "answer" || kind == "wakeup" {
		usage["input_tokens"] = 1000
	}
	if s, _ := in["stream"].(bool); !s {
		writeJSON(w, map[string]any{"id": id, "type": "message", "role": "assistant", "model": in["model"],
			"content": content, "stop_reason": stop, "stop_sequence": nil, "usage": usage})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	bw := bufio.NewWriter(w)
	sse(bw, "message_start", map[string]any{"type": "message_start", "message": map[string]any{"id": id, "type": "message",
		"role": "assistant", "model": in["model"], "content": []any{}, "stop_reason": nil, "stop_sequence": nil, "usage": usage}})
	for i, c := range content {
		if c["type"] == "tool_use" {
			input, _ := json.Marshal(c["input"])
			sse(bw, "content_block_start", map[string]any{"type": "content_block_start", "index": i,
				"content_block": map[string]any{"type": "tool_use", "id": c["id"], "name": c["name"], "input": map[string]any{}}})
			sse(bw, "content_block_delta", map[string]any{"type": "content_block_delta", "index": i,
				"delta": map[string]any{"type": "input_json_delta", "partial_json": string(input)}})
		} else {
			sse(bw, "content_block_start", map[string]any{"type": "content_block_start", "index": i,
				"content_block": map[string]any{"type": "text", "text": ""}})
			sse(bw, "content_block_delta", map[string]any{"type": "content_block_delta", "index": i,
				"delta": map[string]any{"type": "text_delta", "text": c["text"]}})
		}
		sse(bw, "content_block_stop", map[string]any{"type": "content_block_stop", "index": i})
	}
	sse(bw, "message_delta", map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": stop, "stop_sequence": nil},
		"usage": map[string]int{"output_tokens": 5}})
	sse(bw, "message_stop", map[string]any{"type": "message_stop"})
	bw.Flush()
}

func serveFront() {
	gw, err := url.Parse(os.Getenv("E2E_HERMIT_GW"))
	if err != nil || gw.Host == "" {
		log.Fatal("E2E_HERMIT_GW")
	}
	proxy := httputil.NewSingleHostReverseProxy(gw)
	proxy.FlushInterval = -1
	mux := http.NewServeMux()
	mux.HandleFunc("/model/", serveModel)
	mux.HandleFunc("/openrouter/", serveModel)
	mux.Handle("/", proxy)
	go func() { log.Fatal(http.ListenAndServe(os.Getenv("E2E_FRONT_ADDR"), mux)) }()
}

// ---- magpie, through its admin API

// magpieContextWindow: the context window Claude Code states for the conversation's model (a `result`'s
// modelUsage[model].contextWindow, which the supervisor reports at each turn end and magpie keeps on the
// conversation): where Claude Code compacts. 0 until a turn has ended.
func magpieContextWindow() int64 {
	hdr := []string{"Authorization", "Bearer " + os.Getenv("E2E_MAGPIE_ADMIN"), "Aviary-Admin", "e2e@example.com"}
	code, b := call("GET", os.Getenv("E2E_MAGPIE")+"/v1/admin/conversations", nil, hdr...)
	if code != 200 {
		return 0
	}
	var list any
	json.Unmarshal(b, &list)
	var window int64
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if w, ok := x["contextWindow"].(float64); ok {
				window = int64(w)
			}
			for _, y := range x {
				walk(y)
			}
		case []any:
			for _, y := range x {
				walk(y)
			}
		}
	}
	walk(list)
	return window
}

// magpieWaiting: a conversation of magpie's admin list waits on the person (a command in its sandbox waits on him).
func magpieWaiting() bool {
	hdr := []string{"Authorization", "Bearer " + os.Getenv("E2E_MAGPIE_ADMIN"), "Aviary-Admin", "e2e@example.com"}
	code, b := call("GET", os.Getenv("E2E_MAGPIE")+"/v1/admin/conversations", nil, hdr...)
	return code == 200 && strings.Contains(string(b), `"waitingOnPerson":true`)
}

func magpieText() string {
	hdr := []string{"Authorization", "Bearer " + os.Getenv("E2E_MAGPIE_ADMIN"), "Aviary-Admin", "e2e@example.com"}
	code, b := call("GET", os.Getenv("E2E_MAGPIE")+"/v1/admin/conversations", nil, hdr...)
	if code != 200 {
		return ""
	}
	var list any
	json.Unmarshal(b, &list)
	var ids []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if id, ok := x["id"].(string); ok && len(id) >= 32 {
				ids = append(ids, id)
			}
			for _, y := range x {
				walk(y)
			}
		case []any:
			for _, y := range x {
				walk(y)
			}
		}
	}
	walk(list)
	all := string(b)
	for _, id := range ids {
		_, t := call("GET", os.Getenv("E2E_MAGPIE")+"/v1/admin/conversations/"+id+"/transcript", nil, hdr...)
		all += "\n" + string(t)
		_, ev := call("GET", os.Getenv("E2E_MAGPIE")+"/v1/admin/conversations/"+id+"/events?after=0&limit=500", nil, hdr...)
		all += "\n" + string(ev)
	}
	return all
}

// ---- magpie as pigeon calls it (the chat's own calls, for the person hermit-jarvis serves)

func asPigeon() []string {
	return []string{"Authorization", "Bearer " + os.Getenv("E2E_MAGPIE_PIGEON"), "Aviary-Person", os.Getenv("E2E_OWNER"),
		"Aviary-Protocol", "magpie-person=1"}
}

// chatConversation: the conversation as the chat reads it (M2): whether its start waits for an approval, whether it
// left the chat.
type chatConversation struct {
	ID             string  `json:"id"`
	Sandbox        *string `json:"sandbox"`
	SandboxWaiting *string `json:"sandboxWaiting"`
	DeletedAt      *string `json:"deletedAt"`
}

func readChat(id string) chatConversation {
	var c chatConversation
	code, b := call("GET", os.Getenv("E2E_MAGPIE")+"/v1/conversations/"+id, nil, asPigeon()...)
	if code != 200 {
		log.Fatalf("FAIL: magpie answered %d to the chat's read of conversation %s: %s", code, id, b)
	}
	json.Unmarshal(b, &c)
	return c
}

// newChat: New chat with a first message, as pigeon sends it (M3); the conversation's id.
func newChat(text string) string {
	body := map[string]any{"idempotencyKey": "e2e-" + text, "message": map[string]any{
		"clientMessageId": "e2e-" + text, "text": text, "images": []any{}, "files": []any{}}}
	code, b := call("POST", os.Getenv("E2E_MAGPIE")+"/v1/conversations", body, asPigeon()...)
	var r struct {
		Conversation struct{ ID string }
		Turn         *struct{ ID string }
	}
	json.Unmarshal(b, &r)
	if code != 201 || r.Conversation.ID == "" || r.Turn == nil {
		log.Fatalf("FAIL: magpie answered %d to a new chat's first message (no turn admitted): %s", code, b)
	}
	return r.Conversation.ID
}

// magpieConversationTitled: the id of magpie's conversation titled `title` (a session's conversation is titled with
// its name), "" when there is none.
func magpieConversationTitled(title string) string {
	hdr := []string{"Authorization", "Bearer " + os.Getenv("E2E_MAGPIE_ADMIN"), "Aviary-Admin", "e2e@example.com"}
	code, b := call("GET", os.Getenv("E2E_MAGPIE")+"/v1/admin/conversations", nil, hdr...)
	if code != 200 {
		return ""
	}
	var list any
	json.Unmarshal(b, &list)
	found := ""
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if id, ok := x["id"].(string); ok && x["title"] == title {
				found = id
			}
			for _, y := range x {
				walk(y)
			}
		case []any:
			for _, y := range x {
				walk(y)
			}
		}
	}
	walk(list)
	return found
}

// approvalFor: whether the Inbox holds an approval for `session`.
func approvalFor(session string) bool {
	var s struct {
		Approvals []struct{ Session string } `json:"approvals"`
	}
	must("GET", router+"/api/state", nil, &s)
	for _, x := range s.Approvals {
		if x.Session == session {
			return true
		}
	}
	return false
}

// proposal: the new-session approval the router filed for a session other than `skip` (hermit-jarvis's proposal for a
// conversation begun in the chat), once it is in the Inbox.
func proposal(skip map[string]bool) (session, approval string, challenge sig.Doc) {
	waitFor("hermit-jarvis's proposal in the Inbox", 2*time.Minute, func() bool {
		var s struct {
			Approvals []struct {
				ID, Kind, Session string
				Challenge         sig.Doc
			} `json:"approvals"`
		}
		must("GET", router+"/api/state", nil, &s)
		for _, x := range s.Approvals {
			if !skip[x.Session] && x.Kind == "kernel-source" {
				session, approval, challenge = x.Session, x.ID, x.Challenge
				return true
			}
		}
		return false
	})
	return
}

func main() {
	log.SetFlags(log.Ltime)
	serveFront()
	mk, err := os.ReadFile(os.Getenv("E2E_MASTER_KEY_FILE"))
	if err != nil {
		log.Fatal(err)
	}
	master, err := sig.SignerFromPEM(mk)
	if err != nil {
		log.Fatal(err)
	}
	phone, _ := sig.NewSigner()
	phoneAgree, _ := ecdh.P256().GenerateKey(rand.Reader)
	rk, err := os.ReadFile(os.Getenv("E2E_ROOT_KEY_FILE"))
	if err != nil {
		log.Fatal(err)
	}
	root, err := sig.SignerFromPEM(rk)
	if err != nil {
		log.Fatal(err)
	}
	chat := strings.TrimRight(os.Getenv("E2E_CHAT_URL"), "/")

	step("the roster: the app's root key registered, every component's fresh keys vouched for in one root-signed document")
	must("POST", router+"/api/kernel/root-key", map[string]string{"rootKey": root.PublicKey()}, nil)
	ro := sig.Roster{Kind: "kernel-roster", Copy: "blue"}
	for _, kv := range strings.Split(strings.TrimRight(os.Getenv("E2E_KERNEL"), ","), ",") {
		role, base, _ := strings.Cut(kv, "=")
		var m sig.Identity
		waitFor(role+"'s identity", time.Minute, func() bool {
			code, b := call("GET", base+"/identity", nil)
			if code != 200 {
				return false
			}
			if role == "secrets" { // {role, signingKey, agreementKey, state}
				return json.Unmarshal(b, &m) == nil && m.SigningKey != ""
			}
			var d sig.Doc // self-signed {payload, sig}
			return json.Unmarshal(b, &d) == nil && json.Unmarshal([]byte(d.Payload), &m) == nil && m.SigningKey != ""
		})
		ro.Members = append(ro.Members, sig.Identity{Role: m.Role, SigningKey: m.SigningKey, AgreementKey: m.AgreementKey})
	}
	sort.Slice(ro.Members, func(i, j int) bool { return ro.Members[i].Role < ro.Members[j].Role })
	rp, _ := json.Marshal(ro)
	rsig, _ := root.Sign(rp)
	var rres any
	must("POST", router+"/api/kernel/roster", map[string]string{"payload": string(rp), "rootSig": rsig}, &rres)
	log.Printf("roster: %v", rres)

	step("the kernel's secrets: a Reset with the test master key; the store aviary-gw (this run's chat peer)")
	var id struct{ SigningKey, AgreementKey string }
	must("GET", router+"/api/kernel/secrets/identity", nil, &id)
	ka, _ := b64.DecodeString(id.AgreementKey)
	combined, err := secrets.AddPoints(phoneAgree.PublicKey().Bytes(), ka)
	if err != nil {
		log.Fatal(err)
	}
	keys := []secrets.KeyEntry{}
	for k, v := range map[string]string{"AVIARY_GW_ACCESS_ID": "e2e", "AVIARY_GW_ACCESS_SECRET": "e2e",
		"AVIARY_GW_URL": chat, "AVIARY_MODEL_URL": chat + "/model",
		"AVIARY_OPENROUTER_URL": chat + "/openrouter", "OPENROUTER_API": openRouterKey} {
		keys = append(keys, wrapKey(combined, "aviary-gw", k, v))
	}
	bundle, _ := json.Marshal(map[string]any{"format": "keys", "stores": []string{"aviary-gw"}, "keys": keys,
		"notSensitive": []string{"aviary-gw"}})
	sum := sha256.Sum256(bundle)
	st, _ := json.Marshal(map[string]any{"kind": "kernel-claim", "master": master.PublicKey(),
		"secrets": map[string]string{"signingKey": id.SigningKey, "agreementKey": id.AgreementKey},
		"phone":   map[string]string{"signingKey": phone.PublicKey(), "agreementKey": b64.EncodeToString(phoneAgree.PublicKey().Bytes())},
		"root":    root.PublicKey(), "bundleSha256": hex.EncodeToString(sum[:])})
	ms, _ := master.Sign(st)
	sealed, err := secrets.SealTo(id.AgreementKey, bundle, "jarvis2/kernel-claim")
	if err != nil {
		log.Fatal(err)
	}
	must("POST", router+"/api/kernel/secrets/claim", map[string]any{"statement": string(st), "masterSig": ms, "bundle": sealed}, nil)

	var sd sig.Doc
	must("GET", os.Getenv("E2E_SPAWNER")+"/identity", nil, &sd)
	var sid sig.Identity
	json.Unmarshal([]byte(sd.Payload), &sid)
	// the runner of this run: Fly (rust/e2e-kernel's default), or the fabric (rust/e2e-kernel E2E_RUNNER=fabric, its hermit
	// the replica's fake one)
	runner = os.Getenv("E2E_RUNNER")
	if runner == "fabric" {
		step("the spawner's fabric credentials, sealed to it")
		cred, _ := json.Marshal(map[string]string{"magpieToken": os.Getenv("E2E_FABRIC_MAGPIE"),
			"adminToken": os.Getenv("E2E_FABRIC_ADMIN"), "admin": "e2e@fabric.invalid", "person": "jarvis4@deyaochen.com"})
		cs, err := sig.SealTo(sid.AgreementKey, cred, "jarvis4/fabric-credentials")
		if err != nil {
			log.Fatal(err)
		}
		must("POST", os.Getenv("E2E_SPAWNER")+"/fabric-credentials", map[string]any{"sealed": cs}, nil)
	} else {
		step("the spawner's Fly token, sealed to it")
		tok, _ := json.Marshal(map[string]string{"FLY_API_TOKEN": os.Getenv("E2E_FLY_TOKEN")})
		ts, err := sig.SealTo(sid.AgreementKey, tok, "jarvis2/fly-token")
		if err != nil {
			log.Fatal(err)
		}
		must("POST", os.Getenv("E2E_SPAWNER")+"/fly-token", map[string]any{"sealed": ts}, nil)
	}

	step("the root grant: ⊤ on the sink, signed by the root key")
	var draft struct{ Payload string }
	must("GET", router+"/api/kernel/root-grant/draft", nil, &draft)
	rs, _ := root.Sign([]byte(draft.Payload))
	must("POST", router+"/api/kernel/root-grant", map[string]any{"grant": map[string]string{"payload": draft.Payload, "sig": rs}}, nil)

	step("a standing unlock of aviary (the Stores page): the phone's share of each key, sealed to secrets' one-off key")
	var ubd sig.Doc
	must("POST", router+"/api/kernel/secrets/unlock/begin", map[string]string{"store": "aviary-gw"}, &ubd)
	var ub struct {
		Pending, T string
		Keys       []struct{ Key, E string }
	}
	json.Unmarshal([]byte(ubd.Payload), &ub)
	shares := map[string]secrets.Sealed{}
	for _, k := range ub.Keys {
		eb, _ := b64.DecodeString(k.E)
		E, err := ecdh.P256().NewPublicKey(eb)
		if err != nil {
			log.Fatal(err)
		}
		x, _ := phoneAgree.ECDH(E)
		if shares[k.Key], err = secrets.SealTo(ub.T, x, "jarvis2/unlock-share"); err != nil {
			log.Fatal(err)
		}
	}
	must("POST", router+"/api/kernel/secrets/unlock/finish", map[string]any{"pending": ub.Pending, "shares": shares}, nil)

	step("a Claude account with a fake login (its token reaches only the stand-in model)")
	must("POST", router+"/api/claude-accounts", map[string]any{"name": "e2e"}, nil)
	must("POST", router+"/peer/claude-login", map[string]any{"credentials": `{"claudeAiOauth": {"accessToken": "e2e-fake-access", "refreshToken": "e2e-fake-refresh", "expiresAt": 4102444800000, "scopes": ["user:inference"], "subscriptionType": "max"}}`,
		"account": `{"oauthAccount":{"accountUuid":"e2e-account","emailAddress":"e2e@example.com"}}`, "relogin": true}, nil)

	step("a session with the harness aviary and a first prompt with a screenshot attached; the phone signs its source")
	shot := "e2e-shot-" + token + ".png"
	uploadID := "e2e-" + token
	{
		img := image.NewRGBA(image.Rect(0, 0, 8, 8))
		for i := range img.Pix {
			img.Pix[i] = byte(i * 7)
		}
		var buf bytes.Buffer
		png.Encode(&buf, img)
		req, _ := http.NewRequest("POST", router+"/api/uploads", &buf)
		req.Header.Set("x-upload-id", uploadID)
		req.Header.Set("x-upload-name", shot)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode/100 != 2 {
			log.Fatalf("the screenshot's upload: %v %v", err, resp)
		}
		resp.Body.Close()
	}
	// the session's name: the conversation's title from its start, kept as a rename (hermit-jarvis's create, Deyao,
	// 2026-11-17), so the title model's title never replaces it
	label := "e2e aviary " + token
	var created struct{ ID string }
	newSession := map[string]any{"label": label, "harness": "aviary", "size": "small",
		"model": sessionModel(), "prompt": "E2E-RUN " + token,
		"attachments": map[string]any{"uploadId": uploadID, "files": []map[string]any{{"name": shot, "isImage": true}}}}
	if runner != "" {
		newSession["runner"] = runner
	}
	must("POST", router+"/api/sessions", newSession, &created)
	var aID, aKind string
	var challenge sig.Doc
	waitFor("the approval", time.Minute, func() bool {
		var s struct {
			Approvals []struct {
				ID, Kind, Session string
				Challenge         sig.Doc
			} `json:"approvals"`
		}
		must("GET", router+"/api/state", nil, &s)
		for _, x := range s.Approvals {
			if x.Session == created.ID {
				aID, aKind, challenge = x.ID, x.Kind, x.Challenge
			}
		}
		return aID != ""
	})
	if aKind != "kernel-source" {
		log.Fatalf("approval kind %s", aKind)
	}
	var c doc.Cert
	json.Unmarshal([]byte(challenge.Payload), &c)
	log.Printf("session %s, image %s", created.ID, c.Source.Image)
	ps, _ := phone.Sign([]byte(challenge.Payload))
	must("POST", router+"/api/approvals/"+aID+"/respond", map[string]string{"signature": ps}, nil)

	var machine string
	waitFor("the machine to boot", 15*time.Minute, func() bool {
		s, _ := readSession(created.ID)
		if s != nil && s.State == "failed" {
			log.Fatalf("the session failed: %s", s.Error)
		}
		if s != nil && s.State == "started" && s.Booted == s.MachineID && s.MachineID != "" {
			machine = s.MachineID
			return true
		}
		return false
	})
	log.Printf("machine %s booted", machine)

	step("the sandbox boots, the first prompt runs: a Bash tool call in the sandbox, then the answer quoting its output")
	waitFor("the answer in magpie", 10*time.Minute, func() bool {
		t := magpieText()
		return strings.Contains(t, "E2E-DONE "+token) && strings.Contains(t, "E2E-OUT-"+token)
	})
	step("a command waiting on Deyao (jarvis-request) marks the conversation as needing him, until it ends")
	// the supervisor's person wait → its heartbeat's `waiting` → magpie's waitingOnPerson → pigeon's needs_input
	// (Deyao, 2026-11-18: what waits on him shows yellow in the chat)
	waitFor("magpie's waitingOnPerson while jarvis-request waits", 40*time.Second, func() bool { return magpieWaiting() })
	waitFor("magpie's waitingOnPerson cleared once jarvis-request ended", 90*time.Second, func() bool { return !magpieWaiting() })
	step("the screenshot is an image of the first message, as Deyao's own in the chat: never a path in its text")
	models.Lock()
	sawImage := models.image
	models.Unlock()
	if !sawImage {
		log.Fatalf("FAIL: the first prompt's message reached the model without an image block: the attached screenshot was not sent as an image")
	}
	if t := magpieText(); !strings.Contains(t, `"path":"uploads/`+shot+`"`) || strings.Contains(t, "[attached image:") {
		log.Fatalf("FAIL: magpie's first message does not carry the screenshot as its image (uploads/%s), or names it as a path in its text", shot)
	}
	step("the conversation's title is the session's name (never the title model's), which the session's card gets")
	waitFor("the title in magpie", 3*time.Minute, func() bool {
		return strings.Contains(magpieText(), `"title":"`+label+`"`)
	})
	if strings.Contains(magpieText(), `"title":"E2E-TITLE `+token+`"`) {
		log.Fatalf("FAIL: the title model replaced the session's name as the conversation's title")
	}
	waitFor("the title on the session (the router's aiTitle)", 4*time.Minute, func() bool {
		s, _ := readSession(created.ID)
		return s != nil && s.AiTitle == label
	})
	step("the wakeup the tool armed arrives as a later turn")
	sawFrozen := false
	waitFor("the wakeup's answer in magpie", 5*time.Minute, func() bool {
		if s, _ := readSession(created.ID); s != nil && s.State == "frozen" {
			sawFrozen = true
		}
		return strings.Contains(magpieText(), "E2E-WOKE "+token)
	})
	if runner == "fabric" {
		step("the time machine (a fabric session): frozen 20 s, back at its time")
		models.Lock()
		tm := models.timeMachine
		models.Unlock()
		if !sawFrozen {
			log.Fatalf("FAIL: the session was never frozen while its time-machine ran (tool result: %.300s)", tm)
		}
		if !strings.Contains(tm, "the time") {
			log.Fatalf("FAIL: the time machine did not come back at its time: %.300s", tm)
		}
		if s, _ := readSession(created.ID); s == nil || s.State != "started" {
			log.Fatalf("FAIL: the session is not running after the time machine: %+v", s)
		}
	}
	models.Lock()
	if !models.scheduled {
		models.Unlock()
		log.Fatalf("FAIL: the wakeup's turn was not magpie's schedule firing (schedule-wakeup armed no magpie schedule)")
	}
	log.Printf("the stand-in model answered %d calls: %v", len(models.calls), models.calls)
	// the agent's turns went where the session's model lives: an OpenRouter model's to OpenRouter, a Claude model's
	// to Anthropic; never the other
	wantOpenRouter := strings.Contains(strings.TrimPrefix(sessionModel(), "aviary/"), "/")
	// the context window: 1M, the default for every model that names no window of its own (Deyao, 2026-11-16), and
	// GLM 5.3's own. Two checks: the supervisor asks Claude Code for it (the models route's contextTokens →
	// CLAUDE_CODE_MAX_CONTEXT_TOKENS), and Claude Code runs the conversation at it (below, after the lock)
	wantContext := "1000000"
	if models.root != "aviary" {
		log.Fatalf("FAIL: the tool call did not run in aviary's sandbox image with Jarvis's session commands (%q): the session's sandbox is not the image YYC AI runs", models.root)
	}
	if models.context != wantContext {
		log.Fatalf("FAIL: Claude Code's context window for %s is %q, want %q", sessionModel(), models.context, wantContext)
	}
	for _, c := range models.calls {
		kind := strings.TrimPrefix(c, "openrouter:")
		if kind != "tool" && kind != "answer" && kind != "wakeup" {
			continue
		}
		if strings.HasPrefix(c, "openrouter:") != wantOpenRouter {
			log.Fatalf("FAIL: the session's model is %s, but a turn (%s) went to the other model stand-in", sessionModel(), c)
		}
	}
	models.Unlock()
	// The window Claude Code runs the conversation at, as Claude Code states it. The variable alone proved nothing:
	// Claude Code 2.1.304 had it at 1000000 and still compacted Fable 5.2's conversations at 200k (a `claude-` id
	// it did not recognise; 2026-11-16).
	var window int64
	waitFor("the conversation's context window in magpie", 2*time.Minute, func() bool {
		window = magpieContextWindow()
		return window > 0
	})
	if fmt.Sprint(window) != wantContext {
		log.Fatalf("FAIL: Claude Code runs %s at a context window of %d, want %s: it compacts the conversation there", sessionModel(), window, wantContext)
	}
	log.Printf("Claude Code runs %s at a context window of %d", sessionModel(), window)

	step("a message to a paused session resumes it (no prompt, no approval) and is answered on its new machine")
	must("POST", router+"/api/sessions/"+created.ID+"/pause", map[string]any{}, nil)
	waitFor("the session paused", 15*time.Minute, func() bool {
		s, _ := readSession(created.ID)
		if s != nil && s.State == "failed" {
			log.Fatalf("FAIL: the pause failed: %s", s.Error)
		}
		return s != nil && s.State == "paused"
	})
	conversation := magpieConversationTitled(label)
	if conversation == "" {
		log.Fatalf("FAIL: no conversation in magpie titled %q (the session's)", label)
	}
	// as pigeon sends a message (M4): a closed conversation refuses it
	paused := map[string]any{"clientMessageId": "e2e-paused-" + token, "text": "E2E-PAUSED " + token, "images": []any{}, "files": []any{}}
	if code, b := call("POST", os.Getenv("E2E_MAGPIE")+"/v1/conversations/"+conversation+"/turns", paused, asPigeon()...); code/100 != 2 {
		log.Fatalf("FAIL: magpie answered %d to a message in the paused session's conversation (it must take it and resume the session): %s", code, b)
	}
	waitFor("the paused session resumed on a new machine", 15*time.Minute, func() bool {
		s, _ := readSession(created.ID)
		if s != nil && s.State == "failed" {
			log.Fatalf("FAIL: the resume for the message failed: %s", s.Error)
		}
		if approvalFor(created.ID) {
			log.Fatalf("FAIL: the resume for a message waits for an approval in the Inbox: it must need none")
		}
		return s != nil && s.State == "started" && s.MachineID != "" && s.MachineID != machine && s.Booted == s.MachineID
	})
	waitFor("the message's answer in magpie", 10*time.Minute, func() bool {
		return strings.Contains(magpieText(), "E2E-RESUMED "+token)
	})

	step("a conversation begun in the chat: its message waits for the session hermit-jarvis proposes, which Deyao approves")
	chatID := newChat("E2E-CHAT " + token)
	chatSession, chatApproval, chatChallenge := proposal(map[string]bool{created.ID: true})
	waitFor("the chat saying the start waits for an approval", 2*time.Minute, func() bool {
		c := readChat(chatID)
		return c.Sandbox != nil && *c.Sandbox == "preparing" && c.SandboxWaiting != nil && *c.SandboxWaiting == "approval"
	})
	if s, _ := readSession(chatSession); s == nil || s.Harness != "aviary" {
		log.Fatalf("FAIL: the proposed session is not an aviary session: %+v", s)
	}
	ps, _ = phone.Sign([]byte(chatChallenge.Payload))
	must("POST", router+"/api/approvals/"+chatApproval+"/respond", map[string]string{"signature": ps}, nil)
	waitFor("the chat session's machine to boot", 15*time.Minute, func() bool {
		s, _ := readSession(chatSession)
		if s != nil && s.State == "failed" {
			log.Fatalf("the chat's session failed: %s", s.Error)
		}
		return s != nil && s.State == "started" && s.Booted == s.MachineID && s.MachineID != ""
	})
	waitFor("the held message's answer in magpie", 10*time.Minute, func() bool {
		return strings.Contains(magpieText(), "E2E-CHATTED "+token)
	})
	if c := readChat(chatID); c.SandboxWaiting != nil {
		log.Fatalf("FAIL: the chat still says the start waits for an approval after its answer: %s", *c.SandboxWaiting)
	}

	step("a conversation begun in the chat whose session Deyao denies: it leaves the chat with its message")
	deniedID := newChat("E2E-DENIED " + token)
	_, deniedApproval, _ := proposal(map[string]bool{created.ID: true, chatSession: true})
	must("POST", router+"/api/approvals/"+deniedApproval+"/reject", map[string]any{}, nil)
	waitFor("the denied conversation out of the chat", 2*time.Minute, func() bool {
		return readChat(deniedID).DeletedAt != nil
	})

	// a fabric session destroyed while frozen: no force, so its final snapshot must arrive (2026-11-19: a frozen
	// machine answered nothing and the destroy failed with "silent since")
	chatForce := "?force=1"
	if runner == "fabric" {
		// 2026-11-20: a destroy's final snapshot stops aviary's supervisor, the fabric hermit's health checks went
		// unanswered and it released the sandbox mid-snapshot; hermit.json's sandbox.silenceSeconds keeps it
		step("a fabric session whose supervisor is stopped 150 s is kept by the fabric hermit")
		before, _ := readSession(chatSession)
		body := map[string]any{"clientMessageId": "e2e-silent-" + token, "text": "E2E-SILENT " + token, "images": []any{}, "files": []any{}}
		if code, b := call("POST", os.Getenv("E2E_MAGPIE")+"/v1/conversations/"+chatID+"/turns", body, asPigeon()...); code/100 != 2 {
			log.Fatalf("FAIL: magpie answered %d to the silent message: %s", code, b)
		}
		waitFor("the silent turn's answer", 6*time.Minute, func() bool {
			return strings.Contains(magpieText(), "E2E-STILL-HERE "+token)
		})
		time.Sleep(160 * time.Second) // the stop's whole 150 s has passed, whenever the answer came
		body = map[string]any{"clientMessageId": "e2e-after-" + token, "text": "E2E-AFTER " + token, "images": []any{}, "files": []any{}}
		if code, b := call("POST", os.Getenv("E2E_MAGPIE")+"/v1/conversations/"+chatID+"/turns", body, asPigeon()...); code/100 != 2 {
			log.Fatalf("FAIL: magpie answered %d to the message after the silence: %s", code, b)
		}
		waitFor("the answer after the silence", 6*time.Minute, func() bool {
			return strings.Contains(magpieText(), "E2E-AFTERED "+token)
		})
		if s, _ := readSession(chatSession); s == nil || s.State != "started" || before == nil || s.MachineID != before.MachineID {
			log.Fatalf("FAIL: the session did not keep its machine through its supervisor's silence: %+v", s)
		}
	}
	if runner == "fabric" {
		step("a frozen fabric session's destroy: thawed for its final snapshot, no force needed")
		body := map[string]any{"clientMessageId": "e2e-freeze-" + token, "text": "E2E-FREEZE " + token, "images": []any{}, "files": []any{}}
		if code, b := call("POST", os.Getenv("E2E_MAGPIE")+"/v1/conversations/"+chatID+"/turns", body, asPigeon()...); code/100 != 2 {
			log.Fatalf("FAIL: magpie answered %d to the chat's second message: %s", code, b)
		}
		waitFor("the chat's session frozen in the time machine", 3*time.Minute, func() bool {
			s, _ := readSession(chatSession)
			return s != nil && s.State == "frozen"
		})
		chatForce = ""
	}
	step("destroy: archived, its source burned")
	must("POST", router+"/api/sessions/"+created.ID+"/destroy?force=1", map[string]any{}, nil)
	must("POST", router+"/api/sessions/"+chatSession+"/destroy"+chatForce, map[string]any{}, nil)
	waitFor("the destroy", 15*time.Minute, func() bool {
		s, burned := readSession(created.ID)
		c, cburned := readSession(chatSession)
		if c != nil && c.State == "failed" {
			log.Fatalf("FAIL: the chat's session's destroy failed: %s", c.Error)
		}
		return s == nil && burned && c == nil && cburned
	})
	fmt.Println("e2e aviary: ok")
}
