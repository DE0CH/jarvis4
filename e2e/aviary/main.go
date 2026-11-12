// e2e/aviary: the aviary harness end to end on real Fly machines (infra/e2e-aviary.sh runs it, with the chat stack
// and the kernel's line beside it). It plays the iPhone with software keys as e2e/kernel does, serves the stand-in
// model and the machines' front to hermit-jarvis's gateway listener, and checks every step through the router's
// records and magpie's admin API:
//
//   - the kernel set up from the TEST master key, with the store `aviary-gw` (the gateway's Access pair as dummies, and
//     AVIARY_GW_URL / AVIARY_MODEL_URL naming this run's chat peer);
//
//   - a Claude account with a fake login (the machine's gateway sends its token to the stand-in model only);
//
//   - a session with the harness aviary and a first prompt; the phone signs its source;
//
//   - the machine boots, its gateway boots a sandbox through hermit-jarvis (signed with the machine key, checked with
//     the router), the supervisor starts Claude Code on magpie's ~/.claude, the first prompt arrives through magpie;
//
//   - Claude Code's model calls reach the stand-in model through the machine's gateway: a Bash tool call that writes
//     ~/artifacts/e2e-aviary.txt and arms a wakeup through the session's local Jarvis API, then an answer naming the
//     tool's output (so the command ran in the sandbox);
//
//   - the wakeup arrives as a later turn (the harness's inbox, magpie's hermit route), answered by the stand-in;
//
//   - destroy: the source burns, the record stays.
//
//     E2E_ROUTER, E2E_SPAWNER, E2E_DATA_DIR, E2E_MASTER_KEY_FILE, E2E_FLY_TOKEN (as e2e/kernel); E2E_FRONT_ADDR (where
//     the chat peer's m-gateway sends), E2E_HERMIT_GW (hermit-jarvis's gateway listener), E2E_CHAT_URL (the chat peer
//     as the machines know it), E2E_MAGPIE + E2E_MAGPIE_ADMIN (magpie and its admin token)
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
	// CLAUDE_CODE_MAX_CONTEXT_TOKENS in the sandbox ("none": unset), from the tool call's output
	context string
}

var models modelLog

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
		return "answer", []map[string]any{{"type": "text", "text": "E2E-DONE " + token + ": the command printed E2E-OUT-" + token}}
	case strings.Contains(last, "E2E-WAKEUP "+token):
		return "wakeup", []map[string]any{{"type": "text", "text": "E2E-WOKE " + token}}
	case strings.Contains(last, "E2E-RUN "+token):
		cmd := "echo E2E-OUT-" + token + " | tee ~/artifacts/e2e-aviary.txt && echo E2E-CTX=${CLAUDE_CODE_MAX_CONTEXT_TOKENS:-none}. && curl -sS -H 'Content-Type: application/json' " +
			"-d '{\"delaySeconds\":60,\"prompt\":\"E2E-WAKEUP " + token + "\"}' \"$JARVIS_URL/api/sessions/$SESSION_ID/wakeup\""
		return "tool", []map[string]any{{"type": "tool_use", "id": "toolu_e2e_" + token, "name": "Bash",
			"input": map[string]any{"command": cmd, "description": "e2e: write the marker and arm the wakeup"}}}
	}
	return "other", []map[string]any{{"type": "text", "text": "ok"}}
}

func sse(w io.Writer, typ string, data any) {
	b, _ := json.Marshal(data)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", typ, b)
}

// sessionModel: the model the run's session starts on (E2E_MODEL): a Claude model by default; an OpenRouter one
// (aviary/z-ai/glm-5.3) sends the agent's turns to the stand-in OpenRouter, the title call still to the Claude one.
func sessionModel() string {
	if m := os.Getenv("E2E_MODEL"); m != "" {
		return m
	}
	return "aviary/claude-opus-5-5"
}

// openRouterKey: the OPENROUTER_API of the run's store, which only the stand-in OpenRouter takes.
const openRouterKey = "e2e-openrouter"

func serveModel(w http.ResponseWriter, req *http.Request) {
	openRouter := strings.HasPrefix(req.URL.Path, "/openrouter/")
	p := strings.TrimPrefix(strings.TrimPrefix(req.URL.Path, "/openrouter"), "/model")
	if openRouter && strings.HasSuffix(p, "/count_tokens") { // OpenRouter has no count_tokens (404, 2026-11-12)
		http.Error(w, `{"error":{"message":"Not Found","code":404}}`, 404)
		return
	}
	if strings.HasSuffix(p, "/count_tokens") {
		json.NewEncoder(w).Encode(map[string]int{"input_tokens": 10})
		return
	}
	if req.Method != http.MethodPost || !strings.HasSuffix(p, "/v1/messages") {
		http.Error(w, `{"type":"error","error":{"type":"not_found_error","message":"e2e stand-in"}}`, 404)
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
		// (aviary/src/machine.rs for_openrouter), and no thinking switched off (its hosts answer that 400).
		provider, _ := in["provider"].(map[string]any)
		order, _ := provider["order"].([]any)
		thinking, _ := in["thinking"].(map[string]any)
		if req.Header.Get("Authorization") != "Bearer "+openRouterKey || !strings.Contains(model, "/") || len(order) == 0 || thinking["type"] == "disabled" {
			log.Printf("openrouter: refused (auth %q, model %q, provider %v, thinking %v)", req.Header.Get("Authorization"), model, provider, thinking)
			http.Error(w, `{"type":"error","error":{"type":"invalid_request_error","message":"e2e stand-in OpenRouter"}}`, 400)
			return
		}
	} else if strings.Contains(model, "/") || req.Header.Get("Authorization") == "Bearer "+openRouterKey {
		log.Printf("model: refused, an OpenRouter call reached the Claude stand-in (model %q)", model)
		http.Error(w, `{"type":"error","error":{"type":"invalid_request_error","message":"e2e: not a Claude call"}}`, 400)
		return
	}
	// As Anthropic treats a subscription login: a call whose system prompt does not begin with Claude Code's identity
	// is refused 429 (2026-11-12: every title call, so no conversation had a title). Claude Code's own calls carry it;
	// the gateway puts it first on any other (the supervisor's title call).
	if sys := systemText(in); !openRouter && !strings.HasPrefix(req.UserAgent(), "claude-cli/") &&
		!strings.HasPrefix(sys, "You are Claude Code") && !strings.HasPrefix(sys, "You are a Claude agent") {
		log.Printf("model: refused, no Claude Code identity (user agent %q)", req.UserAgent())
		http.Error(w, `{"type":"error","error":{"type":"rate_limit_error","message":"Error"}}`, 429)
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
	id := "msg_e2e_" + hex.EncodeToString(randBytes(6))
	usage := map[string]int{"input_tokens": 10, "output_tokens": 5}
	if s, _ := in["stream"].(bool); !s {
		json.NewEncoder(w).Encode(map[string]any{"id": id, "type": "message", "role": "assistant", "model": in["model"],
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
	}
	return all
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

	step("the spawner's Fly token, sealed to it")
	var sd sig.Doc
	must("GET", os.Getenv("E2E_SPAWNER")+"/identity", nil, &sd)
	var sid sig.Identity
	json.Unmarshal([]byte(sd.Payload), &sid)
	tok, _ := json.Marshal(map[string]string{"FLY_API_TOKEN": os.Getenv("E2E_FLY_TOKEN")})
	ts, err := sig.SealTo(sid.AgreementKey, tok, "jarvis2/fly-token")
	if err != nil {
		log.Fatal(err)
	}
	must("POST", os.Getenv("E2E_SPAWNER")+"/fly-token", map[string]any{"sealed": ts}, nil)

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

	step("a session with the harness aviary and a first prompt; the phone signs its source")
	var created struct{ ID string }
	must("POST", router+"/api/sessions", map[string]any{"label": "e2e aviary", "harness": "aviary", "size": "small",
		"model": sessionModel(), "prompt": "E2E-RUN " + token}, &created)
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
	step("the conversation has its title, which the session's card gets")
	waitFor("the title in magpie", 3*time.Minute, func() bool {
		return strings.Contains(magpieText(), `"title":"E2E-TITLE `+token+`"`)
	})
	waitFor("the title on the session (the router's aiTitle)", 4*time.Minute, func() bool {
		s, _ := readSession(created.ID)
		return s != nil && s.AiTitle == "E2E-TITLE "+token
	})
	step("the wakeup the tool armed arrives as a later turn")
	waitFor("the wakeup's answer in magpie", 5*time.Minute, func() bool { return strings.Contains(magpieText(), "E2E-WOKE "+token) })
	models.Lock()
	log.Printf("the stand-in model answered %d calls: %v", len(models.calls), models.calls)
	// the agent's turns went where the session's model lives: an OpenRouter model's to OpenRouter, a Claude model's
	// to Anthropic; never the other
	wantOpenRouter := strings.Contains(strings.TrimPrefix(sessionModel(), "aviary/"), "/")
	// the model's own context window reaches Claude Code (the models route's per-model contextTokens → the
	// supervisor): GLM 5.3's 1M; a Claude model names none, so Claude Code keeps its own
	wantContext := "none"
	if wantOpenRouter {
		wantContext = "1000000"
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

	step("destroy: archived, its source burned")
	must("POST", router+"/api/sessions/"+created.ID+"/destroy?force=1", map[string]any{}, nil)
	waitFor("the destroy", 15*time.Minute, func() bool {
		s, burned := readSession(created.ID)
		return s == nil && burned
	})
	fmt.Println("e2e aviary: ok")
}
