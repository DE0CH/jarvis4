package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// storeCore: a core with stores made of keys (core/keys.go)
type storeCore struct {
	mu     sync.Mutex
	key    key
	writes []map[string]any
	fail   int // answer write-key with this status
}

func (c *storeCore) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, _ := io.ReadAll(req.Body)
	switch req.URL.Path {
	case "/identity":
		writeJSON(w, 200, map[string]any{"signingKey": c.key.pub(), "state": c.key.doc(map[string]any{"kind": "core-state", "master": "M", "phone": map[string]string{"agreementKey": "P"}})})
	case "/store-key":
		writeJSON(w, 200, c.key.doc(map[string]any{"kind": "store-key", "phone": "P", "storeKey": "C"}))
	case "/stores":
		rows := []map[string]any{
			{"name": "default", "sensitive": false, "empty": false, "unlocked": true},
			{"name": "fresh", "sensitive": false, "empty": true, "unlocked": false},
			{"name": "github-claude-env", "sensitive": false, "empty": false, "unlocked": false},
		}
		rows[0]["keys"] = []map[string]any{{"name": "EXA_API", "at": "t1", "writer": map[string]string{"by": "machine", "machine": "mA", "line": "LsA"}},
			{"name": "OPENROUTER_API", "at": "t0", "writer": map[string]string{"by": "setup"}}}
		rows[1]["keys"] = []map[string]any{}
		rows[2]["keys"] = []map[string]any{{"name": "GITHUB_DEPLOY_KEY_DE0CH_CLAUDE_ENV", "writer": map[string]string{"by": "core"}}}
		writeJSON(w, 200, c.key.doc(map[string]any{"kind": "stores", "nonce": "n", "stores": rows}))
	case "/stores/write-key":
		if c.fail != 0 {
			writeJSON(w, c.fail, c.key.doc(map[string]string{"error": "refused"}))
			return
		}
		var in map[string]any
		json.Unmarshal(b, &in)
		c.writes = append(c.writes, in)
		writeJSON(w, 200, c.key.doc(map[string]any{"kind": "key-written", "store": in["store"], "key": in["key"]}))
	default:
		http.NotFound(w, req)
	}
}

// fakeBucket: the backup bucket (PUT and GET of objects), recording each version
type fakeBucket struct {
	mu   sync.Mutex
	puts []string
	objs map[string][]byte
	down bool
}

func (b *fakeBucket) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.down {
		w.WriteHeader(503)
		return
	}
	key := strings.TrimPrefix(req.URL.Path, "/jarvis2-backup-de0ch/")
	switch req.Method {
	case "PUT":
		body, _ := io.ReadAll(req.Body)
		b.puts = append(b.puts, key)
		b.objs[key] = body
	case "GET":
		w.Write(b.objs[key])
	}
}

func storeRouter(t *testing.T) (*Router, *storeCore, *fakeBucket) {
	t.Helper()
	r := newTestRouter(t)
	c := &storeCore{key: newTestKey()}
	cs := httptest.NewServer(c)
	t.Cleanup(cs.Close)
	r.core = &CoreClient{base: cs.URL, http: http.DefaultClient}
	fb := &fakeBucket{objs: map[string][]byte{}}
	bs := httptest.NewServer(fb)
	t.Cleanup(bs.Close)
	t.Setenv("BACKUP_ENDPOINT", bs.URL)
	t.Setenv("BACKUP_READ_ACCESS_KEY", "ak")
	t.Setenv("BACKUP_READ_SECRET_KEY", "sk")
	return r, c, fb
}

func byName(rows []any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, x := range rows {
		m := x.(map[string]any)
		out[m["name"].(string)] = m
	}
	return out
}

func keyNames(row map[string]any) []string {
	out := []string{}
	ks, _ := row["keys"].([]any) // names: the shape every session image reads
	for _, k := range ks {
		out = append(out, k.(string))
	}
	return out
}

// the core's keys with their writers (a machine's line as the session that wrote it) and the explanations
func TestStoresListKeysWritersAndExplanations(t *testing.T) {
	r, _, _ := storeRouter(t)
	addSession(r, "sA", "started", "mA", false)
	if code, out := appDo(t, r, "POST", "/setup/store-docs", `{"store":"default","about":"everyday keys","keys":{"EXA_API":"Exa search","OPENROUTER_API":"OpenRouter, every model"}}`); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := appDo(t, r, "PUT", "/api/stores/default/docs", `{"keys":{"EXA_API":"Exa web search (the exa skill)"}}`); code != 200 {
		t.Fatal(code)
	}
	long := strings.Repeat("a", 1500) // longer than an Inbox explanation, within an explanation of a key
	if code, out := appDo(t, r, "POST", "/setup/store-docs", `{"store":"shopping","about":"`+long+`"}`); code != 200 {
		t.Fatalf("a 1500-character about text: %d %v", code, out)
	}
	if code, _ := appDo(t, r, "POST", "/setup/store-docs", `{"store":"shopping","about":"`+long+long+`"}`); code != 400 {
		t.Fatal("a 3000-character about text was taken")
	}
	if code, _ := appDo(t, r, "PUT", "/api/stores/default/docs", `{"keys":{"bad name":"x"}}`); code != 400 {
		t.Fatal("a bad key name was documented")
	}
	check := func(code int, out map[string]any) {
		t.Helper()
		if code != 200 || out["signed"] == nil {
			t.Fatalf("%d %v", code, out)
		}
		s := byName(out["stores"].([]any))
		d := s["default"]
		if strings.Join(keyNames(d), ",") != "EXA_API,OPENROUTER_API" {
			t.Fatalf("default's names: %v", d["keys"])
		}
		ks := d["keyInfo"].([]any)
		exa := ks[0].(map[string]any)
		w := exa["writer"].(map[string]any)
		if d["about"] != "everyday keys" || d["keysFrom"] != "core" || exa["explanation"] != "Exa web search (the exa skill)" ||
			w["by"] != "machine" || w["session"] != "sA" || w["sessionLabel"] != "label sA" {
			t.Fatalf("default: %v", d)
		}
		if ks[1].(map[string]any)["explanation"] != "OpenRouter, every model" {
			t.Fatalf("default: %v", d)
		}
		if len(keyNames(s["fresh"])) != 0 || s["fresh"]["keys"] == nil {
			t.Fatalf("fresh: %v", s["fresh"])
		}
	}
	check(appDo(t, r, "GET", "/api/stores", ""))
	check(appDo(t, r, "GET", "/setup/stores/keys", ""))
	m := newTestMachine(r, "mA")
	check(m.do(t, r.MachineHandler(), "GET", "/m/stores", "")) // every session sees every store
}

func writeBody(expl string) string {
	b, _ := json.Marshal(map[string]any{"wrapped": map[string]string{"e": "E", "wrapped": "W"}, "data": "D",
		"backup": map[string]string{"e": "BE", "data": "BD"}, "backupSha256": backupSha("BE", "BD"), "sig": "S", "explanation": expl})
	return string(b)
}

// a running session writes one key: the backup first, then the core (with the machine's newest cert), the explanation
// kept, and every running session holding the store asked to refresh (one batch)
func TestASessionWritesAKey(t *testing.T) {
	r, c, fb := storeRouter(t)
	addSession(r, "sA", "started", "mA", false)
	addSession(r, "sB", "started", "mB", false)
	addSession(r, "sC", "started", "mC", false)
	addSession(r, "sP", "paused", "", false)
	r.st.Do(func(d *persisted) {
		d.Sessions["sB"].Stores = []string{"default", "gmail"}
		d.Sessions["sC"].Stores = []string{"default"}
		d.Sessions["sP"].Stores = []string{"default"}
	})
	m := newTestMachine(r, "mA")
	h := r.MachineHandler()
	if code, out := m.do(t, h, "POST", "/m/stores/default/keys/NEW_KEY", writeBody("")); code != 400 || !strings.Contains(out["error"].(string), "explanation") {
		t.Fatalf("a new key without an explanation: %d %v", code, out)
	}
	bad := strings.Replace(writeBody("x"), backupSha("BE", "BD"), backupSha("BE", "other"), 1)
	if code, _ := m.do(t, h, "POST", "/m/stores/default/keys/NEW_KEY", bad); code != 400 {
		t.Fatal("a backup that isn't the one signed was taken")
	}
	for _, store := range []string{"core", "github-deploy-keys"} {
		if code, _ := m.do(t, h, "POST", "/m/stores/"+store+"/keys/K", writeBody("x")); code != 403 {
			t.Fatalf("%s written", store)
		}
	}
	if len(fb.puts) != 0 || len(c.writes) != 0 {
		t.Fatal("a refused write reached the bucket or the core")
	}
	code, out := m.do(t, h, "POST", "/m/stores/default/keys/NEW_KEY", writeBody("The new API's key"))
	if code != 200 || out["ok"] != true {
		t.Fatalf("%d %v", code, out)
	}
	if len(fb.puts) != 1 || fb.puts[0] != "keys/default/NEW_KEY.json" || len(c.writes) != 1 {
		t.Fatalf("puts %v writes %v", fb.puts, c.writes)
	}
	var obj map[string]any
	json.Unmarshal(fb.objs["keys/default/NEW_KEY.json"], &obj)
	w := obj["writer"].(map[string]any)
	if obj["kind"] != "key-backup" || obj["explanation"] != "The new API's key" || w["by"] != "machine" || w["cert"] == nil || obj["core"] == nil {
		t.Fatalf("backup %v", obj)
	}
	if c.writes[0]["writer"] != "machine" || c.writes[0]["cert"] == nil || c.writes[0]["backupSha256"] != backupSha("BE", "BD") {
		t.Fatalf("core got %v", c.writes[0])
	}
	if r.readStoreDocs()["default"].Keys["NEW_KEY"] != "The new API's key" {
		t.Fatal("the explanation wasn't kept")
	}
	// sB and sC hold default and run: no request goes to Deyao for them (they get it at their next pull, Deyao 2026-10-22)
	if _, ok := out["refreshAsked"]; ok || len(r.Inbox()) != 0 || len(r.InboxBatches(nil)) != 0 {
		t.Fatalf("a write filed a request: %v inbox %+v", out, r.Inbox())
	}
	// a documented key needs no explanation again
	if code, out := m.do(t, h, "POST", "/m/stores/default/keys/NEW_KEY", writeBody("")); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	// a paused session writes nothing
	addSession(r, "sQ", "paused", "mQ", false)
	mq := newTestMachine(r, "mQ")
	if code, _ := mq.do(t, h, "POST", "/m/stores/default/keys/K", writeBody("x")); code != 403 {
		t.Fatal("a session that isn't running wrote")
	}
}

// no backup, no write: the bucket down leaves the core untouched; the core's refusal comes back as it is
func TestNoKeyWithoutItsBackup(t *testing.T) {
	r, c, fb := storeRouter(t)
	addSession(r, "sA", "started", "mA", false)
	m := newTestMachine(r, "mA")
	fb.down = true
	if code, _ := m.do(t, r.MachineHandler(), "POST", "/m/stores/default/keys/K", writeBody("x")); code == 200 || len(c.writes) != 0 {
		t.Fatal("a key was written with its backup failing")
	}
	fb.down = false
	c.fail = 403
	if code, _ := m.do(t, r.MachineHandler(), "POST", "/m/stores/default/keys/K", writeBody("x")); code != 403 {
		t.Fatalf("the core's refusal came back as %d", code)
	}
}

// the setup session writes the same way, its own signature passed on
func TestTheSetupSessionWritesAKey(t *testing.T) {
	r, c, _ := storeRouter(t)
	if code, out := appDo(t, r, "POST", "/setup/stores/infra/keys/K", writeBody("a key")); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if c.writes[0]["writer"] != "setup" || c.writes[0]["cert"] != nil {
		t.Fatalf("core got %v", c.writes[0])
	}
	// the deploy-key token (RUNBOOK: setup.py write github-deploy-keys …; the replica writes its throwaway PAT): the
	// setup session writes it, as the core allows; never the core's own store
	if code, out := appDo(t, r, "POST", "/setup/stores/github-deploy-keys/keys/GITHUB_DEPLOY_KEYS_TOKEN", writeBody("the PAT")); code != 200 {
		t.Fatalf("the setup session's deploy-key token write: %d %v", code, out)
	}
	if c.writes[1]["store"] != "github-deploy-keys" || c.writes[1]["writer"] != "setup" {
		t.Fatalf("core got %v", c.writes[1])
	}
	if code, _ := appDo(t, r, "POST", "/setup/stores/core/keys/FLY_API_TOKEN", writeBody("x")); code != 403 {
		t.Fatal("the core's own store was written key by key")
	}
	if code, out := appDo(t, r, "GET", "/setup/store-key", ""); code != 200 || out["identity"] == nil || out["storeKey"] == nil {
		t.Fatalf("%d %v", code, out)
	}
}

// the phone's unlock for a running, booted machine's cert makes that machine pull again
func TestAnUnlockPullsAgain(t *testing.T) {
	r, c, _ := storeRouter(t)
	addSession(r, "sA", "started", "mA", false)
	payload, _ := json.Marshal(map[string]any{"line": "LsA", "nonce": "N1"})
	r.st.Do(func(d *persisted) {
		d.Sessions["sA"].Cert = &Doc{Payload: string(payload)}
		d.Sessions["sA"].Booted = "mA"
	})
	ans, _ := json.Marshal(c.key.doc(map[string]any{"kind": "unlocked", "for": "N1", "store": "yyc"}))
	r.unlockArrived(ans)
	if cmd, ok := waitCmd(r, "mA", time.Second); !ok {
		t.Fatal("the machine wasn't told to pull again")
	} else if cmd != "refresh-secrets" {
		t.Fatalf("got %s", cmd)
	}
	other, _ := json.Marshal(c.key.doc(map[string]any{"kind": "unlocked", "for": "N2", "store": "yyc"}))
	r.unlockArrived(other)
	if cmd, ok := takeCmd(r, "mA"); ok {
		t.Fatalf("an unlock for another cert sent %s", cmd)
	}
}
