package main

// A repo a session asks for lands in that session in the same approval (Deyao, 2026-10-15; DECISIONS 182): the
// request names the asking session; the finished deploy key files the add-store approval at once and names it to the
// phone, which signs it under the same Face ID.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// repoCore: a stand-in core that answers a finish with the key added and any succession with a challenge
func repoCore(t *testing.T, r *Router, repo string) *[]map[string]any {
	successions := &[]map[string]any{}
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		switch req.URL.Path {
		case "/deploy-keys/finish":
			p, _ := json.Marshal(`{"kind":"deploy-key-added","repo":"` + repo + `","sensitive":false,"fingerprint":"SHA256:abc"}`)
			w.Write([]byte(`{"payload":` + string(p) + `,"sig":"s"}`))
		case "/succession":
			var in map[string]any
			json.Unmarshal(b, &in)
			*successions = append(*successions, in)
			p, _ := json.Marshal(map[string]any{"kind": "challenge", "nonce": strings.Repeat("c", 64), "request": in})
			json.NewEncoder(w).Encode(map[string]string{"payload": string(p), "sig": "s"})
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(core.Close)
	r.core = &CoreClient{base: core.URL, http: http.DefaultClient}
	return successions
}

func approvalsFor(r *Router, sid string) []*Approval {
	out := []*Approval{}
	r.st.Do(func(d *persisted) {
		for _, a := range d.Approvals {
			if a.Session == sid {
				out = append(out, a)
			}
		}
	})
	return out
}

func TestARepoASessionAsksForLandsInItInTheSameApproval(t *testing.T) {
	r := newTestRouter(t)
	successions := repoCore(t, r, "DE0CH/claude-env")
	addSession(r, "sA", "started", "mA", false)
	addSession(r, "sB", "started", "mB", false)
	addSession(r, "sP", "paused", "", false)
	r.st.Do(func(d *persisted) { d.Sessions["sA"].Stores = []string{"default"} })
	mA, mB, mh := newTestMachine(r, "mA"), newTestMachine(r, "mB"), r.MachineHandler()

	code, out := mA.do(t, mh, "POST", "/m/api/requests/repo/add", `{"repo":"https://github.com/DE0CH/claude-env","explanation":"push the skill"}`)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	qA := out["id"].(string)
	it, ok := r.InboxItem(qA)
	if !ok || it.Session != "sA" || it.Open["options"].(map[string]any)["into"] != "sA" || it.Open["options"].(map[string]any)["store"] != "github-claude-env" {
		t.Fatalf("the request doesn't name the session the store goes to: %+v", it)
	}
	if it.Call.Args["into"] != "sA" {
		t.Fatalf("the recorded call: %+v", it.Call)
	}
	// a second session asks too; a session that opts out gets no store; a paused session's request stays without one
	_, out = mB.do(t, mh, "POST", "/m/api/requests/repo/add", `{"repo":"DE0CH/claude-env","explanation":"me too"}`)
	qB := out["id"].(string)
	_, out = mB.do(t, mh, "POST", "/m/api/requests/repo/add", `{"repo":"DE0CH/other","noStore":true,"explanation":"for a new session"}`)
	if q, _ := r.InboxItem(out["id"].(string)); q.Session != "" || q.Open["options"].(map[string]any)["into"] != nil {
		t.Fatalf("noStore: %+v", q)
	}
	r.st.Do(func(d *persisted) {
		d.Inbox["qP"] = &InboxRequest{ID: "qP", Kind: requestKindRepo, Params: RequestParams{Action: "add", Repo: "DE0CH/claude-env", Session: "sP"},
			Origin: Origin{Caller: Caller{Kind: "session", Session: "sP"}}, Key: "p", Expires: it.Created.Add(inboxTTL)}
	})

	// the phone finishes the key for sA's request: the answer names sA's add-store approval
	code, out = appDo(t, r, "POST", "/api/repos/key/finish?inbox="+qA, `{"pending":"p"}`, "cf-access-token", "x")
	if code != 200 || out["payload"] == nil || out["sig"] != "s" {
		t.Fatalf("%d %v", code, out)
	}
	f, _ := out["followups"].([]any)
	as := approvalsFor(r, "sA")
	if len(f) != 1 || len(as) != 1 || f[0] != as[0].ID {
		t.Fatalf("followups %v, approvals %+v", f, as)
	}
	a := as[0]
	if a.Kind != "add-store" || a.Options["store"] != "github-claude-env" || a.Machine != "mA" || a.Origin.Caller != (Caller{Kind: "session", Session: "sA"}) ||
		a.Origin.Signed != nil || a.Explanation != "push the skill" || a.Origin.Call.Args["for"] != qA {
		t.Fatalf("%+v %+v", a, a.Origin)
	}
	// the challenge adds exactly that store to sA's machine
	var ch map[string]any
	for _, s := range *successions {
		if s["machine"] == "mA" {
			ch = s
		}
	}
	if ch == nil || strings.Join(toStrings(ch["stores"]), ",") != "default,github-claude-env" {
		t.Fatalf("successions %v", *successions)
	}
	// sB's waits in the Inbox on its own; the paused session's gets none; every request for the repo is answered
	if bs := approvalsFor(r, "sB"); len(bs) != 1 || bs[0].Kind != "add-store" {
		t.Fatalf("sB %+v", bs)
	}
	if ps := approvalsFor(r, "sP"); len(ps) != 0 {
		t.Fatalf("a paused session got an approval: %+v", ps)
	}
	for _, q := range []string{qA, qB, "qP"} {
		if _, ok := r.InboxItem(q); ok {
			t.Fatalf("request %s still waits", q)
		}
	}
	// a session that holds the store already (a key rotated) gets no add-store
	r.st.Do(func(d *persisted) {
		d.Approvals = map[string]*Approval{}
		d.Sessions["sA"].Stores = []string{"default", "github-claude-env"}
	})
	_, out = mA.do(t, mh, "POST", "/m/api/requests/repo/add", `{"repo":"DE0CH/claude-env","explanation":"rotate"}`)
	_, out = appDo(t, r, "POST", "/api/repos/key/finish?inbox="+out["id"].(string), `{"pending":"p"}`, "cf-access-token", "x")
	if out["followups"] != nil || len(approvalsFor(r, "sA")) != 0 {
		t.Fatalf("%v", out)
	}
}

func TestARepoInABatchNamesTheAskingSession(t *testing.T) {
	r := newTestRouter(t)
	repoCore(t, r, "DE0CH/claude-env")
	addSession(r, "sA", "started", "mA", false)
	mA, mh := newTestMachine(r, "mA"), r.MachineHandler()
	code, out := mA.do(t, mh, "POST", "/m/api/requests/batch", `{"summary":"work","items":[{"intent":"repo/add","repo":"DE0CH/claude-env"},{"intent":"grant","holder":"status","minutes":5}]}`)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	id := out["items"].([]any)[0].(map[string]any)["id"].(string)
	if it, _ := r.InboxItem(id); it.Session != "sA" || it.Batch == "" {
		t.Fatalf("%+v", it)
	}
	// Deyao's own add (Settings → Repos, the web page) names no session
	_, out = appDo(t, r, "POST", "/api/requests/repo/add", `{"repo":"DE0CH/x"}`, "cf-access-token", "x")
	if it, _ := r.InboxItem(out["id"].(string)); it.Session != "" {
		t.Fatalf("%+v", it)
	}
}

// A repo that has its deploy key already (Deyao, 2026-11-17: "sessions keep asking me to make a new deploy key even
// when one already exists"): a session asking for it needs the key's store, so the ask is the add-store of that
// store, alone or in a batch, and no new key is asked for. A session that holds the store asks for a new key (a
// rotation), as does anyone naming no session.
func TestARepoThatHasItsKeyIsAnAddStoreNotANewKey(t *testing.T) {
	r := newTestRouter(t)
	successions := repoCore(t, r, "DE0CH/claude-env")
	addSession(r, "sA", "started", "mA", false)
	addSession(r, "sH", "started", "mH", false)
	r.st.Do(func(d *persisted) {
		d.Sessions["sA"].Stores = []string{"default"}
		d.Sessions["sH"].Stores = []string{"github-claude-env"}
	})
	r.updateRepos(func([]RepoEntry) []RepoEntry {
		e, n := repoEntry("DE0CH/claude-env"), repoEntry("DE0CH/nokey")
		e.Fingerprint = "SHA256:abc"
		return []RepoEntry{e, n}
	})
	mA, mH, mh := newTestMachine(r, "mA"), newTestMachine(r, "mH"), r.MachineHandler()
	requests := func() int {
		n := 0
		r.st.Do(func(d *persisted) { n = len(d.Inbox) })
		return n
	}

	// the answer's id is the add-store's own (what its outcome is filed under, what jarvis-request add-repo waits on)
	code, out := mA.do(t, mh, "POST", "/m/api/requests/repo/add", `{"repo":"https://github.com/de0ch/claude-env.git","explanation":"push the skill"}`)
	as := approvalsFor(r, "sA")
	if code != 200 || out["existing"] != true || out["store"] != "github-claude-env" || requests() != 0 || len(as) != 1 || out["id"] != as[0].ID {
		t.Fatalf("%d %v, %d requests, approvals %+v", code, out, requests(), as)
	}
	a := as[0]
	if a.Kind != "add-store" || a.Options["store"] != "github-claude-env" || a.Machine != "mA" || a.Explanation != "push the skill" ||
		a.Origin.Caller != (Caller{Kind: "session", Session: "sA"}) || !strings.EqualFold(a.Origin.Call.Args["repo"].(string), "DE0CH/claude-env") || out["approval"] != a.ID {
		t.Fatalf("%+v %+v", a, a.Origin)
	}
	if len(*successions) != 1 || strings.Join(toStrings((*successions)[0]["stores"]), ",") != "default,github-claude-env" {
		t.Fatalf("successions %v", *successions)
	}
	// in a batch: the item is the add-store
	r.st.Do(func(d *persisted) { d.Approvals = map[string]*Approval{} })
	code, out = mA.do(t, mh, "POST", "/m/api/requests/batch", `{"summary":"work","items":[{"intent":"repo/add","repo":"DE0CH/claude-env"}]}`)
	as = approvalsFor(r, "sA")
	if code != 200 || requests() != 0 || len(as) != 1 || as[0].Kind != "add-store" || as[0].Options["store"] != "github-claude-env" || as[0].Batch == "" {
		t.Fatalf("%d %v, %d requests, approvals %+v", code, out, requests(), as)
	}
	// still a new key: a repo with none, a session that holds the store (a rotation), an ask without the store
	for i, c := range []struct {
		m    testMachine
		body string
	}{
		{mA, `{"repo":"DE0CH/nokey","explanation":"x"}`},
		{mA, `{"repo":"DE0CH/unlisted","explanation":"x"}`},
		{mH, `{"repo":"DE0CH/claude-env","explanation":"rotate"}`},
		{mA, `{"repo":"DE0CH/claude-env","noStore":true,"explanation":"x"}`},
	} {
		code, out = c.m.do(t, mh, "POST", "/m/api/requests/repo/add", c.body)
		if code != 200 || out["id"] == nil || requests() != i+1 {
			t.Fatalf("%s: %d %v (%d requests)", c.body, code, out, requests())
		}
	}
	// Deyao's own add makes a key
	if _, out = appDo(t, r, "POST", "/api/requests/repo/add", `{"repo":"DE0CH/claude-env"}`, "cf-access-token", "x"); out["id"] == nil {
		t.Fatalf("%v", out)
	}
}

func toStrings(v any) []string {
	out := []string{}
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
