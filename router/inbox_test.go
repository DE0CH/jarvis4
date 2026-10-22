package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func inboxDo(t *testing.T, r *Router, method, target, body string, app bool) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if app {
		req.Header.Set("cf-access-token", "x")
	}
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)
	out := map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestInboxFromEachCaller(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	addSession(r, "sB", "started", "mB", false)
	m := newTestMachine(r, "mA")
	mh := r.MachineHandler()

	// a session: a repo add, with its explanation; the caller comes from the machine key, not from the body
	code, out := m.do(t, mh, "POST", "/m/api/requests/repo/add", `{"repo": "https://github.com/DE0CH/claude-env.git", "explanation": "I need to push the skill.‮", "caller": "setup"}`)
	if code != 200 || out["duplicate"] != false {
		t.Fatalf("%d %v", code, out)
	}
	id := out["id"].(string)
	// the same again: one request
	if code, out := m.do(t, mh, "POST", "/m/api/requests/repo/add", `{"repo": "DE0CH/claude-env", "explanation": "again"}`); code != 200 || out["id"] != id || out["duplicate"] != true {
		t.Fatalf("dedup: %d %v", code, out)
	}
	// a session may ask anything for any session (its actions could already; each still waits for Deyao)
	for _, c := range []struct{ path, body string }{
		{"/m/api/requests/repo/remove", `{"repo": "DE0CH/claude-env", "explanation": "x"}`},
		{"/m/api/requests/grant", `{"session": "sB", "holder": "terminal", "explanation": "x"}`},
		{"/m/api/requests/unlock", `{"session": "sB", "explanation": "x"}`},
	} {
		code, out := m.do(t, mh, "POST", c.path, c.body)
		if code != 200 {
			t.Fatalf("%s: %d %v", c.path, code, out)
		}
		r.DenyRequest(out["id"].(string))
	}
	if code, _ := m.do(t, mh, "POST", "/m/api/requests/grant", `{"holder": "terminal"}`); code != 400 {
		t.Fatalf("no explanation: %d", code)
	}
	// its own grant, the session left out of the body
	if code, out := m.do(t, mh, "POST", "/m/api/requests/grant", `{"holder": "terminal", "minutes": 5, "explanation": "let me see the screen"}`); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := m.do(t, mh, "POST", "/m/api/requests/grant", `{"holder": "nope", "explanation": "x"}`); code != 400 {
		t.Fatalf("unknown holder: %d", code)
	}

	// the web page (no device token) and the app
	if code, out := inboxDo(t, r, "POST", "/api/requests/unlock", `{"session": "sB"}`, false); code != 200 {
		t.Fatalf("web: %d %v", code, out)
	}
	if code, out := inboxDo(t, r, "POST", "/api/requests/repo/remove", `{"repo": "DE0CH/china-train", "explanation": "done with it"}`, true); code != 200 {
		t.Fatalf("app: %d %v", code, out)
	}

	items := r.Inbox()
	if len(items) != 4 {
		t.Fatalf("%d items: %+v", len(items), items)
	}
	byKind := map[string]InboxItem{}
	for _, it := range items {
		byKind[it.Kind+" "+it.Params.Action] = it
	}
	repo := byKind["repo-key add"]
	if repo.Caller != (Caller{Kind: "session", Session: "sA"}) || !strings.HasPrefix(repo.CallerText, "session “label sA”") ||
		repo.Call.Path != "/api/requests/repo/add" || repo.Call.Args["repo"] != "DE0CH/claude-env" || repo.Explanation != "I need to push the skill." {
		t.Fatalf("%+v", repo)
	}
	if o := repo.Open["options"].(map[string]any); repo.Open["kind"] != "repo-key" || o["repo"] != "DE0CH/claude-env" || o["action"] != "add" || o["inboxId"] != repo.ID {
		t.Fatalf("open: %+v", repo.Open)
	}
	if g := byKind["grant "]; g.Open["kind"] != "grant" || g.Open["options"].(map[string]any)["minutes"] != 5 || g.Open["options"].(map[string]any)["sessionId"] != "sA" {
		t.Fatalf("grant: %+v", g)
	}
	if u := byKind["unlock "]; u.CallerText != "Deyao, from the web page" || u.Explanation != "" {
		t.Fatalf("unlock: %+v", u)
	}
	if rm := byKind["repo-key remove"]; rm.CallerText != "Deyao, from the Jarvis 4 app" {
		t.Fatalf("remove: %+v", rm)
	}
	// a session lists only its own
	if code, out := m.do(t, mh, "GET", "/m/api/requests", ""); code != 200 || len(out["requests"].([]any)) != 2 {
		t.Fatalf("%d %v", code, out)
	}

	// Deny drops it; done drops it; the core answer for the repo drops the add
	if code, _ := inboxDo(t, r, "DELETE", "/api/requests/"+byKind["unlock "].ID, "", true); code != 200 {
		t.Fatal(code)
	}
	inboxDo(t, r, "POST", "/api/requests/"+byKind["grant "].ID+"/done", "", true)
	r.applyKeyAnswer(keyAnswer{Kind: "deploy-key-added", Repo: "DE0CH/claude-env"}, nil)
	if items := r.Inbox(); len(items) != 1 || items[0].Kind != "repo-key" || items[0].Params.Action != "remove" {
		t.Fatalf("%+v", items)
	}
	// a destroyed session's requests go; expired ones go
	r.st.Do(func(d *persisted) {
		for _, q := range d.Inbox {
			q.Expires = time.Now().Add(-time.Second)
		}
	})
	if items := r.Inbox(); len(items) != 0 {
		t.Fatalf("expired: %+v", items)
	}
}

func TestInboxGrantRuleAndLimits(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	q, _, err := r.FileRequest(requestKindGrant, RequestParams{Session: "sA", Holder: "archive", Days: 30}, "", Origin{Caller: Caller{Kind: "web"}})
	if err != nil || q.Params.Days != 30 || q.Params.Minutes != 0 {
		t.Fatalf("%+v %v", q, err)
	}
	it, _ := r.InboxItem(q.ID)
	o := it.Open["options"].(map[string]any)
	until, _ := time.Parse(time.RFC3339, o["until"].(string))
	if o["grantKind"] != "rule" || until.Sub(time.Now()) < 29*24*time.Hour {
		t.Fatalf("%+v", o)
	}
	for _, p := range []RequestParams{{Session: "sA", Holder: "terminal", Minutes: 11}, {Session: "sA", Holder: "terminal", Days: 400},
		{Session: "sA", Holder: "terminal", Days: 3, Minutes: 3}, {Session: "nope", Holder: "terminal"}} {
		if _, _, err := r.FileRequest(requestKindGrant, p, "x", Origin{Caller: Caller{Kind: "setup"}}); err == nil {
			t.Fatalf("%+v should be refused", p)
		}
	}
	// a setup request needs words; at most requestPerCaller pending per caller
	if _, _, err := r.FileRequest(requestKindRepo, RequestParams{Action: "add", Repo: "a/b"}, "  ", Origin{Caller: Caller{Kind: "setup"}}); err == nil {
		t.Fatal("setup without an explanation")
	}
	for i := 0; i < requestPerCaller; i++ {
		if _, _, err := r.FileRequest(requestKindRepo, RequestParams{Action: "add", Repo: "a/r" + string(rune('a'+i))}, "why", Origin{Caller: Caller{Kind: "setup"}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := r.FileRequest(requestKindRepo, RequestParams{Action: "add", Repo: "a/zz"}, "why", Origin{Caller: Caller{Kind: "setup"}}); err == nil {
		t.Fatal("over the limit")
	}
	// a grant the phone stored answers the request
	r.st.Do(func(d *persisted) { d.Inbox[q.ID].Params.Holder = "terminal" })
}

func TestCleanExplanation(t *testing.T) {
	for in, want := range map[string]string{
		"  plain  ":             "plain",
		"a\r\n\r\n\r\nb":        "a\n\nb",
		"tab\there\x1b[31mred​": "tab here[31mred",
		"<b>kept as text</b>":   "<b>kept as text</b>",
		"rtl ‮gnp.exe‬ trick":   "rtl gnp.exe trick",
	} {
		if got, err := cleanExplanation(in, false); err != nil || got != want {
			t.Fatalf("%q → %q %v", in, got, err)
		}
	}
	if _, err := cleanExplanation(strings.Repeat("x", explanationMax+1), false); err == nil {
		t.Fatal("too long")
	}
	if _, err := cleanExplanation(strings.Repeat("x\n", explanationLines+1), false); err == nil {
		t.Fatal("too many lines")
	}
	if _, err := cleanExplanation("", true); err == nil {
		t.Fatal("required")
	}
}

// every intent endpoint makes a request the app can open: a kind the app lists and the shell has a page for
func TestEveryIntentOpensAPage(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	pages := map[string]bool{"repo-key": true, "grant": true, "unlock": true, "approval": true, "restore": true}
	for intent, mk := range intents {
		kind, p := mk(requestIn{Repo: "DE0CH/x", Session: "sA", Holder: "terminal", Store: "default", Seq: 3})
		q, _, err := r.FileRequest(kind, p, "why", Origin{Caller: Caller{Kind: "setup"}, Call: APICall{Method: "POST", Path: "/setup/requests/" + intent}})
		if err != nil {
			t.Fatalf("%s: %v", intent, err)
		}
		it, ok := r.InboxItem(q.ID)
		if !ok || !pages[it.Open["kind"].(string)] || it.Open["options"].(map[string]any)["inboxId"] != q.ID || it.CallerText == "" || it.Call.Path == "" {
			t.Fatalf("%s: %+v", intent, it)
		}
	}
}

func TestApprovalsInTheInboxWithTheirCaller(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "paused", "", false)
	r.noteOrigin("sA", Origin{Caller: Caller{Kind: "web"}, Call: APICall{Method: "POST", Path: "/api/sessions/sA/resume", Args: map[string]any{"upgrade": true}}})
	r.addApproval(&Approval{Kind: "resume-upgrade", Session: "sA"})
	r.addApproval(&Approval{Kind: "add-store", Session: "sA", Origin: &Origin{Caller: Caller{Kind: "session", Session: "sA"}}, Explanation: "need gmail"})
	items := r.Inbox()
	if len(items) != 2 {
		t.Fatalf("%+v", items)
	}
	for _, it := range items {
		if !it.Approval || it.Open["kind"] != "approval" || it.Open["options"].(map[string]any)["approvalId"] != it.ID {
			t.Fatalf("%+v", it)
		}
		switch it.Kind {
		case "resume-upgrade":
			if it.CallerText != "Deyao, from the web page" || it.Call.Path != "/api/sessions/sA/resume" {
				t.Fatalf("%+v", it)
			}
		case "add-store":
			if it.Explanation != "need gmail" || !strings.HasPrefix(it.CallerText, "session ") {
				t.Fatalf("%+v", it)
			}
		}
	}
	// Deny on an approval rejects it: the resume stays paused
	if err := r.DenyRequest(items[0].ID); err != nil {
		t.Fatal(err)
	}
	if len(r.Inbox()) != 1 {
		t.Fatal("not dropped")
	}
}

func TestSetupSessionsAndRequests(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "started", "mA", false)
	code, out := inboxDo(t, r, "GET", "/setup/sessions", "", false)
	if code != 200 || out["sessions"].([]any)[0].(map[string]any)["machineId"] != "mA" {
		t.Fatalf("%d %v", code, out)
	}
	code, out = inboxDo(t, r, "POST", "/setup/requests/repo/add", `{"repo": "DE0CH/claude-env", "explanation": "for the skill"}`, false)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	it, _ := r.InboxItem(out["id"].(string))
	if it.CallerText != "Claude (setup session)" || it.Call.Path != "/setup/requests/repo/add" {
		t.Fatalf("%+v", it)
	}
}

// a session's actions (its machine key): resume only a paused session, deny an Inbox item, propose a session and
// file a request — each named as that session's actions in the Inbox; nothing once the session stops running
func TestActionsKey(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sR", "started", "mR", false)
	addSession(r, "sP", "paused", "", false)
	m, mh := newTestMachine(r, "mR"), r.MachineHandler()
	// a running session's resume: already what was asked, nothing done
	if code, out := m.do(t, mh, "POST", "/m/api/actions/sessions/sR/resume", ""); code != 200 {
		t.Fatalf("a running session's resume: %d %v", code, out)
	}
	r.st.Do(func(d *persisted) {
		if s := d.Sessions["sR"]; s.State != "started" || s.MachineID != "mR" {
			t.Fatalf("the running session was touched: %+v", s)
		}
	})
	if code, out := m.do(t, mh, "GET", "/m/api/actions/sessions", ""); code != 200 || len(out["sessions"].([]any)) != 2 {
		t.Fatalf("%d %v", code, out)
	}
	code, out := m.do(t, mh, "POST", "/m/api/actions/requests/unlock", `{"session": "sP", "explanation": "it waits for a store"}`)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	id := out["id"].(string)
	if it, _ := r.InboxItem(id); it.CallerText != "the actions of session “label sR” (sR)" || it.Call.Path != "/api/actions/requests/unlock" {
		t.Fatalf("%+v", it)
	}
	if code, out := m.do(t, mh, "POST", "/m/api/actions/requests/"+id+"/deny", ""); code != 200 || len(r.Inbox()) != 0 {
		t.Fatalf("not denied: %d %v", code, out)
	}
	if code, out := m.do(t, mh, "POST", "/m/api/actions/sessions", `{"label": "x", "explanation": "a test"}`); code != 400 {
		t.Fatalf("a proposal with no prompt: %d %v", code, out)
	}
	// the old shared key's path is gone (only the web page's fallback answers it)
	if _, out := inboxDo(t, r, "GET", "/actions/sessions", "", false); out["sessions"] != nil {
		t.Fatalf("/actions still served: %v", out)
	}
	// pausing ends the key
	r.st.Do(func(d *persisted) { d.Sessions["sR"].State = "pausing" })
	if code, out := m.do(t, mh, "GET", "/m/api/actions/sessions", ""); code != 403 {
		t.Fatalf("a pausing session's actions still work: %d %v", code, out)
	}
}

func TestInboxItemsGoAfterTenMinutes(t *testing.T) {
	r := newTestRouter(t)
	addSession(r, "sA", "paused", "", false)
	addSession(r, "sN", "pending", "", false)
	r.addApproval(&Approval{Kind: "add-store", Session: "sA"})
	r.addApproval(&Approval{Kind: "new-session", Session: "sN"})
	q, _, err := r.FileRequest("unlock", RequestParams{Session: "sA"}, "need it", Origin{Caller: Caller{Kind: "session", Session: "sA"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := q.Expires.Sub(q.Created); got != 10*time.Minute {
		t.Fatalf("request lives %s", got)
	}
	if len(r.Inbox()) != 3 {
		t.Fatalf("%+v", r.Inbox())
	}
	// eleven minutes on: every item is gone; Deyao's own new session is kept as failed, so Start again asks again
	later := time.Now().UTC().Add(11 * time.Minute)
	r.expireApprovals(later)
	r.st.Do(func(d *persisted) {
		pruneRequests(d, later)
		if len(d.Approvals) != 0 || len(d.Inbox) != 0 || d.Sessions["sN"] == nil || d.Sessions["sN"].State != "failed" || d.Sessions["sA"] == nil {
			t.Fatalf("approvals %d inbox %d sN %v", len(d.Approvals), len(d.Inbox), d.Sessions["sN"])
		}
	})
	if _, _, err := r.Respond("nope", "sig"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatal(err)
	}
}
