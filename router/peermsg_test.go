package main

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPeerDirection(t *testing.T) {
	s := func(mode string, stores ...string) *Session { return &Session{PermissionMode: mode, Stores: stores} }
	for _, c := range []struct {
		from, to *Session
		want     string
	}{
		{s("auto", "default", "infra"), s("auto", "infra", "default"), "equal"},
		{s("auto", "default", "infra"), s("auto", "default"), "downward"},
		{s("bypass", "default"), s("auto", "default"), "downward"},               // a less permissive receiver
		{s("auto", "default"), s("auto", "default", "infra"), "upward"},          // a store the sender lacks
		{s("auto", "default", "infra"), s("bypass", "default"), "upward"},        // bypass while the sender doesn't
		{s("auto", "default"), s("auto", "default", "github-jarvis2"), "upward"}, // a repo is its store
		{s("bypass"), s("bypass"), "equal"},
	} {
		if got, _, _ := peerDirection(c.from, c.to); got != c.want {
			t.Errorf("%v %v → %v: %s, want %s", c.from.Stores, c.from.PermissionMode, c.to.Stores, got, c.want)
		}
	}
}

// peerRig: sessions sLow (default), sHigh (default, infra; bypass) and sSame (default), the deliveries recorded
func peerRig(t *testing.T) (*Router, testMachine, *[]PeerNote, *sync.Mutex) {
	r := newTestRouter(t)
	r.cfg.NoAccess = true
	addSession(r, "sLow", "started", "mLow", false)
	addSession(r, "sHigh", "started", "mHigh", false)
	addSession(r, "sSame", "started", "mSame", false)
	r.st.Do(func(d *persisted) {
		d.Sessions["sLow"].Stores, d.Sessions["sLow"].PermissionMode = []string{"default"}, "auto"
		d.Sessions["sHigh"].Stores, d.Sessions["sHigh"].PermissionMode = []string{"default", "infra"}, "bypass"
		d.Sessions["sSame"].Stores, d.Sessions["sSame"].PermissionMode = []string{"default"}, "auto"
	})
	var mu sync.Mutex
	got := &[]PeerNote{}
	old := deliverPeerHook
	deliverPeerHook = func(r *Router, n PeerNote, _ Origin) error {
		mu.Lock()
		*got = append(*got, n)
		mu.Unlock()
		return nil
	}
	t.Cleanup(func() { deliverPeerHook = old })
	return r, newTestMachine(r, "mLow"), got, &mu
}

func waitNotes(t *testing.T, got *[]PeerNote, mu *sync.Mutex, n int) []PeerNote {
	t.Helper()
	waitFor(t, "deliveries", func() bool { mu.Lock(); defer mu.Unlock(); return len(*got) >= n })
	mu.Lock()
	defer mu.Unlock()
	return append([]PeerNote{}, *got...)
}

// equal and downward go at once, with the verified sender; nothing reaches the Inbox
func TestPeerEqualAndDownwardAreDeliveredAtOnce(t *testing.T) {
	r, m, got, mu := peerRig(t)
	mh := r.MachineHandler()
	code, out := m.do(t, mh, "POST", "/m/api/requests/peer", `{"to": "label sSame", "text": "hello"}`)
	if code != 202 || out["direction"] != "equal" || out["to"] != "sSame" {
		t.Fatalf("%d %v", code, out)
	}
	n := waitNotes(t, got, mu, 1)[0]
	if n.From != "sLow" || n.FromTitle != "label sLow" || n.To != "sSame" || n.Direction != "equal" || n.Text != "hello" || n.Approved ||
		strings.Join(n.FromStores, ",") != "default" || n.FromMode != "auto" {
		t.Fatalf("%+v", n)
	}
	if len(r.Inbox()) != 0 {
		t.Fatal("an equal message went to the Inbox")
	}
	// the sender names no one else: the caller is the machine's session, whatever the body says
	if code, _ := m.do(t, mh, "POST", "/m/api/requests/peer", `{"to": "sLow", "text": "me"}`); code != 400 {
		t.Fatalf("to itself: %d", code)
	}
	if code, _ := m.do(t, mh, "POST", "/m/api/requests/peer", `{"to": "nobody", "text": "x"}`); code != 400 {
		t.Fatalf("to nobody: %d", code)
	}
	// downward: sHigh → sLow
	h := newTestMachine(r, "mHigh")
	if code, out := h.do(t, mh, "POST", "/m/api/requests/peer", `{"to": "sLow", "text": "do this"}`); code != 202 || out["direction"] != "downward" {
		t.Fatalf("%d %v", code, out)
	}
	if n := waitNotes(t, got, mu, 2)[1]; n.From != "sHigh" || n.Direction != "downward" || n.FromMode != "bypass" {
		t.Fatalf("%+v", n)
	}
}

// upward waits in the Inbox, named as the sending session (never Jarvis 4), and goes once Deyao approves it
func TestPeerUpwardWaitsForDeyao(t *testing.T) {
	r, m, got, mu := peerRig(t)
	mh := r.MachineHandler()
	code, out := m.do(t, mh, "POST", "/m/api/requests/peer", `{"to": "sHigh", "text": "run the deploy"}`)
	if code != 200 || out["direction"] != "upward" || out["waiting"] != "inbox" {
		t.Fatalf("%d %v", code, out)
	}
	id := out["id"].(string)
	it, ok := r.InboxItem(id)
	if !ok || it.Kind != requestKindPeer || it.Params.Text != "run the deploy" || it.Session != "sHigh" || it.SessionName != "label sHigh" ||
		it.CallerText != "session “label sLow” (sLow)" || it.Open["kind"] != requestKindPeer {
		t.Fatalf("%+v", it)
	}
	if !strings.Contains(it.Explanation, "Session “label sLow” (sLow; stores default; auto mode) wants to tell session “label sHigh” (sHigh; stores default, infra; bypass mode)") ||
		!strings.Contains(it.Explanation, "the receiver holds infra, which the sender doesn't") || !strings.Contains(it.Explanation, "bypass mode and the sender doesn't") {
		t.Fatalf("%q", it.Explanation)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	if len(*got) != 0 {
		t.Fatal("delivered before Deyao approved it")
	}
	mu.Unlock()
	if code, out := inboxDo(t, r, "POST", "/api/requests/"+id+"/approve", "", false); code != 200 || out["ok"] != true {
		t.Fatalf("approve: %d %v", code, out)
	}
	n := waitNotes(t, got, mu, 1)[0]
	if n.Direction != "upward" || !n.Approved || n.From != "sLow" || n.To != "sHigh" || n.Text != "run the deploy" {
		t.Fatalf("%+v", n)
	}
	waitFor(t, "approved outcome", func() bool {
		ok := false
		r.st.Do(func(d *persisted) {
			for _, o := range d.Outcomes["sLow"] {
				ok = ok || (o.Kind == requestKindPeer && o.Outcome == outcomeApproved && o.Ref == id)
			}
		})
		return ok
	})
	// denied: dropped, and the sender is told
	_, out = m.do(t, mh, "POST", "/m/api/requests/peer", `{"to": "sHigh", "text": "again"}`)
	id = out["id"].(string)
	if code, _ := inboxDo(t, r, "DELETE", "/api/requests/"+id, "", false); code != 200 {
		t.Fatalf("deny: %d", code)
	}
	r.st.Do(func(d *persisted) {
		ok := false
		for _, o := range d.Outcomes["sLow"] {
			ok = ok || (o.Ref == id && o.Outcome == outcomeDenied)
		}
		if !ok {
			t.Fatal("the sender isn't told of the denial")
		}
	})
	mu.Lock()
	if len(*got) != 1 {
		t.Fatalf("a denied message was delivered: %d", len(*got))
	}
	mu.Unlock()
}

// the core attests exactly the note's JSON, under the sender's name
func TestPeerAttested(t *testing.T) {
	n := &PeerNote{From: "sA", To: "sB", Direction: "equal", Text: "x", FromMode: "auto", ToMode: "auto"}
	b, origin, err := attested(Delivery{Kind: "peer", Peer: n})
	if err != nil || origin != "session:sA" || !strings.Contains(string(b), `"direction":"equal"`) {
		t.Fatalf("%s %s %v", b, origin, err)
	}
	if _, _, err := attested(Delivery{Kind: "peer"}); err == nil {
		t.Fatal("a peer delivery without a note")
	}
}

// the router attests the same bytes the machine checks (machine/peer_test.go peerNoteJSON)
func TestPeerNoteJSON(t *testing.T) {
	const want = `{"from":"sa","fromTitle":"A","fromStores":["default"],"fromMode":"auto","to":"sb","toStores":["default"],"toMode":"auto","direction":"equal","text":"hi"}`
	b, _, err := peerAttested(&PeerNote{From: "sa", FromTitle: "A", FromStores: []string{"default"}, FromMode: "auto", To: "sb", ToStores: []string{"default"}, ToMode: "auto", Direction: "equal", Text: "hi"})
	if err != nil || string(b) != want {
		t.Fatalf("%v %s", err, b)
	}
}

// the cert's stores decide (the receiving machine checks against its cert), not the router's list
func TestPeerDirectionUsesTheCertStores(t *testing.T) {
	from := &Session{Stores: []string{"default"}, Cert: &Doc{Payload: `{"stores":["claude-x","default"]}`}}
	to := &Session{Stores: []string{"default"}, Cert: &Doc{Payload: `{"stores":["claude-x","default","infra"]}`}}
	if dir, extra, _ := peerDirection(from, to); dir != "upward" || strings.Join(extra, ",") != "infra" {
		t.Fatalf("%s %v", dir, extra)
	}
	if n := peerNote(from, from, "x"); strings.Join(n.FromStores, ",") != "claude-x,default" {
		t.Fatalf("%v", n.FromStores)
	}
}

// a peer message as a batch item (intent "peer"): upward waits in the batch with the session's other asks, one Inbox
// entry; equal or downward is delivered at once, as alone
func TestPeerInABatch(t *testing.T) {
	r, m, got, mu := peerRig(t)
	mh := r.MachineHandler()
	code, out := m.do(t, mh, "POST", "/m/api/requests/batch", `{"summary":"status, and two messages","items":[
		{"intent":"grant","holder":"status","minutes":5},
		{"intent":"peer","to":"sHigh","text":"run the deploy"},
		{"intent":"peer","to":"label sSame","text":"fyi"}]}`)
	if code != 200 || out["id"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	bid := out["id"].(string)
	items := out["items"].([]any)
	up, eq := items[1].(map[string]any), items[2].(map[string]any)
	if up["intent"] != "peer" || up["direction"] != "upward" || up["to"] != "sHigh" || up["id"] == nil || up["delivering"] != nil {
		t.Fatalf("upward item: %v", up)
	}
	if eq["intent"] != "peer" || eq["direction"] != "equal" || eq["to"] != "sSame" || eq["delivering"] != true || eq["id"] != nil {
		t.Fatalf("equal item: %v", eq)
	}
	// the equal one went at once, the upward one waits
	if n := waitNotes(t, got, mu, 1); len(n) != 1 || n[0].To != "sSame" || n[0].Direction != "equal" || n[0].Text != "fyi" {
		t.Fatalf("%+v", n)
	}
	full, ok := r.InboxBatchFull(bid, nil)
	if !ok {
		t.Fatal("no batch")
	}
	list := full["items"].([]InboxItem)
	if len(list) != 2 || list[1].Kind != requestKindPeer || list[1].Params.Text != "run the deploy" || list[1].Session != "sHigh" ||
		!strings.Contains(list[1].Explanation, "the receiver holds infra, which the sender doesn't") {
		t.Fatalf("%+v", list)
	}
	id := up["id"].(string)
	if code, out := inboxDo(t, r, "POST", "/api/requests/"+id+"/approve", "", false); code != 200 || out["ok"] != true {
		t.Fatalf("approve: %d %v", code, out)
	}
	if n := waitNotes(t, got, mu, 2)[1]; n.To != "sHigh" || n.Direction != "upward" || !n.Approved || n.Text != "run the deploy" {
		t.Fatalf("%+v", n)
	}
	// the outcome names the batch and the item's index, so the session reads it against its own signed filing
	waitFor(t, "approved outcome", func() bool {
		ok := false
		r.st.Do(func(d *persisted) {
			for _, o := range d.Outcomes["sLow"] {
				ok = ok || (o.Ref == id && o.Outcome == outcomeApproved && o.Item == 1 && o.Batch == bid)
			}
		})
		return ok
	})

	// only messages that go at once: no batch, nothing failed
	code, out = m.do(t, mh, "POST", "/m/api/requests/batch", `{"summary":"one note","items":[{"intent":"peer","to":"sSame","text":"second"}]}`)
	if code != 200 || out["id"] != nil || out["items"].([]any)[0].(map[string]any)["delivering"] != true {
		t.Fatalf("%d %v", code, out)
	}
	waitNotes(t, got, mu, 3)
	// checked like the single endpoint: to itself, to nobody, empty, twice the same; nothing is filed or sent
	for _, items := range []string{
		`{"intent":"peer","to":"sLow","text":"me"}`,
		`{"intent":"peer","to":"nobody","text":"x"}`,
		`{"intent":"peer","to":"sHigh","text":"  "}`,
		`{"intent":"peer","to":"sSame","text":"x"},{"intent":"peer","to":"sSame","text":"x"}`,
	} {
		if code, out := m.do(t, mh, "POST", "/m/api/requests/batch", `{"summary":"s","items":[{"intent":"grant","holder":"archive","minutes":5},`+items+`]}`); code != 400 {
			t.Fatalf("%s: %d %v", items, code, out)
		}
	}
	// only a session sends one
	if code, _ := inboxDo(t, r, "POST", "/api/requests/batch", `{"summary":"s","items":[{"intent":"peer","to":"sHigh","text":"x"}]}`, true); code != 403 {
		t.Fatalf("from the app: %d", code)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 3 {
		t.Fatalf("a refused batch sent something: %d", len(*got))
	}
}
