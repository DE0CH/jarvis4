package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// msgRig: a router with a core that attests, one STARTED session s1 on machine `machine` whose cert names the phone
// key and (sensitive) a sensitive store, and a fake machine that answers each delivery with answer(d)
type msgRig struct {
	r     *Router
	phone *ecdh.PrivateKey
	mu    sync.Mutex
	got   []Delivery
	dms   func() []string
}

func newMsgRig(t *testing.T, machine string, sensitive bool, answer func(d Delivery) DeliveryResult) *msgRig {
	rg, _ := v2Rig(t)
	m := &msgRig{r: rg.r, dms: captureDM(t)}
	m.phone, _ = ecdh.P256().GenerateKey(rand.Reader)
	cert, _ := json.Marshal(map[string]any{"kind": "succession-cert", "line": "L1", "sensitive": sensitive,
		"phone": base64.StdEncoding.EncodeToString(m.phone.PublicKey().Bytes())})
	m.r.st.Do(func(d *persisted) {
		s := d.Sessions["s1"]
		s.State, s.MachineID, s.Cert = "started", machine, &Doc{Payload: string(cert)}
		d.Machines[machine] = "s1"
	})
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			b, ok := mqWaitKind(m.r, machine, "delivery", 50*time.Millisecond)
			if !ok {
				continue
			}
			var d Delivery
			json.Unmarshal(b, &d)
			m.mu.Lock()
			m.got = append(m.got, d)
			m.mu.Unlock()
			res := answer(d)
			res.ID = d.ID
			m.r.mqAnswer(d.ID, res)
		}
	}()
	t.Cleanup(func() { messageWG.Wait(); close(stop) })
	return m
}

func (m *msgRig) deliveries() []Delivery {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Delivery{}, m.got...)
}

func (m *msgRig) pending() []*PendingMessage {
	out := []*PendingMessage{}
	m.r.st.Do(func(d *persisted) {
		for _, pm := range d.Messages {
			x := *pm
			out = append(out, &x)
		}
	})
	return out
}

// sign: what the phone does with a draft
func (m *msgRig) sign(t *testing.T, text string) *Doc {
	sig, err := signP256(m.phone, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return &Doc{Payload: text, Sig: sig}
}

// previewOK: the machine renders the canned text the router would (its preview), and takes approved deliveries
func previewOK(d Delivery) DeliveryResult {
	if d.Preview {
		in, _, _ := attested(d)
		return DeliveryResult{OK: true, Text: string(in)}
	}
	return DeliveryResult{OK: true}
}

// sendPeer: session from (added, started, holding stores) sends s1 a peer message through SendPeer; s1 holds
// claude+default, so a sender holding fewer stores sends UPWARD
func (m *msgRig) sendPeer(t *testing.T, from string, stores []string, text string) map[string]any {
	t.Helper()
	m.r.st.Do(func(d *persisted) {
		if d.Sessions[from] == nil {
			d.Sessions[from] = &Session{ID: from, State: "started", MachineID: "m" + from, Label: "label " + from, Harness: "claude", Stores: stores}
			d.Machines["m"+from] = from
		}
	})
	out, err := m.r.SendPeer(from, "s1", text, &SignedRequest{Machine: "m" + from, Method: "POST", Path: "/m/api/requests/peer", Sig: "p" + randID()}, "POST", "/m/api/requests/peer")
	if err != nil {
		t.Fatal(out, err)
	}
	return out
}

// waitPending: until n messages are held (SendPeer hands them over in the background)
func (m *msgRig) waitPending(t *testing.T, n int) []*PendingMessage {
	t.Helper()
	var ps []*PendingMessage
	for i := 0; i < 300; i++ {
		if ps = m.pending(); len(ps) >= n {
			return ps
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%d held, want %d: %+v", len(ps), n, ps)
	return nil
}

// waitDeliveries: until the fake machine got n deliveries
func (m *msgRig) waitDeliveries(t *testing.T, n int) []Delivery {
	t.Helper()
	var ds []Delivery
	for i := 0; i < 300; i++ {
		if ds = m.deliveries(); len(ds) >= n {
			return ds
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%d deliveries, want %d: %+v", len(ds), n, ds)
	return nil
}

func TestAMessageIntoASensitiveSessionWaitsForDeyao(t *testing.T) {
	m := newMsgRig(t, "mmsg1", true, previewOK)
	// an upward peer message: held (the sender sees it handed over), with the machine's own text
	if out := m.sendPeer(t, "sfrom", nil, "please run the report"); out["waiting"] != "message" {
		t.Fatal(out)
	}
	ps := m.waitPending(t, 1)
	want := ps[0].Text
	if len(ps) != 1 || ps[0].Kind != "peer" || !strings.Contains(want, "please run the report") || ps[0].State != "pending" || !strings.Contains(ps[0].From, "sfrom") {
		t.Fatalf("held %+v", ps)
	}
	if ds := m.deliveries(); len(ds) != 1 || !ds[0].Preview || ds[0].Attest != nil {
		t.Fatalf("only a preview reached the machine: %+v", ds)
	}
	messageWG.Wait() // the hand-over DMs after the message is in the Inbox
	if len(m.dms()) != 1 || !strings.Contains(m.dms()[0], "Peer message") {
		t.Fatalf("dm %q", m.dms())
	}
	// it is in the Inbox, under its session, with the exact text and who asks
	var it *InboxItem
	for _, x := range m.r.Inbox() {
		if x.Kind == requestKindMsg {
			x := x
			it = &x
		}
	}
	if it == nil || it.Session != "s1" || it.Params.Text != want || it.CallerText != ps[0].From || !strings.HasPrefix(it.Explanation, "Message from session “") {
		t.Fatalf("inbox %+v", it)
	}
	// a second message waiting doesn't DM again (one DM per session while any waits)
	m.sendPeer(t, "sfrom", nil, "and the other one")
	ps2 := m.waitPending(t, 2)
	messageWG.Wait()
	if len(ps2) != 2 || len(m.dms()) != 1 {
		t.Fatalf("%+v (dms %d)", ps2, len(m.dms()))
	}
	m.r.DenyMessages([]string{func() string {
		for _, pm := range m.pending() {
			if pm.ID != ps[0].ID {
				return pm.ID
			}
		}
		return ""
	}()})

	// Deliver: the phone signs the draft; the machine gets exactly that message with the signature, attested
	id := ps[0].ID
	text, sid, line, err := m.r.DraftMessages([]string{id})
	if err != nil || sid != "s1" || line != "L1" {
		t.Fatal(err)
	}
	var a messageApproval
	json.Unmarshal([]byte(text), &a)
	sum := sha256.Sum256([]byte(want))
	if a.Kind != "messages" || a.Session != "L1" || len(a.Items) != 1 || a.Items[0].Sha256 != hex.EncodeToString(sum[:]) || a.Items[0].Text != want {
		t.Fatalf("draft %s", text)
	}
	stranger, _ := ecdh.P256().GenerateKey(rand.Reader)
	ssig, _ := signP256(stranger, []byte(text))
	if _, err := m.r.ApproveMessages(&Doc{Payload: text, Sig: ssig}); err == nil {
		t.Fatal("took another key's signature")
	}
	doc := m.sign(t, text)
	if ids, err := m.r.ApproveMessages(doc); err != nil || len(ids) != 1 {
		t.Fatal(err)
	}
	messageWG.Wait()
	ds := m.deliveries()
	last := ds[len(ds)-1]
	if last.Preview || last.Kind != "peer" || last.Approval == nil || last.Approval.Payload != text || last.Attest == nil {
		t.Fatalf("delivered %+v", last)
	}
	if len(m.pending()) != 0 {
		t.Fatal("a delivered message stays")
	}
	if _, err := m.r.ApproveMessages(doc); err == nil {
		t.Fatal("the same approval twice")
	}
}

// a resume prompt is rendered by the router itself, so a paused session isn't started just to hold it
func TestAPausedSensitiveSessionIsntStartedToHoldAMessage(t *testing.T) {
	m := newMsgRig(t, "mmsg2", true, previewOK)
	m.r.st.Do(func(d *persisted) { d.Sessions["s1"].State, d.Sessions["s1"].MachineID = "paused", "" })
	if err := m.r.deliverVouched("s1", Delivery{Kind: "resume-prompt", Text: "check   the CI"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := m.r.sessionState("s1"); st != "paused" {
		t.Fatalf("started it: %s", st)
	}
	ps := m.pending()
	if len(ps) != 1 || ps[0].Kind != "resume-prompt" || !strings.Contains(ps[0].Text, "check") || !strings.Contains(ps[0].From, "Deyao") {
		t.Fatalf("%+v", ps)
	}
	// a second one replaces it, still without starting anything
	m.r.deliverVouched("s1", Delivery{Kind: "resume-prompt", Text: "no, carry on"})
	if ps2 := m.pending(); len(ps2) != 1 || ps2[0].ID == ps[0].ID || ps2[0].Text != "no, carry on" {
		t.Fatalf("not replaced: %+v", ps2)
	}
	// Deny: nothing goes in
	if got := m.r.DenyMessages([]string{m.pending()[0].ID}); len(got) != 1 {
		t.Fatal("not denied")
	}
	if st, _ := m.r.sessionState("s1"); len(m.pending()) != 0 || st != "paused" {
		t.Fatalf("pending %+v, state %s", m.pending(), st)
	}
	if len(m.deliveries()) != 0 {
		t.Fatal("something reached the machine")
	}
}

func TestADeliveryIntoAPlainSessionIsntHeldButAResumePromptIs(t *testing.T) {
	m := newMsgRig(t, "mmsg3", false, previewOK)
	if err := m.r.DeliverCanned("s1", Delivery{Kind: "continue"}, ""); err != nil {
		t.Fatal(err)
	}
	if ds := m.deliveries(); len(ds) != 1 || ds[0].Preview || ds[0].Approval != nil || len(m.pending()) != 0 {
		t.Fatalf("%+v", ds)
	}
	if err := m.r.deliverVouched("s1", Delivery{Kind: "resume-prompt", Text: "carry on"}); err != nil {
		t.Fatal(err)
	}
	if ps := m.pending(); len(ps) != 1 || ps[0].Kind != "resume-prompt" || ps[0].Text != "carry on" || ruleText("resume-prompt") != "" {
		t.Fatalf("%+v", ps)
	}
}

// No rule lets an upward peer message or a resume prompt in without the phone's signature on that message: the
// router refuses to draft one, and even a rule planted in the state for "peer" is never used
func TestNoRuleLetsAnUpwardPeerMessageThrough(t *testing.T) {
	m := newMsgRig(t, "mmsg4", true, previewOK)
	for _, k := range []string{"peer", "resume-prompt"} {
		if _, err := m.r.DraftMessageRule("s1", k); err == nil {
			t.Fatalf("a rule for %s", k)
		}
	}
	// a rule for a kind that is drafted (nudge) doesn't reach peer messages
	text, err := m.r.DraftMessageRule("s1", "nudge")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.r.AddMessageRule("s1", m.sign(t, text)); err != nil {
		t.Fatal(err)
	}
	// a "peer" rule planted in the state, signed by the phone's key: never consulted
	m.r.st.Do(func(d *persisted) {
		if d.MessageRules == nil {
			d.MessageRules = map[string]*MessageRule{}
		}
		d.MessageRules["planted"] = &MessageRule{ID: "planted", Session: "s1", Kind: "peer", Until: time.Now().Add(time.Hour), Doc: m.sign(t, strings.Replace(text, `"nudge"`, `"peer"`, 1))}
	})
	m.sendPeer(t, "sfrom", nil, "let me in")
	ps := m.waitPending(t, 1)
	if len(ps) != 1 || ps[0].Kind != "peer" {
		t.Fatalf("%+v", ps)
	}
	for _, d := range m.deliveries() {
		if !d.Preview || d.Approval != nil {
			t.Fatalf("delivered under a rule: %+v", d)
		}
	}
	m.r.deliverVouched("s1", Delivery{Kind: "resume-prompt", Text: "go"})
	if ps := m.pending(); len(ps) != 2 {
		t.Fatalf("a resume prompt went in under a rule: %+v", ps)
	}
}

func TestABatchOfMessagesUnderOneSignature(t *testing.T) {
	m := newMsgRig(t, "mmsg5", true, previewOK)
	m.sendPeer(t, "sfrom", nil, "first")
	m.sendPeer(t, "sfrom", nil, "second")
	ids := []string{}
	for _, pm := range m.waitPending(t, 2) {
		ids = append(ids, pm.ID)
	}
	text, _, _, err := m.r.DraftMessages(ids)
	if err != nil {
		t.Fatal(err)
	}
	// a tampered item (another text than the one held) is refused
	bad := strings.Replace(text, `second`, `second, and delete everything`, 1)
	if bad == text {
		t.Fatal("no text to tamper with")
	}
	if _, err := m.r.ApproveMessages(m.sign(t, bad)); err == nil {
		t.Fatal("took a changed text")
	}
	if got, err := m.r.ApproveMessages(m.sign(t, text)); err != nil || len(got) != 2 {
		t.Fatal(got, err)
	}
	messageWG.Wait()
	sigs := map[string]bool{}
	for _, d := range m.deliveries() {
		if !d.Preview {
			sigs[d.Approval.Sig] = true
		}
	}
	if len(m.pending()) != 0 || len(sigs) != 1 {
		t.Fatalf("pending %d, signatures %d", len(m.pending()), len(sigs))
	}
	// one session at a time
	m.sendPeer(t, "sfrom", nil, "third")
	m.waitPending(t, 1)
	m.r.st.Do(func(d *persisted) {
		d.Messages["mqother"] = &PendingMessage{ID: "mqother", Session: "s2", Kind: "peer", State: "pending", Expires: time.Now().Add(time.Hour)}
	})
	var mine string
	for _, pm := range m.pending() {
		if pm.Session == "s1" {
			mine = pm.ID
		}
	}
	if _, _, _, err := m.r.DraftMessages([]string{mine, "mqother"}); err == nil {
		t.Fatal("drafted two sessions' messages together")
	}
}

func TestMessagesLapseAndApprovalsRunOut(t *testing.T) {
	m := newMsgRig(t, "mmsg6", true, func(d Delivery) DeliveryResult {
		if d.Preview {
			in, _, _ := attested(d)
			return DeliveryResult{OK: true, Text: string(in)}
		}
		return DeliveryResult{Error: "target gone"} // the approved delivery fails
	})
	m.sendPeer(t, "sfrom", nil, "x")
	ps := m.waitPending(t, 1)
	if len(ps) != 1 || ps[0].Kind != "peer" || ps[0].Origin == nil || ps[0].Origin.Caller.Session != "sfrom" {
		t.Fatalf("%+v", ps)
	}
	// a day on, nobody answered: it lapses and the sender hears so
	m.r.messageTickOnce(time.Now().Add(messageTTL + time.Minute))
	var oc []*Outcome
	m.r.st.Do(func(d *persisted) { oc = d.Outcomes["sfrom"] })
	if len(m.pending()) != 0 || len(oc) != 1 || oc[0].Outcome != outcomeLapsed {
		t.Fatalf("%+v", oc)
	}
	// approved but the machine fails it: failed, and it says why
	m.sendPeer(t, "sfrom", nil, "y")
	id := m.waitPending(t, 1)[0].ID
	text, _, _, _ := m.r.DraftMessages([]string{id})
	m.r.ApproveMessages(m.sign(t, text))
	messageWG.Wait()
	if ps := m.pending(); len(ps) != 1 || ps[0].State != "failed" || !strings.Contains(ps[0].Error, "target gone") {
		t.Fatalf("%+v", ps)
	}
}

// DECISIONS 210: Jarvis's own messages (an Inbox outcome, the watchdog, "continue", an upgrade note) and the session's
// own wakeups go straight into a running session holding a sensitive store: never held, no preview, no signature
func TestJarvisOwnMessagesGoStraightIntoASensitiveSession(t *testing.T) {
	m := newMsgRig(t, "mmsg10", true, previewOK)
	wake := &SignedRequest{Machine: "mmsg10", Method: "POST", Path: "/m/api/sessions/s1/wakeup", At: "1",
		Body: base64.StdEncoding.EncodeToString([]byte(`{"name":"ci","prompt":"check the CI","delaySeconds":60}`)), Sig: "sw"}
	filed := &SignedRequest{Machine: "mmsg10", Method: "POST", Path: "/m/api/requests/add-store", At: "1", Body: base64.StdEncoding.EncodeToString([]byte(`{}`)), Sig: "sr"}
	for i, d := range []Delivery{
		{Kind: "request-outcome", Request: filed, Outcomes: []OutcomeItem{{Outcome: outcomeApproved, Ref: "q1"}}},
		{Kind: "nudge", Minutes: 20, Jobs: 2},
		{Kind: "wakeup", Request: wake},
		{Kind: "continue"},
		{Kind: "upgraded", From: "medium", To: "large"},
	} {
		if m.r.needsApproval("s1", d) {
			t.Fatalf("%s needs approval", d.Kind)
		}
		if err := m.r.deliverVouched("s1", d); err != nil {
			t.Fatalf("%s: %v", d.Kind, err)
		}
		ds := m.deliveries()
		if len(ds) != i+1 || ds[i].Kind != d.Kind || ds[i].Preview || ds[i].Approval != nil || ds[i].Attest == nil {
			t.Fatalf("%s not delivered straight in: %+v", d.Kind, ds)
		}
	}
	if len(m.pending()) != 0 || len(m.dms()) != 0 {
		t.Fatalf("held %+v, dms %q", m.pending(), m.dms())
	}
}

// DECISIONS 210: into a session holding a sensitive store, an equal or downward peer message goes straight in (no
// Inbox, no signature); only an upward one (from a session holding less) waits for Deyao
func TestOnlyAnUpwardPeerMessageIntoASensitiveSessionIsHeld(t *testing.T) {
	m := newMsgRig(t, "mmsg11", true, previewOK)
	if out := m.sendPeer(t, "sequal", []string{"claude", "default"}, "same stores"); out["direction"] != "equal" || out["waiting"] != nil {
		t.Fatal(out)
	}
	if out := m.sendPeer(t, "sdown", []string{"claude", "default", "infra"}, "more stores"); out["direction"] != "downward" || out["waiting"] != nil {
		t.Fatal(out)
	}
	ds := m.waitDeliveries(t, 2)
	for _, d := range ds {
		if d.Kind != "peer" || d.Preview || d.Approval != nil || d.Attest == nil || d.Peer.Approved {
			t.Fatalf("not straight in: %+v", d)
		}
	}
	if len(m.pending()) != 0 {
		t.Fatalf("held %+v", m.pending())
	}
	for _, q := range m.r.Inbox() {
		t.Fatalf("an Inbox item for an equal/downward message: %+v", q)
	}
	if out := m.sendPeer(t, "sup", []string{"claude"}, "fewer stores"); out["direction"] != "upward" || out["waiting"] != "message" {
		t.Fatal(out)
	}
	if ps := m.waitPending(t, 1); len(ps) != 1 || ps[0].Kind != "peer" || ps[0].Delivery.Peer.From != "sup" {
		t.Fatalf("%+v", ps)
	}
	// the same rule on the router's side, peer by peer
	for dir, want := range map[string]bool{"equal": false, "downward": false, "upward": true} {
		if got := m.r.needsApproval("s1", Delivery{Kind: "peer", Peer: &PeerNote{Direction: dir}}); got != want {
			t.Fatalf("%s: needsApproval %v", dir, got)
		}
	}
	// into a plain session not even an upward one waits for a signature (it is a one-tap upward request instead)
	m.r.st.Do(func(d *persisted) {
		d.Sessions["s1"].Cert = &Doc{Payload: `{"kind":"succession-cert","line":"L1","sensitive":false}`}
	})
	if m.r.needsApproval("s1", Delivery{Kind: "peer", Peer: &PeerNote{Direction: "upward"}}) {
		t.Fatal("an upward peer into a plain session needs the phone's signature")
	}
}

// the machine renders another text than the phone signed: it refuses with its own, and that one is held for Deyao
func TestATextTheMachineRendersDifferentlyIsHeldAgain(t *testing.T) {
	m := newMsgRig(t, "mmsg7", true, func(d Delivery) DeliveryResult {
		if d.Preview {
			return DeliveryResult{OK: true, Text: "continue"}
		}
		return DeliveryResult{Error: "message approval: the signed text isn't the text this machine renders", NeedsApproval: true, Text: "the machine's text"}
	})
	m.r.DeliverCanned("s1", Delivery{Kind: "continue"}, "")
	id := m.pending()[0].ID
	text, _, _, _ := m.r.DraftMessages([]string{id})
	if _, err := m.r.ApproveMessages(m.sign(t, text)); err != nil {
		t.Fatal(err)
	}
	messageWG.Wait()
	ps := m.pending()
	if len(ps) != 1 || ps[0].ID == id || ps[0].State != "pending" || ps[0].Text != "the machine's text" {
		t.Fatalf("%+v", ps)
	}
}

// a peer message into a session holding a sensitive store isn't a one-tap upward request: Deyao signs the message
func TestAPeerMessageIntoASensitiveSessionIsHeld(t *testing.T) {
	m := newMsgRig(t, "mmsg8", true, func(d Delivery) DeliveryResult {
		if d.Preview {
			return DeliveryResult{OK: true, Text: "[Message from another Jarvis 4 session] " + d.Peer.Text}
		}
		return DeliveryResult{OK: true}
	})
	addSession(m.r, "sfrom", "started", "mfrom", false)
	out, err := m.r.SendPeer("sfrom", "s1", "please run the report", &SignedRequest{Machine: "mfrom", Method: "POST", Path: "/m/api/requests/peer", Sig: "p"}, "POST", "/m/api/requests/peer")
	if err != nil || out["waiting"] != "message" {
		t.Fatal(out, err)
	}
	var ps []*PendingMessage
	for i := 0; i < 100 && len(ps) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
		ps = m.pending()
	}
	if len(ps) != 1 || ps[0].Kind != "peer" || !ps[0].Delivery.Peer.Approved || ps[0].Origin == nil || ps[0].Origin.Caller.Session != "sfrom" {
		t.Fatalf("%+v", ps)
	}
	for _, q := range m.r.Inbox() {
		if q.Kind == requestKindPeer {
			t.Fatal("also filed as an upward peer request")
		}
	}
	m.r.DenyMessages([]string{ps[0].ID})
	var oc []*Outcome
	m.r.st.Do(func(d *persisted) { oc = d.Outcomes["sfrom"] })
	if len(oc) != 1 || oc[0].Outcome != outcomeDenied || oc[0].Kind != requestKindPeer {
		t.Fatalf("the sender wasn't told: %+v", oc)
	}
	if !errors.Is(handedOver(errAwaitingApproval), nil) {
		t.Fatal("held counts as handed over")
	}
}

// the router's twins render what machine/deliver.go deliveryText renders (its tests pin the same strings)
func TestMessageTextTwins(t *testing.T) {
	req := func(path, body string) *SignedRequest {
		return &SignedRequest{Method: "POST", Path: path, Body: base64.StdEncoding.EncodeToString([]byte(body))}
	}
	for d, want := range map[*Delivery]string{
		{Kind: "cron", Run: 3, Request: req("/m/api/sessions/s1/crons", `{"name":"daily","prompt":"report","everySeconds":86400}`)}: `[recurring wakeup "daily" — run 3] report`,
		{Kind: "wakeup", Request: req("/m/api/sessions/s1/wakeup", `{"prompt":"go  on"}`)}:                                          `go on`,
		{Kind: "watch-fail", Request: req("/m/api/sessions/s1/watches", `{"name":"ci","prompt":"x","failPrompt":"look"}`)}:          `[watch "ci" gave up] look`,
		{Kind: "upgraded", From: "medium", To: "large"}:                                                                             upgradedText("medium", "large"),
	} {
		if got, _, _, ok := messageText(*d); !ok || got != want {
			t.Fatalf("%s: %q", d.Kind, got)
		}
	}
}

// oldImageMachine: a machine on an image from before message approvals (2026-10-20, s6056456f64d9d2df): it knows no
// preview, so it takes the router's preview as a delivery and refuses it for want of the core's attestation; an
// attested delivery it takes (it checks no phone approval)
func oldImageMachine(d Delivery) DeliveryResult {
	if d.Attest == nil {
		return DeliveryResult{Error: "no core attestation (the input isn't in the core's log)"}
	}
	return DeliveryResult{OK: true}
}

// An upward peer message into a sensitive session whose machine can't preview was reported FAILED to its sender
// within 0.2 s, before Deyao ever saw it ("It was approved but carrying it out failed", the Paseo test session's two
// replies to "Jarvis 4 works", 2026-10-20). It is held with Jarvis's own rendering instead, and delivered once Deyao
// delivers it.
func TestAMessageIntoAnOldImageMachineIsHeldWithJarvisText(t *testing.T) {
	m := newMsgRig(t, "mmsg9", true, oldImageMachine)
	addSession(m.r, "sfrom", "started", "mfrom", false)
	out, err := m.r.SendPeer("sfrom", "s1", "test step 2 could not run", &SignedRequest{Machine: "mfrom", Method: "POST", Path: "/m/api/requests/peer", Sig: "p"}, "POST", "/m/api/requests/peer")
	if err != nil || out["waiting"] != "message" {
		t.Fatal(out, err)
	}
	var ps []*PendingMessage
	for i := 0; i < 200 && len(ps) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
		ps = m.pending()
	}
	var oc []*Outcome
	m.r.st.Do(func(d *persisted) { oc = d.Outcomes["sfrom"] })
	if len(oc) != 0 {
		t.Fatalf("the sender was told %s before Deyao saw the message", oc[0].Outcome)
	}
	if len(ps) != 1 || ps[0].Kind != "peer" || ps[0].State != "pending" || !strings.Contains(ps[0].Text, "test step 2 could not run") ||
		!strings.Contains(ps[0].Text, "relayed by Jarvis") || !strings.Contains(ps[0].Note, "before message approvals") {
		t.Fatalf("not held with Jarvis's text: %+v", ps)
	}
	text, _, _, err := m.r.DraftMessages([]string{ps[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.r.ApproveMessages(m.sign(t, text)); err != nil {
		t.Fatal(err)
	}
	messageWG.Wait()
	ds := m.deliveries()
	last := ds[len(ds)-1]
	if last.Preview || last.Kind != "peer" || last.Attest == nil || last.Peer == nil || !last.Peer.Approved {
		t.Fatalf("delivered %+v", last)
	}
	m.r.st.Do(func(d *persisted) { oc = d.Outcomes["sfrom"] })
	if len(oc) != 1 || oc[0].Outcome != outcomeApproved || len(m.pending()) != 0 {
		t.Fatalf("outcomes %+v, pending %+v", oc, m.pending())
	}

	// Jarvis's own kinds aren't held at all (DECISIONS 210): the watchdog's check-in goes straight in, attested
	n := len(m.deliveries())
	if err := m.r.DeliverCanned("s1", Delivery{Kind: "nudge", Minutes: 20, Jobs: 2}, ""); err != nil {
		t.Fatal(err)
	}
	if ds := m.deliveries(); len(ds) != n+1 || ds[n].Kind != "nudge" || ds[n].Preview || ds[n].Attest == nil || len(m.pending()) != 0 {
		t.Fatalf("nudge %+v, pending %+v", ds[n:], m.pending())
	}
}
