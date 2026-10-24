package main

// Peer messages (docs/DESIGN.md "Peer messages", DECISIONS 199): the only way one session's words reach another.
// Claude Code's own cross-session channels are refused in every session (session-image/claude-code/
// managed-settings.json: crossSessionInbound "refuse"), so a session with fewer secrets can't get one with more to act
// for it (a confused deputy) behind Deyao's back. A session calls POST /m/api/requests/peer {to, text}
// (`jarvis-message`); the router names the sender from its machine key and decides the direction:
//
//   equal     the receiver holds exactly the sender's stores, in the same permission mode
//   downward  the receiver holds no store the sender lacks, and bypasses only if the sender does
//   upward    anything else: the receiver holds a store the sender lacks, or bypasses while the sender doesn't
//
// Equal and downward are delivered at once; upward waits in the Inbox as a "peer-message" request that Deyao
// approves or denies with one tap (no Face ID: nothing is signed, like an API call). Either way the receiving machine
// gets a core-attested "peer" delivery carrying the verified sender, both sides' stores and modes and the direction;
// it checks the direction against its own cert and wraps the text with all of it (machine/peer.go). A denial, a lapse
// or a failed delivery comes back to the sender as its request's outcome (outcomes.go).
//
// Repos count through their stores (a repo is its deploy-key store). Grants and standing rules don't count: they let
// a router feature run commands in the session, not the session's Claude do more.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	requestKindPeer = "peer-message"
	peerNoteMax     = 8000 // characters of a peer message
)

// PeerNote: what the receiving machine gets (machine/peer.go has the same struct: the core attests its JSON)
type PeerNote struct {
	From       string   `json:"from"` // the sending session's id
	FromTitle  string   `json:"fromTitle"`
	FromStores []string `json:"fromStores"`
	FromMode   string   `json:"fromMode"` // auto | bypass
	To         string   `json:"to"`
	ToStores   []string `json:"toStores"`
	ToMode     string   `json:"toMode"`
	Direction  string   `json:"direction"`          // equal | downward | upward
	Approved   bool     `json:"approved,omitempty"` // upward: Deyao approved it in the Inbox
	Text       string   `json:"text"`
}

func modeOf(s *Session) string {
	if s.PermissionMode == "bypass" {
		return "bypass"
	}
	return "auto"
}

// peerStores: the stores the session's machine holds, as its latest cert names them (the machine checks against the
// same list); the router's list when there is no cert yet
func peerStores(s *Session) []string {
	st, _ := certStoresHarness(s.Cert, s.Stores, "")
	return st
}

func sortedStores(ss []string) []string {
	out := append([]string{}, ss...)
	sort.Strings(out)
	return out
}

// peerDirection: equal, downward or upward, and why it is upward (the stores the receiver has beyond the sender's,
// and whether it bypasses while the sender doesn't)
func peerDirection(from, to *Session) (dir string, extra []string, modeUp bool) {
	have := map[string]bool{}
	for _, s := range peerStores(from) {
		have[s] = true
	}
	for _, s := range peerStores(to) {
		if !have[s] {
			extra = append(extra, s)
		}
	}
	sort.Strings(extra)
	modeUp = modeOf(to) == "bypass" && modeOf(from) != "bypass"
	switch {
	case len(extra) > 0 || modeUp:
		return "upward", extra, modeUp
	case len(peerStores(from)) == len(peerStores(to)) && modeOf(from) == modeOf(to):
		return "equal", nil, false
	}
	return "downward", nil, false
}

func peerNote(from, to *Session, text string) PeerNote {
	dir, _, _ := peerDirection(from, to)
	return PeerNote{From: from.ID, FromTitle: clip(sessionTitle(*from), 200), FromStores: sortedStores(peerStores(from)), FromMode: modeOf(from),
		To: to.ID, ToStores: sortedStores(peerStores(to)), ToMode: modeOf(to), Direction: dir, Text: text}
}

// resolvePeer: the receiving session by id, or by its exact title when exactly one live session has it
func resolvePeer(d *persisted, to string) (*Session, error) {
	to = strings.TrimSpace(to)
	live := func(s *Session) bool { return s != nil && s.State != "destroyed" && s.State != "destroying" }
	if s := d.Sessions[to]; live(s) {
		return s, nil
	}
	var hit []*Session
	for _, s := range d.Sessions {
		if live(s) && to != "" && strings.EqualFold(sessionTitle(*s), to) {
			hit = append(hit, s)
		}
	}
	switch len(hit) {
	case 1:
		return hit[0], nil
	case 0:
		return nil, &badRequest{fmt.Sprintf("no session %q (its id, or its exact title)", to)}
	}
	return nil, &badRequest{fmt.Sprintf("%d sessions are titled %q: use the session id", len(hit), to)}
}

func listOrNone(ss []string) string {
	if len(ss) == 0 {
		return "none"
	}
	return clip(strings.Join(ss, ", "), 120)
}

// peerExplanation: the Inbox item's words, by the router: who wants to tell whom, and why it is upward
func peerExplanation(from, to *Session) string {
	_, extra, modeUp := peerDirection(from, to)
	why := []string{}
	if len(extra) > 0 {
		why = append(why, "the receiver holds "+listOrNone(extra)+", which the sender doesn't")
	}
	if modeUp {
		why = append(why, "the receiver runs in bypass mode and the sender doesn't")
	}
	return fmt.Sprintf("Upward: %s.\nSession “%s” (%s; stores %s; %s mode) wants to tell session “%s” (%s; stores %s; %s mode) the message above.",
		strings.Join(why, "; "), clip(sessionTitle(*from), 80), from.ID, listOrNone(sortedStores(peerStores(from))), modeOf(from),
		clip(sessionTitle(*to), 80), to.ID, listOrNone(sortedStores(peerStores(to))), modeOf(to))
}

// peerParties: the sending session, the receiving one (its id or exact title) and the cleaned text, checked as a
// message is checked wherever it is filed (alone or as a batch item)
func (r *Router) peerParties(sender, to, text string) (from, recv Session, clean string, err error) {
	clean = cleanPeerText(text)
	if clean == "" {
		return from, recv, "", &badRequest{"an empty message"}
	}
	if n := len([]rune(clean)); n > peerNoteMax {
		return from, recv, "", &badRequest{fmt.Sprintf("a message longer than %d characters (%d)", peerNoteMax, n)}
	}
	r.st.Do(func(d *persisted) {
		s := d.Sessions[sender]
		if s == nil {
			err = errNoSession
			return
		}
		from = *s
		var t *Session
		if t, err = resolvePeer(d, to); err == nil {
			recv = *t
		}
	})
	if err == nil && recv.ID == from.ID {
		err = &badRequest{"that is this session"}
	}
	return from, recv, clean, err
}

// SendPeer: the sending session's message → delivered at once (equal, downward) or filed in the Inbox (upward). A
// batch takes the same message as an item (intent "peer", batches.go), so it goes in one Inbox entry with the
// session's other asks.
func (r *Router) SendPeer(sender, to, text string, signed *SignedRequest, method, path string) (map[string]any, error) {
	from, recv, text, err := r.peerParties(sender, to, text)
	if err != nil {
		return nil, err
	}
	o := Origin{Caller: Caller{Kind: "session", Session: sender}, Call: APICall{Method: method, Path: strings.TrimPrefix(path, "/m"),
		Args: map[string]any{"to": recv.ID}}, Signed: signed}
	note := peerNote(&from, &recv, text)
	if held, ok := heldPeerNote(note, &recv); ok {
		r.goPeerNote(held, o, "")
		return map[string]any{"delivering": true, "direction": note.Direction, "to": recv.ID,
			"waiting": "message", "note": "the receiving session holds a sensitive store: Deyao delivers or denies this message in the Inbox; you hear the outcome"}, nil
	}
	if note.Direction != "upward" {
		r.goPeerNote(note, o, "")
		return map[string]any{"delivering": true, "direction": note.Direction, "to": recv.ID}, nil
	}
	q, dup, err := r.FileRequest(requestKindPeer, RequestParams{Session: recv.ID, Text: text}, peerExplanation(&from, &recv), o)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": q.ID, "duplicate": dup, "expires": q.Expires, "direction": "upward", "waiting": "inbox", "to": recv.ID}, nil
}

// goPeerNote: deliverPeerNote in the background, counted in messageWG with the other message goroutines (a test
// waits for them before its DM hook and its directory go: a held message DMs after it is in the Inbox)
func (r *Router) goPeerNote(note PeerNote, o Origin, ref string) {
	messageWG.Add(1)
	go func() {
		defer messageWG.Done()
		r.deliverPeerNote(note, o, ref)
	}()
}

// deliverPeerNote: the note into the receiving session (started if paused); a failure is the sender's outcome. ref:
// the Inbox id an approved upward message had ("" for one delivered at once: the receiver's id names it then).
func (r *Router) deliverPeerNote(note PeerNote, o Origin, ref string) {
	err := deliverPeerHook(r, note, o)
	if ref == "" {
		ref = note.To
	}
	if errors.Is(err, errAwaitingApproval) { // messages.go: the receiver holds a sensitive store; Deyao decides, the sender hears
		log.Printf("peer message %s → %s (%s) waits for Deyao", note.From, note.To, note.Direction)
		return
	}
	if err != nil {
		log.Printf("peer message %s → %s (%s) not delivered: %v", note.From, note.To, note.Direction, err)
		r.st.Do(func(d *persisted) { noteOutcome(d, &o, requestKindPeer, ref, outcomeFailed, 0, nil) })
		return
	}
	log.Printf("peer message %s → %s (%s) delivered", note.From, note.To, note.Direction)
	if note.Approved {
		r.st.Do(func(d *persisted) { noteOutcome(d, &o, requestKindPeer, ref, outcomeApproved, 0, nil) })
	}
}

// deliverPeerHook: a seam for tests (errAwaitingApproval: held for Deyao, who decides; o hears of it)
var deliverPeerHook = func(r *Router, note PeerNote, o Origin) error {
	return r.deliverVouchedOpts(note.To, Delivery{Kind: "peer", Peer: &note}, true, &o)
}

// heldPeerNote: an upward message into a session holding a sensitive store isn't filed as an upward peer request:
// Deyao delivers or denies the message itself, signed (messages.go), so it carries his approval in that signature. An
// equal or downward one goes straight in, as into any session (DECISIONS 210)
func heldPeerNote(note PeerNote, recv *Session) (PeerNote, bool) {
	if !certSensitive(recv.Cert) || note.Direction != "upward" {
		return note, false
	}
	note.Approved = true
	return note, true
}

// peerAttested: what the core attests for a peer delivery (machine/peer.go checks the same bytes)
func peerAttested(n *PeerNote) ([]byte, string, error) {
	if n == nil || n.From == "" || n.To == "" || n.Text == "" {
		return nil, "", errors.New("peer: no note")
	}
	b, err := json.Marshal(n)
	return b, "session:" + n.From, err
}

// ApprovePeer: Deyao's one tap on an upward peer message: it is delivered now, with the session's current stores
func (r *Router) ApprovePeer(id string) (map[string]any, error) {
	var q *InboxRequest
	var from, to Session
	r.st.Do(func(d *persisted) {
		pruneRequests(d, time.Now().UTC())
		x := d.Inbox[id]
		if x == nil || x.Kind != requestKindPeer {
			return
		}
		f, t := d.Sessions[x.Origin.Caller.Session], d.Sessions[x.Params.Session]
		if f == nil || t == nil {
			return
		}
		q, from, to = x, *f, *t
		delete(d.Inbox, id)
	})
	if q == nil {
		return nil, errNoRequest
	}
	note := peerNote(&from, &to, q.Params.Text)
	note.Approved = note.Direction == "upward"
	r.goPeerNote(note, q.Origin, q.ID)
	return map[string]any{"ok": true, "state": "delivering", "direction": note.Direction}, nil
}

// isPeerRequest: an Inbox id that is a peer message (the approve route serves both kinds)
func (r *Router) isPeerRequest(id string) bool {
	ok := false
	r.st.Do(func(d *persisted) { ok = d.Inbox[id] != nil && d.Inbox[id].Kind == requestKindPeer })
	return ok
}

func (r *Router) registerPeerMessages(m machineRoute) {
	m("POST /m/api/requests/peer", func(w http.ResponseWriter, req *http.Request, machine string, b []byte) {
		sid, err := r.machineSession(machine)
		if err != nil {
			writeJSON(w, 403, map[string]string{"error": err.Error()})
			return
		}
		var in struct {
			To   string `json:"to"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(b, &in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
			return
		}
		out, err := r.SendPeer(sid, in.To, in.Text, signedRequestOf(req, req.Header.Get("X-Machine"), b), req.Method, req.URL.Path)
		if err != nil {
			writeRequestErr(w, err)
			return
		}
		code := 200
		if out["delivering"] == true {
			code = 202
		}
		writeJSON(w, code, out)
	})
}
