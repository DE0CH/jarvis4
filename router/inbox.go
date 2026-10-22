package main

// Requests (the app's Inbox, docs/API.md "Requests"): anything that needs Deyao's Face ID and was asked for
// somewhere other than the phone itself — by a session, the web page or the setup session (Claude) — waits here
// until he reviews it on the phone. A caller calls an intent endpoint (`…/requests/repo/add` and so on) with its
// arguments and its own explanation; the router keeps the request with who called (worked out from the caller's
// credential, never from what it says about itself) and the exact call. The phone opens the shell's secure page
// for it, which renders what the core (or the phone's grant) will actually do from the signed content, and signs
// only that. Nothing here can approve anything: a request is a pointer to a secure page, and Deny just drops it.
//
// The approvals the router already holds (new session, resume on the latest image, add a store) are listed in the
// same Inbox, with their caller and call recorded when they were made.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	inboxTTL          = 10 * time.Minute // Deyao, 2026-10-12: anything in the Inbox (request or approval) goes after 10 min
	requestPerCaller  = 20               // pending requests one caller may have
	explanationMax    = 600              // characters
	explanationLines  = 8
	originRemember    = 10 * time.Minute // a caller noted before its approval is made (flows run in goroutines)
	requestKindRepo   = "repo-key"
	requestKindGrant  = "grant"
	requestKindUnlock = "unlock"
)

// Caller: who called, from the credential the call carried
type Caller struct {
	Kind    string `json:"kind"`              // web | app | session | setup | actions | router
	Session string `json:"session,omitempty"` // kind session: the calling machine's session
}

// APICall: the endpoint the caller called and its arguments (the parsed ones, without the explanation)
type APICall struct {
	Method string         `json:"method"`
	Path   string         `json:"path"`
	Args   map[string]any `json:"args,omitempty"`
}

type Origin struct {
	Caller Caller  `json:"caller"`
	Call   APICall `json:"call"`
	// outcomes.go: a session's filing exactly as its machine signed it, and the item's index in it (a batch), so the
	// decision can be delivered into the session built from its own request
	Signed *SignedRequest `json:"signed,omitempty"`
	Item   int            `json:"item,omitempty"`
	Batch  string         `json:"batch,omitempty"`
	// apicalls.go: the API-call request whose approved call made this (its review sheet follows the approval)
	ViaCall string `json:"viaCall,omitempty"`
}

type RequestParams struct {
	Action    string `json:"action,omitempty"` // repo-key: add | remove
	Repo      string `json:"repo,omitempty"`   // repo-key: owner/name
	Sensitive bool   `json:"sensitive,omitempty"`
	// grant, unlock: the session it is for. repo-key add from a session: the session that asked, which gets the repo's
	// store in the same approval (repos.go repoFollowups; DECISIONS 182)
	Session string `json:"session,omitempty"`
	Holder  string `json:"holder,omitempty"`  // grant
	Minutes int    `json:"minutes,omitempty"` // grant: 1–10
	Days    int    `json:"days,omitempty"`    // a standing rule instead: 1–365 days
	// api-call (apicalls.go): the call to run as Deyao
	Method      string `json:"method,omitempty"`
	Path        string `json:"path,omitempty"` // with its query
	Body        string `json:"body,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	// restore (storerestore.go): the store and the version to put back
	Store string `json:"store,omitempty"`
	Seq   int    `json:"seq,omitempty"`
	// peer-message (peermsg.go): the words; Session is the receiving session, the caller the sending one
	Text string `json:"text,omitempty"`
}

type InboxRequest struct {
	ID          string        `json:"id"`
	Kind        string        `json:"kind"` // repo-key | grant | unlock | api-call | restore
	Params      RequestParams `json:"params"`
	Origin      Origin        `json:"origin"`
	Explanation string        `json:"explanation"`
	Created     time.Time     `json:"created"`
	Expires     time.Time     `json:"expires"`
	Key         string        `json:"key"`             // dedup: kind + params
	Batch       string        `json:"batch,omitempty"` // batches.go: filed in this batch
}

// what a caller may ask for: every kind, for any session. Every request still needs Deyao on the phone, which renders
// it from signed content and names the caller; a session's actions could already ask all of these (actions.go), so a
// narrower rule for its /m/api requests protected nothing (refusal audit, DECISIONS 189).
func callerMay(c Caller, kind string, p RequestParams) error {
	switch kind {
	case requestKindRestore, requestKindRepo, requestKindGrant, requestKindUnlock, requestKindCall:
		return nil
	case requestKindPeer: // only a session's own message (peermsg.go)
		if c.Kind == "session" && c.Session != "" {
			return nil
		}
		return errors.New("only a session sends a peer message")
	}
	return fmt.Errorf("unknown request kind %s", kind)
}

// cleanExplanation: the caller's words as plain text — control characters dropped (line breaks kept), at most
// explanationLines lines and explanationMax characters. Required from a session and the setup session.
func cleanExplanation(s string, required bool) (string, error) {
	s, err := plainLines(s)
	if err != nil {
		return "", err
	}
	if n := len([]rune(s)); n > explanationMax {
		return "", fmt.Errorf("explanation longer than %d characters (%d)", explanationMax, n)
	}
	if required && s == "" {
		return "", errors.New("an explanation is required: say why this is needed")
	}
	return s, nil
}

// plainLines: plain text — control characters dropped (line breaks kept), blank runs collapsed, at most
// explanationLines lines
func plainLines(s string) (string, error) {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	var b strings.Builder
	for _, ch := range s {
		switch {
		case ch == '\n':
			b.WriteRune(ch)
		case ch == '\t':
			b.WriteRune(' ')
		case unicode.IsControl(ch) || unicode.In(ch, unicode.Cf): // incl. bidi overrides and zero-width marks
		default:
			b.WriteRune(ch)
		}
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	out := []string{}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" && (len(out) == 0 || out[len(out)-1] == "") {
			continue
		}
		out = append(out, l)
	}
	if len(out) > explanationLines {
		return "", fmt.Errorf("explanation longer than %d lines", explanationLines)
	}
	return strings.Join(out, "\n"), nil
}

// normalize: the request's params checked and in one form (the dedup key depends on it)
func (r *Router) normalizeRequest(kind string, p RequestParams) (RequestParams, error) {
	switch kind {
	case requestKindRepo:
		repo := parseGitHubRepo(p.Repo)
		if repo == "" {
			return p, errors.New("a GitHub repo: owner/name or its URL")
		}
		if p.Action != "add" && p.Action != "remove" {
			return p, errors.New("action add or remove")
		}
		out := RequestParams{Action: p.Action, Repo: repo}
		if p.Action == "add" {
			out.Sensitive = p.Sensitive
			if p.Session != "" {
				var ok bool
				r.st.Do(func(d *persisted) {
					s := d.Sessions[p.Session]
					ok = s != nil && s.State != "destroyed" && s.State != "destroying"
				})
				if !ok {
					return p, fmt.Errorf("no session %q", p.Session)
				}
				out.Session = p.Session
			}
		}
		return out, nil
	case requestKindGrant, requestKindUnlock:
		var ok bool
		r.st.Do(func(d *persisted) {
			s := d.Sessions[p.Session]
			ok = s != nil && s.State != "destroyed" && s.State != "destroying"
		})
		if !ok {
			return p, fmt.Errorf("no session %q", p.Session)
		}
		if kind == requestKindUnlock {
			return RequestParams{Session: p.Session}, nil
		}
		known := false
		for _, h := range holderNames {
			known = known || h == p.Holder
		}
		if !known {
			return p, fmt.Errorf("holder is one of %s", strings.Join(holderNames, ", "))
		}
		out := RequestParams{Session: p.Session, Holder: p.Holder}
		switch {
		case p.Days != 0 && p.Minutes != 0:
			return p, errors.New("minutes (a grant) or days (a standing rule), not both")
		case p.Days != 0:
			if p.Days < 1 || p.Days > 365 {
				return p, errors.New("a standing rule lasts 1 to 365 days")
			}
			out.Days = p.Days
		default:
			if p.Minutes == 0 {
				p.Minutes = 10
			}
			if p.Minutes < 1 || p.Minutes > 10 {
				return p, errors.New("a grant lasts 1 to 10 minutes")
			}
			out.Minutes = p.Minutes
		}
		return out, nil
	case requestKindRestore:
		if p.Store == flyStore {
			return p, fmt.Errorf("store %s (the core's Fly token) is never restored: write it again with infra/setup.py backup-core", flyStore)
		}
		if !storeNameOK(p.Store) {
			return p, fmt.Errorf("no store %q", p.Store)
		}
		if p.Seq < 1 {
			return p, errors.New("seq: the version to put back (infra/setup.py versions STORE, or the Stores page)")
		}
		return RequestParams{Store: p.Store, Seq: p.Seq}, nil
	case requestKindPeer: // peermsg.go
		var ok bool
		r.st.Do(func(d *persisted) {
			s := d.Sessions[p.Session]
			ok = s != nil && s.State != "destroyed" && s.State != "destroying"
		})
		if !ok {
			return p, fmt.Errorf("no session %q", p.Session)
		}
		t := cleanPeerText(p.Text)
		if t == "" || len([]rune(t)) > peerNoteMax {
			return p, fmt.Errorf("a message of 1 to %d characters", peerNoteMax)
		}
		return RequestParams{Session: p.Session, Text: t}, nil
	case requestKindCall: // checked by fileCall (apicalls.go)
		return RequestParams{Method: p.Method, Path: p.Path, Body: p.Body, ContentType: p.ContentType}, nil
	}
	return p, fmt.Errorf("unknown request kind %s", kind)
}

func requestKey(kind string, p RequestParams) string {
	p.Repo = strings.ToLower(p.Repo)
	b, _ := json.Marshal(p)
	return kind + " " + string(b)
}

var errDuplicate = errors.New("duplicate")

// FileRequest: a request into the Inbox → it (or the same one already pending, dup true)
func (r *Router) FileRequest(kind string, p RequestParams, explanation string, o Origin) (*InboxRequest, bool, error) {
	p, err := r.normalizeRequest(kind, p)
	if err != nil {
		return nil, false, &badRequest{err.Error()}
	}
	if err := callerMay(o.Caller, kind, p); err != nil {
		return nil, false, &forbidden{err.Error()}
	}
	explanation, err = cleanExplanation(explanation, o.Caller.Kind == "session" || o.Caller.Kind == "setup" || o.Caller.Kind == "actions")
	if err != nil {
		return nil, false, &badRequest{err.Error()}
	}
	now := time.Now().UTC()
	q := &InboxRequest{ID: "q" + randID(), Kind: kind, Params: p, Origin: o, Explanation: explanation, Created: now, Expires: now.Add(inboxTTL), Key: requestKey(kind, p)}
	var dup *InboxRequest
	r.st.Do(func(d *persisted) {
		pruneRequests(d, now)
		for _, x := range d.Inbox {
			if x.Key == q.Key {
				dup = x
			}
		}
		if dup != nil {
			return
		}
		if mine, _ := callerLoad(d, o.Caller); mine >= requestPerCaller {
			err = &tooMany{fmt.Sprintf("this caller has %d requests waiting already: wait for Deyao to answer them, or deny some (DELETE /api/requests/ID, jarvis2-actions.py deny ID), then file again", requestPerCaller)}
			return
		}
		d.Inbox[q.ID] = q
	})
	if dup != nil {
		return dup, true, nil
	}
	return q, false, err
}

func pruneRequests(d *persisted, now time.Time) {
	if d.Inbox == nil {
		d.Inbox = map[string]*InboxRequest{}
	}
	for id, q := range d.Inbox {
		lapsed := !now.Before(q.Expires)
		gone := false
		if q.Kind == requestKindCall { // it waits while its session is paused; only a destroyed session's goes
			gone = gone || !callerExists(d, q.Origin.Caller)
		}
		if q.Params.Session != "" {
			s := d.Sessions[q.Params.Session]
			gone = gone || s == nil || s.State == "destroyed"
		}
		if lapsed || gone {
			delete(d.Inbox, id)
			oc := outcomeDropped
			if lapsed {
				oc = outcomeLapsed
			}
			noteOutcome(d, &q.Origin, q.Kind, q.ID, oc, 0, nil)
		}
	}
}

// dropRequests: requests that were done (by any path: a repo added from Settings answers a pending request too), with
// what the requesting session is told (outcomes.go; "" = nothing) and what vouches for it
func (r *Router) dropRequests(match func(q *InboxRequest) bool, outcome string, proof *Doc) {
	r.st.Do(func(d *persisted) {
		for id, q := range d.Inbox {
			if match(q) {
				delete(d.Inbox, id)
				if outcome != "" {
					noteOutcome(d, &q.Origin, q.Kind, q.ID, outcome, 0, proof)
				}
			}
		}
	})
}

// ---- who called -----------------------------------------------------------------------------------------

// appCaller: Deyao's own login. The iPhone app sends its device login in cf-access-token; a browser doesn't. A call
// the router runs for an approved API-call request (apicalls.go) carries its requester instead.
func appCaller(req *http.Request) Caller {
	if c, ok := req.Context().Value(onBehalfKey{}).(Caller); ok {
		return c
	}
	if req.Header.Get("cf-access-token") != "" {
		return Caller{Kind: "app"}
	}
	return Caller{Kind: "web"}
}

func callerText(d *persisted, c Caller) string {
	switch c.Kind {
	case "web":
		return "Deyao, from the web page"
	case "app":
		return "Deyao, from the Jarvis 4 app"
	case "setup":
		return "Claude (setup session)"
	case "actions":
		return "the actions of " + callerText(d, Caller{Kind: "session", Session: c.Session})
	case "session":
		title := c.Session
		if s := d.Sessions[c.Session]; s != nil {
			title = sessionTitle(*s)
		} else {
			for _, rec := range d.Records {
				if rec.ID == c.Session {
					title = sessionTitle(rec.Session)
				}
			}
		}
		if title == c.Session {
			return "session " + c.Session
		}
		return fmt.Sprintf("session “%s” (%s)", title, c.Session)
	}
	return "Jarvis 4 itself"
}

// originNotes: the caller of an action whose approval the router makes later, in a goroutine (resume, restore)
type originNotes struct {
	mu sync.Mutex
	m  map[string]noted
}
type noted struct {
	o  Origin
	at time.Time
}

var origins = &originNotes{m: map[string]noted{}}

// noteOrigin: the caller of the approval session sid gets next (and of one it has already, without a caller)
func (r *Router) noteOrigin(sid string, o Origin) {
	origins.mu.Lock()
	for k, v := range origins.m {
		if time.Since(v.at) > originRemember {
			delete(origins.m, k)
		}
	}
	origins.m[sid] = noted{o, time.Now()}
	origins.mu.Unlock()
	r.st.Do(func(d *persisted) {
		for _, a := range d.Approvals {
			if a.Session == sid && a.Origin == nil {
				oc := o
				a.Origin = &oc
				linkFollowup(d, a) // apicalls.go
			}
		}
	})
}

func takeOrigin(sid string) *Origin {
	origins.mu.Lock()
	defer origins.mu.Unlock()
	if v, ok := origins.m[sid]; ok && time.Since(v.at) <= originRemember {
		delete(origins.m, sid)
		return &v.o
	}
	return nil
}

// ---- the Inbox, as the app lists it ----------------------------------------------------------------------

// InboxItem: one entry. Title and core action are NOT here: the app renders them from kind + params (the list)
// and the shell from the signed content (the review page) — never from router prose.
type InboxItem struct {
	ID          string            `json:"id"`
	Kind        string            `json:"kind"` // repo-key | grant | unlock | new-session | resume-upgrade | add-store
	Approval    bool              `json:"approval"`
	Params      RequestParams     `json:"params"`
	Session     string            `json:"session,omitempty"`
	SessionName string            `json:"sessionName,omitempty"`
	Caller      Caller            `json:"caller"`
	CallerText  string            `json:"callerText"`
	Call        APICall           `json:"call"`
	Explanation string            `json:"explanation"`
	Created     time.Time         `json:"created"`
	Expires     *time.Time        `json:"expires,omitempty"`
	Options     map[string]string `json:"options,omitempty"` // an approval's unsigned form fields
	Open        map[string]any    `json:"open"`              // the shell page to open: {kind, options}
	Batch       string            `json:"batch,omitempty"`   // batches.go: reviewed together with the batch's other items
	ViaCall     string            `json:"viaCall,omitempty"` // apicalls.go: the API-call request whose approved call brought it about
	Does        string            `json:"does,omitempty"`    // an API call's effect in words, rendered by the router (callDoes)
}

func (r *Router) Inbox() []InboxItem {
	out := []InboxItem{}
	now := time.Now().UTC()
	r.expireApprovals(now)
	r.st.Do(func(d *persisted) {
		pruneRequests(d, now)
		pruneBatches(d, now)
		for _, q := range d.Inbox {
			out = append(out, requestItem(d, q, now))
		}
		for _, a := range d.Approvals {
			out = append(out, approvalItem(d, a))
		}
		out = append(out, messageInboxItems(d)...) // messages.go
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

func (r *Router) InboxItem(id string) (InboxItem, bool) {
	for _, it := range r.Inbox() {
		if it.ID == id {
			return it, true
		}
	}
	return InboxItem{}, false
}

func inboxSessionName(d *persisted, sid string) string {
	if s := d.Sessions[sid]; s != nil {
		return sessionTitle(*s)
	}
	return sid
}

func requestItem(d *persisted, q *InboxRequest, now time.Time) InboxItem {
	exp := q.Expires
	it := InboxItem{ID: q.ID, Kind: q.Kind, Params: q.Params, Session: q.Params.Session, Caller: q.Origin.Caller,
		CallerText: callerText(d, q.Origin.Caller), Call: q.Origin.Call, Explanation: q.Explanation, Created: q.Created, Expires: &exp,
		Batch: q.Batch}
	opts := map[string]any{"inboxId": q.ID}
	switch q.Kind {
	case requestKindRepo:
		opts["action"], opts["repo"], opts["sensitive"] = q.Params.Action, q.Params.Repo, q.Params.Sensitive
		if q.Params.Session != "" { // the store goes into this session in the same approval (repos.go)
			it.SessionName = inboxSessionName(d, q.Params.Session)
			opts["into"], opts["intoLabel"], opts["store"] = q.Params.Session, it.SessionName, repoStore(q.Params.Repo)
		}
	case requestKindGrant:
		it.SessionName = inboxSessionName(d, q.Params.Session)
		opts["sessionId"], opts["label"], opts["holder"] = q.Params.Session, it.SessionName, q.Params.Holder
		if q.Params.Days > 0 {
			opts["grantKind"], opts["until"] = "rule", now.Add(time.Duration(q.Params.Days)*24*time.Hour).Format(time.RFC3339)
		} else {
			opts["grantKind"], opts["minutes"] = "grant", q.Params.Minutes
		}
	case requestKindUnlock:
		it.SessionName = inboxSessionName(d, q.Params.Session)
		opts["sessionId"], opts["label"] = q.Params.Session, it.SessionName
	case requestKindRestore:
		opts["store"], opts["seq"] = q.Params.Store, q.Params.Seq
	case requestKindPeer: // its own review (one tap, no Face ID): Approve = POST /api/requests/{id}/approve
		it.SessionName = inboxSessionName(d, q.Params.Session)
		opts["session"], opts["sessionName"], opts["from"], opts["fromName"] = q.Params.Session, it.SessionName,
			q.Origin.Caller.Session, inboxSessionName(d, q.Origin.Caller.Session)
	case requestKindCall: // its own review sheet (app APICallReviewView, web pages/APICall.tsx): Approve = POST /api/requests/{id}/approve
		it.Session, it.SessionName = q.Origin.Caller.Session, inboxSessionName(d, q.Origin.Caller.Session)
		it.Does = callDoes(d, q.Params)
	}
	it.Open = map[string]any{"kind": q.Kind, "options": opts}
	return it
}

func approvalItem(d *persisted, a *Approval) InboxItem {
	o := Origin{Caller: Caller{Kind: "router"}}
	if a.Origin != nil {
		o = *a.Origin
	}
	it := InboxItem{ID: a.ID, Kind: a.Kind, Approval: true, Session: a.Session, SessionName: inboxSessionName(d, a.Session),
		Caller: o.Caller, CallerText: callerText(d, o.Caller), Call: o.Call, Explanation: a.Explanation, Created: a.Created, Options: a.Options,
		Batch: a.Batch, ViaCall: o.ViaCall}
	if b := d.Batches[a.Batch]; b != nil {
		exp := approvalDeadline(d, a)
		it.Expires = &exp
	}
	if a.Label != "" && d.Sessions[a.Session] == nil {
		it.SessionName = a.Label
	}
	it.Open = map[string]any{"kind": "approval", "options": map[string]any{"approvalId": a.ID, "inboxId": a.ID}}
	return it
}

// expireApprovals: an approval older than inboxTTL is rejected, exactly as Deny would (a new session disappears, a
// resume stays paused, an add-store is dropped); the caller asks again if it still needs it.
func (r *Router) expireApprovals(now time.Time) {
	var old []string
	r.st.Do(func(d *persisted) {
		for id, a := range d.Approvals {
			if !now.Before(approvalDeadline(d, a)) {
				old = append(old, id)
			}
		}
	})
	for _, id := range old {
		if err := r.RejectAs(id, outcomeLapsed); err == nil {
			log.Printf("inbox: approval %s expired after %s", id, inboxTTL)
		}
	}
}

func (r *Router) inboxLoop() {
	for {
		time.Sleep(time.Minute)
		now := time.Now().UTC()
		r.expireApprovals(now)
		r.st.Do(func(d *persisted) { pruneRequests(d, now); pruneBatches(d, now) })
	}
}

// Deny: drop a request; for an approval, reject it (a new session disappears, a resume stays paused); a held message
// is denied (messages.go)
func (r *Router) DenyRequest(id string) error {
	if r.isMessage(id) {
		if len(r.DenyMessages([]string{id})) == 0 {
			return errAlreadyGone
		}
		return nil
	}
	var found bool
	r.st.Do(func(d *persisted) {
		if q, ok := d.Inbox[id]; ok {
			delete(d.Inbox, id)
			found = true
			noteOutcome(d, &q.Origin, q.Kind, q.ID, outcomeDenied, 0, nil)
			if q.Kind == requestKindCall { // the caller reads that it was denied
				pruneCallResults(d, time.Now().UTC())
				d.CallResults[id] = &CallResult{ID: id, Caller: q.Origin.Caller, Method: q.Params.Method, Path: q.Params.Path, State: "denied", At: time.Now().UTC()}
			}
		}
	})
	if found {
		return nil
	}
	if r.Reject(id) != nil {
		return errAlreadyGone
	}
	return nil
}

// errAlreadyGone: a deny of something no longer waiting (answered, denied or lapsed): what was asked for holds, so it
// is answered 200 {ok, gone} (refusal audit, DECISIONS 189)
var errAlreadyGone = errors.New("already gone (answered, denied or lapsed)")

// writeDenied: a deny's answer
func writeDenied(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errAlreadyGone):
		writeJSON(w, 200, map[string]any{"ok": true, "gone": true})
	case err != nil:
		writeErr(w, err)
	default:
		writeJSON(w, 200, map[string]bool{"ok": true})
	}
}

// ---- the intent endpoints, for each kind of caller ---------------------------------------------------------

// requestIn: what the intent endpoints take
type requestIn struct {
	Repo        string `json:"repo"`
	Sensitive   bool   `json:"sensitive"`
	NoStore     bool   `json:"noStore"` // repo/add from a session: don't add the repo's store to the asking session
	Session     string `json:"session"`
	Holder      string `json:"holder"`
	Minutes     int    `json:"minutes"`
	Days        int    `json:"days"`
	Store       string `json:"store"`
	Seq         int    `json:"seq"`
	Explanation string `json:"explanation"`
}

// intents: path suffix → kind + params from the body
var intents = map[string]func(in requestIn) (string, RequestParams){
	"repo/add": func(in requestIn) (string, RequestParams) {
		return requestKindRepo, RequestParams{Action: "add", Repo: in.Repo, Sensitive: in.Sensitive}
	},
	"repo/remove": func(in requestIn) (string, RequestParams) {
		return requestKindRepo, RequestParams{Action: "remove", Repo: in.Repo}
	},
	"grant": func(in requestIn) (string, RequestParams) {
		return requestKindGrant, RequestParams{Session: in.Session, Holder: in.Holder, Minutes: in.Minutes, Days: in.Days}
	},
	"unlock": func(in requestIn) (string, RequestParams) {
		return requestKindUnlock, RequestParams{Session: in.Session}
	},
	"restore": func(in requestIn) (string, RequestParams) {
		return requestKindRestore, RequestParams{Store: in.Store, Seq: in.Seq}
	},
}

// ownSession: what a session leaves out is its own — the session of a grant or an unlock, and, for a repo it asks to
// be added, the session that gets the repo's store in the same approval (unless noStore)
func ownSession(c Caller, kind string, p RequestParams, in requestIn) RequestParams {
	switch {
	case c.Kind == "session" && p.Session == "" && kind != requestKindRepo:
		p.Session = c.Session
	case (c.Kind == "session" || c.Kind == "actions") && kind == requestKindRepo && p.Action == "add" && !in.NoStore:
		p.Session = c.Session
	}
	return p
}

// callArgs: the arguments as the router understood them (shown as the API call; the explanation is shown apart)
func callArgs(kind string, p RequestParams) map[string]any {
	switch kind {
	case requestKindRepo:
		a := map[string]any{"repo": p.Repo}
		if p.Sensitive {
			a["sensitive"] = true
		}
		if p.Session != "" {
			a["into"] = p.Session
		}
		return a
	case requestKindGrant:
		a := map[string]any{"session": p.Session, "holder": p.Holder}
		if p.Days > 0 {
			a["days"] = p.Days
		} else {
			a["minutes"] = p.Minutes
		}
		return a
	case requestKindRestore:
		return map[string]any{"store": p.Store, "seq": p.Seq}
	}
	return map[string]any{"session": p.Session}
}

type forbidden struct{ msg string }

// tooMany: a caller over its limit of waiting asks (429)
type tooMany struct{ msg string }

func (t *tooMany) Error() string { return t.msg }

func (f *forbidden) Error() string { return f.msg }

func writeRequestErr(w http.ResponseWriter, err error) {
	var b *badRequest
	var f *forbidden
	var tm *tooMany
	switch {
	case errors.As(err, &tm):
		writeJSON(w, 429, map[string]string{"error": tm.msg})
	case errors.As(err, &b):
		writeJSON(w, 400, map[string]string{"error": b.msg})
	case errors.As(err, &f):
		writeJSON(w, 403, map[string]string{"error": f.msg})
	default:
		writeErr(w, err)
	}
}

// fileIntent: one intent endpoint call → 200 {id, duplicate, expires} or 202 {approval} for add-store
func (r *Router) fileIntent(w http.ResponseWriter, method, path, intent string, c Caller, body []byte, signed *SignedRequest) {
	var in requestIn
	if len(body) > 0 {
		if err := json.Unmarshal(body, &in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
			return
		}
	}
	mk := intents[intent]
	if mk == nil {
		writeJSON(w, 404, map[string]string{"error": "no such request: " + intent})
		return
	}
	kind, p := mk(in)
	p = ownSession(c, kind, p, in)
	np, err := r.normalizeRequest(kind, p)
	if err != nil {
		writeRequestErr(w, &badRequest{err.Error()})
		return
	}
	q, dup, err := r.FileRequest(kind, np, in.Explanation, Origin{Caller: c, Call: APICall{Method: method, Path: path, Args: callArgs(kind, np)}, Signed: signed})
	if err != nil {
		writeRequestErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"id": q.ID, "duplicate": dup, "expires": q.Expires})
}

func (r *Router) registerInbox(app appRoute, m machineRoute, public publicRoute) {
	readBody := func(req *http.Request) []byte { b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20)); return b } // a batch of 20 new sessions with their prompts
	// ---- the app and the web page (Deyao's Access login) ----
	app("GET /api/requests", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, 200, map[string]any{"requests": r.Inbox(), "batches": r.InboxBatches(nil)})
	})
	app("GET /api/requests/{id}", func(w http.ResponseWriter, req *http.Request) {
		it, ok := r.InboxItem(req.PathValue("id"))
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "this request is gone (answered, denied or expired)"})
			return
		}
		writeJSON(w, 200, it)
	})
	app("DELETE /api/requests/{id}", func(w http.ResponseWriter, req *http.Request) {
		writeDenied(w, r.DenyRequest(req.PathValue("id")))
	})
	// done: the shell's page went through (the phone signed it); the request leaves the Inbox. An approval leaves
	// by itself when it is answered.
	app("POST /api/requests/{id}/done", func(w http.ResponseWriter, req *http.Request) {
		id := req.PathValue("id")
		r.dropRequests(func(q *InboxRequest) bool { return q.ID == id }, outcomeApproved, nil)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	// approve an API-call request (apicalls.go): the call runs now as Deyao (this request's Access login)
	app("POST /api/requests/{id}/approve", func(w http.ResponseWriter, req *http.Request) {
		if r.isPeerRequest(req.PathValue("id")) { // an upward peer message (peermsg.go): one tap delivers it
			out, err := r.ApprovePeer(req.PathValue("id"))
			if errors.Is(err, errNoRequest) {
				writeJSON(w, 404, map[string]string{"error": err.Error()})
				return
			}
			if err != nil {
				writeErr(w, err)
				return
			}
			writeJSON(w, 200, out)
			return
		}
		res, err := r.ApproveCall(req.PathValue("id"), req)
		if errors.Is(err, errNoRequest) {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		out := map[string]any{"ok": res.State == "done", "state": res.State, "status": res.Status, "error": res.Error}
		if f, ok := r.CallFollowupsOf(res.ID); ok { // the sheet stays up for these (apicalls.go)
			out["followups"], out["awaiting"] = f.Followups, f.Awaiting
		}
		writeJSON(w, 200, out)
	})
	// followups: the core requests an approved API call brought about, and whether one may still come (apicalls.go)
	app("GET /api/requests/calls/{id}", func(w http.ResponseWriter, req *http.Request) {
		f, ok := r.CallFollowupsOf(req.PathValue("id"))
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "no approved call " + req.PathValue("id") + " (or its result is over " + inboxTTL.String() + " old)"})
			return
		}
		writeJSON(w, 200, f)
	})
	// batches (batches.go): several items filed together, reviewed on one page under one Face ID
	app("POST /api/requests/batch", func(w http.ResponseWriter, req *http.Request) {
		r.serveFileBatch(w, appCaller(req), req.Method, req.URL.Path, readBody(req), nil)
	})
	app("GET /api/requests/batches/{id}", func(w http.ResponseWriter, req *http.Request) { r.serveBatch(w, req.PathValue("id"), nil) })
	app("DELETE /api/requests/batches/{id}", func(w http.ResponseWriter, req *http.Request) { r.serveDenyBatch(w, req.PathValue("id")) })
	for intent := range intents {
		app("POST /api/requests/"+intent, func(w http.ResponseWriter, req *http.Request) {
			r.fileIntent(w, req.Method, req.URL.Path, intent, appCaller(req), readBody(req), nil)
		})
	}

	// ---- the setup session (Claude): its Access token and the setup key's signature ----
	setupOnly := func(fn func(w http.ResponseWriter, req *http.Request, body []byte)) http.Handler {
		return r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
			b := readBody(req)
			if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), b); err != nil {
				writeJSON(w, 401, map[string]string{"error": err.Error()})
				return
			}
			fn(w, req, b)
		})
	}
	public("GET /setup/requests", setupOnly(func(w http.ResponseWriter, req *http.Request, _ []byte) {
		writeJSON(w, 200, map[string]any{"requests": r.Inbox(), "batches": r.InboxBatches(nil)})
	}))
	// the sessions and their current machines (ids and states only): the phone replica runs jarvis2-request in a
	// session's machine (flyctl exec) and finds it here, since machines carry no router env any more
	public("GET /setup/sessions", setupOnly(func(w http.ResponseWriter, req *http.Request, _ []byte) {
		out := []map[string]any{}
		r.st.Do(func(d *persisted) {
			for _, s := range d.Sessions {
				v := map[string]any{"id": s.ID, "machineId": s.MachineID, "state": s.State, "title": sessionTitle(*s), "image": s.Image, "stores": s.Stores}
				// the autopilot's view (no secrets): what the machine last reported and the stall watchdog's clock
				if l := s.Live; l != nil {
					v["lastReport"], v["nudgeAt"], v["nudgeError"], v["needsGrant"] = l.LastReport, l.NudgeAt, l.NudgeError, l.NeedsGrant
					if g := l.Reg; g != nil {
						v["status"], v["bgTasks"], v["statusUpdatedAt"] = g.Status, g.BgTasks, g.StatusUpdatedAt
					}
					if l.Stall != nil {
						v["stallSince"] = l.Stall.At
					}
					v["busy"] = r.busy(s.ID)
				}
				out = append(out, v)
			}
		})
		writeJSON(w, 200, map[string]any{"sessions": out})
	}))
	public("GET /setup/repos", setupOnly(func(w http.ResponseWriter, req *http.Request, _ []byte) {
		writeJSON(w, 200, map[string]any{"repos": r.Repos()})
	}))
	public("POST /setup/requests/batch", setupOnly(func(w http.ResponseWriter, req *http.Request, b []byte) {
		r.serveFileBatch(w, Caller{Kind: "setup"}, req.Method, req.URL.Path, b, nil)
	}))
	public("GET /setup/requests/batches/{id}", setupOnly(func(w http.ResponseWriter, req *http.Request, _ []byte) {
		r.serveBatch(w, req.PathValue("id"), nil)
	}))
	for intent := range intents {
		public("POST /setup/requests/"+intent, setupOnly(func(w http.ResponseWriter, req *http.Request, b []byte) {
			r.fileIntent(w, req.Method, req.URL.Path, intent, Caller{Kind: "setup"}, b, nil)
		}))
	}

	// ---- a session (its machine key, through the machine's local proxy: $JARVIS_URL/api/requests/…) ----
	own := func(fn func(w http.ResponseWriter, req *http.Request, sid string, body []byte)) func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		return func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
			sid, err := r.machineSession(machine)
			if err != nil {
				writeJSON(w, 403, map[string]string{"error": err.Error()})
				return
			}
			fn(w, req, sid, body)
		}
	}
	m("GET /m/api/requests", own(func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		mine := []InboxItem{}
		c := Caller{Kind: "session", Session: sid}
		for _, it := range r.Inbox() {
			if it.Caller == c {
				mine = append(mine, it)
			}
		}
		writeJSON(w, 200, map[string]any{"requests": mine, "batches": r.InboxBatches(&c)})
	}))
	m("POST /m/api/requests/batch", own(func(w http.ResponseWriter, req *http.Request, sid string, b []byte) {
		r.serveFileBatch(w, Caller{Kind: "session", Session: sid}, req.Method, strings.TrimPrefix(req.URL.Path, "/m"), b, signedRequestOf(req, req.Header.Get("X-Machine"), b))
	}))
	m("GET /m/api/requests/batches/{id}", own(func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		r.serveBatch(w, req.PathValue("id"), &Caller{Kind: "session", Session: sid})
	}))
	for intent := range intents {
		m("POST /m/api/requests/"+intent, own(func(w http.ResponseWriter, req *http.Request, sid string, b []byte) {
			r.fileIntent(w, req.Method, strings.TrimPrefix(req.URL.Path, "/m"), intent, Caller{Kind: "session", Session: sid}, b, signedRequestOf(req, req.Header.Get("X-Machine"), b))
		}))
	}
	// one more store for this session: the router's add-store approval, with the caller's explanation
	m("POST /m/api/requests/add-store", own(func(w http.ResponseWriter, req *http.Request, sid string, b []byte) {
		var in requestIn
		json.Unmarshal(b, &in)
		expl, err := cleanExplanation(in.Explanation, true)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		var machine string
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[sid]; s != nil {
				machine = s.MachineID
			}
		})
		o := Origin{Caller: Caller{Kind: "session", Session: sid}, Call: APICall{Method: "POST", Path: "/api/requests/add-store", Args: map[string]any{"store": in.Store}},
			Signed: signedRequestOf(req, req.Header.Get("X-Machine"), b)}
		if err := r.AddStoreFrom(machine, in.Store, o, expl, ""); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "approval": true})
	}))
}

func init() {
	stateHooks = append(stateHooks, func(r *Router, out map[string]any) {
		if r != nil {
			out["inbox"] = r.Inbox()
			out["inboxBatches"] = r.InboxBatches(nil)
		}
	})
	onDestroy = append(onDestroy, func(r *Router, s Session) {
		r.dropRequests(func(q *InboxRequest) bool { return q.Params.Session == s.ID }, outcomeDropped, nil)
	})
}
