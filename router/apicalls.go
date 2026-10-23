package main

// API-call requests (Deyao, 2026-10-13): a session's actions (actions.go) may ask for ANY app API call — one of the
// routes only Deyao's Access login reaches — to be run as Deyao. The request waits in the Inbox (kind "api-call")
// with its method, path and body; Deyao approves it from the app or the web page (no Face ID for the approval: a
// step that needs the core's signature, such as the terminal grant behind a switch to bypass, still asks for its own
// Face ID afterwards). The router then runs the call through its own public mux carrying the approver's own Access
// login (so the route's requireDeyao checks Deyao himself), and keeps the outcome for inboxTTL; the requesting
// session reads it back (GET /m/api/actions/requests/call/{id}).
//
// callRules classifies every app route (TestEveryAppRouteClassified fails on a new route left out):
//   callBody    the call may be requested and its status and response body go back to the session
//   callStatus  may be requested, but the response carries a credential, so only the status goes back
//   callNo      never requestable: the Inbox itself (a request can't approve or file another), or a call that can't be
//               run server-side or would hand out Deyao's own login

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"
)

const (
	requestKindCall = "api-call"
	callBodyMax     = 64 << 10 // a requested call's body, kept in the Inbox
	callResultMax   = 1 << 20  // a call's response kept for the session
)

type callRule int

const (
	callNo callRule = iota
	callBody
	callStatus
)

// CallResult: what an approved (or denied) API-call request came to, kept inboxTTL for its caller
type CallResult struct {
	ID          string    `json:"id"`
	Caller      Caller    `json:"caller"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	State       string    `json:"state"` // running | done | denied | failed
	Status      int       `json:"status,omitempty"`
	ContentType string    `json:"contentType,omitempty"`
	Body        string    `json:"body,omitempty"`
	Withheld    bool      `json:"withheld,omitempty"` // callStatus: the body carried a credential
	Error       string    `json:"error,omitempty"`
	ApprovedBy  string    `json:"approvedBy,omitempty"` // app | web
	At          time.Time `json:"at"`
	// the core requests the call brought about (approvals whose Origin.ViaCall is this call), and, while one may
	// still come, what the router waits on: the review sheet follows exactly these, never a guess
	Followups []string   `json:"followups,omitempty"`
	Awaiting  *CallAwait `json:"awaiting,omitempty"`
}

// CallAwait: an approved call started work that may still file a core request (a resume asking the core): the
// sheet waits for it until Until, or until the router says nothing more comes (Awaiting cleared)
type CallAwait struct {
	Session string    `json:"session,omitempty"`
	Until   time.Time `json:"until"`
}

// followupWait: how long an approved call's sheet waits for a request the call's work may still file. The work is
// router-side (a challenge, one core call): seconds; a minute covers a slow core.
const followupWait = time.Minute

// callIn: what POST /m/api/actions/requests/call takes. body is any JSON value (sent as application/json);
// bodyText a raw body with its contentType instead.
type callIn struct {
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	Body        json.RawMessage `json:"body"`
	BodyText    string          `json:"bodyText"`
	ContentType string          `json:"contentType"`
	Explanation string          `json:"explanation"`
}

// callRoute: the app route a method + path (with its query) reaches, and its rule
func (r *Router) callRoute(method, target string) (string, callRule, error) {
	u, err := url.Parse(target)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/") {
		return "", callNo, errors.New("path: an absolute path on the router, e.g. /api/sessions/ID/permission-mode")
	}
	r.handlers()
	req := httptest.NewRequest(method, u.RequestURI(), nil)
	_, pattern := r.publicMux.Handler(req)
	if pattern == "" {
		return "", callNo, fmt.Errorf("no route %s %s", method, u.Path)
	}
	rule, known := callRules[pattern]
	if !r.appPatterns[pattern] || !known {
		return pattern, callNo, fmt.Errorf("%s is not an app API call", pattern)
	}
	if rule == callNo {
		return pattern, callNo, fmt.Errorf("%s can't be requested (%s)", pattern, callNoWhy(pattern))
	}
	return pattern, rule, nil
}

func callNoWhy(pattern string) string {
	if strings.Contains(pattern, "/api/requests") || strings.Contains(pattern, "/api/approvals") {
		return "the Inbox itself"
	}
	return "it would hand out Deyao's own login, or it can't run on the router"
}

// checkCall: a requested call as the Inbox keeps it (method, path, body) and the arguments shown as its call, or why
// it can't be requested
func (r *Router) checkCall(in callIn) (RequestParams, map[string]any, error) {
	in.Method = strings.ToUpper(strings.TrimSpace(in.Method))
	switch in.Method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
	default:
		return RequestParams{}, nil, errors.New("method: GET, POST, PUT, PATCH or DELETE")
	}
	p := RequestParams{Method: in.Method, Path: strings.TrimSpace(in.Path)}
	switch {
	case len(in.Body) > 0 && string(in.Body) != "null" && in.BodyText != "":
		return p, nil, errors.New("body (JSON) or bodyText, not both")
	case len(in.Body) > 0 && string(in.Body) != "null":
		var compact bytes.Buffer
		if err := json.Compact(&compact, in.Body); err != nil {
			return p, nil, errors.New("body: " + err.Error())
		}
		p.Body, p.ContentType = compact.String(), "application/json"
	case in.BodyText != "":
		p.Body, p.ContentType = in.BodyText, in.ContentType
		if p.ContentType == "" {
			p.ContentType = "text/plain"
		}
	}
	if len(p.Body) > callBodyMax {
		return p, nil, fmt.Errorf("body over %d KB", callBodyMax>>10)
	}
	pattern, _, err := r.callRoute(p.Method, p.Path)
	if err != nil {
		return p, nil, err
	}
	args := map[string]any{"method": p.Method, "path": p.Path, "route": pattern}
	if p.Body != "" {
		args["body"] = p.Body
	}
	return p, args, nil
}

// fileCall: an API-call request into the Inbox → {id, duplicate, expires}
func (r *Router) fileCall(w http.ResponseWriter, c Caller, path string, b []byte, signed *SignedRequest) {
	var in callIn
	if err := json.Unmarshal(b, &in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
		return
	}
	p, args, err := r.checkCall(in)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	q, dup, err := r.FileRequest(requestKindCall, p, in.Explanation, Origin{Caller: c, Call: APICall{Method: "POST", Path: path, Args: args}, Signed: signed})
	if err != nil {
		writeRequestErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"id": q.ID, "duplicate": dup, "expires": q.Expires})
}

// sameSessionCaller: the session's own two credentials (its requests and its actions, both its machine key) are one
// caller for reading a call's result: a call filed in a session's batch (jarvis2-request) is read like its actions' own
func sameSessionCaller(a, b Caller) bool {
	own := func(c Caller) bool { return (c.Kind == "session" || c.Kind == "actions") && c.Session != "" }
	return a == b || own(a) && own(b) && a.Session == b.Session
}

// callerExists: the requesting session is still there (any state but destroyed). An approved call runs as Deyao, so
// it needs no running session; its result and outcome wait for the session's next run (refusal audit, DECISIONS 189).
func callerExists(d *persisted, c Caller) bool {
	if c.Kind != "session" && c.Kind != "actions" {
		return true // the setup session, the app or the web page: no session to end with
	}
	s := d.Sessions[c.Session]
	return s != nil && s.State != "destroyed"
}

// ApproveCall: Deyao's approval of an API-call request: the call runs now, as him (his Access login from the
// approving request), and its outcome is kept for the caller
func (r *Router) ApproveCall(id string, approver *http.Request) (*CallResult, error) {
	var q *InboxRequest
	r.st.Do(func(d *persisted) {
		pruneRequests(d, time.Now().UTC())
		if x := d.Inbox[id]; x != nil && x.Kind == requestKindCall {
			q = x
			delete(d.Inbox, id)
		}
	})
	if q == nil {
		return nil, errNoRequest
	}
	defer func() { // outcomes.go: the requesting session is told (its result stays readable for inboxTTL)
		r.st.Do(func(d *persisted) {
			x := d.CallResults[q.ID]
			if x == nil {
				return
			}
			if x.State == "done" {
				noteOutcome(d, &q.Origin, q.Kind, q.ID, outcomeApproved, x.Status, nil)
			} else {
				noteOutcome(d, &q.Origin, q.Kind, q.ID, outcomeFailed, 0, nil)
			}
		})
	}()
	res := &CallResult{ID: q.ID, Caller: q.Origin.Caller, Method: q.Params.Method, Path: q.Params.Path, ApprovedBy: appCaller(approver).Kind, At: time.Now().UTC()}
	pattern, rule, err := r.callRoute(q.Params.Method, q.Params.Path)
	if err != nil {
		res.State, res.Error = "failed", err.Error()
		r.keepCallResult(res)
		return res, nil
	}
	running0 := *res
	running0.State = "running"
	r.keepCallResult(&running0) // the approvals the call files link to it while it runs (linkFollowup)
	ctx := context.WithValue(context.WithValue(approver.Context(), onBehalfKey{}, q.Origin.Caller), viaCallKey{}, q.ID)
	req := httptest.NewRequest(q.Params.Method, q.Params.Path, strings.NewReader(q.Params.Body)).WithContext(ctx)
	for _, h := range []string{"Cf-Access-Jwt-Assertion", "cf-access-token", "Cf-Access-Authenticated-User-Email"} {
		if v := approver.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	if q.Params.ContentType != "" {
		req.Header.Set("Content-Type", q.Params.ContentType)
	}
	rec := httptest.NewRecorder()
	r.publicMux.ServeHTTP(rec, req)
	res.State, res.Status, res.ContentType = "done", rec.Code, rec.Header().Get("Content-Type")
	if rule == callStatus {
		res.Withheld = true
	} else {
		body := rec.Body.Bytes()
		if len(body) > callResultMax {
			body, res.Error = body[:callResultMax], fmt.Sprintf("response cut at %d KB", callResultMax>>10)
		}
		res.Body = string(body)
	}
	log.Printf("api-call %s: %s %s (%s) for %s, approved from the %s: %d", q.ID, q.Params.Method, q.Params.Path, pattern,
		q.Origin.Caller.Session, res.ApprovedBy, res.Status)
	r.keepCallResult(res)
	return res, nil
}

// onBehalfKey: the context value naming whose approved call the router is running (appCaller)
type onBehalfKey struct{}

// viaCallKey: the context value naming the API-call request whose approved call the router is running: the
// approvals the call's handler files (or notes an origin for) are linked to it (Origin.ViaCall)
type viaCallKey struct{}

// viaCall: the API-call request a request runs for ("" for Deyao's own calls)
func viaCall(req *http.Request) string {
	id, _ := req.Context().Value(viaCallKey{}).(string)
	return id
}

// expectFollowup: the handler of an approved call started work that may file a core request for session sid
// later (a resume): the call's sheet waits for it. Called BEFORE the work starts, so the work's own end
// (settleFollowups) or its request (linkFollowup) always comes after and clears it.
func (r *Router) expectFollowup(req *http.Request, sid string) {
	id := viaCall(req)
	if id == "" {
		return
	}
	r.st.Do(func(d *persisted) {
		if x := d.CallResults[id]; x != nil && len(x.Followups) == 0 {
			x.Awaiting = &CallAwait{Session: sid, Until: time.Now().UTC().Add(followupWait)}
		}
	})
}

// settleFollowups: the work on session sid ended; a call waiting on it gets nothing more (inside or outside st.Do)
func (r *Router) settleFollowups(sid string) {
	r.st.Do(func(d *persisted) {
		for _, x := range d.CallResults {
			if x.Awaiting != nil && x.Awaiting.Session == sid {
				x.Awaiting = nil
			}
		}
	})
}

// linkFollowup: an approval whose origin is an approved call joins that call's follow-ups (inside st.Do)
func linkFollowup(d *persisted, a *Approval) {
	if a.Origin == nil || a.Origin.ViaCall == "" {
		return
	}
	x := d.CallResults[a.Origin.ViaCall]
	if x == nil {
		return
	}
	if !containsString(x.Followups, a.ID) {
		x.Followups = append(x.Followups, a.ID)
	}
	x.Awaiting = nil
}

// CallFollowups: what the review sheet of an API call shows after Approve: the call's outcome, each core request it
// brought about (the Inbox item while it waits; gone = answered, denied or lapsed) and what may still come
type CallFollowups struct {
	ID        string         `json:"id"`
	State     string         `json:"state"`
	Status    int            `json:"status,omitempty"`
	Error     string         `json:"error,omitempty"`
	Followups []CallFollowup `json:"followups"`
	Awaiting  *CallAwait     `json:"awaiting,omitempty"`
}

type CallFollowup struct {
	ID   string     `json:"id"`
	Open bool       `json:"open"`           // still in the Inbox
	Item *InboxItem `json:"item,omitempty"` // while open: the item, opened like any other (its signed page)
}

func (r *Router) CallFollowupsOf(id string) (CallFollowups, bool) {
	var x CallResult
	ok := false
	r.st.Do(func(d *persisted) {
		now := time.Now().UTC()
		pruneCallResults(d, now)
		if c := d.CallResults[id]; c != nil {
			if c.Awaiting != nil && !now.Before(c.Awaiting.Until) {
				c.Awaiting = nil
			}
			x, ok = *c, true
		}
	})
	if !ok {
		return CallFollowups{}, false
	}
	out := CallFollowups{ID: x.ID, State: x.State, Status: x.Status, Error: x.Error, Followups: []CallFollowup{}, Awaiting: x.Awaiting}
	for _, fid := range x.Followups {
		f := CallFollowup{ID: fid}
		if it, open := r.InboxItem(fid); open {
			f.Open, f.Item = true, &it
		}
		out.Followups = append(out.Followups, f)
	}
	return out, true
}

var errNoRequest = errors.New("this request is gone (answered, denied or expired)")

// keepCallResult: the call's outcome; the follow-ups linked while it ran stay, and a call that failed brings
// nothing more about
func (r *Router) keepCallResult(res *CallResult) {
	r.st.Do(func(d *persisted) {
		pruneCallResults(d, time.Now().UTC())
		if old := d.CallResults[res.ID]; old != nil && old != res {
			res.Followups, res.Awaiting = old.Followups, old.Awaiting
		}
		if res.State == "failed" || res.Status >= 400 {
			res.Awaiting = nil
		}
		d.CallResults[res.ID] = res
	})
}

func pruneCallResults(d *persisted, now time.Time) {
	if d.CallResults == nil {
		d.CallResults = map[string]*CallResult{}
	}
	for id, x := range d.CallResults {
		if now.Sub(x.At) >= inboxTTL {
			delete(d.CallResults, id)
		}
	}
}

// serveCallResult: the caller's own request: pending while it waits, then its outcome
func (r *Router) serveCallResult(w http.ResponseWriter, c Caller, id string) {
	var out any
	r.st.Do(func(d *persisted) {
		now := time.Now().UTC()
		pruneRequests(d, now)
		pruneCallResults(d, now)
		if q := d.Inbox[id]; q != nil && q.Kind == requestKindCall && sameSessionCaller(q.Origin.Caller, c) {
			out = map[string]any{"id": id, "state": "pending", "expires": q.Expires}
		} else if x := d.CallResults[id]; x != nil && sameSessionCaller(x.Caller, c) {
			out = x
		}
	})
	if out == nil {
		writeJSON(w, 404, map[string]string{"error": "no such request of this session (expired, or its result is over " + inboxTTL.String() + " old)"})
		return
	}
	writeJSON(w, 200, out)
}

// callRules: every app route (the 2026-10-13 sweep). A new app route needs its line here (TestEveryAppRouteClassified).
var callRules = map[string]callRule{
	"GET /api/messages":                           callNo, // the Inbox: messages held for Deyao (messages.go)
	"POST /api/messages/draft":                    callNo, // the Inbox
	"POST /api/messages/approve":                  callNo, // the Inbox: takes the phone's signature
	"POST /api/messages/deny":                     callNo, // the Inbox
	"GET /api/sessions/{id}/message-rules":        callNo, // Deyao's per-kind delivery rules
	"POST /api/sessions/{id}/message-rules":       callNo, // takes a phone-signed rule
	"POST /api/sessions/{id}/message-rules/draft": callNo,
	"DELETE /api/message-rules/{rid}":             callNo,
	"GET /api/approvals":                          callNo,     // the Inbox
	"POST /api/approvals/{id}/reject":             callNo,     // the Inbox
	"POST /api/approvals/{id}/respond":            callNo,     // the Inbox
	"GET /api/auth/start":                         callNo,     // hands out Deyao's Access login (a jarvis2:// redirect carrying it)
	"GET /api/backups":                            callStatus, // every store's sealed backup
	"POST /api/backups/fallback":                  callBody,   // an export the app saved, served only while the bucket fails
	"DELETE /api/backups/fallback":                callBody,
	"DELETE /api/claude-accounts/{store}":         callBody,
	"GET /api/claude-accounts":                    callBody,
	"GET /api/claude-accounts/{store}/usage":      callBody,
	"POST /api/claude-accounts":                   callStatus, // the OAuth sign-in URL with its state and PKCE challenge
	"POST /api/claude-accounts/{store}/code":      callBody,
	"POST /api/claude-accounts/{store}/default":   callBody,
	"POST /api/claude-accounts/{store}/login":     callStatus, // the OAuth sign-in URL with its state and PKCE challenge
	"POST /api/claude-accounts/{store}/refresh":   callBody,
	"GET /api/claude-login":                       callBody,
	"POST /api/claude-login/code":                 callBody,
	"POST /api/claude-login/refresh":              callBody,
	"POST /api/claude-login/start":                callStatus, // the OAuth sign-in URL with its state and PKCE challenge
	"GET /api/content":                            callBody,
	"POST /api/content":                           callBody,
	"DELETE /api/content/{name}":                  callBody,
	"DELETE /api/content/{name}/file":             callBody,
	"GET /api/content/{name}/file":                callBody,
	"POST /api/content/{name}/file":               callBody,
	"GET /api/content/{name}/files":               callBody,
	"POST /api/core/claim":                        callNo, // the iPhone app's Recover, signed by the master key
	"GET /api/core/identity":                      callBody,
	"GET /api/core/line-state":                    callBody, // sealed by the core: nothing in it opens outside a core from the same kit
	"POST /api/core/lock":                         callBody,
	"POST /api/core/store-key":                    callBody,
	"POST /api/core/stores":                       callBody,
	"POST /api/core/stores/create":                callBody,
	"POST /api/core/stores/mark-sensitive":        callBody,
	"POST /api/core/stores/restore/begin":         callNo, // half of a restore the phone finishes with its signature and shares
	"POST /api/core/stores/versions":              callBody,
	"POST /api/core/unlock/begin":                 callNo, // half of an unlock the phone finishes with its sealed share
	"POST /api/core/unlock/finish":                callNo, // needs the phone's sealed share
	"POST /api/core/unlocked":                     callBody,
	"POST /api/core/wipe":                         callNo, // the iPhone app's Reset, signed by the master key
	"GET /api/devices":                            callBody,
	"GET /api/devices/pair":                       callNo, // mints a device service token: a login of its own
	"DELETE /api/devices/{id}":                    callBody,
	"GET /api/github/repos":                       callBody,
	"DELETE /api/grants/{gid}":                    callBody,
	"GET /api/holders":                            callBody,
	"GET /api/icloud/file":                        callBody,
	"POST /api/icloud/relist":                     callBody,
	"POST /api/icloud/retry":                      callBody,
	"GET /api/icloud/search":                      callBody,
	"GET /api/icloud/status":                      callBody,
	"GET /api/input-log":                          callBody,
	"GET /api/jarvis1/paused":                     callBody,
	"GET /api/jarvis1/paused/{id}":                callBody,
	"POST /api/jarvis1/paused/{id}/import":        callBody,
	"POST /api/jarvis1/paused/{id}/prepare":       callBody,
	"GET /api/leases":                             callBody,
	"GET /api/leases/{name}":                      callBody,
	"POST /api/leases/{name}/force-return":        callBody,
	"POST /api/leases/{name}/hand-back":           callBody,
	"POST /api/leases/{name}/take-over":           callBody,
	"GET /api/machines":                           callBody,
	"POST /api/machines/{id}/destroy":             callBody,
	"GET /api/models":                             callBody,
	"GET /api/policy":                             callBody,
	"GET /api/kernel":                             callBody, // kernelline.go: whether the kernel is here and serves
	"POST /api/kernel/root-grant":                 callNo,   // the root key's grant, signed on the phone
	"POST /api/kernel/root-key":                   callNo,   // roster.go: the app's root key (only the app registers it)
	"GET /api/kernel/roster":                      callBody, // roster.go: the current roster and what each component said
	"GET /api/kernel/roster/pending":              callBody,
	"POST /api/kernel/roster":                     callNo, // the root key's roster, signed on the phone
	"GET /api/kernel/root-grant/draft":            callBody,
	"GET /api/kernel/line-state":                  callBody, // the kernel secrets' sealed line state (a Recover's)
	"GET /api/kernel/spawner/identity":            callBody,
	"POST /api/kernel/spawner/fly-token":          callNo, // sealed to the spawner by the app's Recover
	"GET /api/kernel/secrets/{path...}":           callNo, // the kernel's secrets, relayed for the app (claim, unlock: the phone's)
	"POST /api/kernel/secrets/{path...}":          callNo,
	"GET /api/records":                            callBody,
	"DELETE /api/records/{id}":                    callBody,
	"POST /api/records/{id}/restore":              callBody,
	"GET /api/records/{id}/tail":                  callBody,
	"GET /api/remotes":                            callStatus, // every session's OpenClaw token / OpenCode pairing URL
	"GET /api/repos":                              callBody,
	"POST /api/repos/key/begin":                   callNo, // half of a deploy key the phone finishes with its signature
	"POST /api/repos/key/finish":                  callNo, // needs the phone's signature and sealed share
	"GET /api/requests":                           callNo, // the Inbox
	"POST /api/requests/batch":                    callNo, // the Inbox
	"DELETE /api/requests/batches/{id}":           callNo, // the Inbox
	"GET /api/requests/batches/{id}":              callNo, // the Inbox
	"POST /api/requests/grant":                    callNo, // the Inbox
	"POST /api/requests/repo/add":                 callNo, // the Inbox
	"POST /api/requests/repo/remove":              callNo, // the Inbox
	"POST /api/requests/restore":                  callNo, // the Inbox
	"POST /api/requests/unlock":                   callNo, // the Inbox
	"DELETE /api/requests/{id}":                   callNo, // the Inbox
	"GET /api/requests/{id}":                      callNo, // the Inbox
	"GET /api/requests/calls/{id}":                callNo, // the Inbox
	"POST /api/requests/{id}/approve":             callNo, // the Inbox
	"POST /api/requests/{id}/done":                callNo, // the Inbox
	"GET /api/search":                             callBody,
	"GET /api/search/context":                     callBody,
	"POST /api/search/reindex":                    callBody,
	"GET /api/search/status":                      callBody,
	"POST /api/sessions":                          callBody,
	"GET /api/sessions/{id}/attachments/{name}":   callBody,
	"POST /api/sessions/{id}/auto-pause":          callBody,
	"GET /api/sessions/{id}/cert":                 callStatus, // the line's core-signed cert
	"GET /api/sessions/{id}/changes":              callBody,
	"GET /api/sessions/{id}/crons":                callBody,
	"POST /api/sessions/{id}/crons":               callBody,
	"DELETE /api/sessions/{id}/crons/{name}":      callBody,
	"POST /api/sessions/{id}/destroy":             callBody,
	"POST /api/sessions/{id}/env":                 callBody,
	"POST /api/sessions/{id}/exec":                callStatus, // another session's command output (its env, its files)
	"GET /api/sessions/{id}/grants":               callStatus, // phone-signed grant documents
	"POST /api/sessions/{id}/grants":              callNo,     // takes a phone-signed grant
	"POST /api/sessions/{id}/grants/draft":        callBody,
	"POST /api/sessions/{id}/notify-idle":         callBody,
	"POST /api/sessions/{id}/pause":               callBody,
	"POST /api/sessions/{id}/permission-mode":     callBody,
	"POST /api/sessions/{id}/account":             callBody,
	"GET /api/sessions/{id}/remote":               callStatus, // the OpenClaw gateway token / OpenCode pairing URL
	"POST /api/sessions/{id}/restart":             callBody,
	"POST /api/sessions/{id}/resume":              callBody,
	"POST /api/sessions/{id}/start":               callBody,
	"GET /api/sessions/{id}/tail":                 callBody,
	"GET /api/sessions/{id}/terminal":             callStatus, // another session's screen
	"GET /api/sessions/{id}/events":               callBody,   // the supervisor's lines (free of secrets) and the lifecycle log
	"POST /api/sessions/{id}/harness":             callBody,   // pause/resume the Claude process
	"POST /api/sessions/{id}/terminal":            callBody,
	"POST /api/sessions/{id}/upgrade":             callBody,
	"POST /api/sessions/{id}/disk":                callBody,
	"DELETE /api/sessions/{id}/wakeup":            callBody,
	"GET /api/sessions/{id}/wakeup":               callBody,
	"POST /api/sessions/{id}/wakeup":              callBody,
	"GET /api/sessions/{id}/wakeups":              callBody,
	"POST /api/sessions/{id}/wakeups":             callBody,
	"DELETE /api/sessions/{id}/wakeups/{name}":    callBody,
	"GET /api/sessions/{id}/watches":              callBody,
	"POST /api/sessions/{id}/watches":             callNo, // only a session's own signed request arms a watch (always 400 here)
	"DELETE /api/sessions/{id}/watches/{name}":    callBody,
	"GET /api/sizes":                              callBody,
	"GET /api/state":                              callBody,
	"GET /api/stores":                             callBody,
	"PUT /api/stores/{store}/docs":                callBody, // explanations: no secret, no trust decision
	"POST /api/stores/restore/finish":             callNo,   // needs the phone's signature and sealed shares
	"GET /api/tasks":                              callBody,
	"POST /api/tasks/instances":                   callBody,
	"DELETE /api/tasks/instances/{id}":            callBody,
	"PUT /api/tasks/instances/{id}":               callBody,
	"POST /api/tasks/instances/{id}/approve":      callBody,
	"POST /api/tasks/instances/{id}/run":          callBody,
	"GET /api/tasks/instances/{id}/runs":          callBody,
	"GET /api/tasks/runs/{id}":                    callBody,
	"POST /api/tasks/runs/{id}/stop":              callBody,
	"POST /api/tasks/schedules":                   callBody,
	"DELETE /api/tasks/schedules/{id}":            callBody,
	"PUT /api/tasks/schedules/{id}":               callBody,
	"POST /api/uploads":                           callNo, // the app's attachment upload (raw file with its x-upload-* headers)
	"GET /api/usage":                              callBody,
	"GET /term/{id}":                              callNo, // a terminal page for a browser
}
