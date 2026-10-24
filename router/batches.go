package main

// Batches (Deyao, 2026-10-13): a caller files several Inbox items at once, with one summary; the Inbox shows them as
// one entry and the phone reviews them on one page and allows them under ONE Face ID. Nothing about what is signed
// changes: the app signs each item exactly as it would alone (each approval's own core challenge, each grant's own
// text, each deploy key's own begin document), using one LAContext that the batch's Face ID authenticated, and sends
// each signature on its own; the core verifies every item unchanged. A batch is only a grouping the router keeps:
//
//   - the caller groups (through the API), any item kind; the summary is the caller's words, shown as unverified
//     above every item's signed details;
//   - the whole batch goes 10 minutes after it was filed (inboxTTL), every item with it;
//   - Deny drops the whole batch (requests leave, approvals are rejected); a single item can still be denied (or
//     allowed) on its own, which takes it out of the batch;
//   - a batch counts once toward a caller's limits: one of its 20 waiting requests (requestPerCaller) and, when it
//     proposes new sessions, one of its 3 waiting proposals (maxProposedSessions); a batch holds at most 20 items.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const batchMaxItems = 20

type Batch struct {
	ID      string       `json:"id"`
	Summary string       `json:"summary"`
	Origin  Origin       `json:"origin"`
	Created time.Time    `json:"created"`
	Expires time.Time    `json:"expires"`
	Entries []BatchEntry `json:"entries"`
	Filing  bool         `json:"filing,omitempty"` // its items are still being filed: not pruned as empty
}

// BatchEntry: one filed item. A request is known by its id; an approval by its session (the approval's id exists
// once the core's challenge is in, a moment after filing for a new session)
type BatchEntry struct {
	Intent      string `json:"intent"`
	Request     string `json:"request,omitempty"`
	Session     string `json:"session,omitempty"`
	ProposesNew bool   `json:"proposesNew,omitempty"` // a new-session proposal (counted toward the 3)
}

// callerLoad: what a caller has waiting, as the limits count it — requests (each standalone request, each batch
// once) and proposals (each standalone new-session approval it proposed, each batch that proposes any once)
func callerLoad(d *persisted, c Caller) (requests, proposals int) {
	for _, q := range d.Inbox {
		if q.Origin.Caller == c && (q.Batch == "" || d.Batches[q.Batch] == nil) {
			requests++
		}
	}
	for _, a := range d.Approvals {
		if a.Kind == "new-session" && a.Origin != nil && a.Origin.Caller == c && (a.Batch == "" || d.Batches[a.Batch] == nil) {
			proposals++
		}
	}
	for _, b := range d.Batches {
		if b.Origin.Caller != c {
			continue
		}
		requests++
		for _, e := range b.Entries {
			if e.ProposesNew {
				proposals++
				break
			}
		}
	}
	return
}

// approvalDeadline: when an approval goes — inboxTTL after it was made, or its batch's end if sooner
func approvalDeadline(d *persisted, a *Approval) time.Time {
	t := a.Created.Add(inboxTTL)
	if b := d.Batches[a.Batch]; b != nil && b.Expires.Before(t) {
		t = b.Expires
	}
	return t
}

// batchPreparing: the batch's approvals still being made (a new session whose challenge isn't in yet)
func batchPreparing(d *persisted, b *Batch) int {
	n := 0
	for _, e := range b.Entries {
		if e.Request != "" || e.Session == "" {
			continue
		}
		s := d.Sessions[e.Session]
		if s == nil || s.State != "approval" {
			continue
		}
		found := false
		for _, a := range d.Approvals {
			found = found || (a.Session == e.Session && a.Batch == b.ID)
		}
		if !found {
			n++
		}
	}
	return n
}

func batchItemCount(d *persisted, id string) int {
	n := 0
	for _, q := range d.Inbox {
		if q.Batch == id {
			n++
		}
	}
	for _, a := range d.Approvals {
		if a.Batch == id {
			n++
		}
	}
	return n
}

// pruneBatches: an expired batch goes (its items expire with it: requests carry its end, approvals are rejected by
// expireApprovals, which runs first); a batch with nothing left in it goes
func pruneBatches(d *persisted, now time.Time) {
	for id, b := range d.Batches {
		if b.Filing {
			continue
		}
		if !now.Before(b.Expires) || (batchItemCount(d, id) == 0 && batchPreparing(d, b) == 0) {
			delete(d.Batches, id)
		}
	}
}

// InboxBatch: a batch as the Inbox lists it. Its items are the Inbox items whose `batch` is this id.
type InboxBatch struct {
	ID         string    `json:"id"`
	Summary    string    `json:"summary"` // the caller's words, unverified
	Caller     Caller    `json:"caller"`
	CallerText string    `json:"callerText"`
	Call       APICall   `json:"call"`
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires"`
	Items      []string  `json:"items"`     // the Inbox ids in it now, in the order filed
	Preparing  int       `json:"preparing"` // approvals still being made: the phone waits for them before Allow all
}

// InboxBatches: every batch (or only one caller's), newest first
func (r *Router) InboxBatches(only *Caller) []InboxBatch {
	items := r.Inbox() // prunes first
	out := []InboxBatch{}
	r.st.Do(func(d *persisted) {
		for _, b := range d.Batches {
			if b.Filing || (only != nil && b.Origin.Caller != *only) {
				continue
			}
			ib := InboxBatch{ID: b.ID, Summary: b.Summary, Caller: b.Origin.Caller, CallerText: callerText(d, b.Origin.Caller), Call: b.Origin.Call,
				Created: b.Created, Expires: b.Expires, Items: []string{}, Preparing: batchPreparing(d, b)}
			// in the order filed: the entries' requests and sessions, then anything adopted
			seen := map[string]bool{}
			for _, e := range b.Entries {
				for _, it := range items {
					if it.Batch == b.ID && !seen[it.ID] && ((e.Request != "" && it.ID == e.Request) || (e.Request == "" && it.Approval && it.Session == e.Session)) {
						ib.Items, seen[it.ID] = append(ib.Items, it.ID), true
					}
				}
			}
			for _, it := range items {
				if it.Batch == b.ID && !seen[it.ID] {
					ib.Items, seen[it.ID] = append(ib.Items, it.ID), true
				}
			}
			out = append(out, ib)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// InboxBatchFull: one batch with its items (GET …/requests/batches/:id)
func (r *Router) InboxBatchFull(id string, only *Caller) (map[string]any, bool) {
	for _, b := range r.InboxBatches(only) {
		if b.ID != id {
			continue
		}
		byID := map[string]InboxItem{}
		for _, it := range r.Inbox() {
			byID[it.ID] = it
		}
		list := []InboxItem{}
		for _, i := range b.Items {
			if it, ok := byID[i]; ok {
				list = append(list, it)
			}
		}
		return map[string]any{"batch": b, "items": list}, true
	}
	return nil, false
}

// DenyBatch: every request in it leaves, every approval is rejected (a new session disappears, a resume stays
// paused), and the batch goes; an approval still being made is rejected as it arrives (addApproval)
func (r *Router) DenyBatch(id string) error {
	var approvals []string
	found := false
	r.st.Do(func(d *persisted) {
		if d.Batches[id] == nil {
			return
		}
		found = true
		delete(d.Batches, id)
		for qid, q := range d.Inbox {
			if q.Batch == id {
				delete(d.Inbox, qid)
				noteOutcome(d, &q.Origin, q.Kind, q.ID, outcomeDenied, 0, nil)
			}
		}
		for aid, a := range d.Approvals {
			if a.Batch == id {
				approvals = append(approvals, aid)
			}
		}
	})
	if !found {
		return errAlreadyGone
	}
	for _, aid := range approvals {
		r.Reject(aid)
	}
	return nil
}

// ---- filing ------------------------------------------------------------------------------------------------

// batchIn: POST …/requests/batch
type batchIn struct {
	Summary string            `json:"summary"`
	Items   []json.RawMessage `json:"items"`
}

// batchItemIn: one item: its intent and that intent's own body (as the single endpoint takes it); explanation is
// optional here (the batch's summary is required)
type batchItemIn struct {
	Intent string `json:"intent"` // repo/add | repo/remove | grant | unlock | add-store | call | new-session | jarvis1-import | peer
	requestIn
	ID   string `json:"id"`   // jarvis1-import: the Jarvis 1 session
	To   string `json:"to"`   // peer: the receiving session (its id or exact title)
	Text string `json:"text"` // peer: the message
}

// a checked item, ready to file
type batchItem struct {
	intent string
	// requests
	kind string
	p    RequestParams
	// add-store
	machine, store string
	// new-session
	ns NewSession
	// jarvis1-import
	j1id string
	j1   J1ImportIn
	// peer: a message that isn't upward is delivered at once (as POST …/requests/peer does), not filed
	note *PeerNote
	expl string
	args map[string]any
	// outcomes.go: the batch as the session's machine signed it, and this item's index in it
	signed *SignedRequest
	index  int
}

// BatchResult: what filing one item did
type BatchResult struct {
	Intent    string `json:"intent"`
	ID        string `json:"id,omitempty"`      // a request's id, or a new session's id (its approval follows)
	Session   string `json:"session,omitempty"` // add-store, new-session, jarvis1-import: the session the approval is for
	Duplicate bool   `json:"duplicate,omitempty"`
	Batch     string `json:"batch,omitempty"` // a duplicate already in another batch: that batch
	Error     string `json:"error,omitempty"`
	// Own: filed as a request of its own beside the batch (a restore is reviewed on its own page)
	Own bool `json:"own,omitempty"`
	// peer: equal | downward | upward; Delivering: not upward, so delivered at once instead of waiting in the batch
	Direction  string `json:"direction,omitempty"`
	Delivering bool   `json:"delivering,omitempty"`
	To         string `json:"to,omitempty"`
}

// checkBatchItem: one item checked as its own endpoint would check it, before anything is filed
func (r *Router) checkBatchItem(c Caller, raw json.RawMessage) (*batchItem, error) {
	var in batchItemIn
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, &badRequest{"bad JSON: " + err.Error()}
	}
	expl, err := cleanExplanation(in.Explanation, false)
	if err != nil {
		return nil, &badRequest{err.Error()}
	}
	it := &batchItem{intent: in.Intent, expl: expl}
	if mk := intents[in.Intent]; mk != nil {
		kind, p := mk(in.requestIn)
		p = ownSession(c, kind, p, in.requestIn)
		np, err := r.normalizeRequest(kind, p)
		if err != nil {
			return nil, &badRequest{err.Error()}
		}
		if err := callerMay(c, kind, np); err != nil {
			return nil, &forbidden{err.Error()}
		}
		it.kind, it.p, it.args = kind, np, callArgs(kind, np)
		it.args["intent"] = in.Intent
		return it, nil
	}
	switch in.Intent {
	case "call":
		// an app API call, run as Deyao once approved (apicalls.go): in a batch beside the session's other asks, so it
		// never has to be filed on its own. Any caller may ask: it runs only once Deyao approves it.
		var ci callIn
		if err := json.Unmarshal(raw, &ci); err != nil {
			return nil, &badRequest{"bad JSON: " + err.Error()}
		}
		p, args, err := r.checkCall(ci)
		if err != nil {
			return nil, &badRequest{"call: " + err.Error()}
		}
		it.kind, it.p, it.args = requestKindCall, p, args
		it.args["intent"] = in.Intent
		return it, nil
	case "add-store":
		sid := in.Session
		if sid == "" && (c.Kind == "session" || c.Kind == "actions") {
			sid = c.Session // for itself by default; for another session too (the phone shows which)
		}
		if strings.TrimSpace(in.Store) == "" {
			return nil, &badRequest{"add-store: store is required"}
		}
		r.st.Do(func(d *persisted) {
			// a running machine with a cert or a kernel line (started, or initialising while it waits on a locked store),
			// as addStoreApproval takes
			if s := d.Sessions[sid]; s != nil && s.MachineID != "" && (s.Cert != nil || s.Kernel != nil) && (s.State == "started" || s.State == "initialising") {
				it.machine = s.MachineID
			}
		})
		if it.machine == "" {
			return nil, &badRequest{fmt.Sprintf("add-store: session %q has no running machine: a store is added to a paused session at its resume (jarvis-request add-store once it runs)", sid)}
		}
		it.store, it.args = in.Store, map[string]any{"intent": in.Intent, "session": sid, "store": in.Store}
		return it, nil
	case "new-session":
		var pin proposalIn
		if err := json.Unmarshal(raw, &pin); err != nil {
			return nil, &badRequest{"bad JSON: " + err.Error()}
		}
		prefix := string(c.Kind)
		if c.Kind == "session" {
			prefix = c.Session
		}
		ns, err := r.checkProposal(c, prefix, pin, false)
		if err != nil {
			return nil, err
		}
		it.ns = ns
		it.args = ns.Origin.Call.Args
		it.args["intent"] = in.Intent
		return it, nil
	case "peer":
		// a message to another session (peermsg.go), checked as POST …/requests/peer checks it: upward waits in the
		// batch as a peer-message request (the router's explanation says why it is upward), equal or downward is
		// delivered at once when the batch is filed
		if c.Kind != "session" || c.Session == "" {
			return nil, &forbidden{"only a session sends a peer message"}
		}
		from, recv, text, err := r.peerParties(c.Session, in.To, in.Text)
		if err != nil {
			if errors.Is(err, errNoSession) {
				return nil, &forbidden{"peer: the sending session is gone"}
			}
			return nil, err
		}
		it.args = map[string]any{"intent": in.Intent, "to": recv.ID}
		if note, held := heldPeerNote(peerNote(&from, &recv, text), &recv); held || note.Direction != "upward" {
			it.note = &note // held: the receiver holds a sensitive store, Deyao decides on the message itself (messages.go)
			return it, nil
		}
		it.kind, it.p, it.expl = requestKindPeer, RequestParams{Session: recv.ID, Text: text}, peerExplanation(&from, &recv)
		return it, nil
	case "jarvis1-import":
		if c.Kind != "setup" && c.Kind != "app" && c.Kind != "web" {
			return nil, &forbidden{"a Jarvis 1 import is filed by the setup session or Deyao"}
		}
		var j J1ImportIn
		json.Unmarshal(raw, &j)
		if in.ID == "" || len(j.Stores) == 0 {
			return nil, &badRequest{"jarvis1-import: id and stores are required"}
		}
		if _, _, _, err := r.preparedJarvis1(in.ID); err != nil {
			return nil, &badRequest{fmt.Sprintf("jarvis1-import %s: %v", in.ID, err)}
		}
		j.Explanation = expl
		it.j1id, it.j1 = in.ID, j
		it.args = map[string]any{"intent": in.Intent, "id": in.ID, "stores": j.Stores, "size": j.Size}
		return it, nil
	}
	return nil, &badRequest{fmt.Sprintf("unknown intent %q", in.Intent)}
}

// FileBatch: every item checked first (any bad item: nothing is filed, 400 naming it), then filed in order. An item
// that fails while being filed (the core refused a challenge) is reported and the rest stand; when none stands, the
// batch is dropped. A request already waiting outside any batch joins this one; one in another batch stays there.
func (r *Router) FileBatch(c Caller, method, path string, body []byte, signed *SignedRequest) (int, map[string]any) {
	var in batchIn
	if err := json.Unmarshal(body, &in); err != nil {
		return 400, map[string]any{"error": "bad JSON: " + err.Error()}
	}
	summary, err := cleanExplanation(in.Summary, true)
	if err != nil {
		return 400, map[string]any{"error": "summary: " + strings.Replace(err.Error(), "explanation", "summary", 1)}
	}
	if len(in.Items) == 0 || len(in.Items) > batchMaxItems {
		return 400, map[string]any{"error": fmt.Sprintf("a batch holds 1 to %d items (%d given)", batchMaxItems, len(in.Items))}
	}
	items := []*batchItem{}
	keys := map[string]int{}
	uploadsUsed := map[string]int{} // each upload binds to one new session
	proposes := false
	for i, raw := range in.Items {
		it, err := r.checkBatchItem(c, raw)
		if err != nil {
			code := 400
			var f *forbidden
			if errors.As(err, &f) {
				code = 403
			}
			return code, map[string]any{"error": fmt.Sprintf("item %d: %v", i, err), "item": i}
		}
		var k string
		switch {
		case it.kind != "":
			k = requestKey(it.kind, it.p)
		case it.intent == "new-session":
			k = "new-session " + it.ns.RequestID
		case it.intent == "jarvis1-import":
			k = "jarvis1-import " + it.j1id
		case it.note != nil:
			k = "peer " + it.note.To + "\n" + it.note.Text
		default:
			k = it.intent + " " + string(mustJSON(it.args))
		}
		if j, ok := keys[k]; ok {
			return 400, map[string]any{"error": fmt.Sprintf("item %d is the same as item %d", i, j), "item": i}
		}
		if it.intent == "new-session" && it.ns.Attachments != nil {
			if j, ok := uploadsUsed[it.ns.Attachments.UploadID]; ok {
				return 400, map[string]any{"error": fmt.Sprintf("item %d attaches upload %s, as item %d does: each new session needs its own upload", i, it.ns.Attachments.UploadID, j), "item": i}
			}
			uploadsUsed[it.ns.Attachments.UploadID] = i
		}
		keys[k] = i
		proposes = proposes || it.intent == "new-session"
		items = append(items, it)
	}
	now := time.Now().UTC()
	b := &Batch{ID: "b" + randID(), Summary: summary, Created: now, Expires: now.Add(inboxTTL), Filing: true,
		Origin: Origin{Caller: c, Call: APICall{Method: method, Path: path, Args: map[string]any{"items": len(items)}}}}
	var limit string
	r.st.Do(func(d *persisted) {
		pruneRequests(d, now)
		pruneBatches(d, now)
		reqs, props := callerLoad(d, c)
		switch {
		case reqs >= requestPerCaller:
			limit = fmt.Sprintf("this caller has %d requests waiting already: wait for Deyao to answer them, or deny some, then file again", reqs)
		case proposes && (c.Kind == "session" || c.Kind == "actions") && props >= maxProposedSessions:
			limit = fmt.Sprintf("%d proposed sessions already wait for Deyao: wait for his answer, or deny one, then file again", props)
		default:
			d.Batches[b.ID] = b
		}
	})
	if limit != "" {
		return 429, map[string]any{"error": limit}
	}
	results := []BatchResult{}
	entries := []BatchEntry{}
	for i, it := range items {
		it.signed, it.index = signed, i
		res, entry := r.fileBatchItem(c, method, path, b, it)
		results = append(results, res)
		if entry != nil {
			entries = append(entries, *entry)
		}
	}
	r.st.Do(func(d *persisted) {
		if x := d.Batches[b.ID]; x != nil {
			x.Entries, x.Filing = entries, false
			if len(entries) == 0 {
				delete(d.Batches, b.ID)
			}
		}
	})
	if len(entries) == 0 {
		for _, x := range results {
			if (x.Own || x.Delivering) && x.Error == "" { // only requests of their own or messages delivered at once: no batch, but nothing failed
				return 200, map[string]any{"items": results}
			}
		}
		return 400, map[string]any{"error": "nothing in the batch could be filed", "items": results}
	}
	return 200, map[string]any{"id": b.ID, "expires": b.Expires, "items": results}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func (r *Router) fileBatchItem(c Caller, method, path string, b *Batch, it *batchItem) (BatchResult, *BatchEntry) {
	res := BatchResult{Intent: it.intent}
	o := Origin{Caller: c, Call: APICall{Method: method, Path: path, Args: it.args}, Signed: it.signed, Item: it.index, Batch: b.ID}
	switch {
	case it.note != nil: // a peer message that isn't upward: delivered now, as POST …/requests/peer delivers it
		o.Batch = ""
		r.goPeerNote(*it.note, o, "")
		res.Direction, res.Delivering, res.To = it.note.Direction, true, it.note.To
		return res, nil
	case it.kind == requestKindRestore: // its own review page, so its own request beside the batch
		o.Batch, o.Item = "", 0
		q, dup, err := r.FileRequest(it.kind, it.p, it.expl, o)
		if err != nil {
			res.Error = err.Error()
			return res, nil
		}
		res.ID, res.Duplicate, res.Own = q.ID, dup, true
		return res, nil
	case it.kind != "":
		q := &InboxRequest{ID: "q" + randID(), Kind: it.kind, Params: it.p, Origin: o, Explanation: it.expl, Created: b.Created,
			Expires: b.Expires, Key: requestKey(it.kind, it.p), Batch: b.ID}
		r.st.Do(func(d *persisted) {
			for _, x := range d.Inbox {
				if x.Key != q.Key {
					continue
				}
				res.Duplicate = true
				if x.Batch != "" && d.Batches[x.Batch] != nil {
					res.ID, res.Batch = x.ID, x.Batch // stays in its own batch
					return
				}
				x.Batch, x.Expires = b.ID, b.Expires // a standalone request joins
				q = x
			}
			d.Inbox[q.ID] = q
		})
		res.ID = q.ID
		if it.kind == requestKindPeer {
			res.Direction, res.To = "upward", it.p.Session
		}
		if res.Batch != "" {
			return res, nil
		}
		return res, &BatchEntry{Intent: it.intent, Request: q.ID}
	case it.intent == "add-store":
		var sid string
		r.st.Do(func(d *persisted) { sid = d.Machines[it.machine] })
		res.Session = sid
		if err := r.AddStoreFrom(it.machine, it.store, o, it.expl, b.ID); err != nil {
			res.Error = err.Error()
			return res, nil
		}
		return res, &BatchEntry{Intent: it.intent, Session: sid}
	case it.intent == "new-session" || it.intent == "jarvis1-import":
		var sid string
		var err error
		if it.intent == "new-session" {
			ns := it.ns
			ns.Origin.Call = o.Call
			ns.Origin.Call.Path = path
			ns.Origin.Signed, ns.Origin.Item, ns.Origin.Batch = o.Signed, o.Item, o.Batch
			ns.Batch = b.ID
			sid, err = r.CreateSession(ns)
		} else {
			j := it.j1
			j.Batch = b.ID
			sid, err = r.ImportJarvis1(it.j1id, j, o)
		}
		if err != nil {
			res.Error = err.Error()
			return res, nil
		}
		res.ID, res.Session = sid, sid
		// the same proposal again (its requestId): its approval joins this batch when it is in none
		r.st.Do(func(d *persisted) {
			for _, a := range d.Approvals {
				if a.Session == sid && a.Batch != b.ID {
					res.Duplicate = true
					if a.Batch == "" || d.Batches[a.Batch] == nil {
						a.Batch = b.ID
					} else {
						res.Batch = a.Batch
					}
				}
			}
		})
		if res.Batch != "" {
			return res, nil
		}
		return res, &BatchEntry{Intent: it.intent, Session: sid, ProposesNew: it.intent == "new-session"}
	}
	res.Error = "unknown intent"
	return res, nil
}

// ---- routes ------------------------------------------------------------------------------------------------

func (r *Router) serveFileBatch(w http.ResponseWriter, c Caller, method, path string, body []byte, signed *SignedRequest) {
	code, out := r.FileBatch(c, method, path, body, signed)
	writeJSON(w, code, out)
}

func (r *Router) serveBatch(w http.ResponseWriter, id string, only *Caller) {
	out, ok := r.InboxBatchFull(id, only)
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "this batch is gone (answered, denied or expired)"})
		return
	}
	writeJSON(w, 200, out)
}

func (r *Router) serveDenyBatch(w http.ResponseWriter, id string) {
	writeDenied(w, r.DenyBatch(id))
}
