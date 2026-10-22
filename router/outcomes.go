package main

// Outcomes (Deyao, 2026-10-13: "Approving an Inbox request should send a message or something to notify the session
// that requested it"): when an Inbox item a SESSION filed is decided — approved, denied, lapsed after inboxTTL, dropped
// (it left without a decision), or failed after approval — the requesting session gets a delivery saying so (one per
// filing: a batch's items arrive together). It fits "router-only data never reaches the agent" the way the lease wake
// does (leases.go):
//
//   - the delivery carries the session's OWN signed filing request (the intent POST, the batch, the add-store, the
//     new-session proposal) and the item's index in it; the machine (machine/outcomes.go) builds the text from that
//     body and texts built into the image, never from router prose;
//   - per item the router names only strict-format values: the outcome (a word), the Inbox id or session id (a
//     [a-z0-9-] id), an HTTP status (a number), and a proof document;
//   - an approval that leaves a signed trace carries it, and the machine refuses the delivery when it doesn't check
//     out: a grant is the phone-signed grant (checked against the phone key in the machine's cert), an added store is
//     the machine's new core-signed cert naming it, a new session is the core's approval (by phone) whose config is
//     the proposal's label and prompt, a deploy key is the core's signed key answer for the repo. An unlock and an
//     API call leave nothing signed: the text says it is Jarvis's report. A denial, a lapse or a drop is the router's
//     word too (docs/DECISIONS.md): nothing can sign a non-event, and the text says so;
//   - the core attests the delivery (the input log) over the canonical record below.
//
// A paused session isn't started for this: the outcomes wait in the router's state and go in once it runs again. A
// destroyed session's outcomes go with it. Deyao's own words (a note, a reason) never travel.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	outcomeApproved = "approved"
	outcomeDenied   = "denied"
	outcomeLapsed   = "lapsed"  // nobody answered within inboxTTL
	outcomeDropped  = "dropped" // left the Inbox without a decision (the session paused, what it was about went away)
	outcomeFailed   = "failed"  // approved, but carrying it out failed

	outcomeMaxPerSession = 100
	outcomeMaxAttempts   = 20
)

var (
	outcomeSettle    = 30 * time.Second // a batch's items are delivered together: until all are decided, or this long after the last
	outcomeTickEvery = 15 * time.Second
	outcomeRefRE     = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
)

// Outcome: one decided item of a session's filing, kept until it is delivered (persisted)
type Outcome struct {
	ID          string         `json:"id"`
	Session     string         `json:"session"` // the requesting session
	Request     *SignedRequest `json:"request"` // its own filing, as its machine signed it
	Item        int            `json:"item"`    // the item's index in a batch (0 otherwise)
	Batch       string         `json:"batch,omitempty"`
	Ref         string         `json:"ref"`  // the Inbox id, or the session the approval was for
	Kind        string         `json:"kind"` // what was asked (for listing): repo-key | grant | unlock | api-call | add-store | new-session
	Outcome     string         `json:"outcome"`
	Status      int            `json:"status,omitempty"` // an approved API call: its HTTP status
	Proof       *Doc           `json:"proof,omitempty"`
	At          time.Time      `json:"at"`
	DeliveredAt *time.Time     `json:"deliveredAt,omitempty"`
	Attempts    int            `json:"attempts,omitempty"`
	Error       string         `json:"error,omitempty"` // the last delivery error (or why it was given up)
}

// OutcomeItem: one item in a request-outcome delivery
type OutcomeItem struct {
	Item    int    `json:"item"`
	Outcome string `json:"outcome"`
	Ref     string `json:"ref"`
	Status  int    `json:"status,omitempty"`
	Proof   *Doc   `json:"proof,omitempty"`
}

// outcomeRecord: what the core attests for a request-outcome delivery (machine/outcomes.go builds the same bytes)
type outcomeRecord struct {
	Request string              `json:"request"` // the filing's signature
	Items   []outcomeRecordItem `json:"items"`
}

type outcomeRecordItem struct {
	Item    int    `json:"item"`
	Outcome string `json:"outcome"`
	Ref     string `json:"ref"`
	Status  int    `json:"status"`
	Proof   string `json:"proof"` // sha256 of the proof's payload and signature, "" = none
}

func proofHash(p *Doc) string {
	if p == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(p.Payload + "\n" + p.Sig))
	return hex.EncodeToString(sum[:])
}

func outcomeAttested(d Delivery) ([]byte, error) {
	if d.Request == nil || len(d.Outcomes) == 0 {
		return nil, errors.New("request-outcome: no signed request or no items")
	}
	rec := outcomeRecord{Request: d.Request.Sig}
	for _, it := range d.Outcomes {
		if !outcomeRefRE.MatchString(it.Ref) || it.Status < 0 || it.Status > 999 || it.Item < 0 || it.Item >= batchMaxItems {
			return nil, errors.New("request-outcome: not an id, status or item index")
		}
		switch it.Outcome {
		case outcomeApproved, outcomeDenied, outcomeLapsed, outcomeDropped, outcomeFailed:
		default:
			return nil, errors.New("request-outcome: not an outcome")
		}
		rec.Items = append(rec.Items, outcomeRecordItem{Item: it.Item, Outcome: it.Outcome, Ref: it.Ref, Status: it.Status, Proof: proofHash(it.Proof)})
	}
	return json.Marshal(rec)
}

// noteOutcome (under the state lock): the item an Origin filed was decided. Only a session's own signed filing gets
// one; the first decision of an item stands.
func noteOutcome(d *persisted, o *Origin, kind, ref, outcome string, status int, proof *Doc) {
	if o == nil || o.Signed == nil || (o.Caller.Kind != "session" && o.Caller.Kind != "actions") || o.Caller.Session == "" {
		return
	}
	sid := o.Caller.Session
	if s := d.Sessions[sid]; s == nil || s.State == "destroyed" || s.State == "destroying" {
		return
	}
	if !outcomeRefRE.MatchString(ref) {
		return
	}
	if d.Outcomes == nil {
		d.Outcomes = map[string][]*Outcome{}
	}
	for _, x := range d.Outcomes[sid] {
		if x.Request != nil && x.Request.Sig == o.Signed.Sig && x.Item == o.Item {
			return
		}
	}
	batch := ""
	if isBatchPath(o.Signed.Path) {
		batch = o.Batch
	}
	list := append(d.Outcomes[sid], &Outcome{ID: randID(), Session: sid, Request: o.Signed, Item: o.Item, Batch: batch, Ref: ref,
		Kind: kind, Outcome: outcome, Status: status, Proof: proof, At: time.Now().UTC()})
	if len(list) > outcomeMaxPerSession { // the oldest delivered one goes, else the oldest
		drop := 0
		for i, x := range list {
			if x.DeliveredAt != nil {
				drop = i
				break
			}
		}
		list = append(list[:drop:drop], list[drop+1:]...)
	}
	d.Outcomes[sid] = list
	log.Printf("[outcome] %s: %s %s %s", sid, kind, ref, outcome)
	select {
	case outcomeKick <- struct{}{}:
	default:
	}
}

var outcomeKick = make(chan struct{}, 1)

func isBatchPath(p string) bool { return strings.HasSuffix(p, "/requests/batch") }

// batchSize: the number of items in a signed batch filing (0 when it isn't one)
func batchSize(sr *SignedRequest) int {
	if sr == nil || !isBatchPath(sr.Path) {
		return 0
	}
	b, err := base64.StdEncoding.DecodeString(sr.Body)
	if err != nil {
		return 0
	}
	var in struct {
		Items []json.RawMessage `json:"items"`
	}
	json.Unmarshal(b, &in)
	return len(in.Items)
}

// ---- delivery ---------------------------------------------------------------------------------------------

type outcomeGroup struct {
	sid   string
	sig   string
	ids   []string
	deliv Delivery
}

// readyOutcomes (under the lock): each started session's undelivered outcomes, grouped by filing; a batch's group is
// ready once every item is decided or outcomeSettle after its newest
func readyOutcomes(d *persisted, now time.Time) []outcomeGroup {
	out := []outcomeGroup{}
	for sid, list := range d.Outcomes {
		s := d.Sessions[sid]
		if s == nil || s.State == "destroyed" {
			delete(d.Outcomes, sid)
			continue
		}
		if s.State != "started" || s.MachineID == "" {
			continue // a paused session gets them at its next start; nothing boots it for this
		}
		groups := map[string]*outcomeGroup{}
		newest := map[string]time.Time{}
		order := []string{}
		for _, x := range list {
			if x.DeliveredAt != nil || x.Request == nil {
				continue
			}
			g := groups[x.Request.Sig]
			if g == nil {
				g = &outcomeGroup{sid: sid, sig: x.Request.Sig, deliv: Delivery{Kind: "request-outcome", Request: x.Request}}
				groups[x.Request.Sig] = g
				order = append(order, x.Request.Sig)
			}
			g.ids = append(g.ids, x.ID)
			g.deliv.Outcomes = append(g.deliv.Outcomes, OutcomeItem{Item: x.Item, Outcome: x.Outcome, Ref: x.Ref, Status: x.Status, Proof: x.Proof})
			if x.At.After(newest[x.Request.Sig]) {
				newest[x.Request.Sig] = x.At
			}
		}
		for _, sig := range order {
			g := groups[sig]
			if n := batchSize(g.deliv.Request); n > 0 {
				decided := map[int]bool{}
				for _, x := range list {
					if x.Request != nil && x.Request.Sig == sig {
						decided[x.Item] = true
					}
				}
				if len(decided) < n && now.Sub(newest[sig]) < outcomeSettle {
					continue
				}
			}
			sort.Slice(g.deliv.Outcomes, func(i, j int) bool { return g.deliv.Outcomes[i].Item < g.deliv.Outcomes[j].Item })
			out = append(out, *g)
		}
	}
	return out
}

// deliverOutcomeHook: a seam for tests
var deliverOutcomeHook = func(r *Router, sid string, d Delivery) error { return r.deliverVouchedRunning(sid, d) }

var outcomeRun = struct {
	sync.Mutex
	busy    map[string]bool
	ticking sync.Mutex
}{busy: map[string]bool{}}

var outcomeWG sync.WaitGroup

func (r *Router) outcomeLoop() {
	t := time.NewTicker(outcomeTickEvery)
	defer t.Stop()
	for {
		awaitLead() // leaderlease.go
		r.outcomeTick()
		select {
		case <-t.C:
		case <-outcomeKick:
			time.Sleep(2 * time.Second) // let a batch's other answers land
		}
	}
}

// outcomeTick: deliver every ready group, each outside the lock and once at a time
func (r *Router) outcomeTick() {
	if !outcomeRun.ticking.TryLock() {
		return
	}
	defer outcomeRun.ticking.Unlock()
	var ready []outcomeGroup
	r.st.Do(func(d *persisted) { ready = readyOutcomes(d, time.Now().UTC()) })
	for _, g := range ready {
		key := g.sid + " " + g.sig
		outcomeRun.Lock()
		if outcomeRun.busy[key] {
			outcomeRun.Unlock()
			continue
		}
		outcomeRun.busy[key] = true
		outcomeRun.Unlock()
		outcomeWG.Add(1)
		go func(g outcomeGroup) {
			defer outcomeWG.Done()
			defer func() { outcomeRun.Lock(); delete(outcomeRun.busy, key); outcomeRun.Unlock() }()
			err := deliverOutcomeHook(r, g.sid, g.deliv)
			if errors.Is(err, errSkip) {
				return // not running right now: the next tick (or the next start)
			}
			now := time.Now().UTC()
			ids := map[string]bool{}
			for _, id := range g.ids {
				ids[id] = true
			}
			r.st.Do(func(d *persisted) {
				for _, x := range d.Outcomes[g.sid] {
					if !ids[x.ID] {
						continue
					}
					if err == nil {
						x.DeliveredAt, x.Error = &now, ""
						continue
					}
					x.Attempts++
					x.Error = trimTo(err.Error(), 300)
					// an image from before outcomes refuses the kind: it never will take it
					if x.Attempts >= outcomeMaxAttempts || errors.Is(err, errNoSession) || strings.Contains(err.Error(), "unknown delivery kind") {
						x.DeliveredAt = &now // given up; the session can still read it (GET /m/api/requests/outcomes)
						x.Error = "not delivered: " + x.Error
					}
				}
			})
			if err != nil {
				log.Printf("[outcome] %s: delivering %d item(s) failed: %v", g.sid, len(g.ids), err)
			} else {
				log.Printf("[outcome] %s: %d item(s) delivered", g.sid, len(g.ids))
			}
		}(g)
	}
}

// ---- the session reads its own (jarvis2-request wait / outcomes) -----------------------------------------------

type outcomeView struct {
	Ref       string     `json:"ref"`
	Batch     string     `json:"batch,omitempty"`
	Item      int        `json:"item"`
	Kind      string     `json:"kind"`
	Outcome   string     `json:"outcome"`
	Status    int        `json:"status,omitempty"`
	At        time.Time  `json:"at"`
	Delivered *time.Time `json:"delivered,omitempty"`
	Error     string     `json:"error,omitempty"`
}

func (r *Router) registerOutcomes(m machineRoute) {
	m("GET /m/api/requests/outcomes", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		sid, err := r.machineSession(machine)
		if err != nil {
			writeJSON(w, 403, map[string]string{"error": err.Error()})
			return
		}
		out := []outcomeView{}
		r.st.Do(func(d *persisted) {
			for _, x := range d.Outcomes[sid] {
				out = append(out, outcomeView{Ref: x.Ref, Batch: x.Batch, Item: x.Item, Kind: x.Kind, Outcome: x.Outcome, Status: x.Status,
					At: x.At, Delivered: x.DeliveredAt, Error: x.Error})
			}
		})
		sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
		writeJSON(w, 200, map[string]any{"outcomes": out})
	})
}

func init() {
	onDestroy = append(onDestroy, func(r *Router, s Session) {
		r.st.Do(func(d *persisted) { delete(d.Outcomes, s.ID) })
	})
}
