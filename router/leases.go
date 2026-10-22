package main

// Shared-device leases (Jarvis 1's lib/leases.js and its server.js routes, ported): several sessions share one
// physical or cloud device (the WeChat cloud phone, Deyao's iPhone, his Mac) and must never drive it at the same
// time. A resource is just a name; the router keeps, per name, at most ONE holder and a FIFO queue of waiting
// sessions.
//
//   acquire  → granted at once when free (or already ours: a renew), else queued (FIFO); a lowPriority caller (the
//              WeChat warm-up) is never queued: it gets "busy".
//   renew    → the holder only; pushes expiresAt out by the lease's ttl (the device helpers renew on every action).
//   return   → the holder hands it back; the next waiter becomes the holder and is WOKEN (a delivery, resuming the
//              session when it is paused). A waiter's DELETE leaves the queue.
//   expiry   → a holder that stopped renewing loses the lease at expiresAt; the next waiter is promoted the same way.
//   take-over / hand-back → Deyao takes the device himself from the app (holder "deyao", never expires); an agent
//              holding it is told and goes to the front of the queue; on hand-back the next waiter is woken, and every
//              other session that found it taken over meanwhile is told it is back.
//
// Leases end with their session: a destroyed session's holder or queue place goes at the next tick.
//
// Jarvis 4 differences (docs/DECISIONS.md 100): the state is the router's (persisted.Leases, state.json on its volume),
// the holder is the calling machine's own session (the path's id must be it), and the wake messages are deliveries
// the machine checks (machine/deliver.go): "lease-granted" carries the waiter's own signed acquire request (its
// prompt and the device name in the signed path), "lease-taken" and "lease-back" are texts built into the image over
// the device name. Deyao's notes never go into a session (nothing vouches for them); the session reads them with
// lease.py status. Jarvis 1's lease table is separate: Jarvis 4 is the lease authority for Jarvis 4 sessions.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	leaseDefaultTTL  = 3600 // seconds (Deyao, 2026-09-26: 1 hour, renewable)
	leaseMinTTL      = 60
	leaseMaxTTL      = 6 * 3600
	leaseMaxPurpose  = 200
	leaseMaxDescr    = 2000
	leaseMaxPrompt   = 2000
	leaseMaxNote     = 1000
	leaseLogMax      = 50
	leaseHuman       = "deyao" // the holder while Deyao has taken the device over
	leaseTickEvery   = 30 * time.Second
	leaseMaxAttempts = 20 // wake deliveries tried per promotion before the holder is left un-notified (logged)
)

// knownDevices: always listed (so Take over is there even when a device is free)
var knownDevices = []string{"wechat-phone", "iphone", "mac"}

var leaseNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

type LeaseEntry struct {
	Sid         string         `json:"sid"`
	Human       bool           `json:"human,omitempty"`
	Purpose     string         `json:"purpose"`
	Description string         `json:"description"`
	DescribedAt int64          `json:"describedAt"`
	TTL         int64          `json:"ttl"` // seconds
	Since       int64          `json:"since,omitempty"`
	ExpiresAt   int64          `json:"expiresAt,omitempty"` // ms; 0 for Deyao
	EnqueuedAt  int64          `json:"enqueuedAt,omitempty"`
	Prompt      string         `json:"prompt,omitempty"` // the wake note (the session's own words)
	Signed      *SignedRequest `json:"signed,omitempty"` // the acquire request that carried the prompt, as signed
	Note        string         `json:"note,omitempty"`   // Deyao's take-over note
	Promoted    bool           `json:"promoted,omitempty"`
	Notified    bool           `json:"notified,omitempty"`
	Interrupted bool           `json:"interrupted,omitempty"`
	Handover    *LeaseHandover `json:"handover,omitempty"`
	Blocked     []string       `json:"blocked,omitempty"` // sessions that found it taken over (told on hand-back)
}

type LeaseHandover struct {
	TakenAt    int64  `json:"takenAt"`
	ReturnedAt int64  `json:"returnedAt"`
	TakeNote   string `json:"takeNote,omitempty"`
	Note       string `json:"note,omitempty"`
}

type LeaseEvent struct {
	At          int64  `json:"at"`
	Kind        string `json:"kind"`
	Sid         string `json:"sid"`
	Purpose     string `json:"purpose,omitempty"`
	Note        string `json:"note,omitempty"`
	Interrupted string `json:"interrupted,omitempty"`
}

type LeaseResource struct {
	Holder *LeaseEntry   `json:"holder"`
	Queue  []*LeaseEntry `json:"queue"`
	Log    []LeaseEvent  `json:"log"`
}

type LeaseState struct {
	Resources map[string]*LeaseResource `json:"resources"`
}

type leaseError struct {
	status    int
	msg       string
	takenOver bool
}

func (e *leaseError) Error() string { return e.msg }

func leaseErrf(status int, format string, a ...any) error {
	return &leaseError{status: status, msg: fmt.Sprintf(format, a...)}
}

func leasesOf(d *persisted) *LeaseState {
	if d.Leases == nil {
		d.Leases = &LeaseState{}
	}
	if d.Leases.Resources == nil {
		d.Leases.Resources = map[string]*LeaseResource{}
	}
	return d.Leases
}

func (st *LeaseState) res(name string) (*LeaseResource, error) {
	if !leaseNameRE.MatchString(name) {
		return nil, leaseErrf(400, "bad resource name (lowercase letters/digits/dashes)")
	}
	r := st.Resources[name]
	if r == nil {
		r = &LeaseResource{Queue: []*LeaseEntry{}, Log: []LeaseEvent{}}
		st.Resources[name] = r
	}
	return r, nil
}

func (r *LeaseResource) logEv(now int64, kind, sid string, ev LeaseEvent) {
	ev.At, ev.Kind, ev.Sid = now, kind, sid
	r.Log = append(r.Log, ev)
	if len(r.Log) > leaseLogMax {
		r.Log = r.Log[len(r.Log)-leaseLogMax:]
	}
}

func leaseTTL(v any) (int64, error) {
	if v == nil {
		return leaseDefaultTTL, nil
	}
	f, ok := number(v)
	if !ok {
		return 0, leaseErrf(400, "ttlSeconds must be a number")
	}
	return int64(math.Min(leaseMaxTTL, math.Max(leaseMinTTL, math.Round(f)))), nil
}

func cleanLine(s string, max int) string {
	s = strings.TrimSpace(spaceRE.ReplaceAllString(s, " "))
	return truncRunes(s, max)
}

var trailingSpaceRE = regexp.MustCompile(`[ \t]+\n`)
var blankRunRE = regexp.MustCompile(`\n{3,}`)

// cleanText: multi-line: keeps line breaks, trims trailing spaces, collapses blank runs
func cleanText(s string, max int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	s = trailingSpaceRE.ReplaceAllString(s+"\n", "\n")
	s = blankRunRE.ReplaceAllString(s, "\n\n")
	return truncRunes(strings.TrimSpace(s), max)
}

func truncRunes(s string, max int) string {
	if r := []rune(s); len(r) > max {
		return string(r[:max])
	}
	return s
}

// LeaseOpts: an acquire's or describe's body
type LeaseOpts struct {
	Purpose     *string
	Description *string
	Prompt      string
	TTL         any
	LowPriority bool
	Signed      *SignedRequest
}

func (e *LeaseEntry) setText(o LeaseOpts, now int64) {
	if o.Purpose != nil && *o.Purpose != "" {
		e.Purpose = cleanLine(*o.Purpose, leaseMaxPurpose)
	}
	if o.Description != nil {
		e.Description, e.DescribedAt = cleanText(*o.Description, leaseMaxDescr), now
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

type LeaseOut struct {
	Status   string         `json:"status"`
	Position int            `json:"position,omitempty"`
	Lease    map[string]any `json:"lease"`
}

func (st *LeaseState) acquire(name, sid string, o LeaseOpts, now int64) (*LeaseOut, error) {
	r, err := st.res(name)
	if err != nil {
		return nil, err
	}
	ttl, err := leaseTTL(o.TTL)
	if err != nil {
		return nil, err
	}
	if h := r.Holder; h != nil && h.Sid == sid {
		h.ExpiresAt = now + h.TTL*1000
		h.setText(o, now)
		return &LeaseOut{Status: "renewed", Lease: leaseView(r, name, now)}, nil
	}
	prompt := cleanLine(o.Prompt, leaseMaxPrompt)
	if r.Holder == nil {
		r.Queue = dropSid(r.Queue, sid)
		// the prompt is kept for a direct grant too: if Deyao takes the device over, it goes back in the queue with it
		r.Holder = &LeaseEntry{Sid: sid, Purpose: cleanLine(deref(o.Purpose), leaseMaxPurpose), Description: cleanText(deref(o.Description), leaseMaxDescr),
			DescribedAt: now, TTL: ttl, Since: now, ExpiresAt: now + ttl*1000, Prompt: prompt, Signed: o.Signed}
		r.logEv(now, "granted", sid, LeaseEvent{Purpose: r.Holder.Purpose})
		return &LeaseOut{Status: "granted", Lease: leaseView(r, name, now)}, nil
	}
	if o.LowPriority {
		return &LeaseOut{Status: "busy", Lease: leaseView(r, name, now)}, nil
	}
	var w *LeaseEntry
	for _, x := range r.Queue {
		if x.Sid == sid {
			w = x
		}
	}
	if w == nil {
		w = &LeaseEntry{Sid: sid, EnqueuedAt: now}
		r.Queue = append(r.Queue, w)
	}
	w.Purpose = cleanLine(deref(o.Purpose), leaseMaxPurpose)
	if o.Description != nil || w.DescribedAt == 0 {
		w.Description, w.DescribedAt = cleanText(deref(o.Description), leaseMaxDescr), now
	}
	w.Prompt, w.Signed, w.TTL = prompt, o.Signed, ttl
	return &LeaseOut{Status: "queued", Position: indexOf(r.Queue, sid) + 1, Lease: leaseView(r, name, now)}, nil
}

func dropSid(q []*LeaseEntry, sid string) []*LeaseEntry {
	out := []*LeaseEntry{}
	for _, w := range q {
		if w.Sid != sid {
			out = append(out, w)
		}
	}
	return out
}

func indexOf(q []*LeaseEntry, sid string) int {
	for i, w := range q {
		if w.Sid == sid {
			return i
		}
	}
	return -1
}

// noteBlocked: a session found the device taken over by Deyao; it is told when he hands it back. True while he has it.
func (st *LeaseState) noteBlocked(name, sid string) (bool, error) {
	r, err := st.res(name)
	if err != nil {
		return false, err
	}
	if r.Holder == nil || !r.Holder.Human || sid == "" {
		return false, nil
	}
	for _, b := range r.Holder.Blocked {
		if b == sid {
			return true, nil
		}
	}
	r.Holder.Blocked = append(r.Holder.Blocked, sid)
	if len(r.Holder.Blocked) > 50 {
		r.Holder.Blocked = r.Holder.Blocked[1:]
	}
	return true, nil
}

func isoMs(ms int64) string { return time.UnixMilli(ms).UTC().Format(time.RFC3339) }

// renew: the holder only. While Deyao has the device the refusal says why and records the session (the caller keeps
// the state even then).
func (st *LeaseState) renew(name, sid string, now int64) (*LeaseOut, error) {
	r, err := st.res(name)
	if err != nil {
		return nil, err
	}
	if h := r.Holder; h != nil && h.Human && h.Sid != sid {
		st.noteBlocked(name, sid)
		msg := fmt.Sprintf("don't touch it. Jarvis will tell this session when he hands it back; to be GIVEN it then, queue now with scripts/lease.py acquire %s", name)
		if i := indexOf(r.Queue, sid); i >= 0 {
			msg = fmt.Sprintf("don't touch it. You are #%d in the queue and will be woken when it is your turn", i+1)
		}
		why := " (no note)"
		if h.Note != "" {
			why = fmt.Sprintf(" — his note: %q", h.Note)
		}
		return nil, &leaseError{status: 409, takenOver: true,
			msg: fmt.Sprintf("Deyao has taken over %q himself (since %s)%s — %s", name, isoMs(h.Since), why, msg)}
	}
	if r.Holder == nil || r.Holder.Sid != sid {
		held := ""
		if r.Holder != nil {
			held = fmt.Sprintf(" (held by %s)", r.Holder.Sid)
		}
		return nil, leaseErrf(409, "this session does not hold %q%s", name, held)
	}
	r.Holder.ExpiresAt = now + r.Holder.TTL*1000
	return &LeaseOut{Status: "renewed", Lease: leaseView(r, name, now)}, nil
}

// describe: the purpose and/or description of this session's holder or queue entry (no renew)
func (st *LeaseState) describe(name, sid string, o LeaseOpts, now int64) (*LeaseOut, error) {
	r, err := st.res(name)
	if err != nil {
		return nil, err
	}
	var x *LeaseEntry
	status := "holder"
	if r.Holder != nil && r.Holder.Sid == sid {
		x = r.Holder
	} else if i := indexOf(r.Queue, sid); i >= 0 {
		x, status = r.Queue[i], "queued"
	}
	if x == nil { // nothing of this session's to describe: the lease as it is
		return &LeaseOut{Status: "none", Lease: leaseView(r, name, now)}, nil
	}
	x.setText(o, now)
	return &LeaseOut{Status: status, Lease: leaseView(r, name, now)}, nil
}

// promote: the next waiter becomes the holder (the tick wakes it); nil when the queue is empty
func (r *LeaseResource) promote(now int64) *LeaseEntry {
	if len(r.Queue) == 0 {
		r.Holder = nil
		return nil
	}
	next := r.Queue[0]
	r.Queue = r.Queue[1:]
	ttl := next.TTL
	if ttl == 0 {
		ttl = leaseDefaultTTL
	}
	d := next.DescribedAt
	if d == 0 {
		d = now
	}
	r.Holder = &LeaseEntry{Sid: next.Sid, Purpose: next.Purpose, Description: next.Description, DescribedAt: d, TTL: ttl, Since: now,
		ExpiresAt: now + ttl*1000, Promoted: true, Prompt: next.Prompt, Signed: next.Signed, Interrupted: next.Interrupted}
	r.logEv(now, "promoted", next.Sid, LeaseEvent{})
	c := *next
	return &c
}

type giveBackOut struct {
	Returned bool
	Previous string
	Promoted *LeaseEntry
}

// giveBack: the holder returns it ("return", never "release": releasing the cloud phone deletes it); force = the
// app's escape hatch
func (st *LeaseState) giveBack(name, sid string, now int64, force bool) (*giveBackOut, error) {
	r, err := st.res(name)
	if err != nil {
		return nil, err
	}
	if r.Holder == nil {
		return &giveBackOut{}, nil
	}
	if !force && r.Holder.Sid != sid {
		return nil, leaseErrf(409, "this session does not hold %q (held by %s)", name, r.Holder.Sid)
	}
	prev := r.Holder.Sid
	kind := "returned"
	if force {
		kind = "force-returned"
	}
	r.logEv(now, kind, prev, LeaseEvent{})
	return &giveBackOut{Returned: true, Previous: prev, Promoted: r.promote(now)}, nil
}

func (st *LeaseState) leave(name, sid string) (bool, error) {
	r, err := st.res(name)
	if err != nil {
		return false, err
	}
	n := len(r.Queue)
	r.Queue = dropSid(r.Queue, sid)
	return len(r.Queue) < n, nil
}

type takeOverOut struct {
	Taken       bool   `json:"taken"`
	Interrupted string `json:"interrupted"`
	NoteUpdated bool   `json:"noteUpdated,omitempty"`
}

// takeOver: Deyao takes the device himself; an agent holding it goes to the front of the queue. While he already
// has it, a take-over with a note only replaces his note.
func (st *LeaseState) takeOver(name string, note *string, now int64) (*takeOverOut, error) {
	r, err := st.res(name)
	if err != nil {
		return nil, err
	}
	if r.Holder != nil && r.Holder.Human {
		if note == nil {
			return &takeOverOut{}, nil
		}
		r.Holder.Note = cleanLine(*note, leaseMaxNote)
		r.logEv(now, "note", leaseHuman, LeaseEvent{Note: r.Holder.Note})
		return &takeOverOut{NoteUpdated: true}, nil
	}
	out := &takeOverOut{Taken: true}
	if h := r.Holder; h != nil {
		out.Interrupted = h.Sid
		r.Queue = append([]*LeaseEntry{{Sid: h.Sid, EnqueuedAt: now, Purpose: h.Purpose, Description: h.Description, DescribedAt: h.DescribedAt,
			Prompt: h.Prompt, Signed: h.Signed, TTL: h.TTL, Interrupted: true}}, dropSid(r.Queue, h.Sid)...)
	}
	r.Holder = &LeaseEntry{Sid: leaseHuman, Human: true, Purpose: "Deyao is using it himself", Since: now, Note: cleanLine(deref(note), leaseMaxNote)}
	r.logEv(now, "taken-over", leaseHuman, LeaseEvent{Note: r.Holder.Note, Interrupted: out.Interrupted})
	return out, nil
}

type handBackOut struct {
	HandedBack bool
	Promoted   *LeaseEntry
	Notify     []string
}

// handBack: Deyao gives it back; the next waiter is promoted (woken by the tick) and the other sessions that found it
// taken over meanwhile are to be told it is back
func (st *LeaseState) handBack(name, note string, now int64) (*handBackOut, error) {
	r, err := st.res(name)
	if err != nil {
		return nil, err
	}
	if r.Holder == nil || !r.Holder.Human {
		return &handBackOut{}, nil
	}
	h := &LeaseHandover{TakenAt: r.Holder.Since, ReturnedAt: now, TakeNote: r.Holder.Note, Note: cleanLine(note, leaseMaxNote)}
	blocked := r.Holder.Blocked
	r.logEv(now, "handed-back", leaseHuman, LeaseEvent{Note: h.Note})
	p := r.promote(now)
	if p != nil && r.Holder != nil {
		r.Holder.Handover = h
	}
	out := &handBackOut{HandedBack: true, Promoted: p, Notify: []string{}}
	for _, sid := range blocked {
		if p == nil || sid != p.Sid {
			out.Notify = append(out.Notify, sid)
		}
	}
	return out, nil
}

type sweepChange struct {
	Name, Expired string
	Promoted      *LeaseEntry
}

// sweep: expire holders that stopped renewing; drop sessions that no longer exist (holder or waiting)
func (st *LeaseState) sweep(now int64, alive func(sid string) bool) []sweepChange {
	var out []sweepChange
	for _, name := range sortedKeys(st.Resources) {
		r := st.Resources[name]
		fresh := func() {
			q := []*LeaseEntry{}
			for _, w := range r.Queue {
				if alive(w.Sid) {
					q = append(q, w)
				}
			}
			r.Queue = q
		}
		fresh()
		for r.Holder != nil && !r.Holder.Human && (r.Holder.ExpiresAt <= now || !alive(r.Holder.Sid)) {
			exp := r.Holder.Sid
			r.logEv(now, "expired", exp, LeaseEvent{})
			fresh()
			out = append(out, sweepChange{Name: name, Expired: exp, Promoted: r.promote(now)})
		}
		if r.Holder == nil && len(r.Queue) == 0 && !isKnownDevice(name) && len(r.Log) == 0 {
			delete(st.Resources, name)
		}
	}
	return out
}

func isKnownDevice(name string) bool {
	for _, k := range knownDevices {
		if k == name {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type leasePending struct {
	Name, Sid   string
	Since       int64
	TTL         int64
	Signed      *SignedRequest
	Handover    bool
	Interrupted bool
}

// pendingNotifications: holders promoted from the queue that haven't been told yet
func (st *LeaseState) pendingNotifications() []leasePending {
	var out []leasePending
	for _, name := range sortedKeys(st.Resources) {
		r := st.Resources[name]
		if h := r.Holder; h != nil && h.Promoted && !h.Notified {
			out = append(out, leasePending{Name: name, Sid: h.Sid, Since: h.Since, TTL: h.TTL, Signed: h.Signed, Handover: h.Handover != nil, Interrupted: h.Interrupted})
		}
	}
	return out
}

func (st *LeaseState) markNotified(name, sid string, since int64) {
	if r := st.Resources[name]; r != nil && r.Holder != nil && r.Holder.Sid == sid && r.Holder.Since == since {
		r.Holder.Notified = true
	}
}

func leaseEntryView(e *LeaseEntry, now int64) map[string]any {
	d := e.DescribedAt
	if d == 0 {
		d = e.Since
	}
	v := map[string]any{"sid": e.Sid, "human": e.Human, "purpose": e.Purpose, "description": e.Description, "describedAt": d,
		"note": e.Note, "since": e.Since, "expiresAt": nil, "expiresInSeconds": nil}
	if !e.Human {
		v["expiresAt"] = e.ExpiresAt
		v["expiresInSeconds"] = max(0, int64(math.Round(float64(e.ExpiresAt-now)/1000)))
	}
	return v
}

func leaseView(r *LeaseResource, name string, now int64) map[string]any {
	var holder any
	if r.Holder != nil {
		holder = leaseEntryView(r.Holder, now)
	}
	q := []map[string]any{}
	for i, w := range r.Queue {
		d := w.DescribedAt
		if d == 0 {
			d = w.EnqueuedAt
		}
		q = append(q, map[string]any{"position": i + 1, "sid": w.Sid, "purpose": w.Purpose, "description": w.Description, "describedAt": d,
			"enqueuedAt": w.EnqueuedAt, "interrupted": w.Interrupted})
	}
	lg := r.Log
	if len(lg) > 20 {
		lg = lg[len(lg)-20:]
	}
	if lg == nil {
		lg = []LeaseEvent{}
	}
	return map[string]any{"name": name, "holder": holder, "queue": q, "log": lg}
}

func (st *LeaseState) list(now int64) []map[string]any {
	names := append([]string{}, knownDevices...)
	for _, n := range sortedKeys(st.Resources) {
		if !isKnownDevice(n) {
			names = append(names, n)
		}
	}
	out := []map[string]any{}
	for _, n := range names {
		r := st.Resources[n]
		if r == nil {
			r = &LeaseResource{}
		}
		out = append(out, leaseView(r, n, now))
	}
	return out
}

// ---- the wake texts (built the same way in machine/deliver.go; the router picks when and for which device) ------

func leaseGrantedText(device string, ttlMin int64, handover, interrupted bool, prompt string) string {
	t := fmt.Sprintf("[lease %q granted] This session now holds the shared device %q (you were queued for it). ", device, device) +
		fmt.Sprintf("It is yours for %d min, renewed automatically by the device helpers on every action; return it when done (scripts/lease.py return %s). ", ttlMin, device)
	if handover {
		t += fmt.Sprintf("Deyao had taken %q over himself", device)
		if interrupted {
			t += " (interrupting you: your earlier steps may no longer apply)"
		}
		t += fmt.Sprintf(" and has handed it back; his notes are in scripts/lease.py status %s. The device is in whatever state he left it: look at it first (screenshot / UI tree) and continue from there.", device)
	} else {
		t += "The previous holder may have left it in any state: inspect it first."
	}
	if prompt != "" {
		t += " Your note: " + prompt
	}
	return t
}

func leaseTakenText(device string) string {
	return fmt.Sprintf("[lease %q taken over] Deyao has taken the shared device %q himself. Stop using it now: every device action is refused while he has it. ", device, device) +
		"You are first in the queue; when he hands it back you'll be woken. Then look at the device first: it will be in whatever state he left it. " +
		"This is an automated message from Jarvis."
}

func leaseBackText(device string) string {
	return fmt.Sprintf("[lease %q handed back] Deyao has handed the shared device %q back. Earlier this session found it taken over: that no longer applies. ", device, device) +
		fmt.Sprintf("Run scripts/lease.py status %s to see whether it is free or who holds it now, and acquire it if this session still needs it (scripts/lease.py acquire %s --purpose \"…\"). ", device, device) +
		"If you told Deyao or planned around it being unavailable, reconsider now. It is in whatever state he left it: look at it first. " +
		"This is an automated message from Jarvis."
}

// signedPrompt: the prompt of a signed acquire request (what the machine reads from it too)
func signedPrompt(s *SignedRequest) string {
	if s == nil {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(s.Body)
	if err != nil {
		return ""
	}
	var x struct {
		Prompt string `json:"prompt"`
	}
	json.Unmarshal(b, &x)
	return cleanLine(x.Prompt, leaseMaxPrompt)
}

// ---- the router's side ----------------------------------------------------------------------------------------

func (r *Router) leaseTx(fn func(st *LeaseState) error) error {
	var err error
	r.st.Do(func(d *persisted) { err = fn(leasesOf(d)) })
	return err
}

func (r *Router) LeaseList() []map[string]any {
	var out []map[string]any
	r.leaseTx(func(st *LeaseState) error { out = st.list(time.Now().UnixMilli()); return nil })
	return out
}

func leaseErr(w http.ResponseWriter, err error) {
	var le *leaseError
	if errors.As(err, &le) {
		out := map[string]any{"error": le.msg}
		if le.takenOver {
			out["takenOver"] = true
		}
		writeJSON(w, le.status, out)
		return
	}
	scheduleErr(w, err)
}

func leaseBody(b []byte) (map[string]any, error) {
	m, err := decodeBody(b)
	if err != nil {
		return nil, leaseErrf(400, "%v", err)
	}
	return m, nil
}

func optStr(m map[string]any, k string) *string {
	v, ok := m[k]
	if !ok || v == nil {
		return nil
	}
	s := fmt.Sprint(v)
	return &s
}

func (r *Router) registerLeases(app appRoute, m machineRoute, public publicRoute) {
	// ---- the app (Deyao) -------------------------------------------------------------------------------
	app("GET /api/leases", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, 200, map[string]any{"leases": r.LeaseList()})
	})
	app("GET /api/leases/{name}", func(w http.ResponseWriter, req *http.Request) { r.getLease(w, req.PathValue("name")) })
	app("POST /api/leases/{name}/force-return", func(w http.ResponseWriter, req *http.Request) {
		name := req.PathValue("name")
		var out *giveBackOut
		err := r.leaseTx(func(st *LeaseState) (e error) { out, e = st.giveBack(name, "", time.Now().UnixMilli(), true); return })
		if err != nil {
			leaseErr(w, err)
			return
		}
		log.Printf("[lease] %s: force-returned from %q%s", name, out.Previous, promotedSuffix(out.Promoted))
		writeJSON(w, 200, map[string]any{"returned": out.Returned, "previous": nullIfEmpty(out.Previous), "next": promotedSid(out.Promoted)})
		r.kickLeases(out.Promoted)
	})
	app("POST /api/leases/{name}/take-over", func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<16))
		r.takeOverLease(w, req.PathValue("name"), b)
	})
	app("POST /api/leases/{name}/hand-back", func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<16))
		r.handBackLease(w, req.PathValue("name"), b)
	})
	// the setup session (Claude, fully trusted: DECISIONS 57) acts for Deyao here, e.g. to carry his Jarvis 1
	// take-overs over (DECISIONS 113); signed with the setup key like every /setup call
	for _, act := range []string{"take-over", "hand-back"} {
		public("POST /setup/leases/{name}/"+act, r.requireSetup(func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<16))
			if err := r.checkSetupSig(req.Method, req.URL.Path, req.Header.Get("X-Setup-Time"), req.Header.Get("X-Setup-Sig"), b); err != nil {
				writeJSON(w, 401, map[string]string{"error": err.Error()})
				return
			}
			if act == "take-over" {
				r.takeOverLease(w, req.PathValue("name"), b)
			} else {
				r.handBackLease(w, req.PathValue("name"), b)
			}
		}))
	}

	// ---- the session itself (through its machine's local proxy; the path's id must be its own) ---------------------
	own := func(pattern string, fn func(w http.ResponseWriter, req *http.Request, sid, machine string, body []byte)) {
		m(pattern, func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
			sid, err := r.machineSession(machine)
			if err != nil {
				writeJSON(w, 403, map[string]string{"error": err.Error()})
				return
			}
			if id := req.PathValue("id"); id != "" && id != sid {
				writeJSON(w, 403, map[string]string{"error": fmt.Sprintf("this machine is session %s, not %s", sid, id)})
				return
			}
			fn(w, req, sid, machine, body)
		})
	}
	own("GET /m/api/leases", func(w http.ResponseWriter, req *http.Request, _, _ string, _ []byte) {
		writeJSON(w, 200, map[string]any{"leases": r.LeaseList()})
	})
	own("GET /m/api/leases/{name}", func(w http.ResponseWriter, req *http.Request, _, _ string, _ []byte) {
		r.getLease(w, req.PathValue("name"))
	})
	own("POST /m/api/sessions/{id}/leases/{name}", func(w http.ResponseWriter, req *http.Request, sid, machine string, b []byte) {
		name := req.PathValue("name")
		m, err := leaseBody(b)
		if err != nil {
			leaseErr(w, err)
			return
		}
		low, _ := m["lowPriority"].(bool)
		o := LeaseOpts{Purpose: optStr(m, "purpose"), Description: optStr(m, "description"), Prompt: deref(optStr(m, "prompt")), TTL: m["ttlSeconds"],
			LowPriority: low, Signed: signedRequestOf(req, req.Header.Get("X-Machine"), b)}
		var out *LeaseOut
		err = r.leaseTx(func(st *LeaseState) (e error) { out, e = st.acquire(name, sid, o, time.Now().UnixMilli()); return })
		if err != nil {
			leaseErr(w, err)
			return
		}
		if out.Status != "renewed" {
			log.Printf("[lease] %s: %s %s #%d (%s)", name, sid, out.Status, out.Position, trimTo(deref(o.Purpose), 60))
		}
		status := 200
		if out.Status == "busy" {
			status = 409
		}
		writeJSON(w, status, out)
	})
	own("PUT /m/api/sessions/{id}/leases/{name}", func(w http.ResponseWriter, req *http.Request, sid, _ string, _ []byte) {
		var out *LeaseOut
		// a take-over refusal is kept too: it records the session to be told when Deyao hands the device back
		err := r.leaseTx(func(st *LeaseState) (e error) {
			out, e = st.renew(req.PathValue("name"), sid, time.Now().UnixMilli())
			return
		})
		if err != nil {
			leaseErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	own("PATCH /m/api/sessions/{id}/leases/{name}", func(w http.ResponseWriter, req *http.Request, sid, _ string, b []byte) {
		m, err := leaseBody(b)
		if err != nil {
			leaseErr(w, err)
			return
		}
		var out *LeaseOut
		err = r.leaseTx(func(st *LeaseState) (e error) {
			out, e = st.describe(req.PathValue("name"), sid, LeaseOpts{Purpose: optStr(m, "purpose"), Description: optStr(m, "description")}, time.Now().UnixMilli())
			return
		})
		if err != nil {
			leaseErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	own("POST /m/api/sessions/{id}/leases/{name}/seen", func(w http.ResponseWriter, req *http.Request, sid, _ string, _ []byte) {
		var taken bool
		err := r.leaseTx(func(st *LeaseState) (e error) { taken, e = st.noteBlocked(req.PathValue("name"), sid); return })
		if err != nil {
			leaseErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"takenOver": taken})
	})
	own("DELETE /m/api/sessions/{id}/leases/{name}", func(w http.ResponseWriter, req *http.Request, sid, _ string, _ []byte) {
		name := req.PathValue("name")
		var gb *giveBackOut
		left := false
		err := r.leaseTx(func(st *LeaseState) (e error) {
			res, e := st.res(name)
			if e != nil {
				return e
			}
			if res.Holder != nil && res.Holder.Sid == sid {
				gb, e = st.giveBack(name, sid, time.Now().UnixMilli(), false)
				return e
			}
			gb = &giveBackOut{}
			left, e = st.leave(name, sid)
			return e
		})
		if err != nil {
			leaseErr(w, err)
			return
		}
		what := "had nothing"
		if gb.Returned {
			what = "returned it"
		} else if left {
			what = "left the queue"
		}
		log.Printf("[lease] %s: %s %s%s", name, sid, what, promotedSuffix(gb.Promoted))
		writeJSON(w, 200, map[string]any{"returned": gb.Returned, "left": left, "next": promotedSid(gb.Promoted)})
		r.kickLeases(gb.Promoted)
	})
}

// takeOverLease: Deyao takes the device himself (the app, or the setup session for him)
func (r *Router) takeOverLease(w http.ResponseWriter, name string, b []byte) {
	m, err := leaseBody(b)
	if err != nil {
		leaseErr(w, err)
		return
	}
	var out *takeOverOut
	err = r.leaseTx(func(st *LeaseState) (e error) {
		out, e = st.takeOver(name, optStr(m, "note"), time.Now().UnixMilli())
		return
	})
	if err != nil {
		leaseErr(w, err)
		return
	}
	log.Printf("[lease] %s: Deyao took it over (interrupted %q)", name, out.Interrupted)
	writeJSON(w, 200, map[string]any{"taken": out.Taken, "interrupted": nullIfEmpty(out.Interrupted), "noteUpdated": out.NoteUpdated})
	if out.Interrupted != "" {
		leaseWG.Add(1)
		go r.tellLease(out.Interrupted, Delivery{Kind: "lease-taken", Device: name}, 1)
	}
}

// handBackLease: Deyao gives it back
func (r *Router) handBackLease(w http.ResponseWriter, name string, b []byte) {
	m, err := leaseBody(b)
	if err != nil {
		leaseErr(w, err)
		return
	}
	var out *handBackOut
	err = r.leaseTx(func(st *LeaseState) (e error) {
		out, e = st.handBack(name, deref(optStr(m, "note")), time.Now().UnixMilli())
		return
	})
	if err != nil {
		leaseErr(w, err)
		return
	}
	log.Printf("[lease] %s: Deyao handed it back%s; telling %v", name, promotedSuffix(out.Promoted), out.Notify)
	writeJSON(w, 200, map[string]any{"handedBack": out.HandedBack, "next": promotedSid(out.Promoted), "notified": orEmptyS(out.Notify)})
	r.kickLeases(out.Promoted)
	for _, sid := range out.Notify {
		leaseWG.Add(1)
		go r.tellLease(sid, Delivery{Kind: "lease-back", Device: name}, 5)
	}
}

func (r *Router) getLease(w http.ResponseWriter, name string) {
	if !leaseNameRE.MatchString(name) {
		writeJSON(w, 400, map[string]string{"error": "bad resource name (lowercase letters/digits/dashes)"})
		return
	}
	var v map[string]any
	r.leaseTx(func(st *LeaseState) error {
		res := st.Resources[name]
		if res == nil {
			res = &LeaseResource{}
		}
		v = leaseView(res, name, time.Now().UnixMilli())
		return nil
	})
	writeJSON(w, 200, map[string]any{"lease": v})
}

func promotedSid(p *LeaseEntry) any {
	if p == nil {
		return nil
	}
	return p.Sid
}

func promotedSuffix(p *LeaseEntry) string {
	if p == nil {
		return ""
	}
	return " → " + p.Sid
}

// kickLeases: wake a promoted holder now rather than on the next tick
func (r *Router) kickLeases(p *LeaseEntry) {
	if p != nil {
		leaseWG.Add(1)
		go func() { defer leaseWG.Done(); r.leaseTick() }()
	}
}

// tellLease: an image text about a device (taken over, handed back), with a few retries (a session mid-pause or
// mid-start refuses a delivery for a while)
func (r *Router) tellLease(sid string, d Delivery, tries int) {
	defer leaseWG.Done()
	for i := 1; ; i++ {
		err := deliverVouchedHook(r, sid, d)
		if err == nil {
			log.Printf("[lease] %s: told %s (%s)", d.Device, sid, d.Kind)
			return
		}
		if i >= tries || errors.Is(err, errNoSession) {
			log.Printf("[lease] %s: telling %s (%s) failed: %v", d.Device, sid, d.Kind, err)
			return
		}
		time.Sleep(leaseRetryWait)
	}
}

var leaseRetryWait = time.Minute

// leaseWG: the lease goroutines in flight (tests wait for them before restoring their seams)
var leaseWG sync.WaitGroup

var leaseRun = struct {
	sync.Mutex
	busy     map[string]bool
	attempts map[string]int
	ticking  sync.Mutex
}{busy: map[string]bool{}, attempts: map[string]int{}}

func (r *Router) leaseLoop() {
	for {
		awaitLead() // leaderlease.go
		r.leaseTick()
		time.Sleep(leaseTickEvery)
	}
}

// leaseTick: expire silent holders, drop gone sessions, and wake each newly promoted holder. The wake is delivered
// outside the state lock (a paused session takes minutes to start) and marked only once delivered, so a failure is
// retried at the next tick.
func (r *Router) leaseTick() {
	if !leaseRun.ticking.TryLock() {
		return
	}
	defer leaseRun.ticking.Unlock()
	now := time.Now().UnixMilli()
	var changes []sweepChange
	var pending []leasePending
	r.st.Do(func(d *persisted) {
		alive := func(sid string) bool {
			s := d.Sessions[sid]
			return s != nil && s.State != "destroyed" && s.State != "destroying"
		}
		st := leasesOf(d)
		changes = st.sweep(now, alive)
		pending = st.pendingNotifications()
	})
	for _, c := range changes {
		log.Printf("[lease] %s: %s lost it (expired or gone)%s", c.Name, c.Expired, promotedSuffix(c.Promoted))
	}
	for _, p := range pending {
		key := fmt.Sprintf("%s/%s/%d", p.Name, p.Sid, p.Since)
		leaseRun.Lock()
		if leaseRun.busy[key] || leaseRun.attempts[key] >= leaseMaxAttempts {
			leaseRun.Unlock()
			continue
		}
		leaseRun.busy[key] = true
		leaseRun.Unlock()
		leaseWG.Add(1)
		go func(p leasePending) {
			defer leaseWG.Done()
			defer func() { leaseRun.Lock(); delete(leaseRun.busy, key); leaseRun.Unlock() }()
			d := Delivery{Kind: "lease-granted", Device: p.Name, Request: p.Signed, Minutes: int(max(1, p.TTL/60)), Handover: p.Handover, Interrupted: p.Interrupted}
			if err := deliverVouchedHook(r, p.Sid, d); err != nil {
				leaseRun.Lock()
				leaseRun.attempts[key]++
				n := leaseRun.attempts[key]
				leaseRun.Unlock()
				log.Printf("[lease] %s: waking %s failed (%d/%d): %v", p.Name, p.Sid, n, leaseMaxAttempts, err)
				if errors.Is(err, errNoSession) || n >= leaseMaxAttempts {
					r.leaseTx(func(st *LeaseState) error { st.markNotified(p.Name, p.Sid, p.Since); return nil })
				}
				return
			}
			r.leaseTx(func(st *LeaseState) error { st.markNotified(p.Name, p.Sid, p.Since); return nil })
			leaseRun.Lock()
			delete(leaseRun.attempts, key)
			leaseRun.Unlock()
			log.Printf("[lease] %s: %s woken", p.Name, p.Sid)
		}(p)
	}
}

func init() {
	stateHooks = append(stateHooks, func(r *Router, out map[string]any) {
		if r != nil && r.st != nil {
			out["leases"] = r.LeaseList()
		}
	})
}
