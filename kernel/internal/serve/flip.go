package serve

// The copy flip (docs/PLAN-cluster.md "Releases: the copy flip"): a kernel release lands on the copy that doesn't
// serve; once the root key signed that copy's roster (which names the serving copy's members as retired), the router
// asks every serving component to hand over:
//
//	POST /handoff  {roster}   on a serving component: the other copy's root-signed roster, which must retire this
//	                          component's keys → {kind: "handoff", role, from, roster, to, sealed?}, signed. A
//	                          stateful component (the notarizer, the spawner) seals its state to the agreement key that
//	                          roster names for its role; every component freezes in the same step (it answers nothing
//	                          but its identity, its roster and a handoff again from then on), so no state goes on in
//	                          two places. Again for a newer roster of the other copy (one of its components restarted
//	                          before it took over): the same frozen state, sealed to that roster.
//	POST /takeover {handoff}  on the other copy's stateful component: a handoff for exactly the roster it holds, sealed
//	                          to its own key and signed by the member of its role that roster retires → it takes the
//	                          state whole (replacing what its volume held) and serves. The same handoff again answers
//	                          the same; any other is refused: once it took one it serves (kept on its volume), so a
//	                          frozen state handed over again can never replace the newer one it went on with.
//
// A stateful component keeps its place in the flip on its volume (Continuity): serving, standby (never served, or
// waiting to take a handoff) or handed-off. A volume that never held either is decided by its first roster: standby
// when that roster retires a member of its role (another copy served before it), serving otherwise (the first copy).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/DE0CH/jarvis4/kernel/sig"
)

// The modes of a stateful component, and the reasons of the refusals the router acts on
const (
	ModeServing   = "serving"
	ModeStandby   = "standby"
	ModeHandedOff = "handed-off"

	ReasonStandby   = "standby"    // 409: a standby serves nothing until it takes its predecessor's handoff
	ReasonHandedOff = "handed-off" // 409: this component handed over to the other copy and serves nothing
)

// HandoffInfo: what a handoff's state is sealed under (+ the role)
const HandoffInfo = "jarvis2/kernel-handoff/"

// Handoff: what a component signs when it hands over (the state sealed to its successor's agreement key)
type Handoff struct {
	Kind   string      `json:"kind"`   // "handoff"
	Role   string      `json:"role"`   // the component's role
	From   string      `json:"from"`   // the copy it served in
	Roster string      `json:"roster"` // the ID of the roster it handed over to
	To     string      `json:"to"`     // that roster's agreement key for the role
	Sealed *sig.Sealed `json:"sealed,omitempty"`
}

// Stateful: a component whose state moves to the other copy (Continuity holds its mode)
type Stateful interface {
	// Decide: the first roster a never-decided volume holds sets its mode
	Decide(r sig.Roster) error
	// Handoff: the component freezes (kept before it answers) and gives its state; again for the same roster: the
	// same state (nothing changed since)
	Handoff(roster string) ([]byte, error)
	// Takeover: the state replaces the component's own and it serves; again with the same handoff: nothing
	Takeover(handoff string, state []byte) error
}

// ---- continuity: a stateful component's mode on its volume -----------------------------------------------------

type continuityState struct {
	Mode string `json:"mode"`
	To   string `json:"to,omitempty"`   // handed-off: the roster it handed over to
	Took string `json:"took,omitempty"` // the last handoff it took
}

// Continuity: a stateful component's place in the flip, kept in a file on its volume. Its methods are called with
// the component's own lock held, so a mode change and the component's work never interleave.
type Continuity struct {
	mu   sync.Mutex
	path string
	st   continuityState
}

// OpenContinuity: the mode at path ("" until the first roster decides it)
func OpenContinuity(path string) (*Continuity, error) {
	c := &Continuity{path: path}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, &c.st); err != nil {
			return nil, fmt.Errorf("%s: %v", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return c, nil
}

func (c *Continuity) save(st continuityState) error {
	b, _ := json.Marshal(st)
	tmp := c.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Clean(c.path)); err != nil {
		return err
	}
	c.st = st
	return nil
}

// Mode: serving, standby, handed-off, or "" (no roster has decided it yet)
func (c *Continuity) Mode() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st.Mode
}

// Decide: a volume no roster decided yet: standby when r retires a member of role (another copy served before this
// one; its state comes with its handoff), else serving (the first copy)
func (c *Continuity) Decide(r sig.Roster, role string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st.Mode != "" {
		return nil
	}
	m := ModeServing
	if len(r.RetiredOf(role)) > 0 {
		m = ModeStandby
	}
	return c.save(continuityState{Mode: m})
}

// Serving: nil when the component serves, else the refusal
func (c *Continuity) Serving() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.st.Mode {
	case ModeServing:
		return nil
	case ModeHandedOff:
		return FailBecause(409, ReasonHandedOff, "this component handed over to the other kernel copy: it serves nothing")
	case ModeStandby:
		return FailBecause(409, ReasonStandby, "this component is a standby: it serves nothing until it takes its predecessor's handoff")
	}
	return FailBecause(503, ReasonStandby, "%v", sig.ErrNoRoster)
}

// Freeze: a serving component hands over to roster (kept before the state leaves); a frozen one again, to that roster
// or a newer one of the same other copy (its component restarted before it took the first: the frozen state is the
// same, and a component that took a handoff serves and takes no other, so it can't come back stale)
func (c *Continuity) Freeze(roster string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.st.Mode == ModeHandedOff && c.st.To == roster:
		return nil
	case c.st.Mode == ModeHandedOff:
		return c.save(continuityState{Mode: ModeHandedOff, To: roster, Took: c.st.Took})
	case c.st.Mode != ModeServing:
		return FailBecause(409, ReasonStandby, "this component doesn't serve: it has nothing to hand over")
	}
	return c.save(continuityState{Mode: ModeHandedOff, To: roster, Took: c.st.Took})
}

// CanTake: whether the component takes handoff now (again: it took exactly that one already)
func (c *Continuity) CanTake(handoff string) (again bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.st.Mode == ModeServing && c.st.Took == handoff:
		return true, nil
	case c.st.Mode == ModeServing:
		return false, Fail(409, "this component serves: it takes no handoff")
	case c.st.Mode == "":
		return false, Fail(503, "%v", sig.ErrNoRoster)
	}
	return false, nil
}

// Took: the component serves from the handoff's state (called once that state is kept)
func (c *Continuity) Took(handoff string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.save(continuityState{Mode: ModeServing, Took: handoff})
}

// ---- the routes --------------------------------------------------------------------------------------------------

// HandoffIn, TakeoverIn: what the router posts
type HandoffIn struct {
	Roster sig.Doc `json:"roster"`
}

type TakeoverIn struct {
	Handoff sig.Doc `json:"handoff"`
}

// frozenAllowed: what a component that handed over still answers
func frozenAllowed(pattern string) bool {
	switch pattern {
	case "GET /identity", "GET /roster", "POST /roster", "POST /handoff", "POST /takeover":
		return true
	}
	return false
}

func (s *Server) registerFlip() {
	Handle(s, "POST /handoff", func(in HandoffIn) (any, error) { return s.handoff(in.Roster) })
	Handle(s, "POST /takeover", func(in TakeoverIn) (any, error) { return s.takeover(in.Handoff) })
}

// handoff: the checks, the freeze, the signed handoff
func (s *Server) handoff(d sig.Doc) (sig.Doc, error) {
	own := s.Trust.Roster()
	if own == nil {
		return sig.Doc{}, Fail(503, "%v", sig.ErrNoRoster)
	}
	r, err := sig.OpenRoster(d, s.Trust.Root())
	if err != nil {
		return sig.Doc{}, Fail(403, "%v", err)
	}
	role := s.C.Role
	if r.Copy == own.Copy {
		return sig.Doc{}, Fail(409, "a handoff goes to the other kernel copy (this is %s's %s)", own.Copy, role)
	}
	if !slices.Contains(r.RetiredOf(role), s.C.Identity) {
		return sig.Doc{}, Fail(403, "the %s roster doesn't retire this %s's keys", r.Copy, role)
	}
	to, ok := r.Member(role)
	if !ok {
		return sig.Doc{}, Fail(403, "the %s roster names no %s", r.Copy, role)
	}
	id := d.ID()
	h := Handoff{Kind: "handoff", Role: role, From: own.Copy, Roster: id, To: to.AgreementKey}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.State != nil {
		state, err := s.State.Handoff(id)
		if err != nil {
			return sig.Doc{}, err
		}
		sealed, err := sig.SealTo(to.AgreementKey, state, HandoffInfo+role)
		if err != nil {
			return sig.Doc{}, err
		}
		h.Sealed = &sealed
	}
	s.frozenTo = id
	return s.C.Signer.SignJSON(h)
}

// takeover: a handoff for the roster this component holds, from the member of its role that roster retires
func (s *Server) takeover(d sig.Doc) (any, error) {
	held := s.Trust.Doc()
	own := s.Trust.Roster()
	if held == nil || own == nil {
		return nil, Fail(503, "%v", sig.ErrNoRoster)
	}
	if s.State == nil {
		return nil, Fail(400, "a %s holds no state: it takes no handoff", s.C.Role)
	}
	var h Handoff
	if err := sig.StrictJSON([]byte(d.Payload), &h); err != nil || h.Kind != "handoff" || h.Sealed == nil {
		return nil, Fail(400, "not a handoff")
	}
	role := s.C.Role
	switch {
	case h.Role != role:
		return nil, Fail(403, "a handoff of a %s, not of this %s", h.Role, role)
	case h.Roster != held.ID():
		return nil, Fail(403, "a handoff to another roster than the one this %s holds", role)
	case h.To != s.C.Identity.AgreementKey:
		return nil, Fail(403, "a handoff sealed to other keys than this %s's", role)
	}
	by := ""
	for _, m := range own.RetiredOf(role) {
		if sig.Verify(m.SigningKey, []byte(d.Payload), d.Sig) {
			by = m.SigningKey
		}
	}
	if by == "" {
		return nil, Fail(403, "the handoff isn't signed by the %s this roster retires", role)
	}
	plain, err := sig.OpenSealed(s.C.Agreement, *h.Sealed, HandoffInfo+role)
	if err != nil {
		return nil, Fail(403, "the handoff's state doesn't open with this %s's key", role)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.State.Takeover(d.ID(), plain); err != nil {
		return nil, err
	}
	s.frozenTo = ""
	return map[string]any{"kind": "took-over", "role": role, "handoff": d.ID(), "from": h.From}, nil
}

// frozen: the handoff this component made ("" = none)
func (s *Server) frozen() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.frozenTo
}
