package sig

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// Identity: a component's fresh keys, made when it starts. Nobody vouches for them by themselves: anyone checks them
// against the kernel's roster, which the root key signs (docs/PLAN-cluster.md "The roster").
type Identity struct {
	Role         string `json:"role"`
	SigningKey   string `json:"signingKey"`
	AgreementKey string `json:"agreementKey"`
}

// Component: a running component's keys
type Component struct {
	Role      string
	Signer    *Signer
	Agreement *ecdh.PrivateKey
	Identity  Identity
}

// NewComponent: fresh keys for role, held in RAM only (a restart makes new ones, which need a new roster)
func NewComponent(role string) (*Component, error) {
	s, err := NewSigner()
	if err != nil {
		return nil, err
	}
	ag, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	agPub := B64.EncodeToString(ag.PublicKey().Bytes())
	return &Component{Role: role, Signer: s, Agreement: ag, Identity: Identity{role, s.PublicKey(), agPub}}, nil
}

// Roster: one kernel copy's components and their keys, as the root key signs it. Members sorted by role, one each.
//
// Retired: keys that served before and sign nothing new (docs/PLAN-cluster.md "Releases: the copy flip"): the
// other copy's members, named by the roster of the copy that takes over from it, and a component's keys from before
// it restarted (a crash), named by its copy's next roster. What a retired key signed while it served still counts
// (a grant, a cert, a notarization a line holds); and a stateful member's handoff is taken only from the retired
// member of its role. Never secrets (its keys come from the kit, the same in both copies). Sorted by role, then
// signing key; no retired key is also a member.
//
// SecretsBoot: in the roster of the copy that takes over, the keys its secrets started with: the serving secrets
// hands over its seed and its final state sealed to them, and from then on that secrets serves with the keys the
// seed derives, which Members names (the same as the serving copy's).
type Roster struct {
	Kind        string     `json:"kind"` // "kernel-roster"
	Copy        string     `json:"copy"` // "blue" or "green"
	Members     []Identity `json:"members"`
	Retired     []Identity `json:"retired,omitempty"`
	SecretsBoot *Identity  `json:"secretsBoot,omitempty"`
}

func keysOK(m Identity) bool {
	return m.Role != "" && m.SigningKey != "" && m.AgreementKey != "" && !strings.ContainsAny(m.SigningKey+m.AgreementKey, " \n")
}

// OpenRoster: d is a roster the root key signed
func OpenRoster(d Doc, rootPub string) (Roster, error) {
	var r Roster
	if rootPub == "" {
		return r, errors.New("no root key to check the roster with")
	}
	if !Verify(rootPub, []byte(d.Payload), d.Sig) {
		return r, errors.New("the roster isn't signed by the root key")
	}
	if err := StrictJSON([]byte(d.Payload), &r); err != nil {
		return r, fmt.Errorf("the roster: %v", err)
	}
	if r.Kind != "kernel-roster" || (r.Copy != "blue" && r.Copy != "green") || len(r.Members) == 0 {
		return r, errors.New("not a kernel roster")
	}
	keys := map[string]bool{}
	for i, m := range r.Members {
		if !keysOK(m) {
			return r, errors.New("a roster member without keys")
		}
		if i > 0 && r.Members[i-1].Role >= m.Role {
			return r, errors.New("the roster's members aren't sorted by role, one each")
		}
		keys[m.SigningKey] = true
	}
	for i, m := range r.Retired {
		if !keysOK(m) || m.Role == "secrets" {
			return r, errors.New("a retired member without keys, or secrets (never retired)")
		}
		if keys[m.SigningKey] {
			return r, errors.New("a retired key is also a member")
		}
		if i > 0 && retiredLess(m, r.Retired[i-1]) || i > 0 && r.Retired[i-1] == m {
			return r, errors.New("the roster's retired members aren't sorted by role and signing key, once each")
		}
	}
	if b := r.SecretsBoot; b != nil && (!keysOK(*b) || b.Role != "secrets") {
		return r, errors.New("secretsBoot: a secrets identity")
	}
	return r, nil
}

func retiredLess(a, b Identity) bool {
	if a.Role != b.Role {
		return a.Role < b.Role
	}
	return a.SigningKey < b.SigningKey
}

// Payload: the exact payload the setup key and the root key sign (kind set, members sorted by role, retired by role
// and signing key)
func (r Roster) Payload() (string, error) {
	r.Kind = "kernel-roster"
	r.Members = slices.Clone(r.Members)
	slices.SortFunc(r.Members, func(a, b Identity) int { return strings.Compare(a.Role, b.Role) })
	r.Retired = slices.Clone(r.Retired)
	slices.SortFunc(r.Retired, func(a, b Identity) int {
		if retiredLess(a, b) {
			return -1
		}
		if retiredLess(b, a) {
			return 1
		}
		return 0
	})
	if len(r.Retired) == 0 {
		r.Retired = nil
	}
	b, err := json.Marshal(r)
	return string(b), err
}

// Trust: the roster a component (or a machine) checks identities against. It starts empty; Set takes a roster the
// root key signed. A component keeps only a roster that names its own keys under its own role.
type Trust struct {
	mu   sync.Mutex
	root string
	doc  *Doc
	r    *Roster
}

// ErrNoRoster: nothing is checked before the root key's roster arrives (a component answers 503)
var ErrNoRoster = errors.New("no roster yet: the kernel's components wait for the root key's roster (Settings → Kernel)")

func NewTrust(rootPub string) *Trust { return &Trust{root: rootPub} }

// Set: d is the root key's roster, and it names self (nil: a machine, which is no member): as the member of its
// role, or, for an empty secrets, as the roster's secretsBoot (it takes over in the copy flip)
func (t *Trust) Set(d Doc, self *Identity) error {
	r, err := OpenRoster(d, t.root)
	if err != nil {
		return err
	}
	if self != nil {
		m, ok := r.Member(self.Role)
		boot := self.Role == "secrets" && r.SecretsBoot != nil && *r.SecretsBoot == *self
		if (!ok || m != *self) && !boot {
			return fmt.Errorf("the roster doesn't name this %s's keys", self.Role)
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.doc, t.r = &d, &r
	return nil
}

// Doc: the roster held (nil: none yet)
func (t *Trust) Doc() *Doc {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.doc
}

func (t *Trust) Root() string { return t.root }

// Member: the roster's keys for role
func (r Roster) Member(role string) (Identity, bool) {
	for _, m := range r.Members {
		if m.Role == role {
			return m, true
		}
	}
	return Identity{}, false
}

// Roster: the roster held (nil: none yet)
func (t *Trust) Roster() *Roster {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.r == nil {
		return nil
	}
	r := *t.r
	return &r
}

// RetiredOf: the roster's retired keys of role (they sign nothing new; what they signed still counts)
func (r Roster) RetiredOf(role string) []Identity {
	out := []Identity{}
	for _, m := range r.Retired {
		if m.Role == role {
			out = append(out, m)
		}
	}
	return out
}

// SigningKeys: every key whose signature as role the held roster takes: the member's, then the retired ones
func (t *Trust) SigningKeys(role string) []string {
	r := t.Roster()
	if r == nil {
		return nil
	}
	out := []string{}
	if m, ok := r.Member(role); ok {
		out = append(out, m.SigningKey)
	}
	for _, m := range r.RetiredOf(role) {
		out = append(out, m.SigningKey)
	}
	return out
}

// Member: the keys the held roster names for role (the current member only: what is sealed to it, or must be
// signed by it now)
func (t *Trust) Member(role string) (Identity, error) {
	t.mu.Lock()
	r := t.r
	t.mu.Unlock()
	if r == nil {
		return Identity{}, ErrNoRoster
	}
	m, ok := r.Member(role)
	if !ok {
		return Identity{}, fmt.Errorf("the roster names no %s", role)
	}
	return m, nil
}

// CheckIdentity: id is the roster's for that role: its member, or a retired one (what it signed while it served still
// counts; it signs nothing new: a retired component froze at its copy's handoff, or its process is gone)
func CheckIdentity(id Identity, role string, t *Trust) error {
	if id.Role != role || strings.ContainsAny(id.SigningKey+id.AgreementKey, " \n") {
		return fmt.Errorf("not a %s identity", role)
	}
	t.mu.Lock()
	r := t.r
	t.mu.Unlock()
	if r == nil {
		return ErrNoRoster
	}
	if m, ok := r.Member(role); ok && m == id {
		return nil
	}
	if slices.Contains(r.RetiredOf(role), id) {
		return nil
	}
	return fmt.Errorf("the %s identity isn't the roster's", role)
}
