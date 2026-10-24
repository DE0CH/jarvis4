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
type Roster struct {
	Kind    string     `json:"kind"` // "kernel-roster"
	Copy    string     `json:"copy"` // "blue" or "green"
	Members []Identity `json:"members"`
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
	for i, m := range r.Members {
		if m.Role == "" || m.SigningKey == "" || m.AgreementKey == "" || strings.ContainsAny(m.SigningKey+m.AgreementKey, " \n") {
			return r, errors.New("a roster member without keys")
		}
		if i > 0 && r.Members[i-1].Role >= m.Role {
			return r, errors.New("the roster's members aren't sorted by role, one each")
		}
	}
	return r, nil
}

// RosterPayload: the exact payload the setup key and the root key sign (members sorted by role)
func RosterPayload(copy string, members []Identity) (string, error) {
	m := slices.Clone(members)
	slices.SortFunc(m, func(a, b Identity) int { return strings.Compare(a.Role, b.Role) })
	b, err := json.Marshal(Roster{Kind: "kernel-roster", Copy: copy, Members: m})
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

// Set: d is the root key's roster, and it names self (nil: a machine, which is no member)
func (t *Trust) Set(d Doc, self *Identity) error {
	r, err := OpenRoster(d, t.root)
	if err != nil {
		return err
	}
	if self != nil {
		if m, ok := r.Member(self.Role); !ok || m != *self {
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

// Member: the keys the held roster names for role
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

// CheckIdentity: id is the roster's for that role
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
	if m, ok := r.Member(role); !ok || m != id {
		return fmt.Errorf("the %s identity isn't the roster's", role)
	}
	return nil
}
