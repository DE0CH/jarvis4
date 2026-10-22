// Package notarizer: the succession notarizer (DESIGN "Target design"). It checks a succession cert against the
// policy table — the shape (kinds of predecessor and successor), the signer's key, and "first successor of a source" —
// and answers the log notary's challenge over the cert's ID. A shape not in the table is refused. It remembers, on its
// own volume, every source that has been defined (a source is defined once, by the first cert into it) and every
// source that has a successor; both are written and synced before the answer.
package notarizer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// ChallengeSkew: how far a challenge's time may be from the notarizer's clock
const ChallengeSkew = 10 * time.Minute

// Keys: the phone's and the root key, as secrets signs them after the claim ({"kind":"keys",…})
type Keys struct {
	Kind  string `json:"kind"` // "keys"
	Phone string `json:"phone"`
	Root  string `json:"root"`
}

// Input: a cert, the notary's challenge over it, and what names the signer's key
type Input struct {
	Cert      sig.Doc       `json:"cert"`
	Challenge sig.Doc       `json:"challenge"`
	Notary    sig.Identity  `json:"notary"`
	Signer    *sig.Identity `json:"signer,omitempty"`  // spawner, identity or gullible: its identity, checked against the roster
	Keys      *sig.Doc      `json:"keys,omitempty"`    // iphone or root: secrets' signed Keys
	Secrets   *sig.Identity `json:"secrets,omitempty"` // … and secrets' identity
}

type entry struct {
	Defined   doc.Object `json:"defined,omitempty"`
	Succeeded doc.Object `json:"succeeded,omitempty"`
}

type Notarizer struct {
	mu        sync.Mutex
	s         *sig.Signer
	trust     *sig.Trust
	f         *os.File
	defined   map[doc.Object]bool
	succeeded map[doc.Object]bool
	now       func() time.Time
}

// Open: the state at path (made if missing)
func Open(path string, s *sig.Signer, t *sig.Trust) (*Notarizer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	n := &Notarizer{s: s, trust: t, f: f, defined: map[doc.Object]bool{}, succeeded: map[doc.Object]bool{}, now: time.Now}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("%s: a bad line: %v", path, err)
		}
		if e.Defined != "" {
			n.defined[e.Defined] = true
		}
		if e.Succeeded != "" {
			n.succeeded[e.Succeeded] = true
		}
	}
	return n, sc.Err()
}

// rule: the table row for a shape and signer, or why there is none
func rule(c doc.Cert) error {
	pk, sk, same := c.Pred.Kind(), c.Succ.Kind(), c.Pred == c.Succ
	ok := false
	switch c.Signer {
	case doc.ByRoot:
		ok = true
	case doc.ByIPhone:
		ok = pk == "sink" && sk == "source" || pk == "source" && sk == "fly"
	case doc.BySpawner:
		ok = pk == "source" && sk == "fly" || pk == "fly" && sk == "source"
		if ok && !c.Pair.Leq(perm.Top()) || ok && !perm.Top().Leq(c.Pair) {
			return fmt.Errorf("the spawner attests Fly facts only: its pair is ⊤")
		}
	case doc.ByIdentity:
		ok = pk == "fly" && same
	case doc.ByGullible:
		ok = pk == "source" && sk == "sink"
	default:
		return fmt.Errorf("unknown signer %q", c.Signer)
	}
	if !ok {
		return fmt.Errorf("(%s, %s) signed by %s is not in the table", pk, sk, c.Signer)
	}
	return nil
}

// signerKey: the public key that must have signed the cert
func (n *Notarizer) signerKey(c doc.Cert, in Input) (string, error) {
	switch c.Signer {
	case doc.ByIPhone, doc.ByRoot:
		if in.Keys == nil || in.Secrets == nil {
			return "", fmt.Errorf("a %s cert needs secrets' signed keys", c.Signer)
		}
		if err := sig.CheckIdentity(*in.Secrets, "secrets", n.trust); err != nil {
			return "", err
		}
		var k Keys
		if err := in.Keys.Open(in.Secrets.SigningKey, &k); err != nil || k.Kind != "keys" {
			return "", fmt.Errorf("secrets' keys: %v", err)
		}
		if c.Signer == doc.ByRoot {
			return k.Root, nil
		}
		return k.Phone, nil
	}
	if in.Signer == nil {
		return "", fmt.Errorf("a %s cert needs the %s's identity", c.Signer, c.Signer)
	}
	if err := sig.CheckIdentity(*in.Signer, c.Signer, n.trust); err != nil {
		return "", err
	}
	return in.Signer.SigningKey, nil
}

// Notarize: the checks, then the record, then the answer
func (n *Notarizer) Notarize(in Input) (sig.Doc, error) {
	c, err := doc.PeekCert(in.Cert)
	if err != nil {
		return sig.Doc{}, serve.Fail(400, "cert: %v", err)
	}
	if err := rule(c); err != nil {
		return sig.Doc{}, serve.Fail(403, "%v", err)
	}
	key, err := n.signerKey(c, in)
	if err != nil {
		return sig.Doc{}, serve.Fail(403, "%v", err)
	}
	if !sig.Verify(key, []byte(in.Cert.Payload), in.Cert.Sig) {
		return sig.Doc{}, serve.Fail(403, "the cert isn't signed by the %s's key", c.Signer)
	}
	if err := sig.CheckIdentity(in.Notary, "notary", n.trust); err != nil {
		return sig.Doc{}, serve.Fail(403, "%v", err)
	}
	var ch doc.Challenge
	if err := in.Challenge.Open(in.Notary.SigningKey, &ch); err != nil || ch.Kind != "challenge" {
		return sig.Doc{}, serve.Fail(403, "challenge: %v", err)
	}
	at, err := time.Parse(time.RFC3339Nano, ch.At)
	if ch.Subject != in.Cert.ID() || ch.About != "cert" || err != nil || n.now().Sub(at).Abs() > ChallengeSkew {
		return sig.Doc{}, serve.Fail(403, "the challenge isn't a fresh one over this cert")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	var rec []entry
	if c.Succ.Kind() == "source" {
		if n.defined[c.Succ] {
			return sig.Doc{}, serve.Fail(409, "%s is already defined", c.Succ)
		}
		rec = append(rec, entry{Defined: c.Succ})
	}
	if c.Pred.Kind() == "source" {
		if !n.defined[c.Pred] {
			return sig.Doc{}, serve.Fail(409, "%s was never defined", c.Pred)
		}
		first := c.Signer == doc.BySpawner || c.Signer == doc.ByIPhone // the table's "first successor" rows
		if first && n.succeeded[c.Pred] {
			return sig.Doc{}, serve.Fail(409, "%s already has a successor", c.Pred)
		}
		rec = append(rec, entry{Succeeded: c.Pred})
	}
	for _, e := range rec {
		b, _ := json.Marshal(e)
		if _, err := n.f.Write(append(b, '\n')); err != nil {
			return sig.Doc{}, err
		}
	}
	if err := n.f.Sync(); err != nil {
		return sig.Doc{}, err
	}
	for _, e := range rec {
		if e.Defined != "" {
			n.defined[e.Defined] = true
		}
		if e.Succeeded != "" {
			n.succeeded[e.Succeeded] = true
		}
	}
	return n.s.SignJSON(doc.Notarized{Kind: "notarized", Cert: in.Cert.ID(), Challenge: in.Challenge})
}

func Register(s *serve.Server, n *Notarizer) {
	serve.Handle(s, "POST /notarize", func(in Input) (any, error) { return n.Notarize(in) })
}
