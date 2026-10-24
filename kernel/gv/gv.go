// Package gv: checking a grant as everyone who takes one does (the mover, the merger, secrets, the guard). A grant is
// signed by the mover or the merger (their identities, checked against the root key's roster: its member, or a retired
// one — the other copy's after a copy flip, or one from before a restart — whose grants still open though it signs
// nothing new), or is the root key's ⊤ on the sink.
package gv

import (
	"fmt"
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// Signed: a grant and what vouches for its signer
type Signed struct {
	Grant   sig.Doc       `json:"grant"`
	By      string        `json:"by"`                // "mover", "merger" or "root"
	Signer  *sig.Identity `json:"signer,omitempty"`  // the mover's or merger's identity
	Keys    *sig.Doc      `json:"keys,omitempty"`    // root: secrets' signed keys statement
	Secrets *sig.Identity `json:"secrets,omitempty"` // … and secrets' identity
}

// RootKey: the root key from secrets' signed keys statement
func RootKey(keys *sig.Doc, secrets *sig.Identity, t *sig.Trust) (string, error) {
	if keys == nil || secrets == nil {
		return "", fmt.Errorf("the root key needs secrets' signed keys")
	}
	if err := sig.CheckIdentity(*secrets, "secrets", t); err != nil {
		return "", err
	}
	var k struct {
		Kind  string `json:"kind"`
		Phone string `json:"phone"`
		Root  string `json:"root"`
	}
	if err := keys.Open(secrets.SigningKey, &k); err != nil || k.Kind != "keys" {
		return "", fmt.Errorf("secrets' keys: %v", err)
	}
	return k.Root, nil
}

// Open: the grant, checked
func Open(s Signed, t *sig.Trust) (doc.Grant, error) {
	var key string
	switch s.By {
	case "mover", "merger":
		if s.Signer == nil {
			return doc.Grant{}, fmt.Errorf("a %s grant needs the %s's identity", s.By, s.By)
		}
		if err := sig.CheckIdentity(*s.Signer, s.By, t); err != nil {
			return doc.Grant{}, err
		}
		key = s.Signer.SigningKey
	case "root":
		k, err := RootKey(s.Keys, s.Secrets, t)
		if err != nil {
			return doc.Grant{}, err
		}
		key = k
	default:
		return doc.Grant{}, fmt.Errorf("a grant signed by %q", s.By)
	}
	g, err := doc.OpenGrant(s.Grant, key)
	if err != nil {
		return doc.Grant{}, fmt.Errorf("grant: %v", err)
	}
	if s.By == "root" && (g.Machine != doc.Sink || !perm.Top().Leq(g.Pair)) {
		return doc.Grant{}, fmt.Errorf("the root key's grant is ⊤ on the sink only")
	}
	if k := g.Machine.Kind(); k == "sink" || k == "source" {
		if ik, _ := doc.IdealKeys(g.Machine); ik != g.Keys {
			return doc.Grant{}, fmt.Errorf("a grant on %s names keys that aren't its own", g.Machine)
		}
	}
	return g, nil
}

// Later: the later of two RFC 3339 times
func Later(a, b string) string {
	ta, ea := time.Parse(time.RFC3339Nano, a)
	tb, eb := time.Parse(time.RFC3339Nano, b)
	if ea != nil || eb == nil && tb.After(ta) {
		return b
	}
	return a
}
