// Package mover: the grant mover (DESIGN "Target design"). Grant G on a cert's predecessor, along that notarized cert
// with pair P → (successor, G ⊓ P). It never refuses a well-formed move and a move can only narrow. It doesn't check
// the cert's signer: the notarization says the notarizer did.
package mover

import (
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

type Input struct {
	gv.Signed
	Cert      sig.Doc      `json:"cert"`
	Notarized sig.Doc      `json:"notarized"`
	Notarizer sig.Identity `json:"notarizer"`
	Notary    sig.Identity `json:"notary"`
}

type Mover struct {
	s     *sig.Signer
	trust *sig.Trust
}

func New(s *sig.Signer, t *sig.Trust) *Mover { return &Mover{s, t} }

func (m *Mover) Move(in Input) (sig.Doc, error) {
	g, err := gv.Open(in.Signed, m.trust)
	if err != nil {
		return sig.Doc{}, serve.Fail(403, "%v", err)
	}
	if err := sig.CheckIdentity(in.Notarizer, "notarizer", m.trust); err != nil {
		return sig.Doc{}, serve.Fail(403, "%v", err)
	}
	var nz doc.Notarized
	if err := in.Notarized.Open(in.Notarizer.SigningKey, &nz); err != nil || nz.Kind != "notarized" || nz.Cert != in.Cert.ID() {
		return sig.Doc{}, serve.Fail(403, "the cert isn't notarized")
	}
	if err := sig.CheckIdentity(in.Notary, "notary", m.trust); err != nil {
		return sig.Doc{}, serve.Fail(403, "%v", err)
	}
	var ch doc.Challenge
	if err := nz.Challenge.Open(in.Notary.SigningKey, &ch); err != nil {
		return sig.Doc{}, serve.Fail(403, "the notarization's challenge: %v", err)
	}
	c, err := doc.PeekCert(in.Cert)
	if err != nil {
		return sig.Doc{}, serve.Fail(400, "cert: %v", err)
	}
	if g.Machine != c.Pred {
		return sig.Doc{}, serve.Fail(409, "the grant is on %s, the cert leaves %s", g.Machine, c.Pred)
	}
	keys := g.Keys // an identity edge keeps the machine's keys
	switch {
	case c.Machine != nil:
		keys = c.Machine.Keys
	case c.Succ.Kind() == "sink" || c.Succ.Kind() == "source":
		keys, _ = doc.IdealKeys(c.Succ)
	}
	out := doc.Grant{Kind: "grant", Machine: c.Succ, Keys: keys, Pair: g.Pair.Meet(c.Pair),
		From: []string{in.Grant.ID(), in.Notarized.ID()}, At: gv.Later(g.At, ch.At)}
	if _, err := time.Parse(time.RFC3339Nano, out.At); err != nil {
		return sig.Doc{}, serve.Fail(400, "times")
	}
	return m.s.SignJSON(out)
}

func Register(s *serve.Server, m *Mover) {
	serve.Handle(s, "POST /move", func(in Input) (any, error) { return m.Move(in) })
}
