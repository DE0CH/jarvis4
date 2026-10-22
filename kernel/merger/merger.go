// Package merger: the grant merger (DESIGN "Target design"). Two grants on one machine with identical conditions →
// (M, allowed₁ ∪ allowed₂, conditions); anything else is refused.
package merger

import (
	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

type Input struct {
	A gv.Signed `json:"a"`
	B gv.Signed `json:"b"`
}

type Merger struct {
	s     *sig.Signer
	trust *sig.Trust
}

func New(s *sig.Signer, t *sig.Trust) *Merger { return &Merger{s, t} }

func (m *Merger) Merge(in Input) (sig.Doc, error) {
	a, err := gv.Open(in.A, m.trust)
	if err != nil {
		return sig.Doc{}, serve.Fail(403, "a: %v", err)
	}
	b, err := gv.Open(in.B, m.trust)
	if err != nil {
		return sig.Doc{}, serve.Fail(403, "b: %v", err)
	}
	if a.Machine != b.Machine || a.Keys != b.Keys {
		return sig.Doc{}, serve.Fail(409, "the grants are on different machines")
	}
	p, err := a.Pair.Merge(b.Pair)
	if err != nil {
		return sig.Doc{}, serve.Fail(409, "%v", err)
	}
	return m.s.SignJSON(doc.Grant{Kind: "grant", Machine: a.Machine, Keys: a.Keys, Pair: p,
		From: []string{in.A.Grant.ID(), in.B.Grant.ID()}, At: gv.Later(a.At, b.At)})
}

func Register(s *serve.Server, m *Merger) {
	serve.Handle(s, "POST /merge", func(in Input) (any, error) { return m.Merge(in) })
}
