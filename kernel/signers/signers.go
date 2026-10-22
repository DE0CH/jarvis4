// Package signers: the identity signer and the gullible signer (DESIGN "Target design"). Neither checks anything but
// the shape it is for: what their certs may do is the notarizer's table (the identity signer's (M, M, P) only narrows
// a machine's own grant; the gullible signer's certs count only where the table takes any signer: ending a source).
package signers

import (
	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// Identity: signs (M, M, P) for any P (the router picks P)
func Identity(s *sig.Signer, machine doc.Object, p perm.Pair) (sig.Doc, error) {
	c := doc.Cert{Kind: "succession", Pred: machine, Succ: machine, Pair: p, Signer: doc.ByIdentity, IssuedAt: doc.Now()}
	if machine.Kind() != "fly" {
		return sig.Doc{}, serve.Fail(400, "the identity signer signs (M, M, P) for a Fly machine M")
	}
	if err := c.Check(); err != nil {
		return sig.Doc{}, serve.Fail(400, "%v", err)
	}
	return s.SignJSON(c)
}

// Gullible: signs any well-formed (X, Y, P)
func Gullible(s *sig.Signer, pred, succ doc.Object, p perm.Pair, src *doc.Source) (sig.Doc, error) {
	c := doc.Cert{Kind: "succession", Pred: pred, Succ: succ, Pair: p, Source: src, Signer: doc.ByGullible, IssuedAt: doc.Now()}
	if err := c.Check(); err != nil {
		return sig.Doc{}, serve.Fail(400, "%v", err)
	}
	return s.SignJSON(c)
}

func RegisterIdentity(s *serve.Server) {
	serve.Handle(s, "POST /sign", func(in struct {
		Machine doc.Object `json:"machine"`
		Pair    perm.Pair  `json:"pair"`
	}) (any, error) {
		return Identity(s.C.Signer, in.Machine, in.Pair)
	})
}

func RegisterGullible(s *serve.Server) {
	serve.Handle(s, "POST /sign", func(in struct {
		Pred   doc.Object  `json:"pred"`
		Succ   doc.Object  `json:"succ"`
		Pair   perm.Pair   `json:"pair"`
		Source *doc.Source `json:"source,omitempty"`
	}) (any, error) {
		return Gullible(s.C.Signer, in.Pred, in.Succ, in.Pair, in.Source)
	})
}
