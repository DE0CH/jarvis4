package minter

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/internal/kt"
	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

type fakeGitHub struct {
	adds    []string
	deletes []int64
	token   string
}

func (g *fakeGitHub) AddDeployKey(token, repo, title, pub string) (DeployKey, error) {
	g.token = token
	g.adds = append(g.adds, repo+" "+title+" "+pub)
	return DeployKey{ID: 41, Title: title, Key: pub}, nil
}
func (g *fakeGitHub) DeleteDeployKey(token, repo string, id int64) error {
	if repo == "DE0CH/refused" {
		return &GitHubError{403, "GitHub DELETE: HTTP 403 Resource not accessible"}
	}
	g.token = token
	g.deletes = append(g.deletes, id)
	return nil
}

// the minter over HTTP, as secrets reaches it: one add, one delete by id, each phone-approved; GitHub's refusal comes
// back as a 502 naming GitHub's status; the answer is signed by the roster's minter
func TestMintOverHTTP(t *testing.T) {
	w := kt.New(t)
	g := &fakeGitHub{}
	s := serve.New(w.C["minter"], w.Trust)
	Register(s, New(w.C["minter"], w.Trust, g))
	srv := httptest.NewServer(s.Mux)
	defer srv.Close()
	cl := NewClient(srv.URL)
	sec := w.C["secrets"].Signer
	req := func(begin map[string]any) Request {
		b, _ := sec.SignJSON(begin)
		tok, _ := sig.SealTo(w.C["minter"].Identity.AgreementKey, []byte("gh-token"), TokenInfo+begin["pending"].(string))
		ps, _ := w.Phone.Sign([]byte(b.Payload))
		return Request{Begin: b, PhoneSig: ps, Keys: w.KeysDoc, Token: tok}
	}
	d, err := cl.Mint(req(map[string]any{"kind": "deploy-key-begin", "pending": "p1", "action": "add", "repo": "DE0CH/x", "title": "jarvis4 github-x", "publicKey": "ssh-ed25519 AAAA"}))
	var m Minted
	if err != nil || d.Open(w.C["minter"].Identity.SigningKey, &m) != nil || m.KeyID != 41 || m.Pending != "p1" || g.token != "gh-token" || len(g.adds) != 1 {
		t.Fatal(err, m, g)
	}
	if _, err = cl.Mint(req(map[string]any{"kind": "deploy-key-begin", "pending": "p2", "action": "remove", "repo": "DE0CH/x", "keyId": 41})); err != nil || len(g.deletes) != 1 || g.deletes[0] != 41 {
		t.Fatal(err, g.deletes)
	}
	for name, b := range map[string]map[string]any{
		"a remove without an id": {"kind": "deploy-key-begin", "pending": "p3", "action": "remove", "repo": "DE0CH/x"},
		"a path in the repo":     {"kind": "deploy-key-begin", "pending": "p4", "action": "add", "repo": "DE0CH/../x", "title": "t", "publicKey": "k"},
		"another kind":           {"kind": "unlock-begin", "pending": "p5", "action": "add", "repo": "DE0CH/x", "title": "t", "publicKey": "k"},
	} {
		if _, err := cl.Mint(req(b)); err == nil {
			t.Fatalf("%s: minted", name)
		}
	}
	_, err = cl.Mint(req(map[string]any{"kind": "deploy-key-begin", "pending": "p6", "action": "remove", "repo": "DE0CH/refused", "keyId": 9}))
	if e, ok := err.(*Error); !ok || e.Status != 502 || !strings.Contains(e.Msg, "github: HTTP 403") {
		t.Fatal("GitHub's refusal:", err)
	}
}
