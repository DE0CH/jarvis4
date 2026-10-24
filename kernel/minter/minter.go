// Package minter: the kernel's only component that uses a secret (Deyao, 2026-10-23: secrets hands secrets out, it
// never uses one). It is the only component with GitHub egress. Secrets checks the phone's approval of a deploy-key
// call, opens the GitHub token store with the phone's share, seals the token to the minter's agreement key (from the
// root key's roster) and calls POST /mint. The minter checks the same phone-signed request itself — secrets' begin
// document, the phone's signature over exactly it, the phone's key from secrets' signed keys statement — does exactly
// one GitHub call (add the begin's public key to the begin's repo, or delete the key id the begin names), drops the
// token and answers signed. It keeps nothing but the pendings it has served (one call per approval).
package minter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// TokenInfo: the HKDF info the token is sealed under, followed by the begin's pending id
const TokenInfo = "jarvis2/minter-token\n"

var repoRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)

// RepoOK: owner/name as GitHub spells a repo (no path tricks: the minter puts it in the URL)
func RepoOK(repo string) bool {
	return repoRE.MatchString(repo) && !strings.Contains(repo, "..") && !strings.HasSuffix(repo, "/.")
}

// Request: what secrets sends for one phone-approved deploy-key call
type Request struct {
	Begin    sig.Doc    `json:"begin"`    // secrets' signed deploy-key-begin document: what the phone signed
	PhoneSig string     `json:"phoneSig"` // the phone's signature over Begin.Payload
	Keys     sig.Doc    `json:"keys"`     // secrets' signed keys statement {kind: "keys", phone, root}
	Token    sig.Sealed `json:"token"`    // the GitHub token, sealed to the minter's agreement key (TokenInfo + pending)
}

// Minted: the signed answer
type Minted struct {
	Kind    string `json:"kind"` // "deploy-key-minted"
	Pending string `json:"pending"`
	Action  string `json:"action"`
	Repo    string `json:"repo"`
	KeyID   int64  `json:"keyId"` // add: the id GitHub gave the key; remove: the id deleted
}

// Error: a refusal with the HTTP status it answers (502 for GitHub's: "github: HTTP <status>: <GitHub's words>")
type Error struct {
	Status int
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

func fail(status int, f string, a ...any) error { return &Error{status, fmt.Sprintf(f, a...)} }

type Minter struct {
	c     *sig.Component
	trust *sig.Trust
	gh    GitHub
	mu    sync.Mutex
	done  map[string]time.Time // pendings served (each approval reaches GitHub once)
}

func New(c *sig.Component, t *sig.Trust, gh GitHub) *Minter {
	return &Minter{c: c, trust: t, gh: gh, done: map[string]time.Time{}}
}

type beginDoc struct {
	Kind      string `json:"kind"`
	Pending   string `json:"pending"`
	Action    string `json:"action"`
	Repo      string `json:"repo"`
	Title     string `json:"title"`
	PublicKey string `json:"publicKey"`
	KeyID     int64  `json:"keyId"`
}

// Mint: the checks, then exactly one GitHub call
func (m *Minter) Mint(in Request) (sig.Doc, error) {
	sec, err := m.trust.Member("secrets")
	if err != nil {
		return sig.Doc{}, fail(503, "%v", err)
	}
	var keys struct {
		Kind  string `json:"kind"`
		Phone string `json:"phone"`
	}
	if !sig.Verify(sec.SigningKey, []byte(in.Keys.Payload), in.Keys.Sig) || json.Unmarshal([]byte(in.Keys.Payload), &keys) != nil || keys.Kind != "keys" || keys.Phone == "" {
		return sig.Doc{}, fail(403, "the keys statement isn't the roster's secrets'")
	}
	var b beginDoc
	if !sig.Verify(sec.SigningKey, []byte(in.Begin.Payload), in.Begin.Sig) || json.Unmarshal([]byte(in.Begin.Payload), &b) != nil || b.Kind != "deploy-key-begin" || b.Pending == "" {
		return sig.Doc{}, fail(403, "the request isn't a deploy-key begin the roster's secrets signed")
	}
	if !sig.Verify(keys.Phone, []byte(in.Begin.Payload), in.PhoneSig) {
		return sig.Doc{}, fail(403, "the iPhone's signature doesn't cover this request")
	}
	if !RepoOK(b.Repo) {
		return sig.Doc{}, fail(400, "repo: owner/name")
	}
	switch {
	case b.Action == "add" && b.PublicKey != "" && b.Title != "":
	case b.Action == "remove" && b.KeyID > 0:
	default:
		return sig.Doc{}, fail(400, "an add of a public key with its title, or a remove of a key id")
	}
	tok, err := sig.OpenSealed(m.c.Agreement, in.Token, TokenInfo+b.Pending)
	if err != nil || len(tok) == 0 {
		return sig.Doc{}, fail(400, "the token isn't sealed to this minter for this request")
	}
	m.mu.Lock()
	if _, seen := m.done[b.Pending]; seen {
		m.mu.Unlock()
		return sig.Doc{}, fail(409, "this approval was used already")
	}
	m.done[b.Pending] = time.Now()
	for p, at := range m.done {
		if time.Since(at) > 24*time.Hour {
			delete(m.done, p)
		}
	}
	m.mu.Unlock()
	token := string(tok)
	out := Minted{Kind: "deploy-key-minted", Pending: b.Pending, Action: b.Action, Repo: b.Repo}
	if b.Action == "add" {
		var k DeployKey
		k, err = m.gh.AddDeployKey(token, b.Repo, b.Title, b.PublicKey)
		out.KeyID = k.ID
	} else {
		err = m.gh.DeleteDeployKey(token, b.Repo, b.KeyID)
		out.KeyID = b.KeyID
	}
	token, tok = "", nil
	if err != nil {
		log.Printf("minter: %s %s failed: %v", b.Action, b.Repo, err)
		if ge, ok := err.(*GitHubError); ok {
			return sig.Doc{}, fail(502, "github: HTTP %d: %s", ge.Status, ge.Msg)
		}
		return sig.Doc{}, fail(502, "github: %v", err)
	}
	log.Printf("minter: %s %s: GitHub key %d", b.Action, b.Repo, out.KeyID)
	return m.c.Signer.SignJSON(out)
}

// Register: POST /mint
func Register(s *serve.Server, m *Minter) {
	serve.Handle(s, "POST /mint", func(in Request) (any, error) {
		d, err := m.Mint(in)
		var e *Error
		if errors.As(err, &e) {
			return nil, serve.Fail(e.Status, "%s", e.Msg)
		}
		return d, err
	})
}

// Client: the minter over HTTP (secrets' side: KERNEL_MINTER_URL)
type Client struct {
	URL  string
	HTTP *http.Client
}

func NewClient(url string) *Client {
	return &Client{URL: url, HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// Mint: POST /mint; a refusal comes back as *Error with the minter's status and words
func (c *Client) Mint(in Request) (sig.Doc, error) {
	if c.URL == "" {
		return sig.Doc{}, fail(503, "no minter configured (KERNEL_MINTER_URL)")
	}
	b, _ := json.Marshal(in)
	resp, err := c.HTTP.Post(c.URL+"/mint", "application/json", bytes.NewReader(b))
	if err != nil {
		return sig.Doc{}, fail(502, "the minter is unreachable: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var d sig.Doc
	if err := json.Unmarshal(raw, &d); err != nil {
		return sig.Doc{}, fail(502, "the minter's answer isn't a signed document (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal([]byte(d.Payload), &e)
		return sig.Doc{}, &Error{resp.StatusCode, e.Error}
	}
	return d, nil
}
