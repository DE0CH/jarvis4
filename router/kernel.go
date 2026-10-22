package main

// The kernel's HTTP API (kernel/, DESIGN "Target design", docs/PLAN-grants.md): eight components, each at
// KERNEL_URL with %s = its role (e.g. http://%s.jarvis4-kernel.svc:8080). The router carries documents between them
// and keeps them; it can't make one (each is signed by a component or the phone), only withhold or delay it.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

type KernelClient struct {
	url  func(role string) string
	http *http.Client
	mu   sync.Mutex
	ids  map[string]sig.Identity
	// onSecretsSeq: every secrets answer's X-Line-Seq (linestate.go keeps secrets' newest line state), before the
	// answer goes back
	onSecretsSeq func(int)
	// activeSecrets: the colour of the secrets that serves (blue or green)
	activeSecrets func() string
}

// newKernelClient: nil when KERNEL_URL isn't set (no kernel on this box yet)
func newKernelClient(tmpl string) *KernelClient {
	if tmpl == "" || !strings.Contains(tmpl, "%s") {
		return nil
	}
	return &KernelClient{url: func(role string) string { return fmt.Sprintf(tmpl, role) },
		http: &http.Client{Timeout: 2 * time.Minute}, ids: map[string]sig.Identity{}}
}

// KernelError: a component refused (its signed error, relayed)
type KernelError struct {
	Role   string
	Status int
	Msg    string
}

func (e *KernelError) Error() string {
	return fmt.Sprintf("kernel %s: HTTP %d %s", e.Role, e.Status, e.Msg)
}

// call: POST (body != nil) or GET → the raw answer
func (k *KernelClient) call(role, method, path string, body any) ([]byte, error) {
	b, seq, err := k.callSeq(role, method, path, body)
	if role == "secrets" && seq > 0 && k.onSecretsSeq != nil {
		k.onSecretsSeq(seq)
	}
	return b, err
}

// callNoHook: call without the line-state hook (the keeper's own fetches)
func (k *KernelClient) callNoHook(role, method, path string, body any) ([]byte, error) {
	b, _, err := k.callSeq(role, method, path, body)
	return b, err
}

func (k *KernelClient) callSeq(role, method, path string, body any) ([]byte, int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, k.url(k.secretsRole(role))+path, rd)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("kernel %s: %w", role, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	seq, _ := strconv.Atoi(resp.Header.Get(lineSeqHeader))
	if resp.StatusCode != 200 {
		msg := strings.TrimSpace(string(b))
		var d sig.Doc
		if json.Unmarshal(b, &d) == nil && d.Payload != "" {
			var e struct {
				Error string `json:"error"`
			}
			if json.Unmarshal([]byte(d.Payload), &e) == nil && e.Error != "" {
				msg = e.Error
			}
		}
		return nil, seq, &KernelError{role, resp.StatusCode, msg}
	}
	return b, seq, nil
}

// Doc: a POST answered with a signed document
func (k *KernelClient) Doc(role, path string, body any) (sig.Doc, error) {
	b, err := k.call(role, "POST", path, body)
	if err != nil {
		return sig.Doc{}, err
	}
	var d sig.Doc
	if err := json.Unmarshal(b, &d); err != nil || d.Payload == "" {
		return sig.Doc{}, fmt.Errorf("kernel %s%s: not a signed document", role, path)
	}
	return d, nil
}

// Identity: a component's identity (the root key's roster vouches for it) (cached; refetched when a call says it changed: forget)
func (k *KernelClient) Identity(role string) (sig.Identity, error) {
	k.mu.Lock()
	id, ok := k.ids[role]
	k.mu.Unlock()
	if ok {
		return id, nil
	}
	b, err := k.callNoHook(role, "GET", "/identity", nil) // no line-state hook: the keeper itself reads identities
	if err != nil {
		return sig.Identity{}, err
	}
	if role == "secrets" || role == "secrets-next" {
		var m struct {
			SigningKey, AgreementKey string
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return sig.Identity{}, err
		}
		id = sig.Identity{Role: "secrets", SigningKey: m.SigningKey, AgreementKey: m.AgreementKey}
	} else {
		var d sig.Doc
		if err := json.Unmarshal(b, &d); err != nil || json.Unmarshal([]byte(d.Payload), &id) != nil {
			return sig.Identity{}, fmt.Errorf("kernel %s: bad identity", role)
		}
	}
	k.mu.Lock()
	k.ids[role] = id
	k.mu.Unlock()
	return id, nil
}

// forget: a component restarted (new keys): its identity is read again
func (k *KernelClient) forget(role string) {
	k.mu.Lock()
	delete(k.ids, role)
	k.mu.Unlock()
}

// Keys: secrets' signed statement of the phone's and the root key
func (k *KernelClient) Keys() (sig.Doc, sig.Identity, error) {
	id, err := k.Identity("secrets")
	if err != nil {
		return sig.Doc{}, id, err
	}
	d, err := k.Doc("secrets", "/keys", map[string]any{})
	return d, id, err
}

// Notarize: the notary's challenge over the cert, then the notarizer's answer (with what names the cert's signer)
func (k *KernelClient) Notarize(cert sig.Doc) (sig.Doc, error) {
	c, err := doc.PeekCert(cert)
	if err != nil {
		return sig.Doc{}, fmt.Errorf("cert: %w", err)
	}
	nid, err := k.Identity("notary")
	if err != nil {
		return sig.Doc{}, err
	}
	ch, err := k.Doc("notary", "/challenge", map[string]string{"subject": cert.ID(), "about": "cert"})
	if err != nil {
		return sig.Doc{}, err
	}
	in := map[string]any{"cert": cert, "challenge": ch, "notary": nid}
	switch c.Signer {
	case doc.ByIPhone, doc.ByRoot:
		ks, sid, err := k.Keys()
		if err != nil {
			return sig.Doc{}, err
		}
		in["keys"], in["secrets"] = ks, sid
	default:
		id, err := k.Identity(c.Signer)
		if err != nil {
			return sig.Doc{}, err
		}
		in["signer"] = id
	}
	return k.Doc("notarizer", "/notarize", in)
}

// Move: grant g along a notarized cert → the mover's grant on the cert's successor
func (k *KernelClient) Move(g gv.Signed, cert, notarized sig.Doc) (gv.Signed, error) {
	nzID, err := k.Identity("notarizer")
	if err != nil {
		return gv.Signed{}, err
	}
	nID, err := k.Identity("notary")
	if err != nil {
		return gv.Signed{}, err
	}
	in := map[string]any{"grant": g.Grant, "by": g.By, "cert": cert, "notarized": notarized, "notarizer": nzID, "notary": nID}
	if g.Signer != nil {
		in["signer"] = g.Signer
	}
	if g.By == "root" {
		ks, sid, err := k.Keys()
		if err != nil {
			return gv.Signed{}, err
		}
		in["keys"], in["secrets"] = ks, sid
	}
	d, err := k.Doc("mover", "/move", in)
	if err != nil {
		return gv.Signed{}, err
	}
	mid, err := k.Identity("mover")
	if err != nil {
		return gv.Signed{}, err
	}
	return gv.Signed{Grant: d, By: "mover", Signer: &mid}, nil
}

// ---- secrets, blue and green (as the cores: nextcore.go) ----------------------------------------------------------
// Two secrets Deployments, secrets-blue and secrets-green: one serves (persisted.KernelSecrets names it, default blue),
// the other is the next: empty, or Recovered alongside with the same kit as a standby. A secrets release goes only into
// the next (images.yml), so a release never locks every kernel session's stores; Deyao Recovers the next alongside,
// then the router flips: POST /handoff to the serving one (its final state, the open unlocks included), POST /takeover
// with it to the standby, and every later secrets call goes there. Secrets itself guarantees that at most one serves.

// secretsRole: the Deployment a role name means ("secrets" = the serving colour, "secrets-next" = the other)
func (k *KernelClient) secretsRole(role string) string {
	if role != "secrets" && role != "secrets-next" {
		return role
	}
	active := "blue"
	if k.activeSecrets != nil {
		active = k.activeSecrets()
	}
	if role == "secrets-next" {
		if active == "blue" {
			return "secrets-green"
		}
		return "secrets-blue"
	}
	return "secrets-" + active
}

// FlipSecrets: the standby secrets serves from now on; the colour that serves now
func (r *Router) FlipSecrets() (string, error) {
	if r.kernel == nil {
		return "", errors.New("this box runs no kernel")
	}
	final, err := r.kernel.callNoHook("secrets", "POST", "/handoff", map[string]any{})
	if err != nil {
		return "", fmt.Errorf("the serving secrets' handoff: %w", err)
	}
	if _, err := r.kernel.callNoHook("secrets-next", "POST", "/takeover", map[string]json.RawMessage{"lineState": final}); err != nil {
		return "", fmt.Errorf("THE NEXT SECRETS REFUSED THE TAKEOVER (the serving one handed off: no secrets serves until a retry): %w", err)
	}
	var now string
	r.st.Do(func(d *persisted) {
		if d.KernelSecrets == "green" {
			d.KernelSecrets = "blue"
		} else {
			d.KernelSecrets = "green"
		}
		now = d.KernelSecrets
	})
	r.kernel.forget("secrets")
	r.kernel.forget("secrets-next")
	log.Printf("kernel: secrets-%s serves from now on", now)
	return now, nil
}

// wireKernel: the router's kernel client, the colour of secrets that serves, and the keeper of secrets' line state
func (r *Router) wireKernel(k *KernelClient) {
	r.kernel = k
	if k == nil {
		return
	}
	k.activeSecrets = func() string {
		c := "blue"
		r.st.Do(func(d *persisted) {
			if d.KernelSecrets == "green" {
				c = "green"
			}
		})
		return c
	}
	r.kernelLines = newKernelLineKeeper(filepath.Join(r.cfg.DataDir, "kernel-line-state.json"), k)
	k.onSecretsSeq = r.kernelLines.seen
}
