package main

// The kernel's HTTP API (kernel/, DESIGN "Target design", docs/PLAN-grants.md): nine components in each of two
// copies, blue and green (docs/PLAN-cluster.md "Releases: the copy flip"), each at KERNEL_URL with %s = its
// Deployment, "<role>-<copy>" (e.g. http://%s.jarvis4-kernel.svc:8080). Every call goes to the copy that serves
// (persisted.KernelCopy); kernelflip.go moves the kernel to the other copy. The router carries documents between the
// components and keeps them; it can't make one (each is signed by a component or the phone), only withhold or delay it.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

type KernelClient struct {
	url  func(deployment string) string
	http *http.Client
	mu   sync.Mutex
	ids  map[string]sig.Identity // by Deployment
	// onSecretsSeq: every secrets answer's X-Line-Seq (linestate.go keeps secrets' newest line state), before the
	// answer goes back
	onSecretsSeq func(int)
	// active: the copy that serves (blue or green)
	active func() string
	// roster: the root key's current roster (roster.go), re-posted to a component that answers it has none (a
	// restart); onStale: a component refused it (it restarted with new keys: Deyao signs a new one)
	roster  func() *sig.Doc
	onStale func(deployment, msg string)
	// gate: every call holds it shared; the copy flip holds it alone while the serving copy hands over, so no call
	// reaches a component that froze, and every call after it goes to the new copy
	gate sync.RWMutex
}

// kernelCopies: the two copies
var kernelCopies = []string{"blue", "green"}

// otherCopy: the copy that isn't c
func otherCopy(c string) string {
	if c == "green" {
		return "blue"
	}
	return "green"
}

// copyOf: the copy a Deployment name ("<role>-<copy>") is in ("" = a bare role)
func copyOf(dep string) string {
	for _, c := range kernelCopies {
		if strings.HasSuffix(dep, "-"+c) {
			return c
		}
	}
	return ""
}

// serving: the copy that serves
func (k *KernelClient) serving() string {
	if k.active != nil {
		return k.active()
	}
	return "blue"
}

// dep: the Deployment a name means: a role is the serving copy's ("notary" → "notary-blue"); a Deployment name stays
func (k *KernelClient) dep(name string) string {
	if copyOf(name) != "" {
		return name
	}
	return name + "-" + k.serving()
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
	Reason string // the component's stable reason for it (serve.FailBecause), "" when it gave none
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
	k.gate.RLock()
	defer k.gate.RUnlock()
	dep := k.dep(role)
	b, seq, err := k.do(role, dep, method, path, body)
	if err == nil || path == "/roster" || !isNoRoster(err) || k.roster == nil {
		return b, seq, err
	}
	// a component without the roster restarted (fresh keys): it takes the current roster again only if it names its
	// keys, which a restart's new keys never are, unless the roster was signed after it
	d := k.roster()
	if d == nil {
		return b, seq, err
	}
	if perr := k.postRoster(dep, *d); perr != nil {
		return b, seq, perr
	}
	k.forget(dep)
	return k.do(role, dep, method, path, body)
}

// isNoRoster: the component answered that it holds no roster yet (sig.ErrNoRoster)
func isNoRoster(err error) bool {
	var ke *KernelError
	return errors.As(err, &ke) && strings.Contains(ke.Msg, "no roster yet")
}

// postRoster: the roster to one Deployment; a refusal (403: it doesn't name this component's keys) means the
// component restarted since the roster was signed: the roster is stale
func (k *KernelClient) postRoster(dep string, d sig.Doc) error {
	_, _, err := k.do(dep, dep, "POST", "/roster", map[string]sig.Doc{"roster": d})
	var ke *KernelError
	if errors.As(err, &ke) && ke.Status == 403 {
		msg := fmt.Sprintf("roster stale: component %s restarted (%s)", dep, ke.Msg)
		if k.onStale != nil {
			k.onStale(dep, msg)
		}
		return fmt.Errorf("kernel %s: %s", dep, msg)
	}
	return err
}

// do: one request to one Deployment (dep), its errors named by role
func (k *KernelClient) do(role, dep, method, path string, body any) ([]byte, int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, k.url(dep)+path, rd)
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
		msg, reason := strings.TrimSpace(string(b)), ""
		var d sig.Doc
		if json.Unmarshal(b, &d) == nil && d.Payload != "" {
			var e struct {
				Error  string `json:"error"`
				Reason string `json:"reason"`
			}
			if json.Unmarshal([]byte(d.Payload), &e) == nil && e.Error != "" {
				msg, reason = e.Error, e.Reason
			}
		}
		return nil, seq, &KernelError{Role: role, Status: resp.StatusCode, Msg: msg, Reason: reason}
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

// Identity: a component's identity (the root key's roster vouches for it): a role is the serving copy's, a Deployment
// name its own (cached; refetched when a call says it changed: forget)
func (k *KernelClient) Identity(role string) (sig.Identity, error) {
	dep := k.dep(role)
	k.mu.Lock()
	id, ok := k.ids[dep]
	k.mu.Unlock()
	if ok {
		return id, nil
	}
	b, err := k.callNoHook(dep, "GET", "/identity", nil) // no line-state hook: the keeper itself reads identities
	if err != nil {
		return sig.Identity{}, err
	}
	if strings.HasPrefix(dep, "secrets-") {
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
	k.ids[dep] = id
	k.mu.Unlock()
	return id, nil
}

// forget: a component restarted (new keys): its identity is read again (a role: the serving copy's)
func (k *KernelClient) forget(role string) {
	k.mu.Lock()
	delete(k.ids, k.dep(role))
	k.mu.Unlock()
}

// forgetAll: every identity is read again (a new roster, a flip)
func (k *KernelClient) forgetAll() {
	k.mu.Lock()
	k.ids = map[string]sig.Identity{}
	k.mu.Unlock()
}

// signerOf: the identity whose key signed d as role, as the current roster names it: the serving member, else a
// retired one (a document from before a flip or a restart, which the components still take); the serving member when
// none does (the component's refusal then says why)
func (k *KernelClient) signerOf(role string, d sig.Doc) (sig.Identity, error) {
	id, err := k.Identity(role)
	if err != nil || sig.Verify(id.SigningKey, []byte(d.Payload), d.Sig) || k.roster == nil {
		return id, err
	}
	if rd := k.roster(); rd != nil {
		var ro sig.Roster
		if json.Unmarshal([]byte(rd.Payload), &ro) == nil {
			for _, m := range ro.RetiredOf(role) {
				if sig.Verify(m.SigningKey, []byte(d.Payload), d.Sig) {
					return m, nil
				}
			}
		}
	}
	return id, nil
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
		id, err := k.signerOf(c.Signer, cert) // a cert signed before a flip or a restart: by a retired member
		if err != nil {
			return sig.Doc{}, err
		}
		in["signer"] = id
	}
	return k.Doc("notarizer", "/notarize", in)
}

// Move: grant g along a notarized cert → the mover's grant on the cert's successor
func (k *KernelClient) Move(g gv.Signed, cert, notarized sig.Doc) (gv.Signed, error) {
	nzID, err := k.signerOf("notarizer", notarized)
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

// wireKernel: the router's kernel client, the copy that serves, and the keeper of secrets' line state
func (r *Router) wireKernel(k *KernelClient) {
	r.kernel = k
	if k == nil {
		return
	}
	k.active = r.servingCopy
	r.kernelLines = newKernelLineKeeper(r.st, k)
	k.onSecretsSeq = r.kernelLines.seen
	k.roster = r.currentRoster // roster.go
	k.onStale = r.rosterStale
	if r.cfg.NoCore {
		r.secretsStores = &CoreClient{name: "secrets", http: &http.Client{}, onLineSeq: r.kernelLines.seen,
			baseFn: func() string { return k.url(k.dep("secrets")) },
			gate:   func() func() { k.gate.RLock(); return k.gate.RUnlock }}
	}
}

// servingCopy: the kernel copy that serves (persisted.KernelCopy; "" = blue)
func (r *Router) servingCopy() string {
	c := "blue"
	r.st.Do(func(d *persisted) {
		if d.KernelCopy == "green" {
			c = "green"
		}
	})
	return c
}

// storeCore: where the store calls go — the kernel's serving secrets on a box with no core, else the core
func (r *Router) storeCore() *CoreClient {
	if r.secretsStores != nil {
		return r.secretsStores
	}
	return r.core
}
