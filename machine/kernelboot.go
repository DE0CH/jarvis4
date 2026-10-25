package main

// A machine the kernel's spawner started (DESIGN "Target design", docs/PLAN-grants.md §4): its Fly config carries the
// root key's public half (JARVIS2_KERNEL_ROOT), the root key's roster of the kernel's components
// (JARVIS2_KERNEL_ROSTER) and its source (JARVIS2_SOURCE) instead of the old core's key. At boot it reads its documents
// from the router (GET /m/kernel/boot) and believes them only as far as they check:
//
//   - every component identity is the roster's for its role, and the root key signed the roster;
//   - the spawner's cert (source, fly-<this machine>, ⊤) names this machine's own keys and its source, and the
//     notarizer notarized it;
//   - the cert into the source is notarized too: the source's image, settings and snapshot hash are what the
//     notarizer's table let through (the phone signed a new one; the spawner, at its machine's kill, the snapshot);
//   - the grant, signed by the mover or the merger, is on this machine and its keys.
//
// From them it builds the Cert the rest of boot reads (settings, stores, the snapshot to restore), and keeps the roster
// and secrets' keys for its pulls. The snapshot is restored by its hash alone: the spawner checked the predecessor's
// signature over it before it named it.
//
// The roster it checks with is the one the router serves with the documents (the serving kernel copy's, root-signed:
// checked against JARVIS2_KERNEL_ROOT), else the one in its Fly config: a copy flip or a re-signed roster (docs/
// PLAN-cluster.md "Releases: the copy flip") changes the kernel's keys under a live machine. A document a retired
// member signed (the other copy's, or one from before a restart) still checks: the roster names those keys as retired.
// A delivered input whose challenge isn't the notary's this machine knows makes it read the documents again (at most
// every kernelTrustEvery), so the new copy's notary is learnt at its first input.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

const (
	kernelRootEnv   = "JARVIS2_KERNEL_ROOT"
	kernelRosterEnv = "JARVIS2_KERNEL_ROSTER"
	kernelSourceEnv = "JARVIS2_SOURCE"
)

var kernelTrustPath = dir + "/kernel.json"

// kernelTrust: what a kernel machine checks later answers with
type kernelTrust struct {
	Root    string  `json:"root"`    // the root key's public half
	Roster  sig.Doc `json:"roster"`  // the root key's roster
	Secrets string  `json:"secrets"` // secrets' signing key (its pull answers)
	Notary  string  `json:"notary"`  // the log notary's signing key (every delivered input's challenge)
	Machine string  `json:"machine"` // "fly-<id>": the object its grant and pulls name
}

func readKernelTrust() (kernelTrust, bool) {
	var t kernelTrust
	b, err := os.ReadFile(kernelTrustPath)
	return t, err == nil && json.Unmarshal(b, &t) == nil && t.Root != ""
}

type kernelBootDocs struct {
	Grant            gv.Signed    `json:"grant"`
	MachineCert      sig.Doc      `json:"machineCert"`
	MachineNotarized sig.Doc      `json:"machineNotarized"`
	SourceCert       sig.Doc      `json:"sourceCert"`
	SourceNotarized  sig.Doc      `json:"sourceNotarized"`
	Notary           sig.Identity `json:"notary"`
	Notarizer        sig.Identity `json:"notarizer"`
	Mover            sig.Identity `json:"mover"`
	Merger           sig.Identity `json:"merger"`
	Spawner          sig.Identity `json:"spawner"`
	Secrets          sig.Identity `json:"secrets"`
	Keys             sig.Doc      `json:"keys"`             // secrets' {kind: keys, phone, root}
	Stores           sig.Doc      `json:"stores"`           // secrets' signed store list (each store's sensitivity)
	Roster           *sig.Doc     `json:"roster,omitempty"` // the root key's roster of the serving kernel copy
}

// kernelSettings: a source's settings (router/kernelline.go kernelSettings)
type kernelSettings struct {
	V              int             `json:"v"`
	Harness        string          `json:"harness"`
	PermissionMode string          `json:"permissionMode"`
	Config         json.RawMessage `json:"config"`
}

// kernelTrustFor: the roster the documents come with (checked against the root key in the Fly config), else the one
// in the Fly config
func kernelTrustFor(b kernelBootDocs) (*sig.Trust, error) {
	t := sig.NewTrust(strings.TrimSpace(os.Getenv(kernelRootEnv)))
	if b.Roster != nil {
		if err := t.Set(*b.Roster, nil); err != nil {
			return nil, fmt.Errorf("the kernel's roster from the router: %v", err)
		}
		return t, nil
	}
	var d sig.Doc
	if err := json.Unmarshal([]byte(os.Getenv(kernelRosterEnv)), &d); err != nil {
		return nil, fmt.Errorf("the kernel's roster (%s): %v", kernelRosterEnv, err)
	}
	return t, t.Set(d, nil)
}

// openBy: d opened into v by one of the keys the roster takes for role (its member's, then the retired ones)
func openBy(t *sig.Trust, role string, d sig.Doc, v any) error {
	err := errors.New("no " + role + " in the roster")
	for _, k := range t.SigningKeys(role) {
		if err = d.Open(k, v); err == nil {
			return nil
		}
	}
	return err
}

// checkKernelBoot: the documents → the Cert boot reads, and what later pulls are checked with

func checkKernelBoot(b kernelBootDocs, box *sig.Trust, source, me string, keys map[string]string) (Cert, kernelTrust, error) {
	var cert Cert
	for role, id := range map[string]sig.Identity{"notary": b.Notary, "notarizer": b.Notarizer, "mover": b.Mover,
		"merger": b.Merger, "spawner": b.Spawner, "secrets": b.Secrets} {
		if err := sig.CheckIdentity(id, role, box); err != nil {
			return cert, kernelTrust{}, err
		}
	}
	notarized := func(c sig.Doc, nz sig.Doc) error {
		var n doc.Notarized
		if err := openBy(box, "notarizer", nz, &n); err != nil || n.Kind != "notarized" || n.Cert != c.ID() {
			return fmt.Errorf("not notarized (%v)", err)
		}
		return nil
	}
	self := doc.Object("fly-" + me)
	var mc doc.Cert
	err := errors.New("no spawner in the roster")
	for _, k := range box.SigningKeys("spawner") {
		if mc, err = doc.OpenCert(b.MachineCert, k); err == nil {
			break
		}
	}
	if err != nil {
		return cert, kernelTrust{}, fmt.Errorf("the spawner's cert: %w", err)
	}
	if mc.Succ != self || mc.Machine == nil || mc.Machine.SigningKey != keys["signingKey"] || mc.Machine.EncryptionKey != keys["encryptionKey"] {
		return cert, kernelTrust{}, errors.New("the spawner's cert names another machine or other keys")
	}
	if string(mc.Pred) != source {
		return cert, kernelTrust{}, fmt.Errorf("the spawner's cert comes from %s, this machine's Fly config says %s", mc.Pred, source)
	}
	if err := notarized(b.MachineCert, b.MachineNotarized); err != nil {
		return cert, kernelTrust{}, fmt.Errorf("the spawner's cert: %w", err)
	}
	sc, err := doc.PeekCert(b.SourceCert)
	if err != nil || sc.Succ != mc.Pred || sc.Source == nil {
		return cert, kernelTrust{}, errors.New("the source's cert isn't the cert into this machine's source")
	}
	if err := notarized(b.SourceCert, b.SourceNotarized); err != nil {
		return cert, kernelTrust{}, fmt.Errorf("the source's cert: %w", err)
	}
	if reportedDigestOf(mc.Machine.Image) != reportedDigestOf(sc.Source.Image) {
		return cert, kernelTrust{}, errors.New("this machine runs another image than its source's")
	}
	g, err := gv.Open(b.Grant, box)
	if err != nil {
		return cert, kernelTrust{}, fmt.Errorf("the grant: %w", err)
	}
	if g.Machine != self || g.Keys != mc.Machine.Keys {
		return cert, kernelTrust{}, errors.New("the grant is on another machine")
	}
	var st kernelSettings
	d := json.NewDecoder(strings.NewReader(string(sc.Source.Settings)))
	d.DisallowUnknownFields()
	if err := d.Decode(&st); err != nil || st.V != 1 {
		return cert, kernelTrust{}, fmt.Errorf("the source's settings: %v", err)
	}
	cert.Kind = "succession-cert"
	cert.Machine = &Machine{ID: me, EncryptionKey: keys["encryptionKey"], SigningKey: keys["signingKey"]}
	cert.Options.Harness, cert.Options.PermissionMode = st.Harness, st.PermissionMode
	if len(st.Config) > 0 && string(st.Config) != "{}" && string(st.Config) != "null" {
		cert.Options.Config = string(st.Config)
	}
	if g.Pair.Allowed.Only != nil {
		for _, a := range g.Pair.Allowed.Only {
			if s, ok := strings.CutPrefix(a, "store:"); ok {
				cert.Stores = append(cert.Stores, s)
			}
		}
	}
	for _, c := range g.Pair.Conditions {
		if s, ok := strings.CutPrefix(c, "session:"); ok {
			cert.Line = s
		}
	}
	if sc.Pred.Kind() == "fly" {
		cert.PredID = sc.Pred.FlyID()
	}
	cert.Snapshot = sc.Source.Snapshot
	// the phone's key and the stores' sensitivity, from secrets (what a core cert's phone and sensitive say): the
	// phone grants and message approvals guard.go and messages.go check
	var ks struct {
		Kind, Phone, Root string
	}
	if err := b.Keys.Open(b.Secrets.SigningKey, &ks); err != nil || ks.Kind != "keys" || ks.Phone == "" {
		return cert, kernelTrust{}, fmt.Errorf("secrets' keys: %v", err)
	}
	cert.Phone = ks.Phone
	var sl struct {
		Kind   string `json:"kind"`
		Stores []struct {
			Name      string `json:"name"`
			Sensitive bool   `json:"sensitive"`
		} `json:"stores"`
	}
	if err := json.Unmarshal([]byte(b.Stores.Payload), &sl); err != nil || !sig.Verify(b.Secrets.SigningKey, []byte(b.Stores.Payload), b.Stores.Sig) || sl.Kind != "stores" {
		return cert, kernelTrust{}, errors.New("secrets' store list isn't signed by secrets")
	}
	known := map[string]bool{}
	for _, s := range sl.Stores {
		known[s.Name] = true
		if s.Sensitive && slices.Contains(cert.Stores, s.Name) {
			cert.Sensitive = true
		}
	}
	for _, s := range cert.Stores {
		if !known[s] {
			cert.Sensitive = true // a store secrets doesn't list: counted sensitive, as every store secrets didn't make otherwise
		}
	}
	return cert, kernelTrust{Root: box.Root(), Roster: *box.Doc(), Secrets: b.Secrets.SigningKey, Notary: b.Notary.SigningKey, Machine: string(self)}, nil
}

func reportedDigestOf(ref string) string {
	if i := strings.LastIndex(ref, "@sha256:"); i >= 0 {
		return ref[i+1:]
	}
	return ""
}

// kernelBootCert: boot's step 1 for a kernel machine (prepare)
func kernelBootCert(c *client, me string, keys map[string]string) (Cert, error) {
	source := strings.TrimSpace(os.Getenv(kernelSourceEnv))
	var b kernelBootDocs
	var err error
	for i := 0; ; i++ {
		if err = c.json("GET", "/m/kernel/boot", nil, &b); err == nil {
			break
		}
		if i > 300 {
			return Cert{}, fmt.Errorf("no boot documents: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
	box, err := kernelTrustFor(b)
	if err != nil {
		return Cert{}, err
	}
	cert, trust, err := checkKernelBoot(b, box, source, me, keys)
	if err != nil {
		return Cert{}, err
	}
	tb, _ := json.Marshal(trust)
	if err := os.WriteFile(kernelTrustPath, tb, 0o644); err != nil {
		return Cert{}, err
	}
	raw, _ := json.Marshal(cert)
	os.WriteFile(certPath, raw, 0o644) // the settings as boot read them (the supervisor reads the stores from it)
	kernelTrustRefresh = func() (kernelTrust, error) { return refreshKernelTrust(c, me, keys) }
	return cert, nil
}

// kernelTrustEvery: how often a delivered input that doesn't check makes the machine read its documents again
var kernelTrustEvery = 10 * time.Second

var (
	kernelTrustRefresh func() (kernelTrust, error) // set at boot
	kernelTrustMu      sync.Mutex
	kernelTrustAt      time.Time
)

// refreshKernelTrust: the documents again, checked as at boot; the trust they give replaces kernel.json (the
// serving copy's notary and roster after a copy flip)
func refreshKernelTrust(c *client, me string, keys map[string]string) (kernelTrust, error) {
	var b kernelBootDocs
	if err := c.json("GET", "/m/kernel/boot", nil, &b); err != nil {
		return kernelTrust{}, err
	}
	box, err := kernelTrustFor(b)
	if err != nil {
		return kernelTrust{}, err
	}
	_, trust, err := checkKernelBoot(b, box, strings.TrimSpace(os.Getenv(kernelSourceEnv)), me, keys)
	if err != nil {
		return kernelTrust{}, err
	}
	tb, _ := json.Marshal(trust)
	if err := os.WriteFile(kernelTrustPath, tb, 0o644); err != nil {
		return kernelTrust{}, err
	}
	log.Printf("the kernel's roster read again (notary %.16s…)", trust.Notary)
	return trust, nil
}

// kernelRestore: the predecessor's snapshot, the one whose hash the source names
func kernelRestore(c *client, want string) error {
	tmp := predecessorTmp
	defer os.Remove(tmp)
	sum, _, err := fetchSnapshot(c, tmp) // snapdirect.go
	if err != nil {
		return err
	}
	if sum != want {
		return errors.New("the snapshot isn't the one the source names")
	}
	n, err := unpackFile(tmp)
	if err != nil {
		return err
	}
	log.Printf("restored the predecessor's snapshot (%d files)", n)
	return nil
}

// attestKey: what an input's attestation is checked with — the old core's key, or (a kernel machine, which has none)
// "", checkAttest then reading the notary's key from the kernel trust
func attestKey() (string, error) {
	if _, ok := readKernelTrust(); ok {
		return "", nil
	}
	return readTrim(coreKeyPath)
}

// KernelInputSubject: what the log notary's challenge for an input delivered to a kernel machine is over (the
// router's kernelAttest makes the same): the machine's object, the input's kind and the sha256 of its bytes
func KernelInputSubject(machine, kind, sum string) string {
	h := sha256.Sum256([]byte("jarvis2-input\n" + machine + "\n" + kind + "\n" + sum))
	return hex.EncodeToString(h[:])
}

// checkKernelAttest: the notary logged this input for this machine (a challenge about "input" over its subject). One
// that isn't this notary's: the documents are read again (a copy flip brings another notary), at most every
// kernelTrustEvery, and the challenge checked against the notary they name
func checkKernelAttest(t kernelTrust, me, kind string, attested []byte, d *SignedDoc) error {
	if d == nil {
		return errors.New("no notary challenge (the input isn't in the kernel's log)")
	}
	var ch doc.Challenge
	open := func(notary string) bool {
		err := (sig.Doc{Payload: d.Payload, Sig: d.Sig}).Open(notary, &ch)
		return err == nil && ch.Kind == "challenge" && ch.About == "input"
	}
	if !open(t.Notary) {
		t2, ok := refreshedTrust()
		if !ok || t2.Notary == t.Notary || t2.Machine != t.Machine || !open(t2.Notary) {
			return errors.New("no notary challenge (the input isn't in the kernel's log)")
		}
	}
	sum := sha256.Sum256(attested)
	if ch.Subject != KernelInputSubject("fly-"+me, kind, hex.EncodeToString(sum[:])) {
		return errors.New("the notary's challenge is for another input or machine")
	}
	return nil
}

// refreshedTrust: the trust read again now, unless that was done less than kernelTrustEvery ago
func refreshedTrust() (kernelTrust, bool) {
	kernelTrustMu.Lock()
	defer kernelTrustMu.Unlock()
	if kernelTrustRefresh == nil || time.Since(kernelTrustAt) < kernelTrustEvery {
		return kernelTrust{}, false
	}
	kernelTrustAt = time.Now()
	t, err := kernelTrustRefresh()
	if err != nil {
		log.Printf("reading the kernel's documents again: %v", err)
		return kernelTrust{}, false
	}
	return t, true
}

// reloadKernel: a kernel machine's reload (refresh-secrets: its grant changed, an add-store or a downgrade): its boot
// documents again, checked the same way (the grant names the stores now), then a pull with it
func (h *heldSecrets) reloadKernel(c *client, drop, lockHeld bool) (int, error) {
	keys, err := ownKeys()
	if err != nil {
		return 0, err
	}
	refresh := refreshSecrets
	if lockHeld {
		refresh = refreshUnlocked
	}
	n, err := refresh(func() error {
		var b kernelBootDocs
		if err := c.json("GET", "/m/kernel/boot", nil, &b); err != nil {
			return err
		}
		box, err := kernelTrustFor(b)
		if err != nil {
			return err
		}
		cert, trust, err := checkKernelBoot(b, box, strings.TrimSpace(os.Getenv(kernelSourceEnv)), c.me, keys)
		if err != nil {
			return err
		}
		tb, _ := json.Marshal(trust)
		raw, _ := json.Marshal(cert)
		os.WriteFile(kernelTrustPath, tb, 0o644)
		return os.WriteFile(certPath, raw, 0o644)
	}, func() (map[string]string, error) {
		h.pullMu.Lock()
		defer h.pullMu.Unlock()
		return pullSecrets(c, "", c.me)
	})
	if err != nil && drop {
		h.set(map[string]string{})
	}
	return n, err
}

// downgradeKernel: `jarvis downgrade` on a kernel machine: the router has the identity signer narrow this machine's
// grant to the stores kept (a cert (M, M, P), notarized, the grant moved along it) and the supervisor pulls with the
// narrower grant, holding only those stores' keys from then on (no key rotation: secrets serves a pull only to the
// stores the grant names)
func downgradeKernel(sp downgradeSpec) error {
	b, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	var cert Cert
	if json.Unmarshal(b, &cert) != nil {
		return errors.New("couldn't read this session's grant, so the stores it holds aren't known; nothing changed")
	}
	keep, err := sp.keepFor(cert.Stores)
	if errors.Is(err, errNothingToDrop) {
		fmt.Fprintf(os.Stderr, "nothing changed: this session holds %s\n", strings.Join(cert.Stores, " "))
		return nil
	}
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	if err := c.json("POST", "/m/kernel/downgrade", map[string]any{"keep": keep}, nil); err != nil {
		return err
	}
	r, err := askSecrets(secretsReq{Op: "reload", Drop: true}, 20*time.Minute) // the supervisor's RAM copy, at once
	if err != nil {
		r.N = 0 // locked or empty: nothing kept
	}
	fmt.Fprintf(os.Stderr, "downgraded to %v: the supervisor holds %d keys. Values already loaded in running processes stay there until they exit.\n", keep, r.N)
	return nil
}
