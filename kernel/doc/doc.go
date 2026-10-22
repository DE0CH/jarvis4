// Package doc: the kernel's documents (docs/PLAN-grants.md §2). Every one travels as a sig.Doc and is opened
// strictly: an unknown field refuses it. The kernel reads a source's settings as opaque JSON (only the guard gives them
// meaning).
package doc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/DE0CH/jarvis4/kernel/h2c"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// ---- objects ---------------------------------------------------------------------------------------------------

// Object: "sink", "source-<32 hex>" or "fly-<Fly machine id>"
type Object string

const Sink Object = "sink"

var (
	sourceRE = regexp.MustCompile(`^source-[0-9a-f]{32}$`)
	flyRE    = regexp.MustCompile(`^fly-[0-9a-f]{8,32}$`)
	imageRE  = regexp.MustCompile(`^[a-z0-9./-]+(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}$`)
	hex64RE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Kind: "sink", "source", "fly" or "" (not an object)
func (o Object) Kind() string {
	switch {
	case o == Sink:
		return "sink"
	case sourceRE.MatchString(string(o)):
		return "source"
	case flyRE.MatchString(string(o)):
		return "fly"
	}
	return ""
}

// FlyID: the Fly machine id of a fly- object
func (o Object) FlyID() string { return strings.TrimPrefix(string(o), "fly-") }

// Keys: an object's public keys
type Keys struct {
	SigningKey    string `json:"signingKey"`
	EncryptionKey string `json:"encryptionKey"`
}

// IdealKeys: the keys of the sink or a source, hashed from its name (nobody holds their private halves)
func IdealKeys(o Object) (Keys, error) {
	if k := o.Kind(); k != "sink" && k != "source" {
		return Keys{}, fmt.Errorf("%s has no ideal keys", o)
	}
	return Keys{h2c.ObjectKey(string(o), "signing"), h2c.ObjectKey(string(o), "encryption")}, nil
}

// NewSource: a fresh source name
func NewSource(random []byte) Object { return Object("source-" + hex.EncodeToString(random[:16])) }

// ---- sources and certs ----------------------------------------------------------------------------------------

// Source: what a cert into a source defines it as
type Source struct {
	Image    string          `json:"image"`              // ref@sha256:…
	Settings json.RawMessage `json:"settings"`           // the start settings (the guard's)
	Snapshot string          `json:"snapshot,omitempty"` // a kill's: the machine's signed snapshot hash
}

// Machine: a Fly machine as the spawner attests it
type Machine struct {
	Keys
	Image string `json:"image"` // ref@sha256:… Fly reported
}

// Signers of succession certs (DESIGN's table)
const (
	ByIPhone   = "iphone"
	ByRoot     = "root"
	BySpawner  = "spawner"
	ByIdentity = "identity"
	ByGullible = "gullible"
)

// Cert: a succession cert (pred → succ with pair), signed by Signer
type Cert struct {
	Kind     string    `json:"kind"` // "succession"
	Pred     Object    `json:"pred"`
	Succ     Object    `json:"succ"`
	Pair     perm.Pair `json:"pair"`
	Source   *Source   `json:"source,omitempty"`  // succ is a source
	Machine  *Machine  `json:"machine,omitempty"` // succ is a Fly machine other than pred: its keys and image
	Signer   string    `json:"signer"`
	IssuedAt string    `json:"issuedAt"`
}

// Check: well formed (not who signed it: the notarizer's table)
func (c Cert) Check() error {
	switch {
	case c.Kind != "succession":
		return errors.New("not a succession cert")
	case c.Pred.Kind() == "" || c.Succ.Kind() == "":
		return errors.New("predecessor or successor isn't an object")
	case (c.Succ.Kind() == "source") != (c.Source != nil):
		return errors.New("a cert into a source carries the source, and only then")
	case (c.Succ.Kind() == "fly" && c.Pred != c.Succ) != (c.Machine != nil):
		return errors.New("a cert into another Fly machine names its keys, and only then")
	}
	if err := c.Pair.Valid(); err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	if c.Source != nil {
		if !imageRE.MatchString(c.Source.Image) {
			return errors.New("source image: not ref@sha256:digest")
		}
		if c.Source.Snapshot != "" && !hex64RE.MatchString(c.Source.Snapshot) {
			return errors.New("source snapshot: not a sha256")
		}
		var m map[string]any
		if json.Unmarshal(c.Source.Settings, &m) != nil {
			return errors.New("source settings: not a JSON object")
		}
	}
	if c.Machine != nil && !imageRE.MatchString(c.Machine.Image) {
		return errors.New("machine image: not ref@sha256:digest")
	}
	if _, err := time.Parse(time.RFC3339Nano, c.IssuedAt); err != nil {
		return errors.New("issuedAt")
	}
	return nil
}

// OpenCert: the cert d holds, signed by pub, well formed
func OpenCert(d sig.Doc, pub string) (Cert, error) {
	var c Cert
	if err := d.Open(pub, &c); err != nil {
		return Cert{}, err
	}
	return c, c.Check()
}

// PeekCert: the cert's text, not checked (to find who signed it)
func PeekCert(d sig.Doc) (Cert, error) {
	var c Cert
	if err := sig.StrictJSON([]byte(d.Payload), &c); err != nil {
		return Cert{}, err
	}
	return c, c.Check()
}

// ---- the log notary --------------------------------------------------------------------------------------------

// Challenge: one entry of the log notary's log
type Challenge struct {
	Kind    string `json:"kind"` // "challenge"
	Seq     int64  `json:"seq"`
	Prev    string `json:"prev"` // ID of the previous entry ("" = the first)
	At      string `json:"at"`   // the notary's clock, RFC 3339 UTC
	Subject string `json:"subject"`
	About   string `json:"about"`
	Nonce   string `json:"nonce"`
}

var aboutRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// CheckChallengeInput: what a challenge may be asked for
func CheckChallengeInput(subject, about string) error {
	if !hex64RE.MatchString(subject) {
		return errors.New("subject: a sha256 in hex")
	}
	if !aboutRE.MatchString(about) {
		return errors.New("about: a short lowercase word")
	}
	return nil
}

// Notarized: the notarizer's answer for a cert, carrying the notary's challenge over the cert's ID
type Notarized struct {
	Kind      string  `json:"kind"` // "notarized"
	Cert      string  `json:"cert"` // ID of the cert
	Challenge sig.Doc `json:"challenge"`
}

// ---- grants ----------------------------------------------------------------------------------------------------

// Grant: (machine, pair), made by the mover or the merger (⊤ on the sink by the root key)
type Grant struct {
	Kind    string    `json:"kind"` // "grant"
	Machine Object    `json:"machine"`
	Keys    Keys      `json:"keys"` // the machine's keys (ideal keys for the sink or a source)
	Pair    perm.Pair `json:"pair"`
	From    []string  `json:"from"` // IDs: the grant and notarization it was moved along, or the two merged
	At      string    `json:"at"`   // the newest notarized time along its chain
}

func (g Grant) Check() error {
	switch {
	case g.Kind != "grant":
		return errors.New("not a grant")
	case g.Machine.Kind() == "":
		return errors.New("machine isn't an object")
	case g.Keys.SigningKey == "" || g.Keys.EncryptionKey == "":
		return errors.New("keys missing")
	case g.From == nil:
		return errors.New("from missing")
	}
	if _, err := time.Parse(time.RFC3339Nano, g.At); err != nil {
		return errors.New("at")
	}
	return g.Pair.Valid()
}

// OpenGrant: a grant signed by pub, well formed
func OpenGrant(d sig.Doc, pub string) (Grant, error) {
	var g Grant
	if err := d.Open(pub, &g); err != nil {
		return Grant{}, err
	}
	return g, g.Check()
}

// Now: the kernel's time format
func Now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
