package main

// What a machine that receives secrets may be shaped by (docs/DESIGN.md "Inputs to a machine", Deyao 2026-10-11):
// only the cert and what it vouches for. This file holds the core's part of that rule:
//
//   - the image: the one session repository, pinned by digest; Fly must report that digest (certify);
//   - the machine's Fly config: no env from the caller. The core sets only its own key and the router's address
//     (MachineURL, a value of the core's own deployment, never a request's);
//   - the session's settings (Options.Config) and one machine's one-time inputs (Options.Once) travel inside the
//     cert, so the phone approved them, or an unattended resume carried them over unchanged;
//   - a resume restores exactly the snapshot the predecessor signed when it was killed: kill takes the
//     machine-signed snapshot hash, certify puts it into the successor's cert (Cert.Snapshot);
//   - every input a running machine takes later carries a core attestation (audit.go).

import (
	"os"
	"regexp"
	"strings"
)

// SessionRepo: the one image repository machines run (built by CI from git; images.yml). An approval names it
// pinned by digest, so nothing can be swapped between the approval and Fly's pull.
const SessionRepo = "ghcr.io/de0ch/jarvis4-session"

var imageRE = regexp.MustCompile(`^` + regexp.QuoteMeta(SessionRepo) + `(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@(sha256:[0-9a-f]{64})$`)

// imageDigest: the sha256:… of a pinned session image, "" when the reference isn't one
func imageDigest(ref string) string {
	m := imageRE.FindStringSubmatch(ref)
	if m == nil {
		return ""
	}
	return m[2]
}

// reportedDigest: the digest in what Fly reports a machine runs (registry/repository@sha256:…)
func reportedDigest(ref string) string {
	i := strings.LastIndex(ref, "@sha256:")
	if i < 0 || len(ref)-i-1 != len("sha256:")+64 {
		return ""
	}
	return ref[i+1:]
}

// machineURLEnv: the core's own setting for the router's address on Fly's private network (MACHINE_URL of its
// deployment: k8s/apps/core.yaml for production, infra/e2e.sh / rehearsal-box.sh for test cores), set in every
// machine's config by the core alone. No default: a core without it starts no machine (a test core must never make
// a machine that reaches production's router).
const machineURLEnv = "JARVIS2_URL"

var machineURLRE = regexp.MustCompile(`^http://[A-Za-z0-9][A-Za-z0-9._-]{0,200}(:[0-9]{1,5})?/?$`)

func machineURL() string {
	u := strings.TrimSpace(os.Getenv("MACHINE_URL"))
	if !machineURLRE.MatchString(u) {
		return ""
	}
	return u
}

// machineEnv: the whole env a machine's Fly config gets (the request's is ignored); nil without MACHINE_URL
func (c *Core) machineEnv() map[string]string {
	u := machineURL()
	if u == "" {
		return nil
	}
	return map[string]string{coreKeyEnv: c.signer.PublicKey(), machineURLEnv: u}
}

const (
	maxConfig = 64 << 10 // the session's settings (the first prompt is the big part)
	maxOnce   = 16 << 10 // a resume's prompt and a rollback marker
)

// persistentOptions: what an unattended resume must keep exactly (Once is never carried over)
func persistentOptions(o Options) Options {
	o.Once = ""
	return o
}

var hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// SnapshotClaim: what a machine signed over its snapshot (the hex sha256 of the tarball, as the machine signs it)
type SnapshotClaim struct {
	Sha256 string `json:"sha256"`
	Sig    string `json:"sig"`
	// Required: the caller (a pause) would rather keep the machine than kill it without this snapshot vouched for
	Required bool `json:"required"`
}

// signCert: a cert, its entry in the input log beside it (a cert is an input too: it decides what a machine gets),
// and, given the line's carry blob (its predecessor's, or this machine's previous cert's), that blob rebound to this
// cert: only the stores it names, so a downgrade's dropped stores leave it at once (carry.go). Callers hold c.mu.
func (c *Core) signCert(cert Cert, by, carry string) (SignedDoc, error) {
	d, err := c.sign(cert)
	if err != nil {
		return d, err
	}
	id := ""
	if cert.Machine != nil {
		id = cert.Machine.ID
	}
	if !auditWordRE.MatchString(by) {
		by = "core"
	}
	e, err := c.appendAudit(id, "cert", by, sha256Hex(d.Payload))
	if err != nil {
		return SignedDoc{}, err
	}
	d.Entry = &e
	if carried, versions := c.openCarryFor(carry, &cert); carried != nil {
		if d.Carry, err = c.sealCarry(&cert, carried, versions); err != nil {
			return SignedDoc{}, err
		}
	}
	return d, nil
}
