package main

// The guard (docs/DESIGN.md "The supervisor and the guard"): the part of the supervisor that checks what comes in
// from the router and lets through only what something Deyao trusts vouches for. It guards exactly the commands that
// can steer the session or run code in it:
//   - execs (a router feature's shell command): the holder's signature, then a phone grant, a standing rule or the
//     session's own allow list (authoriseExec; "Grants");
//   - deliveries (prompts into the harness: wakeups, crons, watches, Inbox outcomes, leases, the image's own texts):
//     the line's own signature or the image's text, the core's attestation, once each ("Inputs to a machine"); in a
//     session holding a sensitive store also the phone's signature over that very message or a per-kind rule
//     (messages.go, "Message approvals").
// Everything else the supervisor takes (snapshot, free, refresh-secrets, pause-harness, resume-harness) can't carry
// an instruction and runs unguarded (supervisor.go commands). Nothing guarded runs once the session is frozen for its
// final snapshot.

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// guardExec: the exec request, when it may run now
func guardExec(e Exec, now time.Time) (ExecRequest, error) {
	r, err := authoriseExec(e, now)
	if err == nil {
		err = notFrozen()
	}
	return r, err
}

// guardDelivery: the text a delivery puts into the harness, once its voucher and the core's attestation check out,
// and (a sensitive session, or a resume prompt) the phone's approval of exactly that message (messages.go); approved:
// the approval item to record once the harness took it. The replay check and record happen in deliver, in order with
// the send.
func guardDelivery(c *client, d Delivery) (text string, out Delivery, cert Cert, approved string, err error) {
	text, out, cert, attested, err := renderDelivery(d)
	if err != nil {
		return "", d, cert, "", err
	}
	coreKey, err := attestKey()
	if err != nil {
		return "", d, cert, "", err
	}
	if err := checkAttest(coreKey, c.me, d.Kind, attested, d.Attest); err != nil {
		return "", d, cert, "", err
	}
	if approved, err = checkMessageApproval(cert, d, attested, text, time.Now()); err != nil {
		return text, d, cert, "", err
	}
	if err := notFrozen(); err != nil {
		return "", d, cert, "", err
	}
	return text, out, cert, approved, nil
}

// renderDelivery: the text the harness would get (a request-outcome's items already told left out), the delivery as
// it goes in, this machine's cert and the bytes the core attests. Nothing is recorded or sent: the router's preview of
// a message for Deyao's approval is exactly this text (deliver.go previewDelivery).
func renderDelivery(d Delivery) (string, Delivery, Cert, []byte, error) {
	cert, err := currentCert()
	if err != nil {
		return "", d, cert, nil, err
	}
	text, attested, err := deliveryText(d, readLineKeys())
	if err != nil {
		return "", d, cert, nil, err
	}
	if d.Kind == "request-outcome" && d.Request != nil {
		if f := outcomeFresh(d); len(f.Outcomes) != len(d.Outcomes) {
			if text, _, err = deliveryText(f, readLineKeys()); err != nil { // the same checks, on the items still untold
				return "", d, cert, nil, err
			}
			d = f
		}
	}
	return text, d, cert, attested, nil
}

// authoriseExec: nil when the holder-signed request may run (a phone grant, a standing rule or the allow list)
func authoriseExec(e Exec, now time.Time) (ExecRequest, error) {
	var r ExecRequest
	if err := json.Unmarshal([]byte(e.Request), &r); err != nil {
		return r, errors.New("bad request")
	}
	if !verify(r.Holder, []byte(e.Request), e.Sig) {
		return r, errors.New("not signed by the holder it names")
	}
	if at := time.Unix(r.At, 0); now.Sub(at) > 2*time.Minute || at.Sub(now) > 2*time.Minute {
		return r, errors.New("request too old or from the future")
	}
	seenMu.Lock()
	for id, t := range seen {
		if now.Sub(t) > 5*time.Minute {
			delete(seen, id)
		}
	}
	dup := seen[r.ID] != time.Time{}
	seen[r.ID] = now
	seenMu.Unlock()
	if r.ID == "" || dup {
		return r, errors.New("request id missing or already used")
	}
	cert, err := currentCert()
	if err != nil {
		return r, fmt.Errorf("no valid cert: %v", err)
	}
	me := cert.Line // core-signed, so the router can't relabel a machine to reuse another line's grant
	if me == "" || r.Session != me {
		return r, fmt.Errorf("request is for line %s, this is %s", r.Session, me)
	}
	if r.PhoneOnly && e.Grant == nil {
		return r, fmt.Errorf("this request needs a phone grant: file `jarvis-request grant %s --minutes N --why …` and Deyao approves it with Face ID", r.Holder)
	}
	if e.Grant == nil {
		if cert.Sensitive {
			return r, fmt.Errorf("this session holds a sensitive store, so only a phone grant opens a shell: `jarvis-request grant %s --minutes N --why …`", r.Holder)
		}
		for _, a := range readAllow() {
			if u, err := time.Parse(time.RFC3339, a.Until); err == nil && a.Holder == r.Holder && now.Before(u) {
				return r, nil
			}
		}
		return r, fmt.Errorf("no grant, and %s isn't on this session's allow list: `jarvis-machine allow %s DURATION` (non-sensitive sessions), or `jarvis-request grant %s --why …`", r.Holder, r.Holder, r.Holder)
	}
	var g Grant
	if cert.Phone == "" || verifyDoc(cert.Phone, e.Grant, &g) != nil {
		return r, errors.New("the grant isn't signed by the phone named in this machine's cert")
	}
	if g.Holder != r.Holder || g.Session != me || g.Scope != "shell" {
		return r, errors.New("the grant is for another holder, session or scope")
	}
	switch g.Kind {
	case "grant":
		iss, err1 := time.Parse(time.RFC3339, g.Issued)
		exp, err2 := time.Parse(time.RFC3339, g.Expires)
		if err1 != nil || err2 != nil || exp.Sub(iss) > maxGrant || !now.Before(exp) || now.Before(iss.Add(-2*time.Minute)) {
			return r, fmt.Errorf("the grant is expired, or longer than 10 minutes: ask for a new one (`jarvis-request grant %s --minutes N --why …`)", r.Holder)
		}
	case "rule":
		if r.PhoneOnly {
			return r, fmt.Errorf("this request needs a phone grant, not a standing rule: `jarvis-request grant %s --minutes N --why …`", r.Holder)
		}
		if cert.Sensitive {
			return r, fmt.Errorf("this session holds a sensitive store, so standing rules don't apply: `jarvis-request grant %s --minutes N --why …` (at most 10 minutes)", r.Holder)
		}
		u, err := time.Parse(time.RFC3339, g.Until)
		if err != nil || !now.Before(u) {
			return r, fmt.Errorf("the standing rule has expired: ask again (`jarvis-request grant %s --days N --why …`)", r.Holder)
		}
	default:
		return r, errors.New("unknown grant kind")
	}
	return r, nil
}
