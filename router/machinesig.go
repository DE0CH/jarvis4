package main

// POST /api/machine-signatures/verify (Deyao or a paired device, the Access app "Jarvis 4 devices"): whether a request
// a session machine signed for a service OUTSIDE Jarvis 4 is that machine's, checked as /m checks its own
// (requireMachine): the machine's current signing key, X-Time within machineTimeSkew, the payload
// "<method> <path> <time> <sha256 hex of body>". The answer names the machine's session, its harness and its state, so
// the service learns which session asks without holding any credential of the session's. Today's caller: hermit-jarvis,
// the aviary harness's hermit (aviary/README.md), at a machine's boot. A path under /m is refused: a signature meant
// for the router itself is never checked for anyone else.

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type machineSigRequest struct {
	Machine    string `json:"machine"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Time       string `json:"time"`
	BodySha256 string `json:"bodySha256"`
	Sig        string `json:"sig"`
}

var (
	sigMethodRE = regexp.MustCompile(`^[A-Z]{3,7}$`)
	sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// checkMachineSignature: the machine's session id, harness and state when sig is its machine's over the request, else
// a reason ("" session)
func (r *Router) checkMachineSignature(m machineSigRequest, now time.Time) (sid, harness, state, why string) {
	if m.Machine == "" || !sigMethodRE.MatchString(m.Method) || !strings.HasPrefix(m.Path, "/") ||
		m.Path == "/m" || strings.HasPrefix(m.Path, "/m/") || !sha256HexRE.MatchString(m.BodySha256) {
		return "", "", "", "malformed: machine, an upper-case method, a path outside /m and a sha256 hex are required"
	}
	ts, err := strconv.ParseInt(m.Time, 10, 64)
	if d := now.Sub(time.Unix(ts, 0)); err != nil || d > machineTimeSkew || d < -machineTimeSkew {
		return "", "", "", "time too far off"
	}
	var key string
	r.st.Do(func(d *persisted) {
		if s := d.Started[m.Machine]; s != nil {
			key = s.SigningKey
		}
		sid = d.Machines[m.Machine]
		if s := d.Sessions[sid]; s != nil {
			harness, state = s.Harness, s.State
		} else {
			sid = ""
		}
	})
	if key == "" || sid == "" || !verifyP256(key, []byte(m.Method+" "+m.Path+" "+m.Time+" "+m.BodySha256), m.Sig) {
		return "", "", "", "not signed by a running session's machine"
	}
	return sid, harness, state, ""
}

func (r *Router) verifyMachineSignature(w http.ResponseWriter, req *http.Request) {
	var m machineSigRequest
	if err := json.NewDecoder(io.LimitReader(req.Body, 64<<10)).Decode(&m); err != nil {
		writeJSON(w, 400, map[string]string{"error": "not JSON"})
		return
	}
	sid, harness, state, why := r.checkMachineSignature(m, time.Now())
	if sid == "" {
		status := 403
		if strings.HasPrefix(why, "malformed") {
			status = 400
		}
		writeJSON(w, status, map[string]string{"error": why})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]string{"session": sid, "harness": harness, "state": state})
}
