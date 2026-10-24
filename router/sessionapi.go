package main

// The session-facing API (Jarvis 1's `$JARVIS_URL/api/...` as its session scripts call it). In a Jarvis 4
// session JARVIS_URL points at the machine's local proxy (the supervisor, `jarvis-machine supervisor`, machine/apiproxy.go), which
// signs each request with the machine key and sends it here as /m/api/<rest>. Any session id in the path must
// be the calling machine's own session.
//
// Served by the router: wakeups and crons (schedule.go), watches (watches.go), notify-idle (autopilot.go's switch), and the session
// retiring itself.
// The iCloud index (searchsvc.go). Device leases: leases.go; content
// stores: content.go.
// The shared Claude login (`/api/credentials`): claudelogin.go. Nothing is forwarded to Jarvis 1. The secrets and
// changes calls never reach the router: the machine answers them itself (it holds its secrets and its repos).

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// maxProposedSessions: new sessions one session may have waiting for Deyao's approval at a time
const maxProposedSessions = 3

// auto-pause (autopilot.go) leaves a session running when a wakeup or cron fires within 10 minutes
func init() {
	autoPauseVeto = func(d *persisted, sid string) bool { return scheduleDueWithin(d, sid, 10*time.Minute) }
}

func (r *Router) registerSessionAPI(app appRoute, m machineRoute) {
	// ---- the app (Deyao) -------------------------------------------------------------------------------
	app("GET /api/sessions/{id}/wakeup", func(w http.ResponseWriter, req *http.Request) { r.getWakeups(w, req.PathValue("id"), true) })
	app("GET /api/sessions/{id}/wakeups", func(w http.ResponseWriter, req *http.Request) { r.getWakeups(w, req.PathValue("id"), false) })
	for _, p := range []string{"POST /api/sessions/{id}/wakeup", "POST /api/sessions/{id}/wakeups"} {
		app(p, func(w http.ResponseWriter, req *http.Request) {
			appArmRefused(w, "wakeup", "scripts/schedule-wakeup.sh")
		})
	}
	app("DELETE /api/sessions/{id}/wakeup", func(w http.ResponseWriter, req *http.Request) {
		r.deleteWakeups(w, req.PathValue("id"), req.URL.Query().Get("name"), req.URL.Query().Get("all") == "1")
	})
	app("DELETE /api/sessions/{id}/wakeups/{name}", func(w http.ResponseWriter, req *http.Request) {
		r.deleteWakeups(w, req.PathValue("id"), req.PathValue("name"), false)
	})
	app("GET /api/sessions/{id}/crons", func(w http.ResponseWriter, req *http.Request) { r.getCrons(w, req.PathValue("id")) })
	app("POST /api/sessions/{id}/crons", func(w http.ResponseWriter, req *http.Request) { appArmRefused(w, "cron", "scripts/schedule-cron.sh") })
	app("DELETE /api/sessions/{id}/crons/{name}", func(w http.ResponseWriter, req *http.Request) {
		r.deleteCron(w, req.PathValue("id"), req.PathValue("name"))
	})

	r.registerSearchServices(app, m) // the iCloud index (searchsvc.go)

	// ---- the session itself (through its machine's local proxy) -------------------------------------------
	own := func(pattern string, fn func(w http.ResponseWriter, req *http.Request, sid string, body []byte)) {
		m(pattern, func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
			sid, err := r.machineSession(machine)
			if err != nil {
				writeJSON(w, 403, map[string]string{"error": err.Error()})
				return
			}
			if id := req.PathValue("id"); id != "" && id != sid {
				writeJSON(w, 403, map[string]string{"error": fmt.Sprintf("this machine is session %s, not %s: these routes act on the calling session only; to act on another session use its actions (scripts/jarvis4-actions.py, /m/api/actions/sessions/%s/…) or message it", sid, id, id)})
				return
			}
			fn(w, req, sid, body)
		})
	}
	own("GET /m/api/sessions/{id}/wakeup", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) { r.getWakeups(w, sid, true) })
	own("GET /m/api/sessions/{id}/wakeups", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) { r.getWakeups(w, sid, false) })
	// the session's own request, kept exactly as its machine signed it: what vouches for the delivery (vouch.go)
	own("POST /m/api/sessions/{id}/wakeup", func(w http.ResponseWriter, req *http.Request, sid string, b []byte) {
		r.postWakeup(w, sid, b, signedRequestOf(req, req.Header.Get("X-Machine"), b))
	})
	own("POST /m/api/sessions/{id}/wakeups", func(w http.ResponseWriter, req *http.Request, sid string, b []byte) {
		r.postWakeup(w, sid, b, signedRequestOf(req, req.Header.Get("X-Machine"), b))
	})
	own("DELETE /m/api/sessions/{id}/wakeup", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		r.deleteWakeups(w, sid, req.URL.Query().Get("name"), req.URL.Query().Get("all") == "1")
	})
	own("DELETE /m/api/sessions/{id}/wakeups/{name}", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		r.deleteWakeups(w, sid, req.PathValue("name"), false)
	})
	own("GET /m/api/sessions/{id}/crons", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) { r.getCrons(w, sid) })
	own("POST /m/api/sessions/{id}/crons", func(w http.ResponseWriter, req *http.Request, sid string, b []byte) {
		r.postCron(w, sid, b, signedRequestOf(req, req.Header.Get("X-Machine"), b))
	})
	own("DELETE /m/api/sessions/{id}/crons/{name}", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		r.deleteCron(w, sid, req.PathValue("name"))
	})
	own("POST /m/api/sessions/{id}/notify-idle", func(w http.ResponseWriter, req *http.Request, sid string, b []byte) { r.postNotifyIdle(w, sid, b) })
	// retire-session.sh: the session destroys itself, unless it still has a wakeup or cron to wait for
	own("DELETE /m/api/sessions/{id}", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		if p := r.PendingSchedule(sid); len(p) > 0 {
			writeJSON(w, 409, map[string]any{"error": "the session still has pending " + strings.Join(p, ", ") + " — cancel them first, or let them fire", "pending": p})
			return
		}
		if err := r.Destroy(sid); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 202, map[string]any{"started": true, "phase": "destroying"})
	})
	// a session proposes a new session (Deyao, 2026-10-12: "launch a new session through jarvis 2"): the same line as
	// the app's New session, so nothing starts until Deyao approves the core's succession from null with Face ID; the
	// approval names the proposing session and carries its reason. Attachments: files this session staged
	// (PUT /m/api/sessions/{id}/uploads/…, uploads.go), signed by hash with the line as the app's are.
	own("POST /m/api/sessions", func(w http.ResponseWriter, req *http.Request, sid string, b []byte) {
		r.proposeSession(w, Caller{Kind: "session", Session: sid}, sid, b, signedRequestOf(req, req.Header.Get("X-Machine"), b))
	})
	own("/m/api/", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		writeJSON(w, 404, map[string]string{"error": fmt.Sprintf("Jarvis 4 doesn't serve %s %s", req.Method, strings.TrimPrefix(req.URL.Path, "/m"))})
	})
}

// the machine-side proxy's address (machine/apiproxy.go) and placeholders for the Access/session-token variables
// Jarvis 1's scripts insist on before calling; the proxy ignores them (a store's real values override these).
// Not for OpenCode/OpenClaw: their harness scripts take CF_ACCESS_* as "publish the web UI through the
// cf-tunnel" and would loop on a placeholder.
const machineAPIURL = "http://127.0.0.1:7171"

func init() {
	envHooks = append(envHooks, func(_ *Router, s *Session, e map[string]string) {
		sessionAPIEnv(e, s.Harness)
		// cf-tunnel/agent.js would otherwise name the tunnel after Claude's own conversation id, which the
		// Worker refuses for Jarvis 4 (only s+16 hex, with this session's proof)
		e["TUNNEL_ID"] = s.ID
	})
}

func sessionAPIEnv(e map[string]string, harness string) {
	e["JARVIS_URL"] = machineAPIURL

	e["SESSION_API_TOKEN"] = "jarvis2-local-proxy"
	if !harnessSend[harness] {
		e["CF_ACCESS_CLIENT_ID"], e["CF_ACCESS_CLIENT_SECRET"] = "jarvis2-local-proxy", "jarvis2-local-proxy"
	}
}

// cleanResumePrompt: CRLF → LF, trimmed, at most resumePromptMax characters (multi-line kept)
func cleanResumePrompt(p string) (string, error) {
	p = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(p, "\r\n", "\n"), "\r", "\n"))
	if len([]rune(p)) > resumePromptMax {
		return "", fmt.Errorf("prompt longer than %d characters", resumePromptMax)
	}
	return p, nil
}

// machineSession: the session a machine currently runs (a paused or replaced machine has none)
func (r *Router) machineSession(machine string) (string, error) {
	var sid string
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine {
			sid = s.ID
		}
	})
	if sid == "" {
		return "", errors.New("this machine isn't a running session")
	}
	return sid, nil
}

func scheduleErr(w http.ResponseWriter, err error) {
	var b *badRequest
	switch {
	case errors.As(err, &b):
		writeJSON(w, 400, map[string]string{"error": b.msg})
	case errors.Is(err, errNoSession):
		writeJSON(w, 404, map[string]string{"error": err.Error()})
	case strings.HasPrefix(err.Error(), "session is "):
		writeJSON(w, 409, map[string]string{"error": err.Error()})
	default:
		writeErr(w, err)
	}
}

func decodeBody(b []byte) (map[string]any, error) {
	m := map[string]any{}
	if len(strings.TrimSpace(string(b))) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, bad("bad JSON: %v", err)
	}
	return m, nil
}

// GET …/wakeup → {wakeup (the soonest, or null), wakeups}; GET …/wakeups → {wakeups}
func (r *Router) getWakeups(w http.ResponseWriter, sid string, single bool) {
	ws, err := r.ListWakeups(sid)
	if err != nil {
		scheduleErr(w, err)
		return
	}
	views := []map[string]any{}
	for _, x := range ws {
		views = append(views, wakeupView(x))
	}
	if !single {
		writeJSON(w, 200, map[string]any{"wakeups": views})
		return
	}
	var first any
	if len(views) > 0 {
		first = views[0]
	}
	writeJSON(w, 200, map[string]any{"wakeup": first, "wakeups": views})
}

// appArmRefused: arming from the app. Nothing would vouch for its delivery into the session (only the session's own
// signed request does, machine/deliver.go), so a wakeup or cron armed here could never fire: it was accepted and then
// failed at every firing. Refused upfront instead, saying what works (like watches.go).
func appArmRefused(w http.ResponseWriter, kind, script string) {
	writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("a %s is armed by the session itself (%s): only its own signed request can be delivered into it. Ask the session to arm it (message it in its chat)", kind, script)})
}

func (r *Router) postWakeup(w http.ResponseWriter, sid string, body []byte, signed *SignedRequest) {
	b, err := decodeBody(body)
	if err != nil {
		scheduleErr(w, err)
		return
	}
	wu, err := normalizeWakeup(b, time.Now())
	if err == nil {
		wu.Signed = signed
		err = r.ArmWakeup(sid, wu)
	}
	if err != nil {
		scheduleErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "wakeup": wakeupView(wu)})
}

func (r *Router) deleteWakeups(w http.ResponseWriter, sid, name string, all bool) {
	var names []string
	if !all {
		n, err := wakeupName(name)
		if err != nil {
			scheduleErr(w, err)
			return
		}
		names = []string{n}
	}
	out, err := r.CancelWakeups(sid, names, all)
	if err != nil {
		scheduleErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "cancelled": out})
}

func (r *Router) getCrons(w http.ResponseWriter, sid string) {
	cs, err := r.ListCrons(sid)
	if err != nil {
		scheduleErr(w, err)
		return
	}
	views := []map[string]any{}
	for _, c := range cs {
		views = append(views, cronView(c))
	}
	writeJSON(w, 200, map[string]any{"crons": views})
}

func (r *Router) postCron(w http.ResponseWriter, sid string, body []byte, signed *SignedRequest) {
	b, err := decodeBody(body)
	if err != nil {
		scheduleErr(w, err)
		return
	}
	c, err := normalizeCron(b, time.Now())
	if err == nil {
		c.Signed = signed
		err = r.ArmCron(sid, c)
	}
	if err != nil {
		scheduleErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "cron": cronView(c)})
}

func (r *Router) deleteCron(w http.ResponseWriter, sid, name string) {
	if !scheduleNameRE.MatchString(name) {
		writeJSON(w, 400, map[string]string{"error": "bad cron name"})
		return
	}
	if err := r.CancelCron(sid, name); err != nil {
		scheduleErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// postNotifyIdle: scripts/session-notify-idle.sh — the same switch as the app's (autopilot.go Liveness)
func (r *Router) postNotifyIdle(w http.ResponseWriter, sid string, body []byte) {
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	json.Unmarshal(body, &in)
	on := in.Enabled == nil || *in.Enabled
	found := false
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[sid]; s != nil {
			found = true
			if s.Live == nil {
				s.Live = &Liveness{}
			}
			s.Live.NotifyIdleOff = !on
		}
	})
	if !found {
		scheduleErr(w, errNoSession)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "notifyIdle": onOff(!on)})
}

// proposeSession: a caller that isn't Deyao (a session, the actions key) proposes a new session — the same line as
// the app's New session, so nothing starts until Deyao approves the core's succession from null with Face ID; the
// approval names the caller and carries its reason. Attachments only from a session, its own uploads (uploads.go). prefix keeps the
// caller's request ids apart from the app's and every other caller's.
func (r *Router) proposeSession(w http.ResponseWriter, c Caller, prefix string, b []byte, signed *SignedRequest) {
	var in proposalIn
	if err := json.Unmarshal(b, &in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad JSON: " + err.Error()})
		return
	}
	ns, err := r.checkProposal(c, prefix, in, true)
	if err == nil {
		ns.Origin.Signed = signed
	}
	if err != nil {
		writeRequestErr(w, err)
		return
	}
	waiting := 0
	r.st.Do(func(d *persisted) { _, waiting = callerLoad(d, c) })
	if waiting >= maxProposedSessions {
		writeJSON(w, 429, map[string]string{"error": fmt.Sprintf("%d proposed sessions already wait for Deyao: wait for his answer, or deny one (jarvis4-actions.py deny ID), then propose again", waiting)})
		return
	}
	id, err := r.CreateSession(ns)
	if err != nil {
		scheduleErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "requestId": strings.TrimPrefix(ns.RequestID, prefix+":"), "approval": true})
}

// proposalIn: a proposed new session (POST /m/api/sessions, /actions/sessions, a batch's new-session item)
type proposalIn struct {
	NewSession
	Explanation string `json:"explanation"`
}

// checkProposal: the proposal checked and made into the NewSession CreateSession takes (the caller and its call
// recorded); explanation required unless the batch's summary stands for it
func (r *Router) checkProposal(c Caller, prefix string, in proposalIn, explRequired bool) (NewSession, error) {
	expl, err := cleanExplanation(in.Explanation, explRequired)
	if err != nil {
		return NewSession{}, &badRequest{err.Error()}
	}
	if strings.TrimSpace(in.Prompt) == "" {
		return NewSession{}, &badRequest{"prompt is required"}
	}
	if in.RequestID == "" {
		in.RequestID = randID()
	}
	in.RequestID = prefix + ":" + in.RequestID
	var attached []string
	if in.Attachments != nil {
		if c.Kind != "session" {
			return NewSession{}, &badRequest{"attachments come only with a session's own proposal (jarvis-request new-session --attach FILE)"}
		}
		var err error
		r.st.Do(func(d *persisted) {
			sid := "" // a repeat of a proposal already made: its own upload
			for _, x := range d.Sessions {
				if x.RequestID == in.RequestID {
					sid = x.ID
				}
			}
			var files []AttachFile
			if files, _, err = checkUpload(d, sid, c.Session, in.Attachments); err == nil {
				for _, f := range files {
					attached = append(attached, f.Name)
				}
			}
		})
		if err != nil {
			return NewSession{}, &badRequest{err.Error()}
		}
		in.AttachOwner = c.Session
	}
	args := map[string]any{"label": in.Label, "harness": in.Harness, "stores": in.Stores, "model": in.Model, "permissionMode": in.PermissionMode,
		"size": in.Size, "prompt": fmt.Sprintf("(%d characters)", len([]rune(in.Prompt)))}
	if len(in.Content) > 0 {
		args["content"] = in.Content
	}
	if in.Repos != "" {
		args["repos"] = in.Repos
	}
	if len(attached) > 0 {
		args["attachments"] = attached
	}
	ns := in.NewSession
	ns.Origin = &Origin{Caller: c, Call: APICall{Method: "POST", Path: "/api/sessions", Args: args}}
	ns.Explanation = expl
	return ns, nil
}
