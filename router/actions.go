package main

// The actions (Deyao, 2026-10-13): what a session may do to Jarvis 4 beyond its own business — list sessions and the
// Inbox, resume a paused session with no prompt (same image: approve_by_dead_machine), pause one, move a running one
// to the next size, destroy one (the app's Destroy), deny a request or approval, and file requests (a new session,
// an added store, a repo, a grant, an unlock, or any app API call: apicalls.go), which only wait in Deyao's Inbox.
//
// Each session's key is its own machine key (minted when the core starts the machine, signs every /m call), so
// every action is recorded as that session's actions (Caller{Kind: "actions", Session}), shown in the Inbox and
// logged. The key works only while the session runs: once it starts pausing or destroying (or is paused), every
// action is refused and its pending API-call requests leave the Inbox (dropActionsOf).

import (
	"errors"
	"log"
	"net/http"
)

// actionsSession: the running session whose machine signed this call
func (r *Router) actionsSession(machine string) (string, error) {
	var sid string
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[d.Machines[machine]]; s != nil && s.MachineID == machine && (s.State == "started" || s.State == "initialising") {
			sid = s.ID
		}
	})
	if sid == "" {
		return "", errors.New("this machine isn't a running session: its actions end when it pauses or is destroyed")
	}
	return sid, nil
}

func (r *Router) registerActions(m machineRoute) {
	act := func(pattern string, fn func(w http.ResponseWriter, req *http.Request, c Caller, b []byte)) {
		m(pattern, func(w http.ResponseWriter, req *http.Request, machine string, b []byte) {
			sid, err := r.actionsSession(machine)
			if err != nil {
				writeJSON(w, 403, map[string]string{"error": err.Error()})
				return
			}
			if req.Method != "GET" {
				log.Printf("actions: session %s: %s %s", sid, req.Method, req.URL.Path)
			}
			fn(w, req, Caller{Kind: "actions", Session: sid}, b)
		})
	}
	// the path as the caller called it (without the machine listener's /m prefix), for the Inbox's "Call" row
	path := func(req *http.Request) string { return req.URL.Path[len("/m"):] }
	act("GET /m/api/actions/sessions", func(w http.ResponseWriter, req *http.Request, _ Caller, _ []byte) {
		out := []map[string]any{}
		r.st.Do(func(d *persisted) {
			for _, s := range d.Sessions {
				v := map[string]any{"id": s.ID, "machineId": s.MachineID, "state": s.State, "title": sessionTitle(*s), "error": s.Error, "image": s.Image}
				if l := s.Live; l != nil && l.Reg != nil {
					v["status"] = l.Reg.Status
				}
				if l := s.Live; l != nil && l.NeedsGrant != "" {
					v["needsGrant"] = l.NeedsGrant
				}
				out = append(out, v)
			}
		})
		writeJSON(w, 200, map[string]any{"sessions": out})
	})
	act("GET /m/api/actions/requests", func(w http.ResponseWriter, req *http.Request, _ Caller, _ []byte) {
		writeJSON(w, 200, map[string]any{"requests": r.Inbox(), "batches": r.InboxBatches(nil)})
	})
	// resume: same image, no prompt, no option changes, so the core answers approve_by_dead_machine and nothing
	// reaches the phone (a line whose permission mode differs from its cert still gets its approval in the Inbox)
	act("POST /m/api/actions/sessions/{id}/resume", func(w http.ResponseWriter, req *http.Request, c Caller, _ []byte) {
		id := req.PathValue("id")
		r.noteOrigin(id, Origin{Caller: c, Call: APICall{Method: "POST", Path: path(req), Args: map[string]any{"upgrade": false}}})
		if err := r.Resume(id, false); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	act("POST /m/api/actions/sessions/{id}/pause", func(w http.ResponseWriter, req *http.Request, _ Caller, _ []byte) {
		if err := r.Pause(req.PathValue("id")); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	// upgrade: the next size up, as the app's Upgrade (memory.go): frees, snapshots, resumes on the bigger machine
	act("POST /m/api/actions/sessions/{id}/upgrade", func(w http.ResponseWriter, req *http.Request, _ Caller, _ []byte) {
		out, err := r.Upgrade(req.PathValue("id"))
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 202, out)
	})
	// destroy (Deyao, 2026-10-13): exactly the app's Destroy, ?force=1 included (its "confirm lost work")
	act("POST /m/api/actions/sessions/{id}/destroy", func(w http.ResponseWriter, req *http.Request, _ Caller, _ []byte) {
		if err := r.DestroyWith(req.PathValue("id"), req.URL.Query().Get("force") == "1"); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	// deny: an Inbox request leaves; an approval is rejected as Deny in the app would (a new session disappears, a
	// resume stays paused)
	act("POST /m/api/actions/requests/{id}/deny", func(w http.ResponseWriter, req *http.Request, _ Caller, _ []byte) {
		writeDenied(w, r.DenyRequest(req.PathValue("id")))
	})
	act("POST /m/api/actions/sessions", func(w http.ResponseWriter, req *http.Request, c Caller, b []byte) {
		r.proposeSession(w, c, "actions-"+c.Session, b, signedRequestOf(req, req.Header.Get("X-Machine"), b))
	})
	act("POST /m/api/actions/requests/batch", func(w http.ResponseWriter, req *http.Request, c Caller, b []byte) {
		r.serveFileBatch(w, c, req.Method, path(req), b, signedRequestOf(req, req.Header.Get("X-Machine"), b))
	})
	act("POST /m/api/actions/requests/batches/{id}/deny", func(w http.ResponseWriter, req *http.Request, _ Caller, _ []byte) {
		r.serveDenyBatch(w, req.PathValue("id"))
	})
	for intent := range intents {
		act("POST /m/api/actions/requests/"+intent, func(w http.ResponseWriter, req *http.Request, c Caller, b []byte) {
			r.fileIntent(w, req.Method, path(req), intent, c, b, signedRequestOf(req, req.Header.Get("X-Machine"), b))
		})
	}
	// any app API call (apicalls.go): filed for Deyao's approval; its result read back by the same session
	act("POST /m/api/actions/requests/call", func(w http.ResponseWriter, req *http.Request, c Caller, b []byte) {
		r.fileCall(w, c, path(req), b, signedRequestOf(req, req.Header.Get("X-Machine"), b))
	})
	act("GET /m/api/actions/requests/call/{id}", func(w http.ResponseWriter, req *http.Request, c Caller, _ []byte) {
		r.serveCallResult(w, c, req.PathValue("id"))
	})
}
