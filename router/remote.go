package main

// Remote access to a Paseo (OpenCode, Claude Code) or OpenClaw session (Jarvis 1's remoteInfo,
// /api/sessions/:id/remote and /api/remotes). These harnesses publish their front end through the session's own
// cf-tunnel origin https://<session id>-s.deyaochen.com/ (behind Cloudflare Access, Deyao's login):
//   opencode, paseo-claude  the Paseo daemon's web UI; the daemon also prints a pairing offer for the Paseo app (its
//             relay is end-to-end encrypted, the link IS the secret)
//   openclaw  the OpenClaw gateway: Control UI over HTTPS and the app's WebSocket on the same origin; the gateway
//             token (~/.openclaw/jarvis-remote.json, written by harness-openclaw.sh) is the secret
//   dsh       DeepSeek Harness web (harness-dsh.sh): its web UI on the same origin; Cloudflare Access is its only
//             gate (dsh-front.js hands dsh's launch token to a request Access admitted; nothing for the router to read)
//   cloudcli  the CloudCLI server (harness-cloudcli.sh): its chat web UI and the API + WebSocket the Jarvis 4 Chat app
//             uses, on the same origin; Cloudflare Access is its only gate (no secret of its own, nothing to read)
// The router reads those secrets on demand through a grant for holder "remote" (grants.go): its own key, so
// Deyao can let the router read a session's remote without giving it the terminal. Never in /api/state.
//
// The tunnel agent on the machine needs an Access service token: the store `tunnel` (CF_ACCESS_CLIENT_ID/SECRET =
// the token jarvis2-tunnel, which the cf-tunnel Worker confines to registering agents for Jarvis 4 session ids),
// brought by these harnesses through the policy. The Worker also wants a proof for that one id, which the router
// (JARVIS2_TUNNEL_KEY) hands each machine for its own session id only (GET /m/tunnel-proof → TUNNEL_AGENT_SECRET,
// sent by agent.js as x-agent-secret), so one session can't take over another's tunnel id: proof = hex
// HMAC-SHA256(key, "jarvis2-tunnel:" + id).
//
// GET /api/remotes also admits Deyao's paired OpenClaw, Paseo and Jarvis 4 Chat apps (devices.go).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const remoteHolder = "remote"

var remoteHarnesses = map[string]bool{"opencode": true, "openclaw": true, "paseo-claude": true, "cloudcli": true, "dsh": true}

// webOriginHarness: the remote is only the session's origin, Cloudflare Access its gate (nothing to read)
//
// A dsh session's link is the persistent dsh web UI (DE0CH/services dsh-web), which reaches that origin itself with its
// own service token and stays up while the machine is paused
func dshWebURL(id string) string { return "https://dsh.deyaochen.com/s/" + id + "/" }

func webOriginHarness(h string) bool { return h == "cloudcli" || h == "dsh" }

// the commands the remote holder runs (bash -lc as the session user)
const (
	paseoPairCmd   = `export PATH="$HOME/.local/bin:/usr/local/bin:$PATH" PASEO_HOME="$HOME/.paseo"; paseo daemon pair --json`
	openclawRemote = `cat "$HOME/.openclaw/jarvis-remote.json"`
)

type RemoteInfo struct {
	WebURL  string `json:"webUrl"`
	Harness string `json:"harness"`
	PairURL string `json:"pairUrl,omitempty"` // a Paseo harness
	Relay   bool   `json:"relay,omitempty"`   // a Paseo harness
	URL     string `json:"url,omitempty"`     // openclaw: the gateway's WebSocket
	Token   string `json:"token,omitempty"`   // openclaw: the gateway token
	Error   string `json:"error,omitempty"`
	// NeedsGrant: the machine refused the remote holder; a phone grant or standing rule for "remote" opens it
	NeedsGrant string `json:"needsGrant,omitempty"`
}

func tunnelHost(id string) string { return id + env("SESSION_TUNNEL_SUFFIX", "-s.deyaochen.com") }

// a paseo offer costs a ~200 MB node run on the machine: one per machine per minute
var remoteCache = struct {
	sync.Mutex
	m map[string]remoteHit
}{m: map[string]remoteHit{}}

type remoteHit struct {
	at   time.Time
	info RemoteInfo
}

// parseRemote: what the holder's command printed → the remote of that harness
func parseRemote(harness, id, stdout string) RemoteInfo {
	web := "https://" + tunnelHost(id) + "/"
	info := RemoteInfo{WebURL: web, Harness: harness}
	if paseoHarness(harness) {
		var pair struct {
			URL          string `json:"url"`
			RelayEnabled bool   `json:"relayEnabled"`
		}
		if i := strings.Index(stdout, "{"); i < 0 || json.Unmarshal([]byte(stdout[i:]), &pair) != nil || pair.URL == "" {
			info.Error = "the Paseo daemon is not up yet — try again in a moment"
			return info
		}
		info.PairURL, info.Relay = pair.URL, pair.RelayEnabled
		return info
	}
	var rec struct {
		Token string `json:"token"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(stdout)), &rec) != nil || rec.Token == "" {
		info.Error = "the OpenClaw gateway is not up yet — try again in a moment"
		return info
	}
	info.WebURL = web + "#token=" + url.QueryEscape(rec.Token)
	info.URL, info.Token = "wss://"+tunnelHost(id), rec.Token
	return info
}

// RemoteInfo: a started Paseo/OpenClaw session's remote, read through the remote holder (a CloudCLI session's is
// only its origin: nothing to read)
func (r *Router) RemoteInfo(s Session) RemoteInfo {
	if s.Harness == "dsh" {
		return RemoteInfo{WebURL: dshWebURL(s.ID), Harness: s.Harness}
	}
	if webOriginHarness(s.Harness) {
		return RemoteInfo{WebURL: "https://" + tunnelHost(s.ID) + "/", Harness: s.Harness}
	}
	remoteCache.Lock()
	hit, ok := remoteCache.m[s.MachineID]
	remoteCache.Unlock()
	if ok && time.Since(hit.at) < time.Minute {
		return hit.info
	}
	cmd, wait := openclawRemote, 15*time.Second
	if paseoHarness(s.Harness) {
		cmd, wait = paseoPairCmd, 30*time.Second
	}
	res, err := r.Exec(s.ID, remoteHolder, cmd, wait)
	if err != nil {
		info := RemoteInfo{WebURL: "https://" + tunnelHost(s.ID) + "/", Harness: s.Harness, Error: err.Error()}
		if isGrantRefusal(err) {
			info.NeedsGrant = remoteHolder
		}
		return info
	}
	info := parseRemote(s.Harness, s.ID, res.Stdout)
	if info.Error == "" {
		remoteCache.Lock()
		remoteCache.m[s.MachineID] = remoteHit{time.Now(), info}
		remoteCache.Unlock()
	}
	return info
}

func (r *Router) registerRemote(app appRoute, m machineRoute, public publicRoute) {
	app("GET /api/sessions/{id}/remote", func(w http.ResponseWriter, req *http.Request) {
		var s Session
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[req.PathValue("id")]; x != nil {
				s = *x
			}
		})
		switch {
		case s.ID == "":
			writeJSON(w, 404, map[string]string{"error": "no such session"})
			return
		case !remoteHarnesses[s.Harness]:
			writeJSON(w, 400, map[string]string{"error": "only Paseo, OpenClaw and CloudCLI sessions have a remote here — a Claude session is in the Claude app"})
			return
		case s.State != "started" || s.MachineID == "":
			writeJSON(w, 409, map[string]string{"error": "session is " + s.State})
			return
		}
		info := r.RemoteInfo(s)
		w.Header().Set("Cache-Control", "no-store")
		status := 200
		if info.NeedsGrant != "" {
			status = 403
		} else if info.Error != "" {
			status = 503
		}
		writeJSON(w, status, info)
	})
	// GET /api/remotes: devices.go (Deyao, or a paired OpenClaw/Paseo app)
	// the machine's proof for registering its own session's tunnel id (boot: TUNNEL_AGENT_SECRET)
	m("GET /m/tunnel-proof", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		sid, err := r.machineSession(machine)
		if err != nil {
			writeJSON(w, 403, map[string]string{"error": err.Error()})
			return
		}
		p := tunnelProof(os.Getenv("JARVIS2_TUNNEL_KEY"), sid)
		if p == "" {
			writeJSON(w, 404, map[string]string{"error": "the router has no JARVIS2_TUNNEL_KEY"})
			return
		}
		writeJSON(w, 200, map[string]string{"proof": p, "id": sid})
	})
}

func tunnelProof(key, id string) string {
	if key == "" {
		return ""
	}
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte("jarvis2-tunnel:" + id))
	return hex.EncodeToString(h.Sum(nil))
}

// GET /api/remotes?harness=openclaw|opencode|paseo-claude|paseo|cloudcli|dsh → {sessions: [{id, title, state, model,
// harness, + url, token, webUrl (openclaw) | pairUrl (a Paseo harness) | webUrl (cloudcli, dsh) — only on a started session
// whose front end is up, else error}]}. harness=paseo: every session a Paseo daemon fronts (opencode and paseo-claude),
// what the Paseo app lists; harness=cloudcli: what the Jarvis 4 Chat app lists.
func (r *Router) remotes(w http.ResponseWriter, req *http.Request) {
	harness := req.URL.Query().Get("harness")
	if !remoteHarnesses[harness] && harness != "paseo" {
		writeJSON(w, 400, map[string]string{"error": "harness must be openclaw, opencode, paseo-claude, paseo, cloudcli or dsh"})
		return
	}
	match := func(h string) bool { return h == harness || harness == "paseo" && paseoHarness(h) }
	var all []Session
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if match(s.Harness) && s.State != "destroying" && s.State != "approval" {
				all = append(all, *s)
			}
		}
	})
	sort.Slice(all, func(i, j int) bool { return all[i].Created.After(all[j].Created) })
	out := make([]map[string]any, len(all))
	var wg sync.WaitGroup
	for i, s := range all {
		o := map[string]any{"id": s.ID, "title": sessionTitle(s), "state": s.State, "model": s.Model, "harness": s.Harness}
		out[i] = o
		if s.State != "started" || s.MachineID == "" {
			continue
		}
		wg.Add(1)
		go func(s Session, o map[string]any) {
			defer wg.Done()
			info := r.RemoteInfo(s)
			if info.Error != "" {
				o["error"] = info.Error
				if info.NeedsGrant != "" {
					o["needsGrant"] = info.NeedsGrant
				}
				switch harness {
				case "openclaw":
					o["url"], o["token"] = nil, nil
				case "cloudcli", "dsh":
					o["webUrl"] = nil
				default:
					o["pairUrl"] = nil
				}
				return
			}
			switch harness {
			case "openclaw":
				o["url"], o["token"], o["webUrl"] = info.URL, info.Token, info.WebURL
			case "cloudcli", "dsh":
				o["webUrl"] = info.WebURL
			default:
				o["pairUrl"] = info.PairURL
			}
		}(s, o)
	}
	wg.Wait()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"sessions": out})
}
