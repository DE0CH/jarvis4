package main

// Paired devices for Deyao's builds of the OpenClaw and Paseo apps (Jarvis 1's lib/devices.js, PARITY "Device
// pairing"): each app pairs ONCE and then lists the sessions it can drive (GET /api/remotes) and starts a paused one
// (POST /api/sessions/:id/start), with no Access login of its own.
//
//   - Pairing: the app opens GET /api/devices/pair?state=…&name=…&model=…&app=openclaw|paseo in the system sign-in
//     sheet, where Access logs Deyao in (the Jarvis 4 app's own Access app: his email only). The router mints a
//     Cloudflare Access service token for that one device (CF_DEVICE_TOKENS_API: a Cloudflare token that can manage
//     Access service tokens and nothing else) and hands its credentials back through the app's own URL scheme
//     (302 <scheme>://paired?state=…&id=…&clientId=…&clientSecret=…), which only the app that opened the sheet gets.
//     The secret is never stored; the router keeps the device's name, its service token's id and client id.
//   - Use: the Access app "Jarvis 4 devices" (infra/cloudflare.py --devices) covers only /api/remotes and
//     /api/sessions/*/start, and admits Deyao's email or any service token of the account (ACCESS_DEVICES_AUD). The
//     router then admits a service token only when its client id (the JWT's common_name) is a paired device's.
//     The same device token passes the session hosts' Access (<id>-s.deyaochen.com admits any service token), where
//     the apps reach the OpenClaw gateway and the Paseo daemon.
//   - Revoke: DELETE /api/devices/:id deletes the service token at Cloudflare and forgets the device.
//
// The apps' server URL is a constant in each fork (DE0CH/openclaw JarvisConfig.baseURL, DE0CH/paseo app.config.js
// jarvis.url); it must name this host (docs/RUNBOOK.md "Device pairing").

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// deviceSchemes: the apps that pair, each with the URL scheme its pairing answer goes to
var deviceSchemes = map[string]string{"openclaw": "openclaw-de0ch", "paseo": "paseo-de0ch"}

var (
	pairStateRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
	cfAPIBase     = "https://api.cloudflare.com/client/v4"
	cfAccount     = "ee3b4deef856baf11e1a67b242438325"
	pairEvery     = 30 * time.Second // a client stuck in a pairing loop made 28 tokens in a minute (Jarvis 1, 2026-09-28)
	deviceSeenGap = 5 * time.Minute  // lastSeenAt is written at most this often
)

type Device struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Model          string    `json:"model"`
	App            string    `json:"app"`
	CreatedAt      time.Time `json:"createdAt"`
	LastSeenAt     time.Time `json:"lastSeenAt"`
	ServiceTokenID string    `json:"serviceTokenId"`
	ClientID       string    `json:"clientId"` // the service token's client id (not a secret: the JWT's common_name)
}

// deviceView: what the app sees (no token ids)
func deviceView(d *Device) map[string]any {
	return map[string]any{"id": d.ID, "name": d.Name, "model": d.Model, "app": d.App, "createdAt": d.CreatedAt, "lastSeenAt": d.LastSeenAt}
}

func devicesOf(d *persisted) map[string]*Device {
	if d.Devices == nil {
		d.Devices = map[string]*Device{}
	}
	return d.Devices
}

// ---- Cloudflare: Access service tokens -----------------------------------------------------------------------

type cfServiceToken struct {
	ID           string `json:"id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func cfCall(method, path string, body any, out any) error {
	tok := os.Getenv("CF_DEVICE_TOKENS_API")
	if tok == "" {
		return errors.New("the router has no CF_DEVICE_TOKENS_API: it can't mint device tokens")
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, cfAPIBase+"/accounts/"+cfAccount+path, rd)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "jarvis2-router")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var j struct {
		Success bool            `json:"success"`
		Errors  json.RawMessage `json:"errors"`
		Result  json.RawMessage `json:"result"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&j)
	if !j.Success {
		e := string(j.Errors)
		if len(e) > 200 {
			e = e[:200]
		}
		return fmt.Errorf("Cloudflare %s %s: HTTP %d %s", method, path, resp.StatusCode, e)
	}
	if out != nil {
		return json.Unmarshal(j.Result, out)
	}
	return nil
}

var mintDeviceToken = func(name string) (cfServiceToken, error) {
	var t cfServiceToken
	err := cfCall("POST", "/access/service_tokens", map[string]string{"name": name, "duration": "forever"}, &t)
	if err == nil && (t.ID == "" || t.ClientID == "" || t.ClientSecret == "") {
		err = errors.New("Cloudflare answered no service token")
	}
	return t, err
}

var deleteDeviceToken = func(id string) error {
	err := cfCall("DELETE", "/access/service_tokens/"+url.PathEscape(id), nil, nil)
	if err != nil && (strings.Contains(err.Error(), "HTTP 404") || strings.Contains(strings.ToLower(err.Error()), "not found")) {
		return nil // already gone
	}
	return err
}

// ---- pairing ---------------------------------------------------------------------------------------------

var pairMu sync.Mutex

func cleanDeviceText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > n {
		s = string(r[:n])
	}
	return s
}

// PairDevice: a new device of app (openclaw | paseo) → its id and the service token's credentials
func (r *Router) PairDevice(name, model, app string, now time.Time) (*Device, cfServiceToken, error) {
	if deviceSchemes[app] == "" {
		return nil, cfServiceToken{}, bad("unknown app: %s", app)
	}
	pairMu.Lock()
	defer pairMu.Unlock()
	var newest time.Time
	r.st.Do(func(d *persisted) {
		for _, x := range devicesOf(d) {
			if x.CreatedAt.After(newest) {
				newest = x.CreatedAt
			}
		}
	})
	if now.Sub(newest) < pairEvery {
		return nil, cfServiceToken{}, &contentErr{429, "a device was paired less than 30 s ago — try again shortly"}
	}
	name = cleanDeviceText(name, 60)
	if name == "" {
		name = "device"
	}
	tok, err := mintDeviceToken("jarvis2-device " + app + " " + name)
	if err != nil {
		return nil, cfServiceToken{}, err
	}
	b := make([]byte, 8)
	rand.Read(b)
	dev := &Device{ID: hex.EncodeToString(b), Name: name, Model: cleanDeviceText(model, 40), App: app, CreatedAt: now.UTC(), LastSeenAt: now.UTC(),
		ServiceTokenID: tok.ID, ClientID: tok.ClientID}
	r.st.Do(func(d *persisted) { devicesOf(d)[dev.ID] = dev })
	log.Printf("[devices] paired %s (%s, %s)", dev.ID, app, name)
	return dev, tok, nil
}

func (r *Router) RevokeDevice(id string) error {
	var dev *Device
	r.st.Do(func(d *persisted) { dev = devicesOf(d)[id] })
	if dev == nil {
		return nil // already unpaired: what was asked for holds
	}
	if err := deleteDeviceToken(dev.ServiceTokenID); err != nil {
		return err
	}
	r.st.Do(func(d *persisted) { delete(devicesOf(d), id) })
	log.Printf("[devices] revoked %s (%s, %s)", id, dev.App, dev.Name)
	return nil
}

// deviceOfClient: the paired device whose service token has this client id (and notes it was seen)
func (r *Router) deviceOfClient(clientID string, now time.Time) *Device {
	if clientID == "" {
		return nil
	}
	var out *Device
	r.st.Do(func(d *persisted) {
		for _, x := range devicesOf(d) {
			if x.ClientID == clientID {
				if now.Sub(x.LastSeenAt) > deviceSeenGap {
					x.LastSeenAt = now.UTC()
				}
				c := *x
				out = &c
			}
		}
	})
	return out
}

// requireDeyaoOrDevice: Deyao's own Access login, or a paired device's service token; the JWT's audience is the
// Jarvis 4 app or the devices' Access app (ACCESS_DEVICES_AUD)
func (r *Router) requireDeyaoOrDevice(fn http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !r.cfg.NoAccess && !r.deyaoOrDevice(req.Header.Get("Cf-Access-Jwt-Assertion")) {
			writeJSON(w, 403, map[string]string{"error": "Access login required"})
			return
		}
		fn(w, req)
	})
}

func (r *Router) deyaoOrDevice(tok string) bool {
	for _, aud := range []string{r.cfg.AppAUD, os.Getenv("ACCESS_DEVICES_AUD")} {
		if aud == "" {
			continue
		}
		c, err := r.access().verify(tok, aud)
		if err != nil {
			continue
		}
		return r.admitClaims(c, time.Now())
	}
	return false
}

// admitClaims: Deyao's email, or no email and a paired device's client id
func (r *Router) admitClaims(c *accessClaims, now time.Time) bool {
	if c.Email != "" {
		return strings.EqualFold(c.Email, r.cfg.AllowedEmail)
	}
	return r.deviceOfClient(c.CommonName, now) != nil
}

func (r *Router) registerDevices(app appRoute, public publicRoute) {
	// the pairing page: Deyao's own login only (app() admits his email, never a service token)
	app("GET /api/devices/pair", func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		state, appID := q.Get("state"), q.Get("app")
		if !pairStateRE.MatchString(state) {
			writeJSON(w, 400, map[string]string{"error": "missing or malformed state"})
			return
		}
		scheme := deviceSchemes[appID]
		if scheme == "" {
			writeJSON(w, 400, map[string]string{"error": "unknown app: " + appID})
			return
		}
		back := url.Values{"state": {state}}
		dev, tok, err := r.PairDevice(q.Get("name"), q.Get("model"), appID, time.Now())
		if err != nil {
			status := 500
			var ce *contentErr
			var br *badRequest
			if errors.As(err, &ce) {
				status = ce.status
			} else if errors.As(err, &br) {
				status = 400
			}
			back.Set("error", err.Error())
			back.Set("status", fmt.Sprint(status))
		} else {
			back.Set("id", dev.ID)
			back.Set("clientId", tok.ClientID)
			back.Set("clientSecret", tok.ClientSecret)
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, req, scheme+"://paired?"+back.Encode(), http.StatusFound)
	})
	app("GET /api/devices", func(w http.ResponseWriter, req *http.Request) {
		out := []map[string]any{}
		r.st.Do(func(d *persisted) {
			list := []*Device{}
			for _, x := range devicesOf(d) {
				list = append(list, x)
			}
			sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
			for _, x := range list {
				out = append(out, deviceView(x))
			}
		})
		writeJSON(w, 200, map[string]any{"devices": out})
	})
	app("DELETE /api/devices/{id}", func(w http.ResponseWriter, req *http.Request) {
		if err := r.RevokeDevice(req.PathValue("id")); err != nil {
			contentWriteErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	// the apps: their sessions, and Start for a paused one (a resume on the same image: no phone step)
	r.appPatterns["GET /api/remotes"], r.appPatterns["POST /api/sessions/{id}/start"] = true, true // Deyao's too (apicalls.go)
	public("GET /api/remotes", r.requireDeyaoOrDevice(r.remotes))
	public("POST /api/sessions/{id}/start", r.requireDeyaoOrDevice(func(w http.ResponseWriter, req *http.Request) {
		if err := r.resumeWithPrompt(req.PathValue("id"), false, ""); err != nil {
			scheduleErr(w, err)
			return
		}
		writeJSON(w, 202, map[string]bool{"ok": true})
	}))
}
