package main

// Runners belong to a session (Deyao, 2026-11-17: "runners need to be owned by a session, just like fly sandboxes so
// I can see orphaned or leaking runner machines"). A runner is a throwaway Hetzner Cloud server in the project
// "runners" that a session uses for heavy work. The router holds that project's only token (HETZNER_RUNNERS_TOKEN,
// router-secrets part `runners`); a session asks the router for a runner through its machine's proxy and never holds
// a Hetzner token, so no server is made without an owner.
//
// The owner is the server's label `session=<session id>`, set by the router at create and never by the caller. The
// router keeps no list of its own: Hetzner's is the only one, so a server the router didn't make shows too.
//
//   - Destroy deletes the session's runners.
//   - A pause deletes them, unless a wakeup, cron or watch is armed: that session will run again and finds them
//     ("Delete on idle pause. Kept when theres scheduled wakeup"). A restart, an Upgrade or a move to a bigger
//     machine is no pause: the runners stay.
//   - The Machines view (GET /api/runners) lists every server of the project with its session, or why it stands out:
//     no session label, a session that is gone, a paused session nothing will wake. Delete is offered only for those.
//
// The session's SSH key is a Hetzner key object `runner-<session id>` (a server made with no key gets a root
// password e-mailed to the account); it goes with the session's last runner.

import (
	"bytes"
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
	"time"
)

const (
	runnersProject    = "runners"
	runnerPurpose     = "runner"
	maxSessionRunners = 10
	runnerUserDataMax = 32 << 10 // Hetzner's limit
)

// hetznerAPI: the Cloud API (a test's fake)
var hetznerAPI = "https://api.hetzner.cloud/v1"

var hetznerClient = &http.Client{Timeout: 40 * time.Second}

var (
	runnerNameRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	runnerWordRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
	runnerLabelRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$`)
	// what a session may do to its runner besides deleting it
	runnerActions = map[string]bool{"poweron": true, "poweroff": true, "shutdown": true, "reboot": true, "reset": true}
)

var errNoRunners = errors.New("runners aren't set up on this router (no HETZNER_RUNNERS_TOKEN)")

type hzPrice struct {
	Location     string `json:"location"`
	PriceMonthly struct {
		Gross string `json:"gross"`
	} `json:"price_monthly"`
}

type hzServer struct {
	ID         int64             `json:"id"`
	Name       string            `json:"name"`
	Status     string            `json:"status"`
	Created    string            `json:"created"`
	Labels     map[string]string `json:"labels"`
	ServerType struct {
		Name   string    `json:"name"`
		Cores  int       `json:"cores"`
		Memory float64   `json:"memory"`
		Prices []hzPrice `json:"prices"`
	} `json:"server_type"`
	Location *struct {
		Name string `json:"name"`
	} `json:"location"`
	Datacenter *struct {
		Location struct {
			Name string `json:"name"`
		} `json:"location"`
	} `json:"datacenter"`
	PublicNet struct {
		IPv6 *struct {
			IP string `json:"ip"`
		} `json:"ipv6"`
	} `json:"public_net"`
}

func (s hzServer) location() string {
	if s.Location != nil && s.Location.Name != "" {
		return s.Location.Name
	}
	if s.Datacenter != nil {
		return s.Datacenter.Location.Name
	}
	return ""
}

// ipv6: the server's address, the first of its /64
func (s hzServer) ipv6() string {
	if s.PublicNet.IPv6 == nil {
		return ""
	}
	ip := s.PublicNet.IPv6.IP
	if i := strings.Index(ip, "/"); i >= 0 {
		ip = ip[:i]
	}
	if strings.HasSuffix(ip, "::") {
		ip += "1"
	}
	return ip
}

// monthly: what the server costs a month where it runs, as Hetzner prices it (gross), "" when it doesn't say
func (s hzServer) monthly() string {
	for _, p := range s.ServerType.Prices {
		if p.Location == s.location() && p.PriceMonthly.Gross != "" {
			var f float64
			if _, err := fmt.Sscanf(p.PriceMonthly.Gross, "%g", &f); err == nil {
				return fmt.Sprintf("EUR %.2f/month", f)
			}
		}
	}
	return ""
}

type hzError struct {
	Status  int
	Code    string
	Message string
}

func (e *hzError) Error() string {
	return fmt.Sprintf("Hetzner: %s (%s, HTTP %d)", e.Message, e.Code, e.Status)
}

// hetzner: one call of the Cloud API with the runners project's token
var hetzner = func(method, path string, in, out any) error {
	tok := os.Getenv("HETZNER_RUNNERS_TOKEN")
	if tok == "" {
		return errNoRunners
	}
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, hetznerAPI+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("User-Agent", "jarvis4-router/1")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hetznerClient.Do(req)
	if err != nil {
		return fmt.Errorf("Hetzner: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		json.Unmarshal(b, &e)
		if e.Error.Message == "" {
			e.Error.Message = "no error text"
		}
		return &hzError{Status: resp.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("Hetzner's answer: %w", err)
		}
	}
	return nil
}

func hzGone(err error) bool {
	var e *hzError
	return errors.As(err, &e) && e.Status == 404
}

// hzServers: every server of the project matching the label selector ("" = all)
func hzServers(selector string) ([]hzServer, error) {
	var all []hzServer
	for page := 1; page <= 20; page++ {
		var out struct {
			Servers []hzServer `json:"servers"`
			Meta    struct {
				Pagination struct {
					NextPage *int `json:"next_page"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		q := url.Values{"per_page": {"50"}, "page": {fmt.Sprint(page)}}
		if selector != "" {
			q.Set("label_selector", selector)
		}
		if err := hetzner("GET", "/servers?"+q.Encode(), nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Servers...)
		if out.Meta.Pagination.NextPage == nil {
			break
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Created < all[j].Created })
	return all, nil
}

func runnersOf(sid string) ([]hzServer, error) { return hzServers("session=" + sid) }

// runnerKeyName: the Hetzner key object of a session's runners
func runnerKeyName(sid string) string { return "runner-" + sid }

type hzKey struct {
	ID        int64  `json:"id"`
	PublicKey string `json:"public_key"`
}

func hzKeyByName(name string) (*hzKey, error) {
	var out struct {
		Keys []hzKey `json:"ssh_keys"`
	}
	if err := hetzner("GET", "/ssh_keys?name="+url.QueryEscape(name), nil, &out); err != nil {
		return nil, err
	}
	if len(out.Keys) == 0 {
		return nil, nil
	}
	return &out.Keys[0], nil
}

// keyBody: an OpenSSH public key without its comment
func keyBody(pub string) string {
	f := strings.Fields(pub)
	if len(f) < 2 {
		return ""
	}
	return f[0] + " " + f[1]
}

// ensureRunnerKey: the session's key object holds this public key (a session on a new machine may have a new one)
func ensureRunnerKey(sid, pub string) (int64, error) {
	name := runnerKeyName(sid)
	k, err := hzKeyByName(name)
	if err != nil {
		return 0, err
	}
	if k != nil && keyBody(k.PublicKey) == keyBody(pub) {
		return k.ID, nil
	}
	if k != nil {
		if err := hetzner("DELETE", fmt.Sprintf("/ssh_keys/%d", k.ID), nil, nil); err != nil && !hzGone(err) {
			return 0, err
		}
	}
	var out struct {
		Key hzKey `json:"ssh_key"`
	}
	in := map[string]any{"name": name, "public_key": keyBody(pub), "labels": map[string]string{"session": sid}}
	if err := hetzner("POST", "/ssh_keys", in, &out); err != nil {
		return 0, err
	}
	return out.Key.ID, nil
}

// NewRunner: what a session asks for
type NewRunner struct {
	Name     string            `json:"name"`
	Type     string            `json:"type"`     // default cx23
	Location string            `json:"location"` // default fsn1
	Image    string            `json:"image"`    // default ubuntu-24.04
	SSHKey   string            `json:"sshKey"`   // the session's public key: root's authorized key
	UserData string            `json:"userData"` // cloud-init user data
	Labels   map[string]string `json:"labels"`   // the caller's own; `session` and `purpose` are the router's
}

type runnerView struct {
	ID        int64             `json:"id"`
	Name      string            `json:"name"`
	Status    string            `json:"status"`
	Type      string            `json:"type"`
	Guest     string            `json:"guest"` // "2 vCPU · 4 GB"
	Location  string            `json:"location"`
	IPv6      string            `json:"ipv6"`
	Created   string            `json:"created"`
	Monthly   string            `json:"monthly"` // "EUR 6.59/month"
	Labels    map[string]string `json:"labels,omitempty"`
	SessionID string            `json:"sessionId"` // the `session` label, "" = none
	// the Machines view only: the owner's state ("" = no such session), why the runner stands out ("" = it doesn't),
	// and whether Delete is offered (only for a runner that stands out for its owner)
	SessionState string `json:"sessionState,omitempty"`
	Attention    string `json:"attention,omitempty"`
	Deletable    bool   `json:"deletable,omitempty"`
}

func runnerViewOf(s hzServer) runnerView {
	v := runnerView{ID: s.ID, Name: s.Name, Status: s.Status, Type: s.ServerType.Name, Location: s.location(), IPv6: s.ipv6(),
		Created: s.Created, Monthly: s.monthly(), SessionID: s.Labels["session"]}
	if s.ServerType.Cores > 0 {
		v.Guest = fmt.Sprintf("%d vCPU · %g GB", s.ServerType.Cores, s.ServerType.Memory)
	}
	for k, val := range s.Labels {
		if k != "session" && k != "purpose" {
			if v.Labels == nil {
				v.Labels = map[string]string{}
			}
			v.Labels[k] = val
		}
	}
	return v
}

// CreateRunner: a server of the calling session
func (r *Router) CreateRunner(sid string, in NewRunner) (*runnerView, error) {
	in.Name = strings.TrimSpace(in.Name)
	if !runnerNameRe.MatchString(in.Name) {
		return nil, fmt.Errorf("a runner's name is a host name: lower-case letters, digits and hyphens, at most 63 characters (got %q)", in.Name)
	}
	for field, v := range map[string]*string{"type": &in.Type, "location": &in.Location, "image": &in.Image} {
		def := map[string]string{"type": "cx23", "location": "fsn1", "image": "ubuntu-24.04"}[field]
		if *v == "" {
			*v = def
		}
		if !runnerWordRe.MatchString(*v) {
			return nil, fmt.Errorf("%s %q is not a Hetzner name", field, *v)
		}
	}
	if keyBody(in.SSHKey) == "" || !strings.HasPrefix(in.SSHKey, "ssh-") && !strings.HasPrefix(in.SSHKey, "ecdsa-") {
		return nil, errors.New("sshKey must be the session's OpenSSH public key (root's authorized key on the runner)")
	}
	if len(in.UserData) > runnerUserDataMax {
		return nil, fmt.Errorf("userData is %d bytes; Hetzner takes at most %d", len(in.UserData), runnerUserDataMax)
	}
	labels := map[string]string{}
	for k, v := range in.Labels {
		if k == "session" || k == "purpose" {
			continue
		}
		if !runnerLabelRe.MatchString(k) || v != "" && !runnerLabelRe.MatchString(v) {
			return nil, fmt.Errorf("label %s=%s: letters, digits, '.', '_' and '-' only, at most 63 characters", k, v)
		}
		labels[k] = v
	}
	labels["session"], labels["purpose"] = sid, runnerPurpose
	have, err := runnersOf(sid)
	if err != nil {
		return nil, err
	}
	if len(have) >= maxSessionRunners {
		return nil, fmt.Errorf("this session has %d runners, the most one session may have: delete one first", len(have))
	}
	key, err := ensureRunnerKey(sid, in.SSHKey)
	if err != nil {
		return nil, fmt.Errorf("the session's SSH key: %w", err)
	}
	body := map[string]any{"name": in.Name, "server_type": in.Type, "image": in.Image, "location": in.Location,
		"labels": labels, "ssh_keys": []int64{key}, "start_after_create": true,
		// IPv6 only: the account is at its limit of primary IPv4 addresses (Deyao, 2026-10-13)
		"public_net": map[string]bool{"enable_ipv4": false, "enable_ipv6": true}}
	if in.UserData != "" {
		body["user_data"] = in.UserData
	}
	var out struct {
		Server hzServer `json:"server"`
	}
	if err := hetzner("POST", "/servers", body, &out); err != nil {
		return nil, err
	}
	log.Printf("runners: session %s made %s (%d, %s in %s)", sid, in.Name, out.Server.ID, in.Type, in.Location)
	r.lcNote(sid, "", fmt.Sprintf("runner %s made (Hetzner %s in %s)", in.Name, in.Type, in.Location))
	v := runnerViewOf(out.Server)
	return &v, nil
}

// ownRunner: the session's runner of that name
func ownRunner(sid, name string) (*hzServer, error) {
	have, err := runnersOf(sid)
	if err != nil {
		return nil, err
	}
	for i := range have {
		if have[i].Name == name {
			return &have[i], nil
		}
	}
	return nil, fmt.Errorf("this session has no runner %q", name)
}

// dropRunnerKey: the session's key object goes once it has no runner left
func dropRunnerKey(sid string) {
	if k, err := hzKeyByName(runnerKeyName(sid)); err == nil && k != nil {
		if err := hetzner("DELETE", fmt.Sprintf("/ssh_keys/%d", k.ID), nil, nil); err != nil && !hzGone(err) {
			log.Printf("runners: session %s's key: %v", sid, err)
		}
	}
}

func deleteServer(id int64) error {
	if err := hetzner("DELETE", fmt.Sprintf("/servers/%d", id), nil, nil); err != nil && !hzGone(err) {
		return err
	}
	return nil
}

// DeleteRunner: one runner of the calling session
func (r *Router) DeleteRunner(sid, name string) error {
	s, err := ownRunner(sid, name)
	if err != nil {
		return err
	}
	if err := deleteServer(s.ID); err != nil {
		return err
	}
	log.Printf("runners: session %s deleted %s (%d)", sid, name, s.ID)
	if left, err := runnersOf(sid); err == nil && len(left) == 0 {
		dropRunnerKey(sid)
	}
	return nil
}

// deleteSessionRunners: every runner of the session and its key; what was deleted, and the first failure
func deleteSessionRunners(sid string) ([]string, error) {
	have, err := runnersOf(sid)
	if err != nil {
		return nil, err
	}
	var gone []string
	var first error
	for _, s := range have {
		if err := deleteServer(s.ID); err != nil {
			if first == nil {
				first = fmt.Errorf("%s: %w", s.Name, err)
			}
			continue
		}
		gone = append(gone, s.Name)
	}
	if first == nil {
		dropRunnerKey(sid)
	}
	return gone, first
}

// endRunners: a session's runners go with it (a destroy, a pause nothing will wake). It never fails the action: a
// runner Hetzner didn't delete stays on the Machines view, standing out.
func (r *Router) endRunners(sid string, op *lcHandle, why string) {
	if os.Getenv("HETZNER_RUNNERS_TOKEN") == "" {
		return
	}
	gone, err := deleteSessionRunners(sid)
	if len(gone) > 0 {
		log.Printf("runners: session %s (%s): deleted %s", sid, why, strings.Join(gone, ", "))
		op.note("", fmt.Sprintf("deleted the session's runners (%s): %s", why, strings.Join(gone, ", ")))
	}
	if err != nil {
		log.Printf("runners: session %s (%s): %v", sid, why, err)
		op.note("", "a runner was not deleted (it shows on the Machines view): "+err.Error())
	}
}

// runnersAfterPause: a paused session keeps its runners only when something armed will run it again
func (r *Router) runnersAfterPause(sid string, op *lcHandle) {
	if os.Getenv("HETZNER_RUNNERS_TOKEN") == "" {
		return
	}
	wakes := false
	r.st.Do(func(d *persisted) { wakes = willWake(d, sid) })
	if !wakes {
		r.endRunners(sid, op, "paused with no wakeup or cron armed")
		return
	}
	if have, err := runnersOf(sid); err == nil && len(have) > 0 {
		op.note("", fmt.Sprintf("kept the session's %d runner(s): a wakeup or cron is armed", len(have)))
	}
}

// runnerAttention: why a runner stands out on the Machines view ("" = it doesn't); callers hold the state lock
func runnerAttention(d *persisted, v *runnerView) {
	if v.SessionID == "" {
		v.Attention, v.Deletable = "No session: made outside Jarvis 4", true
		return
	}
	s := d.Sessions[v.SessionID]
	if s == nil {
		v.Attention, v.Deletable = "Its session is gone", true
		for _, rec := range d.Records {
			if rec.ID == v.SessionID {
				v.Attention = "Its session was destroyed"
				break
			}
		}
		return
	}
	v.SessionState = s.State
	if s.State == "paused" && !willWake(d, s.ID) {
		v.Attention, v.Deletable = "Its session is paused and nothing is armed to wake it", true
	}
}

// RunnersOverview: every server of the project, for the Machines view
func (r *Router) RunnersOverview() (map[string]any, error) {
	all, err := hzServers("")
	if err != nil {
		return nil, err
	}
	views := make([]runnerView, 0, len(all))
	attention := 0
	r.st.Do(func(d *persisted) {
		for _, s := range all {
			v := runnerViewOf(s)
			runnerAttention(d, &v)
			if v.Attention != "" {
				attention++
			}
			views = append(views, v)
		}
	})
	return map[string]any{"project": runnersProject, "runners": views, "attention": attention, "checkedAt": time.Now().UTC()}, nil
}

// runnersForMachines: the runners as a part of GET /api/machines, and how many stand out. nil on a router with no
// runners (a test stack); Hetzner not answering is the part's error, not the view's.
func (r *Router) runnersForMachines() (map[string]any, int) {
	out, err := r.RunnersOverview()
	if errors.Is(err, errNoRunners) {
		return nil, 0
	}
	if err != nil {
		return map[string]any{"project": runnersProject, "runners": []runnerView{}, "attention": 0, "error": err.Error()}, 0
	}
	return out, out["attention"].(int)
}

// DeleteStrayRunner: Deyao's Delete on the Machines view, only for a runner that stands out for its owner (checked
// again here, against Hetzner's list and the sessions as they are now)
func (r *Router) DeleteStrayRunner(id int64) error {
	all, err := hzServers("")
	if err != nil {
		return err
	}
	for _, s := range all {
		if s.ID != id {
			continue
		}
		v := runnerViewOf(s)
		r.st.Do(func(d *persisted) { runnerAttention(d, &v) })
		if !v.Deletable {
			return fmt.Errorf("runner %s belongs to session %s (%s): it goes with its session", s.Name, v.SessionID, v.SessionState)
		}
		if err := deleteServer(id); err != nil {
			return err
		}
		log.Printf("runners: %s (%d) deleted from the Machines view (%s)", s.Name, id, v.Attention)
		if v.SessionID != "" {
			if left, err := runnersOf(v.SessionID); err == nil && len(left) == 0 {
				dropRunnerKey(v.SessionID)
			}
		}
		return nil
	}
	return fmt.Errorf("no runner %d in project %s", id, runnersProject)
}

func runnerErr(w http.ResponseWriter, err error) {
	status := 400
	var he *hzError
	switch {
	case errors.Is(err, errNoRunners):
		status = 503
	case errors.As(err, &he):
		status = 502
		if he.Status == 409 || he.Code == "uniqueness_error" {
			status = 409
		}
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (r *Router) registerRunners(app appRoute, m machineRoute) {
	app("GET /api/runners", func(w http.ResponseWriter, req *http.Request) {
		out, err := r.RunnersOverview()
		if err != nil {
			runnerErr(w, err)
			return
		}
		writeJSON(w, 200, out)
	})
	app("POST /api/runners/{id}/delete", func(w http.ResponseWriter, req *http.Request) {
		var id int64
		if _, err := fmt.Sscanf(req.PathValue("id"), "%d", &id); err != nil {
			writeJSON(w, 400, map[string]string{"error": "a runner's id is a number"})
			return
		}
		if err := r.DeleteStrayRunner(id); err != nil {
			runnerErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "id": id})
	})

	// the session itself, through its machine's proxy: its own runners only
	own := func(pattern string, fn func(w http.ResponseWriter, req *http.Request, sid string, body []byte)) {
		m(pattern, func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
			sid, err := r.machineSession(machine)
			if err != nil {
				writeJSON(w, 403, map[string]string{"error": err.Error()})
				return
			}
			if id := req.PathValue("id"); id != sid {
				writeJSON(w, 403, map[string]string{"error": fmt.Sprintf("this machine is session %s, not %s: a session's runners are its own", sid, id)})
				return
			}
			fn(w, req, sid, body)
		})
	}
	own("GET /m/api/sessions/{id}/runners", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		have, err := runnersOf(sid)
		if err != nil {
			runnerErr(w, err)
			return
		}
		views := make([]runnerView, 0, len(have))
		for _, s := range have {
			views = append(views, runnerViewOf(s))
		}
		writeJSON(w, 200, map[string]any{"runners": views})
	})
	own("POST /m/api/sessions/{id}/runners", func(w http.ResponseWriter, req *http.Request, sid string, b []byte) {
		var in NewRunner
		if err := json.Unmarshal(b, &in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "the body must be JSON: {name, type, location, image, sshKey, userData, labels}"})
			return
		}
		v, err := r.CreateRunner(sid, in)
		if err != nil {
			runnerErr(w, err)
			return
		}
		writeJSON(w, 200, v)
	})
	own("DELETE /m/api/sessions/{id}/runners/{name}", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		if err := r.DeleteRunner(sid, req.PathValue("name")); err != nil {
			runnerErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	own("POST /m/api/sessions/{id}/runners/{name}/{action}", func(w http.ResponseWriter, req *http.Request, sid string, _ []byte) {
		action := req.PathValue("action")
		if !runnerActions[action] {
			writeJSON(w, 400, map[string]string{"error": "a runner's actions are poweron, poweroff, shutdown, reboot and reset"})
			return
		}
		s, err := ownRunner(sid, req.PathValue("name"))
		if err != nil {
			runnerErr(w, err)
			return
		}
		if err := hetzner("POST", fmt.Sprintf("/servers/%d/actions/%s", s.ID, action), map[string]any{}, nil); err != nil {
			runnerErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})
}
