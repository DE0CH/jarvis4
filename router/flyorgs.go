package main

// Every Fly org on the Machines view (Deyao, 2026-10-11: "both list all machines so I can see a leak clearly"):
// besides jarvis4-sessions (machines.go: sessions, Destroy), every app in every org Deyao has, read-only, grouped
// org → app, each machine and volume with why it stands out (a possible leak), if it does.
//
// Where each org comes from: Fly directly, with that org's READ-ONLY token. They can change nothing.
//   - an org in FLY_ORG_READ_TOKENS ({"<org slug>": "<token>"}, router-secrets part `flyorgs`): jarvis2-370 and kamyee
//     (`fly tokens create readonly`);
//   - org personal: FLY_PERSONAL_READ_TOKEN (part `flypersonal`, infra/fly-personal-read-token.sh): the personal org
//     token attenuated to read on that org (caveat Organization mask "r"). It reads every machine's config in the org,
//     env included, and Jarvis 1's session machines carry their stores in their Fly env: the trade-off is DECISIONS 138.
// Only the fields below leave this file: env never does.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// this router's own org (the one jarvis4-sessions lives in)
const ownFlyOrg = "jarvis2-370"

// the apps a Jarvis runs sessions in; a machine anywhere else is unexplained
var knownFlyApps = map[string]string{
	"de0ch-claude-sessions":   "Jarvis 1 sessions",
	"jarvis4-sessions":        "Jarvis 4 sessions",
	"kamyee-jarvis3-sessions": "KAMYEE's Jarvis 3 sessions",
}

// the apps Jarvis 4 itself runs that are not session apps: what each is for (the Machines tab's label, with the
// monthly cost of its started machines added); their machines are expected, so not flagged as unexplained
var jarvisOwnApps = map[string]string{
	"jarvis2-log-shipper": "Jarvis 4's log shipper: sends the session machines' logs to Grafana Cloud",
}

// ownAppLabel: what the app is for, plus what its started machines cost a month at budget.go's rates (Fly's price
// list for lhr; a machine in another region is priced the same, which is close enough for a label)
func ownAppLabel(what string, ms []flyMachineDetail) string {
	perHour := 0.0
	for _, m := range ms {
		if m.State == "started" {
			perHour += hourlyMachineCost(m.Config.Guest)
		}
	}
	if perHour == 0 {
		return what
	}
	return fmt.Sprintf("%s · USD %.2f/month", what, perHour*hoursPerMonth)
}

// a machine still created/starting after this is stuck
const stuckAfter = 15 * time.Minute

type flyVolumeView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	State      string `json:"state"`
	Region     string `json:"region"`
	SizeGB     int    `json:"sizeGb"`
	AttachedTo string `json:"attachedTo"`
	Created    string `json:"created"`
	Attention  string `json:"attention"`
}

type flyAppView struct {
	App      string          `json:"app"`
	Label    string          `json:"label"` // "Jarvis 4 sessions", or "" for an app no Jarvis uses
	Own      bool            `json:"own"`   // jarvis4-sessions: sessions and Destroy
	Status   string          `json:"status"`
	Machines []machineView   `json:"machines"`
	Volumes  []flyVolumeView `json:"volumes"`
	Error    string          `json:"error"`
}

type flyOrgView struct {
	Org       string       `json:"org"`
	Via       string       `json:"via"` // "fly": read directly with a read-only token
	Error     string       `json:"error"`
	CheckedAt string       `json:"checkedAt"`
	Apps      []flyAppView `json:"apps"`
}

// attentionOf: why a machine stands out, or "". Both Jarvises destroy a machine on pause, so a stopped one is
// left over: it keeps its disk (billed) and counts toward the org's machine cap.
func attentionOf(state, created string, own bool, sessionID, app string, now time.Time) string {
	switch state {
	case "stopped", "suspended":
		return "Stopped: keeps its disk (billed) and counts toward Fly's machine cap"
	case "failed":
		return "Failed"
	case "created", "starting", "replacing":
		if t, err := time.Parse(time.RFC3339, created); err == nil && now.Sub(t) > stuckAfter {
			return fmt.Sprintf("Stuck in %q", state)
		}
	}
	if own && sessionID == "" {
		return "No session"
	}
	if !own && app != "" && knownFlyApps[app] == "" && jarvisOwnApps[app] == "" {
		return "In an app no Jarvis runs sessions in"
	}
	return ""
}

func volumeViewOf(v flyVolume) flyVolumeView {
	out := flyVolumeView{ID: v.ID, Name: v.Name, State: v.State, Region: v.Region, SizeGB: v.SizeGB, AttachedTo: v.AttachedMachineID, Created: v.CreatedAt}
	if v.AttachedMachineID == "" {
		out.Attention = "Not attached to a machine: billed for nothing"
	}
	return out
}

// otherMachineView: a machine of another app, read-only (no session, no Destroy); env never copied
func otherMachineView(m flyMachineDetail, app string, now time.Time) machineView {
	v := machineView{ID: m.ID, Name: m.Name, State: m.State, Region: m.Region, Created: m.CreatedAt, Updated: m.UpdatedAt,
		Image: m.Config.Image, NoDestroy: "it is not in " + sessionsApp + ": read-only here"}
	if v.Image == "" && m.ImageRef.Repository != "" {
		v.Image = m.ImageRef.Registry + "/" + m.ImageRef.Repository + ":" + m.ImageRef.Tag
	}
	if g := m.Config.Guest; g != nil {
		v.Guest = guestText(g)
	}
	v.Attention = attentionOf(m.State, m.CreatedAt, false, "", app, now)
	return v
}

// flyOrgTokens: FLY_ORG_READ_TOKENS parsed; an unreadable value is an error shown on the page
func flyOrgTokens() (map[string]string, error) {
	raw := os.Getenv("FLY_ORG_READ_TOKENS")
	if raw == "" {
		raw = "{}"
	}
	m := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		m = map[string]string{}
		err = fmt.Errorf("FLY_ORG_READ_TOKENS is not valid JSON")
		if t := os.Getenv("FLY_PERSONAL_READ_TOKEN"); t != "" {
			m["personal"] = t
		}
		return m, err
	}
	if t := os.Getenv("FLY_PERSONAL_READ_TOKEN"); t != "" {
		m["personal"] = t
	}
	return m, nil
}

var flyOrgHTTP = &http.Client{Timeout: 30 * time.Second}

// flyAPIBase: the Machines API (tests point it at a fake)
var flyAPIBase = "https://api.machines.dev"

func flyGet(token, path string, out any) error {
	req, _ := http.NewRequest("GET", flyAPIBase+path, nil)
	if !strings.HasPrefix(token, "FlyV1 ") && !strings.HasPrefix(token, "Bearer ") {
		token = "Bearer " + token
	}
	req.Header.Set("Authorization", token)
	resp, err := flyOrgHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("Fly GET %s: HTTP %d %s", strings.SplitN(path, "?", 2)[0], resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// scanFlyOrg: one org read directly. ownApp (jarvis4-sessions, in the router's own org) is filled by the caller
// with machinesView's session-aware list.
func scanFlyOrg(org, token string, own func() ([]machineView, error), now time.Time) flyOrgView {
	o := flyOrgView{Org: org, Via: "fly", CheckedAt: now.UTC().Format(time.RFC3339), Apps: []flyAppView{}}
	var apps struct {
		Apps []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"apps"`
	}
	if err := flyGet(token, "/v1/apps?org_slug="+url.QueryEscape(org), &apps); err != nil {
		o.Error = err.Error()
		return o
	}
	out := make([]flyAppView, len(apps.Apps))
	var wg sync.WaitGroup
	for i, a := range apps.Apps {
		wg.Add(1)
		go func(i int, name, status string) {
			defer wg.Done()
			av := flyAppView{App: name, Label: knownFlyApps[name], Status: status, Machines: []machineView{}, Volumes: []flyVolumeView{}}
			if own != nil && org == ownFlyOrg && name == sessionsApp {
				av.Own = true
				ms, err := own()
				if err != nil {
					av.Error = err.Error()
				} else {
					av.Machines = ms
				}
			} else {
				var ms []flyMachineDetail
				if err := flyGet(token, "/v1/apps/"+url.PathEscape(name)+"/machines", &ms); err != nil {
					av.Error = err.Error()
				}
				for _, m := range ms {
					if m.State != "destroyed" {
						av.Machines = append(av.Machines, otherMachineView(m, name, now))
					}
				}
				if what := jarvisOwnApps[name]; what != "" {
					av.Label = ownAppLabel(what, ms)
				}
				sortMachineViews(av.Machines)
			}
			var vs []flyVolume
			if err := flyGet(token, "/v1/apps/"+url.PathEscape(name)+"/volumes", &vs); err != nil && av.Error == "" {
				av.Error = err.Error()
			}
			for _, v := range vs {
				if !volumeGone(v.State) { // deleted ones (pending_destroy) are not billed: not leaks
					av.Volumes = append(av.Volumes, volumeViewOf(v))
				}
			}
			out[i] = av
		}(i, a.Name, a.Status)
	}
	wg.Wait()
	sortApps(out)
	o.Apps = out
	return o
}

func sortMachineViews(ms []machineView) {
	sort.SliceStable(ms, func(i, j int) bool {
		if ms[i].Created != ms[j].Created {
			return ms[i].Created > ms[j].Created
		}
		return ms[i].ID < ms[j].ID
	})
}

func sortApps(as []flyAppView) {
	sort.SliceStable(as, func(i, j int) bool {
		if as[i].Own != as[j].Own {
			return as[i].Own
		}
		return as[i].App < as[j].App
	})
}

// flyOrgsOverview: every org, the router's own first, then the read-only ones by name (personal among them), and
// personal with an error when the router has no token for it
// ownMs: jarvis4-sessions as the caller just listed it (FLY_READ_TOKEN)
func (r *Router) flyOrgsOverview(ownMs []flyMachineDetail, now time.Time) (orgs []flyOrgView, configErr string) {
	toks, err := flyOrgTokens()
	if err != nil {
		configErr = err.Error()
	}
	own := func() ([]machineView, error) { return r.machinesView(ownMs, now), nil }
	names := []string{}
	for org := range toks {
		if org != ownFlyOrg {
			names = append(names, org)
		}
	}
	sort.Strings(names)
	results := make([]flyOrgView, len(names)+1)
	var wg sync.WaitGroup
	wg.Add(len(names) + 1)
	go func() {
		defer wg.Done()
		if t := toks[ownFlyOrg]; t != "" {
			results[0] = scanFlyOrg(ownFlyOrg, t, own, now)
			return
		}
		// no org token: the sessions app alone, with the app-scoped FLY_READ_TOKEN
		av := flyAppView{App: sessionsApp, Label: knownFlyApps[sessionsApp], Own: true, Machines: []machineView{}, Volumes: []flyVolumeView{}}
		if ms, err := own(); err != nil {
			av.Error = err.Error()
		} else {
			av.Machines = ms
		}
		results[0] = flyOrgView{Org: ownFlyOrg, Via: "fly", CheckedAt: now.UTC().Format(time.RFC3339), Apps: []flyAppView{av},
			Error: "no read-only token for the org in FLY_ORG_READ_TOKENS: only " + sessionsApp + " is listed"}
	}()
	for i, org := range names {
		go func(i int, org string) { defer wg.Done(); results[i+1] = scanFlyOrg(org, toks[org], nil, now) }(i, org)
	}
	wg.Wait()
	orgs = results
	if toks["personal"] == "" {
		orgs = append(orgs, flyOrgView{Org: "personal", Via: "fly", CheckedAt: now.UTC().Format(time.RFC3339), Apps: []flyAppView{},
			Error: "no read-only token for org personal (FLY_PERSONAL_READ_TOKEN)"})
	}
	return orgs, configErr
}

// flyAttentionCount: how many machines, volumes, apps and orgs stand out
func flyAttentionCount(orgs []flyOrgView) int {
	n := 0
	for _, o := range orgs {
		if o.Error != "" {
			n++
		}
		for _, a := range o.Apps {
			if a.Error != "" {
				n++
			}
			for _, m := range a.Machines {
				if m.Attention != "" {
					n++
				}
			}
			for _, v := range a.Volumes {
				if v.Attention != "" {
					n++
				}
			}
		}
	}
	return n
}
