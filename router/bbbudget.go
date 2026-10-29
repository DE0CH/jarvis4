package main

// The Browserbase spend guard (Jarvis 1's lib/bbbudget.js, moved here so Jarvis 4 doesn't depend on Jarvis 1): DM only
// (Deyao, 2026-10-01: cap USD 10 overage, warn at 80%); nothing is blocked.
//
// Browserbase has no spend limit, and its project usage API doesn't follow the billing cycle, so the router re-prices
// the UTC month from the session list (GET /v1/sessions: startedAt/endedAt/proxyBytes per session) with the line
// items of the real Developer-plan invoices:
//   - browser time: per session, rounded UP to whole minutes (1 min minimum); 6,000 min included, then USD 0.002/min
//   - proxy, line A: per session, rounded to whole MB (1 MB minimum when any proxy was used); 1,000 MB included,
//     then USD 0.012/MB
//   - proxy, line B: every proxy byte at USD 0.00000001 (USD 10/GB, nothing included), on top of line A
// Fetch/Search/Agent API calls don't show in the session list, so the estimate slightly under-counts.
//
// BROWSERBASE_API_KEY (router secrets, part `browserbase`), BROWSERBASE_BUDGET_USD (0/unset = off) and
// BROWSERBASE_BUDGET_WARN_USD (default 80% of the cap) in the router's env. The month's DM flags live in the router's
// state; /api/state carries the figures as `browserbaseBudget`.

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

var bbPrices = struct {
	includedMinutes, perMinuteUSD, includedProxyMB, perProxyMBUSD, perProxyByteUSD float64
}{6000, 0.002, 1000, 0.012, 0.00000001}

const bbTickEvery = 10 * time.Minute

type bbSession struct {
	CreatedAt  string  `json:"createdAt"`
	StartedAt  string  `json:"startedAt"`
	EndedAt    string  `json:"endedAt"`
	UpdatedAt  string  `json:"updatedAt"`
	Status     string  `json:"status"`
	ProxyBytes float64 `json:"proxyBytes"`
}

type bbUsage struct {
	Count      int     `json:"count"`
	Minutes    float64 `json:"minutes"`
	ProxyMB    float64 `json:"proxyMb"`
	ProxyBytes float64 `json:"proxyBytes"`
}

type bbOverage struct {
	Time       float64 `json:"time"`
	ProxyMB    float64 `json:"proxyMb"`
	ProxyBytes float64 `json:"proxyBytes"`
	Total      float64 `json:"total"`
}

// BBBudgetState: the month's DM flags (persisted)
type BBBudgetState struct {
	Month     string    `json:"month"`
	Warned    bool      `json:"warned"`
	Capped    bool      `json:"capped"`
	OverUSD   float64   `json:"overUsd"`
	SampledAt time.Time `json:"sampledAt"`
}

func bbTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

// bbCycleUsage: the sessions created in month (UTC "YYYY-MM"); a running one counts up to now
func bbCycleUsage(sessions []bbSession, month string, now time.Time) bbUsage {
	var u bbUsage
	for _, s := range sessions {
		created, ok := bbTime(s.CreatedAt)
		if !ok || created.UTC().Format("2006-01") != month {
			continue
		}
		u.Count++
		start, ok := bbTime(s.StartedAt)
		if !ok {
			start = created
		}
		endS := s.EndedAt
		if endS == "" && s.Status != "RUNNING" {
			endS = s.UpdatedAt
		}
		end, ok := bbTime(endS)
		if !ok {
			end = now
		}
		u.Minutes += math.Max(1, math.Ceil(end.Sub(start).Minutes()))
		if s.ProxyBytes > 0 {
			u.ProxyBytes += s.ProxyBytes
			u.ProxyMB += math.Max(1, math.Round(s.ProxyBytes/1e6))
		}
	}
	return u
}

func bbOverageOf(u bbUsage) bbOverage {
	o := bbOverage{
		Time:       math.Max(0, u.Minutes-bbPrices.includedMinutes) * bbPrices.perMinuteUSD,
		ProxyMB:    math.Max(0, u.ProxyMB-bbPrices.includedProxyMB) * bbPrices.perProxyMBUSD,
		ProxyBytes: u.ProxyBytes * bbPrices.perProxyByteUSD,
	}
	o.Total = o.Time + o.ProxyMB + o.ProxyBytes
	return o
}

// bbApply: fold one estimate into the month's flags; which DM (if any) to send now
func bbApply(prev *BBBudgetState, now time.Time, overUSD, capUSD, warnUSD float64) (BBBudgetState, bool, bool) {
	month := now.UTC().Format("2006-01")
	s := BBBudgetState{Month: month}
	if prev != nil && prev.Month == month {
		s = *prev
	}
	s.OverUSD, s.SampledAt = overUSD, now.UTC()
	capDM, warnDM := false, false
	switch {
	case capUSD > 0 && overUSD >= capUSD:
		if !s.Capped {
			capDM, s.Capped = true, true
		}
		s.Warned = true // no separate warn DM after (or in the same tick as) the cap
	case warnUSD > 0 && overUSD >= warnUSD && !s.Warned:
		warnDM, s.Warned = true, true
	}
	return s, capDM, warnDM
}

func bbThresholds(getenv func(string) string) (capUSD, warnUSD float64) {
	capUSD, _ = strconv.ParseFloat(getenv("BROWSERBASE_BUDGET_USD"), 64)
	if v, err := strconv.ParseFloat(getenv("BROWSERBASE_BUDGET_WARN_USD"), 64); err == nil && v > 0 {
		warnUSD = v
	} else if capUSD > 0 {
		warnUSD = math.Round(capUSD*0.8*100) / 100
	}
	return
}

var bbAPIBase = "https://api.browserbase.com"

func bbListSessions(key string) ([]bbSession, error) {
	req, _ := http.NewRequest("GET", bbAPIBase+"/v1/sessions", nil)
	req.Header.Set("X-BB-API-Key", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "jarvis2-router")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("browserbase sessions: HTTP %d", resp.StatusCode)
	}
	var out []bbSession
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// bbView: the last tick's figures; like budget.go's view, written to router_docs (bbViewDoc) by the leader that ticks
// and read from there by whichever replica answers /api/state
var bbView struct {
	sync.Mutex
	v map[string]any
}

const bbViewDoc = "browserbase-budget-view.json"

// bbBudgetTick: one sample; the DM texts are Jarvis 1's
func (r *Router) bbBudgetTick(sessions []bbSession, now time.Time, capUSD, warnUSD float64) {
	month := now.UTC().Format("2006-01")
	u := bbCycleUsage(sessions, month, now)
	o := bbOverageOf(u)
	var st BBBudgetState
	var capDM, warnDM bool
	r.st.Do(func(d *persisted) {
		st, capDM, warnDM = bbApply(d.BBBudget, now, o.Total, capUSD, warnUSD)
		d.BBBudget = &st
	})
	bbView.Lock()
	bbView.v = map[string]any{"month": month, "capUsd": capUSD, "warnUsd": warnUSD, "overUsd": o.Total, "parts": o, "usage": u,
		"warned": st.Warned, "capped": st.Capped, "sampledAt": st.SampledAt}
	b, _ := json.Marshal(bbView.v)
	bbView.Unlock()
	if r.st != nil {
		if err := r.st.WriteDoc(bbViewDoc, b); err != nil && r.st.sdb != nil {
			log.Printf("[bb-budget] saving the view: %v", err)
		}
	}
	detail := fmt.Sprintf("%.0f browser min, %.2f GB proxy across %d session(s)", u.Minutes, u.ProxyBytes/1e9, u.Count)
	switch {
	case capDM:
		budgetDM(r, fmt.Sprintf("Browserbase spend cap reached: estimated overage %s above the USD 20 plan fee in %s (cap %s). %s. Nothing is blocked.",
			usd(o.Total), month, usd(capUSD), detail))
	case warnDM:
		budgetDM(r, fmt.Sprintf("Browserbase spend: estimated overage %s of the %s cap in %s. %s.", usd(o.Total), usd(capUSD), month, detail))
	}
}

func (r *Router) bbBudgetLoop() {
	capUSD, warnUSD := bbThresholds(os.Getenv)
	key := os.Getenv("BROWSERBASE_API_KEY")
	if !(capUSD > 0) || key == "" {
		log.Printf("[bb-budget] off (BROWSERBASE_BUDGET_USD %v, key set %v)", capUSD, key != "")
		return
	}
	for {
		awaitLead() // leaderlease.go
		if ss, err := bbListSessions(key); err != nil {
			log.Printf("[bb-budget] %v", err)
		} else {
			r.bbBudgetTick(ss, time.Now(), capUSD, warnUSD)
		}
		time.Sleep(bbTickEvery)
	}
}

func init() {
	stateHooks = append(stateHooks, func(r *Router, out map[string]any) {
		bbView.Lock()
		out["browserbaseBudget"] = bbView.v
		bbView.Unlock()
		if r != nil && r.st != nil {
			var v map[string]any
			if b, ok := r.st.ReadDoc(bbViewDoc); ok && json.Unmarshal(b, &v) == nil {
				out["browserbaseBudget"] = v
			}
		}
	})
}
