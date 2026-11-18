package main

// Each Claude account's pair is the router's own (claudelogin.go, claudeaccounts.go); a session takes its account's and
// keeps in step by itself (rust/machine/src/claudelogin.rs), so the router never writes credentials into a session (Deyao,
// 2026-10-14: no login repair). A turn that stopped on "Please run /login" only gets "continue" once its pair is in
// step.

import (
	"log"
	"strings"
)

// loginExpiries: each Claude account's stored pair's expiry (claudeaccounts.go), by store; accounts with no pair are left out
func (r *Router) loginExpiries() map[string]int64 {
	out := map[string]int64{}
	for _, h := range r.accounts().all() {
		if cur := h.current(); cur.Credentials != "" {
			out[h.store] = cur.ExpiresAt
		}
	}
	return out
}

func (r *Router) repairLogin(a pilotAction) {
	if a.Repair != "" {
		r.deliverContinue(a)
	}
}

func (r *Router) deliverContinue(a pilotAction) {
	if err := r.DeliverCanned(a.Session, Delivery{Kind: "continue"}, "continue"); err != nil {
		log.Printf("[login] %s: delivering \"continue\" failed: %v", a.Session, err)
		return
	}
	log.Printf("[login] %s (%s): was stuck on \"Please run /login\" — credentials in step, \"continue\" delivered", a.Session, a.Name)
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}
