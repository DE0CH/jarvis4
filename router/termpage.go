package main

// The terminal as a web page (GET /term/{id}): the native iPhone app shows it in a WKWebView (Deyao, 2026-10-11:
// "just open a web page"), so the app carries no terminal code and WebKit's own process draws it. The page polls the
// same API the app used: GET api/sessions/{id}/terminal is the pane the machine uploads (no grant, nothing run in the
// machine); POST (typing, resizing) runs in the machine only under a terminal grant. One self-contained file (inline CSS/JS): nothing is loaded from anywhere else.
import (
	_ "embed"
	"net/http"
	"regexp"
	"strings"
)

//go:embed web/terminal.html
var terminalPage string

// a session id as the router makes them; anything else is not a page
var termIDRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,80}$`)

func (r *Router) registerTermPage(app func(string, http.HandlerFunc)) {
	app("GET /term/{id}", func(w http.ResponseWriter, req *http.Request) {
		id := req.PathValue("id")
		if !termIDRe.MatchString(id) {
			http.NotFound(w, req)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		// the id is checked above ([A-Za-z0-9-] only), so it is safe inside the page's JSON string
		w.Write([]byte(strings.Replace(terminalPage, "__SESSION_ID__", id, 1)))
	})
}
