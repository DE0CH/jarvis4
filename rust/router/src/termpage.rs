//! The terminal as a web page (GET /term/{id}): the native iPhone app shows it in a WKWebView (Deyao, 2026-10-11:
//! "just open a web page"), so the app carries no terminal code and WebKit's own process draws it. The page polls the
//! same API the app used: GET api/sessions/{id}/terminal is the pane the machine uploads (no grant, nothing run in the
//! machine); POST (typing, resizing) runs in the machine only under a terminal grant. One self-contained file (inline
//! CSS/JS): nothing is loaded from anywhere else.

use crate::http::Registrar;
use std::sync::LazyLock;

pub const TERMINAL_PAGE: &str = include_str!("../web/terminal.html");

/// a session id as the router makes them; anything else is not a page
static TERM_ID_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9-]{1,80}$").unwrap_or_else(|_| unreachable!()));

pub fn register_term_page(reg: &mut Registrar) {
    reg.app("GET /term/{id}", |_, w, req| {
        let id = req.path_value("id");
        if !TERM_ID_RE.is_match(&id) {
            return crate::nethttp::not_found(w);
        }
        w.set_header("Content-Type", "text/html; charset=utf-8");
        w.set_header("Cache-Control", "no-store");
        w.set_header("X-Frame-Options", "DENY");
        w.set_header("X-Content-Type-Options", "nosniff");
        w.set_header("Referrer-Policy", "no-referrer");
        w.set_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        );
        // the id is checked above ([A-Za-z0-9-] only), so it is safe inside the page's JSON string
        w.write(TERMINAL_PAGE.replacen("__SESSION_ID__", &id, 1).as_bytes());
    });
}
