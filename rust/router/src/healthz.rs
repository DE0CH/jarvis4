//! GET /healthz: an uptime check behind its own Access service token (the Grafana probe that called it is gone,
//! DECISIONS 237). Behind its own path-scoped Access app (jarvis4.deyaochen.com/healthz, ACCESS_HEALTH_AUD) that admits
//! exactly one service token (HEALTH_CLIENT_ID), which the probe holds; no email login. 200 only while this router
//! serves and its core serves (and its database answers, with this router's schema, and takes every record write); 503
//! names what isn't (a core that is empty after a reboot waits for Deyao's Recover). It reads nothing secret and
//! changes nothing. A router with no core (NO_CORE=1, Jarvis 4) answers for the kernel instead: 200 while its last
//! check found the kernel healthy (kernelhealth.rs), 503 with "kernel": [what is wrong].

use crate::db::DBStatus;
use crate::http::Registrar;
use crate::router::Router;
use jarvis_nethttp::{W, write_json};
use serde_json::json;

impl Router {
    /// the database's status, and the record writes' (a write that keeps failing makes it not ok)
    pub fn db_status(&self) -> DBStatus {
        let mut st = match self.st.db() {
            Some(db) => db.status(),
            None => DBStatus {
                error: "no database".into(),
                ..Default::default()
            },
        };
        if let Some((err, since)) = self.st.store_error() {
            st.ok = false;
            st.error = format!(
                "record writes failing since {}: {err}",
                since.utc().rfc3339()
            );
        }
        st
    }

    /// /healthz on a router with no core
    fn kernel_healthz(&self, w: &mut W, db_ok: bool, db_text: &str) {
        let h = self
            .kernel_health_now
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        match h {
            None => write_json(
                w,
                503,
                &json!({"ok": false, "router": "serving", "kernel": ["not checked yet"], "db": db_text}),
            ),
            Some(h) if !h.healthy => write_json(
                w,
                503,
                &json!({"ok": false, "router": "serving", "kernel": h.problems, "db": db_text}),
            ),
            Some(_) if !db_ok => write_json(
                w,
                503,
                &json!({"ok": false, "router": "serving", "kernel": "healthy", "db": db_text}),
            ),
            Some(_) => write_json(
                w,
                200,
                &json!({"ok": true, "router": "serving", "kernel": "healthy", "db": db_text}),
            ),
        }
    }
}

pub fn register_healthz(reg: &mut Registrar) {
    let aud = std::env::var("ACCESS_HEALTH_AUD").unwrap_or_default();
    let client = std::env::var("HEALTH_CLIENT_ID").unwrap_or_default();
    reg.public_fn("GET /healthz", move |r, w, req| {
        if !r.require_client(w, req, &aud, &client) {
            return;
        }
        let db = r.db_status();
        let db_text = if db.ok { "ok".to_string() } else { db.error.clone() };
        if r.cfg.no_core {
            return r.kernel_healthz(w, db.ok, &db_text);
        }
        match crate::nextcore::core_serving(&r.core) {
            Err(_) => write_json(
                w,
                503,
                &json!({"ok": false, "router": "serving", "core": "unreachable", "db": db_text}),
            ),
            Ok((serving, _)) if serving != "serving" => write_json(
                w,
                503,
                &json!({"ok": false, "router": "serving", "core": crate::nextcore::or_empty_core(&serving), "db": db_text}),
            ),
            Ok(_) if !db.ok => write_json(
                w,
                503,
                &json!({"ok": false, "router": "serving", "core": "serving", "db": db_text}),
            ),
            Ok(_) => write_json(w, 200, &json!({"ok": true, "router": "serving", "core": "serving", "db": db_text})),
        }
    });
}
