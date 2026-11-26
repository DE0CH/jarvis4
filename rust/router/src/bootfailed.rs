//! A machine that refuses to start says so (2026-11-16: a machine whose restore ran out of disk logged "REFUSING TO
//! START: …" and its session showed "initialising" with no error for good).
//!
//!   POST /m/boot-failed   {error}: the machine's boot steps ended without a harness (rust/machine/src/boot.rs
//!                         prepare_cmd). Its session becomes failed with the reason; the machine is kept. Only from the
//!                         session's current machine, before its first status report, while the session is
//!                         initialising or started; else nothing changes.

use crate::http::Registrar;
use crate::router::Router;
use jarvis_nethttp::write_json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

/// the failed session's error
pub fn boot_failed_text(machine: &str, reason: &str) -> String {
    let mut reason = jarvis_go::fmt::fields_join(reason);
    if reason.chars().count() > 500 {
        reason = format!("{}…", reason.chars().take(500).collect::<String>());
    }
    if reason.is_empty() {
        reason = "no reason given".into();
    }
    format!(
        "machine {machine} refused to start: {reason}. Its machine is kept; Resume starts the session again on a new machine."
    )
}

impl Router {
    /// fail the machine's session with its reason and DM once → whether it did
    pub fn boot_failed(self: &Arc<Self>, machine: &str, reason: &str) -> bool {
        let text = boot_failed_text(machine, reason);
        let found = self.st.do_(|d| {
            let sid = d.machines.get(machine).cloned()?;
            let s = d.sessions.get_mut(&sid)?;
            if s.machine_id != machine
                || s.booted == machine
                || !(s.state == "initialising" || s.state == "started")
            {
                return None;
            }
            s.state = "failed".into();
            s.error = text.clone();
            Some((s.id.clone(), crate::autopilot::session_name(s, None)))
        });
        let Some((sid, name)) = found else {
            return false;
        };
        crate::logf!("session {sid}: failed: {text}");
        self.dm(&format!("🔴 Session “{name}” didn't come up: {text}"));
        true
    }
}

pub fn register_boot_failed(reg: &mut Registrar) {
    reg.m("POST /m/boot-failed", |r, w, _, machine, body| {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            #[serde(alias = "Error")]
            error: String,
        }
        let i: In = jarvis_go::unmarshal(body).unwrap_or_default();
        write_json(w, 200, &json!({"ok": r.boot_failed(machine, &i.error)}));
    });
}
