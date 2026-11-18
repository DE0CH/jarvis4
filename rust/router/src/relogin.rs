//! Each Claude account's pair is the router's own (claudelogin.rs, claudeaccounts.rs); a session takes its account's
//! and keeps in step by itself (rust/machine/src/claudelogin.rs), so the router never writes credentials into a session
//! (Deyao, 2026-10-14: no login repair). A turn that stopped on "Please run /login" only gets "continue" once its pair
//! is in step.

use crate::autopilot::PilotAction;
use crate::router::Router;
use crate::types::Delivery;

impl Router {
    pub fn repair_login(&self, a: &PilotAction) {
        if !a.repair.is_empty() {
            self.deliver_continue(a);
        }
    }

    pub fn deliver_continue(&self, a: &PilotAction) {
        if let Err(e) = self.deliver_canned(
            &a.session,
            Delivery {
                kind: "continue".into(),
                ..Default::default()
            },
            "continue",
        ) {
            crate::logf!(
                "[login] {}: delivering \"continue\" failed: {e:#}",
                a.session
            );
            return;
        }
        crate::logf!(
            "[login] {} ({}): was stuck on \"Please run /login\" — credentials in step, \"continue\" delivered",
            a.session,
            a.name
        );
    }
}

pub fn first_line(s: &str) -> &str {
    jarvis_go::fmt::cut(s, "\n").0
}
