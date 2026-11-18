//! A machine boots by pulling its secrets from the core; while one of its stores is locked the core answers 423 "store
//! X is locked" and the machine retries every few seconds. Nothing waits silently: the session carries the store it
//! waits on (locked_store) until a pull goes through, and the app shows it with the phone's unlock page one tap away.
//! The next retry after the unlock carries on.

use crate::core::CoreError;
use crate::router::Router;
use std::sync::{Arc, LazyLock};

static LOCKED_STORE_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"store (\S+) is locked").unwrap_or_else(|_| unreachable!()));

/// the store a pull's error says is locked ("?" when it doesn't say which), "" for any other error or none
pub fn locked_store_of(err: Option<&anyhow::Error>) -> String {
    match err.and_then(|e| e.downcast_ref::<CoreError>()) {
        Some(ce) if ce.status == 423 => LOCKED_STORE_RE
            .captures(&ce.msg)
            .map_or("?".to_string(), |m| m[1].to_string()),
        _ => String::new(),
    }
}

impl Router {
    pub fn note_secrets_pull(self: &Arc<Self>, machine: &str, err: Option<&anyhow::Error>) {
        let locked = locked_store_of(err);
        if err.is_some() && locked.is_empty() {
            return; // another failure: leave what is known
        }
        let ask = self.st.do_(|d| {
            let sid = d.machines.get(machine).cloned()?;
            let s = d.sessions.get_mut(&sid).filter(|s| s.machine_id == machine)?;
            let ask = (!locked.is_empty() && s.locked_store.is_empty() && s.carry_lost).then(|| s.id.clone());
            if err.is_none() {
                s.carry_lost = false; // its secrets came: from now on they are carried as usual
            }
            s.locked_store = locked.clone();
            ask
        });
        if let Some(ask) = ask {
            // legacy.rs: a line taken over from an earlier core waits once for its stores
            self.file_refresh(
                &[ask],
                "This session moved to the new core at its pause; the secrets it carried were sealed by the core before, which is gone. Unlock gives it its stores once; it carries them again from then on.",
            );
        }
    }
}
