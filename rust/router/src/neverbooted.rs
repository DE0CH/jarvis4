//! A machine that never boots fails its session (2026-11-17: the WeChat warm-up session's cron resume started a
//! machine whose restore broke off ("REFUSING TO START: snapshot: … stream error … CANCEL"); the session ran an image
//! from before /m/boot-failed, so nothing told the router, the resume's wait was cut off by a router restart, and the
//! session showed "initialising" with no error for hours while its later crons did nothing).
//!
//!   - A supervisor-log line "REFUSING TO START: <why>" from the session's current machine, before its first status
//!     report, fails the session as POST /m/boot-failed does (bootfailed.rs): the keeper has written that line since
//!     long before the report existed, so a session on an older image fails with the reason too.
//!   - The leader looks every NEVER_BOOTED_EVERY at sessions initialising on a machine that has not booted, waits on no
//!     locked store and runs no action of Jarvis's: one whose machine has logged nothing for LC_BOOT_MAX (counted from
//!     the leader first seeing it, when the machine has logged nothing at all) fails with that said. A slow restore
//!     logs its progress every 10 s, so only a machine that went silent is failed. Resume then kills the machine with
//!     no snapshot and the next one restores the line's last snapshot, as after any refused boot.

use crate::flows::wait_text;
use crate::lifecycle::LC_BOOT_MAX;
use crate::router::Router;
use jarvis_go::GoTime;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

pub const NEVER_BOOTED_EVERY: Duration = Duration::from_secs(30);

const REFUSING_TO_START: &str = "REFUSING TO START: ";

/// the reason in a supervisor-log line that says the machine refuses to start, "" for any other line
pub fn refused_in_log(text: &str) -> String {
    match text.find(REFUSING_TO_START) {
        None => String::new(),
        Some(i) => text[i + REFUSING_TO_START.len()..].trim().to_string(),
    }
}

impl Router {
    pub fn never_booted_loop(self: &Arc<Self>) {
        let mut first = BTreeMap::new();
        loop {
            crate::leaderlease::await_lead();
            self.never_booted_tick(GoTime::now(), &mut first);
            std::thread::sleep(NEVER_BOOTED_EVERY);
        }
    }

    /// one look. first: machine → when the leader first saw it initialising and not booted (kept between looks; a
    /// machine no longer a candidate is forgotten)
    pub fn never_booted_tick(self: &Arc<Self>, now: GoTime, first: &mut BTreeMap<String, GoTime>) {
        let cands: Vec<(String, String)> = self.st.do_(|d| {
            d.sessions
                .values()
                .filter(|s| s.state == "initialising" && !s.machine_id.is_empty() && s.booted != s.machine_id && s.locked_store.is_empty())
                .map(|s| (s.id.clone(), s.machine_id.clone()))
                .collect()
        });
        let mut keep = BTreeSet::new();
        for (sid, machine) in cands {
            keep.insert(machine.clone());
            if self.busy(&sid) {
                first.remove(&machine); // an action of Jarvis's runs: its own wait counts, the count starts after it
                continue;
            }
            let mut since = *first.entry(machine.clone()).or_insert(now);
            for l in self.read_sup_log(&sid) {
                if l.machine != machine {
                    continue;
                }
                if let Some(at) = GoTime::parse(&l.at)
                    && at.after(&since)
                {
                    since = at;
                }
            }
            if now.sub(&since) < LC_BOOT_MAX {
                continue;
            }
            self.boot_failed(&machine, &format!("it never booted and has logged nothing for {}", wait_text(LC_BOOT_MAX)));
            first.remove(&machine);
        }
        first.retain(|m, _| keep.contains(m));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn refused_in_log_takes_the_reason() {
        assert_eq!(super::refused_in_log("x REFUSING TO START: snapshot: broke "), "snapshot: broke");
        assert_eq!(super::refused_in_log("booting"), "");
    }
}
