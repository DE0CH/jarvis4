//! A session's machine that stopped or went away without Jarvis doing it (2026-10-22: Claude ran `fly machine stop` on
//! Jarvis 2's "YYC news monitor 2" after a sync; Jarvis 2 showed it "started, busy" for a long time, then "failed" with
//! its machine still listed, and nothing said whether its work was lost).
//!
//!   - The leader looks at Fly every LOST_EVERY with its read-only token (FLY_READ_TOKEN), and at AWS with its
//!     read-only key (awsrunner.rs), and asks the fabric hermit about a fabric session's machine (fabricrunner.rs
//!     fabric_machine_state: it is in neither list): a session that Jarvis has running (started or initialising, no
//!     action of Jarvis's under way) whose machine Fly shows stopped, suspended, failed or destroyed, or no longer
//!     lists, on two looks in a row, is marked lost: state failed, Session.lost, and an error saying plainly what
//!     happened (Fly's own stop or exit event, when), what is kept, and what Resume does. The session's event stream
//!     gets it as a "machine lost" operation with Fly's events, and Deyao gets a DM.
//!   - Resume of a lost kernel line goes through the kernel like any start: the spawner kills the machine into the
//!     line's next source, naming the newest signed snapshot (the machine's own if it sent one, else the one its source
//!     named), and a new machine starts from that source, as after a pause. What the session did after that snapshot
//!     is lost. A line with no signed snapshot at all is refused (it would start empty), as snapsafe.rs refuses. The
//!     stopped machine is never started again: its key pair lived in its memory only (DECISIONS 228), so started again
//!     it couldn't prove it is the machine its cert names.

use crate::lifecycle::{FlyEvent, LcHandle};
use crate::router::Router;
use crate::types::Session;
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// what became of a session's machine that stopped without Jarvis doing it
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LostMachine {
    pub machine: String,
    /// when it stopped, by Fly's event (else when the router saw it)
    pub at: GoTime,
    /// when the router noticed
    pub seen: GoTime,
    /// stopped | suspended | failed | destroyed | destroying | gone (Fly lists it no more)
    #[serde(rename = "flyState")]
    pub fly_state: String,
    /// Fly's own event for it (the stop or exit)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fly: String,
    /// what Resume does, in plain words
    pub resume: String,
}

/// how often the leader looks (ms; tests shorten it); a machine is lost once it is down on two looks in a row
pub static LOST_EVERY_MS: AtomicU64 = AtomicU64::new(20_000);

/// a Fly state of a machine that isn't running
pub fn machine_down(state: &str) -> bool {
    matches!(
        state,
        "stopped" | "suspended" | "failed" | "destroyed" | "destroying" | "gone" | "released"
    )
}

/// "2006-01-02 15:04 UTC" (secs: "2006-01-02 15:04:05 UTC")
fn utc_text(t: GoTime, secs: bool) -> String {
    let Some(t) = t.utc().0 else {
        return "0001-01-01 00:00 UTC".into();
    };
    let mut s = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute()
    );
    if secs {
        s = format!("{s}:{:02}", t.second());
    }
    format!("{s} UTC")
}

pub fn lost_what(state: &str) -> &'static str {
    match state {
        "stopped" => "stopped",
        "suspended" => "was suspended",
        "failed" => "failed on Fly",
        "gone" => "is gone from Fly",
        "released" => "was released on the fabric",
        _ => "was destroyed",
    }
}

/// the session's error for a lost machine
pub fn lost_text(l: &LostMachine) -> String {
    let mut msg = format!(
        "Its machine {} {} outside Jarvis at {} (Jarvis didn't pause or destroy it)",
        l.machine,
        lost_what(&l.fly_state),
        utc_text(l.at, true)
    );
    if !l.fly.is_empty() {
        msg = format!("{msg}; {}", l.fly);
    }
    format!("{msg}. {}", l.resume)
}

impl Router {
    pub fn lost_loop(self: &Arc<Self>) {
        if std::env::var("FLY_READ_TOKEN")
            .unwrap_or_default()
            .is_empty()
        {
            crate::logf!(
                "[lost] FLY_READ_TOKEN unset: machines stopped outside Jarvis aren't noticed"
            );
            return;
        }
        let mut seen = BTreeMap::new();
        loop {
            crate::leaderlease::await_lead();
            self.lost_tick(&mut seen);
            std::thread::sleep(Duration::from_millis(LOST_EVERY_MS.load(Ordering::Relaxed)));
        }
    }

    /// one look at Fly. seen: machine → how many looks in a row found it down (kept between looks)
    pub fn lost_tick(self: &Arc<Self>, seen: &mut BTreeMap<String, i64>) {
        let ms = match crate::machines::list_fly_machines() {
            Err(e) => return crate::logf!("[lost] Fly: {e:#}"),
            Ok(ms) => ms,
        };
        let mut state: BTreeMap<String, String> = ms.into_iter().map(|m| (m.id, m.state)).collect();
        match crate::awsrunner::list_aws_machines() {
            // awsrunner.rs: the AWS machines, in the same state words
            Err(e) => return crate::logf!("[lost] AWS: {e:#}"),
            Ok(ins) => state.extend(ins.into_iter().map(|i| (i.id, i.state))),
        }
        let cands: Vec<(String, String, String)> = self.st.do_(|d| {
            d.sessions
                .values()
                .filter(|s| {
                    !s.machine_id.is_empty()
                        && s.lost.is_none()
                        && (s.state == "started" || s.state == "initialising")
                })
                .map(|s| {
                    let fabric = match &s.fabric {
                        Some(f) if self.runner_of(s) == "fabric" => f.conversation.clone(),
                        _ => String::new(),
                    };
                    (s.id.clone(), s.machine_id.clone(), fabric)
                })
                .collect()
        });
        let mut next = BTreeMap::new();
        for (sid, machine, fabric) in cands {
            let st = if !fabric.is_empty() {
                // a fabric machine is in neither Fly's list nor AWS's: hermit says what became of it (no answer, no
                // verdict)
                match crate::fabricrunner::fabric_machine_state(&fabric, &machine) {
                    Err(e) => {
                        crate::logf!("[lost] fabric: {sid}: {e:#}");
                        continue;
                    }
                    Ok(st) => st,
                }
            } else {
                state
                    .get(&machine)
                    .cloned()
                    .unwrap_or_else(|| "gone".into())
            };
            if !machine_down(&st) || self.busy(&sid) {
                continue;
            }
            let n = seen.get(&machine).copied().unwrap_or(0) + 1;
            next.insert(machine.clone(), n);
            if n >= 2 {
                self.mark_lost(&sid, &machine, &st);
            }
        }
        *seen = next;
    }

    /// Fly's newest event that took the machine down (exit, stop, destroy), None when Fly has none
    pub fn lost_event(&self, machine: &str) -> Option<FlyEvent> {
        let evs = (self.lc.hooks().fly_events)(machine).ok()?;
        let mut best: Option<FlyEvent> = None;
        for e in evs {
            if !matches!(e.kind.as_str(), "exit" | "stop" | "destroy" | "suspend")
                && !machine_down(&e.status)
            {
                continue;
            }
            if best.as_ref().is_none_or(|b| e.timestamp > b.timestamp) {
                best = Some(e);
            }
        }
        best
    }

    /// what Resume will do for a lost machine, in plain words
    pub fn lost_resume(&self, sid: &str) -> String {
        const GONE: &str = "The machine isn't started again (its keys were in its memory only). ";
        let (older, _, older_at) = self.latest_snapshot(sid);
        if older.is_empty() {
            return format!(
                "{GONE}There is no signed snapshot of the session, so Resume would start it empty and refuses; Destroy archives the live copies of its transcripts."
            );
        }
        format!(
            "{GONE}Resume starts a new machine from the newest signed snapshot (machine {older}'s, from {}); what the session did after that snapshot is lost.",
            utc_text(older_at, false)
        )
    }

    /// the session's machine is down and Jarvis didn't take it down: the session says so
    pub fn mark_lost(self: &Arc<Self>, sid: &str, machine: &str, fly_state: &str) {
        let now = GoTime::now().utc();
        let mut l = LostMachine {
            machine: machine.into(),
            at: now,
            seen: now,
            fly_state: fly_state.into(),
            ..Default::default()
        };
        if let Some(ev) = self.lost_event(machine) {
            l.at = GoTime::from_unix_nanos(ev.timestamp as i128 * 1_000_000).utc();
            l.fly = crate::lifecycle::event_text(&ev);
        }
        l.resume = self.lost_resume(sid);
        let msg = lost_text(&l);
        // the operation first, so the failure below is its end, not a second event (failures.rs). An operation already
        // running (a boot still waiting for the machine's first report) gets the note, and the loss is its own event.
        let (h, own) = match self.lc_current(sid) {
            Some(h) => (h, false),
            None => {
                let h = self.lc_begin(sid, "machine-lost");
                h.machine(machine);
                (h, true)
            }
        };
        let changed = self.st.do_(|d| {
            let Some(s) = d.sessions.get_mut(sid) else {
                return false;
            };
            if s.machine_id != machine
                || s.lost.is_some()
                || !(s.state == "started" || s.state == "initialising")
            {
                return false;
            }
            s.lost = Some(l.clone());
            s.state = "failed".into();
            s.error = msg.clone();
            s.status.clear();
            s.waiting.clear();
            true
        });
        if !changed {
            // Jarvis moved on meanwhile (a pause, a destroy)
            if own {
                h.end("done", "");
            }
            return;
        }
        crate::logf!("session {sid}: {msg}");
        h.note(machine, &msg);
        if own {
            h.end("failed", &msg);
        } else {
            self.lc_ended(sid, "machine-lost", machine, &msg);
        }
        self.dm(&format!("🔴 Session “{}” — {msg}", self.dm_name(sid)));
    }

    /// a lost kernel line's Resume (run by kernel_resume). true: handled (failed with the reason); false: the machine is
    /// killed into the line's next source and the caller spawns from it.
    pub fn kernel_resume_lost(&self, s: &Session, op: &LcHandle) -> bool {
        let id = &s.id;
        let Some(l) = &s.lost else { return false };
        let m = &l.machine;
        op.machine(m);
        op.note(
            m,
            &format!(
                "its machine {} outside Jarvis: asked the kernel's spawner to kill it into the line's next source, with the newest signed snapshot",
                lost_what(&l.fly_state)
            ),
        );
        let snap = match self.kernel_kill(id, m, false, false) {
            Err(e) => {
                self.set_state(
                    id,
                    "failed",
                    &format!(
                        "Resume couldn't take machine {m} off the line ({e:#}): Resume tries again."
                    ),
                );
                return true;
            }
            Ok(s) => s,
        };
        let now = GoTime::now().utc();
        let refused = self.st.do_(|d| {
            let Some(x) = d.sessions.get_mut(id) else { return String::new() };
            x.machine_id.clear();
            x.paused_at = Some(now);
            x.status.clear();
            x.lost = None;
            if snap.is_empty() && x.booted == *m {
                x.no_snapshot = format!("machine {m} stopped outside Jarvis and there is no signed snapshot of the session");
                return x.no_snapshot.clone();
            }
            String::new()
        });
        op.note(
            m,
            &format!(
                "the spawner confirmed the machine destroyed; the line's source names snapshot {}",
                if snap.is_empty() { "(none)" } else { &snap }
            ),
        );
        if !refused.is_empty() {
            self.set_state(
                id,
                "failed",
                &format!("resume: {refused}, so it would start empty: it doesn't"),
            );
            return true;
        }
        false
    }
}
