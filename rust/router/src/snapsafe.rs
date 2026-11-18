//! A pause never loses a session's state (2026-10-15: session sb8e0273d6c308894's final snapshot failed with "no space
//! left on device", the machine was destroyed anyway and the resume started with an empty conversation).
//!
//!   - The machine's final snapshot streams to the router (snapstream.rs): it needs no free disk on the machine.
//!   - A machine whose final snapshot fails (an error the machine reports, no progress for the stall time, a machine
//!     that went silent) is KEPT, never destroyed, with or without a volume (Deyao, 2026-10-21: session
//!     sad35945f04b2124d's machine was killed after its snapshot failed): the session goes "failed" with
//!     snapshot_failed set, and Deyao gets a "needs you" DM. Pause again retries; Destroy anyway (force) goes on
//!     without it.
//!   - A machine with a volume (a core with volumes, core/volumes.go) whose kill goes on: the core destroys it and
//!     deletes the volume. No volume snapshot is taken (DECISIONS 222): the machine's signed snapshot is the only copy
//!     of its state.
//!   - A line whose last machine left no signed snapshot (while an earlier machine of it did, or it had booted) is
//!     marked no_snapshot: Resume refuses (it would start the session empty), says why on the session, and Deyao gets a
//!     DM. Destroy still archives the newest signed snapshot it has (and every live transcript copy it doesn't hold,
//!     livearchive.rs), never DMs about it, and notes the missing snapshot in the record.
//!   - A kill that doesn't finish (the core still can't destroy it after kill_max) leaves the session failed with its
//!     machine, and DMs too.

use crate::core::Doc;
use crate::handover::NextMachine;
use crate::http::null_if_empty;
use crate::router::Router;
use crate::state::{Session, Started};
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};

/// a machine's Fly volume as the core's started document names it (core/volumes.go VolumeInfo)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Volume {
    pub id: String,
    #[serde(rename = "sizeGb")]
    pub size_gb: i64,
    pub path: String,
}

impl Router {
    /// the volume the machine's cert names (None: a machine of a core without volumes)
    pub fn machine_volume(&self, machine: &str) -> Option<Volume> {
        let (cert, st): (Option<Doc>, Option<Started>) = self.st.do_(|d| {
            (
                d.certs.get(machine).cloned(),
                d.started.get(machine).cloned(),
            )
        });
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct M {
            volume: Option<Volume>,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct C {
            machine: Option<M>,
        }
        if let Some(v) = cert
            .and_then(|c| c.decode::<C>().ok())
            .and_then(|c| c.machine)
            .and_then(|m| m.volume)
        {
            return Some(v);
        }
        st.and_then(|s| s.volume)
    }

    /// a pause's or destroy's end of a running machine. false: the machine is still there (kept after a failed
    /// snapshot, or a kill that didn't finish), the session failed with the reason, Deyao DMed.
    pub fn final_snapshot_and_kill(self: &Arc<Self>, id: &str, machine: &str, force: bool) -> bool {
        self.final_snapshot_and_kill_with(id, machine, false, force, None)
    }

    /// destroying = a destroy's (archive.rs snapshot_and_kill: its kill falls back, DECISIONS 181)
    pub fn final_snapshot_and_kill_for(
        self: &Arc<Self>,
        id: &str,
        machine: &str,
        destroying: bool,
        force: bool,
    ) -> bool {
        self.final_snapshot_and_kill_with(id, machine, destroying, force, None)
    }

    /// a pause's end that hands over to next (handover.rs; None = a plain pause)
    pub fn final_snapshot_and_kill_next(
        self: &Arc<Self>,
        id: &str,
        machine: &str,
        next: Option<NextMachine>,
    ) -> bool {
        self.final_snapshot_and_kill_with(id, machine, false, false, next)
    }

    /// next (a handover's next machine) starts as soon as the old one has been told to stop — the snapshot command, or
    /// the kill when no snapshot is asked for — and its cert still waits for this kill (handover.rs). A machine kept
    /// here drops it.
    pub fn final_snapshot_and_kill_with(
        self: &Arc<Self>,
        id: &str,
        machine: &str,
        destroying: bool,
        force: bool,
        next: Option<NextMachine>,
    ) -> bool {
        let has_next = next.is_some();
        let sent = Mutex::new(next);
        let stop_sent = || {
            if let Some(n) = sent.lock().unwrap_or_else(|e| e.into_inner()).take() {
                self.launch_spare(id, Some(&n));
            }
        };
        let mut ok = false;
        (|| {
            let serr = self
                .last_snapshot_then(id, machine, Some(&stop_sent), destroying)
                .err();
            let vol = self.machine_volume(machine);
            if let Some(e) = serr.as_ref().filter(|_| !force) {
                self.keep_machine(id, machine, e);
                return;
            }
            stop_sent(); // the kill below is the stop when no snapshot was asked for (one already here, or a machine never booted)
            if let Some(e) = &serr {
                crate::logf!(
                    "session {id}: {machine}'s final snapshot: {e:#}; going on (destroy anyway)"
                );
            }
            self.lc_note(id, machine, "asked the core to destroy the machine on Fly");
            if self.is_kernel_machine(machine) {
                // kernelline.rs: the spawner kills it into the line's next source
                self.kernel_kill_done(id, machine, destroying, serr.as_ref(), &mut ok);
                return;
            }
            // vouch.rs: with the snapshot's hash; a pause only with it vouched for
            let mut res = self.kill_machine(machine, !destroying);
            if destroying && let Err(e) = res {
                res = self.destroy_kill_fallback(id, machine, force, e);
            }
            self.set_waiting(id, "");
            match res {
                Err(e) => {
                    self.lc_note(id, machine, &format!("the kill failed: {e:#}"));
                    self.kill_failed(id, machine, vol.is_some(), destroying, &e);
                    if destroying {
                        self.st.do_(|d| {
                            if let Some(s) = d.sessions.get_mut(id) {
                                s.error += crate::archive::DESTROY_ANYWAY_HINT;
                            }
                        });
                    }
                }
                Ok(kd) => {
                    self.record_kill(id, machine, kd.as_ref(), serr.as_ref(), destroying);
                    self.lc_note(
                        id,
                        machine,
                        "the core confirmed the machine destroyed on Fly",
                    );
                    ok = true;
                }
            }
        })();
        let _: () = ();
        if !ok && has_next {
            self.cancel_spare(id, "the old machine was kept");
        }
        ok
    }

    pub fn dm_name(&self, id: &str) -> String {
        self.st.do_(|d| {
            d.sessions
                .get(id)
                .map(|s| {
                    crate::autopilot::session_name(s, s.live.as_ref().and_then(|l| l.reg.as_ref()))
                })
                .unwrap_or_else(|| id.to_string())
        })
    }

    /// the final snapshot failed: the machine stays (with its volume, if it has one), so nothing is lost
    pub fn keep_machine(&self, id: &str, machine: &str, serr: &anyhow::Error) {
        let msg = format!(
            "the final snapshot failed ({serr:#}): its machine {machine} is kept, nothing is lost. Pause again once it can snapshot, or Destroy anyway (that drops what changed since its last snapshot)"
        );
        self.st.do_(|d| {
            if let Some(s) = d.sessions.get_mut(id) {
                s.state = "failed".into();
                s.error = msg.clone();
                s.snapshot_failed = format!("{serr:#}");
            }
        });
        crate::logf!("session {id}: {msg}");
        self.dm(&format!(
            "🔴 Session “{}” needs you — its final snapshot failed ({serr:#}), so its machine was kept instead of destroyed: nothing is lost. Free what blocks it (or give it more disk), then Pause again; Destroy anyway drops what changed since its last snapshot.",
            self.dm_name(id)
        ));
    }

    /// the core still refuses or can't finish the kill: the machine (with its volume) stays
    pub fn kill_failed(
        &self,
        id: &str,
        machine: &str,
        has_volume: bool,
        destroying: bool,
        err: &anyhow::Error,
    ) {
        let _ = machine;
        let what = if has_volume {
            "its machine and its volume are kept"
        } else {
            "its machine is kept"
        };
        let (action, retry) = if destroying {
            ("destroy", "Destroy again to retry")
        } else {
            ("pause", "Pause again to retry")
        };
        self.set_state(id, "failed", &format!("kill: {err:#} — {what}: {retry}"));
        self.dm(&format!(
            "🔴 Session “{}” needs you — its {action} couldn't finish ({err:#}); {what}, nothing was destroyed. {retry}.",
            self.dm_name(id)
        ));
    }

    /// the kill's record — a kill that names no snapshot of a line that had state marks it no_snapshot (Resume refuses)
    /// and DMs. A destroy's kill never DMs: a destroy isn't a resume, so there is nothing to refuse; the reason goes into
    /// its record (ArchiveInfo.no_snapshot, the archive's session.json).
    pub fn record_kill(
        &self,
        id: &str,
        machine: &str,
        kd: Option<&Doc>,
        serr: Option<&anyhow::Error>,
        destroying: bool,
    ) {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct K {
            snapshot: String,
        }
        let k = kd.and_then(|d| d.decode::<K>().ok()).unwrap_or_default();
        let (mut older, _, older_at) = self.latest_snapshot(id); // archive.rs: the newest signed snapshot still held
        if older == machine {
            older.clear();
        }
        let reason = self.st.do_(|d| {
            let s = d.sessions.get_mut(id)?;
            s.snapshot_failed.clear();
            if !k.snapshot.is_empty() || (s.booted != machine && older.is_empty()) {
                // a snapshot, or a line with no state yet (its first machine never booted)
                s.no_snapshot.clear();
                s.no_snapshot_dmed = false;
                return None;
            }
            let why = serr.map_or("it sent none".to_string(), |e| format!("{e:#}"));
            let reason = format!("machine {machine} left no snapshot ({why})");
            s.no_snapshot = reason.clone();
            s.no_snapshot_dmed = true;
            Some(reason)
        });
        let Some(reason) = reason else { return };
        if destroying {
            crate::logf!("session {id}: {reason}; destroying, so the archive notes it (no DM)");
            return;
        }
        crate::logf!("session {id}: {reason}; it won't resume");
        self.dm(&format!(
            "🔴 Session “{}” needs you — {reason}, so it won't resume (it would start empty). {}",
            self.dm_name(id),
            state_left(&older, older_at)
        ));
    }

    /// None, or why Resume won't start the session (no_snapshot), DMed once per refusal episode
    pub fn resume_refusal(&self, id: &str) -> Option<anyhow::Error> {
        let (reason, dm) = self.st.do_(|d| {
            let Some(s) = d.sessions.get_mut(id).filter(|s| !s.no_snapshot.is_empty()) else {
                return (String::new(), false);
            };
            let dm = !s.no_snapshot_dmed;
            s.no_snapshot_dmed = true;
            (s.no_snapshot.clone(), dm)
        });
        if reason.is_empty() {
            return None;
        }
        let (older, _, older_at) = self.latest_snapshot(id);
        let msg = format!(
            "session {id} won't resume: its {reason}, so it would start empty. {}",
            state_left(&older, older_at)
        );
        if dm {
            self.dm(&format!(
                "🔴 Session “{}” needs you — a resume was refused: {msg}",
                self.dm_name(id)
            ));
        }
        Some(anyhow!(msg))
    }

    /// a destroy's kill that failed (DECISIONS 181). A refused snapshot claim (a machine from an earlier core: this
    /// core has no key for it) is killed without the claim, the session marked so its archive says so; a kill still
    /// failing is no obstacle when Fly no longer has the machine, or with force (the router stops taking the machine's
    /// calls; it is an orphan on the Machines tab, whose Destroy tries the kill again)
    pub fn destroy_kill_fallback(
        &self,
        id: &str,
        machine: &str,
        force: bool,
        mut err: anyhow::Error,
    ) -> Result<Option<Doc>> {
        if crate::archive::refused_snapshot(&err) {
            crate::logf!(
                "session {id}: the core refused {machine}'s snapshot ({err:#}): killed without it (a destroy restores nothing)"
            );
            self.st.do_(|d| {
                if let Some(x) = d.sessions.get_mut(id) {
                    x.snapshot_note = crate::archive::SNAPSHOT_FROM_EARLIER_CORE.into();
                }
            });
            match self.kill_until_destroyed(&json!({"machine": machine})) {
                Ok(kd) => return Ok(Some(kd)),
                Err(e) => err = e,
            }
        }
        match crate::archive::fly_machine_gone(machine) {
            Ok(true) => {
                crate::logf!(
                    "session {id}: the kill of {machine} failed ({err:#}) but Fly has no such machine: destroying on"
                );
                Ok(None)
            }
            _ if force => {
                crate::logf!(
                    "session {id}: the kill of {machine} failed ({err:#}): destroyed anyway; the machine is left to the Machines tab"
                );
                self.st.do_(|d| {
                    d.started.remove(machine);
                });
                Ok(None)
            }
            _ => Err(err),
        }
    }
}

/// where the session's last state is, for the DM and the refusal
pub fn state_left(older: &str, older_at: GoTime) -> String {
    if older.is_empty() {
        return "There is no other copy of its state.".into();
    }
    format!(
        "The newest signed snapshot is machine {older}'s from {} (Destroy archives it).",
        crate::util::fmt_utc_minute(&older_at)
    )
}

/// what the final snapshot left behind, in /api/state and the records
pub fn snapshot_view(s: &Session, v: &mut Map<String, Value>) {
    v.insert("noSnapshot".into(), null_if_empty(&s.no_snapshot));
    v.insert("snapshotFailed".into(), null_if_empty(&s.snapshot_failed));
}
