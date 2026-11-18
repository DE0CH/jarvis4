//! A handover starts the next machine while the old one is still going (Deyao, 2026-10-19: "you can start a new
//! machine before the old machine has completely shut down, as reported by Fly, as long as the stop command has been
//! sent"; DECISIONS 193).
//!
//! A session moving to a new machine (Upgrade, Restart, More disk, Resume of a failed session that still has its
//! machine) used to run strictly in a row: the final snapshot, the kill until Fly reported the old machine destroyed,
//! then the core's start of the new one (a Fly create, the image pull and boot, init) and its cert. Now the router asks
//! the core for the new machine (a SPARE) the moment the old one has been told to stop: the supervisor's "snapshot"
//! command (it stops the Claude process and freezes the session before the snapshot), or "free" for an Upgrade, or the
//! kill itself when no snapshot needs asking for. The spare's create, pull and boot run while the old machine
//! snapshots and Fly destroys it.
//!
//! What still waits, and why (each is something the new machine depends on):
//!   - The cert. A machine without a cert has no secrets, no snapshot and no session identity: it boots, prints its
//!     keys and waits (rust/machine/src/boot.rs prepare, up to ~10 min). The core certifies a successor only once its
//!     predecessor is killed, and a kill is Fly-confirmed destroyed with the final snapshot named (core/core.go
//!     Certify, Kill). So the snapshot the new machine restores is always the old machine's final one, never an older
//!     one, and the old machine can no longer write state, pull secrets, register the tunnel, hold the Remote Control
//!     entry or use a lease once the new one has its identity. Moving that line is a core change.
//!   - The spare matches what the start would ask for (image, size, disk) or it isn't used: a start the phone approves
//!     (a newer image, a resume prompt, another permission mode) gets its own machine, and the spare goes.
//!   - A spare that isn't taken (the pause kept the machine, the resume went to the phone, nothing came within
//!     SPARE_MAX_AGE, so the machine's own wait for its cert could run out) is killed in the background; Fly's org
//!     machine cap counts it until then (lessons/58). A spare never waits out the machine cap: at the cap it gives up
//!     and the start makes its machine after the kill, as before.

use crate::core::Doc;
use crate::router::Router;
use crate::state::{Session, Started};
use serde::Deserialize;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

/// what the handover's start will ask the core for (start_and_certify: the approval's image, the session's size,
/// region and disk)
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NextMachine {
    pub image: String,
    /// "" = medium
    pub size: String,
    /// regions.rs: the session's region
    pub region: String,
    pub disk_gb: i64,
}

fn or_medium(s: &str) -> &str {
    if s.is_empty() { "medium" } else { s }
}

impl NextMachine {
    pub fn same(&self, o: &NextMachine) -> bool {
        self.image == o.image
            && or_medium(&self.size) == or_medium(&o.size)
            && self.region == o.region
            && self.disk_gb == o.disk_gb
    }
}

#[derive(Default)]
struct SpareState {
    /// the start ended
    done: bool,
    /// the core's signed "started" document
    doc: Option<Doc>,
    /// the machine, once the core's Fly create made it
    id: String,
    err: Option<String>,
    ready_at: Option<Instant>,
}

#[derive(Default)]
pub struct Spare {
    want: NextMachine,
    mu: Mutex<SpareState>,
    cv: Condvar,
}

impl Spare {
    fn lock(&self) -> std::sync::MutexGuard<'_, SpareState> {
        self.mu.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn machine(&self) -> String {
        self.lock().id.clone()
    }

    /// waits until the start ended
    fn wait(&self) -> std::sync::MutexGuard<'_, SpareState> {
        let mut g = self.lock();
        while !g.done {
            g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
        g
    }
}

/// how long a started spare may wait for its cert, in seconds. The machine asks for it 300 times 2 s apart
/// (rust/machine/src/boot.rs prepare) and refuses to start after that, so a spare older than this is killed, not
/// certified. Tests shorten it.
pub static SPARE_MAX_AGE_MS: AtomicU64 = AtomicU64::new(8 * 60 * 1000);

pub fn spare_max_age() -> Duration {
    Duration::from_millis(SPARE_MAX_AGE_MS.load(Ordering::Relaxed))
}

/// tests learn when a spare's start began (None in production)
pub type SpareHook = Arc<dyn Fn(&str) + Send + Sync>;
pub static SPARE_STARTED: RwLock<Option<SpareHook>> = RwLock::new(None);

impl Router {
    fn spares_lock(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::BTreeMap<String, Arc<Spare>>> {
        self.spares.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// the spare is still the session's: then it is no longer (Go's CompareAndDelete)
    fn spare_remove_if(&self, sid: &str, sp: &Arc<Spare>) -> bool {
        let mut g = self.spares_lock();
        if g.get(sid).is_some_and(|x| Arc::ptr_eq(x, sp)) {
            g.remove(sid);
            return true;
        }
        false
    }

    /// the machine an unattended resume of the session will start (the dead-machine rule: the cert's own image), or
    /// None when the resume goes to the phone anyway (a newer image, a resume prompt or rollback, another permission
    /// mode, the Claude login's legacy image): those start their own machine after Deyao's approval.
    pub fn handover_next(&self, s: &Session, size: &str, disk_gb: i64) -> Option<NextMachine> {
        let cert = s.cert.as_ref()?;
        let own = crate::flows::cert_image(Some(cert), &s.image);
        let has_claude = s
            .stores
            .as_ref()
            .is_some_and(|st| st.iter().any(|x| x == "claude"));
        if (has_claude && crate::flows::legacy_login_image(&own, &self.cfg.image_order))
            || !self.resume_once(s).is_empty()
            || crate::flows::cert_mode(Some(cert)) != crate::flows::norm_mode(&s.permission_mode)
        {
            return None;
        }
        Some(NextMachine {
            image: own,
            size: if size.is_empty() {
                s.size.clone()
            } else {
                size.to_string()
            },
            region: self.region_of(s),
            disk_gb: if disk_gb == 0 { s.disk_gb } else { disk_gb },
        })
    }

    /// the core's start of the next machine, in the background. A spare for the same machine already under way
    /// stays; one for another is dropped.
    pub fn launch_spare(self: &Arc<Self>, sid: &str, want: Option<&NextMachine>) {
        let Some(want) = want else { return };
        let sp = Arc::new(Spare {
            want: want.clone(),
            ..Default::default()
        });
        {
            let mut g = self.spares_lock();
            if let Some(old) = g.get(sid).cloned() {
                if old.want.same(want) {
                    return;
                }
                g.remove(sid);
                drop(g);
                self.drop_spare(sid, old, "the handover asks for another machine now");
                g = self.spares_lock();
            }
            if g.contains_key(sid) {
                return; // another launch won the race for the same session
            }
            g.insert(sid.to_string(), sp.clone());
        }
        self.lc_note(
            sid,
            "",
            &format!(
                "the old machine has been told to stop: starting the next machine now ({}); it gets its cert once the old one is killed",
                or_medium(&want.size)
            ),
        );
        if let Some(h) = SPARE_STARTED
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            h(sid);
        }
        let (r, sid) = (self.clone(), sid.to_string());
        std::thread::spawn(move || {
            let w = &sp.want;
            let on_id = |id: &str| {
                sp.lock().id = id.to_string();
                r.lc_note(
                    &sid,
                    id,
                    &format!("the core's Fly create made the next machine {id} (spare); it boots while the old one stops"),
                );
            };
            let res =
                r.start_machine_with(&w.image, &w.size, &w.region, w.disk_gb, Some(&on_id), false);
            let failed = {
                let mut g = sp.lock();
                g.ready_at = Some(Instant::now());
                g.done = true;
                let f = match res {
                    Ok(d) => {
                        g.doc = Some(d);
                        None
                    }
                    Err(e) => {
                        let m = format!("{e:#}");
                        g.err = Some(m.clone());
                        Some(m)
                    }
                };
                sp.cv.notify_all();
                f
            };
            if let Some(e) = failed {
                crate::logf!(
                    "session {sid}: the spare's start: {e} (the start after the kill makes the machine)"
                );
                r.lc_note(
                    &sid,
                    "",
                    &format!(
                        "the spare's start failed ({e}): the start after the kill makes the machine"
                    ),
                );
                r.spare_remove_if(&sid, &sp);
                return;
            }
            // not taken in time: its machine would stop waiting for a cert, so it goes
            std::thread::sleep(spare_max_age());
            if r.spare_remove_if(&sid, &sp) {
                r.drop_spare(
                    &sid,
                    sp,
                    &format!(
                        "not taken within {}",
                        crate::flows::wait_text(spare_max_age())
                    ),
                );
            }
        });
    }

    /// the started spare for this start (its "started" document), or None: none, another machine, a failed start, or
    /// too old (those are dropped). Waits for a spare still starting.
    pub fn take_spare(self: &Arc<Self>, sid: &str, want: &NextMachine) -> Option<Doc> {
        let sp = self.spares_lock().remove(sid)?;
        if !sp.want.same(want) {
            self.drop_spare(sid, sp, "the start asks for another machine");
            return None;
        }
        let (doc, at) = {
            let g = sp.wait();
            if g.err.is_some() {
                return None;
            }
            (g.doc.clone()?, g.ready_at)
        };
        if at.is_some_and(|t| t.elapsed() > spare_max_age()) {
            self.drop_spare(sid, sp, "it waited too long for its cert");
            return None;
        }
        Some(doc)
    }

    /// the handover ends without a start on this router's side (the pause kept the machine, the resume went to the
    /// phone): the spare goes
    pub fn cancel_spare(self: &Arc<Self>, sid: &str, why: &str) {
        let sp = self.spares_lock().remove(sid);
        if let Some(sp) = sp {
            self.drop_spare(sid, sp, why);
        }
    }

    /// kill the spare's machine in the background, once its start has ended (Fly's org machine cap counts it until
    /// then: lessons/58)
    fn drop_spare(self: &Arc<Self>, sid: &str, sp: Arc<Spare>, why: &str) {
        let (r, sid, why) = (self.clone(), sid.to_string(), why.to_string());
        std::thread::spawn(move || {
            let doc = {
                let g = sp.wait();
                if g.err.is_some() {
                    return; // start_machine_with killed what it made
                }
                let Some(doc) = g.doc.clone() else { return };
                doc
            };
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct St {
                machine: Option<Started>,
            }
            let mut id = sp.machine();
            if let Ok(st) = doc.decode::<St>()
                && let Some(m) = st.machine.filter(|m| !m.id.is_empty())
            {
                id = m.id;
            }
            if id.is_empty() {
                return;
            }
            r.lc_note(
                &sid,
                &id,
                &format!(
                    "the spare machine {id} isn't used ({why}): asking the core to destroy it"
                ),
            );
            if let Err(e) = r.kill_until_destroyed(&json!({"machine": id})) {
                crate::logf!(
                    "session {sid}: the unused spare {id}: kill: {e:#} (the Machines tab lists it)"
                );
            }
        });
    }

    /// a handover's resume right after its pause (wait_state has seen the pause end and its lock go). An action that
    /// took the session in between (a wakeup's resume) can still hold it: it tries again for a while.
    pub fn handover_resume(
        self: &Arc<Self>,
        id: &str,
        prompt: &str,
        upgrade: bool,
    ) -> anyhow::Result<()> {
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            match self.resume_with_prompt(id, upgrade, prompt) {
                Err(e) if crate::drain::is_busy(&e) && Instant::now() < end => {
                    std::thread::sleep(crate::sessionops::OPS_POLL);
                }
                other => return other,
            }
        }
    }
}
