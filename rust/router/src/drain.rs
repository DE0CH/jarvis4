//! Draining on SIGTERM (Deyao, 2026-10-13). Every lifecycle action (pause, resume, destroy, a start after the phone's
//! approval, a permission-mode switch, a restart or upgrade job) runs in a thread of the router that began it; a
//! rollout used to cut those off half way (a new session's first start after Face ID failed with "start cut off by a
//! router restart" and needed a second approval).
//!
//! Now each such thread is tracked here: lock() (flows.rs) and respond() begin one, the thread ends it. On SIGTERM the
//! router stops beginning new ones — the caller gets 503 "router updating, try again shortly" (write_err), and a
//! scheduler/autopilot/task tick sees a busy session and tries again on its next tick, i.e. in the next pod — while
//! everything already running finishes. Reads, the machines' reports (/m: status, snapshots — a pause in flight needs
//! its snapshot) and the Claude login's long polls go on being served throughout. Then the process exits. The router's
//! Deployment gives the drain terminationGracePeriodSeconds (DRAIN_SECONDS under it). A pause waits for its snapshot as
//! long as it makes progress (snapwait.rs), so a snapshot still uploading when the drain gives up is cut off with the
//! old pod like any other action (the session goes failed and keeps its machine; Pause again).
//!
//! A crash (OOM, node reboot, a drain past the grace period) still cuts actions off; end_cut_off (below) turns what it
//! left behind into a plain failed or paused session with the reason, and Deyao runs the action again. Nothing is
//! redone by itself (Deyao, 2026-10-13: no save-to-disk-and-redo).

use crate::ctx::Ctx;
use crate::router::Router;
use crate::util::OnceFn;
use anyhow::Result;
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// what a refused action hears during a drain (its start is matched by e2e and leader.rs's own 503)
pub const DRAINING_MSG: &str = "router updating, try again shortly: the actions already running finish first, then the new router takes new ones (usually within a minute or two, at most 29 minutes behind a long pause)";

/// the router is updating. It counts as a busy session too (is_busy), so every automatic caller that already backs off
/// a busy session (schedule.rs, vouch.rs, tasks.rs, watches) treats it as "try again later", not as a failure.
#[derive(Debug)]
pub struct Draining;

impl std::fmt::Display for Draining {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(DRAINING_MSG)
    }
}

impl std::error::Error for Draining {}

/// errBusy or errDraining (Go's errors.Is(err, errBusy))
pub fn is_busy(e: &anyhow::Error) -> bool {
    e.downcast_ref::<crate::router::Busy>().is_some() || e.downcast_ref::<Draining>().is_some()
}

/// a start waiting out Fly's machine limit when the drain began. The wait (up to machine_limit_wait) would hold the
/// rollout for hours, so the start ends instead (Deyao starts it again; DECISIONS).
pub fn limit_draining() -> anyhow::Error {
    anyhow::anyhow!("the Fly org is at its machine limit and the router is updating: start it again")
}

#[derive(Default)]
struct Inner {
    draining: bool,
    /// bumped when a drain begins (sleep_unless_draining wakes on it)
    started_gen: u64,
    next: u64,
    /// what is running, for the drain's log
    inflight: BTreeMap<u64, String>,
    /// session → running multi-step jobs (restart, upgrade): their own steps still begin
    jobs: BTreeMap<String, i64>,
}

#[derive(Default)]
pub struct DrainState {
    mu: Mutex<Inner>,
    cv: Condvar,
}

impl DrainState {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.mu.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn running(g: &Inner) -> Vec<String> {
        g.inflight.values().cloned().collect()
    }
}

impl Router {
    /// a lifecycle thread starts (what: for the log). Refused while draining, unless the session has a job of its own
    /// running that this is a step of (a restart's resume after its pause). The answer ends it; call it exactly once.
    pub fn begin(self: &Arc<Self>, session: &str, what: &str) -> Result<OnceFn> {
        let d = &self.drain;
        let mut g = d.lock();
        if g.draining && g.jobs.get(session).copied().unwrap_or(0) == 0 {
            return Err(Draining.into());
        }
        g.next += 1;
        let n = g.next;
        g.inflight.insert(n, format!("{what} {session}"));
        let r = self.clone();
        Ok(OnceFn::new(move || {
            let mut g = r.drain.lock();
            g.inflight.remove(&n);
            r.drain.cv.notify_all();
        }))
    }

    /// a multi-step job (restart, upgrade) that chains lifecycle actions on one session: tracked as a whole, and its
    /// own steps may begin during a drain, so a drain that starts between its pause and its resume still lets it
    /// finish rather than leaving the session paused half way.
    pub fn begin_job(self: &Arc<Self>, session: &str, what: &str) -> Result<OnceFn> {
        let end = self.begin(session, what)?;
        *self.drain.lock().jobs.entry(session.to_string()).or_default() += 1;
        let r = self.clone();
        let session = session.to_string();
        Ok(OnceFn::new(move || {
            {
                let mut g = r.drain.lock();
                let n = g.jobs.entry(session.clone()).or_default();
                *n -= 1;
                if *n <= 0 {
                    g.jobs.remove(&session);
                }
            }
            end.call();
        }))
    }

    /// lifecycle actions are taken again (a flip that was aborted after its freeze had drained)
    pub fn undrain(&self) {
        let mut g = self.drain.lock();
        if g.draining {
            g.draining = false;
            crate::logf!("drain ended: lifecycle actions are taken again");
        }
    }

    /// sleeps for t; true = a drain began (now or during the sleep)
    pub fn sleep_unless_draining(&self, t: Duration) -> bool {
        let end = Instant::now() + t;
        let mut g = self.drain.lock();
        let gen0 = g.started_gen;
        loop {
            if g.draining || g.started_gen != gen0 {
                return true;
            }
            let now = Instant::now();
            if now >= end {
                return false;
            }
            g = self
                .drain
                .cv
                .wait_timeout(g, end - now)
                .map(|(g, _)| g)
                .unwrap_or_else(|e| e.into_inner().0);
        }
    }

    pub fn draining(&self) -> bool {
        self.drain.lock().draining
    }

    /// refuse new lifecycle actions, then wait (at most max) for the running ones. true = all finished.
    pub fn drain_now(&self, max: Duration) -> bool {
        self.drain_until(max, &Ctx::background())
    }

    /// drain_now that also stops waiting once abort is cancelled (nextcore.rs: the flip's standby went away); false
    /// then. It stays draining either way: the caller undrains.
    pub fn drain_until(&self, max: Duration, abort: &Ctx) -> bool {
        let d = &self.drain;
        let mut g = d.lock();
        if !g.draining {
            g.started_gen += 1;
        }
        g.draining = true;
        d.cv.notify_all();
        let running = DrainState::running(&g);
        crate::logf!(
            "draining: new lifecycle actions are refused; waiting for {}: {running:?}",
            running.len()
        );
        let end = Instant::now() + max;
        let mut next_log = Instant::now() + Duration::from_secs(60);
        loop {
            if g.inflight.is_empty() {
                crate::logf!("drained");
                return true;
            }
            let now = Instant::now();
            if abort.cancelled() {
                crate::logf!("drain aborted; still running: {:?}", DrainState::running(&g));
                return false;
            }
            if now >= end {
                crate::logf!(
                    "drain gave up after {}; cut off: {:?}",
                    jarvis_go::fmt::duration_string(max),
                    DrainState::running(&g)
                );
                return false;
            }
            if now >= next_log {
                crate::logf!("draining: still running: {:?}", DrainState::running(&g));
                next_log = now + Duration::from_secs(60);
            }
            let wait = (end - now).min(next_log - now).min(Duration::from_millis(250));
            g = d.cv.wait_timeout(g, wait).map(|(g, _)| g).unwrap_or_else(|e| e.into_inner().0);
        }
    }

    /// at start, sessions a crash left in the middle of an action that no job holds (jobs.rs: a job whose holder died
    /// is carried on by jobs_loop instead) become plain sessions with the reason; Deyao runs the action again. A
    /// cut-off resume's line is still there (the core marks the predecessor used only at certify), so it is paused
    /// again; a new line's start, a pause or a destroy is failed. A machine the cut-off start had made, never
    /// certified, holds no secret and shows on the Machines tab with no session (attention), where Deyao can destroy
    /// it.
    pub fn end_cut_off(&self) {
        let ids: Vec<String> = self.st.do_(|d| d.sessions.keys().cloned().collect());
        for id in ids {
            if !self.job_busy(&id) {
                self.cut_off_session(&id);
            }
        }
    }

    /// a session in the middle of an action nobody runs any more, made a plain one with the reason
    pub fn cut_off_session(&self, id: &str) {
        self.st.do_(|d| {
            let Some(s) = d.sessions.get_mut(id) else { return };
            let (state, why) = match s.state.as_str() {
                "resuming" | "starting" if s.has_line() && s.machine_id.is_empty() => {
                    ("paused", "the resume was cut off by a router crash: resume it again")
                }
                "resuming" | "starting" => ("failed", "the start was cut off by a router crash: start it again"),
                "pausing" => (
                    "failed",
                    "the pause was cut off by a router crash (the machine may still run): pause it again",
                ),
                "destroying" => ("failed", "the destroy was cut off by a router crash: destroy it again"),
                _ => return,
            };
            s.state = state.into();
            s.error = why.into();
            s.waiting.clear();
            crate::logf!("session {id}: {why}");
        });
    }
}
