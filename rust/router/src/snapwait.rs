//! How long a pause or destroy waits for the machine's final snapshot (DECISIONS 214): for as long as the snapshot
//! makes progress, with no overall limit (a large upload or a bad network may take very long). The wait ends when
//!
//!   - the snapshot arrives (committed, carried over, "nothing to snapshot"), or the machine reports it failed;
//!   - nothing has moved for the snapshot stall (SNAPSHOT_STALL_SECONDS, default 10 min): the stream is stuck, or the
//!     supervisor is stuck before it (the freeze, the repos' state);
//!   - nothing has moved for SILENT_AFTER (3 min) and the machine's last status report is older than that too: the
//!     machine is gone (its supervisor reports at least every 60 s, also while the session is frozen).
//!
//! What counts as progress: the snapshot command being sent (the clock starts), every read of the snapshot's body as
//! it arrives at the router (POST /m/snapshot-stream, or the whole-file POST /m/snapshot of an older image), and a
//! progress report (POST /m/snapshot-progress, snapprogress.rs) whose numbers moved (phase, bytes read, measured,
//! sent). A report that repeats the same numbers is a live machine making no progress, so it doesn't count.
//!
//! The wait itself is a row of snapshot_waits: the replica that streams the snapshot in, or takes a progress report,
//! moves it; the one that waits reads it. Progress from the stream is written at most every SNAP_MOVE_EVERY.

use crate::router::Router;
use crate::snapprogress::SnapProgress;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

/// the stream's progress is written at most this often (a read of the body happens many times a second)
const SNAP_MOVE_EVERY: Duration = Duration::from_millis(100);

/// machine → when this replica last wrote its progress
static SNAP_MOVE_AT: LazyLock<Mutex<BTreeMap<String, Instant>>> = LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn silent_after() -> time::Duration {
    time::Duration::seconds(crate::flows::SILENT_AFTER_SECS.load(Ordering::Relaxed))
}

impl Router {
    pub fn sw_exec(&self, sql: &str, params: &[&(dyn postgres::types::ToSql + Sync)]) -> Result<()> {
        let db = self.st.db().ok_or_else(|| anyhow!("snapshot waits: no database"))?;
        db.conn()?.execute(sql, params)?;
        Ok(())
    }

    /// the wait a pause starts (a later wait for the same machine replaces it) → its token
    pub fn await_snapshot(&self, machine: &str) -> String {
        let tok = crate::util::rand_id();
        let _ = self.sw_exec(
            "INSERT INTO snapshot_waits (machine_id, token, moved_at) VALUES ($1, $2, now())
             ON CONFLICT (machine_id) DO UPDATE SET token = $2, moved_at = now(), progress = NULL, done = false, error = ''",
            &[&machine, &tok],
        );
        tok
    }

    pub fn snapshot_arrived(&self, machine: &str) {
        let _ = self.sw_exec("UPDATE snapshot_waits SET done = true WHERE machine_id = $1", &[&machine]);
        let _ = self.sw_exec("SELECT pg_notify('mq', $1)", &[&format!("w:{machine}")]);
    }

    /// the wait ended without the snapshot (a late one still lands as the machine's snapshot, which the next pause
    /// finds), so later progress reports aren't shown any more
    pub fn stop_awaiting(&self, machine: &str, tok: &str) {
        let _ = self.sw_exec("DELETE FROM snapshot_waits WHERE machine_id = $1 AND token = $2", &[&machine, &tok]);
    }

    /// a sign of progress on the machine's awaited snapshot (no-op when none is awaited)
    pub fn snapshot_moved(&self, machine: &str) {
        {
            let mut g = SNAP_MOVE_AT.lock().unwrap_or_else(|e| e.into_inner());
            if g.get(machine).is_some_and(|t| t.elapsed() < SNAP_MOVE_EVERY) {
                return;
            }
            g.insert(machine.to_string(), Instant::now());
        }
        let _ = self.sw_exec("UPDATE snapshot_waits SET moved_at = now() WHERE machine_id = $1", &[&machine]);
    }

    /// a progress report; it counts as progress only when its numbers moved
    pub fn snapshot_reported(&self, machine: &str, p: &SnapProgress) {
        let b = jarvis_go::marshal(p);
        let _ = self.sw_exec(
            "UPDATE snapshot_waits SET progress = $2::text::jsonb, moved_at = now() WHERE machine_id = $1 AND progress IS DISTINCT FROM $2::text::jsonb",
            &[&machine, &b],
        );
    }

    /// the wait's state → (moved, done), None: no wait
    pub fn snap_wait_row(&self, machine: &str) -> Option<(GoTime, bool)> {
        let db = self.st.db()?;
        let row = db
            .conn()
            .ok()?
            .query_opt("SELECT moved_at, done FROM snapshot_waits WHERE machine_id = $1", &[&machine])
            .ok()??;
        let moved: time::OffsetDateTime = row.get(0);
        Some((GoTime(Some(moved)), row.get(1)))
    }

    /// how long the awaited snapshot has shown no progress
    pub fn snapshot_quiet(&self, machine: &str) -> time::Duration {
        self.snap_wait_row(machine).map_or(time::Duration::ZERO, |(m, _)| m.since())
    }

    pub fn snapshot_awaited(&self, machine: &str) -> bool {
        self.snap_wait_row(machine).is_some_and(|(_, done)| !done)
    }

    /// until the snapshot arrives (Ok), or it stalls or the machine is gone (the error says which)
    pub fn wait_snapshot(&self, machine: &str, tok: String) -> Result<()> {
        let mut stall = self.cfg.snapshot_stall;
        if stall.is_zero() {
            stall = Duration::from_secs(600);
        }
        let stall_t = time::Duration::try_from(stall).unwrap_or(time::Duration::minutes(10));
        let poll = (stall / 20).clamp(Duration::from_millis(10), Duration::from_secs(1));
        let sub = self.notes.sub(&format!("w:{machine}"));
        loop {
            let row = self.snap_wait_row(machine);
            if row.is_some_and(|(_, done)| done) {
                return Ok(()); // the row stays (a reported failure is read from it next); the next wait resets it
            }
            let quiet = row.map_or(time::Duration::ZERO, |(m, _)| m.since());
            let quiet_std = Duration::try_from(quiet).unwrap_or_default();
            if quiet >= stall_t {
                self.stop_awaiting(machine, &tok);
                return Err(anyhow!(
                    "the machine's snapshot made no progress for {}",
                    crate::flows::wait_text(quiet_std)
                ));
            }
            if quiet >= silent_after() {
                let last = self.last_report(machine);
                if last.since() >= silent_after() {
                    self.stop_awaiting(machine, &tok);
                    return Err(anyhow!(
                        "the machine went silent during its snapshot (last report {}, no progress for {})",
                        crate::util::fmt_utc_minute(&last),
                        crate::flows::wait_text(quiet_std)
                    ));
                }
            }
            sub.recv_timeout(poll);
        }
    }

    /// when the machine's supervisor last reported its status (zero: never, or not the session's machine)
    pub fn last_report(&self, machine: &str) -> GoTime {
        self.st.do_(|d| {
            d.machines
                .get(machine)
                .and_then(|sid| d.sessions.get(sid))
                .filter(|s| s.machine_id == machine)
                .and_then(|s| s.live.as_ref())
                .map(|l| l.last_report)
                .unwrap_or_default()
        })
    }
}

/// a snapshot body as it arrives; every read is progress
pub struct MovedReader<R: Read> {
    r: R,
    router: Arc<Router>,
    machine: String,
}

impl<R: Read> MovedReader<R> {
    pub fn new(r: R, router: Arc<Router>, machine: &str) -> MovedReader<R> {
        MovedReader { r, router, machine: machine.to_string() }
    }
}

impl<R: Read> Read for MovedReader<R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.r.read(b)?;
        if n > 0 {
            self.router.snapshot_moved(&self.machine);
        }
        Ok(n)
    }
}
