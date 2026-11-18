//! A session's lifecycle action is a job (docs/STATE.md 3, step 7): a row of `jobs`, at most one running per session
//! (a unique index: the clash is the 409 "in the middle of another action" on every replica alike), held by the
//! replica that runs it under a lease it renews every JOB_LEASE/3. A replica that dies (a crash, a kill past the grace
//! period) stops renewing; once the lease has run out, any replica's jobs_loop claims the job and carries it on:
//!
//! ```text
//! pausing     run again (pause_run): the final snapshot is the one the machine signed (it signs only one), the kill
//!             answers the same cert
//! destroying  run again (destroy_run): the kill as above, the archive skips what it holds, the line's burn is kept
//!             (a one-shot's report hook doesn't survive: its DM is lost, the destroy isn't)
//! starting    a kernel line's start or resume: carried on from where the records say it is (kernel_continue)
//! mode        the permission-mode switch run again (setting the mode it already has is a no-op)
//! account     the machine told again, the switch checked as a fresh one
//! anything else (an old-core line's start or resume: Jarvis 4 runs no old core): cut off as before (end_cut_off),
//!             the session failed or paused with the reason, for Deyao to run again
//! ```
//!
//! An approved add-store on a kernel line is answered within its request (kernelline.rs respond_kernel_add): a replica
//! that dies fails the request, and the app sends the same signatures again (every step of it is safe to repeat).

use crate::autopilot::Registry;
use crate::db::DB;
use crate::flows::DestroyOpts;
use crate::router::{Busy, Router, router_id};
use crate::util::OnceFn;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::Deserialize;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// how long a job's holder may go silent before another replica carries it on (tests shorten it)
pub static JOB_LEASE_MS: AtomicU64 = AtomicU64::new(60_000);

pub fn job_lease() -> Duration {
    Duration::from_millis(JOB_LEASE_MS.load(Ordering::Relaxed))
}

fn lease_interval() -> String {
    format!("{} milliseconds", job_lease().as_millis())
}

#[derive(Debug, Clone, Default)]
pub struct JobRow {
    pub id: String,
    pub session: String,
    pub kind: String,
    pub args: Value,
    pub since: GoTime,
}

/// how a job's holder ends it: (state, error); "abandoned" leaves the lease to lapse
pub type JobEnd = Arc<dyn Fn(&str, &str) + Send + Sync>;

impl Router {
    fn pool(&self) -> Result<&DB> {
        self.st
            .db()
            .ok_or_else(|| anyhow!("the router has no database"))
    }

    /// the session's running job, held by this replica (Busy when another runs)
    pub fn job_start(&self, session: &str, kind: &str, args: Value) -> Result<String> {
        let a = if args.is_null() {
            "{}".to_string()
        } else {
            jarvis_go::marshal(&args)
        };
        let id = crate::util::rand_id();
        let mut c = self.pool()?.conn()?;
        let res = c.execute(
            "INSERT INTO jobs (id, session_id, kind, args, state, owner, lease_until)
             VALUES ($1, $2, $3, $4::text::jsonb, 'running', $5, now() + $6::text::interval)",
            &[&id, &session, &kind, &a, &router_id(), &lease_interval()],
        );
        match res {
            Ok(_) => Ok(id),
            Err(e) if e.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) => {
                let row = c.query_opt(
                    "SELECT kind, created_at FROM jobs WHERE session_id = $1 AND state = 'running'",
                    &[&session],
                );
                if let Ok(Some(row)) = row {
                    let k: String = row.get(0);
                    let since: time::OffsetDateTime = row.get(1);
                    let t = since.to_offset(time::UtcOffset::UTC);
                    return Err(Busy(format!(
                        "{k}, running since {:02}:{:02}:{:02} UTC; try again once it ends (/api/state shows it as busy)",
                        t.hour(),
                        t.minute(),
                        t.second()
                    ))
                    .into());
                }
                Err(Busy(String::new()).into())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// the lease renewed until the returned end is called with the job's outcome
    pub fn job_hold(self: &Arc<Self>, id: &str) -> JobEnd {
        let stop = Arc::new(AtomicBool::new(false));
        {
            let (r, id, stop) = (self.clone(), id.to_string(), stop.clone());
            std::thread::spawn(move || {
                loop {
                    // the lease's third, in short steps so an ended job stops renewing at once
                    let step = job_lease() / 3;
                    let mut slept = Duration::ZERO;
                    while slept < step {
                        if stop.load(Ordering::SeqCst) {
                            return;
                        }
                        let d = Duration::from_millis(100).min(step - slept);
                        std::thread::sleep(d);
                        slept += d;
                    }
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    if let Ok(db) = r.pool()
                        && let Ok(mut c) = db.conn()
                    {
                        let _ = c.execute(
                            "UPDATE jobs SET lease_until = now() + $2::text::interval, updated_at = now() WHERE id = $1 AND owner = $3 AND state = 'running'",
                            &[&id, &lease_interval(), &router_id()],
                        );
                    }
                }
            });
        }
        let (r, id) = (self.clone(), id.to_string());
        let once = Mutex::new(false);
        Arc::new(move |state: &str, err_msg: &str| {
            let mut done = once.lock().unwrap_or_else(|e| e.into_inner());
            if *done {
                return;
            }
            *done = true;
            stop.store(true, Ordering::SeqCst);
            if state == "abandoned" {
                return; // the lease is left to lapse: jobs_loop carries it on
            }
            let res = r.pool().and_then(|db| {
                db.conn()?.execute(
                    "UPDATE jobs SET state = $2, error = $3, updated_at = now() WHERE id = $1 AND state = 'running'",
                    &[&id, &state, &err_msg],
                )?;
                Ok(())
            });
            if let Err(e) = res {
                crate::logf!("job {id}: ending it: {e:#}");
            }
        })
    }

    /// the session has a running job (on any replica)
    pub fn job_busy(&self, session: &str) -> bool {
        let Ok(db) = self.pool() else { return false };
        let Ok(mut c) = db.conn() else { return false };
        c.query_one(
            "SELECT EXISTS (SELECT 1 FROM jobs WHERE session_id = $1 AND state = 'running')",
            &[&session],
        )
        .map(|r| r.get::<_, bool>(0))
        .unwrap_or(false)
    }

    /// a running job whose holder stopped renewing, now this replica's (None: none)
    pub fn job_claim_expired(&self) -> Result<Option<JobRow>> {
        let mut c = self.pool()?.conn()?;
        let row = c.query_opt(
            "UPDATE jobs SET owner = $1, lease_until = now() + $2::text::interval, attempts = attempts + 1, updated_at = now()
             WHERE id = (SELECT id FROM jobs WHERE state = 'running' AND lease_until < now() ORDER BY lease_until FOR UPDATE SKIP LOCKED LIMIT 1)
             RETURNING id, session_id, kind, args::text, created_at",
            &[&router_id(), &lease_interval()],
        )?;
        Ok(row.map(|row| {
            let args: String = row.get(3);
            let since: time::OffsetDateTime = row.get(4);
            JobRow {
                id: row.get(0),
                session: row.get(1),
                kind: row.get(2),
                args: serde_json::from_str(&args).unwrap_or(Value::Null),
                since: GoTime(Some(since)),
            }
        }))
    }

    /// every few seconds, jobs whose holder died are carried on here
    pub fn jobs_loop(self: &Arc<Self>, every: Duration) {
        loop {
            std::thread::sleep(every);
            self.jobs_tick();
        }
    }

    pub fn jobs_tick(self: &Arc<Self>) {
        loop {
            match self.job_claim_expired() {
                Err(e) => {
                    crate::logf!("jobs: {e:#}");
                    return;
                }
                Ok(None) => return,
                Ok(Some(j)) => self.carry_on(&j),
            }
        }
    }

    /// a job another replica held when it died
    pub fn carry_on(self: &Arc<Self>, j: &JobRow) {
        let end = self.job_hold(&j.id);
        let s = self
            .st
            .do_(|d| d.sessions.get(&j.session).cloned())
            .unwrap_or_default();
        crate::logf!(
            "jobs: carrying on {} of session {} (its holder stopped renewing)",
            j.kind,
            j.session
        );
        let unlock = self.job_unlock(&j.session, &j.kind, end.clone());
        // what lock_args kept for the job: {restart} | {mode} | {store, harness, continue} | {force}
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Args {
            restart: bool,
            mode: String,
            store: String,
            harness: String,
            #[serde(rename = "continue")]
            continue_: bool,
            force: bool,
        }
        let a: Args = serde_json::from_value(j.args.clone()).unwrap_or_default();
        let (r, sid) = (self.clone(), j.session.clone());
        if s.id.is_empty() {
            unlock.call();
        } else if j.kind == "pausing" && s.state == "pausing" && !s.machine_id.is_empty() {
            let op = self.lc_begin(&j.session, "pause");
            op.machine(&s.machine_id);
            op.note("", "carried on by another router replica: its holder stopped (the pause runs again from the snapshot)");
            let m = s.machine_id.clone();
            std::thread::spawn(move || r.pause_run(&sid, &m, None, a.restart, unlock, op));
        } else if j.kind == "starting" && s.kernel.is_some() {
            std::thread::spawn(move || r.kernel_continue(&sid, unlock));
        } else if j.kind == "mode" && s.state == "started" {
            let Ok(wj) = self.ops.start_job(&j.session, "permission-mode") else {
                unlock.call();
                return;
            };
            std::thread::spawn(move || r.mode_run(&sid, &a.mode, wj, unlock));
        } else if j.kind == "account" && s.state == "started" {
            let Ok(wj) = self.ops.start_job(&j.session, "account") else {
                unlock.call();
                return;
            };
            // the account is already the session's (set before the job began): the machine is told again and its
            // switch is checked as a fresh one (what ran before isn't known here)
            self.send(&s.machine_id, "claude-account");
            let m = s.machine_id.clone();
            std::thread::spawn(move || {
                let _u = crate::flows::scopeguard(move || unlock.call());
                let Some(to) = r.accounts().hub(&a.store) else {
                    r.ops.phase(
                        &wj,
                        "failed",
                        Some(&anyhow!("no Claude account {}", a.store)),
                    );
                    return;
                };
                match r.run_account_switch(
                    &wj,
                    &sid,
                    &m,
                    &a.harness,
                    Registry::default(),
                    &to,
                    a.continue_,
                ) {
                    Err(e) => r.ops.phase(&wj, "failed", Some(&e)),
                    Ok(()) => r.ops.phase(&wj, "done", None),
                }
            });
        } else if j.kind == "destroying" && s.state == "destroying" {
            let op = self.lc_begin(&j.session, "destroy");
            op.machine(&s.machine_id);
            op.note(
                "",
                "carried on by another router replica: its holder stopped (the destroy runs again)",
            );
            let o = DestroyOpts {
                force: a.force,
                ..Default::default()
            };
            std::thread::spawn(move || r.destroy_run(&sid, s, o, unlock, op));
        } else {
            self.cut_off_session(&j.session);
            end("failed", "cut off: its holder stopped");
            self.ops.set_busy(&j.session, "");
        }
    }

    /// what an action calls when it ends (the job done, the busy mark gone)
    pub fn job_unlock(self: &Arc<Self>, session: &str, kind: &str, end: JobEnd) -> OnceFn {
        self.ops.set_busy(session, kind);
        let (r, session) = (self.clone(), session.to_string());
        OnceFn::new(move || {
            r.ops.set_busy(&session, "");
            if crate::state::STATE_WRITE_FAILING.load(Ordering::SeqCst) {
                // a do_ gave up (state.rs): this job's last change may be lost, so it isn't marked done; its lease
                // lapses and a replica carries it on
                end("abandoned", "");
                return;
            }
            end("done", "");
        })
    }

    /// the jobs this replica holds now
    pub fn my_running_jobs(&self) -> i64 {
        let Ok(db) = self.pool() else { return 0 };
        let Ok(mut c) = db.conn() else { return 0 };
        c.query_one(
            "SELECT count(*) FROM jobs WHERE owner = $1 AND state = 'running'",
            &[&router_id()],
        )
        .map(|r| r.get::<_, i64>(0))
        .unwrap_or(0)
    }
}
