//! The scheduler lease (docs/STATE.md 4, step 8): the periodic loops (wakeups and crons, leases, watches, the budget
//! caps, the Inbox and outcomes, messages, tasks, the Claude logins' refresh, the volume sweep, Discord, the
//! autopilot, the roster, the next core, the queue sweep) run on one replica only: the one holding the row `scheduler`
//! of `leader`, taken for 30 s and renewed every 10 s. Each loop waits at the top of every round until this replica
//! leads (await_lead). A replica that loses the database stops leading when its last renewal runs out (5 s before the
//! row's, so two never lead at once). Jobs (jobs.rs) and the machines' long polls run on every replica.

use crate::router::{Router, router_id};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

const LEASE_FOR: Duration = Duration::from_secs(30);
const LEASE_RENEW: Duration = Duration::from_secs(10);
const LEASE_SAFE: Duration = Duration::from_secs(5);

/// until when this replica leads (unix nanos; 0: it doesn't)
pub static LEAD_UNTIL: AtomicI64 = AtomicI64::new(0);

fn now_nanos() -> i64 {
    jarvis_go::GoTime::now().unix_nanos() as i64
}

pub fn leads() -> bool {
    now_nanos() < LEAD_UNTIL.load(Ordering::SeqCst)
}

/// tests lead without a database
pub fn lead_for(d: Duration) {
    LEAD_UNTIL.store(now_nanos() + d.as_nanos() as i64, Ordering::SeqCst);
}

impl Router {
    /// take or renew the lease; whether this replica leads now
    pub fn lease_once(&self) -> bool {
        let start = now_nanos();
        let t0 = Instant::now();
        let res = self.st.db().ok_or_else(|| anyhow::anyhow!("no database")).and_then(|db| {
            let mut c = db.conn()?;
            Ok(c.query_opt(
                "INSERT INTO leader (name, holder, until) VALUES ('scheduler', $1, now() + interval '30 seconds')
                 ON CONFLICT (name) DO UPDATE SET holder = $1, until = excluded.until WHERE leader.until < now() OR leader.holder = $1
                 RETURNING holder",
                &[&router_id()],
            )?
            .map(|r| r.get::<_, String>(0)))
        });
        match res {
            Ok(Some(h)) if h == router_id() && t0.elapsed() < LEASE_FOR - LEASE_SAFE => {
                let was = leads();
                LEAD_UNTIL.store(start + (LEASE_FOR - LEASE_SAFE).as_nanos() as i64, Ordering::SeqCst);
                if !was {
                    crate::logf!("leader: this replica ({}) runs the scheduler", router_id());
                }
                true
            }
            Err(e) => {
                if leads() {
                    crate::logf!("leader: renewing: {e:#} (leading until the lease runs out)");
                }
                leads()
            }
            _ => leads(),
        }
    }

    /// the lease, for the life of the process
    pub fn lease_loop_scheduler(&self) {
        loop {
            self.lease_once();
            std::thread::sleep(LEASE_RENEW);
        }
    }

    /// a stopping replica gives the scheduler's lease up at once (another takes it at its next renewal)
    pub fn release_lead(&self) {
        LEAD_UNTIL.store(0, Ordering::SeqCst);
        if let Some(db) = self.st.db()
            && let Ok(mut c) = db.conn()
        {
            let _ = c.execute(
                "UPDATE leader SET until = now() WHERE name = 'scheduler' AND holder = $1",
                &[&router_id()],
            );
        }
    }
}

/// returns once this replica leads (at once when it does)
pub fn await_lead() {
    while !leads() {
        std::thread::sleep(Duration::from_secs(1));
    }
}
