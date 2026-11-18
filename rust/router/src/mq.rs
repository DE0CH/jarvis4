//! The machines' queue in the database (docs/STATE.md 5, step 6): what waits for a machine (a supervisor command, a
//! holder-signed exec, an attested delivery) is a row of machine_queue; the machine's long poll (GET /m/commands) takes
//! the oldest untaken row (FOR UPDATE SKIP LOCKED: two polls never take the same one) on whichever replica it reaches,
//! and an exec's or a delivery's answer comes back on that row. Waiting is LISTEN/NOTIFY on one channel, mq (payload
//! m:<machine> for a new row, a:<ref> for an answer, w:<machine> for a snapshot wait, l:<name> for a login document),
//! with a short poll beside it so a lost notification only delays.

use fallible_iterator::FallibleIterator as _;
use crate::ctx::Ctx;
use crate::router::Router;
use anyhow::{Result, anyhow};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// how often a waiter looks again without a notification, in ms (tests shorten it)
pub static MQ_RECHECK_MS: AtomicU64 = AtomicU64::new(2000);

fn mq_recheck() -> Duration {
    Duration::from_millis(MQ_RECHECK_MS.load(Ordering::Relaxed))
}

/// one waiter's mailbox: set by a notification, taken by the waiter
#[derive(Default)]
struct Slot {
    fired: Mutex<bool>,
    cv: Condvar,
}

impl Slot {
    fn fire(&self) {
        *self.fired.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.cv.notify_all();
    }
}

/// this replica's waiters, woken by the database's notifications
#[derive(Default)]
pub struct Broker {
    subs: Mutex<BTreeMap<String, Vec<(u64, Arc<Slot>)>>>,
    next: AtomicU64,
}

/// a subscription; it ends when dropped
pub struct Sub {
    broker: Arc<Broker>,
    key: String,
    id: u64,
    slot: Arc<Slot>,
}

impl Sub {
    /// waits until a notification came (since the last wait) or d passed → whether one came
    pub fn recv_timeout(&self, d: Duration) -> bool {
        let end = Instant::now() + d;
        let mut g = self.slot.fired.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if *g {
                *g = false;
                return true;
            }
            let now = Instant::now();
            if now >= end {
                return false;
            }
            g = self
                .slot
                .cv
                .wait_timeout(g, end - now)
                .map(|(g, _)| g)
                .unwrap_or_else(|e| e.into_inner().0);
        }
    }
}

impl Drop for Sub {
    fn drop(&mut self) {
        let mut g = self.broker.subs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(v) = g.get_mut(&self.key) {
            v.retain(|(id, _)| *id != self.id);
            if v.is_empty() {
                g.remove(&self.key);
            }
        }
    }
}

impl Broker {
    pub fn sub(self: &Arc<Self>, key: &str) -> Sub {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let slot = Arc::new(Slot::default());
        self.subs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.to_string())
            .or_default()
            .push((id, slot.clone()));
        Sub { broker: self.clone(), key: key.to_string(), id, slot }
    }

    pub fn fire(&self, key: &str) {
        let g = self.subs.lock().unwrap_or_else(|e| e.into_inner());
        for (_, s) in g.get(key).into_iter().flatten() {
            s.fire();
        }
    }

    pub fn fire_all(&self) {
        let g = self.subs.lock().unwrap_or_else(|e| e.into_inner());
        for (_, s) in g.values().flatten() {
            s.fire();
        }
    }
}

/// LISTEN mq on a connection of its own, for the life of the database (reconnecting; every waiter looks again after a
/// reconnect, since notifications in between are lost)
pub fn listen_loop(url: &str, done: &AtomicBool, b: &Broker) {
    while !done.load(Ordering::SeqCst) {
        let res = (|| -> Result<()> {
            let mut c = crate::db::connect_one(url)?;
            c.batch_execute("LISTEN mq")?;
            b.fire_all();
            loop {
                if done.load(Ordering::SeqCst) {
                    return Ok(());
                }
                {
                    let mut n = c.notifications();
                    let mut it = n.timeout_iter(Duration::from_secs(1));
                    while let Some(note) = it.next()? {
                        b.fire(note.payload());
                    }
                }
                if c.is_closed() {
                    return Err(anyhow!("the connection closed"));
                }
            }
        })();
        if done.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
        if let Err(e) = res {
            crate::logf!("mq: listening: {e:#} (again)");
        }
    }
}

/// one taken row
#[derive(Debug, Clone)]
pub struct MqItem {
    pub kind: String,
    pub body: Vec<u8>,
}

impl Router {
    fn mq_db(&self) -> Result<&crate::db::DB> {
        self.st.db().ok_or_else(|| anyhow!("the machines' queue needs the database"))
    }

    /// a row for the machine (bounded: at most max untaken of its kind; 0 = no bound) → false when full
    pub fn mq_put(&self, machine: &str, kind: &str, r#ref: &str, body: &Value, max: i64) -> Result<bool> {
        let b = jarvis_go::marshal(body);
        let mut c = self.mq_db()?.conn()?;
        let mut tx = c.transaction()?;
        if max > 0 {
            let n: i64 = tx
                .query_one(
                    "SELECT count(*) FROM machine_queue WHERE machine_id = $1 AND kind = $2 AND taken_at IS NULL",
                    &[&machine, &kind],
                )?
                .get(0);
            if n >= max {
                return Ok(false);
            }
        }
        tx.execute(
            "INSERT INTO machine_queue (machine_id, kind, ref, body) VALUES ($1, $2, $3, $4::text::jsonb)",
            &[&machine, &kind, &r#ref, &b],
        )?;
        tx.execute("SELECT pg_notify('mq', $1)", &[&format!("m:{machine}")])?;
        tx.commit()?;
        Ok(true)
    }

    /// the machine's oldest untaken row (None: none)
    pub fn mq_take(&self, machine: &str) -> Result<Option<MqItem>> {
        let mut c = self.mq_db()?.conn()?;
        let row = c.query_opt(
            "UPDATE machine_queue SET taken_at = now() WHERE id = (SELECT id FROM machine_queue
             WHERE machine_id = $1 AND taken_at IS NULL ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING kind, body::text",
            &[&machine],
        )?;
        Ok(row.map(|r| MqItem { kind: r.get(0), body: r.get::<_, String>(1).into_bytes() }))
    }

    /// the machine's next row, waiting up to wait (None: none came)
    pub fn mq_next(&self, ctx: &Ctx, machine: &str, wait: Duration) -> Result<Option<MqItem>> {
        let sub = self.notes.sub(&format!("m:{machine}"));
        let end = Instant::now() + wait;
        loop {
            if let Some(it) = self.mq_take(machine)? {
                return Ok(Some(it));
            }
            let now = Instant::now();
            if now >= end {
                return Ok(None);
            }
            if ctx.cancelled() {
                return Err(anyhow!("context canceled"));
            }
            sub.recv_timeout(mq_recheck().min(end - now));
        }
    }

    /// the answer to a row (by its ref), for whoever waits for it
    pub fn mq_answer(&self, r#ref: &str, answer: &Value) -> Result<()> {
        if r#ref.is_empty() {
            return Err(anyhow!("no ref"));
        }
        let b = jarvis_go::marshal(answer);
        let mut c = self.mq_db()?.conn()?;
        let mut tx = c.transaction()?;
        tx.execute(
            "UPDATE machine_queue SET answered_at = now(), answer = $2::text::jsonb WHERE ref = $1 AND answered_at IS NULL",
            &[&r#ref, &b],
        )?;
        tx.execute("SELECT pg_notify('mq', $1)", &[&format!("a:{}", r#ref)])?;
        tx.commit()?;
        Ok(())
    }

    /// the answer to the row ref, waiting up to wait (None: none came); done: stop early
    pub fn mq_await(&self, r#ref: &str, wait: Duration, done: Option<&Ctx>) -> Result<Option<Vec<u8>>> {
        let sub = self.notes.sub(&format!("a:{}", r#ref));
        let end = Instant::now() + wait;
        loop {
            let row = self.mq_db()?.conn()?.query_opt(
                "SELECT answer::text FROM machine_queue WHERE ref = $1 AND answered_at IS NOT NULL",
                &[&r#ref],
            )?;
            if let Some(row) = row {
                return Ok(Some(row.get::<_, Option<String>>(0).unwrap_or_else(|| "null".into()).into_bytes()));
            }
            let now = Instant::now();
            if now >= end || done.is_some_and(Ctx::cancelled) {
                return Ok(None);
            }
            sub.recv_timeout(mq_recheck().min(end - now));
        }
    }

    /// the row ref gone (its caller stopped waiting: a later answer has nobody to go to)
    pub fn mq_forget(&self, r#ref: &str) {
        if let Ok(db) = self.mq_db()
            && let Ok(mut c) = db.conn()
        {
            let _ = c.execute("DELETE FROM machine_queue WHERE ref = $1", &[&r#ref]);
        }
    }

    /// rows older than a day go (taken or not: a machine that never polled is long gone)
    pub fn mq_sweep_loop(self: &Arc<Self>) {
        loop {
            std::thread::sleep(Duration::from_secs(3600));
            crate::leaderlease::await_lead();
            if let Ok(db) = self.mq_db()
                && let Ok(mut c) = db.conn()
            {
                let _ = c.execute("DELETE FROM machine_queue WHERE created_at < now() - interval '1 day'", &[]);
            }
        }
    }
}
