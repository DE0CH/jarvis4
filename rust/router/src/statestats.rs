//! What the Do's cost, said once a minute in the log ("state: last minute: …"). Every Do of every replica takes the
//! same lock and, as built, reads the records again after another replica's change and marshals all of them to find
//! its own: when the Do's of a minute take about a minute between them, every request waits its turn (2026-11-17: an
//! approval's signature timed out on the phone, with nothing in the log to say why).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// how often the load is said (ms; tests shorten it)
pub static DO_LOAD_EVERY_MS: AtomicU64 = AtomicU64::new(60_000);

/// how many callers the line names (the ones that held the lock longest)
const DO_LOAD_TOP: usize = 8;

#[derive(Debug, Default, Clone)]
pub struct DoCost {
    pub n: usize,
    pub held: Duration,
}

/// the Do's since `since` (all under the State's lock)
#[derive(Debug, Default, Clone)]
pub struct DoLoad {
    pub since: Option<Instant>,
    pub n: usize,
    /// of n: Reads (nothing marshalled or written, the other replicas not waited for)
    pub reads: usize,
    /// asking → holding this replica's lock, in all
    pub waited: Duration,
    pub max_wait: Duration,
    /// holding this replica's lock, in all
    pub held: Duration,
    /// of held: waiting for the other replicas (the state_version row)
    pub row_lock: Duration,
    /// all the records read again
    pub reloads: usize,
    /// only the records another replica changed read again (statedb.rs catch_up)
    pub catch_ups: usize,
    /// of held: reading the records again
    pub reload: Duration,
    pub writes: usize,
    /// of held: marshalling the records and writing what changed
    pub write: Duration,
    pub rows: usize,
    pub bytes: usize,
    /// the line that asked → its Do's
    pub by: BTreeMap<String, DoCost>,
}

impl DoLoad {
    /// the size of the records as they were just marshalled
    pub fn note(&mut self, now: &crate::statedb::Rows) {
        self.rows = now.values().map(|m| m.len()).sum();
        self.bytes = now.values().flat_map(|m| m.values()).map(|d| d.len()).sum();
    }

    /// one Do asked for at `asked` that got the lock at `got` has ended
    pub fn done(&mut self, who: &str, asked: Instant, got: Instant) {
        let end = Instant::now();
        let c = self.by.entry(who.to_string()).or_default();
        c.n += 1;
        c.held += end - got;
        let since = *self.since.get_or_insert(asked);
        self.n += 1;
        let w = got - asked;
        self.waited += w;
        self.max_wait = self.max_wait.max(w);
        self.held += end - got;
        if end - since < Duration::from_millis(DO_LOAD_EVERY_MS.load(Ordering::Relaxed)) {
            return;
        }
        crate::logf!("{}", self.line(end));
        *self = DoLoad {
            since: Some(end),
            rows: self.rows,
            bytes: self.bytes,
            ..Default::default()
        };
    }

    pub fn line(&self, end: Instant) -> String {
        let ms = |d: Duration| d.as_millis();
        let span = self.since.map(|s| end - s).unwrap_or_default();
        format!(
            "state: last {}: {} changes asked for ({} of them only reads), holding the lock {} ms in all ({} ms of it waiting for the other replicas, \
{} reloads and {} catch-ups {} ms, {} writes and every marshal {} ms); they waited {} ms in all for it here, the longest {} ms; \
the records are {} rows, {} bytes; asked most by {}",
            jarvis_go::fmt::duration_string(Duration::from_secs(span.as_secs_f64().round() as u64)),
            self.n,
            self.reads,
            ms(self.held),
            ms(self.row_lock),
            self.reloads,
            self.catch_ups,
            ms(self.reload),
            self.writes,
            ms(self.write),
            ms(self.waited),
            ms(self.max_wait),
            self.rows,
            self.bytes,
            self.top()
        )
    }

    /// the callers that held the lock longest ("autopilot.rs:88 ×120 3400 ms, …")
    pub fn top(&self) -> String {
        let mut who: Vec<(&String, &DoCost)> = self.by.iter().collect();
        who.sort_by(|a, b| b.1.held.cmp(&a.1.held).then(a.0.cmp(b.0)));
        who.truncate(DO_LOAD_TOP);
        who.iter()
            .map(|(w, c)| format!("{w} ×{} {} ms", c.n, c.held.as_millis()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}
