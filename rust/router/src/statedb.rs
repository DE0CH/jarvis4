//! The router's records in Postgres (docs/STATE.md step 3). The router holds them in memory under one lock
//! (State::do_), loaded from the database at start; after every Do the records its closure changed are written in one
//! transaction: each record is marshalled, compared with what the database last took, and only the differences go
//! (upserts and deletes).
//!
//! Several replicas: every Do takes the state_version row, and a replica whose copy is older reads again only the
//! records the others changed since (catch_up, from the state_changes list every write adds to), never all of them
//! unless a version's changes aren't listed. A fn that only looks is a Read (state.rs): no marshal, no write.
//!
//! Where each field of Persisted goes: a map → its table, one row per key; records → records, one row per position;
//! anything else → a settings row named "state.<its JSON key>" (`persisted_fields!` below). The Go router's one-time
//! imports of state.json and the volume's files ran in production long ago and aren't carried over.

use crate::db::DB;
use crate::state::{Persisted, State, StateInner};
use anyhow::{Context, Result};
use jarvis_go::GoTime;
use postgres::GenericClient;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::Instant;

/// what the database holds (or is about to): table ("" = settings) → id → the record's JSON
pub type Rows = BTreeMap<String, BTreeMap<String, String>>;

/// the state_changes row every version has (tbl); how many versions back the table goes; the most records a
/// catch-up reads one by one
const CHANGES_MARKER: &str = "*";
const CHANGES_KEPT: i64 = 5000;
const CATCH_UP_MOST: usize = 2000;

fn enc<T: serde::Serialize>(v: &T) -> String {
    jarvis_go::marshal(v)
}

fn dec<T: serde::de::DeserializeOwned>(what: &str, id: &str, b: &str) -> Result<T> {
    jarvis_go::unmarshal(b.as_bytes()).with_context(|| format!("{what} {id}"))
}

/// a settings field's zero value has no row (omitempty in state.json)
pub trait SettingZero {
    fn is_zero(&self) -> bool;
}

impl<T> SettingZero for Option<T> {
    fn is_zero(&self) -> bool {
        self.is_none()
    }
}

impl SettingZero for String {
    fn is_zero(&self) -> bool {
        self.is_empty()
    }
}

/// Persisted's fields: (field, JSON key, table or "" for a settings row). The records list is apart.
macro_rules! persisted_fields {
    (maps: [$($mf:ident = $mkey:literal => $mtable:literal),* $(,)?], settings: [$($sf:ident = $skey:literal),* $(,)?]) => {
        /// persisted's JSON key → its table (maps; and records)
        pub const STATE_TABLES: &[(&str, &str)] = &[$(($mkey, $mtable),)* ("records", "records")];

        pub fn init_maps(_d: &mut Persisted) {}

        /// d as rows
        pub fn rows_of(d: &Persisted) -> Rows {
            let mut out = Rows::new();
            out.insert(String::new(), BTreeMap::new());
            $(
                out.insert($mtable.to_string(), d.$mf.iter().map(|(k, v)| (k.clone(), enc(v))).collect());
            )*
            out.insert("records".into(), records_rows(d));
            $(
                if !SettingZero::is_zero(&d.$sf) {
                    if let Some(m) = out.get_mut("") {
                        m.insert(concat!("state.", $skey).to_string(), enc(&d.$sf));
                    }
                }
            )*
            out
        }

        /// the records as the database has them
        pub fn load(q: &mut impl GenericClient, d: &mut Persisted) -> Result<()> {
            let mut settings: BTreeMap<String, String> = BTreeMap::new();
            for r in q.query("SELECT key, value::text FROM settings WHERE key LIKE 'state.%'", &[])? {
                settings.insert(r.get(0), r.get(1));
            }
            $(
                d.$mf = BTreeMap::new();
                for r in q.query(concat!("SELECT id, doc::text FROM ", $mtable), &[])? {
                    let (id, b): (String, String) = (r.get(0), r.get(1));
                    let v = dec($mtable, &id, &b)?;
                    d.$mf.insert(id, v);
                }
            )*
            load_records(q, d)?;
            $(
                d.$sf = match settings.get(concat!("state.", $skey)) {
                    Some(b) => dec("settings", concat!("state.", $skey), b)?,
                    None => Default::default(),
                };
            )*
            Ok(())
        }

        /// the changed rows of one table (or the settings rows ids) read again into d and w
        fn catch_up_table(q: &mut impl GenericClient, d: &mut Persisted, w: &mut Rows, table: &str, ids: &[String]) -> Result<()> {
            match table {
                $(
                    $mtable => {
                        let mut found = BTreeSet::new();
                        for r in q.query(concat!("SELECT id, doc::text FROM ", $mtable, " WHERE id = ANY($1)"), &[&ids])? {
                            let (id, b): (String, String) = (r.get(0), r.get(1));
                            let v = dec($mtable, &id, &b)?;
                            w.entry(table.to_string()).or_default().insert(id.clone(), enc(&v));
                            d.$mf.insert(id.clone(), v);
                            found.insert(id);
                        }
                        for id in ids {
                            if !found.contains(id) {
                                d.$mf.remove(id);
                                if let Some(m) = w.get_mut(table) {
                                    m.remove(id);
                                }
                            }
                        }
                    }
                )*
                "records" => {
                    load_records(q, d)?;
                    w.insert("records".into(), records_rows(d));
                }
                "" => {
                    for id in ids {
                        let row = q.query_opt("SELECT value::text FROM settings WHERE key = $1", &[id])?;
                        let b: Option<String> = row.map(|r| r.get(0));
                        match id.as_str() {
                            $(
                                concat!("state.", $skey) => {
                                    d.$sf = match &b {
                                        Some(b) => dec("settings", id, b)?,
                                        None => Default::default(),
                                    };
                                    let m = w.entry(String::new()).or_default();
                                    if b.is_some() { m.insert(id.clone(), enc(&d.$sf)); } else { m.remove(id); }
                                }
                            )*
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
            Ok(())
        }
    };
}

persisted_fields! {
    maps: [
        sessions = "sessions" => "sessions",
        approvals = "approvals" => "approvals",
        started = "started" => "machines",
        certs = "certs" => "machine_certs",
        machines = "machines" => "machine_sessions",
        sess_certs = "sessionCerts" => "session_certs",
        grants = "grants" => "grants",
        schedules = "schedules" => "schedules",
        devices = "devices" => "devices",
        uploads = "uploads" => "uploads",
        inbox = "inbox" => "inbox",
        batches = "batches" => "batches",
        call_results = "callResults" => "call_results",
        outcomes = "outcomes" => "outcomes",
        messages = "messages" => "messages",
        message_rules = "messageRules" => "message_rules",
    ],
    settings: [
        budget = "budget",
        bb_budget = "bbBudget",
        tasks = "tasks",
        core_key = "coreKey",
        leases = "leases",
        active_core = "activeCore",
        kernel_root = "kernelRoot",
        kernel_copy = "kernelCopy",
        kernel_root_key = "kernelRootKey",
        kernel_roster_pending = "kernelRosterPending",
        kernel_roster = "kernelRoster",
        kernel_roster_next = "kernelRosterNext",
        kernel_flip = "kernelFlip",
    ]
}

fn records_rows(d: &Persisted) -> BTreeMap<String, String> {
    d.records
        .iter()
        .enumerate()
        .map(|(i, r)| (i.to_string(), enc(r)))
        .collect()
}

fn load_records(q: &mut impl GenericClient, d: &mut Persisted) -> Result<()> {
    d.records = vec![];
    for r in q.query("SELECT doc::text FROM records ORDER BY ord", &[])? {
        let b: String = r.get(0);
        d.records.push(dec("records", "", &b)?);
    }
    Ok(())
}

/// as reload: a session's cert is its session_certs row
fn attach_certs(d: &mut Persisted) {
    for (id, s) in d.sessions.iter_mut() {
        s.cert = d.sess_certs.get(id).cloned();
    }
}

/// the database side of State
pub struct StateDB {
    pub db: DB,
    err: Mutex<Option<(String, GoTime)>>,
}

impl StateDB {
    pub fn new(db: DB) -> StateDB {
        StateDB {
            db,
            err: Mutex::new(None),
        }
    }

    pub fn last_error(&self) -> Option<(String, GoTime)> {
        self.err.lock().ok().and_then(|g| g.clone())
    }

    /// a read-only snapshot transaction: the copy brought up to the database's version → whether it is now
    pub(crate) fn read_tx(&self, g: &mut StateInner) -> Result<bool> {
        let mut c = self.db.conn()?;
        let mut tx = c
            .build_transaction()
            .isolation_level(postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()?;
        let ver: i64 = tx.query_one("SELECT v FROM state_version WHERE id = 1", &[])?.get(0);
        if ver == g.ver {
            return Ok(true);
        }
        let t = Instant::now();
        let from = g.ver;
        if !catch_up(&mut tx, g, from, ver)? {
            return Ok(false);
        }
        g.ver = ver;
        g.load.catch_ups += 1;
        g.load.reload += t.elapsed();
        tx.commit()?;
        Ok(true)
    }

    pub(crate) fn do_once(&self, g: &mut StateInner, f: &mut dyn FnMut(&mut Persisted)) -> Result<()> {
        let r = (|| -> Result<(Rows, i64)> {
            let mut c = self.db.conn()?;
            let mut tx = c.transaction()?;
            let t = Instant::now();
            let mut ver: i64 = tx
                .query_one("SELECT v FROM state_version WHERE id = 1 FOR UPDATE", &[])?
                .get(0);
            g.load.row_lock += t.elapsed();
            if ver != g.ver {
                let t = Instant::now();
                let from = g.ver;
                if catch_up(&mut tx, g, from, ver)? {
                    g.load.catch_ups += 1;
                } else {
                    reload(&mut tx, g)?;
                    g.load.reloads += 1;
                }
                g.ver = ver;
                g.load.reload += t.elapsed();
            }
            f(&mut g.data);
            let d = &mut g.data;
            d.sess_certs = d
                .sessions
                .iter()
                .filter_map(|(id, s)| s.cert.clone().map(|c| (id.clone(), c)))
                .collect();
            let t = Instant::now();
            let (now, changed) = write_tx(&mut tx, &g.written, &g.data, ver + 1)?;
            g.load.write += t.elapsed();
            g.load.note(&now);
            if changed {
                g.load.writes += 1;
                ver = tx
                    .query_one("UPDATE state_version SET v = v + 1 WHERE id = 1 RETURNING v", &[])?
                    .get(0);
            }
            tx.commit()?;
            Ok((now, ver))
        })();
        let mut e = self.err.lock().unwrap_or_else(|e| e.into_inner());
        match r {
            Err(err) => {
                g.ver = -1; // the copy here may hold what the database refused: read again next time
                let since = e.as_ref().map(|x| x.1).unwrap_or_else(GoTime::now);
                *e = Some((format!("{err:#}"), since));
                Err(err)
            }
            Ok((written, ver)) => {
                g.written = written;
                g.ver = ver;
                if let Some((_, since)) = e.take() {
                    crate::logf!(
                        "state: writes go through again (they failed since {})",
                        since.rfc3339()
                    );
                }
                Ok(())
            }
        }
    }
}

/// the differences between d and what the database holds, queued on tx → the rows as they are now, and whether
/// anything changed
fn write_tx(
    tx: &mut postgres::Transaction<'_>,
    old: &Rows,
    d: &Persisted,
    next: i64,
) -> Result<(Rows, bool)> {
    let now = rows_of(d);
    let mut any = false;
    let empty = BTreeMap::new();
    for (table, m) in &now {
        let o = old.get(table).unwrap_or(&empty);
        let dels: Vec<String> = o.keys().filter(|id| !m.contains_key(*id)).cloned().collect();
        if !dels.is_empty() {
            any = true;
            match table.as_str() {
                "" => tx.execute("DELETE FROM settings WHERE key = ANY($1)", &[&dels])?,
                "records" => {
                    let ords: Vec<i32> = dels.iter().filter_map(|x| x.parse().ok()).collect();
                    tx.execute("DELETE FROM records WHERE ord = ANY($1)", &[&ords])?
                }
                t => tx.execute(&format!("DELETE FROM {t} WHERE id = ANY($1)"), &[&dels])?,
            };
        }
        let mut touched = vec![];
        for (id, doc) in m {
            if o.get(id) == Some(doc) {
                continue;
            }
            any = true;
            touched.push(id.clone());
            match table.as_str() {
                "" => tx.execute(
                    "INSERT INTO settings (key, value, updated_at) VALUES ($1, $2::text::jsonb, now()) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = now()",
                    &[id, doc],
                )?,
                "records" => {
                    let ord: i32 = id.parse().unwrap_or(0);
                    tx.execute(
                        "INSERT INTO records (ord, doc) VALUES ($1, $2::text::jsonb) ON CONFLICT (ord) DO UPDATE SET doc = excluded.doc",
                        &[&ord, doc],
                    )?
                }
                t => tx.execute(
                    &format!("INSERT INTO {t} (id, doc) VALUES ($1, $2::text::jsonb) ON CONFLICT (id) DO UPDATE SET doc = excluded.doc"),
                    &[id, doc],
                )?,
            };
        }
        touched.extend(dels);
        if !touched.is_empty() {
            // what the other replicas read again (catch_up)
            tx.execute(
                "INSERT INTO state_changes (v, tbl, id) SELECT $1, $2, unnest($3::text[])",
                &[&next, table, &touched],
            )?;
        }
    }
    if !any {
        return Ok((now, false));
    }
    tx.execute(
        "INSERT INTO state_changes (v, tbl, id) VALUES ($1, $2, '')",
        &[&next, &CHANGES_MARKER],
    )?;
    tx.execute(
        "DELETE FROM state_changes WHERE v <= $1",
        &[&(next - CHANGES_KEPT)],
    )?;
    Ok((now, true))
}

/// The records another replica changed between versions from (this copy's) and to (the database's), read again in
/// place. false: not every version in between listed its changes, or too many to be worth it: the caller reloads
/// everything.
fn catch_up(q: &mut impl GenericClient, g: &mut StateInner, from: i64, to: i64) -> Result<bool> {
    if from < 0 || to <= from || to - from > CHANGES_KEPT {
        return Ok(false);
    }
    let mut marked = BTreeSet::new();
    let mut changed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut n = 0;
    for r in q.query(
        "SELECT v, tbl, id FROM state_changes WHERE v > $1 AND v <= $2",
        &[&from, &to],
    )? {
        let (v, tbl, id): (i64, String, String) = (r.get(0), r.get(1), r.get(2));
        if tbl == CHANGES_MARKER {
            marked.insert(v);
            continue;
        }
        if changed.entry(tbl).or_default().insert(id) {
            n += 1;
        }
    }
    if marked.len() as i64 != to - from || n > CATCH_UP_MOST {
        return Ok(false);
    }
    for (table, ids) in changed {
        let ids: Vec<String> = ids.into_iter().collect();
        catch_up_table(q, &mut g.data, &mut g.written, &table, &ids)?;
    }
    attach_certs(&mut g.data);
    Ok(true)
}

/// the records as the database has them now (another replica changed them)
fn reload(q: &mut impl GenericClient, g: &mut StateInner) -> Result<()> {
    let mut d = Persisted::default();
    load(q, &mut d)?;
    attach_certs(&mut d);
    g.written = rows_of(&d);
    g.data = d;
    Ok(())
}

impl State {
    /// the records from the database, the snapshots directory under dir
    pub fn open(db: DB, dir: &std::path::Path, seal: Option<crate::sealed::Sealer>) -> Result<State> {
        std::fs::create_dir_all(dir)?;
        let s = State {
            inner: Mutex::new(StateInner {
                data: Persisted::default(),
                written: Rows::new(),
                ver: -1,
                load: Default::default(),
            }),
            dir: dir.to_path_buf(),
            sdb: Some(StateDB::new(db)),
            seal,
            on_failed: Mutex::new(None),
        };
        s.reseal_old()?;
        {
            let sdb = s.sdb.as_ref().context("no database")?;
            let mut c = sdb.db.conn()?;
            let mut g = s.inner.lock().unwrap_or_else(|e| e.into_inner());
            reload(&mut *c, &mut g)?;
        }
        Ok(s)
    }

    // ---- the router's small documents (docs/STATE.md step 4) -------------------------------------------------------

    /// the document, and whether there is one (a database error reads as none, and is logged)
    pub fn read_doc(&self, name: &str) -> Option<Vec<u8>> {
        let db = self.db()?;
        let r = (|| -> Result<Option<Vec<u8>>> {
            let mut c = db.conn()?;
            Ok(c.query_opt("SELECT body FROM router_docs WHERE name = $1", &[&name])?
                .map(|r| r.get(0)))
        })();
        match r {
            Ok(b) => b,
            Err(e) => {
                crate::logf!("docs: reading {name}: {e:#}");
                None
            }
        }
    }

    /// the document replaced
    pub fn write_doc(&self, name: &str, b: &[u8]) -> Result<()> {
        let db = self.db().context("docs: no database")?;
        let mut c = db.conn()?;
        c.execute(
            "INSERT INTO router_docs (name, body, updated_at) VALUES ($1, $2, now())
		ON CONFLICT (name) DO UPDATE SET body = excluded.body, updated_at = now()",
            &[&name, &b],
        )?;
        Ok(())
    }

    /// the document gone
    pub fn delete_doc(&self, name: &str) {
        let Some(db) = self.db() else { return };
        let r = db
            .conn()
            .and_then(|mut c| Ok(c.execute("DELETE FROM router_docs WHERE name = $1", &[&name])?));
        if let Err(e) = r {
            crate::logf!("docs: deleting {name}: {e:#}");
        }
    }
}
