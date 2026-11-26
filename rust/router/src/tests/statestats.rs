//! statestats_test.go (the load line is checked as DoLoad::line writes it: tests can't read the log)
use crate::budget::BudgetState;
use crate::state::{Persisted, Record, Session, State};
use crate::statedb::{CHANGES_KEPT, CHANGES_MARKER, rows_of};
use crate::statestats::DO_LOAD_EVERY_MS;
use crate::testutil::*;
use crate::types::Doc;
use std::time::{Duration, Instant};

/// two replicas on one database
struct Two {
    a: State,
    b: State,
    _db: TestDb,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

fn two() -> Two {
    let db = TestDb::new();
    let (da, dbb) = (
        tempfile::tempdir().unwrap_or_else(|e| panic!("{e}")),
        tempfile::tempdir().unwrap_or_else(|e| panic!("{e}")),
    );
    let a = test_state(&db, da.path());
    let b = test_state(&db, dbb.path());
    Two {
        a,
        b,
        _db: db,
        _dirs: (da, dbb),
    }
}

fn load_of(st: &State) -> crate::statestats::DoLoad {
    st.inner
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .load
        .clone()
}

fn exec(st: &State, sql: &str) {
    let db = st.db().unwrap_or_else(|| panic!("no database"));
    let mut c = db.conn().unwrap_or_else(|e| panic!("{e:#}"));
    c.batch_execute(sql).unwrap_or_else(|e| panic!("{e}"));
}

fn session(id: &str, state: &str) -> Session {
    Session {
        id: id.into(),
        state: state.into(),
        ..Default::default()
    }
}

/// the load says what the Do's cost: how many, the reloads after another replica's change, the size of the records
#[test]
fn state_load_is_logged() {
    let _g = serial(); // DO_LOAD_EVERY_MS
    let tw = two();
    let (a, b) = (&tw.a, &tw.b);
    let every = set_u64(&DO_LOAD_EVERY_MS, 3_600_000);
    a.do_(|d| {
        d.sessions.insert("s1".into(), session("s1", "started"));
    });
    b.do_(|_| {}); // reads a's change first
    b.do_(|_| {});
    let l = load_of(b);
    assert!(
        l.n == 2 && l.reloads == 1 && l.writes == 0 && l.rows == 1 && l.bytes > 0,
        "b's load: {l:?}"
    );
    let line = l.line(Instant::now());
    assert!(
        line.starts_with("state: last ")
            && line.contains("2 changes asked for")
            && line.contains("1 reloads")
            && line.contains("0 writes")
            && line.contains("the records are 1 rows")
            && line.contains("asked most by statestats.rs:"),
        "the line: {line:?}"
    );
    drop(every);
    let _every = set_u64(&DO_LOAD_EVERY_MS, 0);
    b.do_(|d| {
        d.sessions.insert("s2".into(), session("s2", ""));
    });
    assert_eq!(load_of(b).n, 0, "not started again (the line was written)");
}

/// a replica behind reads only what the others changed, and ends with exactly the records a full reload gives: rows
/// added, changed and deleted, the records list, settings set and cleared, a session's cert
#[test]
fn state_catch_up() {
    let _g = serial(); // DO_LOAD_EVERY_MS: another test's 0 resets the counters this one reads
    let tw = two();
    let (a, b) = (&tw.a, &tw.b);
    let same = |what: &str| {
        let got = b.read(rows_of);
        let mut fresh = Persisted::default();
        let db = b.db().unwrap_or_else(|| panic!("no database"));
        let mut c = db.conn().unwrap_or_else(|e| panic!("{e:#}"));
        crate::statedb::load(&mut *c, &mut fresh).unwrap_or_else(|e| panic!("{e:#}"));
        let want = rows_of(&fresh);
        assert_eq!(
            got, want,
            "{what}: the caught-up copy differs from the database's"
        );
        let written = b
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .written
            .clone();
        assert_eq!(
            written, want,
            "{what}: what b takes the database to hold differs"
        );
    };
    let cert = Doc {
        payload: r#"{"kind":"succession-cert"}"#.into(),
        sig: "c2ln".into(),
    };
    b.do_(|_| {}); // b's copy is of a version now
    a.do_(|d| {
        let mut s1 = session("s1", "started");
        s1.cert = Some(cert.clone());
        d.sessions.insert("s1".into(), s1);
        d.sessions.insert("s2".into(), session("s2", "paused"));
        d.machines.insert("m1".into(), "s1".into());
        for id in ["r0", "r1", "r2"] {
            d.records.push(Record {
                session: session(id, ""),
                ..Default::default()
            });
        }
        d.kernel_copy = "green".into();
        d.budget = Some(BudgetState::default());
    });
    a.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.state = "pausing".into();
        }
    });
    same("added");
    b.do_(|d| {
        let s = d.sessions.get("s1").cloned().unwrap_or_default();
        assert!(
            s.state == "pausing"
                && s.cert.as_ref().is_some_and(|c| c.sig == "c2ln")
                && d.kernel_copy == "green"
                && d.records.len() == 3,
            "b after a's changes: {s:?}"
        );
    });
    let l = load_of(b);
    assert!(
        l.catch_ups == 1 && l.reloads == 1, // the one reload: its first Do
        "b caught up {} times and reloaded {} times",
        l.catch_ups,
        l.reloads
    );
    a.do_(|d| {
        d.sessions.remove("s2");
        d.machines.remove("m1");
        if let Some(s) = d.sessions.get_mut("s1") {
            s.cert = None;
        }
        d.records.remove(1);
        d.kernel_copy = String::new();
        d.budget = None;
    });
    same("deleted and cleared");
    b.do_(|d| {
        assert!(
            !d.sessions.contains_key("s2")
                && d.sessions.get("s1").is_some_and(|s| s.cert.is_none())
                && d.records.len() == 2
                && d.records[1].session.id == "r2"
                && d.kernel_copy.is_empty()
                && d.budget.is_none(),
            "b after a's deletes"
        );
    });
    // b's own change after a catch-up writes only that change, and a sees it the same way
    b.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.disk_gb = 7;
        }
    });
    a.do_(|d| {
        assert_eq!(
            d.sessions.get("s1").map(|s| s.disk_gb),
            Some(7),
            "a doesn't see b's change"
        );
    });
    assert_eq!(load_of(a).catch_ups, 1, "a's catch-ups");
    // a version whose changes nobody listed (a router from before state_changes): everything is read again
    let before = load_of(b).reloads;
    exec(
        a,
        r#"UPDATE sessions SET doc = jsonb_set(doc, '{label}', '"old router"') WHERE id = 's1'"#,
    );
    exec(a, "UPDATE state_version SET v = v + 1 WHERE id = 1");
    b.do_(|d| {
        assert_eq!(
            d.sessions.get("s1").map(|s| s.label.clone()).as_deref(),
            Some("old router"),
            "an unlisted change was missed"
        );
    });
    assert_eq!(
        load_of(b).reloads,
        before + 1,
        "an unlisted version was caught up, not reloaded"
    );
    same("after an unlisted version");
    // the list is kept short
    let db = a.db().unwrap_or_else(|| panic!("no database"));
    let mut c = db.conn().unwrap_or_else(|e| panic!("{e:#}"));
    let n: i64 = c
        .query_one(
            "SELECT count(*) FROM state_changes WHERE tbl = $1",
            &[&CHANGES_MARKER],
        )
        .map(|r| r.get(0))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(n > 0 && n <= CHANGES_KEPT, "{n} versions listed");
}

fn version(st: &State) -> i64 {
    let db = st.db().unwrap_or_else(|| panic!("no database"));
    let mut c = db.conn().unwrap_or_else(|e| panic!("{e:#}"));
    c.query_one("SELECT v FROM state_version WHERE id = 1", &[])
        .map(|r| r.get(0))
        .unwrap_or_else(|e| panic!("{e}"))
}

/// Read: the other replica's change is seen, nothing is written or marshalled, and the records are read whole (a Do)
/// when the copy can't be caught up
#[test]
fn state_read() {
    let _g = serial(); // DO_LOAD_EVERY_MS
    let tw = two();
    let (a, b) = (&tw.a, &tw.b);
    b.read(|_| {}); // its copy is of no version yet: a Do
    let l = load_of(b);
    assert!(l.reads == 0 && l.reloads == 1, "the first Read: {l:?}");
    a.do_(|d| {
        d.sessions.insert("s1".into(), session("s1", "started"));
    });
    let v = version(a);
    let state_of = |d: &Persisted| {
        d.sessions
            .get("s1")
            .map(|s| s.state.clone())
            .unwrap_or_default()
    };
    let s = format!("{} {}", b.read(state_of), b.read(state_of));
    assert_eq!(s, "started started", "b read");
    let l = load_of(b);
    assert!(
        l.reads == 2 && l.catch_ups == 1 && l.reloads == 1 && l.writes == 0 && l.n == 3,
        "b's load: {l:?}"
    );
    assert_eq!(version(a), v, "a Read wrote");
    // a Read holds no lock the other replica's Do waits for
    std::thread::scope(|sc| {
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        sc.spawn(move || {
            b.read(|_| {
                let _ = held_tx.send(());
                let _ = done_rx.recv_timeout(Duration::from_secs(10));
            })
        });
        let _ = held_rx.recv_timeout(Duration::from_secs(10));
        a.do_(|d| {
            if let Some(s) = d.sessions.get_mut("s1") {
                s.state = "pausing".into();
            }
        });
        let _ = done_tx.send(());
    });
    assert_eq!(b.read(state_of), "pausing", "b read after a's change");
    // an unlisted version (a router from before state_changes): the Read is a Do, which reads everything again
    exec(
        a,
        r#"UPDATE sessions SET doc = jsonb_set(doc, '{label}', '"old router"') WHERE id = 's1'"#,
    );
    exec(a, "UPDATE state_version SET v = v + 1 WHERE id = 1");
    let reads = load_of(b).reads;
    let label = b.read(|d| {
        d.sessions
            .get("s1")
            .map(|s| s.label.clone())
            .unwrap_or_default()
    });
    let l = load_of(b);
    assert!(
        label == "old router" && l.reads == reads && l.reloads == 2,
        "after an unlisted version b read {label:?}: {l:?}"
    );
}
