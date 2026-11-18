//! corechange, sealed and mq tests

use crate::grants::{ExecItem, ExecResult};
use crate::sealed::{Sealer, key_from};
use crate::testutil::{FakeCore, TestDb, add_session, new_test_router, take_cmd, wait_for};
use base64::Engine;
use serde_json::json;
use std::time::{Duration, Instant};

fn sessions(r: &crate::router::Router) -> usize {
    r.st.do_(|d| d.sessions.len())
}

#[test]
fn a_new_core_destroys_the_earlier_cores_paused_sessions() {
    let t = new_test_router();
    t.records_off
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let fc = FakeCore::new();
    t.core.set_url(&fc.srv.url);
    add_session(&t, "s1", "paused", "", false);
    add_session(&t, "s2", "started", "m2", false);
    t.save_carry("m1", "blob");
    t.st.do_(|d| {
        d.machines.insert("m1".into(), "s1".into());
    });
    t.core_change_tick(); // first sight: these are the running core's
    t.core_change_tick();
    assert_eq!(sessions(&t), 2, "the same core destroyed sessions");
    let fc2 = FakeCore::new(); // a restart: a new core
    t.core.set_url(&fc2.srv.url);
    t.core_change_tick();
    wait_for("s1 destroyed", || sessions(&t) == 1);
    assert_eq!(
        t.read_carry("m1"),
        "",
        "the carried secrets outlived the session"
    );
    assert!(
        t.st.do_(|d| d.records.len() == 1 && d.records[0].session.id == "s1"),
        "no record in Previous"
    );
    // the running one goes once it is paused; a session the new core certified stays
    add_session(&t, "s3", "paused", "", false);
    t.core_change_tick();
    t.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s2") {
            s.state = "paused".into();
        }
    });
    t.core_change_tick();
    wait_for("s2 destroyed", || sessions(&t) == 1);
    assert!(
        t.st.do_(|d| d.sessions.contains_key("s3")),
        "the new core's own session was destroyed"
    );
    // an unreachable core decides nothing
    drop(fc2);
    t.core_change_tick();
    assert_eq!(sessions(&t), 1, "an unreachable core destroyed a session");
}

/// sealed documents: never in the clear in the database, bound to their name, read under the previous key and resealed
/// under the new one after a rotation
#[test]
fn sealed_docs() {
    let t = TestDb::new();
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let (k1, k2) = (crate::util::rand_bytes(32), crate::util::rand_bytes(32));
    let sealer = |cur: &[u8], old: Option<&[u8]>| Sealer {
        cur: key_from(&b64(cur)).unwrap_or_else(|e| panic!("{e:#}")),
        old: old.map(|o| key_from(&b64(o)).unwrap_or_else(|e| panic!("{e:#}"))),
    };
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let open = |s: Sealer| {
        crate::state::State::open(t.db(), dir.path(), Some(s)).unwrap_or_else(|e| panic!("{e:#}"))
    };
    let s1 = sealer(&k1, None);
    let id1 = s1.cur.id.clone();
    let st = open(s1);
    st.write_sealed("holders/a.key", b"holder-key-bytes")
        .unwrap_or_else(|e| panic!("{e:#}"));
    st.write_sealed(
        "claude-accounts/claude-main.json",
        br#"{"refreshToken":"sk-ant-ort-secret"}"#,
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    let q = |sql: &str| -> Vec<postgres::Row> {
        st.db()
            .and_then(|db| db.conn().ok())
            .and_then(|mut c| c.query(sql, &[]).ok())
            .unwrap_or_default()
    };
    let rows = q(
        "SELECT key_id, encode(body, 'escape') FROM sealed_docs WHERE name = 'claude-accounts/claude-main.json'",
    );
    let (kid, body): (String, String) = rows
        .first()
        .map(|r| (r.get(0), r.get(1)))
        .unwrap_or_default();
    assert!(
        !body.contains("secret") && kid == id1,
        "the row isn't sealed under the current key"
    );
    // a row moved to another name doesn't open
    q(
        "UPDATE sealed_docs SET name = 'claude-accounts/claude-x.json' WHERE name = 'claude-accounts/claude-main.json'",
    );
    assert!(
        st.read_sealed("claude-accounts/claude-x.json").is_err(),
        "a row opened under another name"
    );
    q(
        "UPDATE sealed_docs SET name = 'claude-accounts/claude-main.json' WHERE name = 'claude-accounts/claude-x.json'",
    );
    // a rotation: the new key current, the old one beside it; every row resealed at start
    let s2 = sealer(&k2, Some(&k1));
    let id2 = s2.cur.id.clone();
    let st2 = open(s2);
    let old: i64 = st2
        .db()
        .and_then(|db| db.conn().ok())
        .and_then(|mut c| {
            c.query_one(
                "SELECT count(*) FROM sealed_docs WHERE key_id <> $1",
                &[&id2],
            )
            .ok()
        })
        .map(|r| r.get(0))
        .unwrap_or(-1);
    let b = st2
        .read_sealed("claude-accounts/claude-main.json")
        .ok()
        .flatten()
        .unwrap_or_default();
    assert!(
        old == 0 && String::from_utf8_lossy(&b).contains("sk-ant-ort-secret"),
        "after the rotation: {} rows under another key",
        old
    );
    // without the old key now: still readable (all resealed)
    let st3 = open(sealer(&k2, None));
    assert!(
        st3.read_sealed("holders/a.key").ok().flatten().is_some(),
        "a row is still under the old key"
    );
}

/// the queue through the database: a row is taken once (two polls never get the same one), the answer reaches the
/// waiter by its notification, and a bounded kind refuses past its bound
#[test]
fn machine_queue() {
    let t = new_test_router();
    for _ in 0..10 {
        t.send("m1", "snapshot");
    }
    let mut n = 0;
    while take_cmd(&t, "m1").is_some() {
        n += 1;
    }
    assert_eq!(n, 8, "commands queued, want the bound of 8");
    let _ = t.mq_put(
        "m1",
        "exec",
        "x1",
        &json!(ExecItem {
            request: "{}".into(),
            ..Default::default()
        }),
        16,
    );
    let got: Vec<bool> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..2)
            .map(|_| {
                s.spawn(|| {
                    t.mq_next(&crate::ctx::Ctx::background(), "m1", Duration::from_secs(1))
                        .ok()
                        .flatten()
                        .is_some()
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap_or(false)).collect()
    });
    assert_eq!(
        got.iter().filter(|x| **x).count(),
        1,
        "two polls: {got:?} (want exactly one row)"
    );
    let (ans, took) = std::thread::scope(|s| {
        let h = s.spawn(|| t.mq_await("x1", Duration::from_secs(5), None));
        std::thread::sleep(Duration::from_millis(50));
        let start = Instant::now();
        let _ = t.mq_answer(
            "x1",
            &json!(ExecResult {
                id: "x1".into(),
                code: 3,
                ..Default::default()
            }),
        );
        let ans = h
            .join()
            .ok()
            .and_then(|a| a.ok())
            .flatten()
            .unwrap_or_default();
        (ans, start.elapsed())
    });
    let res: ExecResult = serde_json::from_slice(&ans).unwrap_or_default();
    assert!(
        res.code == 3 && took < crate::mq::mq_recheck(),
        "answer {} after {took:?} (the notification should beat the recheck)",
        String::from_utf8_lossy(&ans)
    );
}
