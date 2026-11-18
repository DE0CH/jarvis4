use crate::autopilot::{Liveness, WaitEpisode};
use crate::core::Doc;
use crate::outcomes::Outcome;
use crate::state::{Record, Session, State};
use crate::testutil::{TestDb, new_test_router, test_state};
use jarvis_go::GoTime;
use std::sync::Arc;

fn sv(s: &Session) -> serde_json::Value {
    serde_json::to_value(s).unwrap_or_default()
}

/// the records survive a restart: every kind of field (a map, the records list, a settings row) written by Do is what a
/// new State reads back; a deleted record and a cleared setting are gone
#[test]
fn state_in_postgres() {
    let t = TestDb::new();
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let st = test_state(&t, dir.path());
    let cert = Doc {
        payload: r#"{"kind":"succession-cert"}"#.into(),
        sig: "c2ln".into(),
    };
    st.do_(|d| {
        d.sessions.insert(
            "s1".into(),
            Session {
                id: "s1".into(),
                state: "started".into(),
                machine_id: "m1".into(),
                label: "one".into(),
                created: GoTime::parse("2026-10-01T00:00:00Z").unwrap_or_default(),
                cert: Some(cert.clone()),
                ..Default::default()
            },
        );
        d.sessions.insert(
            "s2".into(),
            Session {
                id: "s2".into(),
                state: "paused".into(),
                ..Default::default()
            },
        );
        d.records.push(Record {
            session: Session {
                id: "s0".into(),
                state: "destroyed".into(),
                ..Default::default()
            },
            ..Default::default()
        });
        d.records.push(Record {
            session: Session {
                id: "s9".into(),
                ..Default::default()
            },
            ..Default::default()
        });
        d.machines.insert("m1".into(), "s1".into());
        d.kernel_copy = "green".into();
        d.kernel_root = serde_json::from_value(
            serde_json::json!({"grant": {"payload": "", "sig": ""}, "by": "root"}),
        )
        .ok();
        d.outcomes.insert(
            "s1".into(),
            vec![Outcome {
                id: "o1".into(),
                session: "s1".into(),
                ..Default::default()
            }],
        );
    });
    st.do_(|d| {
        d.sessions.remove("s2");
        d.records.truncate(1);
        d.kernel_root = None;
    });
    let hot: String = st
        .db()
        .and_then(|db| db.conn().ok())
        .and_then(|mut c| {
            c.query_one("SELECT state FROM sessions WHERE machine_id = 'm1'", &[])
                .ok()
        })
        .map(|r| r.get(0))
        .unwrap_or_default();
    assert_eq!(hot, "started", "hot column");
    let a = st.do_(|d| d.sessions.get("s1").cloned());
    drop(st);
    let dir2 = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let st2 = test_state(&t, dir2.path());
    st2.do_(|d| {
        let b = d.sessions.get("s1");
        assert!(
            b.is_some_and(|b| b.cert.is_some()) && !d.sessions.contains_key("s2"),
            "sessions: {:?}",
            d.sessions
        );
        assert_eq!(a.as_ref().map(sv), b.map(sv));
        assert!(
            d.records.len() == 1
                && d.records[0].session.id == "s0"
                && d.machines.get("m1").map(String::as_str) == Some("s1")
                && d.kernel_copy == "green"
                && d.kernel_root.is_none()
                && d.outcomes.get("s1").map_or(0, Vec::len) == 1,
            "read back"
        );
    });
}

/// a change the database keeps refusing never vanishes quietly: Do retries it on a fresh copy, then panics with a
/// StateWriteError, which an HTTP caller gets as a 503
#[test]
fn state_write_refused() {
    let r = new_test_router();
    let exec = |q: &str| {
        let _ =
            r.st.db()
                .and_then(|db| db.conn().ok())
                .map(|mut c| c.batch_execute(q));
    };
    exec("ALTER TABLE sessions RENAME TO sessions_away");
    let tries = std::sync::atomic::AtomicI64::new(0);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        r.st.do_(|d| {
            tries.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            d.sessions.insert(
                "s1".into(),
                Session {
                    id: "s1".into(),
                    state: "started".into(),
                    ..Default::default()
                },
            );
        })
    }));
    let p = res
        .err()
        .unwrap_or_else(|| panic!("a refused change didn't panic"));
    assert!(
        p.downcast_ref::<crate::state::StateWriteError>().is_some(),
        "not a StateWriteError"
    );
    assert!(tries.load(std::sync::atomic::Ordering::SeqCst) <= 4 && !r.db_status().ok);
    // an HTTP caller gets a 503 saying nothing was kept
    let r2 = r.r.clone();
    let h = crate::http::state_write_guard(Arc::new(move |w, _| {
        r2.st.do_(|d| {
            d.sessions.insert(
                "s9".into(),
                Session {
                    id: "s9".into(),
                    ..Default::default()
                },
            );
        });
        w.write_header(200);
    }));
    let (code, v) = crate::testutil::call(&h, "POST", "/api/x", "");
    assert!(
        code == 503 && v.to_string().contains("nothing of this request was kept"),
        "{code} {v}"
    );
    exec("ALTER TABLE sessions_away RENAME TO sessions");
    r.st.do_(|d| {
        assert!(
            !d.sessions.contains_key("s1") && !d.sessions.contains_key("s9"),
            "a refused change stayed in the copy"
        );
        d.sessions.insert(
            "s2".into(),
            Session {
                id: "s2".into(),
                ..Default::default()
            },
        );
    });
    assert!(
        r.st.store_error().is_none() && r.db_status().ok,
        "after a write went through"
    );
}

/// two replicas: a change one makes is what the other's next Do sees
#[test]
fn state_across_replicas() {
    let t = TestDb::new();
    let (da, db) = (
        tempfile::tempdir().unwrap_or_else(|e| panic!("{e}")),
        tempfile::tempdir().unwrap_or_else(|e| panic!("{e}")),
    );
    let a: State = test_state(&t, da.path());
    let b: State = test_state(&t, db.path());
    a.do_(|d| {
        d.sessions.insert(
            "s1".into(),
            Session {
                id: "s1".into(),
                state: "started".into(),
                ..Default::default()
            },
        );
    });
    b.do_(|d| {
        let s = d
            .sessions
            .get_mut("s1")
            .unwrap_or_else(|| panic!("the other replica's change isn't seen"));
        s.state = "pausing".into();
    });
    a.do_(|d| assert_eq!(d.sessions["s1"].state, "pausing", "a stale copy was used"));
    // concurrent Do's on both: none is lost
    std::thread::scope(|sc| {
        for st in [&a, &b] {
            sc.spawn(move || {
                for _ in 0..20 {
                    st.do_(|d| {
                        if let Some(s) = d.sessions.get_mut("s1") {
                            s.disk_gb += 1;
                        }
                    });
                }
            });
        }
    });
    a.do_(|d| assert_eq!(d.sessions["s1"].disk_gb, 40, "increments survived"));
    // the autopilot's episodes are records like the rest: one replica's is the other's
    a.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.live = Some(Liveness {
                waiting: Some(WaitEpisode {
                    at: GoTime::now().utc(),
                    status_at: 7,
                    ..Default::default()
                }),
                login_busy_at: GoTime::now().utc(),
                ..Default::default()
            });
        }
    });
    b.do_(|d| {
        let l = d.sessions["s1"].live.as_ref();
        assert!(
            l.is_some_and(|l| l.waiting.as_ref().is_some_and(|w| w.status_at == 7)
                && !l.login_busy_at.is_zero()),
            "the other replica doesn't see the episode: {l:?}"
        );
    });
}

/// the small documents: read and written in the database
#[test]
fn router_docs() {
    let r = new_test_router();
    assert!(
        r.st.read_doc("store-docs.json").is_none(),
        "a document nobody wrote"
    );
    let _ = r.st.write_doc("store-docs.json", br#"{"a":{}}"#);
    let _ = r.st.write_doc("store-docs.json", br#"{"b":{}}"#);
    let _ = r.st.write_doc(
        "repos.json",
        br#"[{"url":"https://github.com/DE0CH/b.git"}]"#,
    );
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let st2 = test_state(&r.db, dir.path());
    assert_eq!(
        st2.read_doc("store-docs.json").as_deref(),
        Some(&br#"{"b":{}}"#[..]),
        "after a restart"
    );
    let rs = r.repos();
    assert!(rs.len() == 1 && rs[0].repo == "DE0CH/b", "repos: {rs:?}");
}
