use crate::db::{DB, migrations};
use crate::testutil::TestDb;

#[test]
fn migrations_apply_once() {
    let t = TestDb::new();
    // two routers starting together: each migration applied once
    let (a, b) = std::thread::scope(|s| {
        let a = s.spawn(|| DB::open(&t.url));
        let b = s.spawn(|| DB::open(&t.url));
        (a.join(), b.join())
    });
    let a = a
        .unwrap_or_else(|_| panic!("open panicked"))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let _b = b
        .unwrap_or_else(|_| panic!("open panicked"))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let st = a.status();
    let want = migrations().unwrap_or_default().len() as i32;
    assert!(st.ok && st.primary && st.schema == want, "status: {st:?}");
    let n: i64 = a
        .conn()
        .and_then(|mut c| {
            Ok(c.query_one("SELECT count(*) FROM schema_migrations", &[])?
                .get(0))
        })
        .unwrap_or(0);
    assert_eq!(n, want as i64, "schema_migrations rows");
    // a database at a newer schema than this router knows: refused
    let _ = a.conn().map(|mut c| {
        c.execute(
            "INSERT INTO schema_migrations (version, name) VALUES (9999, '9999_future.sql')",
            &[],
        )
    });
    match DB::open(&t.url) {
        Err(e) => assert!(format!("{e:#}").contains("newer"), "a newer schema: {e:#}"),
        Ok(_) => panic!("a newer schema was opened"),
    }
}

/// a test's database ends with the test: once a router on it is dropped, none of its connections stays (the LISTEN
/// of every router and their pools once held about 1.6 connections per finished test, past CI Postgres's 100)
#[test]
fn a_finished_test_leaves_no_connection() {
    let count = |schema: &str| -> i64 {
        let base = std::env::var("TEST_DATABASE_URL").unwrap_or_default();
        let mut c = crate::db::connect_one(&base).unwrap_or_else(|e| panic!("{e:#}"));
        c.query_one(
            "SELECT count(*) FROM pg_stat_activity WHERE application_name = $1",
            &[&schema],
        )
        .map(|r| r.get(0))
        .unwrap_or_else(|e| panic!("{e}"))
    };
    let t = crate::testutil::new_test_router();
    let (r2, _d2) = crate::testutil::new_test_router_on(&t);
    let schema = t.db.schema.clone();
    let mut n = 0;
    for _ in 0..50 {
        n = count(&schema);
        if n >= 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        n >= 2,
        "the routers' connections carry the schema's name: {n}"
    );
    drop(t);
    for _ in 0..50 {
        n = count(&schema);
        if n == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(n, 0, "connections left after the test's database ended");
    drop(r2);
}
