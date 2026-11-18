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
