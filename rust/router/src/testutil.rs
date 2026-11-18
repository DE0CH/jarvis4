//! What the router's tests share (Go's *_test.go helpers): a Postgres schema of the test's own, a router on it, test
//! HTTP servers for the services the router calls, P-256 test keys.
//!
//! The tests need a Postgres: TEST_DATABASE_URL (CI runs a service container, images.yml; a session runs one locally,
//! docs/STATE.md "Tests").

use crate::core::{CoreClient, Doc};
use crate::db::DB;
use crate::nethttp::{Handler, Req, W};
use crate::router::{Config, Router};
use crate::state::State;
use std::sync::Arc;

/// a fresh schema of TEST_DATABASE_URL's database (dropped with this), as a URL whose connections use only it
pub struct TestDb {
    pub url: String,
    base: String,
    schema: String,
}

impl TestDb {
    pub fn new() -> TestDb {
        let base = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            panic!("TEST_DATABASE_URL isn't set: the router's tests need a Postgres (e.g. postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable)")
        });
        let schema = format!("t_{}", hex::encode(crate::util::rand_bytes(6)));
        let mut c =
            crate::db::connect_one(&base).unwrap_or_else(|e| panic!("TEST_DATABASE_URL: {e:#}"));
        c.batch_execute(&format!("CREATE SCHEMA {schema}"))
            .unwrap_or_else(|e| panic!("{e}"));
        let sep = if base.contains('?') { '&' } else { '?' };
        let url = format!("{base}{sep}options=-c%20search_path%3D{schema}");
        TestDb { url, base, schema }
    }

    /// a migrated database on this schema
    pub fn db(&self) -> DB {
        DB::open(&self.url).unwrap_or_else(|e| panic!("{e:#}"))
    }
}

impl Default for TestDb {
    fn default() -> Self {
        TestDb::new()
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        if let Ok(mut c) = crate::db::connect_one(&self.base) {
            let _ = c.batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema));
        }
    }
}

/// a router on a database of its own, with no core, no Access and no policy (Go's newTestRouter)
pub struct TestRouter {
    pub r: Arc<Router>,
    pub db: TestDb,
    pub dir: tempfile::TempDir,
}

impl std::ops::Deref for TestRouter {
    type Target = Arc<Router>;
    fn deref(&self) -> &Arc<Router> {
        &self.r
    }
}

pub fn test_config(dir: &std::path::Path) -> Config {
    Config {
        no_access: true,
        data_dir: dir.display().to_string(),
        web_dir: dir.join("web").display().to_string(),
        ..Default::default()
    }
}

pub fn test_state(db: &TestDb, dir: &std::path::Path) -> State {
    State::open(db.db(), dir, Some(crate::sealed::random_sealer()))
        .unwrap_or_else(|e| panic!("{e:#}"))
}

pub fn new_test_router() -> TestRouter {
    new_test_router_with(|_| {}, None, Default::default())
}

/// a router whose config f adjusts, on core (None: a core nobody answers)
pub fn new_test_router_with(
    f: impl FnOnce(&mut Config),
    core: Option<&str>,
    policy: crate::policy::Policy,
) -> TestRouter {
    let db = TestDb::new();
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let st = test_state(&db, dir.path());
    let mut cfg = test_config(dir.path());
    f(&mut cfg);
    let core = Arc::new(CoreClient::new(core.unwrap_or("http://127.0.0.1:9")));
    let r = Router::new(cfg, Arc::new(st), core, policy);
    TestRouter { r, db, dir }
}

/// a second replica on the same database as t (Go's newTestRouterOn)
pub fn new_test_router_on(t: &TestRouter) -> (Arc<Router>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let st = test_state(&t.db, dir.path());
    let r = Router::new(
        test_config(dir.path()),
        Arc::new(st),
        Arc::new(CoreClient::new("http://127.0.0.1:9")),
        Default::default(),
    );
    (r, dir)
}

/// a test HTTP server (Go's httptest.NewServer): handler h on 127.0.0.1, stopped when dropped
pub struct TestServer {
    pub url: String,
    stop: tokio_util::sync::CancellationToken,
    th: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    pub fn start(h: Handler) -> TestServer {
        let stop = tokio_util::sync::CancellationToken::new();
        let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
        let url = format!(
            "http://{}",
            ln.local_addr().unwrap_or_else(|e| panic!("{e}"))
        );
        ln.set_nonblocking(true).unwrap_or_else(|e| panic!("{e}"));
        let s2 = stop.clone();
        let th = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap_or_else(|e| panic!("{e}"));
            rt.block_on(async move {
                let ln = tokio::net::TcpListener::from_std(ln).unwrap_or_else(|e| panic!("{e}"));
                let _ = crate::nethttp::serve_listener(ln, h, s2).await;
            });
        });
        TestServer {
            url,
            stop,
            th: Some(th),
        }
    }

    pub fn handler(f: impl Fn(&mut W, &mut Req) + Send + Sync + 'static) -> TestServer {
        TestServer::start(Arc::new(f))
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(th) = self.th.take() {
            let _ = th.join();
        }
    }
}

/// a P-256 key that signs test documents (Go's newTestKey)
pub struct TestKey(pub jarvis_sig::Signer);

impl TestKey {
    pub fn new() -> TestKey {
        TestKey(jarvis_sig::Signer::generate())
    }

    pub fn public(&self) -> String {
        self.0.public_key()
    }

    /// v signed as the Go side signs (its json.Marshal bytes)
    pub fn doc(&self, v: &serde_json::Value) -> Doc {
        let payload = jarvis_go::marshal(v);
        let sig = self.0.sign(payload.as_bytes());
        Doc { payload, sig }
    }
}

impl Default for TestKey {
    fn default() -> Self {
        TestKey::new()
    }
}

/// waits up to 4 s for ok (Go's waitFor)
pub fn wait_for(what: &str, ok: impl Fn() -> bool) {
    for _ in 0..200 {
        if ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("timed out waiting for {what}");
}

/// a JSON body as a map (Go's body helper)
pub fn body(s: &str) -> serde_json::Map<String, serde_json::Value> {
    serde_json::from_str(s).unwrap_or_default()
}

/// one request through a handler → (status, the JSON answer)
pub fn call(h: &Handler, method: &str, path: &str, b: &str) -> (u16, serde_json::Value) {
    let mut w = W::recorder();
    let mut req = Req::new(method, path, b.as_bytes());
    h(&mut w, &mut req);
    let v = serde_json::from_str(&w.body_text()).unwrap_or(serde_json::Value::Null);
    (w.status(), v)
}
