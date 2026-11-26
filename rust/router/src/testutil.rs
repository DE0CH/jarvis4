//! What the router's tests share (Go's *_test.go helpers): a Postgres schema of the test's own, a router on it, test
//! HTTP servers for the services the router calls, P-256 test keys.
//!
//! The tests need a Postgres: TEST_DATABASE_URL (CI runs a service container, images.yml; a session runs one locally,
//! docs/STATE.md "Tests").

use crate::core::{CoreClient, Doc};
use crate::db::DB;
use crate::router::{Config, Router};
use crate::state::State;
use jarvis_nethttp::{Handler, Req, W};
use std::sync::Arc;

/// a fresh schema of TEST_DATABASE_URL's database (dropped with this), as a URL whose connections use only it
pub struct TestDb {
    pub url: String,
    base: String,
    pub schema: String,
    /// every DB handed out (db), closed when the test ends: a router's LISTEN reconnects until its DB is closed
    opened: std::sync::Mutex<Vec<Arc<std::sync::atomic::AtomicBool>>>,
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
        // the connections carry the schema's name, so the test's end can find every one of them
        let url =
            format!("{base}{sep}application_name={schema}&options=-c%20search_path%3D{schema}");
        TestDb {
            url,
            base,
            schema,
            opened: Default::default(),
        }
    }

    /// a migrated database on this schema
    pub fn db(&self) -> DB {
        let db = DB::open(&self.url).unwrap_or_else(|e| panic!("{e:#}"));
        self.opened
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(db.done.clone());
        db
    }
}

impl Default for TestDb {
    fn default() -> Self {
        TestDb::new()
    }
}

/// A test's database ends with the test: its DBs are closed and every connection to its schema is ended (routers'
/// threads outlive the test and hold their pools and LISTEN, which ran CI's Postgres out of connections).
impl Drop for TestDb {
    fn drop(&mut self) {
        for d in self.opened.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            d.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        if let Ok(mut c) = crate::db::connect_one(&self.base) {
            let _ = c.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = $1",
                &[&self.schema],
            );
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
    new_test_router_on_objects(f, core, policy, None)
}

/// the same on these objects (None: memory)
pub fn new_test_router_on_objects(
    f: impl FnOnce(&mut Config),
    core: Option<&str>,
    policy: crate::policy::Policy,
    objects: Option<Arc<dyn crate::objstore::ObjStore>>,
) -> TestRouter {
    let db = TestDb::new();
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let st = test_state(&db, dir.path());
    let mut cfg = test_config(dir.path());
    f(&mut cfg);
    let core = Arc::new(CoreClient::new(core.unwrap_or("http://127.0.0.1:9")));
    let r = Router::new_on(cfg, Arc::new(st), core, policy, objects);
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
                let _ = jarvis_nethttp::serve_listener(ln, h, s2).await;
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

/// waits up to 20 s for ok (Go's waitFor waited 4 s, but Go ran a package's tests one at a time: here every test runs
/// at once, and a resume on a loaded box outlasted 4 s)
pub fn wait_for(what: &str, ok: impl Fn() -> bool) {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < end {
        if ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    if !ok() {
        panic!("timed out waiting for {what}");
    }
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

// ---- an in-memory WebDAV server (the Storage Box) ----------------------------------------------------------

#[derive(Default)]
pub struct MemDavState {
    pub files: std::collections::BTreeMap<String, Vec<u8>>,
    pub dirs: std::collections::BTreeSet<String>,
    /// a path prefix whose PUTs (and MOVEs to) fail
    pub fail: String,
}

/// the Storage Box as a test server: basic auth u/p, MKCOL, PUT, GET (and a suffix range), MOVE, DELETE, PROPFIND
pub struct MemDav {
    pub st: Arc<std::sync::Mutex<MemDavState>>,
    pub srv: TestServer,
}

fn dav_parent(p: &str) -> String {
    match p.rfind('/') {
        Some(i) => p[..i].to_string(),
        None => ".".into(),
    }
}

impl MemDav {
    pub fn new() -> MemDav {
        use base64::Engine;
        let st: Arc<std::sync::Mutex<MemDavState>> = Arc::default();
        let s2 = st.clone();
        let srv = TestServer::handler(move |w, req| {
            let mut m = s2.lock().unwrap_or_else(|e| e.into_inner());
            let want = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("u:p")
            );
            if req.header("Authorization") != want {
                return w.write_header(401);
            }
            let p = req.path.trim_matches('/').to_string();
            match req.method.as_str() {
                "MKCOL" => {
                    if m.dirs.contains(&p) {
                        return w.write_header(405);
                    }
                    let parent = dav_parent(&p);
                    if parent != "." && !m.dirs.contains(&parent) {
                        return w.write_header(409);
                    }
                    m.dirs.insert(p);
                    w.write_header(201);
                }
                "PUT" => {
                    // the body first: a server refusing a file still consumes the request, and a client cut off
                    // mid-upload never reads the answer (the Storage Box answers 507 the same way)
                    let b = req.read_body(1 << 30);
                    // answered mid-upload, a client may see its send fail ("receiver is gone") instead of the 507:
                    // the body is read first, as the Storage Box does
                    if !m.fail.is_empty() && p.starts_with(&m.fail) {
                        return w.write_header(507);
                    }
                    let parent = dav_parent(&p);
                    if parent != "." && !m.dirs.contains(&parent) {
                        return w.write_header(409);
                    }
                    m.files.insert(p, b);
                    w.write_header(201);
                }
                "GET" | "HEAD" => {
                    let Some(mut b) = m.files.get(&p).cloned() else {
                        return w.write_header(404);
                    };
                    let rg = req.header("Range");
                    if let Some(n) = rg
                        .strip_prefix("bytes=-")
                        .and_then(|n| n.parse::<usize>().ok())
                    {
                        if n < b.len() {
                            b = b[b.len() - n..].to_vec();
                        }
                        w.set_header("Content-Length", &b.len().to_string());
                        w.write_header(206);
                    } else {
                        w.set_header("Content-Length", &b.len().to_string());
                    }
                    if req.method == "GET" {
                        w.write(&b);
                    }
                }
                "MOVE" => {
                    let dest = req.header("Destination");
                    let to = url::Url::parse(&dest).ok().map(|u| {
                        percent_encoding::percent_decode_str(u.path())
                            .decode_utf8_lossy()
                            .trim_matches('/')
                            .to_string()
                    });
                    let (Some(b), Some(to)) = (m.files.get(&p).cloned(), to) else {
                        return w.write_header(404);
                    };
                    if !m.fail.is_empty() && to.starts_with(&m.fail) {
                        return w.write_header(507);
                    }
                    m.files.remove(&p);
                    m.files.insert(to, b);
                    w.write_header(201);
                }
                "DELETE" => {
                    let pre = format!("{p}/");
                    let n0 = m.files.len() + m.dirs.len();
                    m.files.retain(|f, _| !(*f == p || f.starts_with(&pre)));
                    m.dirs.retain(|d| !(*d == p || d.starts_with(&pre)));
                    if m.files.len() + m.dirs.len() == n0 {
                        return w.write_header(404);
                    }
                    w.write_header(204);
                }
                "PROPFIND" => {
                    let is_dir = p.is_empty() || m.dirs.contains(&p);
                    if !m.files.contains_key(&p) && !is_dir {
                        return w.write_header(404);
                    }
                    let mut ents =
                        vec![(format!("/{p}"), is_dir, m.files.get(&p).map_or(0, Vec::len))];
                    if is_dir && req.header("Depth") == "1" {
                        for (f, b) in &m.files {
                            if dav_parent(f) == p || (p.is_empty() && !f.contains('/')) {
                                ents.push((format!("/{f}"), false, b.len()));
                            }
                        }
                        for d in &m.dirs {
                            if dav_parent(d) == p && *d != p {
                                ents.push((format!("/{d}/"), true, 0));
                            }
                        }
                    }
                    let mut b = String::from(
                        r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">"#,
                    );
                    for (href, dir, size) in ents {
                        let href = if dir && !href.ends_with('/') {
                            format!("{href}/")
                        } else {
                            href
                        };
                        let rt = if dir {
                            "<D:resourcetype><D:collection/></D:resourcetype>"
                        } else {
                            "<D:resourcetype/>"
                        };
                        let esc: String = href
                            .split('/')
                            .map(|s| {
                                percent_encoding::utf8_percent_encode(
                                    s,
                                    percent_encoding::NON_ALPHANUMERIC,
                                )
                                .to_string()
                            })
                            .collect::<Vec<_>>()
                            .join("/");
                        b.push_str(&format!(
                            r#"<D:response><D:href>{esc}</D:href><D:propstat><D:prop>{rt}<lp1:getcontentlength xmlns:lp1="DAV:">{size}</lp1:getcontentlength><lp1:getlastmodified xmlns:lp1="DAV:">Mon, 12 Oct 2026 10:00:00 GMT</lp1:getlastmodified></D:prop></D:propstat></D:response>"#
                        ));
                    }
                    b.push_str("</D:multistatus>");
                    w.write_header(207);
                    w.write(b.as_bytes());
                }
                _ => w.write_header(405),
            }
        });
        MemDav { st, srv }
    }

    pub fn get(&self, p: &str) -> Option<Vec<u8>> {
        self.st
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .files
            .get(p)
            .cloned()
    }

    pub fn set_fail(&self, f: &str) {
        self.st.lock().unwrap_or_else(|e| e.into_inner()).fail = f.into();
    }

    /// the files under dir (relative), sorted
    pub fn under(&self, dir: &str) -> Vec<String> {
        let pre = format!("{dir}/");
        self.st
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .files
            .keys()
            .filter_map(|f| f.strip_prefix(&pre).map(str::to_string))
            .collect()
    }

    /// the members of a .tar.gz on the box (a hard link holds its target's bytes) and their order
    pub fn archive(
        &self,
        file: &str,
    ) -> (std::collections::BTreeMap<String, Vec<u8>>, Vec<String>) {
        let b = self.get(file).unwrap_or_else(|| {
            panic!(
                "no archive {file} (have {:?})",
                self.under("claude-records")
            )
        });
        let mut tr = tar::Archive::new(flate2::read::GzDecoder::new(&b[..]));
        let mut out = std::collections::BTreeMap::new();
        let mut order = vec![];
        for e in tr.entries().unwrap_or_else(|e| panic!("{e}")) {
            let mut e = e.unwrap_or_else(|e| panic!("{e}"));
            let name = e
                .path()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            order.push(name.clone());
            if e.header().entry_type() == tar::EntryType::Link {
                let to = e
                    .link_name()
                    .ok()
                    .flatten()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let v = out.get(&to).cloned().unwrap_or_default();
                out.insert(name, v);
                continue;
            }
            let mut v = vec![];
            let _ = std::io::Read::read_to_end(&mut e, &mut v);
            out.insert(name, v);
        }
        (out, order)
    }

    pub fn storage_box(&self) -> crate::storagebox::StorageBox {
        crate::storagebox::StorageBox::new(&self.srv.url, "u", "p")
    }
}

impl Default for MemDav {
    fn default() -> Self {
        MemDav::new()
    }
}

// ---- a fake core, a snapshot ---------------------------------------------------------------------------------

/// a core that signs every answer with its key (archive_test.go's fakeCore)
pub struct FakeCore {
    pub key: Arc<TestKey>,
    pub calls: Arc<std::sync::Mutex<Vec<String>>>,
    pub srv: TestServer,
}

/// a test's answer for some paths of the fake core (true: answered)
pub type CoreHook = Arc<dyn Fn(&mut W, &TestKey, &str, &[u8]) -> bool + Send + Sync>;

/// the fake core's answer to one call (body: the request's, read)
pub fn fake_core_answer(k: &TestKey, w: &mut W, path: &str, body: &[u8]) {
    use jarvis_nethttp::write_json;
    use serde_json::json;
    match path {
        "/key" => write_json(w, 200, &json!({"signingKey": k.public()})),
        // a set-up core (features.rs core_set_up)
        "/identity" => write_json(
            w,
            200,
            &json!({"signingKey": k.public(), "state": k.doc(&json!({"kind": "core-state", "master": "m"}))}),
        ),
        "/core-cert" => write_json(w, 200, &json!({"statement": "{}", "masterSig": "x"})),
        // the signed store list (storedocs.rs store_list): the stores a new session pre-picks
        "/stores" => write_json(
            w,
            200,
            &k.doc(&json!({"kind": "stores", "stores": [
            {"name": "default", "keys": []}, {"name": "github-claude-env", "keys": []},
            {"name": "identity", "sensitive": true, "keys": []}]})),
        ),
        // the core's record names the snapshot the kill named (core.rs kill_with_snapshot)
        "/kill" => {
            let b: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
            let sum = b["snapshot"]["sha256"].as_str().unwrap_or("").to_string();
            write_json(
                w,
                200,
                &k.doc(
                    &json!({"kind": "killed", "id": b["machine"], "snapshot": sum, "path": path}),
                ),
            );
        }
        p => write_json(w, 200, &k.doc(&json!({"kind": "ok", "path": p}))),
    }
}

impl FakeCore {
    pub fn new() -> FakeCore {
        let key = Arc::new(TestKey::new());
        let calls: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let (k, c) = (key.clone(), calls.clone());
        let srv = TestServer::handler(move |w, req| {
            c.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(req.path.clone());
            let b = req.read_body(16 << 20);
            fake_core_answer(&k, w, &req.path, &b);
        });
        FakeCore { key, calls, srv }
    }

    /// a core signing with key whose hook answers some paths itself (true: answered); the rest as the fake core's
    pub fn hooked(key: Arc<TestKey>, hook: CoreHook) -> FakeCore {
        let calls: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let (k, c) = (key.clone(), calls.clone());
        let srv = TestServer::handler(move |w, req| {
            c.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(req.path.clone());
            let b = req.read_body(16 << 20);
            if !hook(w, &k, &req.path, &b) {
                fake_core_answer(&k, w, &req.path, &b);
            }
        });
        FakeCore { key, calls, srv }
    }

    /// a core whose /start answers 502 "no Fly in tests" (sessionops_test.go's startCore), its starts kept
    pub fn starting() -> (FakeCore, Arc<std::sync::Mutex<Vec<serde_json::Value>>>) {
        let key = Arc::new(TestKey::new());
        let calls: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let starts: Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Arc::default();
        let (k, c, st) = (key.clone(), calls.clone(), starts.clone());
        let srv = TestServer::handler(move |w, req| {
            c.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(req.path.clone());
            let b = req.read_body(16 << 20);
            if req.path == "/start" {
                st.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(serde_json::from_slice(&b).unwrap_or_default());
                return jarvis_nethttp::write_json(
                    w,
                    502,
                    &serde_json::json!({"error": "no Fly in tests"}),
                );
            }
            fake_core_answer(&k, w, &req.path, &b);
        });
        (FakeCore { key, calls, srv }, starts)
    }
}

impl Default for FakeCore {
    fn default() -> Self {
        FakeCore::new()
    }
}

/// a file of a test tarball (a symlink when link is set)
#[derive(Clone, Default)]
pub struct TFile {
    pub name: String,
    pub body: String,
    pub link: String,
    pub at: i64,
}

pub fn tfile(name: &str, body: &str, at: i64) -> TFile {
    TFile {
        name: name.into(),
        body: body.into(),
        at,
        ..Default::default()
    }
}

pub fn tlink(name: &str, link: &str, at: i64) -> TFile {
    TFile {
        name: name.into(),
        link: link.into(),
        at,
        ..Default::default()
    }
}

pub fn make_tar(files: &[TFile]) -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
    let mut tw = tar::Builder::new(gz);
    for f in files {
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o644);
        h.set_mtime(f.at.max(0) as u64);
        if !f.link.is_empty() {
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            let _ = tw.append_link(&mut h, &f.name, &f.link);
        } else {
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(f.body.len() as u64);
            let _ = tw.append_data(&mut h, &f.name, f.body.as_bytes());
        }
    }
    tw.into_inner()
        .and_then(|gz| gz.finish())
        .unwrap_or_default()
}

/// one JSONL line
pub fn line(v: serde_json::Value) -> String {
    format!("{}\n", jarvis_go::marshal(&v))
}

/// a committed snapshot of machine (snapstore.rs), as a machine's stream and commit leave it
pub fn put_snap(r: &Router, machine: &str, body: &[u8], sig: &str) {
    r.snap_put_whole(machine, &mut std::io::Cursor::new(body.to_vec()), sig)
        .unwrap_or_else(|e| panic!("{e:#}"));
}

/// the machine's snapshot's bytes (None: none)
pub fn snap_bytes(r: &Router, machine: &str) -> Option<Vec<u8>> {
    let s = r.snap(machine)?;
    let mut rd = r.snap_open(&s).ok()?;
    let mut b = vec![];
    std::io::Read::read_to_end(&mut rd, &mut b).ok()?;
    Some(b)
}

// ---- the rig: a router with one paused session "s1" whose machine m1 left a signed snapshot ---------------

pub struct Rig {
    pub t: TestRouter,
    pub dav: MemDav,
    pub core: FakeCore,
    pub mkey: TestKey,
    pub cert: Doc,
    pub files: Vec<TFile>,
}

impl std::ops::Deref for Rig {
    type Target = Arc<Router>;
    fn deref(&self) -> &Arc<Router> {
        &self.t.r
    }
}

/// 2026-10-01T12:00:00Z
pub const RIG_T0: i64 = 1_790_856_000;

pub fn rig_files() -> Vec<TFile> {
    use serde_json::json;
    let t0 = RIG_T0;
    vec![
        tfile(
            ".claude/projects/-home-claude-workspace/aaaa.jsonl",
            &line(json!({"type": "user", "sessionId": "aaaa", "message": {"content": "old one"}})),
            t0,
        ),
        tfile(
            ".claude/projects/-home-claude-workspace/bbbb.jsonl",
            &(line(json!({"type": "ai-title", "aiTitle": "Fix the: router"}))
                + &line(
                    json!({"type": "user", "sessionId": "bbbb", "message": {"content": "hello"}}),
                )
                + &line(
                    json!({"type": "assistant", "message": {"content": [{"type": "text", "text": "done it"}]}}),
                )),
            t0 + 3600,
        ),
        tfile("artifacts/record.md", "# record", t0),
        tfile("artifacts/sub/shot.png", "png", t0),
        tlink(
            "artifacts/report.html",
            "../workspace/proj/out/report.html",
            t0,
        ),
        tlink("artifacts/proj", "/home/claude/workspace/proj/out", t0),
        tlink("artifacts/outside", "/etc/passwd", t0),
        tfile("workspace/proj/out/report.html", "<p>r</p>", t0),
        tfile(crate::archive::CHANGES_FILE, "proj 2 1\nother 0 -1\n", t0),
    ]
}

impl Rig {
    pub fn new() -> Rig {
        Rig::with(|_| {})
    }

    /// a rig whose router's config f adjusts (Go's tests set r.cfg fields after newRig)
    pub fn with(f: impl FnOnce(&mut Config)) -> Rig {
        let policy = crate::policy::Policy {
            harnesses: [(
                "claude".to_string(),
                crate::policy::HarnessPolicy {
                    stores: vec!["tunnel".into()],
                    ..Default::default()
                },
            )]
            .into_iter()
            .collect(),
        };
        Rig::with_policy(f, policy)
    }

    /// the same with the router's policy (Go's tests set r.policy after newRig)
    pub fn with_policy(f: impl FnOnce(&mut Config), policy: crate::policy::Policy) -> Rig {
        Rig::build(f, policy, None)
    }

    /// the rig on these objects (snapdirect_test.go's directMem)
    pub fn with_objects(objects: Arc<dyn crate::objstore::ObjStore>) -> Rig {
        Rig::build(|_| {}, Default::default(), Some(objects))
    }

    fn build(
        f: impl FnOnce(&mut Config),
        policy: crate::policy::Policy,
        objects: Option<Arc<dyn crate::objstore::ObjStore>>,
    ) -> Rig {
        use serde_json::json;
        crate::storagebox::PUT_BACKOFF_MS.store(1, std::sync::atomic::Ordering::Relaxed);
        let dav = MemDav::new();
        let core = FakeCore::new();
        let t = new_test_router_on_objects(
            |c| {
                c.no_access = false;
                c.snapshot_stall = std::time::Duration::from_secs(1);
                c.session_image = "img".into();
                f(c);
            },
            Some(&core.srv.url),
            policy,
            objects,
        );
        *t.r.box_override.write().unwrap_or_else(|e| e.into_inner()) =
            Some(Some(Arc::new(dav.storage_box())));
        let mkey = TestKey::new();
        let cert = core.key.doc(
            &json!({"kind": "succession-cert", "predecessorId": "", "line": "m1",
            "machine": {"id": "m1", "signingKey": mkey.public()}, "stores": ["default"]}),
        );
        let files = rig_files();
        let rg = Rig {
            t,
            dav,
            core,
            mkey,
            cert,
            files,
        };
        rg.write_snapshot("m1", &rg.files.clone());
        let cert = rg.cert.clone();
        rg.st.do_(|d| {
            d.sessions.insert(
                "s1".into(),
                crate::state::Session {
                    id: "s1".into(),
                    state: "paused".into(),
                    created: jarvis_go::GoTime::from_unix(RIG_T0),
                    harness: "claude".into(),
                    stores: Some(vec!["claude".into(), "default".into()]),
                    model: "claude-opus-5-5".into(),
                    size: "medium".into(),
                    permission_mode: "auto".into(),
                    repos: "https://github.com/DE0CH/x".into(),
                    ..Default::default()
                },
            );
            d.machines.insert("m1".into(), "s1".into());
            d.certs.insert("m1".into(), cert.clone());
        });
        rg
    }

    pub fn write_snapshot(&self, machine: &str, files: &[TFile]) {
        use sha2::Digest;
        let body = make_tar(files);
        let sum = hex::encode(sha2::Sha256::digest(&body));
        let sig = self.mkey.0.sign(sum.as_bytes());
        put_snap(&self.t.r, machine, &body, &sig);
    }

    pub fn session(&self, id: &str) -> crate::state::Session {
        self.st
            .do_(|d| d.sessions.get(id).cloned().unwrap_or_default())
    }
}

impl Default for Rig {
    fn default() -> Self {
        Rig::new()
    }
}

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// the tests that change a process-wide seam (a static) run one at a time
pub fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

// ---- machines, setup calls, sessions -------------------------------------------------------------------------

/// a session machine's key, signing /m requests as the machine does (sessionapi_test.go's testMachine)
pub struct TestMachine {
    pub id: String,
    pub key: TestKey,
}

/// a started machine of r with its own signing key
pub fn new_test_machine(r: &Router, id: &str) -> TestMachine {
    let key = TestKey::new();
    let started = crate::state::Started {
        id: id.into(),
        signing_key: key.public(),
        ..Default::default()
    };
    r.st.do_(|d| {
        d.started.insert(id.into(), started.clone());
    });
    TestMachine { id: id.into(), key }
}

/// "<method> <path> <time> <sha256 hex of body>" signed by key
pub fn signed_headers(
    key: &TestKey,
    method: &str,
    path: &str,
    body: &[u8],
    at: i64,
) -> (String, String) {
    use sha2::Digest;
    let ts = at.to_string();
    let sum = hex::encode(sha2::Sha256::digest(body));
    let sig = key.0.sign(format!("{method} {path} {ts} {sum}").as_bytes());
    (ts, sig)
}

impl TestMachine {
    /// a request to the machines' listener, signed as the machine signs it (decoded path, no query)
    pub fn do_(
        &self,
        h: &Handler,
        method: &str,
        target: &str,
        body: &str,
    ) -> (u16, serde_json::Value) {
        let path = target.split_once('?').map_or(target, |(p, _)| p);
        let path = percent_encoding::percent_decode_str(path)
            .decode_utf8_lossy()
            .into_owned();
        let (ts, sig) = signed_headers(
            &self.key,
            method,
            &path,
            body.as_bytes(),
            crate::util::unix_now(),
        );
        let mut req = Req::new(method, target, body.as_bytes())
            .with_header("X-Machine", &self.id)
            .with_header("X-Time", &ts)
            .with_header("X-Sig", &sig)
            .with_header("Content-Type", "application/json");
        let mut w = W::recorder();
        h(&mut w, &mut req);
        (
            w.status(),
            serde_json::from_str(&w.body_text()).unwrap_or(serde_json::Value::Null),
        )
    }
}

/// a /setup call, signed by setup when given (roster_test.go's rdo)
pub fn rdo(
    h: &Handler,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    setup: Option<&TestKey>,
) -> (u16, serde_json::Value) {
    let b = body.map(jarvis_go::marshal).unwrap_or_default();
    let mut req = Req::new(method, path, b.as_bytes());
    if let Some(k) = setup {
        let (ts, sig) = signed_headers(k, method, path, b.as_bytes(), crate::util::unix_now());
        req = req
            .with_header("X-Setup-Time", &ts)
            .with_header("X-Setup-Sig", &sig);
    }
    let mut w = W::recorder();
    h(&mut w, &mut req);
    (
        w.status(),
        serde_json::from_str(&w.body_text()).unwrap_or(serde_json::Value::Null),
    )
}

/// a session of the line "L<id>" (schedule_test.go's addSession)
pub fn add_session(r: &Router, id: &str, state: &str, machine: &str, sensitive: bool) {
    let payload =
        jarvis_go::marshal(&serde_json::json!({"line": format!("L{id}"), "sensitive": sensitive}));
    let s = crate::state::Session {
        id: id.into(),
        state: state.into(),
        machine_id: machine.into(),
        label: format!("label {id}"),
        harness: "claude".into(),
        cert: Some(Doc {
            payload,
            sig: String::new(),
        }),
        ..Default::default()
    };
    r.st.do_(|d| {
        d.sessions.insert(id.into(), s.clone());
        if !machine.is_empty() {
            d.machines.insert(machine.into(), id.into());
        }
    });
}

/// every DM r sends, kept
pub fn capture_dm(r: &Router) -> Arc<std::sync::Mutex<Vec<String>>> {
    let got: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let g = got.clone();
    *r.dm_hook.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(move |t: &str| {
        g.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(t.to_string())
    }));
    got
}

impl Rig {
    /// the rig's s1 runs on m2 (a successor of m1, the same signing key), booted (snapsafe_test.go's runningM2)
    pub fn running_m2(&self, with_volume: bool) {
        use serde_json::json;
        let mut machine = json!({"id": "m2", "signingKey": self.mkey.public()});
        if with_volume {
            machine["volume"] = json!({"id": "vol_m2", "sizeGb": 10, "path": "/data"});
        }
        let cert = self.core.key.doc(&json!({"kind": "succession-cert", "predecessorId": "m1", "line": "m1", "machine": machine, "stores": ["default"]}));
        let started = crate::state::Started {
            id: "m2".into(),
            signing_key: self.mkey.public(),
            ..Default::default()
        };
        self.st.do_(|d| {
            if let Some(s) = d.sessions.get_mut("s1") {
                s.state = "started".into();
                s.machine_id = "m2".into();
                s.booted = "m2".into();
                s.cert = Some(cert.clone());
                s.live = Some(crate::autopilot::Liveness {
                    last_report: jarvis_go::GoTime::now(),
                    ..Default::default()
                });
            }
            d.machines.insert("m2".into(), "s1".into());
            d.certs.insert("m2".into(), cert.clone());
            d.started.insert("m2".into(), started.clone());
        });
    }

    /// the rig's machine key as a TestMachine of id
    pub fn machine(&self, id: &str) -> TestMachine {
        TestMachine {
            id: id.into(),
            key: TestKey(
                jarvis_sig::Signer::from_scalar(&self.mkey.0.scalar())
                    .unwrap_or_else(|e| panic!("{e:?}")),
            ),
        }
    }
}

// ---- the machines' queue, played by the test ----------------------------------------------------------------

/// the machine's oldest untaken row of this kind (the tests play the machine for one kind at a time)
pub fn mq_take_kind(r: &Router, machine: &str, kind: &str) -> Option<String> {
    let mut c = r.st.db()?.conn().ok()?;
    let row = c
        .query_opt(
            "UPDATE machine_queue SET taken_at = now() WHERE id = (SELECT id FROM machine_queue
		WHERE machine_id = $1 AND kind = $2 AND taken_at IS NULL ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING body::text",
            &[&machine, &kind],
        )
        .ok()??;
    Some(row.get(0))
}

pub fn mq_wait_kind(
    r: &Router,
    machine: &str,
    kind: &str,
    wait: std::time::Duration,
) -> Option<String> {
    let end = std::time::Instant::now() + wait;
    loop {
        if let Some(b) = mq_take_kind(r, machine, kind) {
            return Some(b);
        }
        if std::time::Instant::now() > end {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// the machine's next supervisor command, if one waits now
pub fn take_cmd(r: &Router, machine: &str) -> Option<String> {
    mq_take_kind(r, machine, "command").and_then(|b| serde_json::from_str(&b).ok())
}

pub fn wait_cmd(r: &Router, machine: &str, wait: std::time::Duration) -> Option<String> {
    mq_wait_kind(r, machine, "command", wait).and_then(|b| serde_json::from_str(&b).ok())
}

// ---- deliveries, played by the test --------------------------------------------------------------------------

#[derive(Default)]
pub struct FakeDeliveryState {
    pub texts: Vec<String>,
    pub after: Vec<String>,
    /// every delivery fails with this, when set
    pub err: Option<String>,
}

/// deliveries recorded as "<session>: <kind> <the signed request's body> [run n]" (schedule_test.go's fakeDelivery)
#[derive(Clone, Default)]
pub struct FakeDelivery(pub Arc<std::sync::Mutex<FakeDeliveryState>>);

impl FakeDelivery {
    pub fn install(r: &Router) -> FakeDelivery {
        let f = FakeDelivery::default();
        let g = f.0.clone();
        *r.deliver_hook.write().unwrap_or_else(|e| e.into_inner()) =
            Some(Arc::new(move |_, sid, d| {
                let mut g = g.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(e) = &g.err {
                    return Err(anyhow::anyhow!("{e}"));
                }
                let mut x = format!(
                    "{sid}: {} {}",
                    d.kind,
                    d.request
                        .as_ref()
                        .map(|r| r.body.clone())
                        .unwrap_or_default()
                );
                if d.run > 0 {
                    x = format!("{x} run {}", d.run);
                }
                g.texts.push(x);
                Ok(())
            }));
        f
    }

    pub fn texts(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .texts
            .clone()
    }

    pub fn set_err(&self, e: Option<&str>) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).err = e.map(str::to_string);
    }
}

// ---- the v2 core (vouch_test.go's v2Core): records every body, signs challenges, refuses on demand -------------

#[derive(Default)]
pub struct V2State {
    pub bodies: std::collections::BTreeMap<String, Vec<serde_json::Value>>,
    /// approve_by_dead_machine answers 403 with this (the core's refusal)
    pub refuse: String,
    /// /kill answers these first, one per call: status and the core's error
    pub kill_errs: Vec<(u16, String)>,
    /// every path, in the order called
    pub order: Vec<String>,
}

pub struct V2Core {
    pub st: Arc<std::sync::Mutex<V2State>>,
    pub srv: TestServer,
}

/// a test's own answer for some paths of the v2 core (true: answered); the rest go to the v2 core's
pub type V2Hook = Arc<dyn Fn(&mut W, &TestKey, &str, &serde_json::Value) -> bool + Send + Sync>;

impl V2Core {
    pub fn new(key: Arc<TestKey>) -> V2Core {
        V2Core::with_hook(key, None)
    }

    pub fn with_hook(key: Arc<TestKey>, hook: Option<V2Hook>) -> V2Core {
        use jarvis_nethttp::write_json;
        use serde_json::json;
        let st: Arc<std::sync::Mutex<V2State>> = Arc::default();
        let s2 = st.clone();
        let srv = TestServer::handler(move |w, req| {
            let b: serde_json::Value =
                serde_json::from_slice(&req.read_body(16 << 20)).unwrap_or(serde_json::Value::Null);
            if let Some(h) = &hook
                && h(w, &key, &req.path, &b)
            {
                return;
            }
            let (refuse, kill_err) = {
                let mut g = s2.lock().unwrap_or_else(|e| e.into_inner());
                g.bodies
                    .entry(req.path.clone())
                    .or_default()
                    .push(b.clone());
                g.order.push(req.path.clone());
                let ke = if req.path == "/kill" && !g.kill_errs.is_empty() {
                    Some(g.kill_errs.remove(0))
                } else {
                    None
                };
                (g.refuse.clone(), ke)
            };
            let k = &key;
            match req.path.as_str() {
                "/input-log" => write_json(w, 200, &json!({"entries": [], "head": k.doc(&json!({"kind": "input-log-head", "seq": 0}))})),
                "/succession" => write_json(w, 200, &k.doc(&json!({"kind": "challenge", "nonce": "a".repeat(64), "request": b}))),
                "/approve/by-dead-machine" if !refuse.is_empty() => write_json(w, 403, &k.doc(&json!({"error": refuse}))),
                "/kill" => match kill_err {
                    Some((st, msg)) => write_json(w, st, &k.doc(&json!({"error": msg}))),
                    None => write_json(w, 200, &k.doc(&json!({"kind": "killed", "id": b["machine"]}))),
                },
                "/attest" => write_json(
                    w,
                    200,
                    &k.doc(&json!({"kind": "input", "machine": b["machine"], "input": b["input"], "sha256": b["sha256"]})),
                ),
                "/key" => write_json(w, 200, &json!({"signingKey": k.public()})),
                "/identity" => write_json(
                    w,
                    200,
                    &json!({"signingKey": k.public(), "state": k.doc(&json!({"kind": "core-state", "master": "m"}))}),
                ),
                "/core-cert" => write_json(w, 200, &json!({"statement": "{}", "masterSig": "x"})),
        // the signed store list (storedocs.rs store_list): the stores a new session pre-picks
        "/stores" => write_json(w, 200, &k.doc(&json!({"kind": "stores", "stores": [
            {"name": "default", "keys": []}, {"name": "github-claude-env", "keys": []},
            {"name": "identity", "sensitive": true, "keys": []}]}))),
                p => write_json(w, 200, &k.doc(&json!({"kind": "ok", "path": p}))),
            }
        });
        V2Core { st, srv }
    }

    /// the last body of a call to path (None: never called)
    pub fn last(&self, path: &str) -> Option<serde_json::Value> {
        self.st
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .bodies
            .get(path)
            .and_then(|b| b.last().cloned())
    }

    pub fn calls(&self, path: &str) -> usize {
        self.st
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .bodies
            .get(path)
            .map_or(0, Vec::len)
    }
}

impl Rig {
    /// the rig on a v2 core (vouch_test.go's v2Rig)
    pub fn v2() -> (Rig, V2Core) {
        Rig::v2_with(|_| {})
    }

    pub fn v2_with(f: impl FnOnce(&mut Config)) -> (Rig, V2Core) {
        let rg = Rig::with(f);
        let vc = V2Core::new(rg.core.key.clone());
        rg.core().set_url(&vc.srv.url);
        (rg, vc)
    }

    /// the rig on a v2 core whose hook answers some paths itself
    pub fn v2_hooked(hook: V2Hook) -> (Rig, V2Core) {
        let rg = Rig::new();
        let vc = V2Core::with_hook(rg.core.key.clone(), Some(hook));
        rg.core().set_url(&vc.srv.url);
        (rg, vc)
    }

    /// s1 failed with its machine m1 still there (failedsession_test.go's failedWithMachine)
    pub fn failed_with_machine(&self, msg: &str) {
        let cert = self.v2_cert("m1", r#"{"v":1}"#);
        let started = crate::state::Started {
            id: "m1".into(),
            signing_key: self.mkey.public(),
            ..Default::default()
        };
        self.st.do_(|d| {
            if let Some(s) = d.sessions.get_mut("s1") {
                s.state = "failed".into();
                s.error = msg.into();
                s.machine_id = "m1".into();
                s.cert = Some(cert.clone());
            }
            d.started.insert("m1".into(), started.clone());
        });
    }

    pub fn core(&self) -> &Arc<CoreClient> {
        &self.t.r.core
    }

    /// a v2 succession cert of the rig's line for machine, with config (vouch_test.go's v2Cert)
    pub fn v2_cert(&self, machine: &str, config: &str) -> Doc {
        use serde_json::json;
        self.core.key.doc(&json!({"kind": "succession-cert", "line": "m1", "vouch": 2,
            "machine": {"id": machine, "signingKey": self.mkey.public(), "image": format!("ghcr.io/de0ch/jarvis4-session@sha256:{}", "1".repeat(64))},
            "stores": ["claude", "default"], "options": {"harness": "claude", "permissionMode": "auto", "config": config}}))
    }
}

/// an app call (the iPhone app's when app: its Access token header), as inbox_test.go's inboxDo
pub fn inbox_do(
    r: &Router,
    method: &str,
    target: &str,
    body: &str,
    app: bool,
) -> (u16, serde_json::Value) {
    let h = r.arc().handler();
    let mut req = Req::new(method, target, body.as_bytes());
    if app {
        req = req.with_header("cf-access-token", "x");
    }
    let mut w = W::recorder();
    h(&mut w, &mut req);
    (
        w.status(),
        serde_json::from_str(&w.body_text()).unwrap_or(serde_json::Value::Null),
    )
}

/// a rig whose core fails every start (sessionops_test.go's newOpsRig): NoAccess, s1's cert set
pub struct OpsRig {
    pub rg: Rig,
    pub sc: FakeCore,
    pub starts: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
}

impl std::ops::Deref for OpsRig {
    type Target = Rig;
    fn deref(&self) -> &Rig {
        &self.rg
    }
}

impl OpsRig {
    pub fn new() -> OpsRig {
        let rg = Rig::with(|c| c.no_access = true);
        let (sc, starts) = FakeCore::starting();
        rg.t.r.core.set_url(&sc.srv.url);
        let cert = rg.cert.clone();
        rg.st.do_(|d| {
            if let Some(s) = d.sessions.get_mut("s1") {
                s.cert = Some(cert.clone());
            }
        });
        OpsRig { rg, sc, starts }
    }

    pub fn last_start(&self) -> Option<serde_json::Value> {
        self.starts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last()
            .cloned()
    }
}

impl Default for OpsRig {
    fn default() -> Self {
        OpsRig::new()
    }
}

/// a request to the public listener with headers (NoAccess routers only; sessionops_test.go's appDo)
pub fn app_do(
    r: &Router,
    method: &str,
    target: &str,
    body: &str,
    hdr: &[(&str, &str)],
) -> (u16, serde_json::Value) {
    let h = r.arc().handler();
    let mut req = Req::new(method, target, body.as_bytes());
    for (k, v) in hdr {
        req = req.with_header(k, v);
    }
    let mut w = W::recorder();
    h(&mut w, &mut req);
    (
        w.status(),
        serde_json::from_str(&w.body_text()).unwrap_or(serde_json::Value::Null),
    )
}

/// plays the machine for r.exec: records each command and answers with code, until the guard goes
/// (sessionops_test.go's answerExecs)
pub struct ExecAnswerer {
    pub cmds: Arc<std::sync::Mutex<Vec<String>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    th: Option<std::thread::JoinHandle<()>>,
}

impl ExecAnswerer {
    pub fn cmds(&self) -> Vec<String> {
        self.cmds.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Drop for ExecAnswerer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(th) = self.th.take() {
            let _ = th.join();
        }
    }
}

pub fn answer_execs(r: &Arc<Router>, machine: &str, code: i64) -> ExecAnswerer {
    answer_execs_with(r, machine, move |_, _| crate::grants::ExecResult {
        code,
        ..Default::default()
    })
}

/// plays the machine for r.exec with answer(holder name, command) (remote_test.go's fakeMachine)
pub fn answer_execs_with(
    r: &Arc<Router>,
    machine: &str,
    answer: impl Fn(&str, &str) -> crate::grants::ExecResult + Send + 'static,
) -> ExecAnswerer {
    let cmds: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let pubs = r.holder_public_keys().unwrap_or_default();
    let (r, machine, c2, s2) = (r.clone(), machine.to_string(), cmds.clone(), stop.clone());
    let th = std::thread::spawn(move || {
        while !s2.load(std::sync::atomic::Ordering::SeqCst) {
            let Some(b) = mq_wait_kind(&r, &machine, "exec", std::time::Duration::from_millis(50))
            else {
                continue;
            };
            let it: crate::grants::ExecItem = serde_json::from_str(&b).unwrap_or_default();
            let req: serde_json::Value = serde_json::from_str(&it.request).unwrap_or_default();
            let cmd = req["cmd"].as_str().unwrap_or_default().to_string();
            let holder = req["holder"].as_str().unwrap_or_default();
            let name = pubs
                .iter()
                .find(|(_, k)| k.as_str() == holder)
                .map(|(n, _)| n.clone())
                .unwrap_or_default();
            c2.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(cmd.clone());
            let mut res = answer(&name, &cmd);
            res.id = req["id"].as_str().unwrap_or_default().to_string();
            r.exec_result(res);
        }
    });
    ExecAnswerer {
        cmds,
        stop,
        th: Some(th),
    }
}

/// a stored grant as if the phone had signed it (the machine's checks are tested in rust/machine/;
/// sessionops_test.go's addGrant)
pub fn add_grant_kind(r: &Router, session: &str, holder: &str, kind: &str) {
    let id = crate::util::rand_id();
    let g = crate::grants::StoredGrant {
        id: id.clone(),
        session: session.into(),
        holder: holder.into(),
        kind: kind.into(),
        ends: jarvis_go::GoTime::now().add_std(std::time::Duration::from_secs(300)),
        doc: Some(Doc {
            payload: "{}".into(),
            sig: String::new(),
        }),
    };
    r.st.do_(|d| {
        d.grants.insert(id.clone(), g.clone());
    });
}

/// a global step or limit set for one test, put back when dropped (the caller holds serial())
pub struct U64Set(&'static std::sync::atomic::AtomicU64, u64);

pub fn set_u64(a: &'static std::sync::atomic::AtomicU64, v: u64) -> U64Set {
    U64Set(a, a.swap(v, std::sync::atomic::Ordering::SeqCst))
}

impl Drop for U64Set {
    fn drop(&mut self) {
        self.0.store(self.1, std::sync::atomic::Ordering::SeqCst);
    }
}
