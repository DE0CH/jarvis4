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
                    if !m.fail.is_empty() && p.starts_with(&m.fail) {
                        return w.write_header(507);
                    }
                    let parent = dav_parent(&p);
                    if parent != "." && !m.dirs.contains(&parent) {
                        return w.write_header(409);
                    }
                    let b = req.read_body(1 << 30);
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

impl FakeCore {
    pub fn new() -> FakeCore {
        let key = Arc::new(TestKey::new());
        let calls: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let (k, c) = (key.clone(), calls.clone());
        let srv = TestServer::handler(move |w, req| {
            c.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(req.path.clone());
            use crate::nethttp::write_json;
            use serde_json::json;
            match req.path.as_str() {
                "/key" => write_json(w, 200, &json!({"signingKey": k.public()})),
                // a set-up core (features.rs core_set_up)
                "/identity" => write_json(
                    w,
                    200,
                    &json!({"signingKey": k.public(), "state": k.doc(&json!({"kind": "core-state", "master": "m"}))}),
                ),
                "/core-cert" => write_json(w, 200, &json!({"statement": "{}", "masterSig": "x"})),
                // the core's record names the snapshot the kill named (core.rs kill_with_snapshot)
                "/kill" => {
                    let b: serde_json::Value =
                        serde_json::from_slice(&req.read_body(1 << 20)).unwrap_or_default();
                    let sum = b["snapshot"]["sha256"].as_str().unwrap_or("").to_string();
                    write_json(w, 200, &k.doc(&json!({"kind": "killed", "id": b["machine"], "snapshot": sum, "path": req.path})));
                }
                p => write_json(w, 200, &k.doc(&json!({"kind": "ok", "path": p}))),
            }
        });
        FakeCore { key, calls, srv }
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
        use serde_json::json;
        crate::storagebox::PUT_BACKOFF_MS.store(1, std::sync::atomic::Ordering::Relaxed);
        let dav = MemDav::new();
        let core = FakeCore::new();
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
        let t = new_test_router_with(
            |c| {
                c.no_access = false;
                c.snapshot_stall = std::time::Duration::from_secs(1);
                c.session_image = "img".into();
            },
            Some(&core.srv.url),
            policy,
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
