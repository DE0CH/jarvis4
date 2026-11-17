//! What the ported tests share: the one lock, a fresh HOME and machine directory, test keys, a fake router that checks
//! each request's machine signature (apiproxy_test.go fakeRouter).

use crate::client::Client;
use crate::crypto::{Keys, SignedDoc, sha256_hex};
use crate::grants::{Exec, ExecRequest};
use crate::{env, gojson, paths, rt};
use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use jarvis_sig::Signer;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

static LOCK: Mutex<()> = Mutex::new(());

/// one test at a time, with a fresh HOME (env HOME) and machine directory; everything reset when it ends
pub struct TestEnv {
    _g: MutexGuard<'static, ()>,
    pub root: PathBuf,
    pub home: PathBuf,
    pub dir: PathBuf,
}

static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn tempdir() -> PathBuf {
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("jm-test-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

impl TestEnv {
    pub fn new() -> TestEnv {
        let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_seams();
        let root = tempdir();
        let (home, dir) = (root.join("home"), root.join("run"));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        paths::set_dir(&dir);
        env::set("HOME", Some(home.to_str().unwrap()));
        TestEnv { _g: g, root, home, dir }
    }

    /// the machine's private key on disk (the client signs with it)
    pub fn machine_key(&self) -> Keys {
        let k = Keys::generate();
        std::fs::write(paths::priv_path(), k.private_json()).unwrap();
        std::fs::write(paths::keys_path(), k.public_json()).unwrap();
        k
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        reset_seams();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn reset_seams() {
    env::reset();
    *crate::grants::TEST_CERT.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *crate::outcomes::TEST_CORE_KEY.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *crate::apiproxy::TEST_CORE_KEY.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *crate::snapshot::TEST_BOOTED.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *crate::memory::TEST_SIGNALS.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *crate::stall::TEST_SHELL_JOBS.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *crate::deliver::TEST_CHANNEL.write().unwrap_or_else(|e| e.into_inner()) = None;
    *crate::deliver::PREDECESSOR_KEY.lock().unwrap_or_else(|e| e.into_inner()) = String::new();
    crate::deliver::RESTORED_ARCHIVE.store(false, std::sync::atomic::Ordering::SeqCst);
    crate::snapshot::FROZEN.store(false, std::sync::atomic::Ordering::SeqCst);
    crate::snapshot::FULL_SNAPSHOT.store(false, std::sync::atomic::Ordering::SeqCst);
    *crate::snapstream::SIGNED.lock().unwrap_or_else(|e| e.into_inner()) = Default::default();
    *crate::memory::PROC_ROOT.write().unwrap_or_else(|e| e.into_inner()) = None;
    *crate::stall::CLAUDE_SESSIONS.write().unwrap_or_else(|e| e.into_inner()) = None;
    *crate::pressure::GUARD_LOG_PATH.write().unwrap_or_else(|e| e.into_inner()) = None;
    *paths::PREDECESSOR_TMP.write().unwrap_or_else(|e| e.into_inner()) = None;
    crate::secrets::HELD.set_for_test(Default::default());
}

/// a test key pair (grants_test.go tkey)
pub struct Tkey(pub Signer);

pub fn new_key() -> Tkey {
    Tkey(Signer::generate())
}

impl Tkey {
    pub fn public(&self) -> String {
        self.0.public_key()
    }

    /// v marshalled (as Go's json.Marshal) and signed
    pub fn doc<T: serde::Serialize>(&self, v: &T) -> SignedDoc {
        let b = gojson::marshal(v);
        SignedDoc {
            sig: self.0.sign(b.as_bytes()),
            payload: b,
        }
    }

    pub fn req(&self, r: &ExecRequest) -> Exec {
        let b = gojson::marshal(r);
        Exec {
            sig: self.0.sign(b.as_bytes()),
            request: b,
            grant: None,
        }
    }
}

/// what the fake router's handler gets
#[derive(Debug, Clone)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: axum::http::HeaderMap,
    pub body: Vec<u8>,
}

/// what it answers
pub struct Ans {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub fn ans(status: u16, body: impl Into<Vec<u8>>) -> Ans {
    Ans {
        status,
        headers: vec![],
        body: body.into(),
    }
}

pub fn ok_json(v: serde_json::Value) -> Ans {
    ans(200, gojson::marshal(&v))
}

type Handler = Arc<dyn Fn(Req) -> Ans + Send + Sync>;

/// A router on 127.0.0.1 that answers 401 unless the request carries machine m1's signature by `key` over its method,
/// decoded path, time and body; the client the tests use against it
pub struct FakeRouter {
    pub url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for FakeRouter {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl FakeRouter {
    pub fn new(key: &str, h: impl Fn(Req) -> Ans + Send + Sync + 'static) -> FakeRouter {
        let key = key.to_string();
        let h: Handler = Arc::new(h);
        rt::block_on(async move {
            let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", ln.local_addr().unwrap());
            let app = axum::Router::new().fallback(move |req: Request| {
                let (h, key) = (h.clone(), key.clone());
                async move {
                    let (parts, body) = req.into_parts();
                    let body = axum::body::to_bytes(body, 1 << 30).await.unwrap().to_vec();
                    let path = crate::util::path_unescape(parts.uri.path());
                    let t = parts.headers.get("X-Time").and_then(|v| v.to_str().ok()).unwrap_or("");
                    let sig = parts.headers.get("X-Sig").and_then(|v| v.to_str().ok()).unwrap_or("");
                    let me = parts.headers.get("X-Machine").and_then(|v| v.to_str().ok()).unwrap_or("");
                    let sum = if sig.is_empty() { String::new() } else { sha256_hex(&body) };
                    let msg = format!("{} {} {t} {sum}", parts.method, path);
                    let stream_msg = format!("{} {} {t} stream", parts.method, path);
                    let good = me == "m1"
                        && (jarvis_sig::verify(&key, msg.as_bytes(), sig) || jarvis_sig::verify(&key, stream_msg.as_bytes(), sig));
                    if !good {
                        let mut r = Response::new(Body::empty());
                        *r.status_mut() = StatusCode::UNAUTHORIZED;
                        return r;
                    }
                    let req = Req {
                        method: parts.method.to_string(),
                        path,
                        query: parts.uri.query().unwrap_or("").to_string(),
                        headers: parts.headers.clone(),
                        body,
                    };
                    let a = tokio::task::spawn_blocking(move || h(req)).await.unwrap();
                    let mut r = Response::new(Body::from(a.body));
                    *r.status_mut() = StatusCode::from_u16(a.status).unwrap();
                    for (k, v) in a.headers {
                        r.headers_mut().insert(
                            axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                            axum::http::HeaderValue::from_str(&v).unwrap(),
                        );
                    }
                    r
                }
            });
            let handle = tokio::spawn(async move {
                let _ = axum::serve(ln, app).await;
            });
            FakeRouter { url, handle }
        })
    }

    /// a client of this router as machine m1
    pub fn client(&self) -> Client {
        Client::with_url(&self.url, "m1")
    }
}
