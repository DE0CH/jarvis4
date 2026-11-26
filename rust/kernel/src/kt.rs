//! A kernel for tests (kernel/internal/kt): every component's identity and the root key's roster of them, the phone
//! and root keys, secrets' signed keys statement, and certs made and signed as each signer would.

use jarvis_doc::perm::Pair;
use jarvis_doc::{Cert, Challenge, Keys, Machine, Object, Source, by};
use jarvis_sig::{Component, Doc, Identity, Roster, Signer, Trust};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;

pub const ROLES: [&str; 9] = [
    "notary",
    "notarizer",
    "mover",
    "merger",
    "spawner",
    "identity",
    "gullible",
    "minter",
    "secrets",
];

pub const IMAGE: &str = "ghcr.io/de0ch/jarvis4-session@sha256:1111111111111111111111111111111111111111111111111111111111111111";

pub struct World {
    /// holds the root key's roster of c
    pub trust: Arc<Trust>,
    pub roster: Doc,
    /// by role
    pub c: BTreeMap<String, Component>,
    pub phone: Signer,
    pub root: Signer,
    pub keys_doc: Doc,
}

/// the root key's roster r
pub fn sign_roster(root: &Signer, r: &Roster) -> Doc {
    let p = r.payload().unwrap_or_else(|e| panic!("{e}"));
    Doc {
        sig: root.sign(p.as_bytes()),
        payload: p,
    }
}

impl World {
    pub fn new() -> World {
        let c: BTreeMap<String, Component> = ROLES
            .iter()
            .map(|r| (r.to_string(), Component::new(r)))
            .collect();
        let phone = Signer::generate();
        let root = Signer::generate();
        let roster = sign_roster(
            &root,
            &Roster {
                copy: "blue".into(),
                members: ROLES.iter().map(|r| c[*r].identity.clone()).collect(),
                ..Default::default()
            },
        );
        let trust = Arc::new(Trust::new(&root.public_key()));
        trust
            .set(roster.clone(), None)
            .unwrap_or_else(|e| panic!("{e}"));
        let keys_doc = c["secrets"]
            .signer
            .sign_json(
                &json!({"kind": "keys", "phone": phone.public_key(), "root": root.public_key()}),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        World {
            trust,
            roster,
            c,
            phone,
            root,
            keys_doc,
        }
    }

    pub fn id(&self, role: &str) -> Identity {
        self.c[role].identity.clone()
    }

    /// a cert signed as signer would sign it (the iPhone and root by their keys, the others by their component)
    pub fn cert(
        &self,
        signer: &str,
        pred: &str,
        succ: &str,
        p: &Pair,
        src: Option<Source>,
        m: Option<Machine>,
    ) -> Doc {
        let c = Cert {
            kind: "succession".into(),
            pred: Object(pred.into()),
            succ: Object(succ.into()),
            pair: p.clone(),
            source: src,
            machine: m,
            signer: signer.into(),
            issued_at: jarvis_doc::now(),
        };
        let s = match signer {
            by::IPHONE => &self.phone,
            by::ROOT => &self.root,
            other => &self.c[other].signer,
        };
        s.sign_json(&c).unwrap_or_else(|e| panic!("{e}"))
    }

    /// a notary challenge over subject (as the notary signs it, at the given time)
    pub fn challenge(&self, subject: &str, about: &str, at: time::OffsetDateTime) -> Doc {
        self.c["notary"]
            .signer
            .sign_json(&Challenge {
                kind: "challenge".into(),
                seq: 1,
                prev: String::new(),
                at: jarvis_doc::rfc3339_nano(at),
                subject: subject.into(),
                about: about.into(),
                nonce: "00".into(),
            })
            .unwrap_or_else(|e| panic!("{e}"))
    }
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

/// a fresh source name
pub fn source() -> String {
    use rand_core::RngCore as _;
    let mut b = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut b);
    format!(
        "source-{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

/// a source with settings {"title": title}
pub fn source_content(title: &str) -> Source {
    Source {
        image: IMAGE.into(),
        settings: serde_json::value::RawValue::from_string(json!({"title": title}).to_string())
            .unwrap_or_else(|e| panic!("{e}")),
        snapshot: String::new(),
    }
}

/// a Fly machine's keys
pub fn machine_keys() -> (Signer, Machine) {
    let s = Signer::generate();
    let e = Signer::generate();
    let m = Machine {
        signing_key: s.public_key(),
        encryption_key: e.public_key(),
        image: IMAGE.into(),
    };
    (s, m)
}

/// a machine's keys as doc::Keys
pub fn keys_of(m: &Machine) -> Keys {
    Keys {
        signing_key: m.signing_key.clone(),
        encryption_key: m.encryption_key.clone(),
    }
}

/// an HTTP server on a loopback port for a test's stand-ins (a fake hermit, a fake EC2), stopped when dropped
pub struct TestServer {
    pub url: String,
    stop: tokio_util::sync::CancellationToken,
    th: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    pub fn handler(
        f: impl Fn(&mut jarvis_nethttp::W, &mut jarvis_nethttp::Req) + Send + Sync + 'static,
    ) -> TestServer {
        let stop = tokio_util::sync::CancellationToken::new();
        let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
        let url = format!(
            "http://{}",
            ln.local_addr().unwrap_or_else(|e| panic!("{e}"))
        );
        ln.set_nonblocking(true).unwrap_or_else(|e| panic!("{e}"));
        let s2 = stop.clone();
        let h: jarvis_nethttp::HandlerFn = Arc::new(f);
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
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(th) = self.th.take() {
            let _ = th.join();
        }
    }
}
