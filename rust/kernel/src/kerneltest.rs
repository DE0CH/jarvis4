//! The whole kernel for tests (the Go kernel's, ported): this crate's own flip tests and the router's. Every component
//! runs in-process on its own loopback server, on a fake Fly whose machines have real key pairs and a fake GitHub (the
//! minter's), with a phone key and a root key the test holds, and secrets already claimed (Reset with a seed: no
//! stores). Two copies, blue and green (docs/PLAN-cluster.md "Releases: the copy flip"): `start` runs blue, which
//! serves; `release` starts green's components fresh, `roster_for`/`sign_roster` sign a copy's roster (green's retires
//! blue's members), `flip` hands blue over to green as the router does. A failed step panics (the test fails).

use crate::kt::{TestServer, source};
use crate::minter::{Client as MinterClient, DeployKey, GitHub, Minter};
use crate::notarizer::Notarizer;
use crate::notary::Notary;
use crate::secrets::Secrets;
use crate::serve::Server;
use crate::spawner::fly::{Fly, FlyError};
use crate::spawner::{MachineKeys, RunMachine, Spawner};
use crate::{merger, minter, mover, notarizer, notary, secrets, signers, spawner};
use jarvis_doc::gv::{Signed, ideal_keys};
use jarvis_doc::perm::{Pair, Set};
use jarvis_doc::{Cert, Grant, Object, SINK, Source, by, now, peek_cert};
use jarvis_sig::{Component, Doc, Identity, Opener, Roster, Signer, Trust};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

/// every kernel component (a copy has one of each; secrets last)
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

/// one kernel copy's running components
pub struct Copy {
    pub name: String,
    /// role → base URL
    pub url: BTreeMap<String, String>,
    pub secrets: Arc<Secrets>,
    /// the keys this copy's next roster names as retired (a component of it that restarted, or the other copy's
    /// members once this copy takes over)
    pub retired: Vec<Identity>,
}

/// the running copies and the keys a test signs with
pub struct Kernel {
    pub phone: Signer,
    pub phone_agree: Opener,
    pub root: Signer,
    /// the serving copy's components (role → base URL); `url_for` names a copy's own
    pub url: BTreeMap<String, String>,
    pub copies: BTreeMap<String, Copy>,
    /// the copy that serves
    pub active: String,
    pub fly: Arc<FakeFly>,
    /// the minter's
    pub github: FakeGitHub,
    pub secrets: Arc<Secrets>,
    servers: Vec<TestServer>,
    master: Signer,
    seed: Vec<u8>,
    env: BTreeMap<String, String>,
    dir: PathBuf,
    http: reqwest::blocking::Client,
}

impl Drop for Kernel {
    fn drop(&mut self) {
        self.servers.clear();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn rand_bytes(n: usize) -> Vec<u8> {
    use rand_core::RngCore as _;
    let mut b = vec![0u8; n];
    rand_core::OsRng.fill_bytes(&mut b);
    b
}

fn serve(c: Component, trust: Arc<Trust>) -> Arc<Server> {
    Server::new(c, trust)
}

/// a component's answer: its signed document, or the error it gave (its URL, path, status and payload)
fn post_with(
    http: &reqwest::blocking::Client,
    u: &str,
    path: &str,
    body: &Value,
) -> anyhow::Result<Doc> {
    let resp = http
        .post(format!("{u}{path}"))
        .header("Content-Type", "application/json")
        .body(jarvis_sig::go_json(body)?)
        .send()?;
    let status = resp.status().as_u16();
    let b = resp.bytes()?;
    let d: Doc = serde_json::from_slice(&b).unwrap_or(Doc {
        payload: String::from_utf8_lossy(&b).into_owned(),
        sig: String::new(),
    });
    if status != 200 {
        return Err(anyhow::anyhow!("{u}{path}: HTTP {status} {}", d.payload));
    }
    Ok(d)
}

/// the roster to one component
pub fn post_roster(u: &str, d: &Doc) -> anyhow::Result<()> {
    let resp = reqwest::blocking::Client::new()
        .post(format!("{u}/roster"))
        .header("Content-Type", "application/json")
        .body(jarvis_sig::go_json(&json!({"roster": d}))?)
        .send()?;
    let status = resp.status().as_u16();
    let b = resp.text().unwrap_or_default();
    if status != 200 {
        return Err(anyhow::anyhow!("{u}/roster: {status} {b}"));
    }
    Ok(())
}

/// a component's identity at u (secrets: the keys it serves with now)
pub fn identity_of(u: &str, role: &str) -> Identity {
    let b = reqwest::blocking::get(format!("{u}/identity"))
        .and_then(|r| r.bytes())
        .unwrap_or_else(|e| panic!("{u}/identity: {e}"));
    if role == "secrets" {
        #[derive(serde::Deserialize, Default)]
        #[serde(default, rename_all = "camelCase")]
        struct M {
            signing_key: String,
            agreement_key: String,
        }
        let m: M = serde_json::from_slice(&b).unwrap_or_default();
        return Identity {
            role: role.into(),
            signing_key: m.signing_key,
            agreement_key: m.agreement_key,
        };
    }
    let d: Doc = serde_json::from_slice(&b).unwrap_or_else(|e| panic!("{u}/identity: {e}"));
    serde_json::from_str(&d.payload).unwrap_or_else(|e| panic!("{u}/identity: {e}"))
}

/// a new line's documents (what GET /m/kernel/boot answers): `json` as the router serves them, `grant` typed
pub struct Boot {
    pub grant: Signed,
    pub json: Value,
}

impl Kernel {
    /// copy blue, serving; machine_env is what spawned machines' Fly config env gets
    pub fn start(machine_env: BTreeMap<String, String>) -> Kernel {
        let dir = std::env::temp_dir().join(format!(
            "kerneltest-{}",
            rand_bytes(8)
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect::<String>()
        ));
        let root = Signer::generate();
        let mut k = Kernel {
            phone: Signer::generate(),
            phone_agree: Opener::generate(),
            secrets: Arc::new(Secrets::new(&root.public_key(), None)),
            root,
            url: BTreeMap::new(),
            copies: BTreeMap::new(),
            active: "blue".into(),
            fly: Arc::new(FakeFly::default()),
            github: FakeGitHub::default(),
            servers: vec![],
            master: Signer::generate(),
            seed: rand_bytes(32),
            env: machine_env,
            dir,
            http: reqwest::blocking::Client::new(),
        };
        k.start_copy("blue");
        let blue = &k.copies["blue"];
        k.url = blue.url.clone();
        k.secrets = blue.secrets.clone();
        let (sc, seed) = (k.secrets.clone(), k.seed.clone());
        k.claim_seeded(&sc, &seed)
            .unwrap_or_else(|e| panic!("the claim: {e:#}"));
        k.sign_roster("blue")
            .unwrap_or_else(|e| panic!("blue's roster: {e:#}"));
        k
    }

    fn serve_on(&mut self, h: jarvis_nethttp::HandlerFn) -> String {
        let srv = TestServer::handler(move |w, r| h(w, r));
        let u = srv.url.clone();
        self.servers.push(srv);
        u
    }

    /// a stateless component's server, fresh keys
    fn stateless(&mut self, role: &str) -> String {
        let s = serve(
            Component::new(role),
            Arc::new(Trust::new(&self.root.public_key())),
        );
        match role {
            "mover" => mover::register(&s),
            "merger" => merger::register(&s),
            "identity" => signers::register_identity(&s),
            "gullible" => signers::register_gullible(&s),
            "minter" => minter::register(&s, Arc::new(Minter::new(Box::new(self.github.clone())))),
            _ => panic!(
                "{role} keeps state; only mover, merger, identity, gullible and minter are stateless"
            ),
        }
        self.serve_on(s.handler())
    }

    /// fresh components for a copy (its volumes kept from an earlier run of it), none holding a roster
    fn start_copy(&mut self, name: &str) {
        let dir = self.dir.join(name);
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        let mut url = BTreeMap::new();
        for role in &ROLES[..8] {
            let u = match *role {
                "notary" | "notarizer" | "spawner" => {
                    let s = serve(
                        Component::new(role),
                        Arc::new(Trust::new(&self.root.public_key())),
                    );
                    match *role {
                        "notary" => notary::register(
                            &s,
                            Arc::new(
                                Notary::open(&dir.join("notary"))
                                    .unwrap_or_else(|e| panic!("{e:#}")),
                            ),
                        ),
                        "notarizer" => notarizer::register(
                            &s,
                            Arc::new(
                                Notarizer::open(&dir.join("notarizer"), &s.trust)
                                    .unwrap_or_else(|e| panic!("{e:#}")),
                            ),
                        ),
                        _ => {
                            let sp = Spawner::open(
                                &dir.join("spawner"),
                                Signer::from_scalar(&s.c.signer.scalar())
                                    .unwrap_or_else(|e| panic!("{e}")),
                                Opener::from_scalar(&s.c.agreement.scalar())
                                    .unwrap_or_else(|e| panic!("{e}")),
                                s.trust.clone(),
                                self.fly.clone(),
                                None,
                                Some(self.env.clone()),
                                None,
                            )
                            .unwrap_or_else(|e| panic!("{e:#}"));
                            spawner::register(&s, Arc::new(sp));
                        }
                    }
                    self.serve_on(s.handler())
                }
                _ => self.stateless(role),
            };
            url.insert(role.to_string(), u);
        }
        let sc = Arc::new(Secrets::new(
            &self.root.public_key(),
            Some(Box::new(MinterClient::new(&url["minter"]))),
        ));
        let u = self.serve_on(secrets::http::handler(sc.clone()));
        url.insert("secrets".into(), u);
        let retired = self
            .copies
            .get(name)
            .map(|c| c.retired.clone())
            .unwrap_or_default();
        self.copies.insert(
            name.into(),
            Copy {
                name: name.into(),
                url,
                secrets: sc,
                retired,
            },
        );
    }

    /// the base URL of a role in the serving copy, or of a Deployment "<role>-<copy>" (what the router's KERNEL_URL
    /// template gives)
    pub fn url_for(&self, name: &str) -> String {
        for (c, cp) in &self.copies {
            if let Some(r) = name.strip_suffix(&format!("-{c}")) {
                return cp.url.get(r).cloned().unwrap_or_default();
            }
        }
        self.url.get(name).cloned().unwrap_or_default()
    }

    /// the copy serves from now on (a router's flip, as the test's helpers see it)
    pub fn serve(&mut self, copy: &str) {
        self.active = copy.into();
        self.url = self.copies[copy].url.clone();
        self.secrets = self.copies[copy].secrets.clone();
    }

    /// the copy that doesn't serve
    pub fn other(&self) -> String {
        if self.active == "blue" {
            "green"
        } else {
            "blue"
        }
        .into()
    }

    /// a kernel release lands on the copy that doesn't serve: every one of its components starts again fresh (its
    /// volumes kept), its secrets empty; its roster (roster_for) retires the serving copy's members
    pub fn release(&mut self) -> &mut Copy {
        let other = self.other();
        self.start_copy(&other);
        let mut retired: Vec<Identity> = ROLES[..8]
            .iter()
            .map(|r| self.identity_at(&self.active, r))
            .collect();
        retired.extend(self.copies[&self.active].retired.clone());
        let cp = self
            .copies
            .get_mut(&other)
            .unwrap_or_else(|| panic!("no {other}"));
        cp.retired = retired;
        cp
    }

    /// the root key's roster of a copy as its components answer now. The serving copy's names its retired keys
    /// (components that restarted); the other copy's names the secrets the kit derives (the serving one's keys), its
    /// own empty secrets as secretsBoot, and the serving copy's members as retired.
    pub fn roster_for(&self, copy: &str) -> anyhow::Result<Doc> {
        let mut ids: Vec<Identity> = ROLES.iter().map(|r| self.identity_at(copy, r)).collect();
        let mut r = Roster {
            copy: copy.into(),
            retired: self.copies[copy].retired.clone(),
            ..Default::default()
        };
        if copy != self.active {
            let boot = ids[ids.len() - 1].clone();
            let n = ids.len() - 1;
            ids[n] = self.identity_at(&self.active, "secrets");
            r.secrets_boot = Some(boot);
        }
        r.members = ids;
        let p = r.payload()?;
        Ok(Doc {
            sig: self.root.sign(p.as_bytes()),
            payload: p,
        })
    }

    /// the serving copy's roster
    pub fn roster(&self) -> anyhow::Result<Doc> {
        self.roster_for(&self.active)
    }

    /// the serving copy's roster as a machine (or a test) holds it
    pub fn trust(&self) -> Trust {
        let d = self.roster().unwrap_or_else(|e| panic!("{e:#}"));
        let t = Trust::new(&self.root.public_key());
        t.set(d, None).unwrap_or_else(|e| panic!("{e}"));
        t
    }

    /// the copy's roster to each of its components
    pub fn sign_roster(&self, copy: &str) -> anyhow::Result<()> {
        let d = self.roster_for(copy)?;
        for u in self.copies[copy].url.values() {
            post_roster(u, &d)?;
        }
        Ok(())
    }

    /// the serving copy's roster to its components (and to extra, another secrets' URL, if not "")
    pub fn post_roster(&self, extra: &str) -> anyhow::Result<()> {
        self.sign_roster(&self.active)?;
        if !extra.is_empty() {
            post_roster(extra, &self.roster()?)?;
        }
        Ok(())
    }

    /// what the router does once the other copy's roster is signed: every serving component hands over (the stateful
    /// ones' state sealed to the other copy), the other copy's notarizer, spawner and secrets take it, and the other
    /// copy serves
    pub fn flip(&mut self) {
        let to = self.other();
        let d = self.roster_for(&to).unwrap_or_else(|e| panic!("{e:#}"));
        let mut handoffs = BTreeMap::new();
        for role in ROLES {
            let h = post_with(
                &self.http,
                &self.copies[&self.active].url[role],
                "/handoff",
                &json!({"roster": d}),
            )
            .unwrap_or_else(|e| panic!("{role}'s handoff: {e:#}"));
            handoffs.insert(role, h);
        }
        for role in ["notarizer", "spawner", "secrets"] {
            post_with(
                &self.http,
                &self.copies[&to].url[role],
                "/takeover",
                &json!({"handoff": handoffs[role]}),
            )
            .unwrap_or_else(|e| panic!("{role}'s takeover: {e:#}"));
        }
        self.serve(&to);
    }

    /// a component's identity in a copy (secrets: the keys it serves with now)
    pub fn identity_at(&self, copy: &str, role: &str) -> Identity {
        identity_of(&self.copies[copy].url[role], role)
    }

    /// a serving component's identity
    pub fn identity(&self, role: &str) -> Identity {
        identity_of(&self.url[role], role)
    }

    /// ⊤ on the sink, signed by the root key (what the app signs once after the claim)
    pub fn root_top(&self) -> Doc {
        let ik = ideal_keys(&Object(SINK.into())).unwrap_or_else(|e| panic!("{e}"));
        self.root
            .sign_json(&Grant {
                kind: "grant".into(),
                machine: Object(SINK.into()),
                keys: ik,
                pair: Pair::top(),
                from: Some(vec![]),
                at: now(),
            })
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// a serving component's answer (a signed document), or the error it gave
    pub fn post_role(&self, role: &str, path: &str, body: &Value) -> anyhow::Result<Doc> {
        post_with(&self.http, &self.url[role], path, body)
            .map_err(|e| anyhow::anyhow!("{role}: {e:#}"))
    }

    /// a component's answer by its Deployment name ("<role>-<copy>") or serving role, or the error it gave
    pub fn post(&self, name: &str, path: &str, body: &Value) -> anyhow::Result<Doc> {
        post_with(&self.http, &self.url_for(name), path, body)
    }

    /// the notary's challenge, then the notarizer
    pub fn notarize(&self, cert: &Doc) -> Doc {
        let c = peek_cert(cert).unwrap_or_else(|e| panic!("{e}"));
        let ch = self
            .post_role(
                "notary",
                "/challenge",
                &json!({"subject": cert.id(), "about": "cert"}),
            )
            .unwrap_or_else(|e| panic!("{e:#}"));
        let mut i = json!({"cert": cert, "challenge": ch, "notary": self.identity("notary")});
        if c.signer == by::IPHONE || c.signer == by::ROOT {
            let ks = self
                .post_role("secrets", "/keys", &json!({}))
                .unwrap_or_else(|e| panic!("{e:#}"));
            i["keys"] = json!(ks);
            i["secrets"] = json!(self.identity("secrets"));
        } else {
            i["signer"] = json!(self.identity(&c.signer));
        }
        self.post_role("notarizer", "/notarize", &i)
            .unwrap_or_else(|e| panic!("{e:#}"))
    }

    /// g along the notarized cert
    pub fn mv(&self, g: &Signed, cert: &Doc, nz: &Doc) -> Signed {
        let mut i = json!({"grant": g.grant, "by": g.by, "cert": cert, "notarized": nz,
            "notarizer": self.identity("notarizer"), "notary": self.identity("notary")});
        if let Some(s) = &g.signer {
            i["signer"] = json!(s);
        }
        if g.by == "root" {
            let ks = self
                .post_role("secrets", "/keys", &json!({}))
                .unwrap_or_else(|e| panic!("{e:#}"));
            i["keys"] = json!(ks);
            i["secrets"] = json!(self.identity("secrets"));
        }
        let d = self
            .post_role("mover", "/move", &i)
            .unwrap_or_else(|e| panic!("{e:#}"));
        Signed {
            grant: d,
            by: "mover".into(),
            signer: Some(self.identity("mover")),
            keys: None,
            secrets: None,
        }
    }

    /// a spawn from a notarized source cert → the machine id
    pub fn spawn(&self, cert: &Doc, nz: &Doc) -> anyhow::Result<String> {
        let d = self.post_role(
            "spawner",
            "/spawn",
            &json!({"cert": cert, "notarized": nz, "notarizer": self.identity("notarizer"), "region": "lhr",
                "size": "medium", "diskGb": 10}),
        )?;
        let v: Value = serde_json::from_str(&d.payload)?;
        Ok(v["id"].as_str().unwrap_or_default().to_string())
    }

    /// a new line run through the kernel as the router runs it: the phone's cert into a new source (with these
    /// settings and stores, for session sid), notarized, the root's ⊤ moved onto it; a spawn; the spawner's cert,
    /// notarized, the grant moved onto the machine. Its boot documents (what GET /m/kernel/boot answers) and the Fly
    /// machine.
    pub fn line(
        &self,
        sid: &str,
        image: &str,
        settings: &str,
        stores: &[&str],
    ) -> (Boot, FakeMachine) {
        let allowed: Vec<String> = stores.iter().map(|s| format!("store:{s}")).collect();
        let c = Cert {
            kind: "succession".into(),
            pred: Object(SINK.into()),
            succ: Object(source()),
            pair: Pair::new(Set::only(allowed), vec![format!("session:{sid}")]),
            source: Some(Source {
                image: image.into(),
                settings: serde_json::value::RawValue::from_string(settings.into())
                    .unwrap_or_else(|e| panic!("{e}")),
                snapshot: String::new(),
            }),
            machine: None,
            signer: by::IPHONE.into(),
            issued_at: now(),
        };
        let sc = self.phone.sign_json(&c).unwrap_or_else(|e| panic!("{e}"));
        let snz = self.notarize(&sc);
        let root = Signed {
            grant: self.root_top(),
            by: "root".into(),
            signer: None,
            keys: None,
            secrets: None,
        };
        let g = self.mv(&root, &sc, &snz);
        let id = self.spawn(&sc, &snz).unwrap_or_else(|e| panic!("{e:#}"));
        let mc = self
            .post_role("spawner", "/init", &json!({"id": id}))
            .unwrap_or_else(|e| panic!("{e:#}"));
        let mnz = self.notarize(&mc);
        let g = self.mv(&g, &mc, &mnz);
        let mut out = json!({"grant": g, "machineCert": mc, "machineNotarized": mnz, "sourceCert": sc,
            "sourceNotarized": snz});
        for r in [
            "notary",
            "notarizer",
            "mover",
            "merger",
            "spawner",
            "secrets",
        ] {
            out[r] = json!(self.identity(r));
        }
        out["keys"] = json!(self.post_role("secrets", "/keys", &json!({})).ok());
        out["stores"] = json!(
            self.post_role("secrets", "/stores", &json!({"nonce": "n"}))
                .ok()
        );
        let m = self
            .fly
            .machine(&id)
            .unwrap_or_else(|| panic!("no machine {id}"));
        (
            Boot {
                grant: g,
                json: out,
            },
            m,
        )
    }

    /// a log-notary challenge (what the router asks for before an input reaches a kernel machine)
    pub fn challenge(&self, subject: &str, about: &str) -> Doc {
        self.post_role(
            "notary",
            "/challenge",
            &json!({"subject": subject, "about": about}),
        )
        .unwrap_or_else(|e| panic!("{e:#}"))
    }

    /// a claim of sc with keys derived from seed (the same kit derives the same secrets), by the test's master key
    pub fn claim_seeded(&self, sc: &Secrets, seed: &[u8]) -> anyhow::Result<()> {
        use base64::Engine as _;
        use sha2::Digest as _;
        let me = sc.component_identity();
        let (ds, da) = secrets::continuity::seed_identity(seed)?;
        let b = jarvis_sig::go_json(
            &json!({"format": "keys", "secretsSeed": base64::engine::general_purpose::STANDARD.encode(seed)}),
        )?;
        let sum = sha2::Sha256::digest(b.as_bytes());
        let st = json!({"kind": "kernel-claim", "master": self.master.public_key(),
            "secrets": {"signingKey": me.signing_key, "agreementKey": me.agreement_key},
            "phone": {"signingKey": self.phone.public_key(), "agreementKey": self.phone_agree.public_key()},
            "root": self.root.public_key(),
            "bundleSha256": sum.iter().map(|x| format!("{x:02x}")).collect::<String>(),
            "identity": {"signingKey": ds, "agreementKey": da}});
        let sb = jarvis_sig::go_json(&st)?;
        let ms = self.master.sign(sb.as_bytes());
        let sealed = jarvis_sig::seal_to(&me.agreement_key, b.as_bytes(), "jarvis2/kernel-claim")?;
        sc.claim(&sb, &ms, &sealed)?;
        Ok(())
    }

    /// a stateless component (mover, merger, identity, gullible, minter) of the serving copy starts again as a crash
    /// restart does: fresh keys, no roster, on a new server (url_for names it from now on; secrets keeps calling the
    /// minter it was started with). Its old keys go into the copy's next roster as retired.
    pub fn restart(&mut self, role: &str) {
        let old = self.identity_at(&self.active, role);
        let u = self.stateless(role);
        let active = self.active.clone();
        let cp = self
            .copies
            .get_mut(&active)
            .unwrap_or_else(|| panic!("no {active}"));
        cp.retired.push(old);
        cp.url.insert(role.into(), u.clone());
        self.url.insert(role.into(), u);
    }
}

// ---- a fake GitHub (the minter's) ---------------------------------------------------------------------------------

#[derive(Default)]
pub struct GitHubState {
    n: i64,
    /// deploy keys per repo
    pub keys: BTreeMap<String, Vec<DeployKey>>,
    /// every token it was called with
    pub tokens: Vec<String>,
}

#[derive(Default, Clone)]
pub struct FakeGitHub(Arc<Mutex<GitHubState>>);

impl FakeGitHub {
    pub fn st(&self) -> MutexGuard<'_, GitHubState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl GitHub for FakeGitHub {
    fn add_deploy_key(
        &self,
        token: &str,
        repo: &str,
        title: &str,
        public_key: &str,
    ) -> anyhow::Result<DeployKey> {
        let mut g = self.st();
        g.n += 1;
        let k = DeployKey {
            id: g.n,
            title: title.into(),
            key: public_key.into(),
        };
        g.keys.entry(repo.into()).or_default().push(k.clone());
        g.tokens.push(token.into());
        Ok(k)
    }

    fn delete_deploy_key(&self, token: &str, repo: &str, id: i64) -> anyhow::Result<()> {
        let mut g = self.st();
        g.keys
            .entry(repo.into())
            .or_default()
            .retain(|k| k.id != id);
        g.tokens.push(token.into());
        Ok(())
    }
}

// ---- a fake Fly ---------------------------------------------------------------------------------------------------

/// one machine, with the key pairs its image made
#[derive(Clone)]
pub struct FakeMachine {
    pub id: String,
    pub image: String,
    pub state: String,
    /// the source its Fly metadata names
    pub source: String,
    pub volume: String,
    pub env: BTreeMap<String, String>,
    pub sig: Arc<Signer>,
    pub enc: Arc<Opener>,
}

#[derive(Default)]
pub struct FlyState {
    n: i64,
    pub machines: BTreeMap<String, FakeMachine>,
    pub vols: BTreeMap<String, bool>,
    /// new machines stay "starting" until `up`
    pub booting: bool,
    /// the next this-many creates answer that the volume's host is full (Fly's 412 volume_placement_capacity)
    pub full: usize,
    /// the next this-many creates make the machine but answer an error (a lost answer)
    pub lose: usize,
    /// volume deletes fail (Fly still holds the volume)
    pub stuck_volumes: bool,
}

#[derive(Default)]
pub struct FakeFly(Mutex<FlyState>);

impl FakeFly {
    pub fn st(&self) -> MutexGuard<'_, FlyState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// a booting machine is started
    pub fn up(&self, id: &str) {
        if let Some(m) = self.st().machines.get_mut(id) {
            m.state = "started".into();
        }
    }

    pub fn machine(&self, id: &str) -> Option<FakeMachine> {
        self.st().machines.get(id).cloned()
    }

    /// every machine, as Fly's machine list shows them to the router's read-only token
    pub fn list(&self) -> Vec<FakeMachine> {
        self.st().machines.values().cloned().collect()
    }

    /// the volumes Fly still has
    pub fn volumes(&self) -> Vec<String> {
        self.st().vols.keys().cloned().collect()
    }

    /// the machine stopped outside Jarvis (someone ran fly machine stop, or it exited)
    pub fn stop(&self, id: &str) {
        if let Some(m) = self.st().machines.get_mut(id) {
            m.state = "stopped".into();
        }
    }
}

impl Fly for FakeFly {
    fn configure(&self, _: &str) {}

    fn create_volume(&self, _: &str, _: i64, _: &Value) -> anyhow::Result<String> {
        let mut g = self.st();
        g.n += 1;
        let v = format!("vol_{}", g.n);
        g.vols.insert(v.clone(), true);
        Ok(v)
    }

    fn create(
        &self,
        image: &str,
        _: &str,
        _: &Value,
        env: &BTreeMap<String, String>,
        volume: &str,
        source: &str,
    ) -> anyhow::Result<String> {
        let mut g = self.st();
        if g.full > 0 {
            g.full -= 1;
            return Err(FlyError {
                http: 412,
                status: "volume_placement_capacity".into(),
                msg: format!(
                    "POST /machines: HTTP 412 insufficient resources to create new machine with existing volume {volume}"
                ),
            }
            .into());
        }
        g.n += 1;
        let id = format!("{:014x}", g.n);
        let state = if g.booting { "starting" } else { "started" };
        g.machines.insert(
            id.clone(),
            FakeMachine {
                id: id.clone(),
                image: image.into(),
                state: state.into(),
                source: source.into(),
                volume: volume.into(),
                env: env.clone(),
                sig: Arc::new(Signer::generate()),
                enc: Arc::new(Opener::generate()),
            },
        );
        if g.lose > 0 {
            g.lose -= 1;
            return Err(anyhow::anyhow!("connection reset"));
        }
        Ok(id)
    }

    fn inspect(&self, id: &str) -> anyhow::Result<RunMachine> {
        let g = self.st();
        Ok(match g.machines.get(id) {
            None => RunMachine {
                state: "destroyed".into(),
                ..Default::default()
            },
            Some(m) => RunMachine {
                state: m.state.clone(),
                image: m.image.replacen(":latest", "", 1),
                volume: m.volume.clone(),
                source: m.source.clone(),
            },
        })
    }

    fn init(&self, id: &str) -> anyhow::Result<MachineKeys> {
        let g = self.st();
        let m = g
            .machines
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("no machine {id}"))?;
        Ok(MachineKeys {
            signing_key: m.sig.public_key(),
            encryption_key: m.enc.public_key(),
        })
    }

    fn destroy(&self, id: &str) -> anyhow::Result<()> {
        if let Some(m) = self.st().machines.get_mut(id) {
            m.state = "destroyed".into();
        }
        Ok(())
    }

    fn delete_volume(&self, v: &str) -> anyhow::Result<()> {
        let mut g = self.st();
        if g.stuck_volumes {
            return Err(FlyError {
                http: 412,
                status: String::new(),
                msg: format!("DELETE /volumes/{v}: HTTP 412 volume is attached"),
            }
            .into());
        }
        g.vols.remove(v);
        Ok(())
    }
}
