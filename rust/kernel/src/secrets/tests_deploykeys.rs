//! kernel/secrets/deploykeys_test.go: deploy keys through the minter, on a GitHub stand-in

use super::deploykeys::{DEPLOY_KEY_TOKEN_KEY, DEPLOY_KEY_TOKEN_STORE, DeployKeyRequest};
use super::keys::KeyEntry;
use super::tests::{
    Phone, claim_for, pl, setup, store_key, test_values, unlock, wrap_to_point, write_store,
};
use super::{Err as SErr, MinterApi, Secrets, sha256_hex};
use crate::kt::{ROLES, World, sign_roster};
use crate::minter::{DeployKey, GitHub, GitHubError, MintError, Minter, Request, TOKEN_INFO};
use crate::serve::Fail;
use jarvis_sig::{Component, Doc, Opener, Roster, Sealed, Signer, b64, seal_to, verify};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// a GitHub stand-in: deploy keys per repo; tokens other than the one it knows, and repos it was told to refuse,
/// answer 403 like GitHub does for a token without Administration on the repo
#[derive(Default)]
struct GhState {
    n: i64,
    keys: BTreeMap<String, Vec<DeployKey>>,
    refuse: BTreeMap<String, bool>,
    /// every token it was called with
    seen: Vec<String>,
}

type OnAdd = Box<dyn Fn() + Send + Sync>;

#[derive(Default, Clone)]
struct TestGitHub {
    token: String,
    st: Arc<Mutex<GhState>>,
    /// runs inside an add (another add finishing meanwhile)
    on_add: Arc<Mutex<Option<OnAdd>>>,
}

impl TestGitHub {
    fn new() -> TestGitHub {
        let g = TestGitHub {
            token: "gh-admin-token".into(),
            ..Default::default()
        };
        g.st.lock().unwrap_or_else(|e| e.into_inner()).n = 100;
        g
    }
    fn st(&self) -> std::sync::MutexGuard<'_, GhState> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn check(&self, token: &str, repo: &str) -> anyhow::Result<()> {
        let mut g = self.st();
        g.seen.push(token.into());
        if token != self.token || g.refuse.get(repo).copied().unwrap_or(false) {
            return Err(GitHubError {
                status: 403,
                msg: "GitHub: HTTP 403 Resource not accessible by personal access token".into(),
            }
            .into());
        }
        Ok(())
    }
    fn seen(&self) -> usize {
        self.st().seen.len()
    }
    fn keys(&self, repo: &str) -> Vec<DeployKey> {
        self.st().keys.get(repo).cloned().unwrap_or_default()
    }
}

impl GitHub for TestGitHub {
    fn add_deploy_key(
        &self,
        token: &str,
        repo: &str,
        title: &str,
        public_key: &str,
    ) -> anyhow::Result<DeployKey> {
        self.check(token, repo)?;
        let k = {
            let mut g = self.st();
            g.n += 1;
            let k = DeployKey {
                id: g.n,
                title: title.into(),
                key: public_key.into(),
            };
            g.keys.entry(repo.into()).or_default().push(k.clone());
            k
        };
        if let Some(f) = self
            .on_add
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            f();
        }
        Ok(k)
    }
    fn delete_deploy_key(&self, token: &str, repo: &str, id: i64) -> anyhow::Result<()> {
        self.check(token, repo)?;
        self.st()
            .keys
            .entry(repo.into())
            .or_default()
            .retain(|k| k.id != id);
        Ok(())
    }
}

/// the world's minter, in process: its refusals reach secrets as the minter's client gives them (status and words)
struct InProcess {
    m: Minter,
    c: Component,
    trust: Arc<jarvis_sig::Trust>,
}

impl MinterApi for InProcess {
    fn mint(&self, r: &Request) -> anyhow::Result<Doc> {
        self.m
            .mint(&self.c, &self.trust, r)
            .map_err(|e| match e.downcast_ref::<Fail>() {
                Some(f) => MintError {
                    status: f.code,
                    msg: f.msg.clone(),
                }
                .into(),
                None => e,
            })
    }
}

fn copy_component(c: &Component) -> Component {
    Component {
        role: c.role.clone(),
        signer: Signer::from_scalar(&c.signer.scalar()).unwrap_or_else(|e| panic!("{e}")),
        agreement: Opener::from_scalar(&c.agreement.scalar()).unwrap_or_else(|e| panic!("{e}")),
        identity: c.identity.clone(),
    }
}

/// the world's roster with c as its secrets, taken by c and by the world's trust
fn roster_for(w: &World, c: &Secrets) {
    let mut ids = vec![c.component_identity()];
    ids.extend(ROLES.iter().filter(|r| **r != "secrets").map(|r| w.id(r)));
    let d = sign_roster(
        &w.root,
        &Roster {
            copy: "blue".into(),
            members: ids,
            ..Default::default()
        },
    );
    c.set_roster(d.clone()).unwrap_or_else(|e| panic!("{e:#}"));
    w.trust.set(d, None).unwrap_or_else(|e| panic!("{e}"));
}

/// the world's minter, in process on a GitHub stand-in, in c's roster
fn with_minter(w: &World, c: &Secrets) -> TestGitHub {
    roster_for(w, c);
    let g = TestGitHub::new();
    c.set_minter(Arc::new(InProcess {
        m: Minter::new(Box::new(g.clone())),
        c: copy_component(&w.c["minter"]),
        trust: w.trust.clone(),
    }));
    g
}

struct Core {
    w: World,
    c: Arc<Secrets>,
    g: TestGitHub,
    p: Phone,
}

/// a set-up secrets with the token store written (sensitive: the setup session never creates it) and its minter
fn deploy_key_core() -> Core {
    let w = World::new();
    let c = Arc::new(Secrets::new(&w.root.public_key(), None));
    let (master, p, root) = (Phone::new(), Phone::new(), Phone::new());
    let (s, sg, b) = claim_for(&c, &master, &p, &root, &recover_bundle(&c, &p, &[]), None);
    pl(c.claim(&s, &sg, &b));
    let g = with_minter(&w, &c);
    write_store(
        &c,
        &p,
        DEPLOY_KEY_TOKEN_STORE,
        &BTreeMap::from([(DEPLOY_KEY_TOKEN_KEY.to_string(), g.token.clone())]),
    );
    Core { w, c, g, p }
}

fn rand32() -> [u8; 32] {
    use rand_core::RngCore as _;
    let mut b = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut b);
    b
}

/// a store's keys as the app wraps them to this secrets' store key
fn app_wrap(c: &Secrets, p: &Phone, name: &str, vals: &BTreeMap<String, String>) -> Vec<KeyEntry> {
    vals.iter()
        .map(|(k, v)| {
            let dk = rand32();
            KeyEntry {
                store: name.into(),
                key: k.clone(),
                wrapped: wrap_to_point(&store_key(p, &c.component_identity().agreement_key), &dk),
                data: b64(&super::crypto::gcm_seal(
                    &dk,
                    v.as_bytes(),
                    &super::keys::key_aad(name, k),
                )),
                ..Default::default()
            }
        })
        .collect()
}

/// the test stores' Recover bundle, and extra stores of (name, values)
fn recover_bundle(c: &Secrets, p: &Phone, extra: &[(&str, BTreeMap<String, String>)]) -> Value {
    let mut stores: Vec<String> = vec![
        "claude".into(),
        "default".into(),
        "gmail".into(),
        "openrouter".into(),
    ];
    let mut keys = vec![];
    for n in &stores {
        keys.extend(app_wrap(c, p, n, &test_values(n)));
    }
    for (n, v) in extra {
        stores.push(n.to_string());
        keys.extend(app_wrap(c, p, n, v));
    }
    json!({"format": "keys", "stores": stores, "keys": keys, "notSensitive": ["default", "claude", "openrouter"]})
}

/// what the shell does: check the begin document, sign it and share the token store, under one Face ID
fn answer(p: &Phone, begin: &Doc) -> (String, Sealed, String) {
    let b: Value = serde_json::from_str(&begin.payload).unwrap_or_default();
    (
        b["pending"].as_str().unwrap_or_default().to_string(),
        p.share_of(
            b["e"].as_str().unwrap_or_default(),
            b["t"].as_str().unwrap_or_default(),
        ),
        p.sign(&begin.payload),
    )
}

/// the app's names for a repo (ios Checks.repoStore): github-<name> for DE0CH's repos, else github-<owner>-<name>
fn repo_store(repo: &str) -> String {
    let l = repo.to_lowercase();
    let (owner, name) = l.split_once('/').unwrap_or((&l, ""));
    let slug = if owner != "de0ch" {
        format!("{owner}-{name}")
    } else {
        name.to_string()
    };
    let slug: String = slug
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("github-{}", slug.trim_matches('-'))
}

fn env_slug(repo: &str) -> String {
    repo.to_uppercase()
        .chars()
        .map(|c| {
            if c.is_ascii_uppercase() || c.is_ascii_digit() {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// what the app does before Face ID — an ed25519 pair, the store's values (the same format as the app's), the data
/// key wrapped to the store key it computes (P + K) → the public key line, the store's keys, the private key file
fn app_key(c: &Secrets, p: &Phone, repo: &str, store: &str) -> (String, Vec<KeyEntry>, String) {
    let key =
        russh::keys::PrivateKey::random(&mut rand_core::OsRng, russh::keys::Algorithm::Ed25519)
            .unwrap_or_else(|e| panic!("{e}"));
    let mut key = key;
    key.set_comment(format!("jarvis4 {store}"));
    let pem = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .unwrap_or_else(|e| panic!("{e}"))
        .to_string();
    let pub_line = key
        .public_key()
        .to_openssh()
        .unwrap_or_else(|e| panic!("{e}"));
    let pub_line = pub_line
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let vals = BTreeMap::from([
        (
            format!("GITHUB_DEPLOY_REPO_{}", env_slug(repo)),
            repo.to_string(),
        ),
        (
            format!("GITHUB_DEPLOY_KEY_{}", env_slug(repo)),
            b64(pem.as_bytes()),
        ),
    ]);
    (pub_line, app_wrap(c, p, store, &vals), pem)
}

/// what the app sends to deploy_key_begin — the store and title it names, and for an add the key pair it made
fn key_request(
    c: &Secrets,
    p: &Phone,
    action: &str,
    repo: &str,
    sensitive: bool,
) -> DeployKeyRequest {
    let store = repo_store(repo);
    let mut r = DeployKeyRequest {
        action: action.into(),
        repo: repo.into(),
        sensitive,
        store: store.clone(),
        title: format!("jarvis4 {store}"),
        ..Default::default()
    };
    if action == "add" && !c.lock().phone_signing.is_empty() {
        let (pubk, keys, _) = app_key(c, p, repo, &store);
        r.public_key = pubk;
        r.keys = keys;
    }
    r
}

fn deploy_key_req(c: &Secrets, p: &Phone, r: DeployKeyRequest) -> anyhow::Result<Value> {
    let b = c.deploy_key_begin(r)?;
    let (id, s, sig) = answer(p, &b);
    let d = c.deploy_key_finish(&id, &s, &sig)?;
    assert!(
        verify(
            &c.component_identity().signing_key,
            d.payload.as_bytes(),
            &d.sig
        ),
        "the answer isn't secrets-signed"
    );
    Ok(serde_json::from_str(&d.payload).unwrap_or_default())
}

fn deploy_key(
    c: &Secrets,
    p: &Phone,
    action: &str,
    repo: &str,
    sensitive: bool,
) -> anyhow::Result<Value> {
    deploy_key_req(c, p, key_request(c, p, action, repo, sensitive))
}

/// a store's contents, opened the way a session gets them (unlocked by the phone)
fn store_values(c: &Secrets, p: &Phone, name: &str) -> BTreeMap<String, String> {
    unlock(c, p, name);
    c.unlocked_values(name).unwrap_or_default()
}

fn err_of<T>(r: anyhow::Result<T>) -> String {
    r.err().map(|e| format!("{e:#}")).unwrap_or_default()
}

fn status_of<T>(r: &anyhow::Result<T>) -> u16 {
    r.as_ref()
        .err()
        .and_then(|e| e.downcast_ref::<SErr>())
        .map_or(0, |e| e.status)
}

#[test]
fn deploy_key_add_makes_a_key_a_store_and_a_github_key() {
    let k = deploy_key_core();
    let (c, g, p) = (&k.c, &k.g, &k.p);
    let m = deploy_key(c, p, "add", "DE0CH/china-train", false).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        m["kind"] == "deploy-key-added"
            && m["store"] == "github-china-train"
            && m["sensitive"] == false
            && m["title"] == "jarvis4 github-china-train",
        "answer: {m}"
    );
    let ks = g.keys("DE0CH/china-train");
    assert!(
        ks.len() == 1
            && ks[0].title == "jarvis4 github-china-train"
            && ks[0].key.starts_with("ssh-ed25519 "),
        "GitHub keys: {ks:?}"
    );
    assert!(
        m["keyId"] == ks[0].id && c.lock().repo_key_id.get("github-china-train") == Some(&ks[0].id),
        "the key's id isn't recorded"
    );
    assert!(
        g.seen() == 1 && g.st().seen[0] == g.token,
        "GitHub calls: exactly one, with the token"
    );
    assert!(
        c.unlocked_values(DEPLOY_KEY_TOKEN_STORE).is_none(),
        "the token store stayed unlocked after the call"
    );
    assert!(
        c.lock().not_sensitive.contains("github-china-train"),
        "the repo's store came out sensitive"
    );
    let v = store_values(c, p, "github-china-train");
    assert!(
        v.get("GITHUB_DEPLOY_REPO_DE0CH_CHINA_TRAIN")
            .map(String::as_str)
            == Some("DE0CH/china-train")
            && v.len() == 2,
        "{v:?}"
    );
    let pem = jarvis_sig::unb64(
        v.get("GITHUB_DEPLOY_KEY_DE0CH_CHINA_TRAIN")
            .map(String::as_str)
            .unwrap_or_default(),
    )
    .unwrap_or_default();
    assert!(
        String::from_utf8_lossy(&pem).starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"),
        "the store doesn't hold an OpenSSH private key"
    );
    // the private half is the public key GitHub got (an independent implementation: ssh-keygen)
    if let Ok(o) = std::process::Command::new("ssh-keygen").arg("-?").output()
        && !o.stderr.is_empty()
    {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let f = dir.path().join("k");
        std::fs::write(&f, &pem).unwrap_or_else(|e| panic!("{e}"));
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|e| panic!("{e}"));
        let out = std::process::Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(&f)
            .output()
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(out.status.success(), "ssh-keygen can't read the key");
        let got = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            got.split_whitespace().nth(1),
            ks[0].key.split_whitespace().nth(1),
            "the stored private key isn't the deploy key on GitHub"
        );
    }
}

/// a re-add is one GitHub call (the new key): the earlier key is answered as replacedKeyId, an orphan the router has
/// the phone remove by id (the store stays); a remove deletes the recorded key by id and the store
#[test]
fn deploy_key_re_add_leaves_an_orphan_and_remove_deletes_by_id() {
    let k = deploy_key_core();
    let (c, g, p) = (&k.c, &k.g, &k.p);
    g.st().keys.insert(
        "DE0CH/claude-env".into(),
        vec![DeployKey {
            id: 7,
            title: "someone else's key".into(),
            key: String::new(),
        }],
    );
    let m1 = deploy_key(c, p, "add", "DE0CH/claude-env", false).unwrap_or_else(|e| panic!("{e:#}"));
    let first = m1["keyId"].as_i64().unwrap_or_default();
    let m2 = deploy_key(c, p, "add", "DE0CH/claude-env", false).unwrap_or_else(|e| panic!("{e:#}"));
    let second = m2["keyId"].as_i64().unwrap_or_default();
    assert!(
        g.keys("DE0CH/claude-env").len() == 3
            && m2["replacedKeyId"] == first
            && c.lock().repo_key_id.get("github-claude-env") == Some(&second),
        "a re-add: {m2}"
    );
    let calls = g.seen();
    // the orphan, removed by id: the store stays
    let mut r = key_request(c, p, "remove", "DE0CH/claude-env", false);
    r.key_id = first;
    let b = pl(c.deploy_key_begin(r.clone()));
    assert!(
        b["keyId"] == first && b["orphan"] == true,
        "the begin names the orphan: {b}"
    );
    let m = deploy_key_req(c, p, r).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        m["kind"] == "deploy-key-removed" && m["orphan"] == true && g.seen() == calls + 1,
        "{m}"
    );
    assert!(
        c.lock().stores.contains_key("github-claude-env") && g.keys("DE0CH/claude-env").len() == 2,
        "the orphan's remove took the store, or left the orphan"
    );
    let m =
        deploy_key(c, p, "remove", "DE0CH/claude-env", false).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        m["kind"] == "deploy-key-removed" && m["deleted"] == 1 && m["keyId"] == second,
        "{m}"
    );
    let ks = g.keys("DE0CH/claude-env");
    assert!(
        ks.len() == 1 && ks[0].id == 7,
        "remove touched another key or left ours: {ks:?}"
    );
    assert!(
        !c.lock().stores.contains_key("github-claude-env")
            && !c.lock().repo_key_id.contains_key("github-claude-env"),
        "remove left the store"
    );
}

/// sensitivity is what the app asks for; secrets only keeps an existing sensitive store sensitive
#[test]
fn deploy_key_sensitivity() {
    let k = deploy_key_core();
    let (c, p) = (&k.c, &k.p);
    let m =
        deploy_key(c, p, "add", "DE0CH/private-thing", true).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(m["sensitive"] == true, "{m}");
    let m =
        deploy_key(c, p, "add", "DE0CH/private-thing", false).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        m["sensitive"] == true && !c.lock().not_sensitive.contains("github-private-thing"),
        "a re-add downgraded a sensitive store"
    );
    let b = pl(c.deploy_key_begin(key_request(c, p, "add", "DE0CH/private-thing", false)));
    assert!(
        b["sensitive"] == true
            && b["replaces"] == true
            && b["store"] == "github-private-thing"
            && b["tokenStore"] == DEPLOY_KEY_TOKEN_STORE,
        "begin: {b}"
    );
}

#[test]
fn deploy_key_needs_the_phone() {
    let k = deploy_key_core();
    let (c, g, p) = (&k.c, &k.g, &k.p);
    let other = Phone::new();
    let b = c
        .deploy_key_begin(key_request(c, p, "add", "DE0CH/x", false))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let (id, s, _) = answer(p, &b);
    assert!(
        c.deploy_key_finish(&id, &s, &other.sign(&b.payload))
            .is_err(),
        "another key's signature was accepted"
    );
    assert!(
        c.deploy_key_finish(&id, &s, &p.sign(&b.payload)).is_err(),
        "a pending was usable twice"
    );
    let b1 = c
        .deploy_key_begin(key_request(c, p, "add", "DE0CH/x", false))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let b2 = c
        .deploy_key_begin(key_request(c, p, "add", "DE0CH/y", false))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let (id2, s2, _) = answer(p, &b2);
    assert!(
        c.deploy_key_finish(&id2, &s2, &p.sign(&b1.payload))
            .is_err(),
        "a signature over another request was accepted"
    );
    let b3 = c
        .deploy_key_begin(key_request(c, p, "add", "DE0CH/x", false))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let (id3, s3, _) = answer(&other, &b3);
    assert!(
        c.deploy_key_finish(&id3, &s3, &p.sign(&b3.payload))
            .is_err(),
        "another phone's share opened the token store"
    );
    assert!(
        g.seen() == 0 && g.st().keys.is_empty(),
        "GitHub was called without the phone's approval"
    );
}

/// the minter checks the phone-signed request itself: ✱ a begin secrets didn't sign, ✱ the phone's signature over
/// another begin, ✱ a keys statement another key signed, ✱ the token sealed for another request, ✱ one approval twice
#[test]
fn the_minter_checks_the_phone_itself() {
    let k = deploy_key_core();
    let (w, c, g, p) = (&k.w, &k.c, &k.g, &k.p);
    let m = Minter::new(Box::new(g.clone()));
    let keys = c.keys_statement().unwrap_or_else(|e| panic!("{e:#}"));
    let mid = w.id("minter");
    let begin = |repo: &str| {
        let b = c
            .deploy_key_begin(key_request(c, p, "add", repo, false))
            .unwrap_or_else(|e| panic!("{e:#}"));
        let pend = serde_json::from_str::<Value>(&b.payload).unwrap_or_default()["pending"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        (b, pend)
    };
    let token = |pending: &str| {
        seal_to(
            &mid.agreement_key,
            g.token.as_bytes(),
            &format!("{TOKEN_INFO}{pending}"),
        )
        .unwrap_or_else(|e| panic!("{e}"))
    };
    let (b, pend) = begin("DE0CH/x");
    let other = Signer::generate();
    let forged = Doc {
        payload: b.payload.clone(),
        sig: other.sign(b.payload.as_bytes()),
    };
    let (b2, pend2) = begin("DE0CH/y");
    let other_keys = other
        .sign_json(&json!({"kind": "keys", "phone": p.signing_key()}))
        .unwrap_or_else(|e| panic!("{e}"));
    let req = |begin: &Doc, phone_sig: String, keys: &Doc, token: Sealed| Request {
        begin: begin.clone(),
        phone_sig,
        keys: keys.clone(),
        token,
    };
    let mc = &w.c["minter"];
    for (name, r) in [
        (
            "a begin secrets didn't sign",
            req(&forged, p.sign(&b.payload), &keys, token(&pend)),
        ),
        (
            "the phone's signature over another",
            req(&b, p.sign(&b2.payload), &keys, token(&pend)),
        ),
        (
            "another phone's signature",
            req(&b, Phone::new().sign(&b.payload), &keys, token(&pend)),
        ),
        (
            "keys another key signed",
            req(&b, p.sign(&b.payload), &other_keys, token(&pend)),
        ),
        (
            "the token for another request",
            req(&b2, p.sign(&b2.payload), &keys, token(&pend)),
        ),
    ] {
        assert!(m.mint(mc, &w.trust, &r).is_err(), "{name}: minted");
    }
    assert_eq!(g.seen(), 0, "GitHub was called for a refused request");
    let good = req(&b2, p.sign(&b2.payload), &keys, token(&pend2));
    m.mint(mc, &w.trust, &good)
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        m.mint(mc, &w.trust, &good).is_err() && g.seen() == 1,
        "one approval reached GitHub twice"
    );
}

#[test]
fn deploy_key_refusals() {
    let (c, p, _) = setup();
    let e = err_of(c.deploy_key_begin(key_request(&c, &p, "add", "DE0CH/x", false)));
    assert!(
        e.contains(DEPLOY_KEY_TOKEN_STORE),
        "began without the token store: {e}"
    );
    write_store(
        &c,
        &p,
        DEPLOY_KEY_TOKEN_STORE,
        &BTreeMap::from([("OTHER".to_string(), "x".to_string())]),
    );
    let e = err_of(c.deploy_key_begin(key_request(&c, &p, "add", "DE0CH/x", false)));
    assert!(
        e.contains(DEPLOY_KEY_TOKEN_STORE),
        "a token store without the token: {e}"
    );
    write_store(
        &c,
        &p,
        DEPLOY_KEY_TOKEN_STORE,
        &BTreeMap::from([(DEPLOY_KEY_TOKEN_KEY.to_string(), "t".to_string())]),
    );
    for bad in [
        "",
        "x",
        "DE0CH/",
        "/x",
        "DE0CH/a/b",
        "DE0CH/..",
        "-x/y",
        "DE0CH/a b",
        "DE0CH/.",
    ] {
        assert!(
            c.deploy_key_begin(key_request(&c, &p, "add", bad, false))
                .is_err(),
            "repo {bad:?} accepted"
        );
    }
    assert!(
        c.deploy_key_begin(key_request(&c, &p, "rotate", "DE0CH/x", false))
            .is_err(),
        "an unknown action"
    );
    // no minter in the roster: refused before anything leaves secrets
    let b = c
        .deploy_key_begin(key_request(&c, &p, "add", "DE0CH/x", false))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let (id, s, sg) = answer(&p, &b);
    let e = err_of(c.deploy_key_finish(&id, &s, &sg));
    assert!(
        e.contains("minter") || e.contains("roster"),
        "finished with no minter: {e}"
    );
    let empty = Secrets::new(&Signer::generate().public_key(), None);
    assert!(
        empty
            .deploy_key_begin(key_request(&empty, &p, "add", "DE0CH/x", false))
            .is_err(),
        "an empty secrets began"
    );
}

#[test]
fn deploy_key_token_without_administration() {
    let k = deploy_key_core();
    let (c, g, p) = (&k.c, &k.g, &k.p);
    g.st().refuse.insert("DE0CH/x".into(), true);
    let r = deploy_key(c, p, "add", "DE0CH/x", false);
    assert_eq!(status_of(&r), 502, "not a 502");
    let e = err_of(r);
    assert!(e.contains("github: HTTP 403"), "no GitHub status: {e}");
    assert!(
        !c.lock().stores.contains_key("github-x"),
        "a store was made though GitHub refused"
    );
}

/// the app's key file is an unencrypted openssh-key-v1 file that holds its public key
#[test]
fn openssh_key_format() {
    let (c, p, _) = setup();
    let (pubk, _, pem) = app_key(&c, &p, "DE0CH/x", "github-x");
    let lines: Vec<&str> = pem.trim().lines().collect();
    let raw = jarvis_sig::unb64(&lines[1..lines.len() - 1].concat()).unwrap_or_default();
    assert!(
        raw.starts_with(b"openssh-key-v1\0"),
        "not an openssh-key-v1 file"
    );
    let wire =
        jarvis_sig::unb64(pubk.split_whitespace().nth(1).unwrap_or_default()).unwrap_or_default();
    assert!(
        raw.windows(wire.len()).any(|w| w == wire.as_slice()),
        "the public key isn't in the file"
    );
}

/// colliding repos share a store name: the second repo's add (or remove) is refused with 409 naming the owner, and
/// GitHub is never called for it; the owning repo still re-adds and removes, after which the name is free
#[test]
fn deploy_key_store_clash_refused() {
    let k = deploy_key_core();
    let (c, g, p) = (&k.c, &k.g, &k.p);
    assert!(
        repo_store("DE0CH/foo-bar") == repo_store("foo/bar")
            && repo_store("DE0CH/my.repo") == repo_store("DE0CH/My-Repo"),
        "the test's repos don't collide"
    );
    deploy_key(c, p, "add", "DE0CH/foo-bar", false).unwrap_or_else(|e| panic!("{e:#}"));
    let calls = g.seen();
    for action in ["add", "remove"] {
        let r = c.deploy_key_begin(key_request(c, p, action, "foo/bar", false));
        assert_eq!(status_of(&r), 409, "{action} for a colliding repo");
        let e = err_of(r);
        assert!(
            e.contains("store github-foo-bar belongs to DE0CH/foo-bar"),
            "{action}: {e}"
        );
    }
    // a begin taken before the store was owned is refused at finish, before GitHub
    let k2 = deploy_key_core();
    let (c2, g2, p2) = (&k2.c, &k2.g, &k2.p);
    let early = c2
        .deploy_key_begin(key_request(c2, p2, "add", "DE0CH/My-Repo", false))
        .unwrap_or_else(|e| panic!("{e:#}"));
    deploy_key(c2, p2, "add", "DE0CH/my.repo", false).unwrap_or_else(|e| panic!("{e:#}"));
    let n2 = g2.seen();
    let (id, s, sig) = answer(p2, &early);
    let e = err_of(c2.deploy_key_finish(&id, &s, &sig));
    assert!(
        e.contains("belongs to DE0CH/my.repo"),
        "a pending add for a colliding repo finished: {e}"
    );
    assert!(
        g.seen() == calls && g2.seen() == n2 && g2.keys("DE0CH/My-Repo").is_empty(),
        "GitHub was called for a refused repo"
    );
    let v = store_values(c2, p2, "github-my-repo");
    assert_eq!(
        v.get("GITHUB_DEPLOY_REPO_DE0CH_MY_REPO")
            .map(String::as_str),
        Some("DE0CH/my.repo"),
        "the owner's store was replaced"
    );
    deploy_key(c, p, "add", "de0ch/FOO-BAR", false)
        .unwrap_or_else(|e| panic!("the owner's re-add: {e:#}"));
    let m = deploy_key(c, p, "remove", "DE0CH/foo-bar", false)
        .unwrap_or_else(|e| panic!("the owner's remove: {e:#}"));
    assert!(m["kind"] == "deploy-key-removed", "{m}");
    deploy_key(c, p, "add", "foo/bar", false).unwrap_or_else(|e| panic!("the freed name: {e:#}"));
    assert_eq!(
        c.lock()
            .repo_owner
            .get("github-foo-bar")
            .map(String::as_str),
        Some("foo/bar")
    );
}

/// a Recover keeps each deploy-key store's owner: the bundle's owners, for stores the bundle holds and repos that are
/// repos. A bundle carries no key ids: a remove then deletes only the store (GitHub isn't called)
#[test]
fn deploy_key_recover_keeps_the_owner() {
    let w = World::new();
    let c = Secrets::new(&w.root.public_key(), None);
    let (master, p) = (Phone::new(), Phone::new());
    let mut rb = recover_bundle(
        &c,
        &p,
        &[
            (
                "github-foo-bar",
                BTreeMap::from([
                    (
                        "GITHUB_DEPLOY_REPO_DE0CH_FOO_BAR".into(),
                        "DE0CH/foo-bar".into(),
                    ),
                    ("GITHUB_DEPLOY_KEY_DE0CH_FOO_BAR".into(), "x".into()),
                ]),
            ),
            (
                "github-odd",
                BTreeMap::from([(
                    "GITHUB_DEPLOY_REPO_DE0CH_OTHER".into(),
                    "DE0CH/other".into(),
                )]),
            ),
            (
                DEPLOY_KEY_TOKEN_STORE,
                BTreeMap::from([(DEPLOY_KEY_TOKEN_KEY.into(), "gh-admin-token".into())]),
            ),
        ],
    );
    rb["owners"] = json!({"github-foo-bar": "DE0CH/foo-bar", "github-odd": "not a repo", "github-gone": "DE0CH/gone"});
    let (s, sg, b) = claim_for(&c, &master, &p, &Phone::new(), &rb, None);
    pl(c.claim(&s, &sg, &b));
    let g = with_minter(&w, &c);
    {
        let st = c.lock();
        assert!(
            st.repo_owner.len() == 1
                && st.repo_owner.get("github-foo-bar").map(String::as_str) == Some("DE0CH/foo-bar"),
            "owners after Recover: {:?}",
            st.repo_owner
        );
    }
    let e = err_of(c.deploy_key_begin(key_request(&c, &p, "add", "foo/bar", false)));
    assert!(
        e.contains("belongs to DE0CH/foo-bar"),
        "a Recover lost the owner: {e}"
    );
    let m =
        deploy_key(&c, &p, "remove", "DE0CH/foo-bar", false).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        m["deleted"] == 0 && g.seen() == 0,
        "a remove with no key id known: {m}"
    );
    deploy_key(&c, &p, "add", "DE0CH/foo-bar", false)
        .unwrap_or_else(|e| panic!("the re-add after Recover: {e:#}"));
}

/// two colliding adds in flight: the one that loses is refused naming its new key, an orphan on GitHub, and writes
/// nothing
#[test]
fn deploy_key_clash_race_leaves_an_orphan() {
    let k = deploy_key_core();
    let (c, g, p) = (&k.c, &k.g, &k.p);
    let c2 = c.clone();
    *g.on_add.lock().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(move || {
        c2.lock()
            .repo_owner
            .insert("github-foo-bar".into(), "foo/bar".into());
    }));
    let e = err_of(deploy_key(c, p, "add", "DE0CH/foo-bar", false));
    assert!(
        e.contains("belongs to foo/bar") && e.contains("orphan"),
        "the losing add went through: {e}"
    );
    assert!(
        g.keys("DE0CH/foo-bar").len() == 1 && g.seen() == 1,
        "the losing add made more than its one GitHub call"
    );
    assert!(
        !c.lock().stores.contains_key("github-foo-bar"),
        "the losing add wrote the store"
    );
}

#[test]
fn deploy_key_from_the_apps_key_pair() {
    let k = deploy_key_core();
    let (c, g, p) = (&k.c, &k.g, &k.p);
    let (pubk, keys, pem) = app_key(c, p, "DE0CH/china-train", "github-china-train");
    let req = DeployKeyRequest {
        action: "add".into(),
        repo: "DE0CH/china-train".into(),
        store: "github-china-train".into(),
        title: "jarvis4 github-china-train".into(),
        public_key: pubk.clone(),
        keys: keys.clone(),
        ..Default::default()
    };
    let moved = |to: &str| {
        keys.iter()
            .cloned()
            .map(|mut x| {
                x.store = to.into();
                x
            })
            .collect::<Vec<_>>()
    };
    let mut cases: Vec<(&str, DeployKeyRequest)> = vec![];
    let mut r = req.clone();
    r.public_key.clear();
    cases.push(("no public key", r));
    let mut r = req.clone();
    r.keys.clear();
    cases.push(("no keys", r));
    let mut r = req.clone();
    r.keys = moved("github-other");
    cases.push(("keys for another", r));
    let mut r = req.clone();
    r.keys.push(keys[0].clone());
    cases.push(("a key twice", r));
    let mut r = req.clone();
    r.store = DEPLOY_KEY_TOKEN_STORE.into();
    r.keys = moved(DEPLOY_KEY_TOKEN_STORE);
    cases.push(("the token store", r));
    let mut r = req.clone();
    r.store.clear();
    cases.push(("no store", r));
    let mut r = req.clone();
    r.key_id = 5;
    cases.push(("an add by id", r));
    for (name, r) in cases {
        assert!(c.deploy_key_begin(r).is_err(), "{name}: began");
    }
    let b = pl(c.deploy_key_begin(req.clone()));
    let named = b["keys"].as_array().cloned().unwrap_or_default();
    assert!(
        b["publicKey"] == pubk.as_str()
            && named.len() == 2
            && named[0]["e"] == keys[0].wrapped.e.as_str()
            && named[0]["dataSha256"] == sha256_hex(&keys[0].data).as_str(),
        "the begin document doesn't name the key pair: {b}"
    );
    let d = c.deploy_key_begin(req).unwrap_or_else(|e| panic!("{e:#}"));
    let (id, s, sig) = answer(p, &d);
    let a = pl(c.deploy_key_finish(&id, &s, &sig));
    assert!(
        a["kind"] == "deploy-key-added"
            && a["publicKey"] == pubk.as_str()
            && a["fingerprint"].is_null(),
        "answer {a}"
    );
    let ks = g.keys("DE0CH/china-train");
    assert!(ks.len() == 1 && ks[0].key == pubk, "GitHub got {ks:?}");
    {
        let st = c.lock();
        let got = st
            .stores
            .get("github-china-train")
            .and_then(|s| s.get(&keys[0].key))
            .cloned();
        assert!(
            got.as_ref().is_some_and(
                |g| g.data == keys[0].data && g.writer.as_ref().is_some_and(|w| w.by == "core")
            ),
            "the store isn't the app's blob, vouched by secrets"
        );
    }
    let v = store_values(c, p, "github-china-train");
    let kf = jarvis_sig::unb64(
        v.get("GITHUB_DEPLOY_KEY_DE0CH_CHINA_TRAIN")
            .map(String::as_str)
            .unwrap_or_default(),
    )
    .unwrap_or_default();
    assert!(
        String::from_utf8_lossy(&kf).contains("OPENSSH PRIVATE KEY") && !pem.is_empty(),
        "the store doesn't hold the app's private key"
    );
}
