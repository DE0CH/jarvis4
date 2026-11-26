//! The minter (kernel/minter): the kernel's only component that uses a secret (Deyao, 2026-10-23: secrets hands
//! secrets out, it never uses one), and the only one with GitHub egress. Secrets checks the phone's approval of a
//! deploy-key call, opens the GitHub token store with the phone's share, seals the token to the minter's agreement key
//! (from the root key's roster) and calls POST /mint. The minter checks the same phone-signed request itself —
//! secrets' begin document, the phone's signature over exactly it, the phone's key from secrets' signed keys statement
//! — does exactly one GitHub call (add the begin's public key to the begin's repo, or delete the key id the begin
//! names), drops the token and answers signed. It keeps nothing but the pendings it has served (one call per
//! approval).

use crate::serve::{Answer, Server, fail, handle, log};
use jarvis_sig::{Component, Doc, Sealed, Trust, verify};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

/// the HKDF info the token is sealed under, followed by the begin's pending id
pub const TOKEN_INFO: &str = "jarvis2/minter-token\n";

/// the one GitHub host the minter talks to (fixed here, in git, like the Fly app: the token can only ever go there)
pub const GITHUB_API_BASE: &str = "https://api.github.com";

#[allow(clippy::unwrap_used)] // a fixed pattern, checked by the tests
static REPO_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$").unwrap()
});

/// owner/name as GitHub spells a repo (no path tricks: the minter puts it in the URL)
pub fn repo_ok(repo: &str) -> bool {
    REPO_RE.is_match(repo) && !repo.contains("..") && !repo.ends_with("/.")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeployKey {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub key: String,
}

/// GitHub refused; status is its HTTP status (403/404 = the token can't manage this repo's keys)
#[derive(Debug, Clone)]
pub struct GitHubError {
    pub status: u16,
    pub msg: String,
}

impl std::fmt::Display for GitHubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for GitHubError {}

/// GitHub's deploy-key API: one add, or one delete by the id GitHub gave at the add. The token comes in each call,
/// sealed to the minter by secrets, and is never kept.
pub trait GitHub: Send + Sync {
    fn add_deploy_key(
        &self,
        token: &str,
        repo: &str,
        title: &str,
        public_key: &str,
    ) -> anyhow::Result<DeployKey>;
    fn delete_deploy_key(&self, token: &str, repo: &str, id: i64) -> anyhow::Result<()>;
}

pub struct GitHubApi {
    http: reqwest::blocking::Client,
}

impl GitHubApi {
    pub fn new() -> GitHubApi {
        GitHubApi {
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    fn call(
        &self,
        token: &str,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> anyhow::Result<Vec<u8>> {
        let m = method.as_str().to_string();
        let mut req = self
            .http
            .request(method, format!("{GITHUB_API_BASE}{path}"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "jarvis4-minter/1");
        if let Some(b) = body {
            req = req
                .header("Content-Type", "application/json")
                .body(jarvis_sig::go_json(&b)?);
        }
        let resp = req.send().map_err(|e| {
            anyhow::anyhow!(
                "GitHub unreachable: {}",
                e.to_string().replace(token, "***")
            )
        })?;
        let status = resp.status().as_u16();
        let mut b = vec![];
        std::io::Read::read_to_end(&mut std::io::Read::take(resp, 4 << 20), &mut b)?;
        if status / 100 != 2 {
            #[derive(Deserialize, Default)]
            struct E {
                #[serde(default)]
                message: String,
            }
            let e: E = serde_json::from_slice(&b).unwrap_or_default();
            return Err(GitHubError {
                status,
                msg: format!("GitHub {m} {path}: HTTP {status} {}", e.message),
            }
            .into());
        }
        Ok(b)
    }
}

impl Default for GitHubApi {
    fn default() -> Self {
        Self::new()
    }
}

impl GitHub for GitHubApi {
    fn add_deploy_key(
        &self,
        token: &str,
        repo: &str,
        title: &str,
        public_key: &str,
    ) -> anyhow::Result<DeployKey> {
        let b = self.call(
            token,
            reqwest::Method::POST,
            &format!("/repos/{repo}/keys"),
            Some(serde_json::json!({"title": title, "key": public_key, "read_only": false})),
        )?;
        Ok(serde_json::from_slice(&b)?)
    }

    fn delete_deploy_key(&self, token: &str, repo: &str, id: i64) -> anyhow::Result<()> {
        match self.call(
            token,
            reqwest::Method::DELETE,
            &format!("/repos/{repo}/keys/{id}"),
            None,
        ) {
            Err(e)
                if e.downcast_ref::<GitHubError>()
                    .is_some_and(|g| g.status == 404) =>
            {
                Ok(())
            } // already gone
            other => other.map(|_| ()),
        }
    }
}

/// what secrets sends for one phone-approved deploy-key call
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Request {
    /// secrets' signed deploy-key-begin document: what the phone signed
    pub begin: Doc,
    /// the phone's signature over begin.payload
    pub phone_sig: String,
    /// secrets' signed keys statement {kind: "keys", phone, root}
    pub keys: Doc,
    /// the GitHub token, sealed to the minter's agreement key (TOKEN_INFO + pending)
    pub token: Sealed,
}

/// the signed answer
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Minted {
    /// "deploy-key-minted"
    pub kind: String,
    pub pending: String,
    pub action: String,
    pub repo: String,
    /// add: the id GitHub gave the key; remove: the id deleted
    pub key_id: i64,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct BeginDoc {
    kind: String,
    pending: String,
    action: String,
    repo: String,
    title: String,
    public_key: String,
    key_id: i64,
}

pub struct Minter {
    gh: Box<dyn GitHub>,
    /// pendings served (each approval reaches GitHub once)
    done: Mutex<BTreeMap<String, Instant>>,
}

impl Minter {
    pub fn new(gh: Box<dyn GitHub>) -> Minter {
        Minter {
            gh,
            done: Mutex::new(BTreeMap::new()),
        }
    }

    /// the checks, then exactly one GitHub call
    pub fn mint(&self, c: &Component, t: &Trust, i: &Request) -> anyhow::Result<Doc> {
        let sec = t.member("secrets").map_err(|e| fail(503, e.to_string()))?;
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Keys {
            kind: String,
            phone: String,
        }
        let keys: Option<Keys> = verify(&sec.signing_key, i.keys.payload.as_bytes(), &i.keys.sig)
            .then(|| serde_json::from_str(&i.keys.payload).ok())
            .flatten();
        let Some(keys) = keys.filter(|k| k.kind == "keys" && !k.phone.is_empty()) else {
            return Err(fail(403, "the keys statement isn't the roster's secrets'"));
        };
        let b: Option<BeginDoc> =
            verify(&sec.signing_key, i.begin.payload.as_bytes(), &i.begin.sig)
                .then(|| serde_json::from_str(&i.begin.payload).ok())
                .flatten();
        let Some(b) = b.filter(|b| b.kind == "deploy-key-begin" && !b.pending.is_empty()) else {
            return Err(fail(
                403,
                "the request isn't a deploy-key begin the roster's secrets signed",
            ));
        };
        if !verify(&keys.phone, i.begin.payload.as_bytes(), &i.phone_sig) {
            return Err(fail(
                403,
                "the iPhone's signature doesn't cover this request",
            ));
        }
        if !repo_ok(&b.repo) {
            return Err(fail(400, "repo: owner/name"));
        }
        let ok = (b.action == "add" && !b.public_key.is_empty() && !b.title.is_empty())
            || (b.action == "remove" && b.key_id > 0);
        if !ok {
            return Err(fail(
                400,
                "an add of a public key with its title, or a remove of a key id",
            ));
        }
        let tok = match c
            .agreement
            .open(&i.token, &format!("{TOKEN_INFO}{}", b.pending))
        {
            Ok(t) if !t.is_empty() => t,
            _ => {
                return Err(fail(
                    400,
                    "the token isn't sealed to this minter for this request",
                ));
            }
        };
        {
            let mut done = self.done.lock().unwrap_or_else(|e| e.into_inner());
            if done.contains_key(&b.pending) {
                return Err(fail(409, "this approval was used already"));
            }
            done.insert(b.pending.clone(), Instant::now());
            done.retain(|_, at| at.elapsed() <= Duration::from_secs(24 * 3600));
        }
        let token = String::from_utf8_lossy(&tok).into_owned();
        let mut out = Minted {
            kind: "deploy-key-minted".into(),
            pending: b.pending.clone(),
            action: b.action.clone(),
            repo: b.repo.clone(),
            key_id: 0,
        };
        let r = if b.action == "add" {
            self.gh
                .add_deploy_key(&token, &b.repo, &b.title, &b.public_key)
                .map(|k| out.key_id = k.id)
        } else {
            out.key_id = b.key_id;
            self.gh.delete_deploy_key(&token, &b.repo, b.key_id)
        };
        drop(token);
        if let Err(e) = r {
            log(&format!("minter: {} {} failed: {e:#}", b.action, b.repo));
            if let Some(g) = e.downcast_ref::<GitHubError>() {
                return Err(fail(502, format!("github: HTTP {}: {}", g.status, g.msg)));
            }
            return Err(fail(502, format!("github: {e:#}")));
        }
        log(&format!(
            "minter: {} {}: GitHub key {}",
            b.action, b.repo, out.key_id
        ));
        Ok(c.signer.sign_json(&out)?)
    }
}

/// POST /mint
pub fn register(s: &Arc<Server>, m: Arc<Minter>) {
    let s2 = s.clone();
    handle(s, "POST /mint", move |i: Request| {
        Ok(Answer::Doc(m.mint(&s2.c, &s2.trust, &i)?))
    });
}

/// the minter over HTTP (secrets' side: KERNEL_MINTER_URL)
pub struct Client {
    pub url: String,
    http: reqwest::blocking::Client,
}

/// a refusal of the minter's, with its status and words
#[derive(Debug, Clone)]
pub struct MintError {
    pub status: u16,
    pub msg: String,
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for MintError {}

fn mint_err(status: u16, msg: impl Into<String>) -> anyhow::Error {
    MintError {
        status,
        msg: msg.into(),
    }
    .into()
}

impl Client {
    pub fn new(url: &str) -> Client {
        Client {
            url: url.into(),
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
        }
    }

    /// POST /mint; a refusal comes back as MintError with the minter's status and words
    pub fn mint(&self, i: &Request) -> anyhow::Result<Doc> {
        if self.url.is_empty() {
            return Err(mint_err(503, "no minter configured (KERNEL_MINTER_URL)"));
        }
        let resp = self
            .http
            .post(format!("{}/mint", self.url))
            .header("Content-Type", "application/json")
            .body(jarvis_sig::go_json(i)?)
            .send()
            .map_err(|e| mint_err(502, format!("the minter is unreachable: {e}")))?;
        let status = resp.status().as_u16();
        let mut raw = vec![];
        std::io::Read::read_to_end(&mut std::io::Read::take(resp, 1 << 20), &mut raw)?;
        let d: Doc = serde_json::from_slice(&raw).map_err(|_| {
            mint_err(
                502,
                format!("the minter's answer isn't a signed document (HTTP {status})"),
            )
        })?;
        if status != 200 {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct E {
                error: String,
            }
            let e: E = serde_json::from_str(&d.payload).unwrap_or_default();
            return Err(mint_err(status, e.error));
        }
        Ok(d)
    }
}
