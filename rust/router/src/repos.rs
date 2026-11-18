//! Deyao's repo list and the GitHub picker (Jarvis 1's /api/repos, /api/github/repos).
//!
//! Every repo on the list is a GitHub repo with its own deploy key (Deyao, 2026-10-10): adding one in the app's
//! Settings asks the core for a deploy key (docs/DESIGN.md "Deploy keys"), which the phone approves with Face ID; the
//! core makes the key pair, adds the public half to the repo on GitHub and keeps the private half in the store
//! github-<repo>. Removing one deletes both, the same way. The router only relays: it holds no GitHub token that can
//! push or manage keys (the picker lists repos with GITHUB_READ_TOKEN, metadata read only), and it records an entry
//! only from the core's answer. Sessions clone, pull and push a repo over SSH with its store's key
//! (rust/machine/src/deploykeys.rs); the picker only fills New session's `repos`. The repo list is the router's own
//! (repos.json, a row of router_docs in its database), shown in /api/state `repos`.

use crate::core::Doc;
use crate::http::Registrar;
use crate::inbox::{ApiCall, Caller, InboxRequest, Origin, REQUEST_KIND_REPO, RequestParams};
use crate::nethttp::{W, write_json};
use crate::router::Router;
use crate::uploads::HttpStatusErr;
use anyhow::{Result, anyhow};
use base64::Engine;
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant};

/// a repo on the list. repo, url and store follow from the GitHub name; sensitive, fingerprint and key_at come from the
/// core's answer when its deploy key was made.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RepoEntry {
    /// the clone's directory in ~/workspace
    pub name: String,
    /// https://github.com/<owner>/<name>.git
    pub url: String,
    /// <owner>/<name>
    pub repo: String,
    /// the store holding its deploy key
    pub store: String,
    pub sensitive: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    #[serde(rename = "keyAt", skip_serializing_if = "String::is_empty")]
    pub key_at: String,
}

static GITHUB_REPO_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^(?:https://github\.com/|git@github\.com:)?([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$")
        .unwrap_or_else(|_| unreachable!())
});

/// "owner/name" from a GitHub URL or name ("" when it isn't one)
pub fn parse_github_repo(s: &str) -> String {
    let Some(m) = GITHUB_REPO_RE.captures(s.trim()) else {
        return String::new();
    };
    let name = &m[2];
    if name == "." || name == ".." || name.contains("..") {
        return String::new();
    }
    format!("{}/{name}", &m[1])
}

/// the core's RepoStore (core/deploykeys.go) — github-<name> for DE0CH's repos, else github-<owner>-<name>, lower case,
/// anything outside [a-z0-9-] as "-"
pub fn repo_store(repo: &str) -> String {
    let lower = repo.to_lowercase();
    let (owner, name, _) = jarvis_go::fmt::cut(&lower, "/");
    let slug = if owner != "de0ch" {
        format!("{owner}-{name}")
    } else {
        name.to_string()
    };
    let s: String = slug
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("github-{}", s.trim_matches('-'))
}

pub fn repo_entry(repo: &str) -> RepoEntry {
    let (_, name, _) = jarvis_go::fmt::cut(repo, "/");
    RepoEntry {
        name: name.into(),
        url: format!("https://github.com/{repo}.git"),
        repo: repo.into(),
        store: repo_store(repo),
        ..Default::default()
    }
}

/// the core's answer to a finished deploy-key request, applied to the list
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct KeyAnswer {
    /// deploy-key-added | deploy-key-removed
    pub kind: String,
    pub repo: String,
    pub sensitive: bool,
    pub fingerprint: String,
    /// the core from R2 answers the key, not its fingerprint
    #[serde(rename = "publicKey")]
    pub public_key: String,
    /// the kernel's secrets: the GitHub key's id; a re-add's earlier key (an orphan on GitHub until a remove by its id);
    /// a remove of only an orphan key (the repo stays)
    #[serde(rename = "keyId")]
    pub key_id: i64,
    #[serde(rename = "replacedKeyId")]
    pub replaced_key_id: i64,
    pub orphan: bool,
}

/// "SHA256:<base64>" of an "ssh-ed25519 <base64 wire>" line ("" when it isn't one)
pub fn ssh_fingerprint(public: &str) -> String {
    let (_, b, ok) = jarvis_go::fmt::cut(public, " ");
    match base64::engine::general_purpose::STANDARD.decode(b) {
        Ok(w) if ok && !w.is_empty() => {
            format!(
                "SHA256:{}",
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&w))
            )
        }
        _ => String::new(),
    }
}

/// Jarvis 4's deploy keys' title on GitHub (the app's Checks.deployKeyTitle)
pub fn deploy_key_title(store: &str) -> String {
    format!("jarvis4 {store}")
}

/// a session that asked for the repo (its request, as filed)
#[derive(Debug, Clone)]
struct RepoAsker {
    request: String,
    session: String,
    origin: Origin,
    expl: String,
}

// ---- the GitHub picker ----------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct GhRepo {
    #[serde(rename = "fullName")]
    pub full_name: String,
    pub url: String,
    #[serde(rename = "htmlUrl")]
    pub html_url: String,
    pub private: bool,
    pub fork: bool,
    pub archived: bool,
    pub description: String,
    pub language: String,
    #[serde(rename = "pushedAt")]
    pub pushed_at: String,
    pub owner: String,
}

/// the picker's list, cached GH_TTL
#[derive(Default)]
pub struct GhCache(Mutex<Option<(Instant, GoTime, Vec<GhRepo>)>>);

pub static GITHUB_API: LazyLock<RwLock<String>> =
    LazyLock::new(|| RwLock::new("https://api.github.com".into()));

pub fn github_api() -> String {
    GITHUB_API.read().unwrap_or_else(|e| e.into_inner()).clone()
}

pub fn github_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap_or_default()
}

const GH_TTL: Duration = Duration::from_secs(5 * 60);

impl Router {
    pub fn repos(&self) -> Vec<RepoEntry> {
        let _g = self.ops.repos_mu.lock().unwrap_or_else(|e| e.into_inner());
        self.read_repos()
    }

    /// the list; every entry is a GitHub repo, its derived fields recomputed from its URL
    fn read_repos(&self) -> Vec<RepoEntry> {
        let raw: Vec<RepoEntry> = self
            .st
            .read_doc("repos.json")
            .and_then(|b| jarvis_go::unmarshal(&b).ok())
            .unwrap_or_default();
        raw.into_iter()
            .filter_map(|e| {
                let repo = parse_github_repo(&e.url);
                if repo.is_empty() {
                    crate::logf!(
                        "repos: {} isn't a GitHub repo: left off the list",
                        jarvis_go::fmt::go_quote(&e.url)
                    );
                    return None;
                }
                let mut n = repo_entry(&repo);
                n.sensitive = e.sensitive;
                n.fingerprint = e.fingerprint;
                n.key_at = e.key_at;
                Some(n)
            })
            .collect()
    }

    /// read-modify-write under the lock (two adds at once used to drop one in Jarvis 1)
    fn update_repos(&self, f: impl FnOnce(Vec<RepoEntry>) -> Vec<RepoEntry>) -> Result<()> {
        let _g = self.ops.repos_mu.lock().unwrap_or_else(|e| e.into_inner());
        let next = f(self.read_repos());
        self.st.write_doc(
            "repos.json",
            jarvis_go::fmt::marshal_indent1(&next).as_bytes(),
        )
    }

    /// a session asks for a repo that has its deploy key already and doesn't hold the key's store → its running machine
    /// and that store: what it needs is the store (an add-store), not a new key. Every such ask used to become a "make a
    /// deploy key" request, a new key for a repo that had one (Deyao, 2026-11-17). ("", "") for anything else, which
    /// asks for a key as before: a repo with no key, a session that holds the store (a rotation), an ask that names no
    /// session (no store, Deyao's own, the setup session's), one that makes the store sensitive.
    pub fn existing_repo_store(
        &self,
        c: &Caller,
        kind: &str,
        p: &RequestParams,
    ) -> (String, String) {
        if kind != REQUEST_KIND_REPO
            || p.action != "add"
            || p.session.is_empty()
            || (c.kind != "session" && c.kind != "actions")
        {
            return (String::new(), String::new());
        }
        let store = self
            .repos()
            .into_iter()
            .filter(|e| {
                e.repo.eq_ignore_ascii_case(&p.repo)
                    && !e.fingerprint.is_empty()
                    && (e.sensitive || !p.sensitive)
            })
            .map(|e| e.store)
            .next_back()
            .unwrap_or_default();
        if store.is_empty() {
            return (String::new(), String::new());
        }
        // a running machine, as an add-store takes (batches.rs)
        let machine = self.st.do_(|d| {
            d.sessions
                .get(&p.session)
                .filter(|s| {
                    !s.machine_id.is_empty()
                        && (s.cert.is_some() || s.kernel.is_some())
                        && (s.state == "started" || s.state == "initialising")
                        && !s.stores.as_ref().is_some_and(|st| st.contains(&store))
                })
                .map(|s| s.machine_id.clone())
                .unwrap_or_default()
        });
        if machine.is_empty() {
            return (String::new(), String::new());
        }
        (machine, store)
    }

    /// proof: the core's signed answer (outcomes.rs: what vouches for "approved" to a session that asked for the key)
    pub fn apply_key_answer(&self, mut a: KeyAnswer, proof: &Doc) -> Result<()> {
        if a.fingerprint.is_empty() {
            a.fingerprint = ssh_fingerprint(&a.public_key);
        }
        let repo = parse_github_repo(&a.repo);
        if repo.is_empty() {
            return Err(anyhow!("the core's answer names no GitHub repo"));
        }
        if a.orphan {
            // only an orphan key went: the repo stays as it is
            crate::logf!(
                "repos: orphan deploy key {} of {repo} deleted on GitHub",
                a.key_id
            );
            return Ok(());
        }
        if a.replaced_key_id != 0 {
            crate::logf!(
                "repos: {repo}'s earlier deploy key {} stays on GitHub until it is removed by id (an orphan)",
                a.replaced_key_id
            );
        }
        // a pending request for the same thing is answered too (inbox.rs)
        let added = a.kind == "deploy-key-added";
        let r2 = repo.clone();
        self.drop_requests(
            move |q: &InboxRequest| {
                q.kind == REQUEST_KIND_REPO
                    && q.params.repo.eq_ignore_ascii_case(&r2)
                    && (q.params.action == "add") == added
            },
            crate::outcomes::OUTCOME_APPROVED,
            Some(proof),
        );
        self.update_repos(|rs| {
            let mut out: Vec<RepoEntry> = rs
                .into_iter()
                .filter(|e| !e.repo.eq_ignore_ascii_case(&repo))
                .collect();
            if added {
                let mut e = repo_entry(&repo);
                e.sensitive = a.sensitive;
                e.fingerprint = a.fingerprint.clone();
                e.key_at = GoTime::now().rfc3339();
                out.push(e);
            }
            out
        })
    }

    /// the core's answer unchanged; a finished add or remove also updates the list. A core from before deploy keys
    /// answers its mux's plain-text 404: say so plainly. inbox: the Inbox request this page answers
    fn relay_deploy_key(
        self: &Arc<Self>,
        w: &mut W,
        path: &str,
        body: &[u8],
        finish: bool,
        inbox: &str,
    ) {
        let (status, b) = match self.store_core().raw("POST", path, Some(body)) {
            Err(e) => {
                crate::logf!("deploy keys {path}: {e:#}");
                return write_json(
                    w,
                    503,
                    &json!({"error": "the core isn't running", "coreDown": true}),
                );
            }
            Ok(x) => x,
        };
        let doc = jarvis_go::unmarshal::<Doc>(&b).ok();
        if status == 404 && doc.is_none() {
            return write_json(
                w,
                501,
                &json!({"error": "the running core predates deploy keys: it makes them once it has been restarted with the new core image (then Recover)"}),
            );
        }
        if status == 502
            && let Some(d) = &doc
        {
            // the core says only what GitHub said; a 403/404 means the token can't manage this repo's deploy keys (the
            // kernel's secrets answers the same signed error)
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct E {
                #[serde(alias = "Error")]
                error: String,
            }
            if let Ok(e) = d.decode::<E>()
                && (e.error.starts_with("github: HTTP 403")
                    || e.error.starts_with("github: HTTP 404"))
            {
                return write_json(
                    w,
                    502,
                    &json!({"error": format!("the GitHub token in github-deploy-keys can't manage this repo's deploy keys ({}): it needs a fine-grained token with Repository permission \"Administration: read and write\" (all repositories)", e.error)}),
                );
            }
        }
        if finish
            && status == 200
            && let Some(d) = &doc
            && let Ok(a) = d.decode::<KeyAnswer>()
            && (a.kind == "deploy-key-added" || a.kind == "deploy-key-removed")
        {
            let asked = self.repo_askers(&a); // before the answer drops the requests
            if let Err(e) = self.apply_key_answer(a.clone(), d) {
                crate::logf!("repos: {e:#}");
            }
            let f = self.repo_followups(&a, &asked, inbox);
            if !f.is_empty() {
                // beside the core's document, not under its signature: the phone checks each approval itself
                return write_json(
                    w,
                    200,
                    &json!({"payload": d.payload, "sig": d.sig, "followups": f}),
                );
            }
        }
        w.set_header("Content-Type", "application/json");
        w.write_header(status);
        w.write(&b);
    }

    /// the sessions whose pending requests an added key answers (each gets the repo's store)
    fn repo_askers(&self, a: &KeyAnswer) -> Vec<RepoAsker> {
        let repo = parse_github_repo(&a.repo);
        if a.kind != "deploy-key-added" || repo.is_empty() {
            return vec![];
        }
        let mut out: Vec<RepoAsker> = self.st.do_(|d| {
            d.inbox
                .values()
                .filter(|q| {
                    q.kind == REQUEST_KIND_REPO
                        && q.params.action == "add"
                        && !q.params.session.is_empty()
                        && q.params.repo.eq_ignore_ascii_case(&repo)
                })
                .map(|q| RepoAsker {
                    request: q.id.clone(),
                    session: q.params.session.clone(),
                    origin: q.origin.clone(),
                    expl: q.explanation.clone(),
                })
                .collect()
        });
        out.sort_by(|x, y| x.request.cmp(&y.request));
        out
    }

    /// the repo's store into each session that asked for the repo (Deyao, 2026-10-15: "one Face ID, not a repo-key
    /// approval followed by a separate add-store"; DECISIONS 182). An add-store approval per running session that
    /// doesn't hold the store yet, filed at once now that the store exists (the core makes a challenge only for a store
    /// it has). The one for the request this page answered (inbox) is returned: the phone showed it before Face ID
    /// ("then adds the store to session …") and signs it under the same Face ID, after checking it is exactly that. Any
    /// other asking session's approval waits in the Inbox on its own. A session that isn't running gets nothing (it asks
    /// for the store again when it runs). The approval's origin is the request's caller and call, without its signed
    /// filing: the session already hears the outcome of what it filed (the repo's), and its waiter pulls the store.
    fn repo_followups(
        self: &Arc<Self>,
        a: &KeyAnswer,
        asked: &[RepoAsker],
        inbox: &str,
    ) -> Vec<String> {
        let store = repo_store(&parse_github_repo(&a.repo));
        let mut out = vec![];
        for q in asked {
            let (machine, held) = self.st.do_(|d| {
                d.sessions
                    .get(&q.session)
                    .filter(|s| s.state == "started" && s.has_line())
                    .map(|s| {
                        (
                            s.machine_id.clone(),
                            s.stores.as_ref().is_some_and(|st| st.contains(&store)),
                        )
                    })
                    .unwrap_or_default()
            });
            if machine.is_empty() || held {
                crate::logf!(
                    "repos: {} asked for {}; it isn't running (or holds {store} already): no add-store",
                    q.session,
                    a.repo
                );
                continue;
            }
            let mut o = q.origin.clone();
            o.signed = None;
            o.item = 0;
            o.batch.clear();
            let mut args = Map::new();
            args.insert("repo".into(), json!(a.repo));
            args.insert("store".into(), json!(store));
            args.insert("for".into(), json!(q.request));
            o.call = ApiCall {
                method: "POST".into(),
                path: "/api/repos/key/finish".into(),
                args,
            };
            match self.add_store_approval(&machine, &store, o, &q.expl, "") {
                Err(e) => crate::logf!("repos: the add-store of {store} for {}: {e:#}", q.session),
                Ok(id) => {
                    crate::logf!(
                        "repos: {} asked for {}: add-store {store} filed ({id})",
                        q.session,
                        a.repo
                    );
                    if q.request == inbox {
                        out.push(id);
                    }
                }
            }
        }
        out
    }

    /// every repo the read token sees, newest push first; cached 5 minutes. The token never leaves.
    pub fn github_repos(&self, refresh: bool) -> Result<(Vec<GhRepo>, GoTime)> {
        let tok = std::env::var("GITHUB_READ_TOKEN").unwrap_or_default();
        if tok.is_empty() {
            return Err(HttpStatusErr(
                503,
                "the router has no GITHUB_READ_TOKEN: it can't list your GitHub repos".into(),
            )
            .into());
        }
        if !refresh
            && let Some((at, t, repos)) = self
                .ops
                .gh
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
            && at.elapsed() < GH_TTL
        {
            return Ok((repos.clone(), *t));
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Owner {
            login: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Item {
            full_name: String,
            clone_url: String,
            html_url: String,
            private: bool,
            fork: bool,
            archived: bool,
            description: String,
            language: String,
            pushed_at: String,
            updated_at: String,
            owner: Owner,
        }
        let mut out = vec![];
        let c = github_client();
        for page in 1..=10 {
            let resp = c
                .get(format!(
                    "{}/user/repos?per_page=100&page={page}&sort=pushed&direction=desc&affiliation=owner,collaborator,organization_member",
                    github_api()
                ))
                .header("Authorization", format!("Bearer {tok}"))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header("User-Agent", "jarvis2-router/1")
                .send()
                .map_err(|e| HttpStatusErr(502, format!("GitHub unreachable: {e}")))?;
            let st = resp.status().as_u16();
            let b = crate::util::read_limited(resp, 16 << 20).unwrap_or_default();
            if st != 200 {
                return Err(HttpStatusErr(
                    502,
                    format!(
                        "GitHub /user/repos: HTTP {st} {}",
                        crate::util::trim_to(&String::from_utf8_lossy(&b), 200)
                    ),
                )
                .into());
            }
            let items: Vec<Item> = jarvis_go::unmarshal(&b)
                .map_err(|e| HttpStatusErr(502, format!("GitHub /user/repos: {e}")))?;
            let n = items.len();
            for it in items {
                let url = if it.clone_url.is_empty() {
                    format!("https://github.com/{}.git", it.full_name)
                } else {
                    it.clone_url
                };
                let pushed = if it.pushed_at.is_empty() {
                    it.updated_at
                } else {
                    it.pushed_at
                };
                out.push(GhRepo {
                    full_name: it.full_name,
                    url,
                    html_url: it.html_url,
                    private: it.private,
                    fork: it.fork,
                    archived: it.archived,
                    description: it.description,
                    language: it.language,
                    pushed_at: pushed,
                    owner: it.owner.login,
                });
            }
            if n < 100 {
                break;
            }
        }
        let now = GoTime::now();
        *self.ops.gh.0.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((Instant::now(), now, out.clone()));
        Ok((out, now))
    }
}

pub fn repos_state_hook(r: &Arc<Router>, out: &mut Map<String, Value>) {
    out.insert("repos".into(), json!(r.repos()));
}

pub fn register_repos(reg: &mut Registrar) {
    reg.app("GET /api/repos", |r, w, _| {
        write_json(w, 200, &json!({"repos": r.repos()}))
    });
    // ---- deploy keys: the core's two calls, relayed; the list follows the core's signed answer ----------------
    reg.app("POST /api/repos/key/begin", |r, w, req| {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            action: String,
            repo: String,
            sensitive: bool,
            /// the app's key pair (R2): its store name and key title, the public key, and the store's keys holding the
            /// private half (core/keys.go)
            store: String,
            title: String,
            #[serde(rename = "publicKey")]
            public_key: String,
            keys: Option<Box<serde_json::value::RawValue>>,
            /// a remove of one orphan key by GitHub's id (the kernel's secrets; the repo's store stays)
            #[serde(rename = "keyId")]
            key_id: i64,
        }
        let i: In = crate::http::decode_body(req, 1 << 20);
        let repo = parse_github_repo(&i.repo);
        if repo.is_empty() || (i.action != "add" && i.action != "remove") {
            return write_json(w, 400, &json!({"error": "a GitHub repo (owner/name or its URL) and action add or remove"}));
        }
        // the key's title on GitHub is Jarvis 4's own: the core deletes the repo's keys with the same title before it
        // adds one, so Jarvis 2's title ("jarvis2 <store>") would take Jarvis 2's key away (the kernel deletes only by id)
        if !i.store.is_empty() && i.title != deploy_key_title(&i.store) {
            return write_json(
                w,
                400,
                &json!({"error": format!("the deploy key's title must be {} (an older app sends Jarvis 2's: update the Jarvis 4 app)", deploy_key_title(&i.store))}),
            );
        }
        let mut body = json!({"action": i.action, "repo": repo, "sensitive": i.sensitive});
        if !i.store.is_empty() {
            body["store"] = json!(i.store);
            body["title"] = json!(i.title);
            body["publicKey"] = json!(i.public_key);
            if let Some(k) = i.keys.as_ref().and_then(|k| serde_json::from_str::<Value>(k.get()).ok()) {
                body["keys"] = k;
            }
        }
        if i.key_id != 0 {
            body["keyId"] = json!(i.key_id);
        }
        r.relay_deploy_key(w, "/deploy-keys/begin", jarvis_go::marshal(&body).as_bytes(), false, "");
    });
    // ?inbox=ID: the Inbox request this page answers; when a session asked for the repo, the answer names the
    // add-store approval that puts the repo's store into that session (followups), for the phone to sign under the
    // same Face ID
    reg.app("POST /api/repos/key/finish", |r, w, req| {
        let b = req.read_body(1 << 16);
        let inbox = req.query("inbox");
        r.relay_deploy_key(w, "/deploy-keys/finish", &b, true, &inbox);
    });
    reg.app("GET /api/github/repos", |r, w, req| {
        let configured = std::env::var("GITHUB_READ_TOKEN").is_ok_and(|t| !t.is_empty());
        match r.github_repos(req.query("refresh") == "1") {
            Err(e) => {
                let st = e.downcast_ref::<HttpStatusErr>().map_or(502, |h| h.0);
                write_json(w, st, &json!({"error": format!("{e:#}"), "configured": configured}));
            }
            Ok((repos, at)) => write_json(
                w,
                200,
                &json!({"repos": repos, "cachedAt": (at.unix_nanos() / 1_000_000) as i64, "configured": configured}),
            ),
        }
    });
}
