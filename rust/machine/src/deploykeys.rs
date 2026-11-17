//! Per-repo deploy keys (docs/DESIGN.md "Deploy keys"). A repo's store (github-<repo>, made by the core when Deyao
//! added the repo) holds GITHUB_DEPLOY_REPO_<SLUG> = "owner/name" and GITHUB_DEPLOY_KEY_<SLUG> = the base64 of an
//! OpenSSH private key GitHub accepts for that one repo only (read + push). The private keys never touch the disk: the
//! supervisor holds them in RAM in its own ssh-agent (ssh-agent.sock), and every signature it makes is logged with
//! the caller. For every pair in the session's secrets the supervisor sets up:
//!
//!   - the key in its ssh-agent, and its PUBLIC half in ~/.ssh/jarvis2-deploy/<owner>__<name>.pub;
//!   - an SSH host alias github.com-jarvis2-<slug> → github.com with that key only (IdentityFile = the public half,
//!     IdentitiesOnly, IdentityAgent = the supervisor's agent) and GitHub's published host keys pinned; both files
//!     named under `~/`, which ssh takes from the user's passwd home (an aviary session's agent runs in the sandbox as
//!     another user whose home is the machine's /home/claude);
//!   - git rewrites from https://github.com/<owner>/<name>.git and git@github.com:<owner>/<name>.git to the alias.
//!
//! Nothing else reaches the alias: other repos keep plain HTTPS (no credentials). The set is rewritten whole whenever
//! the supervisor's secrets change (boot, refresh, add-store, downgrade), so a dropped store's key goes with it.

use crate::session::{peer_of, session_command, session_peer};
use crate::{logf, paths, util};
use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ssh_key::{Algorithm, PrivateKey};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::sync::{LazyLock, Mutex};

pub const DEPLOY_REPO_PREFIX: &str = "GITHUB_DEPLOY_REPO_";
pub const DEPLOY_KEY_PREFIX: &str = "GITHUB_DEPLOY_KEY_";
pub const DEPLOY_KEY_DIR: &str = ".ssh/jarvis2-deploy";
pub const GITHUB_KNOWN_HOSTS: &str = ".ssh/jarvis2-github-known-hosts";
pub const SSH_CONFIG_BEGIN: &str = "# >>> jarvis2 deploy keys (jarvis-machine rewrites this block)";
pub const SSH_CONFIG_END: &str = "# <<< jarvis2 deploy keys";
pub const ALIAS_PREFIX: &str = "github.com-jarvis2-";

/// GitHub's SSH host keys, as published at https://api.github.com/meta (ssh_keys)
pub const GITHUB_HOST_KEYS: &[&str] = &[
    "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
    "github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
    "github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
];

#[derive(Debug, Clone)]
pub struct DeployKey {
    /// owner/name, as the store says
    pub repo: String,
    /// the SSH host alias
    pub alias: String,
    /// the OpenSSH private key file
    pub key: Vec<u8>,
}

/// the repo/key pairs in the secrets, sorted by repo
pub fn deploy_keys(secrets: &HashMap<String, String>) -> Vec<DeployKey> {
    let mut out = vec![];
    for (k, repo) in secrets {
        let Some(slug) = k.strip_prefix(DEPLOY_REPO_PREFIX) else {
            continue;
        };
        if slug.is_empty() || !valid_repo(repo) {
            continue;
        }
        let key = secrets
            .get(&format!("{DEPLOY_KEY_PREFIX}{slug}"))
            .and_then(|v| B64.decode(v).ok())
            .filter(|k| k.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----"));
        let Some(key) = key else {
            logf!("deploy key for {repo}: missing or not an OpenSSH key; skipped");
            continue;
        };
        out.push(DeployKey {
            repo: repo.clone(),
            alias: format!("{ALIAS_PREFIX}{}", slug.replace('_', "-").to_lowercase()),
            key,
        });
    }
    out.sort_by(|a, b| a.repo.cmp(&b.repo));
    out
}

pub fn valid_repo(repo: &str) -> bool {
    let Some((owner, name)) = repo.split_once('/') else {
        return false;
    };
    if owner.is_empty() || name.is_empty() || name == "." || name.contains("..") {
        return false;
    }
    format!("{owner}{name}")
        .chars()
        .all(|r| r.is_ascii_alphanumeric() || r == '-' || r == '_' || r == '.')
}

/// Write the keys, the SSH aliases and git's rewrites for exactly the repos in `secrets` (and remove earlier ones)
pub fn setup_deploy_keys(secrets: &HashMap<String, String>) -> Result<()> {
    let home = paths::home();
    let keys = deploy_keys(secrets);
    let dir = home.join(DEPLOY_KEY_DIR);
    std::fs::create_dir_all(&dir)?;
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::set_permissions(home.join(".ssh"), std::fs::Permissions::from_mode(0o700));
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let _ = crate::downgrade::shred_write(&e.path(), b"", 0o600); // a key file an earlier image wrote, too
            let _ = std::fs::remove_file(e.path());
        }
    }
    agent_keys().clear();
    util::write_file(
        &home.join(GITHUB_KNOWN_HOSTS),
        (GITHUB_HOST_KEYS.join("\n") + "\n").as_bytes(),
        0o644,
    )?;
    let mut block = format!("{SSH_CONFIG_BEGIN}\n");
    let mut added = vec![];
    for k in &keys {
        let priv_key = match PrivateKey::from_openssh(&k.key) {
            Ok(p) => p,
            Err(e) => {
                logf!("deploy key for {}: {e}; skipped", k.repo);
                continue;
            }
        };
        let pub_line = priv_key
            .public_key()
            .to_openssh()
            .map_err(|e| anyhow!("{e}"))?;
        let f = dir.join(format!("{}.pub", k.repo.replace('/', "__")));
        util::write_file(
            &f,
            format!("{}\n", strip_comment(&pub_line)).as_bytes(),
            0o644,
        )?;
        block.push_str(&format!(
            "Host {}\n  HostName github.com\n  User git\n  IdentityFile ~/{DEPLOY_KEY_DIR}/{}\n  IdentitiesOnly yes\n  IdentityAgent {}\n  UserKnownHostsFile ~/{GITHUB_KNOWN_HOSTS}\n  StrictHostKeyChecking yes\n",
            k.alias,
            f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
            paths::ssh_agent_sock().display()
        ));
        added.push((priv_key, k.repo.clone()));
    }
    agent_keys().extend(added);
    block.push_str(&format!("{SSH_CONFIG_END}\n"));
    write_ssh_config(&home.join(".ssh").join("config"), &block)?;
    // git: drop the earlier rewrites, then one per repo URL form (exact `.git` URLs: a rewrite is a prefix match, so a
    // URL without `.git` would also catch <name>-something)
    let pat = format!(r"^url\.git@{}", ALIAS_PREFIX.replace('.', r"\."));
    if let Ok(out) = session_command(
        "git",
        &["config", "--global", "--name-only", "--get-regexp", &pat],
    )
    .output()
        && out.status.success()
    {
        let mut seen = std::collections::HashSet::new();
        for l in String::from_utf8_lossy(&out.stdout).trim().lines() {
            let sec = l.strip_suffix(".insteadof").unwrap_or(l).to_string();
            if !l.is_empty() && seen.insert(sec.clone()) {
                let _ = session_command("git", &["config", "--global", "--remove-section", &sec])
                    .status();
            }
        }
    }
    for k in &keys {
        let to = format!("url.git@{}:{}.git.insteadOf", k.alias, k.repo);
        let mut forms = std::collections::BTreeSet::new();
        for r in [k.repo.clone(), k.repo.to_lowercase()] {
            forms.insert(format!("https://github.com/{r}.git"));
            forms.insert(format!("git@github.com:{r}.git"));
            forms.insert(format!("ssh://git@github.com/{r}.git"));
        }
        for f in forms {
            let st = session_command("git", &["config", "--global", "--add", &to, &f]).status()?;
            if !st.success() {
                return Err(anyhow!("git config: {st}"));
            }
        }
    }
    if !keys.is_empty() {
        let names: Vec<&str> = keys.iter().map(|k| k.repo.as_str()).collect();
        logf!(
            "deploy keys: {} (SSH, GitHub's host keys pinned)",
            names.join(", ")
        );
    }
    Ok(())
}

/// "type base64" of an authorized_keys line (Go's ssh.MarshalAuthorizedKey writes no comment)
fn strip_comment(line: &str) -> String {
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

/// our block first (ssh takes the first value it finds), the rest of the file as it was
pub fn write_ssh_config(path: &std::path::Path, block: &str) -> Result<()> {
    let mut rest = std::fs::read_to_string(path).unwrap_or_default();
    if let Some(i) = rest.find(SSH_CONFIG_BEGIN)
        && let Some(j) = rest[i..].find(SSH_CONFIG_END)
    {
        let after = &rest[i + j + SSH_CONFIG_END.len()..];
        rest = format!(
            "{}{}",
            &rest[..i],
            after.strip_prefix('\n').unwrap_or(after)
        );
    }
    util::write_file(path, format!("{block}{rest}").as_bytes(), 0o600)?;
    Ok(())
}

/// a GitHub repo as https://github.com/<owner>/<name>.git (the form git's rewrites match); others as given
pub fn clone_url(u: &str) -> String {
    let u = u.trim();
    for p in ["https://github.com/", "git@github.com:"] {
        if let Some(rest) = u.strip_prefix(p) {
            let rest = rest.strip_suffix('/').unwrap_or(rest);
            return format!(
                "https://github.com/{}.git",
                rest.strip_suffix(".git").unwrap_or(rest)
            );
        }
    }
    u.to_string()
}

// ---- the supervisor's ssh-agent ---------------------------------------------------------------------------------

/// the keys the agent holds (in RAM only), each with its repo
static AGENT: LazyLock<Mutex<Vec<(PrivateKey, String)>>> = LazyLock::new(|| Mutex::new(vec![]));

pub fn agent_keys() -> std::sync::MutexGuard<'static, Vec<(PrivateKey, String)>> {
    AGENT.lock().unwrap_or_else(|e| e.into_inner())
}

// the agent protocol (draft-miller-ssh-agent): the two requests ssh makes; anything else (adding or removing keys,
// locking, extensions) fails: only the supervisor's own secrets put keys in it
const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;

fn put_string(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn get_string<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
    if b.len() < 4 {
        return None;
    }
    let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    if b.len() < 4 + n {
        return None;
    }
    let s = &b[4..4 + n];
    *b = &b[4 + n..];
    Some(s)
}

fn public_blob(k: &PrivateKey) -> Vec<u8> {
    k.public_key().to_bytes().unwrap_or_default()
}

/// one agent request → its answer; `caller` for the log
pub fn agent_answer(req: &[u8], caller: &str) -> Vec<u8> {
    let Some((&kind, mut rest)) = req.split_first() else {
        return vec![FAILURE];
    };
    match kind {
        REQUEST_IDENTITIES => {
            let keys = agent_keys();
            let mut out = vec![IDENTITIES_ANSWER];
            out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
            for (k, repo) in keys.iter() {
                put_string(&mut out, &public_blob(k));
                put_string(&mut out, repo.as_bytes());
            }
            out
        }
        SIGN_REQUEST => {
            let (Some(blob), Some(data)) = (get_string(&mut rest), get_string(&mut rest)) else {
                return vec![FAILURE];
            };
            let flags = if rest.len() >= 4 {
                u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]])
            } else {
                0
            };
            let keys = agent_keys();
            let found = keys.iter().find(|(k, _)| public_blob(k) == blob);
            let repo = found.map(|(_, r)| r.as_str()).unwrap_or("?");
            let sig = found.and_then(|(k, _)| sign_with(k, data, flags));
            logf!(
                "ssh-agent: signed with the deploy key of {repo} for {caller}{}",
                if sig.is_none() { " (refused)" } else { "" }
            );
            match sig {
                Some(s) => {
                    let mut out = vec![SIGN_RESPONSE];
                    put_string(&mut out, &s);
                    out
                }
                None => vec![FAILURE],
            }
        }
        _ => vec![FAILURE],
    }
}

/// the signature blob (algorithm name, signature) of `data` (ed25519 and ECDSA: the core makes ed25519 keys; an RSA
/// key, which would need the flags' hash, is refused)
fn sign_with(k: &PrivateKey, data: &[u8], _flags: u32) -> Option<Vec<u8>> {
    if matches!(k.algorithm(), Algorithm::Rsa { .. }) {
        return None;
    }
    let sig: ssh_key::Signature = signature::Signer::try_sign(k, data).ok()?;
    let mut out = vec![];
    put_string(&mut out, sig.algorithm().as_str().as_bytes());
    put_string(&mut out, sig.as_bytes());
    Some(out)
}

fn serve_conn(mut conn: std::os::unix::net::UnixStream) {
    let (pid, uid, comm) = peer_of(&conn);
    if !session_peer(uid) {
        logf!("ssh-agent: refused a caller of uid {uid} (pid {pid} {comm})");
        return;
    }
    let caller = format!("pid {pid} {comm}");
    loop {
        let mut len = [0u8; 4];
        if conn.read_exact(&mut len).is_err() {
            return;
        }
        let n = u32::from_be_bytes(len) as usize;
        if n == 0 || n > 256 << 10 {
            return;
        }
        let mut req = vec![0u8; n];
        if conn.read_exact(&mut req).is_err() {
            return;
        }
        let ans = agent_answer(&req, &caller);
        let mut out = (ans.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&ans);
        if conn.write_all(&out).is_err() {
            return;
        }
    }
}

/// the agent's socket (0600, user claude; started by the supervisor)
pub fn serve_ssh_agent() {
    let p = paths::ssh_agent_sock();
    let _ = std::fs::remove_file(&p);
    let ln = match std::os::unix::net::UnixListener::bind(&p) {
        Ok(l) => l,
        Err(e) => {
            logf!("ssh-agent: {e}");
            return;
        }
    };
    let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    loop {
        match ln.accept() {
            Ok((c, _)) => {
                std::thread::spawn(move || serve_conn(c));
            }
            Err(_) => util::sleep(std::time::Duration::from_secs(1)),
        }
    }
}
