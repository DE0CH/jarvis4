//! session-entrypoint (user claude; the keeper starts it on every start of the harness, rust/machine/src/keeper.rs
//! BASE_ENTRY): the session's own steps before its harness, then `exec harness-claude.sh <working dir>`.
//!
//! The environment it reads (the machine's env, built by jarvis-machine boot):
//!   CLAUDE_CREDENTIALS       ~/.claude/.credentials.json (OAuth; enables remote-control)
//!   CLAUDE_ACCOUNT           a minimal ~/.claude.json (oauthAccount + userID), optional
//!   SESSION_REPOS            comma-separated git URLs cloned into ~/workspace
//!   SESSION_CONTENT          comma-separated content stores, pulled into ~/content/<store>/ (content-sync)
//!   SESSION_SECRET_CONFLICTS the keys several selected stores set differently (one value won at random)
//!   JARVIS_HARNESS_START     which start of the harness this is on this machine (1, 2, …): a restart (> 1) skips the
//!                            one-time steps (the Claude login and account, which the supervisor keeps current; the
//!                            content stores, which may hold unpushed changes; ssh and the on-start hooks, still up)
//!   SESSION_API_TOKEN, JARVIS_URL, SESSION_ID / FLY_MACHINE_ID, CF_ACCESS_CLIENT_ID/SECRET  the repo bundles' download
//! The harness's own settings (SESSION_HARNESS, SESSION_PROMPT, SESSION_MODEL, …) are harness-claude.sh's.
//! Its lines go to the session's log, so each starts with `[entrypoint] `.

use serde_json::{Map, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

pub const TAG: &str = "[entrypoint]";
const HOME: &str = "/home/claude";

fn say(msg: &str) {
    println!("{TAG} {msg}");
    let _ = std::io::stdout().flush();
}

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_default()
}

/// A repo's directory name: the URL's last part without `.git`.
pub fn repo_name(url: &str) -> String {
    let base = url
        .trim()
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("");
    base.strip_suffix(".git").unwrap_or(base).to_string()
}

/// ~/.claude.json: what is there (the predecessor's, restored with the snapshot) with the account over it and the fixed
/// flags last; the machine id stays the restored one (the same Remote Control target), else `fresh_mid`.
pub fn claude_json(existing: Option<Value>, account: &str, fresh_mid: &str) -> Value {
    let mut out = match existing {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    };
    let mid = out
        .get("machineID")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| fresh_mid.to_string());
    if let Ok(Value::Object(acc)) =
        serde_json::from_str::<Value>(if account.is_empty() { "{}" } else { account })
    {
        out.extend(acc);
    }
    for (k, v) in [
        ("machineID", Value::String(mid)),
        ("hasCompletedOnboarding", Value::Bool(true)),
        ("hasUsedRemoteControl", Value::Bool(true)),
        ("bypassPermissionsModeAccepted", Value::Bool(true)),
        ("autoUpdates", Value::Bool(false)),
    ] {
        out.insert(k.to_string(), v);
    }
    Value::Object(out)
}

/// The working directory: the one repo when the workspace holds exactly one directory, else the workspace.
pub fn working_dir(ws: &Path, dirs: &[PathBuf]) -> PathBuf {
    if dirs.len() == 1 {
        dirs[0].clone()
    } else {
        ws.to_path_buf()
    }
}

fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    fs::write(path, text)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

/// Started in its own session, detached from the harness (`setsid nohup … &`).
fn detach(cmd: &mut Command, log: &Path) -> std::io::Result<()> {
    let out = fs::File::create(log)?;
    let err = out.try_clone()?;
    cmd.stdin(Stdio::null()).stdout(out).stderr(err);
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
            Ok(())
        });
    }
    cmd.spawn().map(|_| ())
}

/// The repo's bundle from Jarvis (three tries, 5 min each).
fn download_bundle(name: &str, to: &Path) -> Result<(), String> {
    let url = format!(
        "{}/api/sessions/{}/repos/{name}/bundle",
        env("JARVIS_URL").trim_end_matches('/'),
        if env("SESSION_ID").is_empty() {
            env("FLY_MACHINE_ID")
        } else {
            env("SESSION_ID")
        }
    );
    let mut last = String::new();
    for _ in 0..3 {
        let res = ureq::get(&url)
            .timeout(Duration::from_secs(300))
            .set(
                "Authorization",
                &format!("Bearer {}", env("SESSION_API_TOKEN")),
            )
            .set("User-Agent", "claude-session-entrypoint/1")
            .set("CF-Access-Client-Id", &env("CF_ACCESS_CLIENT_ID"))
            .set("CF-Access-Client-Secret", &env("CF_ACCESS_CLIENT_SECRET"))
            .call();
        match res {
            Ok(r) => {
                let mut f = fs::File::create(to).map_err(|e| e.to_string())?;
                match std::io::copy(&mut r.into_reader(), &mut f) {
                    Ok(_) => return Ok(()),
                    Err(e) => last = e.to_string(),
                }
            }
            Err(e) => last = e.to_string(),
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let _ = fs::remove_file(to);
    Err(last)
}

fn nonempty(p: &Path) -> bool {
    fs::metadata(p).map(|m| m.len() > 0).unwrap_or(false)
}

fn git(args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new("git").args(args).stdin(Stdio::null()).output()
}

fn clone_repos(ws: &Path, delivery: &Path) {
    let repos = env("SESSION_REPOS");
    if repos.is_empty() {
        say("SESSION_REPOS is empty: no repo to clone (the session runs in an empty ~/workspace)");
        return;
    }
    for url in repos.split(',').map(str::trim).filter(|u| !u.is_empty()) {
        let name = repo_name(url);
        let dir = ws.join(&name);
        if dir.join(".git").is_dir() {
            say(&format!(
                "{name} restored from the pause snapshot; not cloning"
            ));
            continue;
        }
        let bundle = delivery.join("repos").join(format!("{name}.bundle"));
        if !nonempty(&bundle)
            && !env("SESSION_API_TOKEN").is_empty()
            && !env("JARVIS_URL").is_empty()
        {
            let _ = fs::create_dir_all(delivery.join("repos"));
            if let Err(e) = download_bundle(&name, &bundle) {
                say(&format!(
                    "WARN could not download the {name} bundle from Jarvis: {e}"
                ));
            }
        }
        if !nonempty(&bundle) {
            say(&format!("WARN no bundle for {name}: not cloned"));
            continue;
        }
        say(&format!("cloning {name} from the Jarvis bundle"));
        let (b, d) = (bundle.to_string_lossy(), dir.to_string_lossy());
        match git(&["clone", "-q", &b, &d]) {
            Ok(o) if o.status.success() => {
                let _ = git(&["-C", &d, "remote", "set-url", "origin", url]);
                // origin/<branch> as the bundle carried them, so `git status` means something
                let _ = git(&[
                    "-C",
                    &d,
                    "fetch",
                    "-q",
                    &b,
                    "+refs/heads/*:refs/remotes/origin/*",
                ]);
            }
            Ok(o) => say(&format!(
                "WARN clone from bundle failed: {name}: {}",
                String::from_utf8_lossy(&[o.stdout, o.stderr].concat()).replace('\n', " ")
            )),
            Err(e) => say(&format!("WARN clone from bundle failed: {name}: {e}")),
        }
    }
}

/// SESSION_CONTENT's stores into ~/content/<store>/, fresh on every first start (unpushed changes from before a pause
/// are gone). A hand-off session (no Jarvis access) has them delivered in ~/.jarvis-delivery/content/ instead.
fn pull_content(home: &Path, delivery: &Path) {
    let _ = fs::remove_dir_all(home.join("content"));
    let _ = fs::remove_dir_all(home.join(".content-sync"));
    if delivery.join("content").is_dir() {
        if fs::rename(delivery.join("content"), home.join("content")).is_ok() {
            let names: Vec<String> = fs::read_dir(home.join("content"))
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect();
            say(&format!(
                "content: delivered by Jarvis: {}",
                names.join(" ")
            ));
        }
        return;
    }
    match Command::new("/usr/local/bin/content-sync")
        .args(["pull", "--force"])
        .stdin(Stdio::null())
        .output()
    {
        Ok(o) => {
            for line in String::from_utf8_lossy(&[o.stdout, o.stderr].concat()).lines() {
                say(&format!("content: {line}"));
            }
        }
        Err(e) => say(&format!("content: content-sync did not start: {e}")),
    }
}

pub fn run() -> Result<ExitCode, String> {
    let home = PathBuf::from(HOME);
    // SAFETY: single-threaded here; harness-claude.sh and everything below read HOME
    unsafe { std::env::set_var("HOME", HOME) };
    std::env::set_current_dir(&home).map_err(|e| format!("cd {HOME}: {e}"))?;
    // ~/artifacts: what the session puts there is archived with its transcripts when it is destroyed
    for d in [".claude", "workspace", "artifacts"] {
        let _ = fs::create_dir_all(home.join(d));
    }
    let start: u64 = env("JARVIS_HARNESS_START").parse().unwrap_or(1);
    let restart = start > 1;
    if restart {
        say(&format!(
            "harness start {start} on this machine: the one-time steps are skipped"
        ));
    }

    // Several selected stores setting one key differently: Jarvis picked one at random; the list lets the agent see it.
    let conflicts = home.join(".session-secret-conflicts.json");
    let _ = fs::remove_file(&conflicts);
    let sc = env("SESSION_SECRET_CONFLICTS");
    if !sc.is_empty() {
        let _ = write_private(&conflicts, &format!("{sc}\n"));
        say(&format!(
            "WARN secret-store key conflicts across the selected stores (value chosen at random): see {}",
            conflicts.display()
        ));
    }

    if !restart {
        let creds = env("CLAUDE_CREDENTIALS");
        if !creds.is_empty()
            && let Err(e) = write_private(&home.join(".claude/.credentials.json"), &creds)
        {
            say(&format!("WARN writing the Claude credentials: {e}"));
        }
        let p = home.join(".claude.json");
        let existing = fs::read_to_string(&p)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok());
        let fresh = fs::read_to_string("/proc/sys/kernel/random/uuid")
            .unwrap_or_default()
            .trim()
            .replace('-', "");
        let v = claude_json(existing, &env("CLAUDE_ACCOUNT"), &fresh);
        if let Err(e) = fs::write(&p, v.to_string()) {
            say(&format!("WARN writing ~/.claude.json: {e}"));
        }
    }

    // Repos come from Jarvis as git bundles (Jarvis fetches them with its own GitHub token); origin then points at
    // the real URL, so pushing works with the session's deploy key.
    let ws = home.join("workspace");
    let delivery = home.join(".jarvis-delivery");
    clone_repos(&ws, &delivery);
    if !restart && !env("SESSION_CONTENT").is_empty() {
        pull_content(&home, &delivery);
    }
    let _ = fs::remove_dir_all(&delivery);

    let mut dirs: Vec<PathBuf> = fs::read_dir(&ws)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    let wd = working_dir(&ws, &dirs);
    // Several repos: Claude Code finds CLAUDE.md, skills, settings and hooks only in the cwd and its ancestors, so the
    // workspace gets a layer linking to every repo's own, rewritten on every start
    if wd == ws
        && dirs.len() > 1
        && let Err(e) = crate::workspace_layer::write(&ws)
    {
        say(&format!("WARN the workspace layer: {e}"));
    }

    if !restart {
        // Deyao's ssh (sshd + the session's <id>-ssh tunnel), once per machine, so a harness restart leaves it up
        if let Err(e) = detach(
            &mut Command::new("/usr/local/bin/jarvis-ssh"),
            &home.join(".jarvis-ssh.log"),
        ) {
            say(&format!("WARN jarvis-ssh did not start: {e}"));
        }
        // Servers a session started die with a pause: executables in ~/artifacts/on-start/ come back with the snapshot
        // and are started here, in the working directory, each logging to <file>.log beside it
        let mut hooks: Vec<PathBuf> = fs::read_dir(home.join("artifacts/on-start"))
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.is_file() && fs::metadata(p).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
            })
            .collect();
        hooks.sort();
        for f in hooks {
            let log = PathBuf::from(format!("{}.log", f.display()));
            match detach(Command::new(&f).current_dir(&wd), &log) {
                Ok(()) => say(&format!("on-start hook: {}", f.display())),
                Err(e) => say(&format!("WARN on-start hook {}: {e}", f.display())),
            }
        }
    }

    let err = Command::new("/usr/local/bin/harness-claude.sh")
        .arg(&wd)
        .exec();
    Err(format!("exec harness-claude.sh: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn repo_names() {
        assert_eq!(
            repo_name(" https://github.com/DE0CH/claude-env.git "),
            "claude-env"
        );
        assert_eq!(repo_name("https://github.com/DE0CH/aviary"), "aviary");
    }

    #[test]
    fn claude_json_keeps_the_restored_machine_id_and_fields() {
        let v = claude_json(
            Some(json!({"machineID": "old", "projects": {"/x": {}}, "autoUpdates": true})),
            r#"{"oauthAccount": {"emailAddress": "a@b"}, "userID": "u"}"#,
            "fresh",
        );
        assert_eq!(v["machineID"], "old");
        assert_eq!(v["projects"], json!({"/x": {}}));
        assert_eq!(v["oauthAccount"]["emailAddress"], "a@b");
        assert_eq!(v["autoUpdates"], false);
        assert_eq!(v["hasCompletedOnboarding"], true);
    }

    #[test]
    fn claude_json_on_a_new_machine() {
        let v = claude_json(None, "not json", "fresh");
        assert_eq!(v["machineID"], "fresh");
        assert_eq!(v["bypassPermissionsModeAccepted"], true);
    }

    #[test]
    fn one_directory_is_the_working_directory() {
        let ws = Path::new("/w");
        assert_eq!(working_dir(ws, &[ws.join("r")]), ws.join("r"));
        assert_eq!(working_dir(ws, &[]), ws);
        assert_eq!(working_dir(ws, &[ws.join("a"), ws.join("b")]), ws);
    }
}
