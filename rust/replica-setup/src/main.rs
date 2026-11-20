//! replica-setup MSG — the setup session's answer to one message from the phone replica's UI test (ReplicaUITests,
//! through ios/ci/replica-host.py's /relay), printed on stdout. It runs on the same runner as the test stack
//! (rust/ios-ci replica up, whose W/env the workflow step sources, so infra/setup.py points at it):
//!   reset-done  after the app's Reset: the stores written with infra/setup.py (dummy values; the harness's tunnel;
//!               github-deploy-keys = the replica test repo's token; the core's Fly token, 6 h) → "filled"
//!   repo-added  the test repo has its one deploy key now (the app shows the repo added) → "ok"
//!   repo-check  …and none left after the app removed it → "ok"
//!   inbox-setup-add / inbox-setup-remove   infra/setup.py request add-repo / remove-repo for the test repo → "ok"
//!   inbox-session:<sid>:<holder>           jarvis-request grant <holder> inside that session's machine → "ok" once filed
//!   inbox-batch:<sid>                      jarvis-request batch (two grants, one summary) there → "ok" once filed
//!   session-file:<sid>:<name>              the image attached on New session is on that session's machine (the
//!                                          machine's hash-checked copy, or the harness's ~/uploads copy)
//!   done        the end → "ok"
//!
//! jarvis-request blocks until Deyao decides (the phone replica decides only after this answers), so it is started
//! detached in the session's machine and this answers once its filing (the router's JSON answer) is in its output.
//! Env: REPLICA_W, REPLICA_PY (from W/env), REPLICA_FLY_TOKEN, REPLICA_REPO (DE0CH/<name>), REPLICA_REPO_TOKEN (that
//! repo's Administration token: its deploy keys).

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

/// The repo's root: this tool is built in the checkout it runs from (the workflow's build step).
const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const APP: &str = "jarvis4-sessions";
/// The line the detached request's shell adds when jarvis-request has ended (it never has before the decision).
const ENDED: &str = "replica-request-ended";

fn main() {
    let msg = std::env::args().nth(1).unwrap_or_default();
    if msg.is_empty() {
        eprintln!("usage: replica-setup MSG");
        std::process::exit(2);
    }
    let answer = match Ctx::from_env() {
        Ok(cx) => {
            cx.log(&format!("{} {msg}", clock(now_secs())));
            cx.answer(&msg)
        }
        Err(e) => e,
    };
    println!("{answer}");
}

struct Ctx {
    w: PathBuf,
    py: String,
    fly_token: String,
    repo: String,
    repo_token: String,
}

fn need(name: &str) -> Result<String, String> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("{name} is not set")),
    }
}

impl Ctx {
    fn from_env() -> Result<Ctx, String> {
        Ok(Ctx {
            w: PathBuf::from(need("REPLICA_W")?),
            py: need("REPLICA_PY")?,
            fly_token: need("REPLICA_FLY_TOKEN")?,
            repo: need("REPLICA_REPO")?,
            repo_token: need("REPLICA_REPO_TOKEN")?,
        })
    }

    fn log_path(&self) -> PathBuf {
        self.w.join("setup.log")
    }

    fn log(&self, text: &str) {
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_path())
        {
            let _ = writeln!(f, "{}", text.trim_end());
        }
    }

    fn log_tail(&self, n: usize) -> String {
        tail(&fs::read_to_string(self.log_path()).unwrap_or_default(), n)
    }

    /// infra/setup.py ARGS with extra env; its stdout and stderr go to the log.
    fn setup(&self, args: &[&str], env: &[(&str, String)]) -> bool {
        let mut c = Command::new(&self.py);
        c.arg("-B")
            .arg(Path::new(ROOT).join("infra/setup.py"))
            .args(args);
        for (k, v) in env {
            c.env(k, v);
        }
        match c.stdin(Stdio::null()).output() {
            Ok(o) => {
                self.log(&String::from_utf8_lossy(&o.stdout));
                self.log(&String::from_utf8_lossy(&o.stderr));
                o.status.success()
            }
            Err(e) => {
                self.log(&format!("setup.py {args:?}: {e}"));
                false
            }
        }
    }

    /// The number of deploy keys on the test repo, or "?".
    fn keys(&self) -> String {
        let o = Command::new("gh")
            .args(["api", &format!("repos/{}/keys", self.repo), "-q", "length"])
            .env("GH_TOKEN", &self.repo_token)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output();
        match o {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => "?".to_string(),
        }
    }

    /// The router's record of the session's current machine, up to 90 s.
    fn machine_of(&self, sid: &str) -> Option<String> {
        for i in 0..18 {
            if i > 0 {
                sleep(Duration::from_secs(5));
            }
            let mut c = Command::new(&self.py);
            c.arg("-B")
                .arg(Path::new(ROOT).join("infra/setup.py"))
                .arg("sessions");
            if let Ok(o) = c.stdin(Stdio::null()).output() {
                self.log(&String::from_utf8_lossy(&o.stderr));
                if let Some(m) = machine_in(&String::from_utf8_lossy(&o.stdout), sid) {
                    return Some(m);
                }
            }
        }
        None
    }

    /// flyctl machine exec M CMD: (whether flyctl exited 0, its stdout, its stderr). flyctl exits 0 whatever the
    /// command did.
    fn fexec(&self, m: &str, cmd: &str) -> (bool, String, String) {
        let o = Command::new("flyctl")
            .args(["machine", "exec", m, "-a", APP, cmd])
            .env("FLY_API_TOKEN", &self.fly_token)
            .stdin(Stdio::null())
            .output();
        match o {
            Ok(o) => (
                o.status.success(),
                String::from_utf8_lossy(&o.stdout).to_string(),
                String::from_utf8_lossy(&o.stderr).to_string(),
            ),
            Err(e) => (false, String::new(), format!("flyctl: {e}")),
        }
    }

    /// Start REQUEST (a jarvis-request command line) detached in machine M and wait, up to 2 min, until its output
    /// holds the router's answer to the filing.
    fn file_in_session(&self, m: &str, request: &str) -> Result<Map<String, Value>, String> {
        let out = format!("/tmp/replica-request-{}.out", random_hex(6));
        let (ok, so, se) = self.fexec(m, &detached(request, &out));
        self.log(&format!("{so}{se}"));
        if !ok {
            return Err(tail(&format!("{so}{se}"), 2));
        }
        let mut last = String::new();
        for _ in 0..60 {
            sleep(Duration::from_secs(2));
            let (_, so, se) = self.fexec(m, &format!("cat {out}"));
            last = format!("{so}{se}");
            match filing(&last) {
                Filing::Filed(answer) => {
                    self.log(&last);
                    return Ok(answer);
                }
                Filing::Ended => break,
                Filing::Pending => {}
            }
        }
        self.log(&last);
        Err(tail(&last, 2))
    }

    fn answer(&self, msg: &str) -> String {
        match msg {
            "reset-done" => self.reset_done(),
            "repo-added" => {
                let n = self.keys();
                if n == "1" {
                    let _ = fs::write(self.w.join("key-seen"), "");
                    "ok".to_string()
                } else {
                    format!("keys={n}")
                }
            }
            "repo-check" => {
                let left = self.keys();
                let seen = self.w.join("key-seen").exists();
                if seen && left == "0" {
                    "ok".to_string()
                } else {
                    format!("seen={} left={left}", if seen { "yes" } else { "no" })
                }
            }
            "inbox-setup-add" => {
                self.setup_request("add-repo", "replica: Claude asks for the test repo")
            }
            "inbox-setup-remove" => self.setup_request(
                "remove-repo",
                "replica: Claude asks to remove it (deny this)",
            ),
            "done" => "ok".to_string(),
            _ => {
                if let Some(rest) = msg.strip_prefix("inbox-session:") {
                    self.inbox_session(rest)
                } else if let Some(sid) = msg.strip_prefix("inbox-batch:") {
                    self.inbox_batch(sid)
                } else if let Some(rest) = msg.strip_prefix("session-file:") {
                    self.session_file(rest)
                } else {
                    format!("unknown: {msg}")
                }
            }
        }
    }

    fn reset_done(&self) -> String {
        let rnd = random_hex(6);
        let tok = self.w.join("deploy-keys.tok");
        let written = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tok)
            .and_then(|mut f| f.write_all(self.repo_token.as_bytes()));
        if let Err(e) = written {
            return format!("fill failed: {}: {e}", tok.display());
        }
        let env = [
            ("RH_PLAIN", format!("plain-{rnd}")),
            ("RH_SECRET", format!("secret-{rnd}")),
            ("CF_ACCESS_CLIENT_ID", format!("tunnel-id-{rnd}")),
            ("CF_ACCESS_CLIENT_SECRET", format!("tunnel-secret-{rnd}")),
            ("JARVIS_NOT_SENSITIVE", "rh-plain".to_string()),
        ];
        let keys_file = format!("GITHUB_DEPLOY_KEYS_TOKEN=file:{}", tok.display());
        let fly_tok = self.w.join("fly.tok").display().to_string();
        let steps: [&[&str]; 8] = [
            &["pin-master"],
            &["create", "rh-plain"],
            &[
                "write",
                "rh-plain",
                "RH_PLAIN",
                "--explain",
                "RH_PLAIN=replica test value (not secret)",
            ],
            &[
                "write",
                "rh-secret",
                "RH_SECRET",
                "--explain",
                "RH_SECRET=replica test value in a sensitive store",
            ],
            &[
                "write",
                "tunnel",
                "CF_ACCESS_CLIENT_ID",
                "CF_ACCESS_CLIENT_SECRET",
                "--explain",
                "CF_ACCESS_CLIENT_ID=replica dummy tunnel id",
                "--explain",
                "CF_ACCESS_CLIENT_SECRET=replica dummy tunnel secret",
            ],
            &[
                "write",
                "github-deploy-keys",
                &keys_file,
                "--explain",
                "GITHUB_DEPLOY_KEYS_TOKEN=the replica test repo token (deploy keys only)",
            ],
            &["backup-core", &fly_tok],
            &["stores"],
        ];
        for s in steps {
            if !self.setup(s, &env) {
                return format!("fill failed: {}", self.log_tail(3));
            }
        }
        "filled".to_string()
    }

    fn setup_request(&self, kind: &str, why: &str) -> String {
        if self.setup(&["request", kind, &self.repo, "--why", why], &[]) {
            "ok".to_string()
        } else {
            format!("request failed: {}", self.log_tail(1))
        }
    }

    fn inbox_session(&self, rest: &str) -> String {
        let (sid, holder) = rest.split_once(':').unwrap_or((rest, ""));
        if !word(holder) {
            return "bad holder".to_string();
        }
        let Some(m) = self.machine_of(sid) else {
            return format!(
                "session request failed (machine none): {}",
                self.log_tail(2)
            );
        };
        let request = format!(
            "/usr/local/bin/jarvis-request grant {holder} --minutes 5 --why replica-the-session-asks-for-{holder}"
        );
        match self.file_in_session(&m, &request) {
            Ok(_) => "ok".to_string(),
            Err(t) => format!("session request failed (machine {m}): {t}"),
        }
    }

    /// Not status: the grants step later forgets ITS status grant by the row's identifier.
    fn inbox_batch(&self, sid: &str) -> String {
        let Some(m) = self.machine_of(sid) else {
            return format!("session batch failed (machine none): {}", self.log_tail(2));
        };
        let request = "/usr/local/bin/jarvis-request batch --summary replica-the-session-asks-for-two-grants \
                       --item grant,holder=archive,minutes=5 --item grant,holder=remote,minutes=5";
        match self.file_in_session(&m, request) {
            Ok(a) if is_batch(&a) => "ok".to_string(),
            Ok(a) => format!(
                "session batch failed (machine {m}): no batch id in {}",
                Value::Object(a)
            ),
            Err(t) => format!("session batch failed (machine {m}): {t}"),
        }
    }

    fn session_file(&self, rest: &str) -> String {
        let (sid, name) = rest.split_once(':').unwrap_or((rest, ""));
        if !word(name) {
            return "bad name".to_string();
        }
        let mut m = None;
        for i in 0..18 {
            if i > 0 {
                sleep(Duration::from_secs(10));
            }
            m = self.machine_of(sid);
            if let Some(ref mm) = m {
                let (_, so, se) = self.fexec(
                    mm,
                    &format!("find /root /home -maxdepth 3 -type f -name {name} -size +0c"),
                );
                self.log(&se);
                let found = uploads_of(&so, name);
                if !found.is_empty() {
                    return format!("ok {}", found.join(" "));
                }
            }
        }
        format!(
            "not on the machine ({}): {}",
            m.as_deref().unwrap_or("none"),
            self.log_tail(2)
        )
    }
}

/// What the detached request's output says so far.
#[derive(Debug, PartialEq)]
enum Filing {
    /// The router's answer to the filing (jarvis-request prints it before it waits on the decision).
    Filed(Map<String, Value>),
    /// jarvis-request ended without one (a refused filing prints its HTTP error instead).
    Ended,
    Pending,
}

fn filing(out: &str) -> Filing {
    for line in out.lines() {
        let l = line.trim();
        if l.starts_with('{')
            && let Ok(Value::Object(o)) = serde_json::from_str::<Value>(l)
        {
            return Filing::Filed(o);
        }
    }
    if out.lines().any(|l| l.trim() == ENDED) {
        Filing::Ended
    } else {
        Filing::Pending
    }
}

fn is_batch(answer: &Map<String, Value>) -> bool {
    answer
        .get("id")
        .and_then(Value::as_str)
        .is_some_and(|id| id.starts_with('b'))
}

/// The machine's command that starts REQUEST in its own session, its output to OUT and ENDED after it, and returns at
/// once. Fly's exec splits the line into words (no shell), hence the sh; no `$`, so nothing depends on how it quotes.
fn detached(request: &str, out: &str) -> String {
    format!(
        "sh -c \"setsid sh -c '{request} > {out} 2>&1; echo {ENDED} >> {out}' < /dev/null > /dev/null 2>&1 &\""
    )
}

/// The machine of SID in `setup.py sessions` output (id, machine or "-", …).
fn machine_in(sessions: &str, sid: &str) -> Option<String> {
    sessions.lines().find_map(|l| {
        let mut f = l.split_whitespace();
        match (f.next(), f.next()) {
            (Some(s), Some(m)) if s == sid && m != "-" => Some(m.to_string()),
            _ => None,
        }
    })
}

/// The paths in `find` output that are NAME in an uploads dir (the machine's .jarvis-uploads or the harness's uploads).
fn uploads_of(find: &str, name: &str) -> Vec<String> {
    find.lines()
        .map(|l| l.trim_end_matches('\r').trim())
        .filter(|p| {
            p.ends_with(&format!("/.jarvis-uploads/{name}"))
                || p.ends_with(&format!("/uploads/{name}"))
        })
        .map(str::to_string)
        .collect()
}

/// A safe word for a machine's command line: [A-Za-z0-9._-]+.
fn word(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// The last N lines, on one line.
fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(n)..].join(" ")
}

fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut b);
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// HH:MM:SS (UTC) of a Unix time.
fn clock(secs: u64) -> String {
    let s = secs % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
}

#[cfg(test)]
mod tests;
