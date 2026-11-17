//! Task lines (router/tasks.go, DECISIONS 32-37): a machine whose signed harness is "task:<template>" runs that
//! template from the image (/opt/jarvis/tasks/<template>, fixed by the cert's image digest) instead of a harness,
//! reports the result to /m/task-result, and waits to be paused. No AI is in the loop unless the template is a prompt
//! (claude -p). No shell grant is involved, so a line holding a sensitive store runs unattended too.
//!
//! The script's environment is built here, not inherited: a fixed base (PATH, HOME, …), the router's TASK_* / PARAM_*
//! values (not secret, unsigned: the script treats them as data), the run's paths, and the line's store values last
//! (the router can't override them). Store values are redacted from the log and the output before they leave the
//! machine or reach the snapshot.

use crate::client::Client;
use crate::session::session_command;
use crate::{gojson, logf, paths, re, util};
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

pub const TASK_HARNESS_PREFIX: &str = "task:";
const TASK_KEEP_LOGS: usize = 20;
const TASK_LOG_MAX: usize = 256 << 10;
const TASK_OUTPUT_MAX: u64 = 64 << 10;
/// baked into the session image (session-image/Dockerfile)
pub const TASKS_ROOT: &str = "/opt/jarvis/tasks";
const TASK_REPORT_WAIT: Duration = Duration::from_secs(10);
const TASK_REPORT_FOR: Duration = Duration::from_secs(30 * 60);

re!(TASK_TEMPLATE_RE = r"^[a-z0-9][a-z0-9-]{0,39}$");
re!(ENV_NAME_RE = r"^[A-Za-z_][A-Za-z0-9_]*$");
re!(PLACEHOLDER_RE = r"\{\{\s*([a-z][a-z0-9_]*)\s*\}\}");

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TaskSpec {
    pub run: String,
    pub prompt: String,
    #[serde(rename = "timeoutSeconds")]
    pub timeout_seconds: Option<f64>,
    pub model: String,
}

/// as router/tasks.go reads it
#[derive(Debug, Clone, Default, Serialize)]
pub struct TaskResult {
    pub run: String,
    #[serde(rename = "exitCode")]
    pub exit_code: i32,
    #[serde(rename = "timedOut")]
    pub timed_out: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "finishedAt")]
    pub finished_at: String,
    pub log: String,
    pub output: String,
}

fn now() -> String {
    jarvis_doc::now()
}

/// the task line's vouched values (boot sets them; Go put them in the process env, which Rust forbids changing once
/// threads run): read over the process env
static TASK_ENV: std::sync::Mutex<BTreeMap<String, String>> =
    std::sync::Mutex::new(BTreeMap::new());

pub fn set_task_env(k: &str, v: &str) {
    if let Ok(mut m) = TASK_ENV.lock() {
        m.insert(k.to_string(), v.to_string());
    }
}

fn getenv(k: &str) -> String {
    TASK_ENV
        .lock()
        .ok()
        .and_then(|m| m.get(k).cloned())
        .unwrap_or_else(|| crate::env::get(k))
}

/// the process env with the task's values over it
fn environ() -> Vec<String> {
    let mut m: BTreeMap<String, String> = crate::env::vars().into_iter().collect();
    if let Ok(t) = TASK_ENV.lock() {
        m.extend(t.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    m.into_iter().map(|(k, v)| format!("{k}={v}")).collect()
}

/// the template's task.json, with the router's defaults (run.py / run.sh / run.js, else prompt.md)
pub fn load_task_spec(dir: &Path) -> Result<(TaskSpec, Duration)> {
    let b = std::fs::read(dir.join("task.json")).map_err(|e| anyhow!("no template here: {e}"))?;
    let mut s: TaskSpec = gojson::unmarshal(&b).map_err(|e| anyhow!("task.json: {e}"))?;
    let exists = |f: &str| !f.is_empty() && dir.join(f).exists();
    if s.run.is_empty() && s.prompt.is_empty() {
        if let Some(f) = ["run.py", "run.sh", "run.js"]
            .into_iter()
            .find(|f| exists(f))
        {
            s.run = f.into();
        }
        if s.run.is_empty() && exists("prompt.md") {
            s.prompt = "prompt.md".into();
        }
    }
    for f in [&s.run, &s.prompt] {
        if !f.is_empty() && (f.contains('/') || !exists(f)) {
            bail!("{} is not a file of the template", gojson::marshal(f));
        }
    }
    if s.run.is_empty() && s.prompt.is_empty() {
        bail!("the template has no run file and no prompt");
    }
    let mut timeout = Duration::from_secs(600);
    if let Some(t) = s.timeout_seconds
        && t >= 10.0
    {
        timeout = Duration::from_secs_f64(t);
    }
    Ok((s, timeout))
}

/// Jarvis 1's runner by extension (python3 -u / bash / node / the file itself); a prompt runs claude -p in the cert's
/// permission mode with the prompt on stdin ({{field}} filled from TASK_PARAMS)
pub fn task_command(
    dir: &Path,
    s: &TaskSpec,
    mode: &str,
    params: &str,
) -> Result<(Vec<String>, String)> {
    if !s.run.is_empty() {
        let p = dir.join(&s.run).to_string_lossy().into_owned();
        let args = if p.ends_with(".py") {
            vec!["python3".into(), "-u".into(), p]
        } else if p.ends_with(".sh") {
            vec!["bash".into(), p]
        } else if p.ends_with(".js") || p.ends_with(".mjs") || p.ends_with(".cjs") {
            vec!["node".into(), p]
        } else {
            vec![p]
        };
        return Ok((args, String::new()));
    }
    let text = fill_prompt(&std::fs::read_to_string(dir.join(&s.prompt))?, params);
    let mut args: Vec<String> = ["claude", "-p", "--output-format", "text"]
        .map(String::from)
        .to_vec();
    if mode == "bypass" {
        args.push("--dangerously-skip-permissions".into());
    } else {
        args.extend(["--permission-mode".into(), "auto".into()]);
    }
    if !s.model.is_empty() {
        args.extend(["--model".into(), s.model.clone()]);
    }
    Ok((args, text))
}

/// {{field}} → the parameter's value (lists comma-joined); an unknown field stays as written
pub fn fill_prompt(text: &str, params: &str) -> String {
    let p: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(params).unwrap_or_default();
    PLACEHOLDER_RE
        .replace_all(text, |c: &regex::Captures| {
            let k = &c[1];
            match p.get(k) {
                None => c[0].to_string(),
                Some(serde_json::Value::Null) => String::new(),
                Some(serde_json::Value::Array(a)) => {
                    a.iter().map(util::go_sprint).collect::<Vec<_>>().join(",")
                }
                Some(v) => util::go_sprint(v),
            }
        })
        .into_owned()
}

/// base → passed-through session values → the router's TASK_*/PARAM_* → the run's paths → the stores' values (last:
/// the router's env can't replace a secret)
pub fn task_environ(
    os_env: &[String],
    secrets: &HashMap<String, String>,
    fixed: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut m: BTreeMap<String, String> = [
        ("LANG", "C.UTF-8"),
        ("SHELL", "/bin/bash"),
        ("USER", "claude"),
        ("LOGNAME", "claude"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let pass = [
        "PATH",
        "HOME",
        "TZ",
        "JARVIS_URL",
        "SESSION_API_TOKEN",
        "SESSION_ID",
        "JARVIS2_SESSION_ID",
        "LOBSTER_CHANNEL",
        "FLY_MACHINE_ID",
    ];
    let mut router = vec![];
    for kv in os_env {
        let Some((k, v)) = kv.split_once('=') else {
            continue;
        };
        if pass.contains(&k) {
            m.insert(k.into(), v.into());
        } else if (k.starts_with("TASK_") || k.starts_with("PARAM_")) && ENV_NAME_RE.is_match(k) {
            router.push((k.to_string(), v.to_string()));
        }
    }
    if m.get("PATH").is_none_or(|p| p.is_empty()) {
        m.insert(
            "PATH".into(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        );
    }
    m.extend(router);
    m.extend(fixed.iter().map(|(k, v)| (k.clone(), v.clone())));
    for (k, v) in secrets {
        if ENV_NAME_RE.is_match(k) {
            m.insert(k.clone(), v.clone());
        }
    }
    m.into_iter().map(|(k, v)| format!("{k}={v}")).collect()
}

/// every store value of 6+ characters, longest first, as [secret NAME]
pub fn redact(text: &str, secrets: &HashMap<String, String>) -> String {
    let mut list: Vec<(&String, &String)> = secrets.iter().filter(|(_, v)| v.len() >= 6).collect();
    list.sort_by_key(|x| std::cmp::Reverse(x.1.len()));
    let mut text = text.to_string();
    for (k, v) in list {
        text = text.replace(v.as_str(), &format!("[secret {k}]"));
    }
    text
}

pub fn tail_bytes(b: &[u8], n: usize) -> &[u8] {
    if b.len() > n { &b[b.len() - n..] } else { b }
}

/// one run of the command, its output into log_path, killed (with its process group) at timeout → (code, timed out)
pub fn exec_task(
    args: &[String],
    stdin: &str,
    env: &[String],
    dir: &Path,
    log_path: &Path,
    timeout: Duration,
) -> Result<(i32, bool)> {
    let f = util::create_file(log_path, 0o600)?;
    let rest: Vec<&str> = args[1..].iter().map(String::as_str).collect();
    let mut cmd = session_command(&args[0], &rest);
    cmd.env_clear()
        .envs(env.iter().filter_map(|kv| kv.split_once('=')))
        .current_dir(dir)
        .stdout(f.try_clone()?)
        .stderr(f)
        .process_group(0);
    cmd.stdin(if stdin.is_empty() {
        std::process::Stdio::null()
    } else {
        std::process::Stdio::piped()
    });
    let mut child = cmd.spawn()?;
    if !stdin.is_empty()
        && let Some(mut w) = child.stdin.take()
    {
        let s = stdin.to_string();
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = w.write_all(s.as_bytes());
        });
    }
    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if !timed_out && start.elapsed() >= timeout {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-(child.id() as i32)),
                nix::sys::signal::Signal::SIGKILL,
            );
            timed_out = true;
        }
        util::sleep(Duration::from_millis(50));
    };
    use std::os::unix::process::ExitStatusExt;
    let code = status
        .code()
        .unwrap_or_else(|| if status.signal().is_some() { -1 } else { 0 });
    Ok((code, timed_out))
}

/// the newest TASK_KEEP_LOGS runs' files stay in ~/artifacts/task-runs (they travel in the snapshot)
pub fn prune_logs(dir: &Path) {
    let mut runs: HashMap<String, SystemTime> = HashMap::new();
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let run = name.strip_suffix(".log").unwrap_or(&name);
        let run = run.strip_suffix(".output").unwrap_or(run).to_string();
        if let Ok(t) = e.metadata().and_then(|m| m.modified()) {
            let cur = runs.entry(run).or_insert(SystemTime::UNIX_EPOCH);
            if t > *cur {
                *cur = t;
            }
        }
    }
    let mut list: Vec<(String, SystemTime)> = runs.into_iter().collect();
    list.sort_by_key(|x| std::cmp::Reverse(x.1));
    for (run, _) in list.iter().skip(TASK_KEEP_LOGS) {
        let _ = std::fs::remove_file(dir.join(format!("{run}.log")));
        let _ = std::fs::remove_file(dir.join(format!("{run}.output")));
    }
}

/// A prompt task needs a Claude login: the pair of the line's Claude account (claudelogin.rs), else the store's
/// CLAUDE_CREDENTIALS. Returns what was written, to push a refreshed pair back afterwards, and whether it is the
/// router's (then a refreshed pair goes back to it).
pub fn claude_login_for_prompt(secrets: &HashMap<String, String>) -> (Option<Vec<u8>>, bool) {
    let mut creds = None;
    let mut from_router = false;
    let got = Client::new().and_then(|c| crate::claudelogin::fetch_login(&c, 0, 0, Duration::ZERO));
    match got {
        Ok(l) if !l.credentials.is_empty() => {
            creds = Some(l.credentials.clone().into_bytes());
            from_router = true;
            let cj = paths::home().join(".claude.json");
            if !cj.exists() && !l.account.is_empty() {
                let _ = util::write_file(&cj, l.account.as_bytes(), 0o600);
            }
        }
        Ok(_) => logf!("task: Claude login: the router holds no Claude login"),
        Err(e) if crate::claudelogin::is_no_account(&e) => {}
        Err(e) => logf!("task: Claude login: {e:#}"),
    }
    if creds.is_none()
        && let Some(v) = secrets.get("CLAUDE_CREDENTIALS").filter(|v| !v.is_empty())
    {
        creds = Some(v.clone().into_bytes());
    }
    if let Some(c) = &creds {
        let p = crate::claudelogin::creds_path();
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = util::write_file(&p, c, 0o600);
    }
    (creds, from_router)
}

/// The task line's boot after the checks (prepare): run the template once for JARVIS2_TASK_RUN (none: just report
/// ready), report, and wait for the router's pause. Never returns.
pub fn run_task(
    c: &Client,
    template: &str,
    secrets: &HashMap<String, String>,
    stores: &[String],
    mode: &str,
) -> ! {
    let run = getenv("JARVIS2_TASK_RUN");
    let res = if !run.is_empty() {
        do_run(template, &run, secrets, stores, mode)
    } else {
        logf!("task {template}: no run asked for (the line's first boot): reporting ready");
        TaskResult {
            run: run.clone(),
            started_at: now(),
            finished_at: now(),
            ..Default::default()
        }
    };
    let deadline = Instant::now() + TASK_REPORT_FOR;
    loop {
        match c.json_ok("POST", "/m/task-result", Some(&res)) {
            Ok(()) => {
                logf!(
                    "task {template}: run {} reported (exit {})",
                    gojson::marshal(&run),
                    res.exit_code
                );
                break;
            }
            Err(e) if Instant::now() > deadline => {
                logf!("task {template}: the result could not be reported: {e:#}");
                break;
            }
            Err(_) => util::sleep(TASK_REPORT_WAIT),
        }
    }
    // the router pauses this machine (snapshot through the supervisor, then the core's kill)
    loop {
        std::thread::park();
    }
}

pub fn do_run(
    template: &str,
    run: &str,
    secrets: &HashMap<String, String>,
    _stores: &[String],
    mode: &str,
) -> TaskResult {
    let mut res = TaskResult {
        run: run.into(),
        started_at: now(),
        ..Default::default()
    };
    let fail = |mut res: TaskResult, msg: String| {
        res.error = msg;
        res.exit_code = -1;
        res.finished_at = now();
        res
    };
    if !TASK_TEMPLATE_RE.is_match(template) {
        return fail(
            res,
            format!("bad template name {}", gojson::marshal(template)),
        );
    }
    let dir = PathBuf::from(TASKS_ROOT).join(template);
    let (spec, timeout) = match load_task_spec(&dir) {
        Ok(x) => x,
        Err(e) => return fail(res, format!("template {template} in this image: {e:#}")),
    };
    let home = paths::home();
    let work = home.join("task-work");
    let state = home.join("workspace").join("task-state");
    let runs = home.join("artifacts").join("task-runs");
    let _ = std::fs::remove_dir_all(&work);
    for d in [&work, &state, &runs] {
        if let Err(e) = std::fs::create_dir_all(d) {
            return fail(res, e.to_string());
        }
    }
    let log_path = runs.join(format!("{run}.log"));
    let out_path = runs.join(format!("{run}.output"));
    let (args, stdin) = match task_command(&dir, &spec, mode, &getenv("TASK_PARAMS")) {
        Ok(x) => x,
        Err(e) => return fail(res, format!("{e:#}")),
    };
    let (creds, creds_from_router) = if !spec.prompt.is_empty() {
        claude_login_for_prompt(secrets)
    } else {
        (None, false)
    };
    let fixed: BTreeMap<String, String> = [
        ("TASK_DIR", dir.to_string_lossy().into_owned()),
        ("TASK_TEMPLATE", template.to_string()),
        ("TASK_RUN", run.to_string()),
        ("TASK_OUTPUT", out_path.to_string_lossy().into_owned()),
        ("TASK_STATE_DIR", state.to_string_lossy().into_owned()),
        ("TASK_WORK", work.to_string_lossy().into_owned()),
        ("TASK_TIMEOUT", timeout.as_secs().to_string()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let os_env = environ();
    let env = task_environ(&os_env, secrets, &fixed);
    logf!(
        "task {template}: run {run}: {} (timeout {}s)",
        args[..args.len().min(2)].join(" "),
        timeout.as_secs()
    );
    res.started_at = now();
    match exec_task(&args, &stdin, &env, &work, &log_path, timeout) {
        Ok((code, timed_out)) => {
            res.exit_code = code;
            res.timed_out = timed_out;
        }
        Err(e) => {
            res.exit_code = -1;
            res.error = format!("could not run: {e:#}");
        }
    }
    res.finished_at = now();
    if let Some(creds) = creds {
        // claude may have refreshed (rotated) the pair: the router keeps the newest
        if let Ok(now_creds) = std::fs::read(crate::claudelogin::creds_path())
            && now_creds != creds
            && creds_from_router
        {
            let body = serde_json::json!({"credentials": String::from_utf8_lossy(&now_creds)});
            if let Err(e) =
                Client::new().and_then(|c| c.json_ok("POST", "/m/claude-login", Some(&body)))
            {
                logf!("task: pushing the refreshed Claude login: {e:#}");
            }
        }
    }
    // redact on disk too: the logs travel in the snapshot and the archive
    let logb = std::fs::read(&log_path).unwrap_or_default();
    let logs = redact(&String::from_utf8_lossy(&logb), secrets);
    let _ = util::write_file(&log_path, logs.as_bytes(), 0o600);
    res.log = String::from_utf8_lossy(tail_bytes(logs.as_bytes(), TASK_LOG_MAX)).into_owned();
    if let Ok(f) = std::fs::File::open(&out_path) {
        let mut ob = vec![];
        let _ = f.take(TASK_OUTPUT_MAX).read_to_end(&mut ob);
        let out = redact(&String::from_utf8_lossy(&ob), secrets);
        let _ = util::write_file(&out_path, out.as_bytes(), 0o600);
        res.output = out;
    }
    prune_logs(&runs);
    res
}
