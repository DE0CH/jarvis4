//! The worker count: a component of the supervisor. It knows how many subagents and background jobs the session's
//! Claude Code harness has running now, for the session's card (router/registry.go Workers); the status report carries
//! it.
//!
//! Claude Code documents no live list of its tasks, so the count comes from its documented hooks: boot installs
//! `jarvis-machine workers-hook` in ~/.claude/settings.json for SessionStart, SubagentStart, SubagentStop, Stop and
//! PostToolUse (Bash|Monitor|Agent). The hook only NOTIFIES the supervisor: ids, types and the event name (never a
//! command, a description or a tool's output) over the supervisor's local socket; it never fails a turn. The supervisor
//! holds the count per conversation, in memory and in workers.json (tmpfs, kept across a restart):
//!   - Stop and SubagentStop carry `background_tasks`, the harness's own list of what is in flight: each one replaces the
//!     conversation's list. A SubagentStop's list still names the agent that is stopping, so that one is left out.
//!   - between two of those, SubagentStart adds the agent, and a PostToolUse whose result has a backgroundTaskId adds
//!     that job until the next list.
//!   - SessionStart (startup, resume) empties it: a restarted host has nothing running.

use crate::{gojson, logf, paths, re, util};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

pub const WORKERS_HOOK_CMD: &str = "/usr/local/bin/jarvis-machine workers-hook";

/// the hook events the count needs (with PostToolUse's matcher)
const WORKER_HOOK_EVENTS: &[(&str, &str)] = &[
    ("SessionStart", ""),
    ("SubagentStart", ""),
    ("SubagentStop", ""),
    ("Stop", ""),
    ("PostToolUse", "Bash|Monitor|Agent"),
];

/// one conversation's count; subagents and jobs are what the router reads
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkerFile {
    #[serde(rename = "workersOf")]
    pub session_id: String,
    /// ms, the last change
    pub at: i64,
    pub subagents: i64,
    /// every other in-flight task by the harness's type label
    pub jobs: BTreeMap<String, i64>,
    /// id → type, from the last background_tasks
    pub listed: BTreeMap<String, String>,
    /// id → type, seen since it ("subagent-fg" until known as background)
    pub added: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct HookTask {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub status: String,
}

/// the notification the hook sends the supervisor (ids, types and names only)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkerEvent {
    #[serde(rename = "session")]
    pub session_id: String,
    pub event: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(rename = "agentId", skip_serializing_if = "String::is_empty")]
    pub agent_id: String,
    #[serde(rename = "agentType", skip_serializing_if = "String::is_empty")]
    pub agent_type: String,
    #[serde(rename = "tool", skip_serializing_if = "String::is_empty")]
    pub tool_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tasks: Option<Vec<HookTask>>,
    /// PostToolUse: the tool result's isAsync
    #[serde(rename = "isAsync", skip_serializing_if = "std::ops::Not::not")]
    pub is_async: bool,
    /// PostToolUse: the tool result's agentId
    #[serde(rename = "rAgentId", skip_serializing_if = "String::is_empty")]
    pub r_agent_id: String,
    /// PostToolUse: the tool result's backgroundTaskId
    #[serde(rename = "taskId", skip_serializing_if = "String::is_empty")]
    pub task_id: String,
}

re!(SAFE_ID = r"^[A-Za-z0-9_.-]{1,100}$");

/// the hook's stdin boiled down to the notification (None: nothing to tell)
pub fn worker_event_of(raw: &[u8]) -> Option<WorkerEvent> {
    let v: serde_json::Value = serde_json::from_slice(raw).ok()?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let sid = s("session_id");
    if !SAFE_ID.is_match(&sid) {
        return None;
    }
    let tasks = match v.get("background_tasks") {
        None | Some(serde_json::Value::Null) => None,
        Some(t) => Some(gojson::unmarshal::<Vec<HookTask>>(t.to_string().as_bytes()).ok()?),
    };
    let mut ev = WorkerEvent {
        session_id: sid,
        event: s("hook_event_name"),
        source: s("source"),
        agent_id: s("agent_id"),
        agent_type: s("agent_type"),
        tool_name: s("tool_name"),
        tasks,
        ..Default::default()
    };
    if ev.event == "PostToolUse" {
        let r = v.get("tool_response")?;
        if !r.is_object() && !r.is_null() {
            return None; // Go refused a result that isn't an object
        }
        ev.is_async = r.get("isAsync").and_then(|x| x.as_bool()).unwrap_or(false);
        ev.r_agent_id = r
            .get("agentId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        ev.task_id = r
            .get("backgroundTaskId")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
    }
    Some(ev)
}

/// the hook command (stdin = the event's JSON): the notification to the supervisor. Always exits 0 with no output.
pub fn workers_hook() {
    let mut b = vec![];
    if std::io::stdin().take(4 << 20).read_to_end(&mut b).is_err() {
        return;
    }
    let Some(ev) = worker_event_of(&b) else {
        return;
    };
    let Ok(mut conn) = std::os::unix::net::UnixStream::connect(paths::workers_sock()) else {
        return;
    };
    let _ = conn.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = conn.set_write_timeout(Some(Duration::from_secs(2)));
    let _ = conn.write_all(format!("{}\n", gojson::marshal(&ev)).as_bytes());
    let mut sink = [0u8; 16];
    let _ = conn.read(&mut sink); // the supervisor closes once it has applied it
}

/// the supervisor's count, per conversation
#[derive(Default)]
pub struct WorkerCount {
    files: BTreeMap<String, WorkerFile>,
    /// where it is kept across a worker restart (None = memory only)
    path: Option<PathBuf>,
}

static WORKERS: LazyLock<Mutex<WorkerCount>> = LazyLock::new(|| Mutex::new(WorkerCount::default()));

fn lock() -> std::sync::MutexGuard<'static, WorkerCount> {
    WORKERS.lock().unwrap_or_else(|e| e.into_inner())
}

/// the supervisor's worker count, kept at path (supervisor-normal starts it)
pub fn set_worker_count(path: &Path) {
    let files = std::fs::read(path)
        .ok()
        .and_then(|b| gojson::unmarshal(&b).ok())
        .unwrap_or_default();
    *lock() = WorkerCount {
        files,
        path: Some(path.to_path_buf()),
    };
}

/// the socket the hook notifies (started by supervisor-normal)
pub fn serve_worker_count() {
    let p = paths::workers_sock();
    let _ = std::fs::remove_file(&p);
    let ln = match std::os::unix::net::UnixListener::bind(&p) {
        Ok(l) => l,
        Err(e) => {
            logf!("worker count: {e}");
            return;
        }
    };
    let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    loop {
        match ln.accept() {
            Ok((conn, _)) => {
                std::thread::spawn(move || {
                    let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
                    if let Ok(ev) =
                        crate::secrets::read_one::<WorkerEvent, _>((&conn).take(1 << 20))
                    {
                        apply(&ev, util::unix_now() * 1000);
                    }
                });
            }
            Err(_) => util::sleep(Duration::from_secs(1)),
        }
    }
}

/// one notification (now_ms: the time, ms)
pub fn apply(ev: &WorkerEvent, now_ms: i64) {
    lock().apply(ev, now_ms);
}

impl WorkerCount {
    pub fn apply(&mut self, ev: &WorkerEvent, now_ms: i64) {
        if !SAFE_ID.is_match(&ev.session_id) {
            return;
        }
        let mut f = self.files.get(&ev.session_id).cloned().unwrap_or_default();
        match ev.event.as_str() {
            "SessionStart" => {
                if ev.source != "startup" && ev.source != "resume" {
                    return;
                }
                f.listed.clear();
                f.added.clear();
            }
            "SubagentStart" => {
                if ev.agent_type.is_empty() || !SAFE_ID.is_match(&ev.agent_id) {
                    return; // the harness's own internal agents
                }
                if !f.listed.contains_key(&ev.agent_id) {
                    f.added.insert(ev.agent_id.clone(), "subagent-fg".into());
                }
            }
            "PostToolUse" => {
                if ev.tool_name == "Agent"
                    && ev.is_async
                    && f.added.get(&ev.r_agent_id).map(String::as_str) == Some("subagent-fg")
                {
                    f.added.insert(ev.r_agent_id.clone(), "subagent".into()); // a background one: the next list says when it ends
                } else if !ev.task_id.is_empty() && SAFE_ID.is_match(&ev.task_id) {
                    if !f.listed.contains_key(&ev.task_id) {
                        let ty = match ev.tool_name.as_str() {
                            "Bash" => "shell",
                            "Monitor" => "monitor",
                            _ => "other",
                        };
                        f.added.insert(ev.task_id.clone(), ty.into());
                    }
                } else {
                    return;
                }
            }
            "SubagentStop" | "Stop" => {
                if ev.event == "SubagentStop" {
                    f.added.remove(&ev.agent_id);
                }
                if let Some(tasks) = &ev.tasks {
                    f.listed.clear();
                    for t in tasks {
                        if t.id.is_empty()
                            || t.id == ev.agent_id
                            || (!t.status.is_empty()
                                && t.status != "running"
                                && t.status != "pending")
                        {
                            continue;
                        }
                        f.listed.insert(t.id.clone(), t.type_.clone());
                    }
                    let listed = f.listed.clone();
                    // background ones the list no longer names have ended, and at the turn's end no foreground
                    // subagent is left
                    f.added.retain(|id, ty| {
                        !(listed.contains_key(id) || ty != "subagent-fg" || ev.event == "Stop")
                    });
                }
                // no list: no registry reachable, keep what we had
            }
            _ => return,
        }
        f.session_id = ev.session_id.clone();
        f.at = now_ms;
        f.subagents = 0;
        f.jobs = BTreeMap::new();
        let mut all = f.listed.clone();
        all.extend(f.added.iter().map(|(k, v)| (k.clone(), v.clone())));
        for ty in all.values() {
            match ty.as_str() {
                "subagent" | "subagent-fg" => f.subagents += 1,
                "" => *f.jobs.entry("other".into()).or_default() += 1,
                t => *f.jobs.entry(t.into()).or_default() += 1,
            }
        }
        self.files.insert(ev.session_id.clone(), f);
        if let Some(p) = &self.path {
            let tmp = PathBuf::from(format!("{}.tmp", p.display()));
            if util::write_file(&tmp, gojson::marshal(&self.files).as_bytes(), 0o600).is_ok() {
                let _ = std::fs::rename(&tmp, p);
            }
        }
    }

    /// the status report's __WORKERS__ section, one JSON object per conversation (router/registry.go)
    pub fn report(&self) -> String {
        self.files
            .values()
            .map(|f| format!("{}\n", gojson::marshal(f)))
            .collect()
    }
}

/// one conversation's count (None when it has none)
pub fn get(sid: &str) -> Option<WorkerFile> {
    lock().files.get(sid).cloned()
}

pub fn report() -> String {
    lock().report()
}

/// the hook entries in ~/.claude/settings.json (boot, before the harness starts), replacing any earlier copy of ours and
/// keeping everything else in the file
pub fn install_worker_hooks(home: &Path) -> Result<()> {
    use serde_json::{Map, Value, json};
    let p = home.join(".claude").join("settings.json");
    let mut s: Map<String, Value> = Map::new();
    if let Ok(b) = std::fs::read(&p)
        && !b.is_empty()
    {
        s = serde_json::from_slice(&b)?; // never overwrite a file we can't read
    }
    let mut hooks = s
        .get("hooks")
        .and_then(|h| h.as_object())
        .cloned()
        .unwrap_or_default();
    for (event, matcher) in WORKER_HOOK_EVENTS {
        let mut keep: Vec<Value> = hooks
            .get(*event)
            .and_then(|g| g.as_array())
            .map(|gs| {
                gs.iter()
                    .filter(|g| !is_workers_group(g))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let mut g =
            json!({"hooks": [{"type": "command", "command": WORKERS_HOOK_CMD, "timeout": 10}]});
        if !matcher.is_empty()
            && let Some(o) = g.as_object_mut()
        {
            o.insert("matcher".into(), (*matcher).into());
        }
        keep.push(g);
        hooks.insert((*event).into(), Value::Array(keep));
    }
    s.insert("hooks".into(), Value::Object(hooks));
    let b = serde_json::to_string_pretty(&s)?;
    let b = b
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    util::write_file(&p, b.as_bytes(), 0o600)?;
    Ok(())
}

fn is_workers_group(g: &serde_json::Value) -> bool {
    g.get("hooks").and_then(|h| h.as_array()).is_some_and(|hs| {
        hs.iter()
            .any(|h| h.get("command").and_then(|c| c.as_str()) == Some(WORKERS_HOOK_CMD))
    })
}
