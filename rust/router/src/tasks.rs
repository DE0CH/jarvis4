//! Tasks (Jarvis 1's lib/tasks.js, DECISIONS 29 and 32-37): templates instantiated with values into INSTANCES, run on
//! a click or on a daily SCHEDULE. In Jarvis 4 an instance is a session LINE:
//!
//!   template  tasks/<name>/task.json + its files, in this repo. Baked into the session image (/opt/jarvis/tasks) and
//!             the router image (/tasks, for the forms). task.json: {title, description?, run? ("run.py" | "run.sh" |
//!             "run.js" | any executable) or prompt? ("prompt.md": claude -p), stores? [...], timeoutSeconds? (600),
//!             size? ("small"), fields: [{name, label?, type (text|textarea|number|select|multiselect|checkbox),
//!             required?, default?, options?, optionsFrom? (stores|content|sizes|models), help?, placeholder?}]}. A
//!             (multi)select with optionsFrom "stores" adds the picked store(s) to the line; with "content", the picked
//!             content store(s) (content.rs: signed in the line's config, so the task's machine may read and write them
//!             through the router).
//!   instance  {id, template, name, params, size, stores, session}: a new session whose harness is "task:<template>"
//!             (signed in the cert's options), approved ONCE on the phone like any new session.
//!   run       a resume of that line (approve_by_dead_machine: same stores, options and image, no phone) whose machine
//!             runs the template instead of a harness (rust/machine/src/task.rs), reports the result to /m/task-result,
//!             and is paused again (snapshot kept: ~/workspace/task-state survives runs).
//!   schedule  {id, instance, time "HH:MM", tz, enabled, since}: the router's own daily tick starts a run.
//!
//! No delivery and no grant is involved: the code that runs is fixed by the cert (image digest + harness), so a line
//! holding a sensitive store runs unattended too. Parameters are not secret (they travel in the machine's unsigned env
//! as TASK_PARAMS / PARAM_<FIELD>); secrets come only from the line's stores.

use crate::flows::NewSession;
use crate::http::{Registrar, write_err};
use crate::router::{Router, bad};
use crate::schedule::{next_time_of_day, number};
use crate::state::Persisted;
use crate::types::Session;
use crate::vouch::TaskConfig;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use jarvis_nethttp::{W, write_error, write_json};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::Duration;

pub const TASK_HARNESS_PREFIX: &str = "task:";
pub const TASK_KEEP_RUNS: usize = 20;
pub const TASK_MAX_QUEUED: usize = 3;
/// a slot missed by more than this (router down) is skipped
pub const TASK_SCHEDULE_GRACE_MS: i64 = 2 * 3600 * 1000;
/// a running run past its timeout + this, with no result, is stopped
pub const TASK_RESULT_GRACE_MS: i64 = 15 * 60 * 1000;
/// a started task line with no run and no result is paused after this
pub const TASK_IDLE_STARTED_MS: i64 = 15 * 60 * 1000;
/// a run whose machine isn't up by then fails (a locked store, a stuck start)
pub const TASK_START_MAX: Duration = Duration::from_secs(30 * 60);
pub const TASK_TICK_EVERY: Duration = Duration::from_secs(15);
pub const TASK_LOG_MAX: usize = 256 << 10;
pub const TASK_OUTPUT_MAX: usize = 64 << 10;

fn re(s: &str) -> regex::Regex {
    regex::Regex::new(s).unwrap_or_else(|_| unreachable!())
}

static TASK_TEMPLATE_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| re(r"^[a-z0-9][a-z0-9-]{0,39}$"));
static TASK_FIELD_RE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[a-z][a-z0-9_]{0,39}$"));
static TASK_STORE_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| re(r"^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$"));
static HHMM_RE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^(\d{1,2}):(\d{2})$"));
const TASK_TYPES: &[&str] = &[
    "text",
    "textarea",
    "number",
    "select",
    "multiselect",
    "checkbox",
];
const TASK_SOURCES: &[&str] = &["stores", "content", "sizes", "models"];
const TASK_SIZES: &[&str] = &["small", "medium", "large"];

/// the templates as the router image carries them (the session image has its own copy)
pub static TASKS_DIR: LazyLock<RwLock<String>> =
    LazyLock::new(|| RwLock::new(crate::router::env("TASKS_DIR", "/tasks")));

fn tasks_dir() -> String {
    TASKS_DIR.read().unwrap_or_else(|e| e.into_inner()).clone()
}

pub fn is_task_harness(h: &str) -> bool {
    h.starts_with(TASK_HARNESS_PREFIX)
}

/// a float as Go's encoding/json writes a float64 (5 as 5, not 5.0)
fn go_number(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 1e15 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

// ---- templates ------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TaskOption {
    pub value: String,
    pub label: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sub: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TaskField {
    pub name: String,
    pub label: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub required: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub help: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub placeholder: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<TaskOption>,
    #[serde(rename = "optionsFrom", skip_serializing_if = "String::is_empty")]
    pub options_from: String,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub default: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TaskTemplate {
    pub name: String,
    pub title: String,
    pub description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub run: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub prompt: String,
    pub stores: Vec<String>,
    #[serde(rename = "timeoutSeconds")]
    pub timeout_seconds: i64,
    pub size: String,
    pub fields: Vec<TaskField>,
    pub files: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

fn is_select(t: &str) -> bool {
    t == "select" || t == "multiselect"
}

fn parse_option(raw: &Value) -> Result<TaskOption, String> {
    if let Value::String(s) = raw {
        return Ok(TaskOption {
            value: s.clone(),
            label: s.clone(),
            sub: String::new(),
        });
    }
    let err = || "an option is a string or {value, label?, sub?}".to_string();
    let o = raw.as_object().ok_or_else(err)?;
    let v = o.get("value").filter(|v| !v.is_null()).ok_or_else(err)?;
    let s = |k: &str| match o.get(k) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(err()),
    };
    let value = jarvis_go::fmt::go_sprint(v);
    let mut label = s("label")?;
    if label.is_empty() {
        label = value.clone();
    }
    Ok(TaskOption {
        value,
        label,
        sub: s("sub")?,
    })
}

/// a task.json (+ the dir's file list) → the template, or an error for a bad spec
pub fn parse_template(name: &str, spec: &[u8], files: &[String]) -> Result<TaskTemplate, String> {
    if !TASK_TEMPLATE_RE.is_match(name) {
        return Err(format!(
            "template dir name {} must be lowercase letters/digits/dashes",
            jarvis_go::fmt::go_quote(name)
        ));
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Spec {
        title: String,
        description: String,
        run: String,
        prompt: String,
        stores: Vec<String>,
        #[serde(rename = "timeoutSeconds")]
        timeout_seconds: Option<f64>,
        size: String,
        fields: Vec<Value>,
    }
    let s: Spec = jarvis_go::unmarshal(spec).map_err(|e| format!("task.json: {e}"))?;
    let mut t = TaskTemplate {
        name: name.into(),
        title: s.title.trim().into(),
        description: s.description,
        files: files.to_vec(),
        ..Default::default()
    };
    if t.title.is_empty() {
        return Err("title is required".into());
    }
    let has = |f: &str| files.iter().any(|x| x == f);
    t.run = s.run;
    t.prompt = s.prompt;
    if t.run.is_empty() && t.prompt.is_empty() {
        if let Some(f) = ["run.py", "run.sh", "run.js"].into_iter().find(|f| has(f)) {
            t.run = f.into();
        }
        if t.run.is_empty() && has("prompt.md") {
            t.prompt = "prompt.md".into();
        }
    }
    if !t.run.is_empty() && !t.prompt.is_empty() {
        return Err("give run or prompt, not both".into());
    }
    if t.run.is_empty() && t.prompt.is_empty() {
        return Err(
            r#"no run file ("run.py", "run.sh", "run.js") and no prompt ("prompt.md")"#.into(),
        );
    }
    if !t.run.is_empty() && !has(&t.run) {
        return Err(format!(
            "run file {} is not in the template dir",
            jarvis_go::fmt::go_quote(&t.run)
        ));
    }
    if !t.prompt.is_empty() && !has(&t.prompt) {
        return Err(format!(
            "prompt file {} is not in the template dir",
            jarvis_go::fmt::go_quote(&t.prompt)
        ));
    }
    for st in s.stores {
        if !TASK_STORE_RE.is_match(&st) || st == crate::policy::FLY_STORE {
            return Err(format!("bad store name {}", jarvis_go::fmt::go_quote(&st)));
        }
        t.stores.push(st);
    }
    t.timeout_seconds = s.timeout_seconds.map_or(600, |f| f.round() as i64);
    if !(10..=6 * 3600).contains(&t.timeout_seconds) {
        return Err("timeoutSeconds must be 10–21600".into());
    }
    t.size = if s.size.is_empty() {
        "small".into()
    } else {
        s.size
    };
    if !valid_size(&t.size) {
        return Err("size must be small, medium or large".into());
    }
    let mut seen = BTreeSet::new();
    for raw in s.fields {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct F {
            name: String,
            label: String,
            #[serde(rename = "type")]
            type_: String,
            required: bool,
            help: String,
            placeholder: String,
            options: Vec<Value>,
            #[serde(rename = "optionsFrom")]
            options_from: String,
            default: Value,
            #[serde(rename = "secretKeys")]
            secret_keys: Value,
        }
        let f: F = serde_json::from_value(raw.clone()).map_err(|e| format!("a field: {e}"))?;
        if !TASK_FIELD_RE.is_match(&f.name) {
            return Err(format!(
                "field name {} must be lowercase letters/digits/_",
                jarvis_go::fmt::go_quote(&f.name)
            ));
        }
        if !seen.insert(f.name.clone()) {
            return Err(format!("field {} is defined twice", f.name));
        }
        let ty = if f.type_.is_empty() {
            "text".to_string()
        } else {
            f.type_
        };
        if !TASK_TYPES.contains(&ty.as_str()) {
            return Err(format!(
                "field {}: type must be one of text, textarea, number, select, multiselect, checkbox",
                f.name
            ));
        }
        if !f.secret_keys.is_null() {
            return Err(format!(
                "field {}: secretKeys is Jarvis 1's; in Jarvis 4 a picked store brings all its keys",
                f.name
            ));
        }
        let mut out = TaskField {
            label: if f.label.is_empty() {
                f.name.clone()
            } else {
                f.label
            },
            name: f.name.clone(),
            type_: ty.clone(),
            required: f.required,
            help: f.help,
            placeholder: f.placeholder,
            default: f.default,
            ..Default::default()
        };
        if is_select(&ty) {
            if !f.options_from.is_empty() {
                if !TASK_SOURCES.contains(&f.options_from.as_str()) {
                    return Err(format!(
                        "field {}: optionsFrom must be stores, content, sizes or models",
                        f.name
                    ));
                }
                out.options_from = f.options_from;
            } else {
                for o in &f.options {
                    out.options
                        .push(parse_option(o).map_err(|e| format!("field {}: {e}", f.name))?);
                }
                if out.options.is_empty() {
                    return Err(format!(
                        "field {}: a {ty} needs options or optionsFrom",
                        f.name
                    ));
                }
            }
        }
        t.fields.push(out);
    }
    Ok(t)
}

pub fn valid_size(s: &str) -> bool {
    TASK_SIZES.contains(&s)
}

/// every tasks/*/task.json; a broken one is listed with its error rather than dropped
pub fn read_templates(root: &Path) -> Vec<TaskTemplate> {
    let Ok(ents) = std::fs::read_dir(root) else {
        return vec![];
    };
    let mut out = vec![];
    for e in ents.flatten() {
        if !e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let dir = e.path();
        let Ok(spec) = std::fs::read(dir.join("task.json")) else {
            continue;
        }; // not a template
        let mut files: Vec<String> = std::fs::read_dir(&dir)
            .map(|fs| {
                fs.flatten()
                    .filter(|f| !f.file_type().is_ok_and(|t| t.is_dir()))
                    .map(|f| f.file_name().to_string_lossy().into_owned())
                    .filter(|n| n != "task.json")
                    .collect()
            })
            .unwrap_or_default();
        files.sort();
        match parse_template(&name, &spec, &files) {
            Err(err) => out.push(TaskTemplate {
                name: name.clone(),
                title: name,
                error: err,
                files,
                ..Default::default()
            }),
            Ok(mut t) => {
                let main = if t.run.is_empty() {
                    t.prompt.clone()
                } else {
                    t.run.clone()
                };
                if let Ok(b) = std::fs::read(dir.join(main)) {
                    t.source = String::from_utf8_lossy(&b[..b.len().min(100_000)]).into_owned();
                }
                out.push(t);
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// the option lists the router knows (sizes, models); "stores" stays empty — the app lists the stores from the core
/// itself
pub fn with_options(t: &TaskTemplate) -> TaskTemplate {
    let mut c = t.clone();
    for f in &mut c.fields {
        match f.options_from.as_str() {
            "sizes" => {
                f.options = TASK_SIZES
                    .iter()
                    .map(|s| TaskOption {
                        value: (*s).into(),
                        label: crate::sizes::size_label(s),
                        sub: String::new(),
                    })
                    .collect()
            }
            "models" => {
                f.options = crate::harness::MODEL_CATALOG
                    .iter()
                    .map(|m| TaskOption {
                        value: m.id.into(),
                        label: m.label.into(),
                        sub: m.harness.into(),
                    })
                    .collect()
            }
            "stores" | "content" => f.options = vec![], // the app lists them (the core's stores, GET /api/content)
            _ => {}
        }
    }
    c
}

pub fn template_by_name(name: &str) -> Result<TaskTemplate> {
    let t = read_templates(Path::new(&tasks_dir()))
        .into_iter()
        .find(|t| t.name == name)
        .ok_or_else(|| anyhow!("no template {} in tasks/", jarvis_go::fmt::go_quote(name)))?;
    if !t.error.is_empty() {
        return Err(anyhow!(
            "template {} is broken: {}",
            jarvis_go::fmt::go_quote(name),
            t.error
        ));
    }
    Ok(with_options(&t))
}

fn sprint(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        o => jarvis_go::fmt::go_sprint(o),
    }
}

/// the values against the fields — unknown keys dropped, defaults filled in, types coerced (numbers as numbers,
/// checkboxes as booleans, multiselects as string lists, the rest strings)
pub fn check_params(t: &TaskTemplate, input: &Map<String, Value>) -> Result<Map<String, Value>> {
    let mut out = Map::new();
    let empty = |v: &Value| v.is_null() || v.as_str() == Some("");
    let allowed = |f: &TaskField, v: &str| match f.options_from.as_str() {
        "stores" => TASK_STORE_RE.is_match(v) && v != crate::policy::FLY_STORE,
        "content" => crate::content::content_name_ok(v),
        _ => f.options.iter().any(|o| o.value == v),
    };
    let values = |f: &TaskField| {
        f.options
            .iter()
            .map(|o| o.value.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let store_field = |f: &TaskField| f.options_from == "stores" || f.options_from == "content";
    let q = jarvis_go::fmt::go_quote;
    for f in &t.fields {
        let mut v = input.get(&f.name).cloned().unwrap_or(Value::Null);
        if empty(&v) {
            v = f.default.clone();
        }
        match f.type_.as_str() {
            "checkbox" => {
                out.insert(
                    f.name.clone(),
                    json!(v == json!(true) || v == json!("true")),
                );
                continue;
            }
            "multiselect" => {
                let list: Vec<String> = match &v {
                    Value::Array(x) => x.iter().map(|e| sprint(e).trim().to_string()).collect(),
                    Value::String(x) => x.split(',').map(str::to_string).collect(),
                    _ => vec![],
                };
                let mut seen = BTreeSet::new();
                let mut clean = vec![];
                for e in list {
                    let e = e.trim().to_string();
                    if e.is_empty() || seen.contains(&e) {
                        continue;
                    }
                    if !allowed(f, &e) {
                        if store_field(f) {
                            return Err(bad(format!(
                                "“{}”: {} is not a store name",
                                f.label,
                                q(&e)
                            )));
                        }
                        return Err(bad(format!(
                            "“{}”: {} is not one of {}",
                            f.label,
                            q(&e),
                            values(f)
                        )));
                    }
                    seen.insert(e.clone());
                    clean.push(e);
                }
                if f.required && clean.is_empty() {
                    return Err(bad(format!("“{}” needs at least one choice", f.label)));
                }
                out.insert(f.name.clone(), json!(clean));
                continue;
            }
            _ => {}
        }
        if empty(&v) {
            if f.required {
                return Err(bad(format!("“{}” is required", f.label)));
            }
            out.insert(
                f.name.clone(),
                if f.type_ == "number" {
                    Value::Null
                } else {
                    json!("")
                },
            );
            continue;
        }
        match f.type_.as_str() {
            "number" => {
                let n = number(&v).ok_or_else(|| bad(format!("“{}” must be a number", f.label)))?;
                out.insert(f.name.clone(), go_number(n));
            }
            "select" => {
                let s = sprint(&v);
                if !allowed(f, &s) {
                    if store_field(f) {
                        return Err(bad(format!("“{}”: {} is not a store name", f.label, q(&s))));
                    }
                    return Err(bad(format!("“{}” must be one of {}", f.label, values(f))));
                }
                out.insert(f.name.clone(), json!(s));
            }
            _ => {
                out.insert(f.name.clone(), json!(sprint(&v)));
            }
        }
    }
    Ok(out)
}

/// the template's stores plus the ones picked in its store fields (sorted, unique)
pub fn line_stores(t: &TaskTemplate, params: &Map<String, Value>) -> Vec<String> {
    picked_in(t, params, "stores", &t.stores)
}

/// the content stores picked in its content fields (sorted, unique; empty for none)
pub fn line_content(t: &TaskTemplate, params: &Map<String, Value>) -> Vec<String> {
    picked_in(t, params, "content", &[])
}

fn picked_in(
    t: &TaskTemplate,
    params: &Map<String, Value>,
    source: &str,
    fixed: &[String],
) -> Vec<String> {
    let mut set: BTreeSet<String> = fixed.iter().cloned().collect();
    for f in t.fields.iter().filter(|f| f.options_from == source) {
        match params.get(&f.name) {
            Some(Value::String(v)) if !v.is_empty() => {
                set.insert(v.clone());
            }
            Some(Value::Array(v)) => {
                set.extend(v.iter().filter_map(Value::as_str).map(str::to_string))
            }
            _ => {}
        }
    }
    set.into_iter().collect()
}

/// a value as its PARAM_<FIELD> string
pub fn param_env(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Array(x) => x.iter().map(sprint).collect::<Vec<_>>().join(","),
        Value::Number(n) => n.as_f64().map(|f| format!("{f}")).unwrap_or_default(),
        Value::Bool(b) => b.to_string(),
        o => sprint(o),
    }
}

// ---- records ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TaskInstance {
    pub id: String,
    pub template: String,
    pub name: String,
    pub params: Map<String, Value>,
    pub size: String,
    /// the line's stores (template + picked), fixed for the line
    pub stores: Vec<String>,
    /// the content stores picked, fixed for the line (signed in its config)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub content: Vec<String>,
    /// a prompt template's Claude account (claudeaccounts.rs), fixed
    #[serde(rename = "claudeAccount", skip_serializing_if = "String::is_empty")]
    pub account: String,
    /// the line; "" once it is gone
    pub session: String,
    #[serde(rename = "createdAt")]
    pub created_at: GoTime,
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<GoTime>,
    /// the run in progress
    #[serde(skip_serializing_if = "String::is_empty")]
    pub active: String,
    /// newest first, TASK_KEEP_RUNS kept
    pub runs: Vec<TaskRun>,
    /// the machine reported: pause the line
    #[serde(rename = "pauseWanted", skip_serializing_if = "std::ops::Not::not")]
    pub pause_wanted: bool,
    /// first seen started with no run
    #[serde(rename = "startedIdle", skip_serializing_if = "Option::is_none")]
    pub started_idle: Option<GoTime>,
    /// the line's first machine reported ready
    #[serde(rename = "readyAt", skip_serializing_if = "Option::is_none")]
    pub ready_at: Option<GoTime>,
    /// the line failed or went
    #[serde(rename = "sessionError", skip_serializing_if = "String::is_empty")]
    pub session_error: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TaskRun {
    pub id: String,
    pub instance: String,
    pub template: String,
    /// manual | schedule
    pub trigger: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub schedule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<GoTime>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub upgrade: bool,
    /// queued | starting | running | succeeded | failed | timedout | stopped | lost
    pub phase: String,
    #[serde(rename = "createdAt")]
    pub created_at: GoTime,
    /// the line's resume was asked for
    #[serde(rename = "resumedAt", skip_serializing_if = "Option::is_none")]
    pub resumed_at: Option<GoTime>,
    /// the machine is up (its secrets pulled)
    #[serde(rename = "startedAt", skip_serializing_if = "Option::is_none")]
    pub started_at: Option<GoTime>,
    /// the script started (machine clock)
    #[serde(rename = "ranAt", skip_serializing_if = "Option::is_none")]
    pub ran_at: Option<GoTime>,
    /// the script ended (machine clock) or the router gave up
    #[serde(rename = "finishedAt", skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<GoTime>,
    #[serde(rename = "exitCode", skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub waiting: String,
    /// the log's last lines
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tail: String,
    #[serde(rename = "logBytes")]
    pub log_bytes: i64,
    #[serde(rename = "outputBytes")]
    pub out_bytes: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub machine: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub image: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TaskSchedule {
    pub id: String,
    pub instance: String,
    pub time: String,
    pub tz: String,
    pub enabled: bool,
    /// ms: a change never fires a slot already past
    pub since: i64,
    #[serde(rename = "createdAt")]
    pub created_at: GoTime,
    /// ms: the slot last fired (or tried)
    #[serde(rename = "lastSlot", skip_serializing_if = "is_zero")]
    pub last_slot: i64,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TaskState {
    pub instances: BTreeMap<String, TaskInstance>,
    pub schedules: BTreeMap<String, TaskSchedule>,
    /// lines of deleted instances, destroyed by the tick
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub doomed: Vec<String>,
}

pub fn tasks_of(d: &mut Persisted) -> &mut TaskState {
    d.tasks.get_or_insert_with(TaskState::default)
}

pub fn instance_by_session<'a>(d: &'a Persisted, sid: &str) -> Option<&'a TaskInstance> {
    if sid.is_empty() {
        return None;
    }
    d.tasks
        .as_ref()?
        .instances
        .values()
        .find(|i| i.session == sid)
}

fn instance_by_session_mut<'a>(d: &'a mut Persisted, sid: &str) -> Option<&'a mut TaskInstance> {
    if sid.is_empty() {
        return None;
    }
    d.tasks
        .as_mut()?
        .instances
        .values_mut()
        .find(|i| i.session == sid)
}

impl TaskInstance {
    pub fn run(&self, id: &str) -> Option<&TaskRun> {
        self.runs.iter().find(|r| r.id == id)
    }

    pub fn run_mut(&mut self, id: &str) -> Option<&mut TaskRun> {
        self.runs.iter_mut().find(|r| r.id == id)
    }

    /// the queued runs' ids, oldest first
    pub fn queued(&self) -> Vec<String> {
        self.runs
            .iter()
            .rev()
            .filter(|r| r.phase == "queued")
            .map(|r| r.id.clone())
            .collect()
    }
}

pub fn finished(phase: &str) -> bool {
    matches!(
        phase,
        "succeeded" | "failed" | "timedout" | "stopped" | "lost"
    )
}

/// a run's log and output are objects task-runs/<run>.log and .output (objstore.rs)
pub fn run_key(id: &str, ext: &str) -> String {
    format!("task-runs/{id}{ext}")
}

/// keep TASK_KEEP_RUNS runs (never an unfinished one); → the runs dropped (their files go with them)
pub(crate) fn prune_runs(i: &mut TaskInstance) -> Vec<String> {
    let mut n = 0;
    let mut gone = vec![];
    i.runs.retain(|x| {
        if !finished(&x.phase) || n < TASK_KEEP_RUNS {
            if finished(&x.phase) {
                n += 1;
            }
            return true;
        }
        gone.push(x.id.clone());
        false
    });
    gone
}

// ---- views ---------------------------------------------------------------------------------------------

pub fn run_view(x: &TaskRun, inst: Option<&TaskInstance>) -> Value {
    let mut v = match serde_json::to_value(x) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    };
    v.insert("name".into(), json!(x.id)); // Jarvis 1 calls a run by its Job name
    if let Some(i) = inst {
        v.insert("instanceName".into(), json!(i.name));
    }
    Value::Object(v)
}

/// what the card shows
fn instance_state(i: &TaskInstance, s: Option<&Session>) -> (String, String) {
    match s {
        None => ("gone".into(), i.session_error.clone()),
        Some(s) if s.state == "approval" && s.cert.is_none() => {
            ("approval".into(), "waiting for the phone".into())
        }
        Some(_) if !i.active.is_empty() => ("running".into(), String::new()),
        Some(s) if s.state == "paused" => ("ready".into(), s.error.clone()),
        Some(s) if s.state == "failed" => ("failed".into(), s.error.clone()),
        Some(s) => ("busy".into(), s.state.clone()),
    }
}

pub fn instance_view(i: &TaskInstance, d: &Persisted) -> Value {
    let s = d.sessions.get(&i.session);
    let (state, detail) = instance_state(i, s);
    let nie = crate::http::null_if_empty;
    let mut v = Map::new();
    for (k, x) in [
        ("id", json!(i.id)),
        ("template", json!(i.template)),
        ("name", json!(i.name)),
        ("params", json!(i.params)),
        ("size", json!(i.size)),
        ("claudeAccount", nie(&i.account)),
        ("stores", json!(i.stores)),
        ("content", json!(i.content)),
        ("session", nie(&i.session)),
        ("createdAt", json!(i.created_at)),
        ("updatedAt", json!(i.updated_at)),
        ("state", json!(state)),
        ("detail", json!(detail)),
        ("lastRun", Value::Null),
        ("activeRun", Value::Null),
        ("image", Value::Null),
    ] {
        v.insert(k.into(), x);
    }
    if let Some(s) = s {
        v.insert("sessionState".into(), json!(s.state));
        v.insert("image".into(), nie(&s.image));
    }
    if let Some(x) = i.runs.iter().find(|x| finished(&x.phase)) {
        v.insert("lastRun".into(), run_view(x, Some(i)));
    }
    if let Some(a) = i.run(&i.active) {
        v.insert("activeRun".into(), run_view(a, Some(i)));
    }
    v.insert("queued".into(), json!(i.queued().len()));
    let n = d.tasks.as_ref().map_or(0, |t| {
        t.schedules
            .values()
            .filter(|sc| sc.instance == i.id)
            .count()
    });
    v.insert("schedules".into(), json!(n));
    Value::Object(v)
}

pub fn schedule_view_t(s: &TaskSchedule, now: GoTime) -> Value {
    let next = if s.enabled {
        next_slot(s, now).map_or(Value::Null, |t| json!(t))
    } else {
        Value::Null
    };
    json!({"id": s.id, "instance": s.instance, "time": s.time, "tz": s.tz, "enabled": s.enabled,
        "since": s.since, "createdAt": s.created_at, "nextAt": next})
}

// ---- schedules ----------------------------------------------------------------------------------------

fn slot_parts(s: &TaskSchedule) -> Result<(i8, i8, jiff::tz::TimeZone)> {
    let bad_time = || bad("time must be HH:MM (24-hour)");
    let m = HHMM_RE.captures(s.time.trim()).ok_or_else(bad_time)?;
    let hh: i8 = m[1].parse().unwrap_or(99);
    let mm: i8 = m[2].parse().unwrap_or(99);
    if hh > 23 || mm > 59 {
        return Err(bad_time());
    }
    match jiff::tz::TimeZone::get(&s.tz) {
        Ok(tz) if !s.tz.is_empty() && s.tz != "Local" => Ok((hh, mm, tz)),
        _ => Err(bad(format!(
            "unknown time zone {}",
            jarvis_go::fmt::go_quote(&s.tz)
        ))),
    }
}

fn ms(t: GoTime) -> i64 {
    (t.unix_nanos() / 1_000_000) as i64
}

fn from_ms(m: i64) -> GoTime {
    GoTime::from_unix_nanos(m as i128 * 1_000_000)
}

/// the next slot after now (ms)
pub(crate) fn next_slot(s: &TaskSchedule, now: GoTime) -> Result<i64> {
    let (hh, mm, tz) = slot_parts(s)?;
    Ok(next_time_of_day(hh, mm, &tz, now))
}

/// the latest daily slot at or before now (ms)
fn last_slot(s: &TaskSchedule, now: GoTime) -> Option<i64> {
    let (hh, mm, tz) = slot_parts(s).ok()?;
    let now_ms = ms(now);
    let mut t = next_time_of_day(hh, mm, &tz, from_ms(now_ms - 26 * 3600 * 1000));
    if t > now_ms {
        return None;
    }
    loop {
        let n = next_time_of_day(hh, mm, &tz, from_ms(t));
        if n > now_ms {
            return Some(t);
        }
        t = n;
    }
}

/// the slot the schedule should fire for at now (ms), or None: the latest slot, after `since`, missed by no more than
/// the grace period, and not fired already
pub(crate) fn due_slot(s: &TaskSchedule, now: GoTime) -> Option<i64> {
    if !s.enabled {
        return None;
    }
    let t = last_slot(s, now)?;
    if t < s.since || ms(now) - t > TASK_SCHEDULE_GRACE_MS || t <= s.last_slot {
        return None;
    }
    Some(t)
}

// ---- lifecycle seams (tests replace them) ----------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct TaskOps {
    pub create: fn(&Arc<Router>, NewSession) -> Result<String>,
    pub resume: fn(&Arc<Router>, &str, bool) -> Result<()>,
    pub pause: fn(&Arc<Router>, &str) -> Result<()>,
    pub destroy: fn(&Arc<Router>, &str) -> Result<()>,
    pub reject: fn(&Arc<Router>, &str) -> Result<()>,
}

pub static TASK_OPS: RwLock<TaskOps> = RwLock::new(TaskOps {
    create: |r, i| r.create_session(i),
    resume: |r, id, up| r.resume(id, up),
    pause: |r, id| r.pause(id),
    destroy: |r, id| r.destroy(id),
    reject: |r, id| r.reject(id),
});

fn ops() -> TaskOps {
    *TASK_OPS.read().unwrap_or_else(|e| e.into_inner())
}

/// an API change runs a tick at once rather than within TASK_TICK_EVERY (tests turn it off)
pub static TASK_KICK: AtomicBool = AtomicBool::new(true);

fn task_kick(r: &Arc<Router>) {
    if TASK_KICK.load(Ordering::Relaxed) {
        let r = r.clone();
        std::thread::spawn(move || r.tasks_tick(GoTime::now()));
    }
}

// ---- the API -------------------------------------------------------------------------------------------

/// a task call's refusal with its status
#[derive(Debug, Clone)]
pub struct TaskErr(pub u16, pub String);

impl std::fmt::Display for TaskErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.1)
    }
}

impl std::error::Error for TaskErr {}

fn not_found(m: String) -> anyhow::Error {
    TaskErr(404, m).into()
}

fn conflict(m: String) -> anyhow::Error {
    TaskErr(409, m).into()
}

fn task_write_err(w: &mut W, err: &anyhow::Error) {
    if let Some(te) = err.downcast_ref::<TaskErr>() {
        return write_error(w, te.0, &te.1);
    }
    write_err(w, err);
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct InstanceIn {
    pub template: String,
    pub name: String,
    pub params: Option<Map<String, Value>>,
    pub size: String,
    pub hide: Vec<String>,
    #[serde(rename = "requestId")]
    pub request_id: String,
    /// a prompt template's Claude account; "" = the default
    pub account: String,
}

fn read_json<T: serde::de::DeserializeOwned + Default>(b: &[u8]) -> Result<T> {
    // Go's json.Decoder: an empty body is no error
    let mut it = serde_json::Deserializer::from_slice(b).into_iter::<Value>();
    match it.next() {
        None => Ok(T::default()),
        Some(Err(e)) => Err(bad(format!("bad JSON: {e}"))),
        Some(Ok(v)) => jarvis_go::unmarshal(jarvis_go::marshal(&v).as_bytes())
            .map_err(|e| bad(format!("bad JSON: {e}"))),
    }
}

/// what the machine reports once its run ended (rust/machine/src/task.rs); run "" = a boot with no run (the line's
/// first machine, or a run stopped before it started)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TaskResult {
    pub run: String,
    #[serde(rename = "exitCode")]
    pub exit_code: i64,
    #[serde(rename = "timedOut")]
    pub timed_out: bool,
    /// the runner itself failed (no template, …)
    pub error: String,
    #[serde(rename = "startedAt")]
    pub started_at: GoTime,
    #[serde(rename = "finishedAt")]
    pub finished_at: GoTime,
    /// tail, the store's values redacted by the machine
    pub log: String,
    /// $TASK_OUTPUT, redacted
    pub output: String,
}

/// the last 15 lines, at most 1200 characters (Jarvis 1's failure DM)
pub fn log_tail(s: &str) -> String {
    let lines: Vec<&str> = s.trim_end_matches('\n').split('\n').collect();
    let t = lines[lines.len().saturating_sub(15)..].join("\n");
    if t.len() > 1200 {
        let mut i = t.len() - 1200;
        while !t.is_char_boundary(i) {
            i += 1;
        }
        return t[i..].to_string();
    }
    t
}

/// a session's task env: the run it is for and the instance's (non-secret) parameters
pub fn task_env(r: &Arc<Router>, s: &Session, e: &mut BTreeMap<String, String>) {
    if !is_task_harness(&s.harness) {
        return;
    }
    let add = r.st.do_(|d| {
        let mut add = BTreeMap::new();
        let Some(i) = instance_by_session(d, &s.id) else {
            return add;
        };
        add.insert("TASK_INSTANCE".to_string(), i.id.clone());
        add.insert("TASK_NAME".to_string(), i.name.clone());
        add.insert("TASK_PARAMS".to_string(), jarvis_go::marshal(&i.params));
        for (k, v) in &i.params {
            add.insert(format!("PARAM_{}", k.to_uppercase()), param_env(v));
        }
        if let Some(a) = i.run(&i.active).filter(|a| a.phase == "starting") {
            add.insert("JARVIS2_TASK_RUN".to_string(), a.id.clone());
            add.insert("TASK_RUN".to_string(), a.id.clone());
            add.insert("TASK_TRIGGER".to_string(), a.trigger.clone());
        }
        add
    });
    e.extend(add);
}

#[derive(Debug, Clone)]
enum TaskAct {
    Fire {
        instance: String,
        schedule: String,
        slot: i64,
    },
    Resume {
        instance: String,
        session: String,
        run: String,
        upgrade: bool,
    },
    Pause {
        session: String,
    },
    Destroy {
        session: String,
    },
}

static TASK_TICKING: Mutex<()> = Mutex::new(());

impl Router {
    fn remove_run_files(&self, id: &str) {
        let _ = self.objects.delete(&run_key(id, ".log"));
        let _ = self.objects.delete(&run_key(id, ".output"));
    }

    /// a new instance = a new session line on harness task:<template>, approved on the phone
    pub fn create_task(self: &Arc<Self>, i: InstanceIn) -> Result<Value> {
        let name: String = i.name.trim().chars().take(80).collect();
        if name.is_empty() {
            return Err(bad("a name is required"));
        }
        if !i.hide.is_empty() {
            return Err(bad(
                "hidden values are Jarvis 1's; in Jarvis 4 secrets go in a store the task picks",
            ));
        }
        let t = template_by_name(&i.template).map_err(|e| bad(format!("{e:#}")))?;
        let params = check_params(&t, &i.params.clone().unwrap_or_default())?;
        let size = if i.size.is_empty() {
            t.size.clone()
        } else {
            i.size.clone()
        };
        if !valid_size(&size) {
            return Err(bad("size must be small, medium or large"));
        }
        // claude -p runs on a Claude account
        let account = self
            .accounts()
            .resolve(&i.account, !t.prompt.is_empty())
            .map_err(|e| bad(format!("{e:#}")))?;
        let mut inst = TaskInstance {
            id: crate::util::rand_id()[..8].to_string(),
            template: t.name.clone(),
            name,
            stores: line_stores(&t, &params),
            content: line_content(&t, &params),
            params,
            size,
            account,
            created_at: GoTime::now().utc(),
            ..Default::default()
        };
        if !i.request_id.is_empty() {
            let dup = self.st.do_(|d| {
                let ts = d.tasks.as_ref()?;
                let x = ts.instances.values().rfind(|x| {
                    !x.session.is_empty()
                        && d.sessions
                            .get(&x.session)
                            .is_some_and(|s| s.request_id == i.request_id)
                })?;
                Some(instance_view(x, d))
            });
            if let Some(v) = dup {
                return Ok(v);
            }
        }
        self.new_task_line(&mut inst, &i.request_id)?;
        let v = self.st.do_(|d| {
            tasks_of(d).instances.insert(inst.id.clone(), inst.clone());
            instance_view(&inst, d)
        });
        crate::logf!(
            "[tasks] instance {} ({}, template {}) made: session {} waits for the phone",
            inst.id,
            inst.name,
            inst.template,
            inst.session
        );
        Ok(v)
    }

    /// the instance's session line (the phone approves it as a new session)
    fn new_task_line(self: &Arc<Self>, inst: &mut TaskInstance, request_id: &str) -> Result<()> {
        let tc = TaskConfig {
            instance: inst.id.clone(),
            name: inst.name.clone(),
            params: Some(inst.params.clone()),
        };
        let sid = (ops().create)(
            self,
            NewSession {
                request_id: request_id.into(),
                label: format!("Task: {}", inst.name),
                harness: format!("{TASK_HARNESS_PREFIX}{}", inst.template),
                stores: inst.stores.clone(),
                content: inst.content.clone(),
                account: inst.account.clone(),
                needs_account: !inst.account.is_empty(),
                size: inst.size.clone(),
                auto_pause: Some(false),
                permission_mode: "bypass".into(),
                task: Some(tc),
                ..Default::default()
            },
        )?;
        inst.session = sid;
        inst.session_error.clear();
        inst.ready_at = None;
        Ok(())
    }

    /// name, params, size. New stores or content stores file a new line for the phone (as reapprove does) and keep
    /// the instance, its runs and schedules; the old line goes once the new one exists.
    pub fn update_task(self: &Arc<Self>, id: &str, i: InstanceIn) -> Result<Value> {
        if !i.hide.is_empty() {
            return Err(bad(
                "hidden values are Jarvis 1's; in Jarvis 4 secrets go in a store the task picks",
            ));
        }
        let (tmpl, cur) = self
            .st
            .do_(|d| {
                d.tasks
                    .as_ref()
                    .and_then(|t| t.instances.get(id))
                    .map(|x| (x.template.clone(), x.params.clone()))
            })
            .ok_or_else(|| not_found(format!("no such task instance: {id}")))?;
        let t = template_by_name(&tmpl).map_err(|e| bad(format!("{e:#}")))?;
        let params = check_params(&t, i.params.as_ref().unwrap_or(&cur))?;
        if !i.size.is_empty() && !valid_size(&i.size) {
            return Err(bad("size must be small, medium or large"));
        }
        let (stores, content) = (line_stores(&t, &params), line_content(&t, &params));
        let new_name = i.name.trim().to_string();
        let relined: Option<TaskInstance> = self.st.do_(|d| {
            let x = tasks_of(d)
                .instances
                .get(id)
                .ok_or_else(|| not_found(format!("no such task instance: {id}")))?;
            if content == x.content && stores == x.stores {
                return Ok(None);
            }
            if !x.active.is_empty() {
                return Err(conflict(
                    "a run is in progress: change the task's stores once it has finished".into(),
                ));
            }
            let mut c = x.clone();
            c.stores = stores.clone();
            c.content = content.clone();
            c.params = params.clone();
            if !new_name.is_empty() {
                c.name = new_name.clone();
            }
            if !i.size.is_empty() {
                c.size = i.size.clone();
            }
            Ok(Some(c))
        })?;
        let mut old = String::new();
        let relined = match relined {
            Some(mut c) => {
                old = c.session.clone();
                self.new_task_line(&mut c, "")?;
                Some(c)
            }
            None => None,
        };
        self.st.do_(|d| {
            let old_live = !old.is_empty() && d.sessions.contains_key(&old);
            let ts = tasks_of(d);
            let Some(x) = ts.instances.get_mut(id) else {
                return Err(not_found(format!("no such task instance: {id}")));
            };
            if let Some(c) = &relined {
                x.stores = c.stores.clone();
                x.content = c.content.clone();
                x.session = c.session.clone();
                x.session_error.clear();
                x.ready_at = None;
                x.pause_wanted = false;
                x.started_idle = None;
            }
            if !new_name.is_empty() {
                x.name = new_name.clone();
            }
            x.params = params.clone();
            x.updated_at = Some(GoTime::now().utc());
            let sid = x.session.clone();
            if !i.size.is_empty() {
                x.size = i.size.clone();
            }
            if relined.is_some() && old_live {
                ts.doomed.push(old.clone());
            }
            if !i.size.is_empty()
                && let Some(s) = d.sessions.get_mut(&sid)
            {
                s.size = i.size.clone(); // unsigned: the next start takes it
            }
            let x = d
                .tasks
                .as_ref()
                .and_then(|t| t.instances.get(id))
                .cloned()
                .unwrap_or_default();
            Ok(instance_view(&x, d))
        })
    }

    /// the instance, its schedules and runs go; its line is destroyed (archived like any session) by the tick, or its
    /// approval dropped
    pub fn delete_task(self: &Arc<Self>, id: &str) -> Result<()> {
        let (inst, approval) = self.st.do_(|d| {
            let s = {
                let Some(inst) = d.tasks.as_ref().and_then(|t| t.instances.get(id)) else {
                    return (None, String::new());
                };
                d.sessions.get(&inst.session).cloned()
            };
            let mut approval = String::new();
            if let Some(s) = &s
                && s.state == "approval"
                && s.cert.is_none()
            {
                approval = d
                    .approvals
                    .values()
                    .filter(|a| a.session == s.id && a.kind == "new-session")
                    .map(|a| a.id.clone())
                    .next_back()
                    .unwrap_or_default();
            }
            let ts = tasks_of(d);
            let inst = ts.instances.remove(id);
            ts.schedules.retain(|_, s| s.instance != id);
            if let Some(s) = s
                && approval.is_empty()
            {
                ts.doomed.push(s.id);
            }
            (inst, approval)
        });
        let inst = inst.ok_or_else(|| not_found(format!("no such task instance: {id}")))?;
        for x in &inst.runs {
            self.remove_run_files(&x.id);
        }
        if !approval.is_empty()
            && let Err(e) = (ops().reject)(self, &approval)
        {
            crate::logf!("[tasks] {id}: dropping its approval: {e:#}");
        }
        task_kick(self);
        Ok(())
    }

    /// a new line for an instance whose line is gone or failed (the old one, if any, is destroyed)
    pub fn reapprove(self: &Arc<Self>, id: &str) -> Result<Value> {
        self.reapprove_opt(id, false)
    }

    /// destroying: a line being destroyed is replaced too (a run asked for meanwhile)
    fn reapprove_opt(self: &Arc<Self>, id: &str, destroying: bool) -> Result<Value> {
        let (mut inst, old) = self.st.do_(|d| {
            let i = d
                .tasks
                .as_ref()
                .and_then(|t| t.instances.get(id))
                .ok_or_else(|| not_found(format!("no such task instance: {id}")))?;
            let s = d.sessions.get(&i.session);
            if !i.active.is_empty() {
                return Err(conflict("a run is in progress".into()));
            }
            if let Some(s) = s
                && s.state != "failed"
                && !(destroying && s.state == "destroying")
            {
                return Err(conflict(format!(
                    "the task's session is {}; only a gone or failed one is replaced",
                    s.state
                )));
            }
            Ok((i.clone(), s.map(|s| s.id.clone()).unwrap_or_default()))
        })?;
        self.new_task_line(&mut inst, "")?;
        Ok(self.st.do_(|d| {
            let ts = tasks_of(d);
            let found = match ts.instances.get_mut(id) {
                Some(i) => {
                    i.session = inst.session.clone();
                    i.session_error.clear();
                    i.ready_at = None;
                    i.pause_wanted = false;
                    i.started_idle = None;
                    true
                }
                None => false,
            };
            if !old.is_empty() && !destroying {
                ts.doomed.push(old.clone());
            }
            if !found {
                return Value::Null;
            }
            let x = d
                .tasks
                .as_ref()
                .and_then(|t| t.instances.get(id))
                .cloned()
                .unwrap_or_default();
            instance_view(&x, d)
        }))
    }

    /// queue a run; the tick starts it when the line is paused (now, for an idle line). A line that waits for the
    /// phone keeps the run queued until it is approved; a line that is gone or being destroyed gets its new line filed
    /// for the phone (reapprove) and the run waits for it.
    pub fn start_run(
        self: &Arc<Self>,
        id: &str,
        trigger: &str,
        schedule: &str,
        slot: Option<GoTime>,
        upgrade: bool,
    ) -> Result<TaskRun> {
        let mut run = TaskRun {
            id: format!("r{}", crate::util::rand_id()),
            instance: id.into(),
            trigger: trigger.into(),
            schedule: schedule.into(),
            slot,
            upgrade,
            phase: "queued".into(),
            created_at: GoTime::now().utc(),
            ..Default::default()
        };
        let (reline, destroying) = self.st.do_(|d| {
            let i = d
                .tasks
                .as_ref()
                .and_then(|t| t.instances.get(id))
                .ok_or_else(|| not_found(format!("no such task instance: {id}")))?;
            if i.queued().len() >= TASK_MAX_QUEUED {
                return Err(conflict(format!(
                    "{TASK_MAX_QUEUED} runs are already queued: wait for them, or stop one"
                )));
            }
            let s = d.sessions.get(&i.session);
            Ok((s.is_none_or(|s| s.state == "destroying"), s.is_some()))
        })?;
        if reline {
            self.reapprove_opt(id, destroying).map_err(|e| {
                anyhow!("the task's line is gone and a new one couldn't be filed: {e:#}")
            })?;
            crate::logf!(
                "[tasks] {id}: its line was gone: a new one waits for the phone; run {} waits for it",
                run.id
            );
        }
        run = self.st.do_(|d| {
            let i = tasks_of(d)
                .instances
                .get_mut(id)
                .ok_or_else(|| not_found(format!("no such task instance: {id}")))?;
            let mut run = run.clone();
            run.template = i.template.clone();
            i.runs.insert(0, run.clone());
            Ok::<_, anyhow::Error>(run)
        })?;
        crate::logf!("[tasks] {id}: run {} queued ({trigger})", run.id);
        task_kick(self);
        Ok(run)
    }

    /// a queued run is dropped; a starting or running one is stopped and its line paused
    pub fn stop_run(self: &Arc<Self>, run_id: &str) -> Result<()> {
        let found = self.st.do_(|d| {
            for i in tasks_of(d).instances.values_mut() {
                let active = i.active == run_id;
                let Some(x) = i.run_mut(run_id) else { continue };
                if finished(&x.phase) {
                    return true; // already over: what was asked for holds
                }
                x.phase = "stopped".into();
                x.finished_at = Some(GoTime::now().utc());
                x.reason = "stopped by Deyao".into();
                if active {
                    i.active.clear();
                    i.pause_wanted = true; // the tick pauses the line once it is up
                }
                return true;
            }
            false
        });
        if !found {
            return Err(not_found(format!("no such run: {run_id}")));
        }
        task_kick(self);
        Ok(())
    }

    fn run_detail(&self, run_id: &str) -> Result<Value> {
        let run = self
            .st
            .do_(|d| {
                let ts = d.tasks.as_ref()?;
                ts.instances
                    .values()
                    .filter_map(|i| i.run(run_id).map(|x| run_view(x, Some(i))))
                    .next_back()
            })
            .ok_or_else(|| not_found(format!("no such run: {run_id}")))?;
        let logb = self
            .obj_get_bytes(&run_key(run_id, ".log"))
            .unwrap_or_default();
        let out = self
            .obj_get_bytes(&run_key(run_id, ".output"))
            .unwrap_or_default();
        Ok(
            json!({"run": run, "log": String::from_utf8_lossy(&logb), "output": String::from_utf8_lossy(&out)}),
        )
    }

    pub(crate) fn save_schedule(&self, id: &str, b: &Map<String, Value>) -> Result<Value> {
        let now = GoTime::now();
        let new_id = crate::util::rand_id()[..8].to_string();
        self.st.do_(|d| {
            let ts = tasks_of(d);
            let mut s = if !id.is_empty() {
                ts.schedules
                    .get(id)
                    .cloned()
                    .ok_or_else(|| not_found(format!("no such schedule: {id}")))?
            } else {
                TaskSchedule {
                    id: new_id.clone(),
                    tz: "Europe/London".into(),
                    enabled: true,
                    created_at: now.utc(),
                    instance: b
                        .get("instance")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .into(),
                    ..Default::default()
                }
            };
            if !ts.instances.contains_key(&s.instance) {
                return Err(not_found(format!("no such task instance: {}", s.instance)));
            }
            if let Some(t) = b.get("time").filter(|t| !t.is_null()) {
                s.time = sprint(t);
            }
            if let Some(tz) = b
                .get("tz")
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty())
            {
                s.tz = tz.into();
            }
            if let Some(e) = b.get("enabled").and_then(Value::as_bool) {
                s.enabled = e;
            }
            let (hh, mm, _) = slot_parts(&s)?;
            s.time = format!("{hh:02}:{mm:02}");
            s.since = ms(now); // a change never fires a slot that has already passed
            ts.schedules.insert(s.id.clone(), s.clone());
            Ok(schedule_view_t(&s, now))
        })
    }

    pub fn task_result(self: &Arc<Self>, machine: &str, mut i: TaskResult) -> Result<()> {
        if i.log.len() > TASK_LOG_MAX {
            let mut k = i.log.len() - TASK_LOG_MAX;
            while !i.log.is_char_boundary(k) {
                k += 1;
            }
            i.log = i.log[k..].to_string();
        }
        if i.output.len() > TASK_OUTPUT_MAX {
            let mut k = TASK_OUTPUT_MAX;
            while !i.output.is_char_boundary(k) {
                k -= 1;
            }
            i.output.truncate(k);
        }
        let (sid, done, pruned) = self.st.do_(|d| {
            let sid = d.machines.get(machine).cloned().unwrap_or_default();
            let Some(s) = d
                .sessions
                .get(&sid)
                .filter(|s| s.machine_id == machine && is_task_harness(&s.harness))
            else {
                return Err(TaskErr(403, "this machine isn't a running task line".into()).into());
            };
            let image = s.image.clone();
            let x = instance_by_session_mut(d, &sid)
                .ok_or_else(|| not_found("no task instance for this session".into()))?;
            x.pause_wanted = true;
            let now = GoTime::now().utc();
            if x.ready_at.is_none() {
                x.ready_at = Some(now);
            }
            if i.run.is_empty() || x.active != i.run || x.run(&i.run).is_none() {
                return Ok((sid, None, vec![])); // a boot with no run, or a run stopped meanwhile: just pause
            }
            let inst_view = x.clone();
            let Some(r) = x.run_mut(&i.run) else {
                return Ok((sid, None, vec![]));
            };
            r.exit_code = Some(i.exit_code);
            r.machine = machine.into();
            r.image = image;
            if !i.started_at.is_zero() {
                r.ran_at = Some(i.started_at.utc());
            }
            r.finished_at = Some(if i.finished_at.is_zero() {
                now
            } else {
                i.finished_at.utc()
            });
            if !i.error.is_empty() {
                r.phase = "failed".into();
                r.reason = i.error.clone();
            } else if i.timed_out {
                r.phase = "timedout".into();
                r.reason = "the run went past the template's timeout".into();
            } else if i.exit_code != 0 {
                r.phase = "failed".into();
                r.reason = format!("exit code {}", i.exit_code);
            } else {
                r.phase = "succeeded".into();
            }
            r.tail = log_tail(&i.log);
            r.log_bytes = i.log.len() as i64;
            r.out_bytes = i.output.len() as i64;
            let done = r.clone();
            x.active.clear();
            let pruned = prune_runs(x);
            Ok::<_, anyhow::Error>((sid, Some((inst_view, done)), pruned))
        })?;
        for p in pruned {
            self.remove_run_files(&p);
        }
        if let Some((inst, done)) = done {
            if let Err(e) = self.obj_put_bytes(&run_key(&done.id, ".log"), i.log.as_bytes()) {
                crate::logf!("[tasks] run {}: its log: {e:#}", done.id);
            }
            if !i.output.is_empty()
                && let Err(e) =
                    self.obj_put_bytes(&run_key(&done.id, ".output"), i.output.as_bytes())
            {
                crate::logf!("[tasks] run {}: its output: {e:#}", done.id);
            }
            crate::logf!("[tasks] {}: run {} {}", inst.id, done.id, done.phase);
            self.notify_run(&inst, &done);
        }
        let r = self.clone();
        std::thread::spawn(move || {
            if let Err(e) = (ops().pause)(&r, &sid) {
                crate::logf!("[tasks] {sid}: pause after the run: {e:#} (the tick retries)");
            }
        });
        Ok(())
    }

    /// Jarvis 1's DM for a scheduled run that failed
    fn notify_run(&self, i: &TaskInstance, x: &TaskRun) {
        if x.trigger != "schedule" || x.phase == "succeeded" || x.phase == "stopped" {
            return;
        }
        let what = match x.phase.as_str() {
            "failed" => "failed",
            "timedout" => "timed out",
            "lost" => "was lost",
            p => p,
        };
        let sched = self.st.do_(|d| {
            d.tasks
                .as_ref()
                .and_then(|t| t.schedules.get(&x.schedule))
                .map(|s| format!(" (daily {} {})", s.time, s.tz))
                .unwrap_or_default()
        });
        let mut msg = format!("Scheduled task “{}”{sched} {what}", i.name);
        if !x.reason.is_empty() {
            msg = format!("{msg} — {}", x.reason);
        }
        msg.push('.');
        if !x.tail.is_empty() {
            msg = format!("{msg}\n```\n{}\n```", x.tail.replace("```", "'''"));
        }
        self.dm(&msg);
    }

    // ---- the tick ----------------------------------------------------------------------------------------------

    pub fn tasks_loop(self: &Arc<Self>) {
        loop {
            std::thread::sleep(TASK_TICK_EVERY);
            crate::leaderlease::await_lead();
            self.tasks_tick(GoTime::now());
        }
    }

    /// schedules fire, runs advance with their line's state, queued runs start, finished lines pause, deleted
    /// instances' lines go. Decisions under the state lock, actions outside it.
    pub fn tasks_tick(self: &Arc<Self>, now: GoTime) {
        let Ok(_g) = TASK_TICKING.try_lock() else {
            return;
        };
        let now_ms = ms(now);
        // the lines' busy marks and the templates' timeouts, read before the state's lock (a re-run of the closure
        // reads them again neither from the database nor the disk)
        let (sids, templates) = self.st.do_(|d| {
            let t = d.tasks.as_ref();
            let mut sids: BTreeSet<String> = t
                .map(|t| t.doomed.iter().cloned().collect())
                .unwrap_or_default();
            let mut templates = BTreeSet::new();
            for i in t.into_iter().flat_map(|t| t.instances.values()) {
                sids.insert(i.session.clone());
                templates.insert(i.template.clone());
            }
            (sids, templates)
        });
        let busy: BTreeSet<String> = sids
            .into_iter()
            .filter(|s| !s.is_empty() && self.busy(s))
            .collect();
        let timeouts: BTreeMap<String, i64> = templates
            .into_iter()
            .map(|t| {
                (
                    t.clone(),
                    template_by_name(&t).map_or(600, |x| x.timeout_seconds),
                )
            })
            .collect();
        let (acts, ended) = self.st.do_(|d| {
            let mut acts = vec![];
            let mut ended: Vec<(TaskInstance, TaskRun)> = vec![];
            let sessions = &mut d.sessions;
            let ts = d.tasks.get_or_insert_with(TaskState::default);
            for s in ts.schedules.values_mut() {
                if let Some(slot) = due_slot(s, now) {
                    s.last_slot = slot;
                    acts.push(TaskAct::Fire { instance: s.instance.clone(), schedule: s.id.clone(), slot });
                }
            }
            ts.doomed.retain(|sid| {
                let Some(s) = sessions.get(sid) else { return false };
                if s.state != "destroying" && !busy.contains(sid) {
                    acts.push(TaskAct::Destroy { session: sid.clone() });
                }
                true
            });
            let finish = |i: &mut TaskInstance, run: &str, phase: &str, reason: &str, ended: &mut Vec<(TaskInstance, TaskRun)>| {
                let Some(x) = i.run_mut(run) else { return };
                x.phase = phase.into();
                x.reason = reason.into();
                x.finished_at = Some(now.utc());
                x.waiting.clear();
                let x = x.clone();
                if i.active == x.id {
                    i.active.clear();
                }
                ended.push((i.clone(), x));
            };
            for i in ts.instances.values_mut() {
                let Some(s) = sessions.get_mut(&i.session) else {
                    if !i.session.is_empty() {
                        i.session_error = "the task's session is gone".into();
                        i.session.clear();
                    }
                    let open: Vec<String> = i.runs.iter().filter(|x| !finished(&x.phase)).map(|x| x.id.clone()).collect();
                    for r in open {
                        finish(i, &r, "failed", "the task's session is gone", &mut ended);
                    }
                    continue;
                };
                let busy = busy.contains(&s.id);
                if let Some(a) = i.run(&i.active).cloned() {
                    match a.phase.as_str() {
                        "starting" => match s.state.as_str() {
                            "started" => {
                                if let Some(x) = i.run_mut(&a.id) {
                                    x.phase = "running".into();
                                    x.started_at = Some(now.utc());
                                    x.waiting.clear();
                                }
                            }
                            "paused" | "failed" => {
                                if !busy {
                                    let reason = if s.error.is_empty() { "the start was rejected" } else { &s.error };
                                    finish(i, &a.id, "failed", &format!("the session didn't start: {reason}"), &mut ended);
                                }
                            }
                            "approval" => {
                                if let Some(x) = i.run_mut(&a.id) {
                                    x.waiting = "waiting for the phone to approve the newer session image".into();
                                }
                            }
                            st => {
                                let waiting = if st == "initialising" {
                                    "the machine waits for its secrets (a locked store needs unlocking on the phone)".to_string()
                                } else {
                                    st.to_string()
                                };
                                if let Some(x) = i.run_mut(&a.id) {
                                    x.waiting = waiting.clone();
                                }
                                if a.resumed_at.is_some_and(|t| now.sub(&t) > TASK_START_MAX) {
                                    finish(
                                        i,
                                        &a.id,
                                        "failed",
                                        &format!("the machine wasn't up after {} ({waiting})", jarvis_go::fmt::duration_string(TASK_START_MAX)),
                                        &mut ended,
                                    );
                                    i.pause_wanted = true;
                                }
                            }
                        },
                        "running" => {
                            let timeout = timeouts.get(&i.template).copied().unwrap_or(600);
                            if s.state == "paused" || s.state == "failed" {
                                if !busy {
                                    finish(
                                        i,
                                        &a.id,
                                        "lost",
                                        "the session stopped before the run reported (a pause, the budget cap or a crash)",
                                        &mut ended,
                                    );
                                }
                            } else if a.started_at.is_some_and(|t| now_ms - ms(t) > timeout * 1000 + TASK_RESULT_GRACE_MS) {
                                finish(i, &a.id, "timedout", "no result from the machine", &mut ended);
                                i.pause_wanted = true;
                            }
                        }
                        _ => i.active.clear(), // a finished run left as active
                    }
                }
                if !i.active.is_empty() {
                    continue;
                }
                if (s.state == "started" || s.state == "initialising") && !s.machine_id.is_empty() {
                    let since = *i.started_idle.get_or_insert(now.utc());
                    if !busy && (i.pause_wanted || now_ms - ms(since) > TASK_IDLE_STARTED_MS) {
                        acts.push(TaskAct::Pause { session: s.id.clone() });
                    }
                    continue;
                }
                if s.state == "paused" || (s.state == "failed" && s.machine_id.is_empty() && s.cert.is_some()) {
                    i.pause_wanted = false;
                    i.started_idle = None;
                } else {
                    continue;
                }
                let q = i.queued();
                let Some(first) = q.first().filter(|_| !busy) else { continue };
                if s.state == "failed" {
                    s.state = "paused".into(); // a failed start left no machine: the line is still there to resume
                }
                let mut upgrade = false;
                if let Some(x) = i.run_mut(first) {
                    x.phase = "starting".into();
                    x.waiting.clear();
                    x.resumed_at = Some(now.utc());
                    upgrade = x.upgrade;
                }
                i.active = first.clone();
                acts.push(TaskAct::Resume { instance: i.id.clone(), session: s.id.clone(), run: first.clone(), upgrade });
            }
            (acts, ended)
        });
        for (inst, run) in &ended {
            crate::logf!(
                "[tasks] {}: run {} {}: {}",
                inst.id,
                run.id,
                run.phase,
                run.reason
            );
            self.notify_run(inst, run);
        }
        for a in acts {
            self.task_act(a);
        }
        let pruned = self.st.do_(|d| {
            tasks_of(d)
                .instances
                .values_mut()
                .flat_map(prune_runs)
                .collect::<Vec<_>>()
        });
        for p in pruned {
            self.remove_run_files(&p);
        }
    }

    fn task_act(self: &Arc<Self>, a: TaskAct) {
        match a {
            TaskAct::Fire {
                instance,
                schedule,
                slot,
            } => {
                if let Err(e) = self.start_run(
                    &instance,
                    "schedule",
                    &schedule,
                    Some(from_ms(slot).utc()),
                    false,
                ) {
                    let name = self
                        .st
                        .do_(|d| {
                            d.tasks
                                .as_ref()
                                .and_then(|t| t.instances.get(&instance))
                                .map(|i| i.name.clone())
                        })
                        .unwrap_or_else(|| instance.clone());
                    crate::logf!("[tasks] schedule {schedule} could not start: {e:#}");
                    self.dm(&format!("Scheduled task “{name}” could not start: {e:#}"));
                }
            }
            TaskAct::Resume {
                instance,
                session,
                run,
                upgrade,
            } => {
                let err = match (ops().resume)(self, &session, upgrade) {
                    Ok(()) => {
                        crate::logf!("[tasks] {instance}: run {run} starting (session {session})");
                        return;
                    }
                    Err(e) => e,
                };
                let busy = err.downcast_ref::<crate::router::Busy>().is_some();
                let msg = format!("{err:#}");
                let ended = self.st.do_(|d| {
                    let i = tasks_of(d).instances.get_mut(&instance)?;
                    if i.active != run || i.run(&run).is_none() {
                        return None;
                    }
                    i.active.clear();
                    let x = i.run_mut(&run)?;
                    if busy {
                        x.phase = "queued".into(); // another action holds the line: the next tick tries again
                        return None;
                    }
                    x.phase = "failed".into();
                    x.reason = format!("resume: {msg}");
                    x.finished_at = Some(GoTime::now().utc());
                    let x = x.clone();
                    Some((i.clone(), x))
                });
                if let Some((inst, x)) = ended {
                    self.notify_run(&inst, &x);
                }
            }
            TaskAct::Pause { session } => {
                if let Err(e) = (ops().pause)(self, &session)
                    && e.downcast_ref::<crate::router::Busy>().is_none()
                {
                    crate::logf!("[tasks] {session}: pause: {e:#}");
                }
            }
            TaskAct::Destroy { session } => {
                if let Err(e) = (ops().destroy)(self, &session)
                    && e.downcast_ref::<crate::router::Busy>().is_none()
                {
                    crate::logf!("[tasks] destroying {session}: {e:#}");
                }
            }
        }
    }
}

// ---- routes --------------------------------------------------------------------------------------------------

pub fn register_tasks(reg: &mut Registrar) {
    reg.app("GET /api/tasks", |r, w, _| {
        let templates: Vec<TaskTemplate> = read_templates(Path::new(&tasks_dir())).iter().map(with_options).collect();
        let now = GoTime::now();
        let (instances, schedules) = r.st.do_(|d| {
            let Some(ts) = d.tasks.as_ref() else { return (vec![], vec![]) };
            let mut is: Vec<&TaskInstance> = ts.instances.values().collect();
            is.sort_by_key(|i| i.created_at);
            let mut ss: Vec<&TaskSchedule> = ts.schedules.values().collect();
            ss.sort_by_key(|s| s.created_at);
            (
                is.into_iter().map(|i| instance_view(i, d)).collect::<Vec<_>>(),
                ss.into_iter().map(|s| schedule_view_t(s, now)).collect::<Vec<_>>(),
            )
        });
        write_json(
            w,
            200,
            &json!({"sessionImage": r.cfg.session_image, "templates": templates, "instances": instances, "schedules": schedules}),
        );
    });
    reg.app("POST /api/tasks/instances", |r, w, req| {
        let b = req.read_body(1 << 20);
        match read_json::<InstanceIn>(&b).and_then(|i| r.create_task(i)) {
            Err(e) => task_write_err(w, &e),
            Ok(v) => write_json(w, 200, &v),
        }
    });
    reg.app("PUT /api/tasks/instances/{id}", |r, w, req| {
        let b = req.read_body(1 << 20);
        match read_json::<InstanceIn>(&b).and_then(|i| r.update_task(&req.path_value("id"), i)) {
            Err(e) => task_write_err(w, &e),
            Ok(v) => write_json(w, 200, &v),
        }
    });
    reg.app("DELETE /api/tasks/instances/{id}", |r, w, req| {
        match r.delete_task(&req.path_value("id")) {
            Err(e) => task_write_err(w, &e),
            Ok(()) => write_json(w, 200, &json!({"ok": true})),
        }
    });
    reg.app(
        "POST /api/tasks/instances/{id}/approve",
        |r, w, req| match r.reapprove(&req.path_value("id")) {
            Err(e) => task_write_err(w, &e),
            Ok(v) => write_json(w, 200, &v),
        },
    );
    reg.app("POST /api/tasks/instances/{id}/run", |r, w, req| {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            upgrade: bool,
        }
        let b = req.read_body(1 << 20);
        let res = read_json::<In>(&b)
            .and_then(|i| r.start_run(&req.path_value("id"), "manual", "", None, i.upgrade));
        match res {
            Err(e) => task_write_err(w, &e),
            Ok(run) => write_json(
                w,
                200,
                &json!({"name": run.id, "run": run_view(&run, None)}),
            ),
        }
    });
    reg.app("GET /api/tasks/instances/{id}/runs", |r, w, req| {
        let id = req.path_value("id");
        let runs = r.st.do_(|d| {
            let i = d.tasks.as_ref()?.instances.get(&id)?;
            Some(
                i.runs
                    .iter()
                    .map(|x| run_view(x, Some(i)))
                    .collect::<Vec<_>>(),
            )
        });
        match runs {
            None => task_write_err(w, &not_found(format!("no such task instance: {id}"))),
            Some(runs) => write_json(w, 200, &json!({"runs": runs})),
        }
    });
    reg.app("GET /api/tasks/runs/{id}", |r, w, req| {
        match r.run_detail(&req.path_value("id")) {
            Err(e) => task_write_err(w, &e),
            Ok(v) => write_json(w, 200, &v),
        }
    });
    reg.app("POST /api/tasks/runs/{id}/stop", |r, w, req| {
        match r.stop_run(&req.path_value("id")) {
            Err(e) => task_write_err(w, &e),
            Ok(()) => write_json(w, 200, &json!({"ok": true})),
        }
    });
    reg.app("POST /api/tasks/schedules", |r, w, req| {
        let b = req.read_body(1 << 20);
        let res = read_json::<Map<String, Value>>(&b).and_then(|m| {
            if !m.contains_key("time") {
                return Err(bad("time must be HH:MM (24-hour)"));
            }
            r.save_schedule("", &m)
        });
        match res {
            Err(e) => task_write_err(w, &e),
            Ok(v) => write_json(w, 200, &v),
        }
    });
    reg.app("PUT /api/tasks/schedules/{id}", |r, w, req| {
        let b = req.read_body(1 << 20);
        match read_json::<Map<String, Value>>(&b)
            .and_then(|m| r.save_schedule(&req.path_value("id"), &m))
        {
            Err(e) => task_write_err(w, &e),
            Ok(v) => write_json(w, 200, &v),
        }
    });
    reg.app("DELETE /api/tasks/schedules/{id}", |r, w, req| {
        let id = req.path_value("id");
        let found = r.st.do_(|d| tasks_of(d).schedules.remove(&id).is_some());
        if !found {
            return task_write_err(w, &not_found(format!("no such schedule: {id}")));
        }
        write_json(w, 200, &json!({"ok": true}));
    });
    reg.m("POST /m/task-result", |r, w, _, machine, body| {
        let Ok(i) = jarvis_go::unmarshal::<TaskResult>(body) else {
            return write_error(w, 400, "bad JSON");
        };
        match r.task_result(machine, i) {
            Err(e) => task_write_err(w, &e),
            Ok(()) => write_json(w, 200, &json!({"ok": true})),
        }
    });
}
