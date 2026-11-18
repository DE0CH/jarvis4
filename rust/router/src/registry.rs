//! A session's live status, reported by its own machine (Jarvis 1 read it by Fly exec: readRegistry in server.js,
//! lib/stall.js normalize, lib/claudelogin.js parse, lib/downgrade.js parse). The machine runs the registry command
//! (rust/machine/src/status.rs) every ~10 s and POSTs the raw text to /m/status when it changes and at least once a
//! minute; the router parses it here. Nothing in it is a secret: claude's registry files, ai-title lines,
//! background-job counts, the one-shot marker, the ids of transcripts ending on "Please run /login", the credentials
//! file's expiry time, the transcripts' refusal entries and the subagent/background-job counts.

use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::sync::LazyLock;

fn re(s: &str) -> regex::Regex {
    regex::Regex::new(s).unwrap_or_else(|_| unreachable!())
}

static TRANSCRIPT_ID: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?i)^[0-9a-f-]{8,}$"));
static WORKER_TYPE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[a-z][a-z _-]{0,30}$"));
static SAFEGUARD_MODEL: LazyLock<regex::Regex> =
    LazyLock::new(|| re(r"(?:^|:[\t\n\x0C\r ]*)([^:\n]{1,60}?)'s safeguards flagged"));
static ONE_SHOT_DONE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"(?m)^done\b"));

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// a safeguard refusal or a refusal fallback found in a transcript (lib/downgrade.js)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Refusal {
    /// fallback | refusal
    pub kind: String,
    /// ms
    pub at: i64,
    pub uuid: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub from: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub to: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub model: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub category: String,
}

/// what the host conversation's harness has running besides itself (rust/machine/src/workers.rs, from Claude Code's
/// hooks): subagents (foreground and background) and every other background job by Claude Code's own type label
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Workers {
    pub subagents: i64,
    pub jobs: BTreeMap<String, i64>,
    /// ms, its last change
    pub at: i64,
}

/// the __HARNESS__ section (rust/machine/src/keeper.rs harness_state). starts > 1: the harness's launcher died and the
/// keeper started it again, the machine staying up.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct HarnessRun {
    pub starts: i64,
    pub running: bool,
    #[serde(rename = "lastExit", skip_serializing_if = "String::is_empty")]
    pub last_exit: String,
    #[serde(rename = "lastExitAt", skip_serializing_if = "String::is_empty")]
    pub last_exit_at: String,
    #[serde(rename = "lastUpSecs", skip_serializing_if = "is_zero")]
    pub last_up_secs: i64,
}

/// Jarvis 1's readRegistry view, field names as in its /api/state
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Registry {
    #[serde(rename = "liveName")]
    pub live_name: String,
    #[serde(rename = "nameSource")]
    pub name_source: String,
    #[serde(rename = "aiTitle")]
    pub ai_title: String,
    /// busy | idle | waiting | … ("shell" folds into idle + bgTasks)
    pub status: String,
    #[serde(rename = "bgTasks")]
    pub bg_tasks: i64,
    /// ms; changes on every turn
    #[serde(rename = "statusUpdatedAt")]
    pub status_updated_at: i64,
    #[serde(rename = "bridgeSessionId")]
    pub bridge_session_id: String,
    /// the host's pid: a new one = the harness restarted it (accountswap.rs)
    #[serde(rename = "hostPid", skip_serializing_if = "is_zero")]
    pub host_pid: i64,
    /// claude's conversation id
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// uuid of a "Please run /login" reply ending the host's transcript
    #[serde(rename = "authFailed")]
    pub auth_failed: String,
    #[serde(rename = "credsExpiresAt")]
    pub creds_expires_at: i64,
    #[serde(rename = "sessionsInside")]
    pub sessions_inside: i64,
    #[serde(rename = "oneShotDone")]
    pub one_shot_done: bool,
    /// Go wrote null for none
    pub refusals: Option<Vec<Refusal>>,
    /// None: the machine doesn't count them (an image from before)
    pub workers: Option<Workers>,
    /// accountswap.rs: the account Anthropic named for the token installed by an account switch
    /// (rust/machine/src/claudelogin.rs after_switch); account_section: the image reports it at all
    #[serde(rename = "accountProof", skip_serializing_if = "String::is_empty")]
    pub account_proof: String,
    #[serde(rename = "accountSection", skip_serializing_if = "is_false")]
    pub account_section: bool,
    /// the keeper's record of the harness (rust/machine/src/keeper.rs): how often it was started on this machine and
    /// how it last ended; None: an image from before the keeper
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness: Option<HarnessRun>,
    /// when Deyao last sent the host conversation a prompt (ms; 0 = none in the transcript's tail); human_section: the
    /// image reports it at all (rust/machine/src/status.rs __HUMAN__, images from 2026-11-02 on)
    #[serde(rename = "lastHumanAt", skip_serializing_if = "is_zero")]
    pub last_human_at: i64,
    #[serde(rename = "humanSection", skip_serializing_if = "is_false")]
    pub human_section: bool,
}

impl Registry {
    pub fn refusals(&self) -> &[Refusal] {
        self.refusals.as_deref().unwrap_or_default()
    }
}

type Obj = Map<String, Value>;

pub fn json_lines(s: &str) -> Vec<Obj> {
    s.split('\n')
        .map(str::trim)
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<Obj>(l).ok())
        .collect()
}

pub fn str_of(m: &Obj, k: &str) -> String {
    m.get(k).and_then(Value::as_str).unwrap_or_default().to_string()
}

pub fn num_of(m: &Obj, k: &str) -> i64 {
    m.get(k).and_then(Value::as_f64).map_or(0, |f| f as i64)
}

/// the text before sep and after it ("" after when sep is missing), like JS split(sep) with [a, rest=""]
pub fn cut<'a>(s: &'a str, sep: &str) -> (&'a str, &'a str) {
    let (a, b, _) = jarvis_go::fmt::cut(s, sep);
    (a, b)
}

/// trimmed, then at most n bytes (sessionops.go clip)
fn clip_trim(s: &str, n: usize) -> String {
    jarvis_go::fmt::clip_bytes(s.trim(), n).to_string()
}

fn ms_of(s: &str) -> Option<i64> {
    GoTime::parse(s).map(|t| (t.unix_nanos() / 1_000_000) as i64)
}

/// the __HUMAN__ section → conversation id → its last human prompt (ms)
pub fn parse_human(section: &str) -> BTreeMap<String, i64> {
    let mut out = BTreeMap::new();
    for l in section.split('\n') {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() != 2 || !TRANSCRIPT_ID.is_match(f[0]) {
            continue;
        }
        if let Some(t) = ms_of(f[1]) {
            out.insert(f[0].to_string(), t);
        }
    }
    out
}

/// the __HARNESS__ section's line
pub fn parse_harness(section: &str) -> Option<HarnessRun> {
    let e = json_lines(section).into_iter().next()?;
    Some(HarnessRun {
        starts: num_of(&e, "starts").clamp(0, 1 << 20),
        running: e.get("running").and_then(Value::as_bool).unwrap_or(false),
        last_exit: clip_trim(&str_of(&e, "lastExit"), 80),
        last_exit_at: clip_trim(&str_of(&e, "lastExitAt"), 40),
        last_up_secs: num_of(&e, "lastUpSecs").max(0),
    })
}

/// the __WORKERS__ section's line for conversation sid
pub fn parse_workers(section: &str, sid: &str) -> Option<Workers> {
    for e in json_lines(section) {
        if sid.is_empty() || str_of(&e, "workersOf") != sid {
            continue;
        }
        let mut w = Workers { subagents: num_of(&e, "subagents").clamp(0, 1000), jobs: BTreeMap::new(), at: num_of(&e, "at") };
        if let Some(jobs) = e.get("jobs").and_then(Value::as_object) {
            for (k, v) in jobs {
                if let Some(n) = v.as_f64()
                    && n > 0.0
                    && WORKER_TYPE.is_match(k)
                    && w.jobs.len() < 20
                {
                    w.jobs.insert(k.clone(), n.min(1000.0) as i64);
                }
            }
        }
        return Some(w);
    }
    None
}

/// claude's "shell" (the turn ended while background shells run) is idle + bgTasks ≥ 1
pub fn normalize(status: &str, bg: i64) -> (String, i64) {
    let bg = bg.max(0);
    if status == "shell" {
        return ("idle".into(), bg.max(1));
    }
    (status.into(), bg)
}

/// the text after __AUTH__ → transcript id → uuid, and the credentials file's expiry (ms)
pub fn parse_login(text: &str) -> (BTreeMap<String, String>, i64) {
    let (auth, creds) = cut(text, "__CREDS__");
    let mut failed = BTreeMap::new();
    for l in auth.split('\n') {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 2 && TRANSCRIPT_ID.is_match(f[0]) {
            failed.insert(f[0].to_string(), f[1].to_string());
        }
    }
    (failed, creds.trim().parse().unwrap_or(0))
}

pub fn model_from_text(text: &str) -> String {
    SAFEGUARD_MODEL
        .captures(text)
        .map(|m| m[1].trim().to_string())
        .unwrap_or_default()
}

/// lib/downgrade.js parse
pub fn parse_refusals(section: &str) -> Vec<Refusal> {
    let mut out = vec![];
    for e in json_lines(section) {
        let at = ms_of(&str_of(&e, "timestamp")).unwrap_or(0);
        let first = |ks: &[&str]| ks.iter().map(|k| str_of(&e, k)).find(|v| !v.is_empty()).unwrap_or_default();
        let msg = e.get("message").and_then(Value::as_object);
        if str_of(&e, "type") == "system" && str_of(&e, "subtype") == "model_refusal_fallback" {
            out.push(Refusal {
                kind: "fallback".into(),
                at,
                uuid: str_of(&e, "uuid"),
                from: first(&["originalModel", "original_model"]),
                to: first(&["fallbackModel", "fallback_model"]),
                category: first(&["apiRefusalCategory", "api_refusal_category"]),
                ..Default::default()
            });
        } else if let Some(msg) = msg.filter(|m| str_of(&e, "type") == "assistant" && str_of(m, "stop_reason") == "refusal") {
            let texts: Vec<String> = msg
                .get("content")
                .and_then(Value::as_array)
                .map(|cs| cs.iter().filter_map(Value::as_object).map(|c| str_of(c, "text")).collect())
                .unwrap_or_default();
            let mut model = str_of(msg, "model");
            if model.is_empty() || model == "<synthetic>" {
                model = model_from_text(&texts.join(" "));
            }
            let cat = msg
                .get("stop_details")
                .and_then(Value::as_object)
                .map(|sd| str_of(sd, "category"))
                .unwrap_or_default();
            out.push(Refusal { kind: "refusal".into(), at, uuid: str_of(&e, "uuid"), model, category: cat, ..Default::default() });
        }
    }
    out.sort_by_key(|r| r.at);
    out
}

fn split3<'a>(s: &'a str, sep: &str) -> (&'a str, &'a str, bool) {
    jarvis_go::fmt::cut(s, sep)
}

/// the raw registry output → the view, or None when there is no live claude inside (and no finished one-shot)
pub fn parse_registry(raw: &str) -> Option<Registry> {
    let (reg_part, rest) = cut(raw, "__TITLES__");
    let (title_part, rest2) = cut(rest, "__BG__");
    let (bg_part, rest3) = cut(rest2, "__ONESHOT__");
    let (one_shot_part, rest4) = cut(rest3, "__AUTH__");
    let (auth_part, rest5) = cut(rest4, "__REFUSAL__");
    let (refusal_part, workers_part) = cut(rest5, "__WORKERS__");
    let (workers_part, harness_part) = cut(workers_part, "__HARNESS__"); // images from 2026-10-21 on (the keeper)
    let (refusal_part, account_part, has_account) = split3(refusal_part, "__ACCOUNT__"); // images from 2026-10-20 on
    let (account_part, human_part, has_human) = split3(account_part, "__HUMAN__"); // images from 2026-11-02 on
    let proof = json_lines(account_part)
        .iter()
        .map(|e| str_of(e, "accountUuid"))
        .next_back()
        .unwrap_or_default();
    let (failed, creds_exp) = parse_login(auth_part);
    let refusals = parse_refusals(refusal_part);
    let one_shot_done = ONE_SHOT_DONE.is_match(one_shot_part.trim());
    let refusals = (!refusals.is_empty()).then_some(refusals);

    let mut entries = json_lines(reg_part);
    entries.sort_by_key(|e| num_of(e, "startedAt")); // stable
    let mut titles = BTreeMap::new();
    let mut last_title = String::new();
    for t in json_lines(title_part) {
        if str_of(&t, "type") == "ai-title" && !str_of(&t, "aiTitle").is_empty() {
            titles.insert(str_of(&t, "sessionId"), str_of(&t, "aiTitle"));
            last_title = str_of(&t, "aiTitle");
        }
    }
    let mut bg = BTreeMap::new();
    for l in bg_part.split('\n') {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() == 2 {
            bg.insert(f[0].to_string(), f[1].parse::<i64>().unwrap_or(0));
        }
    }
    let host = entries
        .iter()
        .find(|e| !str_of(e, "bridgeSessionId").is_empty())
        .or_else(|| entries.first());
    let Some(host) = host else {
        if one_shot_done {
            return Some(Registry { one_shot_done: true, ai_title: last_title, refusals, ..Default::default() });
        }
        return None;
    };
    let sid = str_of(host, "sessionId");
    let (status, n) = normalize(&str_of(host, "status"), bg.get(&num_of(host, "pid").to_string()).copied().unwrap_or(0));
    Some(Registry {
        live_name: str_of(host, "name"),
        name_source: str_of(host, "nameSource"),
        ai_title: titles.get(&sid).cloned().unwrap_or_default(),
        status,
        bg_tasks: n,
        status_updated_at: num_of(host, "statusUpdatedAt"),
        bridge_session_id: str_of(host, "bridgeSessionId"),
        host_pid: num_of(host, "pid"),
        session_id: sid.clone(),
        auth_failed: failed.get(&sid).cloned().unwrap_or_default(),
        creds_expires_at: creds_exp,
        sessions_inside: entries.len() as i64,
        one_shot_done,
        refusals,
        workers: parse_workers(workers_part, &sid),
        account_section: has_account,
        account_proof: proof,
        harness: parse_harness(harness_part),
        // the aviary harness's transcripts never mark a person's prompt (its messages come through the supervisor's
        // stdin with no origin): the machine knows none, so the session keeps the hour (autopilot.rs idle_pause_for)
        last_human_at: parse_human(human_part).get(&sid).copied().unwrap_or(0),
        human_section: has_human && str_of(host, "harness") != "aviary",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_registry() {
        let raw = r#"{"pid":7,"sessionId":"abcdef12-3456","status":"shell","statusUpdatedAt":5,"bridgeSessionId":"b","name":"n","startedAt":1}
__TITLES__
{"type":"ai-title","sessionId":"abcdef12-3456","aiTitle":"T"}
__BG__
7 2
__ONESHOT__
__AUTH__
abcdef12-3456 u1
__CREDS__
1700
__REFUSAL__
{"type":"assistant","uuid":"r1","timestamp":"2026-01-01T00:00:00Z","message":{"stop_reason":"refusal","model":"<synthetic>","content":[{"text":"API Error: Claude Opus 5's safeguards flagged this"}]}}
__ACCOUNT__
{"accountUuid":"acc"}
__HUMAN__
abcdef12-3456 2026-01-01T00:00:01Z
__WORKERS__
{"workersOf":"abcdef12-3456","subagents":2,"jobs":{"shell":1,"BAD":3},"at":9}
__HARNESS__
{"starts":2,"running":true,"lastExit":"signal 9"}
"#;
        let g = parse_registry(raw).unwrap_or_default();
        assert_eq!((g.status.as_str(), g.bg_tasks), ("idle", 2));
        assert_eq!(g.ai_title, "T");
        assert_eq!(g.auth_failed, "u1");
        assert_eq!(g.creds_expires_at, 1700);
        assert_eq!(g.refusals()[0].model, "Claude Opus 5");
        assert_eq!(g.account_proof, "acc");
        assert_eq!(g.last_human_at, 1767225601000);
        assert_eq!(g.workers.as_ref().map(|w| w.jobs.len()), Some(1));
        assert_eq!(g.harness.as_ref().map(|h| h.starts), Some(2));
        assert!(parse_registry("").is_none());
    }
}
