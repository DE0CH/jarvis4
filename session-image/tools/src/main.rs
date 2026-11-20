//! A Jarvis 4 session's own tools, one binary built into the session image (Deyao, 2026-11-17: shell scripts are
//! banned; Rust tools ship built). The name it runs under picks the tool:
//!   schedule-wakeup, schedule-cron  arm, list and cancel the session's router crons (schedule.rs); in an aviary
//!                                   sandbox a wakeup is a magpie schedule instead (aviary.rs)
//!   retire-session                  check the session can go, then ask the router to destroy it (retire.rs)
//!   time-machine                    a fabric session waits frozen until a time or anything that arrives (timemachine.rs)
//!   aviary-sandbox                  (as root) an aviary session's sandbox in aviary's own image (aviary_sandbox.rs)
//!   session-entrypoint              the session's steps before its harness, then the harness (entrypoint.rs)
//!   workspace-layer                 the multi-repo workspace's CLAUDE.md, links and settings (workspace_layer.rs)
//! or `jarvis-tools <tool> …`. Every router call goes to `$JARVIS_URL/api/sessions/$SESSION_ID/…`: the machine's local
//! proxy signs it with the machine key and forwards it to the router (/m/api).

mod aviary;
mod aviary_sandbox;
mod entrypoint;
mod retire;
mod schedule;
mod timemachine;
mod workspace_layer;

use serde_json::Value;
use std::process::ExitCode;
use std::time::Duration;

/// `$JARVIS_URL/api/sessions/$SESSION_ID/<rest>`, or what to do outside a Jarvis 4 session
pub fn session_url(rest: &str, elsewhere: &str) -> Result<String, String> {
    let base = std::env::var("JARVIS_URL").unwrap_or_default();
    let sid = std::env::var("SESSION_ID").unwrap_or_default();
    if base.is_empty() || sid.is_empty() {
        return Err(format!(
            "not a Jarvis 4 session (no JARVIS_URL/SESSION_ID) — {elsewhere}"
        ));
    }
    Ok(format!(
        "{}/api/sessions/{sid}{}{rest}",
        base.trim_end_matches('/'),
        if rest.is_empty() { "" } else { "/" }
    ))
}

/// One call to the session's API (60 s at most); the body comes back whatever the status.
pub fn call(method: &str, url: &str, body: Option<&Value>) -> Result<String, String> {
    let req = ureq::request(method, url)
        .timeout(Duration::from_secs(60))
        .set("Content-Type", "application/json");
    let res = match body {
        Some(b) => req.send_json(b),
        None => req.call(),
    };
    match res {
        Ok(r) | Err(ureq::Error::Status(_, r)) => r
            .into_string()
            .map_err(|e| format!("reading the answer: {e}")),
        Err(e) => Err(format!("jarvis request failed: {e}")),
    }
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().collect();
    let argv0 = args.remove(0);
    let mut tool = std::path::Path::new(&argv0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    if tool == "jarvis-tools" {
        tool = if args.is_empty() {
            String::new()
        } else {
            args.remove(0)
        };
    }
    let (res, failed_word) = match tool.as_str() {
        // in an aviary sandbox a wakeup is a magpie schedule (aviary.rs)
        "schedule-wakeup" => (
            schedule::wakeup_action(&args).and_then(|a| match aviary::conversation() {
                Some(conv) => aviary::run(a, &conv),
                None => schedule::run(a),
            }),
            "ERROR",
        ),
        "schedule-cron" => (
            schedule::cron_action(&args).and_then(schedule::run),
            "ERROR",
        ),
        "aviary-sandbox" => (aviary_sandbox::run(&args), aviary_sandbox::TAG),
        "time-machine" => (timemachine::run(&args), "ERROR"),
        "session-entrypoint" => (entrypoint::run(), entrypoint::TAG),
        "workspace-layer" => (workspace_layer::run(&args), workspace_layer::TAG),
        "retire-session" => (
            retire::run(args.first().is_some_and(|a| a == "--check")),
            "BLOCKED",
        ),
        _ => (
            Err(
                "usage: jarvis-tools schedule-wakeup|schedule-cron|retire-session|time-machine|aviary-sandbox|workspace-layer|session-entrypoint …"
                    .into(),
            ),
            "ERROR",
        ),
    };
    match res {
        Ok(code) => code,
        Err(e) => {
            // a tag (`[aviary-sandbox]`) is followed by a space, as the session's log wants it
            if failed_word.starts_with('[') {
                eprintln!("{failed_word} {e}");
            } else {
                eprintln!("{failed_word}: {e}");
            }
            ExitCode::FAILURE
        }
    }
}
