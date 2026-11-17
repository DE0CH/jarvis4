//! A Jarvis 4 session's own tools, one binary built into the session image (Deyao, 2026-11-17: shell scripts are
//! banned; Rust tools ship built). The name it runs under picks the tool:
//!   schedule-wakeup, schedule-cron  arm, list and cancel the session's router crons (schedule.rs)
//!   retire-session                  check the session can go, then ask the router to destroy it (retire.rs)
//! or `jarvis-tools <tool> …`. Every call goes to `$JARVIS_URL/api/sessions/$SESSION_ID/…`: the machine's local
//! proxy signs it with the machine key and forwards it to the router (/m/api).

mod retire;
mod schedule;

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
        "schedule-wakeup" => (
            schedule::wakeup_action(&args).and_then(schedule::run),
            "ERROR",
        ),
        "schedule-cron" => (
            schedule::cron_action(&args).and_then(schedule::run),
            "ERROR",
        ),
        "retire-session" => (
            retire::run(args.first().is_some_and(|a| a == "--check")),
            "BLOCKED",
        ),
        _ => (
            Err("usage: jarvis-tools schedule-wakeup|schedule-cron|retire-session …".into()),
            "ERROR",
        ),
    };
    match res {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{failed_word}: {e}");
            ExitCode::FAILURE
        }
    }
}
