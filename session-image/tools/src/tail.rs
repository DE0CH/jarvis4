//! jarvis-tail: another session's conversation as it is now (router/livetail.go), where transcript search sees a
//! running session only up to about 10 minutes late (its 5-minute live sync, then the indexer's 5-minute crawl).
//!
//!   jarvis-tail SESSION            SESSION: its id (s…) or its exact title; the last 40 messages with tool calls
//!   jarvis-tail SESSION -n 100     more (at most 500)
//!   jarvis-tail SESSION --said     only what was said (prompts and replies)
//!   jarvis-tail SESSION --json     the router's answer as it is
//!
//! A running session's machine is asked to send its changed transcripts first, so the tail is seconds old. A paused or
//! frozen session (or a machine on an image from before 2026-11-20) gives its last copy, marked stale with why. A
//! destroyed session's whole transcript is in transcript search.

use serde_json::Value;
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str =
    "usage: jarvis-tail SESSION [-n N] [--said] [--json]   (SESSION: its id or exact title)";

pub fn run(args: &[String]) -> Result<ExitCode, String> {
    let (mut session, mut n, mut said, mut raw) = (None::<String>, 0usize, false, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            "-n" => {
                n = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("-n takes a number of messages")?
            }
            "--said" => said = true,
            "--json" => raw = true,
            s if session.is_none() && !s.starts_with('-') => session = Some(s.to_string()),
            _ => return Err(USAGE.into()),
        }
    }
    let session = session.ok_or(USAGE)?;
    let base = std::env::var("JARVIS_URL").unwrap_or_default();
    if base.is_empty() {
        return Err("not a Jarvis 4 session (no JARVIS_URL): use transcript-search".into());
    }
    let mut url = format!(
        "{}/api/tail/{}",
        base.trim_end_matches('/'),
        escape(&session)
    );
    let mut q = vec![];
    if n > 0 {
        q.push(format!("n={n}"));
    }
    if said {
        q.push("said=1".to_string());
    }
    if !q.is_empty() {
        url = format!("{url}?{}", q.join("&"));
    }
    // the router waits up to 45 s for the machine's sync round, then reads the copy
    let res = ureq::get(&url).timeout(Duration::from_secs(150)).call();
    let (status, text) = match res {
        Ok(r) => (r.status(), r.into_string().map_err(|e| e.to_string())?),
        Err(ureq::Error::Status(s, r)) => (s, r.into_string().unwrap_or_default()),
        Err(e) => return Err(format!("jarvis request failed: {e}")),
    };
    let v: Value = serde_json::from_str(&text).map_err(|_| format!("HTTP {status}: {text}"))?;
    if status != 200 {
        return Err(v["error"].as_str().unwrap_or(&text).to_string());
    }
    if raw {
        println!("{text}");
    } else {
        print!("{}", render(&v));
    }
    Ok(ExitCode::SUCCESS)
}

/// a path segment, percent-encoded (a title has spaces)
fn escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// the router's answer for a reader: a heading, then one block per message
pub fn render(v: &Value) -> String {
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    let mut out = format!(
        "{} ({}, {}) {} · last entry {}\n",
        if s("title").is_empty() {
            "(untitled)".to_string()
        } else {
            s("title")
        },
        s("session"),
        s("state"),
        s("file"),
        if s("lastAt").is_empty() {
            "unknown".to_string()
        } else {
            s("lastAt")
        },
    );
    if v["stale"].as_bool() == Some(true) {
        out += &format!("stale: {}\n", s("why"));
    }
    for m in v["messages"].as_array().into_iter().flatten() {
        let at = m["at"].as_str().unwrap_or("");
        let time = at.get(11..19).unwrap_or(at);
        let text = m["text"].as_str().unwrap_or("").replace('\n', "\n    ");
        out += &format!("\n[{time}] {}: {text}\n", m["role"].as_str().unwrap_or(""));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_tail() {
        let v: Value = serde_json::from_str(
            r#"{"title":"Fix the router","session":"s1","state":"paused","file":"a.jsonl","lastAt":"2026-11-20T10:00:01Z",
                "stale":true,"why":"it is paused: its last copy, taken before that",
                "messages":[{"role":"user","text":"go on","at":"2026-11-20T10:00:00Z"},
                            {"role":"tool","text":"Bash {\"command\":\"ls\"}\nmore","at":"2026-11-20T10:00:01Z"}]}"#,
        )
        .unwrap_or_default();
        assert_eq!(
            render(&v),
            "Fix the router (s1, paused) a.jsonl · last entry 2026-11-20T10:00:01Z\n\
             stale: it is paused: its last copy, taken before that\n\
             \n[10:00:00] user: go on\n\
             \n[10:00:01] tool: Bash {\"command\":\"ls\"}\n    more\n"
        );
    }

    #[test]
    fn escapes_a_title() {
        assert_eq!(
            escape("Fix the: router/ü"),
            "Fix%20the%3A%20router%2F%C3%BC"
        );
        assert_eq!(escape("s0123abc"), "s0123abc");
    }
}
