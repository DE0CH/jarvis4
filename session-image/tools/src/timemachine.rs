//! `time-machine <duration>` (jarvis4 docs/PLAN-fabric.md): the session waits frozen. On the fabric (gVisor) the
//! router has the session's sandbox frozen, RAM and processes included, until `<duration>` is up or anything
//! arrives for the session first (a message, a wakeup or cron, a decision on an Inbox request, an answer to a
//! question, Deyao's Resume); then it goes on where it stopped and this command says why it came back. It blocks the
//! whole time, as any wait does: cancelled, it leaves the session running and nothing frozen.
//!
//! What frozen means: nothing in the session runs meanwhile (a local build does not advance: the time machine is for
//! waiting on something outside, such as CI), connections to the outside are reset at the thaw (another host, another
//! address), and the wall and monotonic clocks both jump by the time spent frozen. A session elsewhere than on the
//! fabric has no time machine (use schedule-wakeup).

use serde_json::{Value, json};
use std::process::ExitCode;
use std::time::{Duration, Instant};

pub const USAGE: &str = "usage: time-machine <duration>   e.g. time-machine 2h (90s, 45m, 1.5h, 2d; at most 30d)
  The session waits frozen until then, or until anything arrives for it first (a message, a wakeup or cron, a decision
  on an Inbox request, an answer to a question); then it goes on and this prints why. Frozen means frozen: nothing
  runs meanwhile, outside connections reset at the thaw, and the clocks jump. Only on the fabric (gVisor).";

/// What the router's answer to a GET says: still waiting, or back and why.
#[derive(Debug, PartialEq, Eq)]
pub enum Wait {
    Frozen,
    Back(String),
}

/// The router's GET answer read (a reset connection or a half-thawed proxy answers nothing usable: still waiting).
#[must_use]
pub fn read_wait(body: &str) -> Wait {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    match (v["frozen"].as_bool(), v["why"].as_str()) {
        (Some(false), Some(why)) if !why.is_empty() => Wait::Back(why.to_owned()),
        _ => Wait::Frozen,
    }
}

/// `2h 5m` from a duration.
#[must_use]
pub fn human(d: Duration) -> String {
    let s = d.as_secs();
    match (s / 86400, (s % 86400) / 3600, (s % 3600) / 60, s % 60) {
        (0, 0, 0, sec) => format!("{sec}s"),
        (0, 0, m, sec) => format!("{m}m {sec}s"),
        (0, h, m, _) => format!("{h}h {m}m"),
        (d, h, _, _) => format!("{d}d {h}h"),
    }
}

fn url() -> Result<String, String> {
    let base = std::env::var("JARVIS_URL").unwrap_or_default();
    if base.is_empty() {
        return Err("not a Jarvis 4 session (no JARVIS_URL): use a timer of your own".into());
    }
    Ok(format!("{}/api/time-machine", base.trim_end_matches('/')))
}

/// # Errors
/// The arguments, or the router refusing the freeze.
pub fn run(args: &[String]) -> Result<ExitCode, String> {
    if args.first().is_some_and(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    let [d] = args else {
        return Err(USAGE.into());
    };
    let secs = crate::schedule::secs(d)
        .filter(|s| *s > 0)
        .ok_or_else(|| format!("bad duration {d:?}\n{USAGE}"))?;
    let url = url()?;
    let answer = crate::call("POST", &url, Some(&json!({ "seconds": secs })))?;
    let v: Value = serde_json::from_str(&answer).unwrap_or(Value::Null);
    if v["frozen"].as_bool() != Some(true) {
        return Err(v["error"].as_str().map_or(answer.clone(), str::to_owned));
    }
    eprintln!(
        "In the time machine for up to {}; anything that arrives for the session ends it sooner.",
        human(Duration::from_secs(secs))
    );
    let t0 = Instant::now();
    loop {
        // frozen with the sandbox in between; a call cut by the thaw is asked again
        std::thread::sleep(Duration::from_secs(2));
        if let Ok(body) = crate::call("GET", &url, None)
            && let Wait::Back(why) = read_wait(&body)
        {
            println!("Back after {}: {why}.", human(t0.elapsed()));
            return Ok(ExitCode::SUCCESS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_is_back_only_once_the_router_says_why() {
        assert_eq!(read_wait(r#"{"frozen":true,"since":"x"}"#), Wait::Frozen);
        assert_eq!(
            read_wait(r#"{"frozen":false,"why":"the time","back":"t"}"#),
            Wait::Back("the time".into())
        );
        // not frozen yet, with no why: not back (the freeze was asked a moment ago)
        assert_eq!(read_wait(r#"{"frozen":false}"#), Wait::Frozen);
        // a cut connection or a proxy answering garbage while the sandbox thaws
        assert_eq!(read_wait(""), Wait::Frozen);
        assert_eq!(read_wait("<html>"), Wait::Frozen);
    }

    #[test]
    fn durations_read_as_people_do() {
        assert_eq!(human(Duration::from_secs(42)), "42s");
        assert_eq!(human(Duration::from_secs(125)), "2m 5s");
        assert_eq!(human(Duration::from_secs(7500)), "2h 5m");
        assert_eq!(human(Duration::from_secs(90000)), "1d 1h");
    }
}
