//! schedule-wakeup and schedule-cron: a Jarvis 4 session arms, lists and cancels its own router crons
//! (router/schedule.go, docs/API.md "Wakeups and crons"). One binary; the name it runs under picks the command
//! (`schedule-wakeup`, `schedule-cron`, or `jarvis-schedule wakeup|cron …`).
//!
//! Every wakeup repeats (Deyao, 2026-11-17): `schedule-wakeup` arms a router cron whose first firing is the given time
//! and which then fires every period until cancelled. The calls go to `$JARVIS_URL/api/sessions/$SESSION_ID/crons`:
//! the machine's local proxy signs each with the machine key and forwards it to the router (/m/api).
//!
//! Periods and delays are whole seconds: the session machine reads `everySeconds` from the signed request, and a
//! fractional `1800.0` (the shell scripts' Python float) once made it refuse every run after the first.

use serde_json::{Map, Value, json};
use std::process::ExitCode;

const WAKEUP_USAGE: &str = "usage: schedule-wakeup [--name N] [--every P] <delay|ISO-time> \"<prompt>\" | --list | --cancel [N] | --cancel-all";
const CRON_USAGE: &str = "usage: schedule-cron <name> [--every 1d] [--time HH:MM [--tz Zone] | --at ISO | --in 2h] [--until ISO] \"<prompt>\" | --list | --cancel <name>";
const MIN_EVERY: u64 = 15 * 60;
const MAX_EVERY: u64 = 90 * 24 * 60 * 60;

/// What a command line asks the router for.
#[derive(Debug, PartialEq)]
enum Action {
    List,
    Cancel(String),
    CancelAll,
    Arm(Value),
}

/// A duration such as `90s`, `45m`, `1.5h` or `2d`, in whole seconds (rounded).
fn secs(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_lowercase();
    let unit = match s.chars().last()? {
        's' => 1.0,
        'm' => 60.0,
        'h' => 3600.0,
        'd' => 86400.0,
        _ => return None,
    };
    let num = s[..s.len() - 1].trim_end();
    if num.is_empty()
        || !num.chars().all(|c| c.is_ascii_digit() || c == '.')
        || num.starts_with('.')
    {
        return None;
    }
    let v: f64 = num.parse().ok()?;
    let total = (v * unit).round();
    (total >= 1.0).then_some(total as u64)
}

fn wakeup_action(args: &[String]) -> Result<Action, String> {
    match args.first().map(String::as_str) {
        Some("--list") | Some("--show") => return Ok(Action::List),
        Some("--cancel") => {
            return Ok(Action::Cancel(
                args.get(1).cloned().unwrap_or_else(|| "default".into()),
            ));
        }
        Some("--cancel-all") => return Ok(Action::CancelAll),
        None => return Err(WAKEUP_USAGE.into()),
        _ => {}
    }
    let (mut name, mut every, mut i) = ("default".to_string(), None::<String>, 0);
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                name = args
                    .get(i + 1)
                    .filter(|v| !v.is_empty())
                    .cloned()
                    .ok_or("--name needs a name")?;
                i += 2;
            }
            "--every" => {
                every = Some(
                    args.get(i + 1)
                        .filter(|v| !v.is_empty())
                        .cloned()
                        .ok_or("--every needs a period")?,
                );
                i += 2;
            }
            a if a.starts_with('-') => return Err(WAKEUP_USAGE.into()),
            _ => break,
        }
    }
    let (when, prompt) = match (args.get(i), args.get(i + 1)) {
        (Some(w), Some(p)) if !w.is_empty() && !p.is_empty() => (w, p),
        _ => return Err(WAKEUP_USAGE.into()),
    };
    let mut b = Map::new();
    b.insert("name".into(), json!(name));
    b.insert("prompt".into(), json!(prompt));
    let delay = secs(when);
    match delay {
        Some(d) => b.insert("delaySeconds".into(), json!(d)),
        None => b.insert("at".into(), json!(when)),
    };
    let period = match every {
        Some(p) => secs(&p).ok_or_else(|| format!("bad period {p:?} (e.g. 30m, 6h, 1d)"))?,
        None => delay.map_or(3600, |d| d.clamp(MIN_EVERY, MAX_EVERY)),
    };
    b.insert("everySeconds".into(), json!(period));
    Ok(Action::Arm(Value::Object(b)))
}

fn cron_action(args: &[String]) -> Result<Action, String> {
    match args.first().map(String::as_str) {
        Some("--list") => return Ok(Action::List),
        Some("--cancel") => {
            return args
                .get(1)
                .filter(|v| !v.is_empty())
                .map(|n| Action::Cancel(n.clone()))
                .ok_or("--cancel <name>".into());
        }
        None | Some("") => return Err(CRON_USAGE.into()),
        Some(a) if a.starts_with('-') => return Err(CRON_USAGE.into()),
        _ => {}
    }
    let mut b = Map::new();
    b.insert("name".into(), json!(args[0]));
    let mut prompt = None;
    let mut i = 1;
    while i < args.len() {
        let key = match args[i].as_str() {
            "--every" => "everySeconds",
            "--time" => "time",
            "--tz" => "tz",
            "--at" => "at",
            "--in" => "delaySeconds",
            "--until" => "until",
            _ => {
                prompt = Some(args[i].clone());
                i += 1;
                continue;
            }
        };
        let v = args
            .get(i + 1)
            .ok_or_else(|| format!("{} needs a value", args[i]))?;
        if !v.is_empty() {
            let val = if key == "everySeconds" || key == "delaySeconds" {
                json!(secs(v).ok_or_else(|| format!("bad duration {v:?} (e.g. 30m, 6h, 1d)"))?)
            } else {
                json!(v)
            };
            b.insert(key.into(), val);
        }
        i += 2;
    }
    let prompt = prompt
        .filter(|p| !p.is_empty())
        .ok_or("a prompt is required — what should the session do each time?")?;
    b.insert("prompt".into(), json!(prompt));
    Ok(Action::Arm(Value::Object(b)))
}

/// One call to the session's crons API; the body comes back whatever the status (as `curl -sS` printed it).
fn call(method: &str, url: &str, body: Option<&Value>) -> Result<String, String> {
    let req = ureq::request(method, url).set("Content-Type", "application/json");
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

fn run(action: Action) -> Result<ExitCode, String> {
    let base = std::env::var("JARVIS_URL").unwrap_or_default();
    let sid = std::env::var("SESSION_ID").unwrap_or_default();
    if base.is_empty() || sid.is_empty() {
        return Err("not a Jarvis 4 session (no JARVIS_URL/SESSION_ID) — on the Mac / a web pod use CronCreate/ScheduleWakeup".into());
    }
    let url = format!("{}/api/sessions/{sid}/crons", base.trim_end_matches('/'));
    match action {
        Action::List => println!("{}", call("GET", &url, None)?),
        Action::Cancel(n) => println!("{}", call("DELETE", &format!("{url}/{n}"), None)?),
        Action::CancelAll => {
            let list: Value = serde_json::from_str(&call("GET", &url, None)?)
                .map_err(|_| "could not list the wakeups")?;
            for c in list["crons"].as_array().into_iter().flatten() {
                if let Some(n) = c["name"].as_str() {
                    println!("{}", call("DELETE", &format!("{url}/{n}"), None)?);
                }
            }
        }
        Action::Arm(body) => {
            let out = call("POST", &url, Some(&body))?;
            println!("{out}");
            let ok = serde_json::from_str::<Value>(&out).is_ok_and(|v| v["ok"] == json!(true));
            if !ok {
                return Ok(ExitCode::FAILURE);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().collect();
    let argv0 = args.remove(0);
    let mut cmd = std::path::Path::new(&argv0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    if cmd == "jarvis-schedule" {
        cmd = if args.is_empty() {
            String::new()
        } else {
            format!("schedule-{}", args.remove(0))
        };
    }
    let action = match cmd.as_str() {
        "schedule-wakeup" => wakeup_action(&args),
        "schedule-cron" => cron_action(&args),
        _ => Err(
            "usage: jarvis-schedule wakeup|cron … (or run it as schedule-wakeup / schedule-cron)"
                .into(),
        ),
    };
    match action.and_then(run) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ERROR: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }
    fn armed(r: Result<Action, String>) -> Value {
        match r {
            Ok(Action::Arm(v)) => v,
            other => panic!("not an arm: {other:?}"),
        }
    }

    // 2026-11-17: the shell scripts sent "everySeconds": 1800.0; the machine refused every run after the first
    #[test]
    fn periods_and_delays_are_whole_seconds() {
        let b = armed(wakeup_action(&a(&["--every", "30m", "30m", "p"])));
        assert_eq!(serde_json::to_string(&b["everySeconds"]).unwrap(), "1800");
        assert_eq!(serde_json::to_string(&b["delaySeconds"]).unwrap(), "1800");
        let b = armed(wakeup_action(&a(&["1.5h", "p"])));
        assert_eq!(serde_json::to_string(&b["everySeconds"]).unwrap(), "5400");
        let b = armed(cron_action(&a(&["n", "--every", "6h", "--in", "90s", "p"])));
        assert_eq!(serde_json::to_string(&b["everySeconds"]).unwrap(), "21600");
        assert_eq!(serde_json::to_string(&b["delaySeconds"]).unwrap(), "90");
    }

    #[test]
    fn durations() {
        assert_eq!(secs("90s"), Some(90));
        assert_eq!(secs("45m"), Some(2700));
        assert_eq!(secs(" 2D "), Some(172800));
        assert_eq!(secs("0.5m"), Some(30));
        assert_eq!(secs("2026-11-17T13:52:00Z"), None);
        assert_eq!(secs("m"), None);
        assert_eq!(secs(".5h"), None);
        assert_eq!(secs("5x"), None);
    }

    #[test]
    fn wakeup_period_defaults() {
        // the delay, at least 15m
        assert_eq!(
            armed(wakeup_action(&a(&["90s", "p"])))["everySeconds"],
            json!(900)
        );
        assert_eq!(
            armed(wakeup_action(&a(&["2h", "p"])))["everySeconds"],
            json!(7200)
        );
        // 1h after an absolute time
        let b = armed(wakeup_action(&a(&[
            "--name",
            "x",
            "2026-12-01T00:00:00Z",
            "p",
        ])));
        assert_eq!(
            b,
            json!({"name": "x", "prompt": "p", "at": "2026-12-01T00:00:00Z", "everySeconds": 3600})
        );
    }

    #[test]
    fn wakeup_commands() {
        assert_eq!(wakeup_action(&a(&["--list"])), Ok(Action::List));
        assert_eq!(
            wakeup_action(&a(&["--cancel"])),
            Ok(Action::Cancel("default".into()))
        );
        assert_eq!(
            wakeup_action(&a(&["--cancel", "hotel"])),
            Ok(Action::Cancel("hotel".into()))
        );
        assert_eq!(wakeup_action(&a(&["--cancel-all"])), Ok(Action::CancelAll));
        assert!(wakeup_action(&a(&[])).is_err());
        assert!(wakeup_action(&a(&["1h"])).is_err());
        assert!(wakeup_action(&a(&["--bogus", "1h", "p"])).is_err());
        assert!(wakeup_action(&a(&["--every", "soon", "1h", "p"])).is_err());
    }

    #[test]
    fn cron_commands() {
        assert_eq!(cron_action(&a(&["--list"])), Ok(Action::List));
        assert_eq!(
            cron_action(&a(&["--cancel", "x"])),
            Ok(Action::Cancel("x".into()))
        );
        assert!(cron_action(&a(&["--cancel"])).is_err());
        assert!(cron_action(&a(&["--every", "1d"])).is_err());
        assert!(cron_action(&a(&["n", "--every", "1d"])).is_err());
        let b = armed(cron_action(&a(&[
            "tix",
            "--time",
            "12:00",
            "--tz",
            "Asia/Shanghai",
            "--until",
            "2026-12-07T00:00:00Z",
            "Daily",
        ])));
        assert_eq!(
            b,
            json!({"name": "tix", "time": "12:00", "tz": "Asia/Shanghai", "until": "2026-12-07T00:00:00Z", "prompt": "Daily"})
        );
    }
}
