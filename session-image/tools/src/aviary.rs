//! schedule-wakeup in an aviary session (Claude Code · aviary): its wakeups are magpie's schedules, the ones YYC AI's
//! conversations use (Deyao, 2026-11-17: dogfooding), through magpie's sandbox API (`http://magpie/v1/sandbox/schedules`,
//! by the sandbox's proxy, the machine's aviary-gateway, which adds the verified person and conversation).
//!
//! magpie posts each fire into this conversation as `<scheduled-message rule="…">PROMPT</scheduled-message>`;
//! hermit-jarvis resumes the session when it is paused and tells the router the next fire (a paused session keeps its
//! runners); the chat's conversation list shows a clock on the conversation.
//!
//! Every wakeup repeats: a cron rule in UTC whose first fire is the given time (magpie's `from`) and which then fires
//! every period. A cron rule steps only by 15/20/30 minutes, 1/2/3/4/6/8/12 hours, a day or a week; another period is
//! taken as the nearest of those (said on stderr). The wakeup's name is the prompt's first words, `[wakeup NAME] `,
//! which is how --list, --cancel and arming a name again find it among this conversation's schedules.

use crate::schedule::Action;
use serde_json::{Value, json};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const API: &str = "http://magpie/v1/sandbox/schedules";
/// The machine's aviary-gateway, without the proxy: this sandbox's conversation (only an aviary machine answers it).
const STATE: &str = "http://127.0.0.1:3128/jarvis/state";
/// The periods a cron rule can step by, seconds.
const STEPS: [u64; 12] = [
    900, 1200, 1800, 3600, 7200, 10800, 14400, 21600, 28800, 43200, 86400, 604_800,
];

/// This sandbox's conversation when it is an aviary session, `None` otherwise.
pub fn conversation() -> Option<String> {
    let r = ureq::get(STATE)
        .timeout(Duration::from_secs(3))
        .call()
        .ok()?;
    let v: Value = r.into_json().ok()?;
    v["conversationId"].as_str().map(str::to_owned)
}

/// One call to magpie through the sandbox's proxy; a refusal is an error with magpie's words.
fn magpie(method: &str, url: &str, body: Option<&Value>) -> Result<Value, String> {
    let agent = ureq::AgentBuilder::new().try_proxy_from_env(true).build();
    let req = agent
        .request(method, url)
        .timeout(Duration::from_secs(30))
        .set("Content-Type", "application/json");
    let res = match body {
        Some(b) => req.send_json(b),
        None => req.call(),
    };
    match res {
        Ok(r) => {
            let s = r
                .into_string()
                .map_err(|e| format!("reading magpie's answer: {e}"))?;
            Ok(if s.trim().is_empty() {
                json!({})
            } else {
                serde_json::from_str(&s).map_err(|e| e.to_string())?
            })
        }
        Err(ureq::Error::Status(code, r)) => {
            let s = r.into_string().unwrap_or_default();
            Err(format!(
                "magpie answered {code}: {}",
                s.chars().take(500).collect::<String>()
            ))
        }
        Err(e) => Err(format!("magpie unreachable: {e}")),
    }
}

/// `[wakeup NAME] rest` → (NAME, rest).
fn tag(prompt: &str) -> Option<(&str, &str)> {
    let rest = prompt.strip_prefix("[wakeup ")?;
    let (name, rest) = rest.split_once("] ")?;
    let ok = !name.is_empty()
        && name.len() <= 40
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    ok.then_some((name, rest))
}

/// This conversation's wakeups: (name, schedule).
fn mine(conv: &str) -> Result<Vec<(String, Value)>, String> {
    let list = magpie("GET", API, None)?;
    Ok(list["schedules"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|s| s["conversationId"].as_str() == Some(conv))
        .filter_map(|s| tag(s["prompt"].as_str()?).map(|(n, _)| (n.to_owned(), s.clone())))
        .collect())
}

/// The cron step nearest `period` (by ratio).
fn step(period: u64) -> u64 {
    let p = period.max(1) as f64;
    *STEPS
        .iter()
        .min_by(|a, b| {
            let da = (**a as f64 / p).ln().abs();
            let db = (**b as f64 / p).ln().abs();
            da.total_cmp(&db)
        })
        .unwrap_or(&3600)
}

/// (minute, hour, weekday with Sunday 0) of a Unix time in UTC.
fn utc_parts(t: i64) -> (i64, i64, i64) {
    let day = t.div_euclid(86400);
    let sec = t.rem_euclid(86400);
    // 1970-01-01 was a Thursday
    (sec / 60 % 60, sec / 3600, (day + 4).rem_euclid(7))
}

/// A cron rule in UTC firing at `first` and every `step` seconds (one of [`STEPS`]).
fn rule(first: i64, step: u64) -> String {
    let (m, h, wd) = utc_parts(first);
    let join = |v: Vec<i64>| v.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
    match step {
        s if s < 3600 => {
            let k = (s / 60) as i64;
            let mut mins: Vec<i64> = (0..60 / k).map(|i| (m + i * k) % 60).collect();
            mins.sort_unstable();
            format!("{} * * * *", join(mins))
        }
        3600 => format!("{m} * * * *"),
        s if s < 86400 => {
            let k = (s / 3600) as i64;
            let mut hours: Vec<i64> = (0..24 / k).map(|i| (h + i * k) % 24).collect();
            hours.sort_unstable();
            format!("{m} {} * * *", join(hours))
        }
        86400 => format!("{m} {h} * * *"),
        _ => format!("{m} {h} * * {wd}"),
    }
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// An ISO-8601 time with its offset (`2026-12-01T14:00:00Z`, `2026-12-01T22:00+08:00`) as Unix seconds.
fn parse_time(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once(['T', 't', ' '])?;
    let mut d = date.split('-');
    let (y, mo, da): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let (clock, off) = if let Some(c) = rest.strip_suffix(['Z', 'z']) {
        (c, 0)
    } else {
        let i = rest.rfind(['+', '-'])?;
        let (c, o) = rest.split_at(i);
        let sign = if o.starts_with('-') { -1 } else { 1 };
        let (oh, om) = o[1..]
            .split_once(':')
            .unwrap_or((&o[1..o.len().min(3)], &o[o.len().min(3)..]));
        (
            c,
            sign * (oh.parse::<i64>().ok()? * 3600 + om.parse::<i64>().unwrap_or(0) * 60),
        )
    };
    let mut c = clock.split(':');
    let h: i64 = c.next()?.parse().ok()?;
    let mi: i64 = c.next()?.parse().ok()?;
    let sec: f64 = c.next().map_or(Some(0.0), |x| x.parse().ok())?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) || h > 23 || mi > 59 {
        return None;
    }
    Some(days_from_civil(y, mo, da) * 86400 + h * 3600 + mi * 60 + sec as i64 - off)
}

fn rfc3339(t: i64) -> String {
    let (days, sec) = (t.div_euclid(86400), t.rem_euclid(86400));
    // civil from days (Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sec / 3600,
        sec / 60 % 60,
        sec % 60
    )
}

/// The armed schedule's body: the first fire (the next whole minute at or after the time asked), the rule and its step.
fn arm_body(body: &Value, now: i64) -> Result<(Value, String, u64), String> {
    let name = body["name"].as_str().unwrap_or("default");
    let prompt = body["prompt"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let first = match (body["delaySeconds"].as_u64(), body["at"].as_str()) {
        (Some(d), _) => now + d as i64,
        (None, Some(at)) => parse_time(at)
            .ok_or_else(|| format!("{at:?} is neither a delay (45m, 2h) nor a time with its offset (2026-12-01T14:00:00Z)"))?
            .max(now),
        _ => return Err("no time given".into()),
    };
    let first = (first + 59).div_euclid(60) * 60;
    let period = body["everySeconds"].as_u64().unwrap_or(3600);
    let s = step(period);
    let note = if s == period {
        String::new()
    } else {
        format!(
            "note: a wakeup repeats by a cron step: every {} min instead of {} min",
            s / 60,
            period / 60
        )
    };
    let b = json!({"prompt": format!("[wakeup {name}] {prompt}"), "cron": rule(first, s), "tz": "UTC", "from": rfc3339(first)});
    Ok((b, note, s))
}

pub fn run(action: Action, conv: &str) -> Result<ExitCode, String> {
    match action {
        Action::List => {
            let list: Vec<Value> = mine(conv)?
                .into_iter()
                .map(|(n, s)| {
                    let prompt = s["prompt"].as_str().and_then(tag).map(|(_, p)| p).unwrap_or_default();
                    json!({"name": n, "id": s["id"], "describe": s["describe"], "next": s["next"], "state": s["state"], "prompt": prompt})
                })
                .collect();
            println!("{}", json!({ "wakeups": list }));
        }
        Action::Cancel(_) | Action::CancelAll => {
            let only = if let Action::Cancel(n) = &action {
                Some(n.clone())
            } else {
                None
            };
            let mut gone = vec![];
            for (n, s) in mine(conv)? {
                if only.as_ref().is_none_or(|o| *o == n) {
                    magpie(
                        "DELETE",
                        &format!("{API}/{}", s["id"].as_str().unwrap_or_default()),
                        None,
                    )?;
                    gone.push(n);
                }
            }
            println!("{}", json!({"ok": true, "cancelled": gone}));
        }
        Action::Arm(body) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            let (b, note, s) = arm_body(&body, now)?;
            if !note.is_empty() {
                eprintln!("{note}");
            }
            let name = body["name"].as_str().unwrap_or("default");
            for (n, old) in mine(conv)? {
                if n == name {
                    magpie(
                        "DELETE",
                        &format!("{API}/{}", old["id"].as_str().unwrap_or_default()),
                        None,
                    )?;
                }
            }
            let out = magpie("POST", API, Some(&b))?;
            println!(
                "{}",
                json!({"ok": true, "name": name, "id": out["id"], "describe": out["describe"], "next": out["next"], "everySeconds": s})
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_796_134_020; // 2026-12-01T14:07:00Z, a Tuesday

    #[test]
    fn times() {
        assert_eq!(rfc3339(T), "2026-12-01T14:07:00Z");
        assert_eq!(parse_time("2026-12-01T14:07:00Z"), Some(T));
        assert_eq!(parse_time("2026-12-01T22:07+08:00"), Some(T));
        assert_eq!(parse_time("2026-12-01T09:07:00.5-05:00"), Some(T));
        assert_eq!(parse_time("2026-12-01T14:07:00"), None, "no offset");
        assert_eq!(parse_time("tomorrow"), None);
        assert_eq!(utc_parts(T), (7, 14, 2));
    }

    #[test]
    fn rules_fire_at_the_first_time_and_every_step() {
        assert_eq!(rule(T, 900), "7,22,37,52 * * * *");
        assert_eq!(rule(T, 1200), "7,27,47 * * * *");
        assert_eq!(rule(T, 3600), "7 * * * *");
        assert_eq!(rule(T, 21600), "7 2,8,14,20 * * *");
        assert_eq!(rule(T, 86400), "7 14 * * *");
        assert_eq!(rule(T, 604_800), "7 14 * * 2");
    }

    #[test]
    fn a_period_a_cron_rule_cannot_step_by_is_the_nearest_step() {
        assert_eq!(step(2700), 3600);
        assert_eq!(step(5400), 7200);
        assert_eq!(step(172_800), 86400);
        assert_eq!(step(300), 900);
        assert_eq!(step(1800), 1800);
    }

    #[test]
    fn the_wakeup_is_a_named_repeating_schedule_from_its_first_time() {
        let body = json!({"name": "ci", "prompt": "check\n  CI", "at": "2026-12-01T14:06:30Z", "everySeconds": 3600});
        let (b, note, s) = arm_body(&body, T - 86400).unwrap();
        assert_eq!(
            b,
            json!({"prompt": "[wakeup ci] check CI", "cron": "7 * * * *", "tz": "UTC", "from": "2026-12-01T14:07:00Z"})
        );
        assert_eq!((note.as_str(), s), ("", 3600));
        // a delay counts from now; a time already past is now
        let (b, _, _) = arm_body(
            &json!({"name": "x", "prompt": "p", "delaySeconds": 2700, "everySeconds": 2700}),
            T,
        )
        .unwrap();
        assert_eq!(b["from"], "2026-12-01T14:52:00Z");
        assert_eq!(b["cron"], "52 * * * *");
        let (b, _, _) = arm_body(
            &json!({"name": "x", "prompt": "p", "at": "2026-11-01T00:00:00Z"}),
            T,
        )
        .unwrap();
        assert_eq!(b["from"], "2026-12-01T14:07:00Z");
        assert!(arm_body(&json!({"name": "x", "prompt": "p", "at": "soon"}), T).is_err());
    }

    #[test]
    fn names_are_read_back_from_the_prompt() {
        assert_eq!(tag("[wakeup ci] check CI"), Some(("ci", "check CI")));
        assert_eq!(tag("[wakeup bad name] x"), None);
        assert_eq!(tag("整理昨天的新聞"), None);
    }
}
