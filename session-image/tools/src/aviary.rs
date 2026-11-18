//! schedule-wakeup in an aviary session (harness "Claude Code · aviary"): its wakeups are magpie's schedules, the ones
//! YYC AI's conversations use (Deyao, 2026-11-17: dogfooding), so the chat's conversation list shows a clock on a
//! conversation with one armed. magpie fires each into the conversation as
//! `<scheduled-message rule="…">[wakeup "NAME"] PROMPT</scheduled-message>`; hermit-jarvis resumes a paused session for
//! the turn and tells the router the next fire, which counts it as an armed wakeup (runners kept, no retire, no
//! auto-pause shortly before it).
//!
//! The calls go to `http://magpie/v1/sandbox/schedules` through the machine's aviary-gateway (the sandbox's
//! `http_proxy`, which adds the verified sandbox identity). magpie lists the person's schedules in every
//! conversation: a wakeup is one in this conversation (the gateway's `/jarvis/state` names it) whose prompt starts
//! with `[wakeup "NAME"]`.
//!
//! Every wakeup repeats (Deyao, 2026-11-17): a cron rule in UTC that starts (`from`) at the first time and then fires
//! every period. A cron rule cannot say every period, so the period is the nearest one it can say (15m, 20m, 30m, 1h,
//! 2h, 3h, 4h, 6h, 8h, 12h, 1d, 1w); the answer carries magpie's own reading of the rule.

use serde_json::{Value, json};
use std::process::ExitCode;
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::schedule::Action;

/// The aviary-gateway's own address on the machine (never through the proxy).
const STATE: &str = "http://127.0.0.1:3128/jarvis/state";
const API: &str = "http://magpie/v1/sandbox/schedules";
/// The periods a cron rule can say, seconds.
const STEPS: [u64; 12] = [
    900, 1200, 1800, 3600, 7200, 10800, 14400, 21600, 28800, 43200, 86400, 604800,
];

/// The aviary conversation this sandbox runs, or `None` outside an aviary sandbox (no gateway answers).
pub fn conversation() -> Option<String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(3))
        .build();
    let v: Value = agent.get(STATE).call().ok()?.into_json().ok()?;
    v["conversationId"]
        .as_str()
        .filter(|c| !c.is_empty())
        .map(str::to_string)
}

/// The nearest period a cron rule can say.
pub fn snap(period: u64) -> u64 {
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

fn every(start: u32, step: u32, limit: u32) -> String {
    let start = start % step;
    (start..limit)
        .step_by(step as usize)
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// The UTC cron rule that fires at `first` (to the minute) and then every `period` (one of [`STEPS`]).
pub fn rule(first: OffsetDateTime, period: u64) -> String {
    let first = first.to_offset(time::UtcOffset::UTC);
    let (m, h) = (u32::from(first.minute()), u32::from(first.hour()));
    match period {
        p if p < 3600 => format!("{} * * * *", every(m, (p / 60) as u32, 60)),
        3600 => format!("{m} * * * *"),
        p if p < 86400 => format!("{m} {} * * *", every(h, (p / 3600) as u32, 24)),
        86400 => format!("{m} {h} * * *"),
        _ => format!("{m} {h} * * {}", first.weekday().number_days_from_sunday()),
    }
}

/// The prompt magpie posts: the wakeup's name in front, so the list finds it again.
pub fn tagged(name: &str, prompt: &str) -> String {
    format!("[wakeup \"{name}\"] {prompt}")
}

/// The wakeup's name of a schedule's prompt (`None`: not a wakeup).
pub fn name_of(prompt: &str) -> Option<&str> {
    let rest = prompt.strip_prefix("[wakeup \"")?;
    let end = rest.find("\"]")?;
    Some(&rest[..end])
}

/// magpie's schedule body for an armed wakeup (the router's body: `name`, `prompt`, `delaySeconds` or `at`,
/// `everySeconds`), as of `now`.
pub fn create_body(arm: &Value, now: OffsetDateTime) -> Result<(String, Value), String> {
    let name = arm["name"].as_str().unwrap_or("default").to_string();
    let prompt = arm["prompt"].as_str().unwrap_or_default();
    let first = match (arm["delaySeconds"].as_u64(), arm["at"].as_str()) {
        (Some(d), _) => now + Duration::from_secs(d),
        (None, Some(at)) => OffsetDateTime::parse(at, &Rfc3339).map_err(|_| {
            format!("bad time {at:?}: give a delay (90m, 2h) or an ISO time with its offset (2026-12-01T09:00:00Z)")
        })?,
        _ => return Err("a delay or a time is needed".into()),
    };
    if first < now - Duration::from_secs(60) {
        return Err(format!(
            "{} is in the past",
            arm["at"].as_str().unwrap_or("the time")
        ));
    }
    // to the minute: magpie's first fire is the rule's first time at or after `from`
    let first = first
        .to_offset(time::UtcOffset::UTC)
        .replace_second(0)
        .and_then(|t| t.replace_nanosecond(0))
        .map_err(|e| e.to_string())?;
    let period = snap(arm["everySeconds"].as_u64().unwrap_or(3600));
    let from = first.format(&Rfc3339).map_err(|e| e.to_string())?;
    Ok((
        name.clone(),
        json!({
            "prompt": tagged(&name, prompt),
            "cron": rule(first, period),
            "tz": "UTC",
            "from": from,
        }),
    ))
}

/// This conversation's wakeups among magpie's schedules: (name, schedule).
pub fn wakeups<'a>(list: &'a Value, conv: &str) -> Vec<(&'a str, &'a Value)> {
    list["schedules"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|s| s["conversationId"].as_str() == Some(conv))
        .filter(|s| matches!(s["state"].as_str(), Some("active" | "paused")))
        .filter_map(|s| s["prompt"].as_str().and_then(name_of).map(|n| (n, s)))
        .collect()
}

fn shown(name: &str, s: &Value) -> Value {
    json!({
        "name": name,
        "next": s["next"],
        "rule": s["describe"],
        "cron": s["cron"],
        "tz": s["tz"],
        "from": s["from"],
        "id": s["id"],
        "prompt": s["prompt"].as_str().and_then(|p| p.split_once("] ")).map(|(_, p)| p),
    })
}

fn magpie() -> Result<ureq::Agent, String> {
    let mut b = ureq::AgentBuilder::new().timeout(Duration::from_secs(30));
    let proxy = std::env::var("http_proxy")
        .or_else(|_| std::env::var("HTTP_PROXY"))
        .map_err(|_| "no http_proxy: magpie is reached through the machine's aviary-gateway")?;
    b = b.proxy(ureq::Proxy::new(&proxy).map_err(|_| "the http_proxy is not a proxy URL")?);
    Ok(b.build())
}

fn send(
    agent: &ureq::Agent,
    method: &str,
    url: &str,
    body: Option<&Value>,
) -> Result<Value, String> {
    let req = agent.request(method, url);
    let res = match body {
        Some(b) => req.send_json(b),
        None => req.call(),
    };
    match res {
        Ok(r) => {
            let s = r.into_string().map_err(|e| e.to_string())?;
            Ok(serde_json::from_str(&s).unwrap_or(Value::Null))
        }
        Err(ureq::Error::Status(code, r)) => Err(format!(
            "magpie answered {code} to {method} {url}: {}",
            r.into_string()
                .unwrap_or_default()
                .chars()
                .take(400)
                .collect::<String>()
        )),
        Err(e) => Err(format!("magpie unreachable: {e}")),
    }
}

pub fn run(action: Action, conv: &str) -> Result<ExitCode, String> {
    let agent = magpie()?;
    let list = send(&agent, "GET", API, None)?;
    let mine = wakeups(&list, conv);
    let drop = |name: Option<&str>| -> Result<Vec<String>, String> {
        let mut gone = Vec::new();
        for (n, s) in &mine {
            if name.is_none_or(|w| w == *n) {
                let id = s["id"].as_str().unwrap_or_default();
                send(&agent, "DELETE", &format!("{API}/{id}"), None)?;
                gone.push(n.to_string());
            }
        }
        Ok(gone)
    };
    match action {
        Action::List => {
            let w: Vec<Value> = mine.iter().map(|(n, s)| shown(n, s)).collect();
            println!(
                "{}",
                json!({"wakeups": w, "where": "magpie schedules (aviary session)"})
            );
        }
        Action::Cancel(n) => {
            let gone = drop(Some(&n))?;
            println!("{}", json!({"ok": true, "cancelled": gone}));
        }
        Action::CancelAll => {
            let gone = drop(None)?;
            println!("{}", json!({"ok": true, "cancelled": gone}));
        }
        Action::Arm(arm) => {
            let (name, body) = create_body(&arm, OffsetDateTime::now_utc())?;
            // the new one first: arming a name again moves it, with no moment without it
            let made = send(&agent, "POST", API, Some(&body))?;
            for (n, s) in &mine {
                if *n == name {
                    let id = s["id"].as_str().unwrap_or_default();
                    send(&agent, "DELETE", &format!("{API}/{id}"), None)?;
                }
            }
            let asked = arm["everySeconds"].as_u64().unwrap_or(3600);
            let mut out = json!({"ok": true, "wakeup": shown(&name, &made)});
            if snap(asked) != asked {
                out["note"] = json!(format!(
                    "a cron rule cannot repeat every {asked}s: it repeats every {}s",
                    snap(asked)
                ));
            }
            println!("{out}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn periods_snap_to_what_cron_can_say() {
        assert_eq!(snap(900), 900);
        assert_eq!(snap(300), 900);
        assert_eq!(snap(2700), 3600);
        assert_eq!(snap(5400), 7200);
        assert_eq!(snap(3600), 3600);
        assert_eq!(snap(172_800), 86400);
        assert_eq!(snap(90 * 86400), 604_800);
    }

    #[test]
    fn rules_start_at_the_first_time() {
        let t = datetime!(2026-12-01 14:07 UTC); // a Tuesday
        assert_eq!(rule(t, 900), "7,22,37,52 * * * *");
        assert_eq!(rule(t, 1200), "7,27,47 * * * *");
        assert_eq!(rule(t, 1800), "7,37 * * * *");
        assert_eq!(rule(t, 3600), "7 * * * *");
        assert_eq!(rule(t, 7200), "7 0,2,4,6,8,10,12,14,16,18,20,22 * * *");
        assert_eq!(rule(t, 21600), "7 2,8,14,20 * * *");
        assert_eq!(rule(t, 43200), "7 2,14 * * *");
        assert_eq!(rule(t, 86400), "7 14 * * *");
        assert_eq!(rule(t, 604_800), "7 14 * * 2");
        // the rule is UTC whatever offset the time was given in
        assert_eq!(
            rule(datetime!(2026-12-01 22:07 +08:00), 86400),
            "7 14 * * *"
        );
    }

    #[test]
    fn names_ride_in_the_prompt() {
        let p = tagged("chat-marks", "check the pin");
        assert_eq!(p, "[wakeup \"chat-marks\"] check the pin");
        assert_eq!(name_of(&p), Some("chat-marks"));
        assert_eq!(name_of("整理新聞"), None);
        assert_eq!(name_of("[wakeup \"x"), None);
    }

    #[test]
    fn an_armed_wakeup_is_a_rule_from_its_first_time() {
        let now = datetime!(2026-11-18 01:52:30 UTC);
        let (name, b) = create_body(
            &json!({"name": "n", "prompt": "p", "delaySeconds": 1800, "everySeconds": 1800}),
            now,
        )
        .unwrap();
        assert_eq!(name, "n");
        assert_eq!(
            b,
            json!({"prompt": "[wakeup \"n\"] p", "cron": "22,52 * * * *", "tz": "UTC", "from": "2026-11-18T02:22:00Z"})
        );
        let (_, b) = create_body(
            &json!({"name": "d", "prompt": "p", "at": "2026-12-01T09:00:00+08:00", "everySeconds": 3600}),
            now,
        )
        .unwrap();
        assert_eq!(b["cron"], json!("0 * * * *"));
        assert_eq!(b["from"], json!("2026-12-01T01:00:00Z"));
        assert!(
            create_body(
                &json!({"prompt": "p", "at": "2026-11-01T00:00:00Z", "everySeconds": 3600}),
                now
            )
            .is_err()
        );
        assert!(
            create_body(
                &json!({"prompt": "p", "at": "tomorrow", "everySeconds": 3600}),
                now
            )
            .is_err()
        );
    }

    #[test]
    fn only_this_conversations_wakeups() {
        let list = json!({"schedules": [
            {"id": "sch_1", "conversationId": "c1", "state": "active", "prompt": "[wakeup \"a\"] x"},
            {"id": "sch_2", "conversationId": "c2", "state": "active", "prompt": "[wakeup \"a\"] x"},
            {"id": "sch_3", "conversationId": "c1", "state": "active", "prompt": "整理新聞"},
            {"id": "sch_4", "conversationId": "c1", "state": "done", "prompt": "[wakeup \"b\"] x"},
            {"id": "sch_5", "conversationId": "c1", "state": "paused", "prompt": "[wakeup \"c\"] y"}
        ]});
        let w: Vec<(&str, &str)> = wakeups(&list, "c1")
            .into_iter()
            .map(|(n, s)| (n, s["id"].as_str().unwrap()))
            .collect();
        assert_eq!(w, vec![("a", "sch_1"), ("c", "sch_5")]);
    }
}
