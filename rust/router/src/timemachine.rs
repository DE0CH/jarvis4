//! The time machine (docs/PLAN-fabric.md, "Next: freeze and the time machine"): a fabric session waits frozen. The
//! machine asks with `time-machine <duration>` (POST /m/api/time-machine {seconds}); the router has the fabric hermit
//! freeze its sandbox until then (hermit pauses it in place; the repacking may later evict it to S3) and the session
//! becomes `frozen`, its machine kept. It comes back at the first of:
//!
//!   - the time: hermit thaws it itself at `until`, and the router sees it running again (frozen_loop);
//!   - anything that would resume a paused session: a delivery (a message, wakeup, cron, watch, an Inbox decision's
//!     outcome), the chat wanting a turn or an answer (hermit-jarvis resumes it), the app's Resume. Resume thaws a
//!     frozen session (thaw), so each of these needs nothing of its own.
//!
//! The machine's command waits through it all (it is frozen with the sandbox) and then reads why it came back
//! (GET /m/api/time-machine). Wakeups and crons stay as they are; the time machine is one more way to wait.
//! (timemachine.rs, ported with its later fixes: 4c8b49a0, 0e549d2e.)

use crate::http::Registrar;
use crate::router::Router;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use jarvis_nethttp::write_json;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// a frozen session's wait, and what ended its last one
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TimeMachine {
    pub since: GoTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<GoTime>,
    /// what brought it back ("the time", "a message", …); "" while frozen
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub why: String,
    /// when it was running again (the command's answer)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub back: Option<GoTime>,
}

pub const TIME_MACHINE_MAX: Duration = Duration::from_secs(30 * 24 * 3600);
/// a thaw may wait for a host and a restore from S3
pub const THAW_WAIT_MAX: Duration = Duration::from_secs(20 * 60);
pub const FROZEN_TICK_EVERY: Duration = Duration::from_secs(15);

/// a call to the fabric hermit as caller magpie (the router's pair): (status, body)
pub type HermitCallFn = fn(&str, &str, Option<&Value>) -> Result<(u16, Vec<u8>)>;

fn fabric_hermit_call_live(
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<(u16, Vec<u8>)> {
    let url = format!(
        "{}{path}",
        crate::router::env("FABRIC_HERMIT_URL", "").trim_end_matches('/')
    );
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut req = client
        .request(reqwest::Method::from_bytes(method.as_bytes())?, url)
        .header(
            "Authorization",
            format!(
                "Bearer {}",
                crate::router::env("FABRIC_HERMIT_MAGPIE_TOKEN", "")
            ),
        )
        .header("Aviary-Protocol", "hermit-core=1");
    if let Some(b) = body {
        req = req
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(b)?);
    }
    let resp = req.send()?;
    let st = resp.status().as_u16();
    Ok((
        st,
        crate::util::read_limited(resp, 64 << 10).unwrap_or_default(),
    ))
}

/// a seam for tests
pub static FABRIC_HERMIT_CALL: RwLock<HermitCallFn> = RwLock::new(fabric_hermit_call_live);

fn hermit_call(method: &str, path: &str, body: Option<&Value>) -> Result<(u16, Vec<u8>)> {
    let f = *FABRIC_HERMIT_CALL.read().unwrap_or_else(|e| e.into_inner());
    f(method, path, body)
}

/// the conversation's sandbox state at the fabric hermit ("" when it has none)
pub fn hermit_sandbox_state(conversation: &str) -> Result<String> {
    let (code, b) = hermit_call(
        "GET",
        &format!("/v1/conversations/{conversation}/sandbox"),
        None,
    )?;
    if code == 404 {
        return Ok(String::new());
    }
    if code / 100 != 2 {
        return Err(anyhow!(
            "hermit: HTTP {code} {}",
            String::from_utf8_lossy(&b).trim()
        ));
    }
    let v: Value = serde_json::from_slice(&b).map_err(|e| anyhow!("hermit: {e}"))?;
    // Go's json.Unmarshal into struct{ State string } matches the key case-insensitively
    let state = v
        .as_object()
        .and_then(|o| {
            o.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("state"))
                .map(|(_, v)| v)
        })
        .and_then(Value::as_str)
        .unwrap_or_default();
    Ok(state.to_string())
}

/// what a delivery of this kind is, in the command's words
pub fn time_machine_why(kind: &str) -> String {
    match kind {
        "wakeup" => "a scheduled wakeup".into(),
        "cron" => "a cron run".into(),
        "watch" | "watch-fail" => "a watch".into(),
        "request-outcome" => "a decision on an Inbox request".into(),
        "peer" => "a message from another session".into(),
        "resume-prompt" => "a message from Deyao".into(),
        _ => format!("a message ({kind})"),
    }
}

/// a frozen session whose sandbox hermit runs again is back (hermit thawed it at its until); one hermit no longer has
/// is lost to the time machine and goes as a lost machine does: (back, lost)
pub fn frozen_verdict(hermit_state: &str) -> (bool, bool) {
    match hermit_state {
        "ready" => (true, false),
        "" | "gone" => (false, true),
        _ => (false, false),
    }
}

/// hermit resumes the conversation's frozen sandbox; it returns once hermit has it ready
pub fn thaw_sandbox(conv: &str) -> Result<()> {
    thaw_sandbox_within(conv, THAW_WAIT_MAX, Duration::from_secs(3))
}

pub fn thaw_sandbox_within(conv: &str, wait_max: Duration, every: Duration) -> Result<()> {
    let path = format!("/v1/conversations/{conv}/sandbox/thaw");
    let (code, b) = hermit_call("POST", &path, None)?;
    if code / 100 != 2 {
        return Err(anyhow!(
            "the fabric would not thaw it: HTTP {code} {}",
            String::from_utf8_lossy(&b).trim()
        ));
    }
    let deadline = Instant::now() + wait_max;
    loop {
        let st = hermit_sandbox_state(conv);
        if let Ok(st) = &st {
            if st == "ready" {
                return Ok(());
            }
            if st == "frozen" {
                // a freeze that finished after the first thaw: ask again
                let _ = hermit_call("POST", &path, None);
            }
            if st.is_empty() || st == "gone" || st == "releasing" {
                return Err(anyhow!(
                    "the session's sandbox is {} at the fabric: it could not come back",
                    crate::flows::or_state(st)
                ));
            }
        }
        if Instant::now() > deadline {
            return Err(anyhow!(
                "the session is not back after {}",
                jarvis_go::fmt::duration_string(wait_max)
            ));
        }
        std::thread::sleep(every);
    }
}

impl Router {
    /// the session goes into the time machine for `d` (the machine's own ask)
    pub fn freeze(&self, sid: &str, d: Duration) -> Result<TimeMachine> {
        if !crate::fabricrunner::fabric_enabled() {
            return Err(anyhow!(
                "the time machine needs the fabric, and this router has none"
            ));
        }
        if d.is_zero() || d > TIME_MACHINE_MAX {
            return Err(anyhow!(
                "a time between a second and {}, please",
                jarvis_go::fmt::duration_string(TIME_MACHINE_MAX)
            ));
        }
        let (state, runner, conv) = self.st.read(|p| {
            p.sessions
                .get(sid)
                .map(|s| {
                    (
                        s.state.clone(),
                        s.runner.clone(),
                        s.fabric
                            .as_ref()
                            .map(|f| f.conversation.clone())
                            .unwrap_or_default(),
                    )
                })
                .unwrap_or_default()
        });
        if runner != "fabric" || conv.is_empty() {
            return Err(anyhow!(
                "only a session on the fabric (gVisor) has the time machine"
            ));
        }
        if state != "started" {
            return Err(anyhow!(
                "the session is {}, not running",
                crate::flows::or_state(&state)
            ));
        }
        let until = GoTime::now().add_std(d).utc();
        let (code, b) = hermit_call(
            "POST",
            &format!("/v1/conversations/{conv}/sandbox/freeze"),
            Some(&json!({"until": until.rfc3339_nano()})),
        )?;
        if code / 100 != 2 {
            return Err(anyhow!(
                "the fabric would not freeze it: HTTP {code} {}",
                String::from_utf8_lossy(&b).trim()
            ));
        }
        let tm = TimeMachine {
            since: GoTime::now().utc(),
            until: Some(until),
            ..Default::default()
        };
        self.st.do_(|p| {
            if let Some(s) = p.sessions.get_mut(sid)
                && s.state == "started"
            {
                s.state = "frozen".into();
                s.time_machine = Some(tm.clone());
            }
        });
        crate::logf!("[time-machine] {sid} frozen until {}", until.rfc3339());
        Ok(tm)
    }

    /// a frozen session comes back (hermit resumes it in place, or restores it from S3 on any host), and is `started`
    /// again once hermit has it running; why is what the machine's command reports
    pub fn thaw(&self, sid: &str, why: &str) -> Result<()> {
        let (conv, state) = self.st.read(|p| {
            p.sessions
                .get(sid)
                .map(|s| {
                    (
                        s.fabric
                            .as_ref()
                            .map(|f| f.conversation.clone())
                            .unwrap_or_default(),
                        s.state.clone(),
                    )
                })
                .unwrap_or_default()
        });
        if state != "frozen" {
            return Ok(());
        }
        crate::logf!("[time-machine] {sid} thawing ({why})");
        thaw_sandbox(&conv)?;
        self.back(sid, why);
        Ok(())
    }

    /// a fabric session the time machine has not brought back, and its conversation. Its state may have moved on from
    /// `frozen` (a pause or destroy under way sets `pausing` first), its record has not.
    pub fn frozen_conversation(&self, sid: &str) -> Option<String> {
        self.st.read(|p| {
            let s = p.sessions.get(sid)?;
            let f = s.fabric.as_ref()?;
            let tm = s.time_machine.as_ref()?;
            tm.back.is_none().then(|| f.conversation.clone())
        })
    }

    /// the frozen session runs again: its time machine says why, and a session still `frozen` is `started` (one a
    /// pause or destroy has moved on keeps that state)
    pub fn back(&self, sid: &str, why: &str) {
        let now = GoTime::now().utc();
        self.st.do_(|p| {
            let Some(s) = p.sessions.get_mut(sid) else {
                return;
            };
            if s.state == "frozen" {
                s.state = "started".into();
                if s.time_machine.is_none() {
                    s.time_machine = Some(TimeMachine {
                        since: now,
                        ..Default::default()
                    });
                }
            }
            if let Some(tm) = s.time_machine.as_mut()
                && tm.back.is_none()
            {
                tm.why = why.to_string();
                tm.back = Some(now);
            }
        });
        crate::logf!("[time-machine] {sid} back ({why})");
    }

    /// one pass of frozen_loop: each frozen session hermit runs again is back, one hermit no longer has is failed
    pub fn frozen_tick(&self) {
        let all: Vec<(String, String)> = self.st.read(|p| {
            p.sessions
                .iter()
                .filter(|(_, s)| s.state == "frozen")
                .filter_map(|(id, s)| {
                    s.fabric
                        .as_ref()
                        .map(|f| (id.clone(), f.conversation.clone()))
                })
                .collect()
        });
        for (id, conv) in all {
            let Ok(st) = hermit_sandbox_state(&conv) else {
                continue;
            };
            match frozen_verdict(&st) {
                (true, _) => self.back(&id, "the time"),
                (_, true) => {
                    self.st.do_(|p| {
                        if let Some(s) = p.sessions.get_mut(&id)
                            && s.state == "frozen"
                        {
                            s.state = "failed".into();
                            s.error = "its frozen sandbox is gone from the fabric (Resume starts it from its files)"
                                .into();
                            s.failed_at = Some(GoTime::now());
                        }
                    });
                    crate::logf!("[time-machine] {id}: its frozen sandbox is gone at the fabric");
                }
                _ => {}
            }
        }
    }

    pub fn frozen_loop(self: &Arc<Self>) {
        if !crate::fabricrunner::fabric_enabled() {
            return;
        }
        loop {
            std::thread::sleep(FROZEN_TICK_EVERY);
            self.frozen_tick();
        }
    }

    fn time_machine_view(&self, sid: &str) -> Option<Value> {
        self.st.read(|p| {
            let s = p.sessions.get(sid)?;
            let mut out = json!({"frozen": s.state == "frozen"});
            if let Some(tm) = &s.time_machine {
                out["since"] = json!(tm.since);
                out["until"] = json!(tm.until);
                out["why"] = json!(tm.why);
                out["back"] = json!(tm.back);
            }
            Some(out)
        })
    }
}

pub fn register_time_machine(reg: &mut Registrar) {
    reg.m("POST /m/api/time-machine", |r, w, _, machine, body| {
        let sid = match r.machine_session(machine) {
            Ok(s) => s,
            Err(e) => return write_json(w, 403, &json!({"error": e.to_string()})),
        };
        #[derive(Deserialize)]
        struct In {
            seconds: i64,
        }
        let Ok(input) = serde_json::from_slice::<In>(body) else {
            return write_json(w, 400, &json!({"error": "a body {seconds}"}));
        };
        let d = Duration::from_secs(u64::try_from(input.seconds).unwrap_or(0));
        match r.freeze(&sid, d) {
            Ok(tm) => write_json(w, 202, &json!({"frozen": true, "until": tm.until})),
            Err(e) => write_json(w, 409, &json!({"error": e.to_string()})),
        }
    });
    reg.m("GET /m/api/time-machine", |r, w, _, machine, _| {
        let sid = match r.machine_session(machine) {
            Ok(s) => s,
            Err(e) => return write_json(w, 403, &json!({"error": e.to_string()})),
        };
        match r.time_machine_view(&sid) {
            Some(v) => write_json(w, 200, &v),
            None => write_json(w, 404, &json!({"error": "no such session"})),
        }
    });
}
