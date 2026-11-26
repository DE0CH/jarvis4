//! The AWS machines' logs to Grafana Cloud (docs/PLAN-aws.md "Logs"), next to what the Fly app jarvis2-log-shipper
//! ships of the Fly machines. An EC2 instance's output reaches Grafana from two places, both through the router, which
//! names the machine:
//!   - the machine's own output (source "machine", and "journal" with the kernel's journal bind): POST
//!     /m/machine-output, signed by the machine's certified key, so the instance id on the lines is the router's word;
//!   - the instance's serial console (source "console"), read by the leader every CONSOLE_EVERY with the router's
//!     read-only key (GetConsoleOutput, awsread.rs).
//!
//! Every line goes to the shipper (AWS_LOG_SHIPPER_URL: Alloy with the secret-shape redaction, which holds the Grafana
//! write token and labels everything box="aws"); the router labels each stream with instance, aws_region, session and
//! source.

use crate::http::Registrar;
use crate::router::Router;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use jarvis_nethttp::write_json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

/// lines held for the shipper; past it the oldest go (counted)
pub const AWS_LOG_QUEUE_MAX: usize = 50000;
/// lines per push
pub const AWS_LOG_BATCH: usize = 2000;
/// bytes per line (clipped)
pub const AWS_LOG_LINE_MAX: usize = 4000;
/// lines per machine push
pub const MACHINE_OUT_LINES: usize = 500;
pub const AWS_LOG_EVERY: Duration = Duration::from_secs(2);
pub const CONSOLE_EVERY: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct AwsLogLine {
    /// the stream's labels, canonical JSON
    pub labels: String,
    pub at_nanos: i128,
    pub text: String,
}

#[derive(Default)]
pub struct AwsLogQueue {
    pub lines: Vec<AwsLogLine>,
    pub dropped: usize,
    pub url: Option<String>,
    pub failing: bool,
}

pub static AWS_LOGS: LazyLock<Mutex<AwsLogQueue>> =
    LazyLock::new(|| Mutex::new(AwsLogQueue::default()));

/// the labels of one machine's stream (box="aws" is the shipper's)
pub fn aws_log_labels(instance: &str, region: &str, session: &str, source: &str) -> String {
    let mut l: BTreeMap<&str, &str> = [("instance", instance), ("source", source)]
        .into_iter()
        .collect();
    if !region.is_empty() {
        l.insert("aws_region", region);
    }
    if !session.is_empty() {
        l.insert("session", session);
    }
    jarvis_go::marshal(&l) // keys sorted: the same set, the same string
}

/// the shipper (AWS_LOG_SHIPPER_URL; "" = none)
pub fn shipper_url() -> String {
    queue_url(&mut AWS_LOGS.lock().unwrap_or_else(|e| e.into_inner()))
}

fn queue_url(q: &mut AwsLogQueue) -> String {
    q.url
        .get_or_insert_with(|| std::env::var("AWS_LOG_SHIPPER_URL").unwrap_or_default())
        .clone()
}

/// lines of one stream into the queue (nothing when no shipper is configured)
pub fn ship(labels: &str, at: &[i128], texts: &[String]) {
    let mut q = AWS_LOGS.lock().unwrap_or_else(|e| e.into_inner());
    if queue_url(&mut q).is_empty() {
        return;
    }
    for (i, t) in texts.iter().enumerate() {
        let t = if t.len() > AWS_LOG_LINE_MAX {
            format!("{}…", jarvis_go::fmt::clip_bytes(t, AWS_LOG_LINE_MAX))
        } else {
            t.clone()
        };
        q.lines.push(AwsLogLine {
            labels: labels.into(),
            at_nanos: at[i],
            text: t,
        });
    }
    let over = q.lines.len().saturating_sub(AWS_LOG_QUEUE_MAX);
    if over > 0 {
        q.lines.drain(..over);
        q.dropped += over;
    }
}

/// the lines as Loki's push API JSON, one stream per label set, each in time order
pub fn loki_push(lines: &[AwsLogLine]) -> Result<String> {
    #[derive(Serialize)]
    struct Stream {
        stream: BTreeMap<String, String>,
        values: Vec<[String; 2]>,
    }
    let mut order: Vec<String> = vec![];
    let mut by: BTreeMap<String, (Stream, Vec<(i128, String)>)> = BTreeMap::new();
    for l in lines {
        if !by.contains_key(&l.labels) {
            let st: BTreeMap<String, String> = serde_json::from_str(&l.labels)?;
            by.insert(
                l.labels.clone(),
                (
                    Stream {
                        stream: st,
                        values: vec![],
                    },
                    vec![],
                ),
            );
            order.push(l.labels.clone());
        }
        if let Some(s) = by.get_mut(&l.labels) {
            s.1.push((l.at_nanos, l.text.clone()));
        }
    }
    let mut streams = vec![];
    for k in order {
        let Some((mut s, mut vals)) = by.remove(&k) else {
            continue;
        };
        vals.sort_by_key(|v| v.0); // stable
        s.values = vals.into_iter().map(|(t, x)| [t.to_string(), x]).collect();
        streams.push(s);
    }
    Ok(jarvis_go::marshal(&json!({"streams": streams})))
}

/// up to AWS_LOG_BATCH queued lines to the shipper as one Loki push; kept for the next round when it fails
pub fn push_once() -> Result<()> {
    let (batch, n, dropped, url) = {
        let mut q = AWS_LOGS.lock().unwrap_or_else(|e| e.into_inner());
        let n = q.lines.len().min(AWS_LOG_BATCH);
        let batch: Vec<AwsLogLine> = q.lines[..n].to_vec();
        let dropped = q.dropped;
        q.dropped = 0;
        let url = queue_url(&mut q);
        (batch, n, dropped, url)
    };
    if n == 0 && dropped == 0 {
        return Ok(());
    }
    let mut batch = batch;
    if dropped > 0 {
        batch.push(AwsLogLine {
            labels: aws_log_labels("router", "", "", "router"),
            at_nanos: GoTime::now().unix_nanos(),
            text: format!("[router] {dropped} AWS machine log lines dropped: the shipper didn't take them in time"),
        });
    }
    let res = loki_push(&batch).and_then(|body| {
        let resp = reqwest::blocking::Client::new()
            .post(&url)
            .timeout(Duration::from_secs(30))
            .header("Content-Type", "application/json")
            .body(body)
            .send()?;
        if resp.status().as_u16() / 100 != 2 {
            return Err(anyhow!(
                "the shipper answered HTTP {}",
                resp.status().as_u16()
            ));
        }
        Ok(())
    });
    let mut q = AWS_LOGS.lock().unwrap_or_else(|e| e.into_inner());
    match res {
        Err(e) => {
            q.dropped += dropped;
            if !q.failing {
                crate::logf!("[aws-logs] push: {e:#} (kept, tried again)");
            }
            q.failing = true;
            Err(e)
        }
        Ok(()) => {
            if q.failing {
                crate::logf!("[aws-logs] the shipper takes lines again");
            }
            q.failing = false;
            let k = n.min(q.lines.len());
            q.lines.drain(..k);
            Ok(())
        }
    }
}

impl Router {
    /// the queue to the shipper, on every replica (each ships what its machines pushed to it)
    pub fn aws_log_loop(self: &Arc<Self>) {
        loop {
            std::thread::sleep(AWS_LOG_EVERY);
            while push_once().is_ok() {
                let more = AWS_LOGS
                    .lock()
                    .map(|q| !q.lines.is_empty())
                    .unwrap_or(false);
                if !more {
                    break;
                }
            }
        }
    }

    /// each live session instance's new console lines to the shipper, and the notable ones (an OOM kill, a panic,
    /// Ignition failing, the power-off) into the session's running lifecycle operation. Only on the leader.
    pub fn console_tick(self: &Arc<Self>) {
        if !crate::awsread::aws_read_on() || shipper_url().is_empty() {
            return;
        }
        let mut st = CONSOLE.lock().unwrap_or_else(|e| e.into_inner());
        if st
            .off_until
            .as_ref()
            .is_some_and(|t| GoTime::now().before(t))
        {
            return;
        }
        let live: BTreeMap<String, String> = crate::awsrunner::aws_seen()
            .into_iter()
            .filter(|(_, i)| matches!(i.state.as_str(), "created" | "started" | "destroying"))
            .map(|(id, i)| (id, i.region))
            .collect();
        st.reads.retain(|id, _| live.contains_key(id)); // gone: EC2 keeps no console of a terminated instance
        drop(st);
        for (id, region) in live {
            let out = match crate::awsread::aws_console(&region, &id) {
                Ok(o) => o,
                Err(e) => {
                    if e.downcast_ref::<crate::awsread::Ec2ReadError>()
                        .is_some_and(|x| x.code == "UnauthorizedOperation")
                    {
                        if let Ok(mut g) = CONSOLE.lock() {
                            g.off_until = Some(GoTime::now().add(time::Duration::minutes(10)));
                        }
                        crate::logf!(
                            "[aws-logs] the read key may not GetConsoleOutput (infra/aws/iam.tf jarvis4-router-read): no console lines for 10 min"
                        );
                        return;
                    }
                    continue;
                }
            };
            let lines = {
                let mut g = CONSOLE.lock().unwrap_or_else(|e| e.into_inner());
                let prev = g.reads.entry(id.clone()).or_default();
                let (lines, next) = console_new(prev, &out);
                *prev = next;
                lines
            };
            if lines.is_empty() {
                continue;
            }
            let session = self
                .st
                .do_(|d| d.machines.get(&id).cloned().unwrap_or_default());
            let now = GoTime::now().unix_nanos();
            let n = lines.len() as i128;
            let ats: Vec<i128> = (0..n).map(|i| now + (i - n) * 1000).collect(); // one read, its lines in order
            ship(
                &aws_log_labels(&id, &region, &session, "console"),
                &ats,
                &lines,
            );
            if session.is_empty() {
                continue;
            }
            if let Some(h) = self.lc_current(&session) {
                for l in &lines {
                    if CONSOLE_NOTABLE_RE.is_match(l) && !l.contains(KEYS_LINE_MARK) {
                        h.add(crate::lifecycle::LcEntry {
                            at: GoTime::now().rfc3339_nano(),
                            source: "aws".into(),
                            machine: id.clone(),
                            text: format!("AWS console: {l}"),
                        });
                    }
                }
            }
        }
    }

    /// console_tick every CONSOLE_EVERY on the replica holding the scheduler's lease
    pub fn console_loop(self: &Arc<Self>) {
        loop {
            std::thread::sleep(CONSOLE_EVERY);
            if crate::leaderlease::leads() {
                self.console_tick();
            }
        }
    }
}

#[derive(Default)]
struct ConsoleState {
    /// by instance: the console's text up to the end of its last shipped line, as the newest read had it
    reads: BTreeMap<String, String>,
    /// GetConsoleOutput refused (the read key without it): not asked again until then
    off_until: Option<GoTime>,
}

static CONSOLE: LazyLock<Mutex<ConsoleState>> =
    LazyLock::new(|| Mutex::new(ConsoleState::default()));

/// tests: the console reads start over
#[cfg(test)]
pub fn console_reset() {
    *CONSOLE.lock().unwrap_or_else(|e| e.into_inner()) = ConsoleState::default();
}

/// tests: the console reads are off (a refusal) until then
#[cfg(test)]
pub fn console_off_until() -> Option<GoTime> {
    CONSOLE.lock().unwrap_or_else(|e| e.into_inner()).off_until
}

/// the machine's keys line on the console (rust/kernel/src/spawner keysMark): shipped, never a lifecycle entry
pub const KEYS_LINE_MARK: &str = "JARVIS2-KEYS ";

static CONSOLE_ANSI_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\x1b(\[[0-9;?=]*[ -/]*[@-~]|\][^\x07\x1b]*(\x07|\x1b\\)|P[^\x1b]*\x1b\\|[()][0-9A-Za-z]|[=>78DEHMc])")
        .unwrap_or_else(|e| panic!("{e}"))
});
static CONSOLE_CTRL_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"[\x00-\x08\x0b-\x1f\x7f]").unwrap_or_else(|e| panic!("{e}"))
});
static CONSOLE_NOTABLE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)out of memory|oom-kill|killed process|kernel panic|call trace|ignition.*(fail|error)|segfault|hung_task|blocked for more than|\breboot: |EXT4-fs error|I/O error|JARVIS4-SESSION-END")
        .unwrap_or_else(|e| panic!("{e}"))
});

/// a console line without its terminal escapes, carriage returns and control bytes
pub fn clean_console(l: &str) -> String {
    let mut l = CONSOLE_ANSI_RE.replace_all(l, "").into_owned();
    if let Some(i) = l.rfind('\r')
        && !l[i + 1..].trim().is_empty()
    {
        l = l[i + 1..].to_string(); // a line written over: what shows
    }
    CONSOLE_CTRL_RE.replace_all(&l, "").trim().to_string()
}

/// the complete lines of out that follow what was shipped (prev), and the new prev. EC2 gives the newest 64 KB, so the
/// window slides: prev's last bytes are looked for in out; not there (more than 64 KB came between two reads),
/// everything in out is new.
pub fn console_new(prev: &str, out: &str) -> (Vec<String>, String) {
    let mut rest = out;
    if !prev.is_empty() {
        if let Some(r) = out.strip_prefix(prev) {
            rest = r;
        } else {
            let mut a = prev.len().saturating_sub(1024);
            while !prev.is_char_boundary(a) {
                a += 1;
            }
            let anchor = &prev[a..];
            if let Some(i) = out.rfind(anchor) {
                rest = &out[i + anchor.len()..];
            } else if prev.contains(out) || prev.ends_with(out.trim_end_matches('\n')) {
                return (vec![], prev.to_string()); // nothing new (an older read came back)
            }
        }
    }
    let Some(cut) = rest.rfind('\n') else {
        return (vec![], prev.to_string()); // only part of a line so far
    };
    let shipped_to = out.len() - rest.len() + cut + 1;
    let lines = rest[..cut]
        .split('\n')
        .map(clean_console)
        .filter(|l| !l.is_empty())
        .collect();
    (lines, out[..shipped_to].to_string())
}

pub fn register_machine_output(reg: &mut Registrar) {
    // POST /m/machine-output {"source":"machine"|"journal","lines":[{"at","text"}]}: an AWS machine's output
    reg.m("POST /m/machine-output", |r, w, _, machine, body| {
        if r.runner_of_machine(machine) != "aws" {
            jarvis_nethttp::write_error(w, 404, "only an AWS machine pushes its output: Fly ships its machines' (jarvis2-log-shipper)");
            return;
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct L {
            at: String,
            text: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            source: String,
            lines: Vec<L>,
        }
        let mut i: In = match jarvis_go::unmarshal(body) {
            Ok(i) => i,
            Err(e) => {
                jarvis_nethttp::write_error(w, 400, &format!("not JSON: {e}"));
                return;
            }
        };
        if i.source.is_empty() {
            i.source = "machine".into();
        }
        if i.source != "machine" && i.source != "journal" {
            jarvis_nethttp::write_error(w, 400, r#"source: "machine" or "journal""#);
            return;
        }
        if i.lines.len() > MACHINE_OUT_LINES {
            jarvis_nethttp::write_error(w, 400, &format!("at most {MACHINE_OUT_LINES} lines per push"));
            return;
        }
        let session = r.st.do_(|d| d.machines.get(machine).cloned().unwrap_or_default());
        let now = GoTime::now();
        let (lo, hi) = (now.add(time::Duration::hours(-24)), now.add(time::Duration::minutes(1)));
        let ats: Vec<i128> = i
            .lines
            .iter()
            .map(|l| match GoTime::parse(&l.at) {
                Some(t) if !t.after(&hi) && !t.before(&lo) => t.unix_nanos(),
                _ => now.unix_nanos(), // a machine clock off by a lot: the router's time
            })
            .collect();
        let texts: Vec<String> = i.lines.into_iter().map(|l| l.text).collect();
        ship(
            &aws_log_labels(machine, &crate::awsrunner::aws_region_of_instance(machine), &session, &i.source),
            &ats,
            &texts,
        );
        write_json(w, 200, &json!({"ok": true}));
    });
}
