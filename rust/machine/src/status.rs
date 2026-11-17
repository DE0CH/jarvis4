//! The session's live status, reported by the machine itself: the supervisor runs a shell locally every 10 s and POSTs
//! the raw output to /m/status when it changed, and at least once a minute as a heartbeat; the router parses it
//! (router/registry.go). It prints claude's registry files, ai-title lines, background-job counts, the one-shot marker,
//! transcript ids ending on "Please run /login", the credentials file's expiry, refusal entries, the checked account of
//! an account switch, when Deyao last sent each conversation a prompt, then the subagent/background-job counts the
//! supervisor holds (workers.rs), and the keeper's harness record (starts, last end): never a token.

use crate::client::Client;
use crate::session::rescue_command;
use crate::{gojson, logf, util};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

pub const REG_CMD: &str = concat!(
    r#"for f in /home/claude/.claude/sessions/*.json; do cat "$f" 2>/dev/null; echo; done; echo __TITLES__; "#,
    r#"for f in /home/claude/.claude/projects/*/*.jsonl; do t=$(grep -h '"type":"ai-title"' "$f" 2>/dev/null | tail -1); [ -n "$t" ] && echo "$t"; done; "#,
    r#"echo __BG__; for f in /home/claude/.claude/sessions/*.json; do p=$(grep -o '"pid":[0-9]*' "$f" | head -1 | cut -d: -f2); [ -n "$p" ] && echo "$p $(pgrep -c -P "$p" -f shell-snapshots 2>/dev/null || echo 0)"; done; "#,
    r#"echo __ONESHOT__; cat /home/claude/.claude/.one-shot-done 2>/dev/null; "#,
    r#"echo __AUTH__; for f in $(ls -t /home/claude/.claude/projects/*/*.jsonl 2>/dev/null | head -3); do "#,
    r#"l=$(tail -c 400000 "$f" 2>/dev/null | grep '"type":"assistant"' | tail -1); "#,
    r#"case "$l" in *'"error":"authentication_failed"'*) "#,
    r#"echo "$(basename "$f" .jsonl) $(printf %s "$l" | grep -o '"uuid":"[^"]*"' | head -1 | cut -d'"' -f4)";; esac; done; "#,
    r#"echo __CREDS__; grep -o '"expiresAt":[0-9]*' /home/claude/.claude/.credentials.json 2>/dev/null | head -1 | cut -d: -f2; "#,
    r#"echo __REFUSAL__; for f in /home/claude/.claude/projects/*/*.jsonl; do grep -h -E '"stop_reason":"refusal"|"subtype":"model_refusal_fallback"' "$f" 2>/dev/null | tail -4; done; "#,
    r#"echo __ACCOUNT__; cat /home/claude/.claude/.jarvis-account 2>/dev/null; echo; "#,
    r#"echo __HUMAN__; for f in /home/claude/.claude/sessions/*.json; do s=$(grep -o '"sessionId":"[^"]*"' "$f" | head -1 | cut -d'"' -f4); "#,
    r#"[ -n "$s" ] || continue; t=$(tail -c 8000000 /home/claude/.claude/projects/*/"$s".jsonl 2>/dev/null | grep -F '"origin":{"kind":"human"}' | tail -1 | grep -o '"timestamp":"[^"]*"' | tail -1 | cut -d'"' -f4); "#,
    r#"echo "$s ${t:--}"; done; "#,
    r#"true"#
);

const STATUS_EVERY: Duration = Duration::from_secs(10);
const STATUS_HEARTBEAT: Duration = Duration::from_secs(60);
const STATUS_MAX_BYTES: usize = 256 << 10;

pub fn read_status() -> String {
    let (mut out, _) = util::output_timeout(rescue_command("bash", &["-c", REG_CMD]), STATUS_EVERY);
    // __WORKERS__: the subagent and background-job count per conversation, held by the supervisor (workers.rs)
    out.extend_from_slice(format!("__WORKERS__\n{}", crate::workers::report()).as_bytes());
    // __HARNESS__: the keeper's record of the harness: its starts, and how and when it last ended (keeper.rs)
    if let Some(h) = crate::keeper::read_harness_state() {
        out.extend_from_slice(format!("\n__HARNESS__\n{}\n", gojson::marshal(&h)).as_bytes());
    }
    out.truncate(STATUS_MAX_BYTES);
    String::from_utf8_lossy(&out).into_owned()
}

/// the supervisor's status loop (started once booted)
pub fn status_reporter(c: &Client) {
    let (mut last, mut last_title) = (String::new(), String::new());
    let mut sent: Option<Instant> = None;
    let titles = crate::apptitle::AppTitler::default(); // the Claude app's title of this session
    loop {
        let (raw, title) = (read_status(), titles.current());
        if !(raw == last
            && title == last_title
            && sent.is_some_and(|s| s.elapsed() < STATUS_HEARTBEAT))
        {
            let body = BTreeMap::from([("raw", raw.as_str()), ("appTitle", title.as_str())]);
            match c.json_ok("POST", "/m/status", Some(&body)) {
                Err(e) => logf!("status report failed: {e:#}"),
                Ok(()) => {
                    last = raw;
                    last_title = title;
                    sent = Some(Instant::now());
                }
            }
        }
        util::sleep(STATUS_EVERY);
    }
}
