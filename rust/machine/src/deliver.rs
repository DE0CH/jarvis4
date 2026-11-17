//! Inputs Jarvis 4 delivers into a running session after it started (docs/DESIGN.md "Inputs to a machine"): a
//! wakeup's or cron's prompt, a "continue" after a re-login (the 15-minute watchdog is the supervisor's own,
//! stall.rs). Each arrives in /m/commands as a delivery and is taken only when it is
//!
//!   - vouched for: a wakeup or cron is the session's OWN request (the machine-signed POST the session made to
//!     /m/api/sessions/<id>/wakeup or /crons, which the router keeps as it was), checked against this line's signing
//!     keys (the line-keys file: every machine of the line adds its key; it travels in the signed snapshot); the
//!     "continue" and the other notes are texts built into this image, so the router chooses only when, never what;
//!   - and logged: it carries the core's attestation over (this machine, the kind, the sha256 of the input), so every
//!     input is in the core's hash-chained input log (core/audit.go).
//!
//! A delivery missing either is refused, and so is one into a session holding a sensitive store that the phone didn't
//! approve (messages.rs). The machine sends the text into the harness itself; the router never runs a command for it.

use crate::cert::{Cert, cert_mode};
use crate::client::Client;
use crate::crypto::{SignedDoc, sha256_hex, verify, verify_doc};
use crate::harnesses::via_harness_send;
use crate::messages::ApprovalError;
use crate::outcomes::OutcomeItem;
use crate::peer::PeerNote;
use crate::session::session_command;
use crate::util::{fields_join, go_quote};
use crate::{gojson, logf, paths, re, util};
use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::process::Stdio;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// this line's machines' signing keys (relative to $HOME; in the snapshot's paths)
pub const LINE_KEYS_FILE: &str = ".jarvis2-line-keys.json";
/// what this line's own requests have already delivered (relative to $HOME; in the snapshot's paths, so a successor
/// knows too): a one-time wakeup's request once, a cron's request once per run, in order and no faster than half its
/// period (R1 audit: the router kept a signed request and could deliver it again and again)
pub const DELIVERED_FILE: &str = ".jarvis2-delivered.json";

static LINE_KEYS_MU: Mutex<()> = Mutex::new(());
static DELIVERED_MU: Mutex<()> = Mutex::new(());
/// held by deliver from the replay check to the record
static DELIVER_ORDER_MU: Mutex<()> = Mutex::new(());

/// set by prepare from the predecessor's core-signed cert
pub static PREDECESSOR_KEY: Mutex<String> = Mutex::new(String::new());
/// set by restore_archived
pub static RESTORED_ARCHIVE: AtomicBool = AtomicBool::new(false);

fn lock(m: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// the delivered file's lock (messages.rs and outcomes.rs write it too)
pub fn delivered_lock() -> std::sync::MutexGuard<'static, ()> {
    lock(&DELIVERED_MU)
}

pub fn read_line_keys() -> Vec<String> {
    std::fs::read(paths::home().join(LINE_KEYS_FILE))
        .ok()
        .and_then(|b| gojson::unmarshal::<Vec<String>>(&b).ok())
        .unwrap_or_default()
}

pub fn add_line_key(k: &str) {
    if k.is_empty() {
        return;
    }
    let _g = lock(&LINE_KEYS_MU);
    let mut keys = read_line_keys();
    if keys.iter().any(|x| x == k) {
        return;
    }
    keys.push(k.to_string());
    let _ = util::write_file(
        &paths::home().join(LINE_KEYS_FILE),
        gojson::marshal(&keys).as_bytes(),
        0o600,
    );
}

/// At boot, after the predecessor's verified snapshot (which carried the file) is restored. A new line's first machine
/// starts the file (an archived restore brings the old line's keys: the phone approved that snapshot). Also the
/// predecessor's own key, from its core-signed cert.
pub fn trust_line_keys(cert: &Cert) {
    if cert.pred_id.is_empty() && !RESTORED_ARCHIVE.load(Ordering::SeqCst) {
        let _ = std::fs::remove_file(paths::home().join(LINE_KEYS_FILE));
    }
    let pk = PREDECESSOR_KEY
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    if !pk.is_empty() {
        add_line_key(&pk);
    }
    if let Some(m) = &cert.machine {
        add_line_key(&m.signing_key);
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(default)]
struct Delivered {
    run: i64,
    /// unix seconds
    at: i64,
}

/// check AND record (tests, and any caller with nothing to do between)
pub fn not_replayed(d: &Delivery, now: i64) -> Result<()> {
    replay_guard(d, now, true)
}

/// Refuse a delivery already made; with record, also mark it made. deliver checks first, sends into the harness, and
/// records only after the harness took it (a resumed session's harness still booting answers "target session not
/// found", the router tries again, and that retry must not find the wakeup already burned).
pub fn replay_guard(d: &Delivery, now: i64, record: bool) -> Result<()> {
    if d.kind == "request-outcome" && d.request.is_some() {
        return crate::outcomes::outcome_not_replayed(d, now, record);
    }
    let Some(req) = &d.request else { return Ok(()) };
    if !matches!(d.kind.as_str(), "wakeup" | "cron" | "watch" | "watch-fail") {
        return Ok(());
    }
    let _g = lock(&DELIVERED_MU);
    let p = paths::home().join(DELIVERED_FILE);
    let mut seen: std::collections::BTreeMap<String, Delivered> = std::fs::read(&p)
        .ok()
        .and_then(|b| gojson::unmarshal(&b).ok())
        .unwrap_or_default();
    let key = if d.kind.starts_with("watch") {
        format!("watch {}", req.sig) // met or given up: one of the two, once
    } else {
        format!("{} {}", d.kind, req.sig)
    };
    let last = seen.get(&key).copied();
    if d.kind == "wakeup" && last.is_some() {
        bail!("this wakeup was already delivered");
    }
    if key.starts_with("watch ") && last.is_some() {
        bail!("this watch was already delivered");
    }
    if d.kind == "cron"
        && let Some(last) = last
    {
        let mut every: i64 = 24 * 60 * 60;
        if let Ok(body) = B64.decode(&req.body)
            && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body)
            // a float: the router takes 1800.0, and an int64 refused it (2026-11-17)
            && let Some(e) = v.get("everySeconds").and_then(|x| x.as_f64())
            && e > 0.0
        {
            every = (e as i64).max(15 * 60);
        }
        if d.run <= last.run {
            bail!(
                "cron run {} was already delivered (last {})",
                d.run,
                last.run
            );
        }
        if now - last.at < every / 2 {
            bail!("this cron ran less than half its period ago");
        }
    }
    if !record {
        return Ok(());
    }
    seen.insert(
        key,
        Delivered {
            run: d.run,
            at: now,
        },
    );
    if seen.len() > 2000 {
        // keep the newest
        let mut all: Vec<(String, Delivered)> = seen.into_iter().collect();
        all.sort_by_key(|x| std::cmp::Reverse(x.1.at));
        all.truncate(2000);
        seen = all.into_iter().collect();
    }
    util::write_file(&p, gojson::marshal(&seen).as_bytes(), 0o600)?;
    Ok(())
}

/// a request this line's machine made to the router, exactly as signed (Client::raw)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SignedRequest {
    pub machine: String,
    pub method: String,
    pub path: String,
    pub at: String,
    /// base64
    pub body: String,
    pub sig: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Delivery {
    pub id: String,
    /// wakeup | cron | watch | watch-fail | continue | upgraded | lease-* | request-outcome | peer | resume-prompt
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<SignedRequest>,
    /// a cron's run number
    #[serde(skip_serializing_if = "is_zero")]
    pub run: i64,
    /// a granted lease's length
    #[serde(skip_serializing_if = "is_zero")]
    pub minutes: i64,
    /// upgraded: the old size (small | medium | large)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub from: String,
    /// upgraded: the new size
    #[serde(skip_serializing_if = "String::is_empty")]
    pub to: String,
    /// a lease: the device (a lease name)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub device: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub handover: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub interrupted: bool,
    /// request-outcome (outcomes.rs): the decided items of this session's own filing (request)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub outcomes: Vec<OutcomeItem>,
    /// peer (peer.rs): another session's message, with its verified sender and direction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<PeerNote>,
    /// resume-prompt: Deyao's words from the app, delivered only under the phone's approval of exactly them
    #[serde(skip_serializing_if = "String::is_empty")]
    pub text: String,
    /// messages.rs: the phone's approval of this message (a batch it is in, or a rule for its kind)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<SignedDoc>,
    /// render the text and answer it; nothing is checked against the core, sent or recorded
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub preview: bool,
    pub attest: Option<SignedDoc>,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// the body of a request one of this line's machines signed (a wakeup or cron it asked for)
pub fn own_request_body(r: Option<&SignedRequest>, keys: &[String]) -> Result<Vec<u8>> {
    let r = r.ok_or_else(|| anyhow!("no request"))?;
    let body = B64.decode(&r.body).map_err(|_| anyhow!("bad body"))?;
    let payload = format!("{} {} {} {}", r.method, r.path, r.at, sha256_hex(&body));
    if keys.iter().any(|k| verify(k, payload.as_bytes(), &r.sig)) {
        return Ok(body);
    }
    bail!("not signed by a machine of this line")
}

/// the text a delivery puts into the harness, and the bytes the core attested
pub fn delivery_text(d: &Delivery, keys: &[String]) -> Result<(String, Vec<u8>)> {
    match d.kind.as_str() {
        "wakeup" | "cron" => {
            let body = own_request_body(d.request.as_ref(), keys)?;
            let r = d.request.as_ref().ok_or_else(|| anyhow!("no request"))?;
            let want = if d.kind == "wakeup" {
                "/wakeup"
            } else {
                "/crons"
            };
            if r.method != "POST"
                || !r.path.starts_with("/m/api/sessions/")
                || !(r.path.ends_with(want) || (d.kind == "wakeup" && r.path.ends_with("/wakeups")))
            {
                bail!("the signed request isn't a {}", d.kind);
            }
            let v: serde_json::Value = serde_json::from_slice(&body)
                .map_err(|_| anyhow!("the signed request has no prompt"))?;
            let prompt = match v.get("prompt") {
                None | Some(serde_json::Value::Null) => String::new(),
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(_) => bail!("the signed request has no prompt"),
            };
            if prompt.trim().is_empty() {
                bail!("the signed request has no prompt");
            }
            let mut name = match v.get("name") {
                None | Some(serde_json::Value::Null) => String::new(),
                Some(n) => util::go_sprint(n).trim().to_string(),
            };
            if name.is_empty() {
                name = "default".into();
            }
            let prompt = fields_join(&prompt);
            if d.kind == "wakeup" {
                if name == "default" {
                    return Ok((prompt, body));
                }
                return Ok((
                    format!("[scheduled wakeup {}] {prompt}", go_quote(&name)),
                    body,
                ));
            }
            Ok((
                format!(
                    "[recurring wakeup {} — run {}] {prompt}",
                    go_quote(&name),
                    d.run.max(1)
                ),
                body,
            ))
        }
        "continue" => Ok(("continue".into(), b"continue".to_vec())),
        "resume-prompt" => {
            let t = resume_prompt_text(&d.text);
            if t.is_empty() {
                bail!("resume-prompt: empty or longer than 4000 characters");
            }
            Ok((t.clone(), t.into_bytes()))
        }
        "request-outcome" => crate::outcomes::outcome_text(d, keys),
        "peer" => {
            let cert = crate::grants::current_cert()?;
            let mut stores = cert.stores();
            stores.sort();
            crate::peer::peer_text(d.peer.as_ref(), &stores, &live_mode(&cert))
        }
        "watch" | "watch-fail" => {
            let (w, body) = own_watch(d.request.as_ref(), keys)?;
            if d.kind == "watch" {
                return Ok((
                    format!("[watch {} met] {}", go_quote(&w.name), w.prompt),
                    body,
                ));
            }
            if !w.fail_prompt.is_empty() {
                return Ok((
                    format!("[watch {} gave up] {}", go_quote(&w.name), w.fail_prompt),
                    body,
                ));
            }
            let q = go_quote(&w.name);
            Ok((
                format!(
                    "[watch {q} gave up] Conditional wakeup {q} gave up (its check said to give up, or its time ran out without the condition being met). Decide what to do next."
                ),
                body,
            ))
        }
        "lease-granted" | "lease-taken" | "lease-back" => {
            let t = lease_text(d, keys)?;
            Ok((t.clone(), t.into_bytes()))
        }
        "upgraded" => {
            let t = upgraded_text(&d.from, &d.to)?;
            Ok((t.clone(), t.into_bytes()))
        }
        k => bail!("unknown delivery kind {}", go_quote(k)),
    }
}

/// the core's input-log entry for exactly this input on this machine
pub fn check_attest(
    core_key: &str,
    me: &str,
    kind: &str,
    attested: &[u8],
    d: Option<&SignedDoc>,
) -> Result<()> {
    if let Some(t) = crate::kernelboot::read_kernel_trust() {
        // kernelboot.rs: the log notary's challenge over the same facts
        return crate::kernelboot::check_kernel_attest(&t, me, kind, attested, d);
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct E {
        kind: String,
        machine: String,
        input: String,
        sha256: String,
    }
    let e: E = match verify_doc(core_key, d) {
        Ok(e) => e,
        Err(_) => bail!("no core attestation (the input isn't in the core's log)"),
    };
    if e.kind != "input" {
        bail!("no core attestation (the input isn't in the core's log)");
    }
    if e.machine != me || e.input != kind || e.sha256 != sha256_hex(attested) {
        bail!("the core's attestation is for another input or machine");
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DeliveryResult {
    pub id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// a preview's text; also a refused delivery's text, when the phone signed another (messages.rs)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub text: String,
    /// refused only for want of the phone's approval of this message (the router files it for Deyao)
    #[serde(rename = "needsApproval", skip_serializing_if = "std::ops::Not::not")]
    pub needs_approval: bool,
}

pub fn run_delivery(c: &Client, d: Delivery) {
    let mut res = DeliveryResult {
        id: d.id.clone(),
        ..Default::default()
    };
    if d.preview {
        match preview_delivery(&d) {
            Ok(t) => {
                res.text = t;
                res.ok = true;
            }
            Err(e) => res.error = e,
        }
        if let Err(e) = c.json_ok("POST", "/m/delivery-result", Some(&res)) {
            logf!("delivery preview result not sent: {e:#}");
        }
        return;
    }
    match deliver(c, d.clone()) {
        Ok(()) => {
            res.ok = true;
            logf!("delivery {} ({}) delivered", d.id, d.kind);
        }
        Err(e) => {
            if let Some(a) = e.downcast_ref::<ApprovalError>() {
                res.needs_approval = true;
                if let ApprovalError::TextDiffers(t) = a {
                    res.text = t.clone();
                }
            }
            res.error = format!("{e:#}");
            logf!("delivery {} ({}) refused: {}", d.id, d.kind, res.error);
        }
    }
    if let Err(e) = c.json_ok("POST", "/m/delivery-result", Some(&res)) {
        logf!("delivery result not sent: {e:#}");
    }
}

/// the text this delivery would put into the harness (before a watch's re-run check output), or why it would be
/// refused; nothing runs, is sent or recorded
pub fn preview_delivery(d: &Delivery) -> Result<String, String> {
    let mut d = d.clone();
    d.approval = None;
    d.attest = None;
    crate::guard::render_delivery(&d)
        .map(|r| r.text)
        .map_err(|e| format!("{e:#}"))
}

/// The delivery's text into the harness, once the guard let it through (a refusal because the phone approved another
/// text carries this one: ApprovalError::TextDiffers)
pub fn deliver(c: &Client, d: Delivery) -> Result<()> {
    let g = crate::guard::guard_delivery(c, &d)?;
    let (mut text, d, cert, approved) = (g.text, g.delivery, g.cert, g.approved);
    let _o = lock(&DELIVER_ORDER_MU); // one delivery at a time between the check and the record
    let now = util::unix_now();
    replay_guard(&d, now, false)?;
    if (d.kind == "watch" || d.kind == "watch-fail")
        && let Ok((w, _)) = own_watch(d.request.as_ref(), &read_line_keys())
    {
        // the check once more, here, with the session's own env: its output is the context (the runner's never is)
        text.push_str(&rerun_check(&w));
    }
    if d.kind == "resume-prompt" && !via_harness_send(&cert.options.harness) {
        // Deyao's own words go into the Claude host's input box, typed as his prompt, never as a Jarvis message
        type_into_host(&text)?;
    } else if d.kind == "request-outcome" && crate::outcomes::filed_by_command(&d) {
        // a request's outcome is the answer of the jarvis-request command that filed it, never a message into the
        // conversation (Deyao, 2026-11-17)
        crate::outcomes::record_outcome(&d, &text, now)?;
    } else {
        send_to_harness(&cert.options.harness, &live_mode(&cert), "jarvis", &text)?;
    }
    crate::messages::record_approved(&approved, now)?; // the phone's approval is used up
    replay_guard(&d, now, true)
}

/// Deyao's resume prompt as the router keeps it (router/sessionapi.go cleanResumePrompt): CRLF → LF, trimmed, at most
/// 4000 characters; "" when empty or longer
pub fn resume_prompt_text(p: &str) -> String {
    let p = p.replace("\r\n", "\n").replace('\r', "\n");
    let p = p.trim();
    if p.is_empty() || p.chars().count() > 4000 {
        return String::new();
    }
    p.to_string()
}

/// the in-place permission mode (session-image set-permission-mode writes it), relative to claude's home
pub const MODE_FILE: &str = ".claude/.permission-mode";

/// the mode claude actually runs in, decided exactly as harness-claude.sh decides it: the in-place file when there is
/// one, else the cert's
pub fn live_mode(cert: &Cert) -> String {
    match std::fs::read_to_string(std::path::Path::new(paths::CLAUDE_HOME).join(MODE_FILE)) {
        Err(_) => cert_mode(cert).into(),
        Ok(s) if s.trim() == "bypass" => "bypass".into(),
        Ok(_) => "auto".into(),
    }
}

/// the Jarvis channel's sender and config (session-image/Dockerfile)
pub const CHANNEL_SEND: &str = "/usr/local/bin/jarvis-channel-send";
pub const CHANNEL_CONFIG: &str = "/etc/claude-code/jarvis-channel.json";

/// a command with `stdin` written to it, its combined output, killed after `limit`
pub fn run_with_input(
    mut cmd: std::process::Command,
    stdin: &str,
    limit: Duration,
) -> Result<(std::process::ExitStatus, String)> {
    let (r, w) = std::io::pipe()?;
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(w.try_clone()?)
        .stderr(w)
        .spawn()?;
    drop(cmd);
    if let Some(mut si) = child.stdin.take() {
        let s = stdin.to_string();
        std::thread::spawn(move || {
            let _ = si.write_all(s.as_bytes());
        });
    }
    let reader = std::thread::spawn(move || {
        let mut out = String::new();
        let mut r = r;
        let _ = r.read_to_string(&mut out);
        out
    });
    let start = std::time::Instant::now();
    loop {
        if let Some(st) = child.try_wait()? {
            let out = reader.join().unwrap_or_default();
            return Ok((st, out));
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            bail!("timeout");
        }
        util::sleep(Duration::from_millis(50));
    }
}

/// the text into the harness (the same as the router's old exec path, run here)
pub fn send_to_harness(harness: &str, mode: &str, from: &str, text: &str) -> Result<()> {
    let cmd = if via_harness_send(harness) {
        session_command("/usr/local/bin/harness-send", &["--queue"])
    } else if util::file_exists(std::path::Path::new(CHANNEL_SEND))
        && util::file_exists(std::path::Path::new(CHANNEL_CONFIG))
    {
        // the Jarvis channel: the image refuses every cross-session peer message, so Jarvis's own messages go in
        // through its channel, whatever the session's permission mode
        session_command(CHANNEL_SEND, &["--from", from])
    } else {
        // an image before the channel: the peer socket, in the mode class claude runs in
        let fm = if mode == "bypass" {
            "bypass"
        } else {
            "prompting"
        };
        let t = B64.encode(text.as_bytes());
        session_command("python3", &["-I", "-c", PEER_PY, &t, "", fm, from])
    };
    match run_with_input(cmd, text, Duration::from_secs(30)) {
        Err(e) if e.to_string() == "timeout" => {
            bail!("the harness didn't take the message within 30 s")
        }
        Err(e) => Err(e),
        Ok((st, _)) if st.success() => Ok(()),
        Ok((st, out)) => bail!("{st}: {}", out.trim()),
    }
}

/// The text into the Claude host's input box as the user's prompt: harness-send queues it and harness-claude.sh's
/// typing loop types it and presses Enter once no dialog is up
pub fn type_into_host(text: &str) -> Result<()> {
    let cmd = session_command("/usr/local/bin/harness-send", &["--queue"]);
    match run_with_input(cmd, text, Duration::from_secs(3600))? {
        (st, _) if st.success() => Ok(()),
        (st, out) => bail!("{st}: {}", out.trim()),
    }
}

/// the in-machine sender (router/peer.go's, the same program). argv: base64 text, target name ("" = the one live
/// session), from-mode, from-name.
pub const PEER_PY: &str = r#"
import base64, glob, hashlib, json, os, socket, sys, uuid
text = base64.b64decode(sys.argv[1]).decode("utf-8", "replace")
name, mode, sender = sys.argv[2], sys.argv[3], sys.argv[4]
sess = os.path.expanduser("~/.claude/sessions")
def done(ok, message, **kw):
    print(json.dumps({"success": ok, "message": message, **kw})); sys.exit(0 if ok else 1)
def alive(pid):
    try: os.kill(int(pid), 0); return True
    except Exception: return False
live = []
for f in sorted(glob.glob(os.path.join(sess, "*.json"))):
    try: d = json.load(open(f))
    except Exception: continue
    p = d.get("messagingSocketPath")
    if not p or not os.path.exists(p) or not alive(d.get("pid")): continue
    if d.get("kind", "interactive") != "interactive": continue
    live.append(d)
named = [d for d in live if name and d.get("name") == name]
if len(named) == 1: t = named[0]
elif not named and len(live) == 1: t = live[0]
else:
    done(False, "target session not found: %s (live interactive sessions: %s)" % (name or "(unnamed)", ", ".join(str(d.get("name") or d.get("pid")) for d in live) or "none"))
if t.get("peerProtocol") != 1:
    done(False, "host %s speaks peerProtocol %r, this sender speaks 1" % (t.get("name"), t.get("peerProtocol")))
sock_path = t["messagingSocketPath"]
token = None
for f in glob.glob(os.path.join(sess, "*.%s.key" % hashlib.sha256(sock_path.lower().encode()).hexdigest())):
    try: token = json.load(open(f)).get("peerToken"); break
    except Exception: pass
body = '<cross-session-message from="uds:%s" from-name="%s" from-mode="%s">\n%s\n</cross-session-message>' % (sender, sender, mode, text)
frames = ([json.dumps({"type": "auth", "token": token})] if token else []) + [json.dumps({
    "msgV": 1, "msg_id": str(uuid.uuid4()), "type": "user",
    "message": {"role": "user", "content": body}, "priority": "next", "from": "uds:" + sender})]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect(sock_path)
    s.sendall(("\n".join(frames) + "\n").encode())
except Exception as e:
    done(False, "inbox socket %s: %s" % (sock_path, e))
s.settimeout(2)
try: ack = s.recv(65536).decode("utf-8", "replace")
except Exception: ack = ""
s.close()
done(True, "delivered to %s (pid %s)" % (t.get("name") or "?", t.get("pid")), target=t.get("name") or "", ack=ack[:500])
"#;

// ---- machine sizes (the same block is in router/sizes.go, core/fly.go and kernel/spawner/fly.go) -----------------

/// The sizes: small (2 GB), medium (4 GB), large (8 GB), then every doubling past large, named by its memory
const NAMED_SIZES: &[(&str, i64)] = &[("small", 2), ("medium", 4), ("large", 8)];

fn named_size(s: &str) -> i64 {
    NAMED_SIZES
        .iter()
        .find(|(n, _)| *n == s)
        .map(|(_, g)| *g)
        .unwrap_or(0)
}

/// the size's memory in GB; 0 = not a size
pub fn size_mem_gb(size: &str) -> i64 {
    let gb = named_size(size);
    if gb != 0 {
        return gb;
    }
    let Ok(n) = size.strip_suffix("gb").unwrap_or(size).parse::<i64>() else {
        return 0;
    };
    if !(16..=1 << 20).contains(&n) || n & (n - 1) != 0 || format!("{n}gb") != size {
        return 0;
    }
    n
}

/// the size's Fly guest (cpu kind, cpus, memory MB)
pub fn size_guest(size: &str) -> (&'static str, i64, i64) {
    let gb = size_mem_gb(size);
    match gb {
        0 => ("", 0, 0),
        g if g <= 8 => ("shared", g, g * 1024),
        g if g <= 16 => ("shared", 8, g * 1024),
        g => ("performance", (g / 8).max(8), g * 1024),
    }
}

/// the size Upgrade moves to, twice the memory (a session with no size runs medium)
pub fn next_size(size: &str) -> String {
    let mut gb = size_mem_gb(size);
    if gb == 0 {
        gb = named_size("medium");
    }
    match NAMED_SIZES.iter().find(|(_, n)| *n == 2 * gb) {
        Some((name, _)) => name.to_string(),
        None => format!("{}gb", 2 * gb),
    }
}

/// "large (8 GB)", "16 GB"
pub fn size_text(size: &str) -> String {
    let gb = named_size(size);
    if gb != 0 {
        return format!("{size} ({gb} GB)");
    }
    format!("{} GB", size_mem_gb(size))
}

/// after an Upgrade (router/memory.go), the first message on the bigger machine
pub fn upgraded_text(from: &str, to: &str) -> Result<String> {
    if size_mem_gb(from) == 0 || size_mem_gb(to) == 0 {
        bail!("upgraded: not a machine size");
    }
    Ok(format!(
        "Jarvis: this session ran out of memory and was moved from a {} to a {} machine. ",
        size_text(from),
        size_text(to)
    ) + "To free memory for the move, every process of the old machine was stopped: Claude itself, background jobs, builds, dev servers, browsers. "
        + "Their list is in ~/artifacts/jarvis-upgrade-freed.txt. Check which of them the task still needs, restart only those, then carry on with the task as before: the bigger machine has the room, so do not cut back on parallel work. "
        + "This is an automated message from Jarvis.")
}

// ---- leases (router/leases.go builds the same texts) -------------------------------------------------------------

re!(LEASE_NAME_RE = r"^[a-z0-9][a-z0-9-]{0,40}$");
re!(LEASE_SPACE_RE = r"\s+");
re!(LEASE_PATH_RE = r"^/m/api/sessions/[^/]+/leases/([a-z0-9][a-z0-9-]{0,40})$");

/// the wake text for a lease delivery
pub fn lease_text(d: &Delivery, keys: &[String]) -> Result<String> {
    if !LEASE_NAME_RE.is_match(&d.device) {
        bail!("lease: not a device name");
    }
    let dev = &d.device;
    let q = go_quote(dev);
    match d.kind.as_str() {
        "lease-taken" => {
            return Ok(format!(
                "[lease {q} taken over] Deyao has taken the shared device {q} himself. Stop using it now: every device action is refused while he has it. "
            ) + "You are first in the queue; when he hands it back you'll be woken. Then look at the device first: it will be in whatever state he left it. "
                + "This is an automated message from Jarvis.");
        }
        "lease-back" => {
            return Ok(format!(
                "[lease {q} handed back] Deyao has handed the shared device {q} back. Earlier this session found it taken over: that no longer applies. "
            ) + &format!(
                "Run scripts/lease.py status {dev} to see whether it is free or who holds it now, and acquire it if this session still needs it (scripts/lease.py acquire {dev} --purpose \"…\"). "
            ) + "If you told Deyao or planned around it being unavailable, reconsider now. It is in whatever state he left it: look at it first. "
                + "This is an automated message from Jarvis.");
        }
        _ => {}
    }
    let mut prompt = String::new();
    if let Some(r) = &d.request {
        let body = own_request_body(Some(r), keys)?;
        let ok = r.method == "POST"
            && LEASE_PATH_RE
                .captures(&r.path)
                .is_some_and(|m| &m[1] == dev);
        if !ok {
            bail!("the signed request isn't this session's acquire of that device");
        }
        let p = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("prompt").and_then(|p| p.as_str()).map(String::from))
            .unwrap_or_default();
        prompt = LEASE_SPACE_RE.replace_all(&p, " ").trim().to_string();
        if prompt.chars().count() > 2000 {
            prompt = prompt.chars().take(2000).collect();
        }
    }
    if d.minutes < 1 || d.minutes > 6 * 60 {
        bail!("lease: not a lease length");
    }
    let mut t = format!(
        "[lease {q} granted] This session now holds the shared device {q} (you were queued for it). "
    ) + &format!(
        "It is yours for {} min, renewed automatically by the device helpers on every action; return it when done (scripts/lease.py return {dev}). ",
        d.minutes
    );
    if d.handover {
        t += &format!("Deyao had taken {q} over himself");
        if d.interrupted {
            t += " (interrupting you: your earlier steps may no longer apply)";
        }
        t += &format!(
            " and has handed it back; his notes are in scripts/lease.py status {dev}. The device is in whatever state he left it: look at it first (screenshot / UI tree) and continue from there."
        );
    } else {
        t += "The previous holder may have left it in any state: inspect it first.";
    }
    if !prompt.is_empty() {
        t += &format!(" Your note: {prompt}");
    }
    Ok(t)
}

// ---- watches (router/watches.go) ---------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct WatchReq {
    pub name: String,
    pub script: String,
    pub prompt: String,
    #[serde(rename = "failPrompt")]
    pub fail_prompt: String,
}

re!(WATCH_NAME_RE = r"^[A-Za-z0-9_-]{1,40}$");

/// the watch this line's machine armed (its signed POST …/watches)
pub fn own_watch(r: Option<&SignedRequest>, keys: &[String]) -> Result<(WatchReq, Vec<u8>)> {
    let body = own_request_body(r, keys)?;
    let r = r.ok_or_else(|| anyhow!("no request"))?;
    if r.method != "POST"
        || !r.path.starts_with("/m/api/sessions/")
        || !r.path.ends_with("/watches")
    {
        bail!("the signed request isn't a watch");
    }
    let mut w: WatchReq = match gojson::unmarshal(&body) {
        Ok(w) => w,
        Err(_) => bail!("the signed request has no watch"),
    };
    if w.prompt.trim().is_empty() || !WATCH_NAME_RE.is_match(w.name.trim()) {
        bail!("the signed request has no watch");
    }
    w.name = w.name.trim().to_string();
    w.prompt = fields_join(&w.prompt);
    w.fail_prompt = fields_join(&w.fail_prompt);
    Ok((w, body))
}

/// how long the re-run check may take (seconds; tests shorten it)
pub static RERUN_TIMEOUT_SECS: AtomicU64 = AtomicU64::new(40);

/// The watch's check run here (a login shell: the session's env and secrets) in a throwaway directory, within the
/// re-run timeout (the router waits 60 s for the delivery's answer); its stdout, capped, as the prompt's context
pub fn rerun_check(w: &WatchReq) -> String {
    let Ok(dir) = tempdir("watch-") else {
        return String::new();
    };
    let f = dir.join("check.sh");
    if util::write_file(&f, w.script.as_bytes(), 0o700).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return String::new();
    }
    let limit = Duration::from_secs(RERUN_TIMEOUT_SECS.load(Ordering::Relaxed));
    let fs = f.to_string_lossy().into_owned();
    let mut cmd = session_command("bash", &["-l", &fs]);
    use std::os::unix::process::CommandExt;
    cmd.current_dir(&dir)
        .env("WATCH_NAME", &w.name)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let out = (|| -> Result<(i32, String, bool)> {
        let mut child = cmd.spawn()?;
        let mut so = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
        let reader = std::thread::spawn(move || {
            let mut buf = vec![];
            let mut chunk = [0u8; 8192];
            loop {
                match so.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let room = 6000usize.saturating_sub(buf.len());
                        buf.extend_from_slice(&chunk[..n.min(room)]);
                    }
                }
            }
            buf
        });
        let start = std::time::Instant::now();
        let mut timed_out = false;
        let st = loop {
            if let Some(st) = child.try_wait()? {
                break st;
            }
            if !timed_out && start.elapsed() >= limit {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(-(child.id() as i32)),
                    nix::sys::signal::Signal::SIGKILL,
                );
                timed_out = true;
            }
            util::sleep(Duration::from_millis(50));
        };
        // what the check's children still hold open: at most 2 s more (Go's WaitDelay)
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !reader.is_finished() && std::time::Instant::now() < deadline {
            util::sleep(Duration::from_millis(20));
        }
        let buf = if reader.is_finished() {
            reader.join().unwrap_or_default()
        } else {
            vec![]
        };
        Ok((
            st.code().unwrap_or(-1),
            String::from_utf8_lossy(&buf).into_owned(),
            timed_out,
        ))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    let (code, s, timed_out) = out.unwrap_or((-1, String::new(), false));
    let s = s.trim();
    if timed_out {
        return format!(
            "\n\n[watch {} check output] (the check, run again on this machine, didn't finish within {}s) {s}",
            go_quote(&w.name),
            limit.as_secs()
        );
    }
    if s.is_empty() {
        return String::new();
    }
    format!(
        "\n\n[watch {} check output] (run again on this machine just now, exit {code})\n{s}",
        go_quote(&w.name)
    )
}

/// a fresh private directory under the temp dir (Go's os.MkdirTemp)
pub fn tempdir(prefix: &str) -> Result<std::path::PathBuf> {
    use rand::Rng;
    let base = std::env::temp_dir();
    for _ in 0..100 {
        let n: u64 = rand::thread_rng().r#gen();
        let p = base.join(format!("{prefix}{n}"));
        let mut b = std::fs::DirBuilder::new();
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
        if b.create(&p).is_ok() {
            return Ok(p);
        }
    }
    bail!("no temp dir")
}
