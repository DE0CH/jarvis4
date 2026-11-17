//! Grants (docs/DESIGN.md "Grants"): a router feature (terminal, status, archive, remote) has its own key pair, the
//! holder. It asks this machine to run a shell command. The machine runs it when one of these allows it:
//!   - a phone grant: the phone's signature over {kind "grant", holder, session, scope "shell", expires}, at most 10
//!     minutes long. The phone's key comes from this machine's core-signed cert.
//!   - a standing rule: the phone's signature over {kind "rule", holder, session, scope "shell", until}.
//!   - this session's own allow list (~/.jarvis2-allow.json, written by `jarvis-machine allow`): the machine approving
//!     for itself. It travels in the snapshot, so it survives a pause.
//!
//! A session holding a sensitive store accepts only a phone grant. The core takes no part.

use crate::cert::Cert;
use crate::client::Client;
use crate::crypto::{SignedDoc, read_trim, verify_doc};
use crate::session::rescue_command;
use crate::{gojson, logf, paths, util};
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

pub const ALLOW_FILE: &str = ".jarvis2-allow.json";
/// 10 minutes, plus clock slack
pub const MAX_GRANT_SECS: i64 = 10 * 60 + 30;
const MAX_EXEC_OUTPUT: usize = 1 << 20;

/// what the holder signs. Session in requests and grants is the line id from the core-signed cert (the line's first
/// machine), not the router's session id.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecRequest {
    pub id: String,
    pub session: String,
    /// the holder's public key (base64 x963)
    pub holder: String,
    pub cmd: String,
    /// seconds
    pub timeout: i64,
    /// unix seconds
    pub at: i64,
    /// only a phone grant may allow this request (raising the session to bypass)
    #[serde(rename = "phoneOnly", skip_serializing_if = "std::ops::Not::not")]
    pub phone_only: bool,
}

/// one item of /m/commands: the holder-signed request and what authorises it
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Exec {
    pub request: String,
    pub sig: String,
    /// phone-signed grant or rule; None = the allow list
    pub grant: Option<SignedDoc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Grant {
    /// grant | rule
    pub kind: String,
    pub holder: String,
    pub session: String,
    pub scope: String,
    pub issued: String,
    /// grant
    pub expires: String,
    /// rule
    pub until: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AllowEntry {
    pub holder: String,
    pub name: String,
    pub until: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecResult {
    pub id: String,
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// tests supply a cert here
pub static TEST_CERT: Mutex<Option<Cert>> = Mutex::new(None);

/// the machine's settings (tests: TEST_CERT)
pub fn current_cert() -> Result<Cert> {
    if let Some(c) = TEST_CERT.lock().ok().and_then(|g| g.clone()) {
        return Ok(c);
    }
    read_cert()
}

/// The machine's settings. The old core's machines: its signed cert. A kernel machine has no core: cert.json is what
/// its own boot (and each reload) wrote from the kernel documents it checked (kernelboot.rs), plain JSON.
pub fn read_cert() -> Result<Cert> {
    let raw = std::fs::read(paths::cert_path())?;
    if crate::kernelboot::read_kernel_trust().is_some() {
        return Ok(gojson::unmarshal(&raw)?);
    }
    let d: SignedDoc = gojson::unmarshal(&raw)?;
    let key = read_trim(&paths::core_key_path())?;
    verify_doc(&key, Some(&d))
}

pub fn read_allow() -> Vec<AllowEntry> {
    std::fs::read(paths::home().join(ALLOW_FILE))
        .ok()
        .and_then(|b| {
            gojson::unmarshal::<Option<Vec<AllowEntry>>>(&b)
                .ok()
                .flatten()
        })
        .unwrap_or_default()
}

/// the command's output, the first MAX_EXEC_OUTPUT bytes of it (the rest read and dropped)
fn capped<R: Read + Send + 'static>(r: R) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut r = r;
        let mut buf = vec![];
        let mut chunk = [0u8; 16384];
        loop {
            match r.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = MAX_EXEC_OUTPUT.saturating_sub(buf.len());
                    buf.extend_from_slice(&chunk[..n.min(room)]);
                }
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    })
}

pub fn run_exec(c: &Client, e: Exec) {
    let (r, ok) = crate::guard::guard_exec(&e, util::unix_now());
    let mut res = ExecResult {
        id: r.id.clone(),
        ..Default::default()
    };
    match ok {
        Err(err) => {
            res.code = -1;
            res.error = format!("{err:#}");
            logf!("exec {} refused: {}", r.id, res.error);
        }
        Ok(()) => {
            let t = Duration::from_secs(r.timeout.clamp(1, 600) as u64);
            // back under the OOM killer, outside the session's memory limit
            let mut cmd = rescue_command("bash", &["-lc", &r.cmd]);
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            match cmd.spawn() {
                Err(err) => {
                    res.code = -1;
                    res.error = err.to_string();
                }
                Ok(mut child) => {
                    let so = child.stdout.take().map(capped);
                    let se = child.stderr.take().map(capped);
                    let start = std::time::Instant::now();
                    let st = loop {
                        match child.try_wait() {
                            Ok(Some(st)) => break Some(st),
                            Ok(None) if start.elapsed() >= t => {
                                let _ = child.kill();
                                break child.wait().ok();
                            }
                            Ok(None) => util::sleep(Duration::from_millis(20)),
                            Err(_) => break None,
                        }
                    };
                    res.stdout = so.and_then(|h| h.join().ok()).unwrap_or_default();
                    res.stderr = se.and_then(|h| h.join().ok()).unwrap_or_default();
                    res.code = st.and_then(|s| s.code()).unwrap_or(-1);
                }
            }
        }
    }
    if let Err(e) = c.json_ok("POST", "/m/exec-result", Some(&res)) {
        logf!("exec result not delivered: {e:#}");
    }
}

/// `jarvis-machine allow <holder name> <duration>` (e.g. archive 720h) or `allow --remove <name>`; the holder's key
/// comes from the router's list of feature keys
pub fn allow_cmd(args: &[String]) -> Result<()> {
    let p = paths::home().join(ALLOW_FILE);
    let list = read_allow();
    if args.len() == 2 && args[0] == "--remove" {
        let out: Vec<AllowEntry> = list.into_iter().filter(|a| a.name != args[1]).collect();
        util::write_file(&p, util::marshal_indent1(&out).as_bytes(), 0o600)?;
        return Ok(());
    }
    if args.is_empty() {
        println!("{}", util::marshal_indent1(&list));
        return Ok(());
    }
    if args.len() != 2 {
        bail!("usage: jarvis-machine allow [<holder> <duration> | --remove <holder>]");
    }
    let d = util::parse_go_duration(&args[1])?;
    let c = Client::new()?;
    let holders: BTreeMap<String, String> = c.json::<(), _>("GET", "/m/holders", None)?;
    let key = holders.get(&args[0]).cloned().unwrap_or_default();
    if key.is_empty() {
        let names: Vec<&str> = holders.keys().map(String::as_str).collect();
        return Err(anyhow!(
            "no holder {} (known: {})",
            util::go_quote(&args[0]),
            names.join(", ")
        ));
    }
    let mut out: Vec<AllowEntry> = list.into_iter().filter(|a| a.name != args[0]).collect();
    out.push(AllowEntry {
        holder: key,
        name: args[0].clone(),
        until: util::format_rfc3339(util::unix_now() + d.as_secs() as i64),
    });
    util::write_file(&p, util::marshal_indent1(&out).as_bytes(), 0o600)?;
    Ok(())
}
