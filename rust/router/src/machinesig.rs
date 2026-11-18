//! POST /api/machine-signatures/verify (Deyao or a paired device, the Access app "Jarvis 4 devices"): whether a request
//! a session machine signed for a service OUTSIDE Jarvis 4 is that machine's, checked as /m checks its own
//! (require_machine): the machine's current signing key, X-Time within MACHINE_TIME_SKEW, the payload
//! "<method> <path> <time> <sha256 hex of body>". The answer names the machine's session, its harness and its state,
//! so the service learns which session asks without holding any credential of the session's. Today's caller:
//! hermit-jarvis, the aviary harness's hermit (aviary/README.md), at a machine's boot. A path under /m is refused: a
//! signature meant for the router itself is never checked for anyone else.

use crate::nethttp::{Req, W, write_error, write_json};
use crate::router::Router;
use jarvis_go::GoTime;
use serde::Deserialize;
use serde_json::json;
use std::sync::LazyLock;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct MachineSigRequest {
    pub machine: String,
    pub method: String,
    pub path: String,
    pub time: String,
    #[serde(rename = "bodySha256")]
    pub body_sha256: String,
    pub sig: String,
}

static SIG_METHOD_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[A-Z]{3,7}$").unwrap_or_else(|_| unreachable!()));
static SHA256_HEX_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[0-9a-f]{64}$").unwrap_or_else(|_| unreachable!()));

/// what a checked signature names
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SigOwner {
    pub session: String,
    pub harness: String,
    pub state: String,
}

impl Router {
    /// the machine's session id, harness and state when sig is its machine's over the request, else a reason
    pub fn check_machine_signature(
        &self,
        m: &MachineSigRequest,
        now: GoTime,
    ) -> Result<SigOwner, String> {
        if m.machine.is_empty()
            || !SIG_METHOD_RE.is_match(&m.method)
            || !m.path.starts_with('/')
            || m.path == "/m"
            || m.path.starts_with("/m/")
            || !SHA256_HEX_RE.is_match(&m.body_sha256)
        {
            return Err("malformed: machine, an upper-case method, a path outside /m and a sha256 hex are required".into());
        }
        let skew = crate::http::MACHINE_TIME_SKEW.load(std::sync::atomic::Ordering::Relaxed);
        match m.time.parse::<i64>() {
            Ok(ts)
                if (now.unix_nanos() - ts as i128 * 1_000_000_000).abs()
                    <= skew as i128 * 1_000_000_000 => {}
            _ => return Err("time too far off".into()),
        }
        let (key, owner) = self.st.read(|d| {
            let key = d
                .started
                .get(&m.machine)
                .map(|s| s.signing_key.clone())
                .unwrap_or_default();
            let sid = d.machines.get(&m.machine).cloned().unwrap_or_default();
            let owner = d.sessions.get(&sid).map(|s| SigOwner {
                session: sid.clone(),
                harness: s.harness.clone(),
                state: s.state.clone(),
            });
            (key, owner)
        });
        let payload = format!("{} {} {} {}", m.method, m.path, m.time, m.body_sha256);
        match owner {
            Some(o)
                if !key.is_empty()
                    && crate::http::verify_p256(&key, payload.as_bytes(), &m.sig) =>
            {
                Ok(o)
            }
            _ => Err("not signed by a running session's machine".into()),
        }
    }

    pub fn verify_machine_signature(&self, w: &mut W, req: &mut Req) {
        let b = req.read_body(64 << 10);
        // Go's json.Decoder: the first value, whatever follows it
        let m: MachineSigRequest = match serde_json::Deserializer::from_slice(&b).into_iter().next()
        {
            Some(Ok(m)) => m,
            _ => return write_error(w, 400, "not JSON"),
        };
        match self.check_machine_signature(&m, GoTime::now()) {
            Err(why) => {
                let status = if why.starts_with("malformed") {
                    400
                } else {
                    403
                };
                write_error(w, status, &why);
            }
            Ok(o) => {
                w.set_header("Cache-Control", "no-store");
                write_json(
                    w,
                    200,
                    &json!({"session": o.session, "harness": o.harness, "state": o.state}),
                );
            }
        }
    }
}
