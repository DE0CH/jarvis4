//! The fabric runner (docs/PLAN-fabric.md): a session's machines are gVisor sandboxes on aviary's fabric, started by
//! the fabric hermit through the kernel's spawner (kernel/spawner/fabric.go). Each session has one conversation at
//! hermit for its life (its /workspace and home on the fabric's network filesystem), made here at its first fabric
//! spawn and named in every spawn after.
//!
//! hermit's contract passes no environment to a sandbox, so the spawner's answer carries the machine's env and the
//! router serves it: the fabric image's entrypoint asks GET /fabric/env on the fabric listener (the fabric's egress
//! address leads there) with its sandbox token, hermit's hst1 token from its boot environment's proxy URL, which the
//! router checks against hermit's published keys. Nothing in the env is secret: the machine's keys line and the
//! spawner's cert are the trust path, as on the other runners. The same listener serves the machines' /m routes.
//!
//! ```text
//! FABRIC_HERMIT_URL          the fabric hermit inside the cluster (unset: no fabric runner, nothing here runs)
//! FABRIC_HERMIT_TOOLS_TOKEN  hermit's pair token of the caller tools (GET /v1/sandbox-token-keys)
//! FABRIC_HERMIT_MAGPIE_TOKEN hermit's pair token of the caller magpie for the router (a session's files deleted at
//!                            Destroy)
//! FABRIC_MACHINE_ADDR        the fabric listener (the fabric's egress target), e.g. :3128
//! FABRIC_SESSION_IMAGE       the fabric image a fabric session's sources name (ghcr.io/de0ch/jarvis4-session-fabric@
//!                            sha256:…, the digest hermit's configuration starts), and FABRIC_SESSION_IMAGE_SIG CI's
//!                            signature over it
//! ```

use crate::http::AppFn;
use crate::nethttp::write_json;
use crate::router::Router;
use crate::state::Session;
use anyhow::{Result, anyhow};
use base64::Engine;
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// a fabric session's conversation at hermit, and its current machine's env (from the spawner's answer)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FabricLine {
    pub conversation: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub machine: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_default()
}

/// tests: the fabric on without FABRIC_HERMIT_URL (a test can't set the environment: no unsafe)
pub static FABRIC_FORCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// the router has a fabric hermit to send sessions to
pub fn fabric_enabled() -> bool {
    FABRIC_FORCE.load(std::sync::atomic::Ordering::Relaxed) || !env("FABRIC_HERMIT_URL").is_empty()
}

/// the region a fabric spawn names (the spawner wants one; hermit's hosts are where its config says)
pub const FABRIC_REGION: &str = "fra";

pub fn uuid_text(b: &[u8]) -> String {
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// a random lowercase UUID v4 (the session's conversation at hermit)
pub fn new_conversation() -> String {
    let mut b = crate::util::rand_bytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    uuid_text(&b)
}

fn hermit_url(path: &str) -> String {
    format!("{}{path}", env("FABRIC_HERMIT_URL").trim_end_matches('/'))
}

fn hermit_get(path: &str, token_env: &str, timeout: Duration) -> Result<(u16, Vec<u8>)> {
    let resp = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()?
        .get(hermit_url(path))
        .header("Authorization", format!("Bearer {}", env(token_env)))
        .header("Aviary-Protocol", "hermit-core=1")
        .send()?;
    let st = resp.status().as_u16();
    Ok((
        st,
        crate::util::read_limited(resp, 64 << 10).unwrap_or_default(),
    ))
}

/// DELETE /v1/workspaces/{conversation} as caller magpie: the session's /workspace and its other folders (the home)
/// at the fabric hermit, after its archive (a destroy's last machine sent its whole state). hermit releases a live
/// sandbox of the conversation first and answers 204 also when nothing is there.
fn delete_fabric_files_live(conversation: &str) -> Result<()> {
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?
        .delete(hermit_url(&format!("/v1/workspaces/{conversation}")))
        .header(
            "Authorization",
            format!("Bearer {}", env("FABRIC_HERMIT_MAGPIE_TOKEN")),
        )
        .header("Aviary-Protocol", "hermit-core=1")
        .send()?;
    let st = resp.status().as_u16();
    if st / 100 != 2 {
        let b = crate::util::read_limited(resp, 2048).unwrap_or_default();
        return Err(anyhow!(
            "hermit: HTTP {st} {}",
            String::from_utf8_lossy(&b).trim()
        ));
    }
    Ok(())
}

/// a fabric machine's state in the lost-machine check's words (lostmachine.rs), from hermit: GET
/// /v1/conversations/{conversation}/sandbox as caller magpie. The machine is its sandbox (machine id x<sandbox id
/// without hyphens>): starting or ready is running ("started"); releasing is "destroying"; gone, another sandbox of the
/// conversation, or none at all is "released". An error (hermit not answering) says nothing: no verdict.
fn fabric_machine_state_live(conversation: &str, machine: &str) -> Result<String> {
    let (st, b) = hermit_get(
        &format!("/v1/conversations/{conversation}/sandbox"),
        "FABRIC_HERMIT_MAGPIE_TOKEN",
        Duration::from_secs(15),
    )?;
    if st == 404 {
        return Ok("released".into());
    }
    if st / 100 != 2 {
        return Err(anyhow!(
            "hermit: HTTP {st} {}",
            String::from_utf8_lossy(&b).trim()
        ));
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Sb {
        #[serde(alias = "ID", alias = "Id")]
        id: String,
        #[serde(alias = "State")]
        state: String,
    }
    let sb: Sb = jarvis_go::unmarshal(&b).map_err(|e| anyhow!("hermit: {e}"))?;
    if format!("x{}", sb.id.replace('-', "")) != machine {
        return Ok("released".into());
    }
    Ok(match sb.state.as_str() {
        "releasing" => "destroying",
        "gone" => "released",
        _ => "started",
    }
    .into())
}

/// tests swap hermit out
pub type DeleteFilesFn = fn(&str) -> Result<()>;
pub type MachineStateFn = fn(&str, &str) -> Result<String>;
pub static DELETE_FABRIC_FILES: RwLock<DeleteFilesFn> = RwLock::new(delete_fabric_files_live);
pub static FABRIC_MACHINE_STATE: RwLock<MachineStateFn> = RwLock::new(fabric_machine_state_live);

pub fn fabric_machine_state(conversation: &str, machine: &str) -> Result<String> {
    (*FABRIC_MACHINE_STATE
        .read()
        .unwrap_or_else(|e| e.into_inner()))(conversation, machine)
}

impl Router {
    /// the image a new source of the session names: the fabric image for a fabric session, else the session image
    /// (the phone checks CI's signature over either: ios KernelChecks.pinned)
    pub fn source_image(&self, s: &Session) -> String {
        if self.runner_of(s) == "fabric" {
            let f = env("FABRIC_SESSION_IMAGE");
            if !f.is_empty() {
                return f;
            }
        }
        self.cfg.session_image.clone()
    }

    /// the session's machines run on the fabric
    pub fn is_fabric_session(&self, id: &str) -> bool {
        self.st
            .do_(|d| d.sessions.get(id).is_some_and(|s| s.fabric.is_some()))
    }

    pub fn delete_fabric_files(&self, conversation: &str) -> Result<()> {
        (*DELETE_FABRIC_FILES
            .read()
            .unwrap_or_else(|e| e.into_inner()))(conversation)
    }

    /// the session's fabric line, its conversation made on first use
    pub fn fabric_line(&self, sid: &str) -> Result<FabricLine> {
        self.st
            .do_(|d| {
                let s = d.sessions.get_mut(sid)?;
                Some(
                    s.fabric
                        .get_or_insert_with(|| FabricLine {
                            conversation: new_conversation(),
                            ..Default::default()
                        })
                        .clone(),
                )
            })
            .ok_or_else(|| anyhow!("no session {sid}"))
    }

    /// the machine the spawner made for the session, and the env it is to get
    pub fn set_fabric_machine(&self, sid: &str, machine: &str, e: BTreeMap<String, String>) {
        self.st.do_(|d| {
            if let Some(f) = d.sessions.get_mut(sid).and_then(|s| s.fabric.as_mut()) {
                f.machine = machine.to_string();
                f.env = e.clone();
            }
        });
    }

    /// the env of the session whose current fabric machine is the token's sandbox, with the runner's two names added.
    /// The token's conversation must be that session's.
    pub fn fabric_env_for(&self, c: &HstClaims) -> Option<BTreeMap<String, String>> {
        let machine = format!("x{}", c.sandbox.replace('-', ""));
        let mut e = self.st.do_(|d| {
            d.sessions
                .values()
                .filter_map(|s| s.fabric.as_ref())
                .filter(|f| {
                    f.machine == machine && f.conversation == c.conversation && !f.env.is_empty()
                })
                .map(|f| f.env.clone())
                .next_back()
        })?;
        e.insert("JARVIS2_RUNNER".into(), "fabric".into());
        e.insert("JARVIS2_MACHINE_ID".into(), machine);
        Some(e)
    }

    /// the fabric listener: the machines' /m routes and GET /fabric/env (with `Authorization: Bearer <hst1 token>`)
    pub fn fabric_machine_handler(self: &Arc<Self>, keys: Arc<HermitKeys>) -> AppFn {
        let m = self.machine_handler();
        let r = self.clone();
        Arc::new(move |w, req| {
            if req.path != "/fabric/env" {
                return m(w, req);
            }
            if req.method != "GET" {
                w.set_header("Allow", "GET, HEAD");
                return crate::nethttp::write_error(w, 405, "Method Not Allowed");
            }
            let auth = req.header("Authorization");
            let Some(tok) = auth.strip_prefix("Bearer ") else {
                return write_json(w, 401, &json!({"error": "a sandbox token is needed"}));
            };
            let ks = match keys.current(false) {
                Err(e) => {
                    return write_json(
                        w,
                        503,
                        &json!({"error": format!("hermit's token keys: {e:#}")}),
                    );
                }
                Ok(k) => k,
            };
            let mut c = verify_hst(tok, &ks, GoTime::now());
            if let Err(e) = &c
                && e.starts_with("unknown kid")
                && let Ok(ks) = keys.current(true)
            {
                c = verify_hst(tok, &ks, GoTime::now());
            }
            let c = match c {
                Err(e) => return write_json(w, 401, &json!({"error": e})),
                Ok(c) => c,
            };
            match r.fabric_env_for(&c) {
                None => write_json(
                    w,
                    404,
                    &json!({"error": "no session's machine is this sandbox"}),
                ),
                Some(e) => write_json(w, 200, &json!({"env": e})),
            }
        })
    }
}

// ---- hermit's sandbox token (aviary crates/hermit-api/src/token.rs) ---------------------------------------------

/// what a sandbox token says
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HstClaims {
    /// lowercase hyphenated UUIDs
    pub sandbox: String,
    pub conversation: String,
    pub expires: GoTime,
}

const HST_CONTEXT: &[u8] = b"hermit-sandbox-token\x00";

pub type HermitKeyMap = BTreeMap<u32, ed25519_dalek::VerifyingKey>;

/// `hst1.<kid>.<payload>.<sig>` checked against keys (kid → Ed25519 public key) at now; Err is the reason
pub fn verify_hst(
    tok: &str,
    keys: &HermitKeyMap,
    now: GoTime,
) -> std::result::Result<HstClaims, String> {
    if tok.len() > 600 {
        return Err("token too long".into());
    }
    let parts: Vec<&str> = tok.split('.').collect();
    if parts.len() != 4 || parts[0] != "hst1" {
        return Err("not a sandbox token".into());
    }
    let kid: u32 = parts[1].parse().map_err(|_| "bad kid".to_string())?;
    let key = keys.get(&kid).ok_or_else(|| format!("unknown kid {kid}"))?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (Ok(payload), Ok(sig)) = (b64.decode(parts[2]), b64.decode(parts[3])) else {
        return Err("bad encoding".into());
    };
    let sig =
        ed25519_dalek::Signature::from_slice(&sig).map_err(|_| "bad signature".to_string())?;
    let mut msg = HST_CONTEXT.to_vec();
    msg.extend_from_slice(&payload);
    if ed25519_dalek::Verifier::verify(key, &msg, &sig).is_err() {
        return Err("bad signature".into());
    }
    const FIXED: usize = 1 + 16 + 16 + 4 + 8;
    if payload.len() < FIXED + 1 || payload[0] != 1 {
        return Err("bad payload".into());
    }
    let mut exp = [0u8; 8];
    exp.copy_from_slice(&payload[37..45]);
    let c = HstClaims {
        sandbox: uuid_text(&payload[1..17]),
        conversation: uuid_text(&payload[17..33]),
        expires: GoTime::from_unix(u64::from_be_bytes(exp) as i64),
    };
    if !now.before(&c.expires) {
        return Err("token expired".into());
    }
    Ok(c)
}

pub type KeysFetch = Box<dyn Fn() -> Result<HermitKeyMap> + Send + Sync>;

/// hermit's token keys, fetched at most every 5 minutes (a kid it doesn't know fetches again)
pub struct HermitKeys {
    mu: Mutex<Option<(Instant, HermitKeyMap)>>,
    get: KeysFetch,
}

impl HermitKeys {
    pub fn new(get: KeysFetch) -> HermitKeys {
        HermitKeys {
            mu: Mutex::new(None),
            get,
        }
    }

    pub fn current(&self, force: bool) -> Result<HermitKeyMap> {
        let mut g = self.mu.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, k)) = g.as_ref()
            && !force
            && at.elapsed() < Duration::from_secs(300)
        {
            return Ok(k.clone());
        }
        match (self.get)() {
            Err(e) => match g.as_ref() {
                Some((_, k)) => Ok(k.clone()),
                None => Err(e),
            },
            Ok(k) => {
                *g = Some((Instant::now(), k.clone()));
                Ok(k)
            }
        }
    }
}

/// GET /v1/sandbox-token-keys as caller tools
pub fn fetch_hermit_keys() -> Result<HermitKeyMap> {
    let (st, b) = hermit_get(
        "/v1/sandbox-token-keys",
        "FABRIC_HERMIT_TOOLS_TOKEN",
        Duration::from_secs(10),
    )?;
    if st != 200 {
        return Err(anyhow!("hermit token keys: HTTP {st}"));
    }
    parse_hermit_keys(&b)
}

pub fn parse_hermit_keys(b: &[u8]) -> Result<HermitKeyMap> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct K {
        kid: u32,
        alg: String,
        #[serde(rename = "publicKey")]
        public_key: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct V {
        keys: Vec<K>,
    }
    let v: V = jarvis_go::unmarshal(b)?;
    let mut out = BTreeMap::new();
    for k in v.keys {
        let Ok(b) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&k.public_key) else {
            continue;
        };
        let Ok(arr) = <[u8; 32]>::try_from(b.as_slice()) else {
            continue;
        };
        if k.alg == "Ed25519"
            && let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&arr)
        {
            out.insert(k.kid, vk);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn token(sk: &SigningKey, kid: u32, expires: u64) -> String {
        let mut p = vec![1u8];
        p.extend_from_slice(&[0x11; 16]);
        p.extend_from_slice(&[0x22; 16]);
        p.extend_from_slice(&[0; 4]);
        p.extend_from_slice(&expires.to_be_bytes());
        p.push(0);
        let mut msg = HST_CONTEXT.to_vec();
        msg.extend_from_slice(&p);
        let sig = sk.sign(&msg);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "hst1.{kid}.{}.{}",
            b64.encode(&p),
            b64.encode(sig.to_bytes())
        )
    }

    #[test]
    fn sandbox_tokens() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let keys = BTreeMap::from([(3u32, sk.verifying_key())]);
        let now = GoTime::from_unix(1_000);
        let c = verify_hst(&token(&sk, 3, 2_000), &keys, now).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(c.sandbox, "11111111-1111-1111-1111-111111111111");
        assert_eq!(c.conversation, "22222222-2222-2222-2222-222222222222");
        assert_eq!(
            verify_hst(&token(&sk, 3, 500), &keys, now),
            Err("token expired".into())
        );
        assert_eq!(
            verify_hst(&token(&sk, 4, 2_000), &keys, now),
            Err("unknown kid 4".into())
        );
        let conv = new_conversation();
        assert_eq!(conv.len(), 36);
        assert_eq!(&conv[14..15], "4");
    }
}
