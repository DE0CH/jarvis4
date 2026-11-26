//! The fabric runner (kernel/spawner/fabric.go; docs/PLAN-fabric.md): a machine is a gVisor sandbox on aviary's fabric,
//! started by the fabric hermit (DE0CH/aviary's hermit, an internal service of Jarvis 4's cluster) on one of its AWS
//! hosts. The spawner is a client of hermit's contract (aviary docs/CONTRACTS.md "The hermit contract"), the only
//! holder of its two pair tokens (sealed to it by the setup session: POST /fabric-credentials, memory only, handed
//! over in the copy flip):
//!
//!   create   PUT /v1/conversations/{cid}/sandbox {"person"} as caller magpie → the sandbox; its id is the machine's.
//!            cid is the session's conversation at hermit, named by the router per spawn. hermit keeps one live
//!            sandbox per conversation, so a second machine on one session's files cannot be made.
//!   inspect  GET /v1/conversations/{cid}/sandbox: the sandbox's state in the spawner's words, the image hermit
//!            started it on.
//!   init     the keeper writes its keys line to its stdout, the sandbox's console; hermit's admin route GET
//!            /v1/admin/sandboxes/{id}/log answers a live sandbox's console as its host has it.
//!   destroy  POST /v1/admin/sandboxes/{id}/release (forced, this sandbox and no later one of the conversation).
//!
//! There is no volume: the session's files stay at hermit across machines and go only when the session is destroyed.

use super::aws::{KEYS_MARK, keys_from_line};
use super::{CreateInput, MachineKeys, Missing, RunMachine, Runner, pinned_digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// the only image a fabric machine runs, pinned by digest
pub const FABRIC_REPO: &str = "ghcr.io/de0ch/jarvis4-session-fabric";

/// the digest of a fabric image reference, "" for any other reference
pub fn fabric_image_digest(r: &str) -> String {
    pinned_digest(FABRIC_REPO, r)
}

/// hermit's pair tokens for the callers magpie (a conversation's sandbox) and admin (a sandbox's console, its forced
/// release), the operator the admin calls are audited as, and the person every sandbox is started for
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FabricCredentials {
    #[serde(default)]
    pub magpie_token: String,
    #[serde(default)]
    pub admin_token: String,
    #[serde(default)]
    pub admin: String,
    #[serde(default)]
    pub person: String,
}

impl FabricCredentials {
    pub fn ok(&self) -> bool {
        !self.magpie_token.is_empty()
            && !self.admin_token.is_empty()
            && !self.admin.is_empty()
            && !self.person.is_empty()
    }
}

/// what a spawn on the fabric names beside the cert: the session's conversation at hermit (a UUID)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricInput {
    #[serde(default)]
    pub conversation: String,
}

fn lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// a lowercase UUID
fn uuid(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    p.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&p)
            .all(|(n, x)| x.len() == *n && lower_hex(x))
}

/// ^x[0-9a-f]{32}$: a fabric machine id
pub fn fabric_id(id: &str) -> bool {
    id.len() == 33 && id.starts_with('x') && lower_hex(&id[1..])
}

impl FabricInput {
    pub fn check(&self) -> Result<(), String> {
        if !uuid(&self.conversation) {
            return Err("fabric: conversation is a lowercase UUID".into());
        }
        Ok(())
    }
}

/// a sandbox's id as the machine's: "x" and the UUID's 32 hex digits (the x tells it from a Fly machine id)
pub fn fabric_machine_id(sandbox: &str) -> String {
    format!("x{}", sandbox.replace('-', ""))
}

/// the sandbox's UUID of a machine id ("" for any other id)
pub fn fabric_sandbox_id(id: &str) -> String {
    if !fabric_id(id) {
        return String::new();
    }
    let h = &id[1..];
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// hermit's refusal: the HTTP status and the envelope's code (HTTP 0: hermit did not answer)
#[derive(Debug, Clone)]
pub struct FabricError {
    pub http: u16,
    pub code: String,
    pub msg: String,
}

impl std::fmt::Display for FabricError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for FabricError {}

type ConvOf = Box<dyn Fn(&str) -> String + Send + Sync>;

/// hermit's contract as a Runner. Every call after the create needs the machine's conversation (hermit's sandbox
/// routes are by conversation): the spawner's state names it.
pub struct FabricApi {
    /// hermit's address inside the cluster
    pub url: String,
    http: reqwest::blocking::Client,
    conv: OnceLock<ConvOf>,
    cred: Mutex<Option<FabricCredentials>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Sandbox {
    id: String,
    state: String,
    phase: String,
    image: String,
}

impl FabricApi {
    pub fn new(url: &str) -> FabricApi {
        FabricApi {
            url: url.trim_end_matches('/').into(),
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()
                .unwrap_or_default(),
            conv: OnceLock::new(),
            cred: Mutex::new(None),
        }
    }

    pub(crate) fn set_conversations(&self, f: ConvOf) {
        let _ = self.conv.set(f);
    }

    pub fn configure(&self, c: FabricCredentials) {
        *self.cred.lock().unwrap_or_else(|e| e.into_inner()) = Some(c);
    }

    fn configured(&self) -> anyhow::Result<FabricCredentials> {
        self.cred
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| Missing::Fabric.into())
    }

    /// one call of hermit's core surface as caller magpie or admin → the status and the body (when 2xx)
    fn call(
        &self,
        admin: bool,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (u16, anyhow::Result<Vec<u8>>) {
        let c = match self.configured() {
            Ok(c) => c,
            Err(e) => return (0, Err(e)),
        };
        let m = method.as_str().to_string();
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.url))
            .header("Aviary-Protocol", "hermit-core=1");
        if let Some(b) = &body {
            req = req
                .header("Content-Type", "application/json; charset=utf-8")
                .body(jarvis_sig::go_json(b).unwrap_or_default());
        }
        req = if admin {
            req.header("Authorization", format!("Bearer {}", c.admin_token))
                .header("Aviary-Admin", c.admin)
        } else {
            req.header("Authorization", format!("Bearer {}", c.magpie_token))
        };
        let resp = match req.send() {
            Ok(r) => r,
            Err(e) => {
                return (
                    0,
                    Err(FabricError {
                        http: 0,
                        code: String::new(),
                        msg: format!("hermit {m} {path}: {e}"),
                    }
                    .into()),
                );
            }
        };
        let status = resp.status().as_u16();
        let b = resp.bytes().map(|b| b.to_vec()).unwrap_or_default();
        let b = b[..b.len().min(1 << 20)].to_vec();
        if status / 100 != 2 {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct Env {
                code: String,
                message: String,
            }
            let env: Env = serde_json::from_slice(&b).unwrap_or_default();
            return (
                status,
                Err(FabricError {
                    http: status,
                    code: env.code.clone(),
                    msg: format!("hermit {m} {path}: {status} {} {}", env.code, env.message),
                }
                .into()),
            );
        }
        (status, Ok(b))
    }
}

/// a sandbox's state in the spawner's words. A sandbox is up for the spawner (its first process runs, the keeper can
/// write its keys) from hermit's phase supervisor on: hermit calls it ready only when the session's supervisor answers,
/// which is after the machine has its cert.
fn fabric_state(s: &Sandbox) -> String {
    match s.state.as_str() {
        "starting" if s.phase == "supervisor" => "started",
        "starting" => "created",
        "ready" | "paused" => "started",
        "releasing" => "destroying",
        "gone" => "destroyed",
        other => other,
    }
    .into()
}

impl Runner for FabricApi {
    /// the conversation's sandbox, started if it has none → the machine id. A sandbox of the conversation that is
    /// already there is answered as it is (hermit's get-or-start): spawn refuses an id it already holds. The image,
    /// region, size and disk are hermit's configuration, not the call's; the env is not passed either (hermit's
    /// contract has no per-sandbox environment): the machine asks the router for it.
    fn create(&self, i: &CreateInput) -> anyhow::Result<(String, String)> {
        let c = self.configured()?;
        let Some(f) = &i.fabric else {
            return Err(anyhow::anyhow!("a fabric machine needs its conversation"));
        };
        let (_, r) = self.call(
            false,
            reqwest::Method::PUT,
            &format!("/v1/conversations/{}/sandbox", f.conversation),
            Some(json!({"person": c.person})),
        );
        let s: Sandbox = serde_json::from_slice(&r?)?;
        let id = fabric_machine_id(&s.id);
        if !fabric_id(&id) {
            return Err(anyhow::anyhow!(
                "hermit answered a sandbox with the id {}",
                jarvis_go::fmt::go_quote(&s.id)
            ));
        }
        Ok((id, String::new()))
    }

    /// the machine's sandbox as hermit has it. The conversation's sandbox being another one (a later start), or none at
    /// all, means this one is gone.
    fn inspect(&self, id: &str) -> anyhow::Result<RunMachine> {
        let cid = self.conv.get().map(|f| f(id)).unwrap_or_default();
        if cid.is_empty() {
            return Err(anyhow::anyhow!(
                "no conversation known for fabric machine {id}"
            ));
        }
        let gone = RunMachine {
            state: "destroyed".into(),
            ..Default::default()
        };
        let (code, r) = self.call(
            false,
            reqwest::Method::GET,
            &format!("/v1/conversations/{cid}/sandbox"),
            None,
        );
        let b = match r {
            Ok(b) => b,
            Err(_) if code == 404 => return Ok(gone),
            Err(e) => return Err(e),
        };
        let s: Sandbox = serde_json::from_slice(&b)?;
        if fabric_machine_id(&s.id) != id {
            return Ok(gone);
        }
        let mut m = RunMachine {
            state: fabric_state(&s),
            ..Default::default()
        };
        if s.image.starts_with("sha256:") {
            m.image = format!("{FABRIC_REPO}@{}", s.image);
        }
        Ok(m)
    }

    /// the machine's keys line on the sandbox's console, the newest one hermit's host holds. Not there yet (the sandbox
    /// is still being placed, the keeper hasn't written it): NotYet, and the router asks again.
    fn init(&self, id: &str) -> anyhow::Result<MachineKeys> {
        let sid = fabric_sandbox_id(id);
        if sid.is_empty() {
            return Err(anyhow::anyhow!(
                "{} is no fabric machine id",
                jarvis_go::fmt::go_quote(id)
            ));
        }
        let (code, r) = self.call(
            true,
            reqwest::Method::GET,
            &format!("/v1/admin/sandboxes/{sid}/log"),
            None,
        );
        let b = match r {
            Ok(b) => b,
            Err(_) if code == 404 => return Err(Missing::NotYet.into()),
            Err(e) => return Err(e),
        };
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Tail {
            text: String,
        }
        let t: Tail = serde_json::from_slice(&b)?;
        let Some(found) = t.text.lines().rfind(|l| l.contains(KEYS_MARK)) else {
            return Err(Missing::NotYet.into());
        };
        keys_from_line(found).map(|(k, _)| k)
    }

    /// the sandbox's forced release. One that hermit no longer has, or that is already going, is not an error: the
    /// caller looks (inspect) for what became of it.
    fn destroy(&self, id: &str) -> anyhow::Result<()> {
        let sid = fabric_sandbox_id(id);
        if sid.is_empty() {
            return Err(anyhow::anyhow!(
                "{} is no fabric machine id",
                jarvis_go::fmt::go_quote(id)
            ));
        }
        let (code, r) = self.call(
            true,
            reqwest::Method::POST,
            &format!("/v1/admin/sandboxes/{sid}/release"),
            Some(json!({"note": "jarvis: the machine's end"})),
        );
        match r {
            Err(_) if code == 404 || code == 409 => Ok(()),
            other => other.map(|_| ()),
        }
    }

    /// a fabric machine has no volume of its own
    fn delete_volume(&self, _: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        let sb = "01a1f71e-cb6d-71d6-b5be-4c4e404255df";
        let id = fabric_machine_id(sb);
        assert_eq!(id, "x01a1f71ecb6d71d6b5be4c4e404255df");
        assert!(fabric_id(&id) && fabric_sandbox_id(&id) == sb);
        assert!(!fabric_id("683dde7ea60478") && fabric_sandbox_id("x01a1f71e").is_empty());
        assert!(
            FabricInput {
                conversation: sb.into()
            }
            .check()
            .is_ok()
        );
        assert!(
            FabricInput {
                conversation: sb.to_uppercase()
            }
            .check()
            .is_err()
        );
    }
}
