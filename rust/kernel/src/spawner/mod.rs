//! The spawner (kernel/spawner; DESIGN "Target design"), the kernel's only holder of the Fly token. It attests Fly
//! facts only, so every cert it signs has the pair ⊤:
//!
//!   spawn:   a notarized cert into source-x → a new empty volume and a Fly machine on it with the source's image (by
//!            digest) and the machine env naming the source, the kernel's roster and root key
//!   init:    M started on Fly with that digest → its keys (jarvis2-init, through Fly) → (source-x, fly-M, ⊤) naming
//!            them and the image Fly runs; the first cert signed is the one kept
//!   kill:    M destroyed, confirmed through Fly → (fly-M, source-y, ⊤), source-y holding M's image and settings and
//!            the hash of the snapshot M signed (the source's own when M sent none); one kill cert per machine
//!   destroy: a machine the spawner made that never came up (a spawn whose answer was lost) → destroyed, no cert
//!
//! Each call is single runner calls with no waiting or retrying: the router retries (a 409 while Fly isn't there
//! yet), moves a spawn off a full host by spawning again, finds the machine of a spawn whose answer was lost with its
//! read-only token, and calls kill again while a volume is left. A second machine from one source can't take the line:
//! the notarizer refuses a second successor of a source.
//!
//! The machines it made, and each kill's cert, are kept on its own volume (spawner.json), so a restart neither forgets
//! a machine nor signs a second kill of one. The tokens are kept in memory only: after a restart the setup session (or
//! the app's Recover) sends them again. In the copy flip (flip.rs) the machines and the tokens move to the other copy's
//! spawner, sealed to it, and this one freezes: it makes no runner call after its handoff.

pub mod aws;
pub mod awsserial;
pub mod fabric;
pub mod fly;
#[cfg(test)]
mod tests;

use crate::serve::{
    Answer, Continuity, Server, Stateful, fail, fail_because, handle, log, no_roster,
};
use aws::{AwsApi, AwsCredentials, AwsError, WireGuard, aws_region, instance_type};
use fabric::{
    FabricApi, FabricCredentials, FabricError, FabricInput, fabric_id, fabric_image_digest,
};
use fly::{Fly, FlyRunner, fly_status, size_guest};
use jarvis_doc::perm::Pair;
use jarvis_doc::{
    Cert, Keys, Kind, Machine as DocMachine, Notarized, Object, Source, by, now, peek_cert,
};
use jarvis_sig::{
    Doc, Identity, Opener, Roster, Sealed, Signer, Trust, check_identity, go_json, strict_json,
    verify,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

/// the only image the spawner starts, pinned by digest
pub const SESSION_REPO: &str = "ghcr.io/de0ch/jarvis4-session";

/// a reference of repo pinned by digest (repo(:tag)?@sha256:<64 hex>) → its digest, else ""
pub(crate) fn pinned_digest(repo: &str, r: &str) -> String {
    let Some(rest) = r.strip_prefix(repo) else {
        return String::new();
    };
    let (tag, digest) = match rest.split_once('@') {
        Some((t, d)) => (t, d),
        None => return String::new(),
    };
    let tag_ok = tag.is_empty()
        || tag.strip_prefix(':').is_some_and(|t| {
            let b = t.as_bytes();
            !b.is_empty()
                && b.len() <= 128
                && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
                && b.iter()
                    .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(c))
        });
    let digest_ok = digest.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    });
    if tag_ok && digest_ok {
        digest.to_string()
    } else {
        String::new()
    }
}

fn image_digest(r: &str) -> String {
    pinned_digest(SESSION_REPO, r)
}

/// the digest a runner reports (…@sha256:<64>), else ""
fn reported_digest(r: &str) -> String {
    match r.rfind("@sha256:") {
        Some(i) if r.len() - i - 1 == "sha256:".len() + 64 => r[i + 1..].to_string(),
        _ => String::new(),
    }
}

const MAX_DISK_GB: i64 = 500;
const INFO_FLY_TOKEN: &str = "jarvis2/fly-token";
const INFO_AWS_KEY: &str = "jarvis4/aws-credentials";
const INFO_FABRIC: &str = "jarvis4/fabric-credentials";

// the reasons of the spawner's refusals the router acts on (the error answer's "reason")
/// 503: the setup session (or the app's Recover) sends the token again
pub const REASON_NO_FLY_TOKEN: &str = "no-fly-token";
/// 502: Fly refused or didn't answer; the call may be made again
pub const REASON_FLY: &str = "fly";
/// 503: the setup session (or the app's Recover) sends the AWS key again
pub const REASON_NO_AWS_KEY: &str = "no-aws-key";
/// 502: EC2 refused or didn't answer; the call may be made again
pub const REASON_AWS: &str = "aws";
/// 503: the setup session (or the app's Recover) sends hermit's tokens again
pub const REASON_NO_FABRIC_KEY: &str = "no-fabric-key";
/// 502: the fabric hermit refused or didn't answer; the call may be made again
pub const REASON_FABRIC: &str = "fabric";
/// 409: the session's conversation already has a sandbox the spawner made
pub const REASON_FABRIC_BUSY: &str = "fabric-busy";
/// 502: Fly's 412 volume_placement_capacity; the volume is deleted, spawn again
pub const REASON_HOST_FULL: &str = "host-full";
/// 404: not a machine the spawner made
pub const REASON_UNKNOWN: &str = "unknown-machine";
/// 409: init before the runner says started (AWS: before the keys line)
pub const REASON_NOT_STARTED: &str = "not-started";
/// 409: Fly runs another digest than the source's
pub const REASON_WRONG_IMAGE: &str = "wrong-image";
/// 409: Fly doesn't say destroyed yet; kill (or destroy) again
pub const REASON_NOT_DESTROYED: &str = "not-destroyed";
/// 400: the snapshot isn't signed by the machine's key
pub const REASON_BAD_SNAPSHOT: &str = "bad-snapshot";
/// 409: a destroy of a machine that has a cert: it is killed instead
pub const REASON_CAME_UP: &str = "came-up";
/// 409: init of a machine killed meanwhile
pub const REASON_KILLED: &str = "killed";

/// the runners' refusals that aren't a runner's answer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    /// the spawner restarted and the setup session (or the app's Recover) hasn't sent the token again
    FlyToken,
    AwsKey,
    Fabric,
    /// the machine hasn't written its keys line yet (its image is still being pulled)
    NotYet,
}

impl std::fmt::Display for Missing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Missing::FlyToken => "the spawner has no Fly token yet (infra/setup.py sends it)",
            Missing::AwsKey => {
                "the spawner has no AWS key yet (infra/setup.py aws-credentials sends it)"
            }
            Missing::Fabric => "the spawner has no fabric credentials (POST /fabric-credentials)",
            Missing::NotYet => "no keys on the console yet",
        })
    }
}

impl std::error::Error for Missing {}

/// what jarvis2-init prints (and the keys line carries)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineKeys {
    #[serde(default)]
    pub encryption_key: String,
    #[serde(default)]
    pub signing_key: String,
}

/// a machine's state, the image its runner runs (registry/repository@sha256:…), the volume it mounts and the source
/// its runner's metadata names ("" on a machine the spawner didn't make)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunMachine {
    pub state: String,
    pub image: String,
    pub volume: String,
    pub source: String,
}

/// one machine to make: the image pinned by digest, the region, the size (the Fly guest and its memory), the env, the
/// disk, the source it is from, and (AWS) its WireGuard or (fabric) its conversation
#[derive(Debug, Clone, Default)]
pub struct CreateInput {
    pub image: String,
    pub region: String,
    pub guest: Value,
    pub memory_mb: i64,
    pub env: BTreeMap<String, String>,
    pub disk_gb: i64,
    pub source: String,
    pub wireguard: Option<WireGuard>,
    pub fabric: Option<FabricInput>,
}

/// where machines run: single calls, no waiting or retrying
pub trait Runner: Send + Sync {
    /// a machine on a new, empty disk of in.disk_gb → its id and the volume to delete after it ("" = none)
    fn create(&self, i: &CreateInput) -> anyhow::Result<(String, String)>;
    fn inspect(&self, id: &str) -> anyhow::Result<RunMachine>;
    fn init(&self, id: &str) -> anyhow::Result<MachineKeys>;
    fn destroy(&self, id: &str) -> anyhow::Result<()>;
    fn delete_volume(&self, volume: &str) -> anyhow::Result<()>;
}

/// one the spawner made
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Machine {
    #[serde(default)]
    pub id: String,
    /// "aws", "fabric", or "" for Fly (state from before the AWS runner)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub runner: String,
    #[serde(default = "no_object")]
    pub source: Object,
    /// the source's image and settings (its snapshot is the predecessor's)
    #[serde(default = "empty_source")]
    pub content: Source,
    /// its volume, until its runner deleted it
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub volume: String,
    /// a fabric machine's conversation at hermit (the session's files); its sandbox is looked up by it
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub conversation: String,
    /// once init read them
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Keys>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub image: String,
    /// (source, fly-M, ⊤)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<Doc>,
    /// (fly-M, source-y, ⊤), or a kill record for one never up
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_cert: Option<Doc>,
    /// destroyed on its runner by a kill or a destroy
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub killed: bool,
}

impl Default for Machine {
    fn default() -> Self {
        Machine {
            id: String::new(),
            runner: String::new(),
            source: no_object(),
            content: empty_source(),
            volume: String::new(),
            conversation: String::new(),
            keys: None,
            image: String::new(),
            cert: None,
            kill_cert: None,
            killed: false,
        }
    }
}

fn no_object() -> Object {
    Object(String::new())
}

/// an empty source (a destroyed machine's record from Fly's metadata alone)
fn empty_source() -> Source {
    Source {
        image: String::new(),
        settings: serde_json::value::RawValue::from_string("null".into())
            .unwrap_or_else(|_| unreachable_settings()),
        snapshot: String::new(),
    }
}

#[allow(clippy::unwrap_used)] // a constant that parses
fn unreachable_settings() -> Box<serde_json::value::RawValue> {
    serde_json::value::RawValue::from_string("{}".into()).unwrap()
}

#[derive(Default, Serialize, Deserialize)]
struct StateFile {
    #[serde(default)]
    machines: Option<BTreeMap<String, Option<Machine>>>,
}

/// what the mutex guards
struct St {
    /// the Fly token (memory only), handed over with the machines
    token: String,
    aws_key: Option<AwsCredentials>,
    fabric_key: Option<FabricCredentials>,
    machines: BTreeMap<String, Machine>,
}

/// a machine id's runner: an EC2 instance id (i-…) is AWS's, x<32 hex> (a sandbox's id) the fabric's, anything else
/// Fly's (a Fly machine id is hex only)
pub fn runner_of(id: &str) -> &'static str {
    if id.starts_with("i-") {
        "aws"
    } else if fabric_id(id) {
        "fabric"
    } else {
        "fly"
    }
}

fn or_fly(runner: &str) -> &str {
    if runner.is_empty() { "fly" } else { runner }
}

/// the machine's object, "<runner>-<id>"
pub fn object(id: &str) -> Object {
    Object(format!("{}-{id}", runner_of(id)))
}

/// the digest of the image a machine of this runner may run: the fabric's image on the fabric, the session image
/// elsewhere; "" for any other reference
fn machine_image_digest(runner: &str, r: &str) -> String {
    if runner == "fabric" {
        fabric_image_digest(r)
    } else {
        image_digest(r)
    }
}

/// a runner call that failed, answered with its reason
fn fly_fail(what: &str, e: anyhow::Error) -> anyhow::Error {
    if let Some(m) = e.downcast_ref::<Missing>() {
        return match m {
            Missing::FlyToken => fail_because(503, REASON_NO_FLY_TOKEN, m.to_string()),
            Missing::AwsKey => fail_because(503, REASON_NO_AWS_KEY, m.to_string()),
            Missing::Fabric => fail_because(503, REASON_NO_FABRIC_KEY, m.to_string()),
            Missing::NotYet => fail_because(409, REASON_NOT_STARTED, m.to_string()),
        };
    }
    if e.downcast_ref::<FabricError>().is_some() {
        return fail_because(502, REASON_FABRIC, format!("fabric {what}: {e:#}"));
    }
    if e.downcast_ref::<AwsError>().is_some() {
        return fail_because(502, REASON_AWS, format!("aws {what}: {e:#}"));
    }
    fail_because(502, REASON_FLY, format!("fly {what}: {e:#}"))
}

/// what a machine signed over its snapshot (the hex sha256 of the tarball)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub sig: String,
}

/// the notarized cert into the source, and the machine's size, region and disk
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SpawnInput {
    pub cert: Doc,
    pub notarized: Doc,
    pub notarizer: Identity,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub size: String,
    #[serde(default)]
    pub disk_gb: i64,
    /// "aws", "fabric" or "fly" ("" = fly)
    #[serde(default)]
    pub runner: String,
    /// a fabric machine's conversation at hermit
    #[serde(default)]
    pub fabric: Option<FabricInput>,
    /// an AWS machine's way to the router, which the router makes per spawn
    #[serde(default)]
    pub wireguard: Option<WireGuard>,
}

pub struct Spawner {
    /// every call holds it shared; the handoff and the takeover hold it alone, so no call is halfway through when the
    /// state moves
    op: RwLock<()>,
    /// its mode in the copy flip (path + ".mode")
    cont: Continuity,
    st: Mutex<St>,
    signer: Signer,
    agreement: Opener,
    trust: Arc<Trust>,
    fly: Arc<dyn Fly>,
    aws: Option<Arc<AwsApi>>,
    fabric: OnceLock<(Arc<FabricApi>, BTreeMap<String, String>)>,
    /// what every Fly machine's config env gets (the router's address); the roster and the root key are added per spawn
    env: Option<BTreeMap<String, String>>,
    /// the same for an AWS machine (the router's address on the tailnet)
    aws_env: Option<BTreeMap<String, String>>,
    path: PathBuf,
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(suffix);
    PathBuf::from(p)
}

impl Spawner {
    /// the state at path (made if missing), its mode beside it. env, aws_env: the env every Fly / AWS machine gets
    /// (the router's address as that runner's machines reach it). aws None: no AWS runner.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        path: &Path,
        signer: Signer,
        agreement: Opener,
        t: Arc<Trust>,
        fly: Arc<dyn Fly>,
        aws: Option<Arc<AwsApi>>,
        env: Option<BTreeMap<String, String>>,
        aws_env: Option<BTreeMap<String, String>>,
    ) -> anyhow::Result<Spawner> {
        let cont = Continuity::open(&with_suffix(path, ".mode"))?;
        if let Some(r) = t.roster() {
            // a roster already held decides a new volume's mode now (else POST /roster does)
            cont.decide(&r, "spawner")?;
        }
        let mut machines = BTreeMap::new();
        match std::fs::read(path) {
            Ok(b) => {
                let st: StateFile = serde_json::from_slice(&b)
                    .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
                machines = st
                    .machines
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|(k, m)| m.map(|m| (k, m)))
                    .collect();
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(Spawner {
            op: RwLock::new(()),
            cont,
            st: Mutex::new(St {
                token: String::new(),
                aws_key: None,
                fabric_key: None,
                machines,
            }),
            signer,
            agreement,
            trust: t,
            fly,
            aws,
            fabric: OnceLock::new(),
            env,
            aws_env,
            path: path.into(),
        })
    }

    /// the fabric runner (docs/PLAN-fabric.md) and the env every fabric machine gets, before the spawner serves
    pub fn set_fabric(self: &Arc<Self>, f: Arc<FabricApi>, env: BTreeMap<String, String>) {
        let weak = Arc::downgrade(self);
        f.set_conversations(Box::new(move |id: &str| {
            weak.upgrade()
                .and_then(|sp| sp.lock().machines.get(id).map(|m| m.conversation.clone()))
                .unwrap_or_default()
        }));
        let _ = self.fabric.set((f, env));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, St> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn shared(&self) -> std::sync::RwLockReadGuard<'_, ()> {
        self.op.read().unwrap_or_else(|e| e.into_inner())
    }

    fn alone(&self) -> std::sync::RwLockWriteGuard<'_, ()> {
        self.op.write().unwrap_or_else(|e| e.into_inner())
    }

    /// the state, atomically (callers hold the lock)
    fn save(&self, g: &St) -> anyhow::Result<()> {
        let st = StateFile {
            machines: Some(
                g.machines
                    .iter()
                    .map(|(k, m)| (k.clone(), Some(m.clone())))
                    .collect(),
            ),
        };
        crate::files::write_synced(&self.path, go_json(&st)?.as_bytes())?;
        Ok(())
    }

    /// the API of a machine id's runner
    fn runner(&self, id: &str) -> Arc<dyn Runner> {
        match runner_of(id) {
            "aws" if self.aws.is_some() => self
                .aws
                .clone()
                .map(|a| a as Arc<dyn Runner>)
                .unwrap_or_else(|| self.fly_runner()),
            "fabric" => match self.fabric.get() {
                Some((f, _)) => f.clone(),
                None => Arc::new(NoFabric),
            },
            _ => self.fly_runner(),
        }
    }

    fn fly_runner(&self) -> Arc<dyn Runner> {
        Arc::new(FlyRunner(self.fly.clone()))
    }

    /// a call may go on (callers hold op shared)
    fn serving(&self) -> anyhow::Result<()> {
        self.cont.serving()
    }

    /// serving, standby or handed-off ("" before the first roster)
    pub fn mode(&self) -> String {
        self.cont.mode()
    }

    /// AwsCredentials sealed to the spawner's agreement key
    pub fn set_aws_credentials(&self, sealed: &Sealed) -> anyhow::Result<Value> {
        let _op = self.shared();
        self.serving()?;
        let Some(aws) = &self.aws else {
            return Err(fail(503, "this spawner has no AWS runner"));
        };
        let plain = self
            .agreement
            .open(sealed, INFO_AWS_KEY)
            .map_err(|_| fail(400, "can't open the AWS key"))?;
        let v: AwsCredentials = match serde_json::from_slice::<AwsCredentials>(&plain) {
            Ok(v) if !v.access_key_id.is_empty() && !v.secret_access_key.is_empty() => v,
            _ => {
                return Err(fail(
                    400,
                    "need AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY",
                ));
            }
        };
        aws.configure(v.clone());
        self.lock().aws_key = Some(v);
        log("AWS key set");
        Ok(json!({"kind": "aws-key-set"}))
    }

    /// FabricCredentials sealed to the spawner's agreement key
    pub fn set_fabric_credentials(&self, sealed: &Sealed) -> anyhow::Result<Value> {
        let _op = self.shared();
        self.serving()?;
        let Some((f, _)) = self.fabric.get() else {
            return Err(fail(503, "this spawner has no fabric runner"));
        };
        let plain = self
            .agreement
            .open(sealed, INFO_FABRIC)
            .map_err(|_| fail(400, "can't open the fabric credentials"))?;
        let v: FabricCredentials = match serde_json::from_slice::<FabricCredentials>(&plain) {
            Ok(v) if v.ok() => v,
            _ => return Err(fail(400, "need magpieToken, adminToken, admin and person")),
        };
        f.configure(v.clone());
        self.lock().fabric_key = Some(v);
        log("fabric credentials set");
        Ok(json!({"kind": "fabric-credentials-set"}))
    }

    /// {"FLY_API_TOKEN": …} sealed to the spawner's agreement key
    pub fn set_fly_token(&self, sealed: &Sealed) -> anyhow::Result<Value> {
        let _op = self.shared();
        self.serving()?;
        let plain = self
            .agreement
            .open(sealed, INFO_FLY_TOKEN)
            .map_err(|_| fail(400, "can't open the Fly token"))?;
        #[derive(Deserialize, Default)]
        struct T {
            #[serde(default, rename = "FLY_API_TOKEN")]
            token: String,
        }
        let v: T = serde_json::from_slice(&plain).unwrap_or_default();
        if v.token.is_empty() {
            return Err(fail(400, "no FLY_API_TOKEN"));
        }
        self.fly.configure(&v.token);
        self.lock().token = v.token;
        log("Fly token set");
        Ok(json!({"kind": "fly-token-set"}))
    }

    /// a machine on a new, empty disk on the source's runner (Fly: a volume and one create on it; AWS: one instance;
    /// the fabric: the conversation's sandbox), from a notarized source → {kind: "created", id, source, volume}. A Fly
    /// create that fails deletes the volume (one try; a volume left is the router's sweep's).
    pub fn spawn(&self, i: &SpawnInput) -> anyhow::Result<Value> {
        let _op = self.shared();
        self.serving()?;
        check_identity(&i.notarizer, "notarizer", &self.trust)
            .map_err(|e| fail(403, e.to_string()))?;
        let nz: Option<Notarized> = i.notarized.open::<Notarized>(&i.notarizer.signing_key).ok();
        if !nz.is_some_and(|nz| nz.kind == "notarized" && nz.cert == i.cert.id()) {
            return Err(fail(403, "the cert isn't notarized"));
        }
        let c = match peek_cert(&i.cert) {
            Ok(c) if c.succ.kind() == Some(Kind::Source) && c.source.is_some() => c,
            _ => return Err(fail(400, "a spawn is from a cert into a source")),
        };
        let content = c.source.clone().unwrap_or_else(empty_source);
        if i.runner == "fabric" {
            if fabric_image_digest(&content.image).is_empty() {
                return Err(fail(
                    400,
                    format!(
                        "the source's image isn't {} pinned by digest",
                        fabric::FABRIC_REPO
                    ),
                ));
            }
        } else if image_digest(&content.image).is_empty() {
            return Err(fail(
                400,
                format!("the source's image isn't {SESSION_REPO} pinned by digest"),
            ));
        }
        let (kind, cpus, mem) = size_guest(&i.size);
        if kind.is_empty() {
            return Err(fail(
                400,
                "size: small, medium, large or a doubling past it (16gb, 32gb, …)",
            ));
        }
        if i.disk_gb < 1 || i.disk_gb > MAX_DISK_GB || i.region.is_empty() {
            return Err(fail(400, format!("diskGb 1 to {MAX_DISK_GB} and a region")));
        }
        let run: Arc<dyn Runner> = match i.runner.as_str() {
            "" | "fly" => self.fly_runner(),
            "aws" => {
                let Some(aws) = &self.aws else {
                    return Err(fail(503, "this spawner has no AWS runner"));
                };
                if !aws_region(&i.region) {
                    return Err(fail(
                        400,
                        format!("no AWS region {}", jarvis_go::fmt::go_quote(&i.region)),
                    ));
                }
                if instance_type(mem).is_empty() {
                    return Err(fail(400, format!("no instance type for size {}", i.size)));
                }
                let Some(wg) = &i.wireguard else {
                    return Err(fail(400, "an AWS machine needs its wireguard"));
                };
                wg.check().map_err(|e| fail(400, e))?;
                aws.clone()
            }
            "fabric" => {
                let Some((f, _)) = self.fabric.get() else {
                    return Err(fail(503, "this spawner has no fabric runner"));
                };
                let Some(fi) = &i.fabric else {
                    return Err(fail(400, "a fabric machine needs its conversation"));
                };
                fi.check().map_err(|e| fail(400, e))?;
                f.clone()
            }
            _ => return Err(fail(400, "runner: aws, fabric or fly")),
        };
        let base = match i.runner.as_str() {
            "aws" => self.aws_env.clone(),
            "fabric" => self.fabric.get().map(|(_, e)| e.clone()),
            _ => self.env.clone(),
        };
        let Some(base) = base else {
            return Err(fail(
                503,
                format!(
                    "the spawner has no router address for its {} machines (KERNEL_MACHINE_URL, KERNEL_AWS_MACHINE_URL, KERNEL_FABRIC_MACHINE_URL)",
                    or_fly(&i.runner)
                ),
            ));
        };
        let Some(rd) = self.trust.doc() else {
            return Err(fail(503, no_roster()));
        };
        let guest = json!({"cpu_kind": kind, "cpus": cpus, "memory_mb": mem});
        // the machine checks the kernel's identities against the root key's roster (rust/machine kernelboot)
        let mut env = BTreeMap::from([
            ("JARVIS2_SOURCE".to_string(), c.succ.0.clone()),
            ("JARVIS2_KERNEL_ROSTER".to_string(), go_json(&rd)?),
            (
                "JARVIS2_KERNEL_ROOT".to_string(),
                self.trust.root().to_string(),
            ),
        ]);
        env.extend(base);
        let created = run.create(&CreateInput {
            image: content.image.clone(),
            region: i.region.clone(),
            guest,
            memory_mb: mem,
            env: env.clone(),
            disk_gb: i.disk_gb,
            source: c.succ.0.clone(),
            wireguard: i.wireguard.clone(),
            fabric: i.fabric.clone(),
        });
        let (id, vid) = match created {
            Ok(x) => x,
            Err(e) => {
                if fly_status(&e) == (412, "volume_placement_capacity".to_string()) {
                    // the volume's host has no room for this machine; a volume is pinned to its host, so a new spawn
                    // (a new volume) is the way to another host
                    return Err(fail_because(
                        502,
                        REASON_HOST_FULL,
                        format!("fly create: {e:#}"),
                    ));
                }
                if e.downcast_ref::<AwsError>()
                    .is_some_and(|a| a.code == "InsufficientInstanceCapacity")
                {
                    return Err(fail_because(
                        502,
                        REASON_HOST_FULL,
                        format!("aws create: {e:#}"),
                    ));
                }
                return Err(fly_fail("create", e));
            }
        };
        let runner = match runner_of(&id) {
            "fly" => String::new(),
            r => r.to_string(),
        };
        let mut m = Machine {
            id: id.clone(),
            runner: runner.clone(),
            source: c.succ.clone(),
            content: content.clone(),
            volume: vid.clone(),
            ..Default::default()
        };
        if runner == "fabric"
            && let Some(fi) = &i.fabric
        {
            m.conversation = fi.conversation.clone();
        }
        {
            let mut g = self.lock();
            // hermit answers a conversation's sandbox that is already there: a machine the spawner made before. From
            // this source it is this spawn's machine (an earlier spawn whose answer was lost); from another source it
            // is not, and one session's files never get a second machine.
            if let Some(old) = g.machines.get(&id) {
                if old.source != c.succ || old.killed {
                    return Err(fail_because(
                        409,
                        REASON_FABRIC_BUSY,
                        format!(
                            "the conversation's sandbox {id} is the machine made from {}",
                            old.source.0
                        ),
                    ));
                }
                return Ok(
                    json!({"kind": "created", "id": id, "source": c.succ, "volume": "", "env": env}),
                );
            }
            g.machines.insert(id.clone(), m);
            self.save(&g)?;
        }
        log(&format!(
            "machine {id} created from {} ({})",
            c.succ.0, content.image
        ));
        let mut out = json!({"kind": "created", "id": id, "source": c.succ, "volume": vid});
        if runner == "fabric" {
            // hermit's contract carries no environment to a sandbox: the router serves it to the machine
            out["env"] = json!(env);
        }
        Ok(out)
    }

    /// one try at reading a created machine's keys (409 while it isn't up yet: the router retries) → its cert
    pub fn init(&self, id: &str) -> anyhow::Result<Doc> {
        let _op = self.shared();
        self.serving()?;
        let m = self.lock().machines.get(id).cloned();
        let Some(m) = m else {
            return Err(fail_because(
                404,
                REASON_UNKNOWN,
                format!("machine {id} isn't one the spawner made"),
            ));
        };
        if let Some(c) = &m.cert {
            return Ok(c.clone());
        }
        let run = self.runner(id);
        let fm = run.inspect(id).map_err(|e| fly_fail("inspect", e))?;
        if fm.state != "started" {
            return Err(fail_because(
                409,
                REASON_NOT_STARTED,
                format!("machine {id} is {}, not started", fm.state),
            ));
        }
        let d = machine_image_digest(runner_of(id), &m.content.image);
        if d.is_empty() || reported_digest(&fm.image) != d {
            return Err(fail_because(
                409,
                REASON_WRONG_IMAGE,
                format!(
                    "machine {id} runs {}, not its source's {}",
                    fm.image, m.content.image
                ),
            ));
        }
        let k = run.init(id).map_err(|e| fly_fail("init", e))?;
        let keys = Keys {
            signing_key: k.signing_key.clone(),
            encryption_key: k.encryption_key.clone(),
        };
        let c = Cert {
            kind: "succession".into(),
            pred: m.source.clone(),
            succ: object(id),
            pair: Pair::top(),
            source: None,
            machine: Some(DocMachine {
                signing_key: keys.signing_key.clone(),
                encryption_key: keys.encryption_key.clone(),
                image: fm.image.clone(),
            }),
            signer: by::SPAWNER.into(),
            issued_at: now(),
        };
        c.check()
            .map_err(|e| fail(502, format!("machine {id}: {e}")))?;
        let d = self.signer.sign_json(&c)?;
        let mut g = self.lock();
        let Some(cur) = g.machines.get_mut(id) else {
            return Err(fail_because(
                404,
                REASON_UNKNOWN,
                format!("machine {id} isn't one the spawner made"),
            ));
        };
        if let Some(c) = &cur.cert {
            return Ok(c.clone()); // an init meanwhile: the first cert wins
        }
        if cur.killed {
            return Err(fail_because(
                409,
                REASON_KILLED,
                format!("machine {id} was killed meanwhile"),
            ));
        }
        cur.keys = Some(keys);
        cur.image = fm.image.clone();
        cur.cert = Some(d.clone());
        self.save(&g)?;
        drop(g);
        log(&format!("machine {id} up ({})", fm.image));
        Ok(d)
    }

    /// the machine destroyed, as its runner says (single calls: a destroy, then a look) → its volume as the runner
    /// listed it ("" on AWS and the fabric)
    fn destroy_on_runner(&self, id: &str) -> anyhow::Result<String> {
        let run = self.runner(id);
        let mut fm = run.inspect(id).map_err(|e| fly_fail("inspect", e))?;
        let vol = fm.volume.clone();
        if fm.state != "destroyed" {
            let derr = run.destroy(id);
            fm = run.inspect(id).map_err(|e| fly_fail("inspect", e))?;
            if fm.state != "destroyed" {
                let why = match derr {
                    Ok(()) => "<nil>".to_string(),
                    Err(e) => format!("{e:#}"),
                };
                return Err(fail_because(
                    409,
                    REASON_NOT_DESTROYED,
                    format!(
                        "machine {id} is {}, not destroyed yet (destroy: {why})",
                        fm.state
                    ),
                ));
            }
        }
        Ok(vol)
    }

    /// one try at deleting the destroyed machine's volume → the volume still there ("" = gone)
    fn drop_volume(&self, id: &str) -> String {
        let v = self
            .lock()
            .machines
            .get(id)
            .map(|m| m.volume.clone())
            .unwrap_or_default();
        if v.is_empty() {
            return String::new();
        }
        if let Err(e) = self.runner(id).delete_volume(&v)
            && fly_status(&e).0 != 404
        {
            log(&format!(
                "machine {id}: volume {v}: delete: {e:#} (the router kills it again)"
            ));
            return v;
        }
        let mut g = self.lock();
        if let Some(m) = g.machines.get_mut(id) {
            m.volume.clear();
        }
        let _ = self.save(&g);
        String::new()
    }

    /// the machine destroyed (409 until its runner reports it) → {kind: "killed", id, cert: (fly-M, source-y, ⊤),
    /// volumeLeft}. The cert is signed once per machine and answered again to every later kill; each kill makes one
    /// try at deleting the machine's volume, and volumeLeft names it while it is still there (the router kills again).
    pub fn kill(&self, id: &str, snap: Option<&Snapshot>) -> anyhow::Result<Value> {
        let _op = self.shared();
        self.serving()?;
        let m = self.lock().machines.get(id).cloned();
        let Some(m) = m else {
            return Err(fail_because(
                404,
                REASON_UNKNOWN,
                format!("machine {id} isn't one the spawner made"),
            ));
        };
        if m.kill_cert.is_none() {
            let mut sum = String::new();
            if let Some(snap) = snap {
                let Some(keys) = &m.keys else {
                    return Err(fail_because(
                        400,
                        REASON_BAD_SNAPSHOT,
                        format!("machine {id} never came up, so it signed no snapshot"),
                    ));
                };
                let hex64 = snap.sha256.len() == 64
                    && snap
                        .sha256
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
                if !hex64 || !verify(&keys.signing_key, snap.sha256.as_bytes(), &snap.sig) {
                    return Err(fail_because(
                        400,
                        REASON_BAD_SNAPSHOT,
                        format!("machine {id}'s snapshot isn't signed by its key"),
                    ));
                }
                sum = snap.sha256.clone();
            }
            self.destroy_on_runner(id)?;
            let d = if m.keys.is_none() {
                // never up: no state, nothing goes on from it
                self.signer
                    .sign_json(&json!({"kind": "killed", "id": id, "up": false}))?
            } else {
                // a machine that signed no snapshot passes on the one its source named: it has no newer state the
                // spawner vouched for
                let mut src = m.content.clone();
                if !sum.is_empty() {
                    src.snapshot = sum.clone();
                }
                let c = Cert {
                    kind: "succession".into(),
                    pred: object(id),
                    succ: new_source(),
                    pair: Pair::top(),
                    source: Some(src),
                    machine: None,
                    signer: by::SPAWNER.into(),
                    issued_at: now(),
                };
                c.check().map_err(|e| anyhow::anyhow!("{e}"))?;
                self.signer.sign_json(&c)?
            };
            let mut g = self.lock();
            if let Some(cur) = g.machines.get_mut(id)
                && cur.kill_cert.is_none()
            {
                // a kill meanwhile: its cert is the one
                cur.killed = true;
                cur.kill_cert = Some(d);
                self.save(&g)?;
            }
            drop(g);
            log(&format!(
                "machine {id} killed (snapshot {})",
                jarvis_go::fmt::go_quote(&sum)
            ));
        }
        let left = self.drop_volume(id);
        let d = self
            .lock()
            .machines
            .get(id)
            .and_then(|m| m.kill_cert.clone());
        Ok(json!({"kind": "killed", "id": id, "cert": d, "volumeLeft": left}))
    }

    /// a machine the spawner made that never came up (a spawn whose answer was lost, also one made just before a
    /// restart that the state never recorded: its runner's metadata names its source) destroyed → {kind: "destroyed",
    /// id, volumeLeft}, no cert. A machine with a cert is killed instead (409 came-up).
    pub fn destroy(&self, id: &str) -> anyhow::Result<Value> {
        let _op = self.shared();
        self.serving()?;
        let m = self.lock().machines.get(id).cloned();
        if let Some(m) = &m
            && m.cert.is_some()
            && m.kill_cert.is_none()
        {
            return Err(fail_because(
                409,
                REASON_CAME_UP,
                format!("machine {id} came up: it is killed, not destroyed"),
            ));
        }
        if !m.as_ref().is_some_and(|m| m.killed) {
            let mut fresh = None;
            if m.is_none() {
                let fm = self
                    .runner(id)
                    .inspect(id)
                    .map_err(|e| fly_fail("inspect", e))?;
                if fm.source.is_empty() {
                    return Err(fail_because(
                        404,
                        REASON_UNKNOWN,
                        format!("machine {id} isn't one the spawner made"),
                    ));
                }
                fresh = Some(Machine {
                    id: id.into(),
                    runner: match runner_of(id) {
                        "fly" => String::new(),
                        r => r.to_string(),
                    },
                    source: Object(fm.source),
                    content: empty_source(),
                    ..Default::default()
                });
            }
            let vol = self.destroy_on_runner(id)?;
            let mut g = self.lock();
            if !g.machines.contains_key(id)
                && let Some(f) = fresh
            {
                g.machines.insert(id.into(), f);
            }
            if let Some(cur) = g.machines.get_mut(id) {
                if cur.volume.is_empty() {
                    cur.volume = vol;
                }
                cur.killed = true;
            }
            self.save(&g)?;
            drop(g);
            log(&format!("machine {id} destroyed (never came up)"));
        }
        Ok(json!({"kind": "destroyed", "id": id, "volumeLeft": self.drop_volume(id)}))
    }
}

/// a fresh source: "source-" and 16 random bytes in hex (Go's doc.NewSource)
fn new_source() -> Object {
    use rand_core::RngCore as _;
    let mut b = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut b);
    Object(format!(
        "source-{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    ))
}

/// the runner of a fabric machine on a spawner without the fabric runner: every call fails, none reaches Fly
struct NoFabric;

impl Runner for NoFabric {
    fn create(&self, _: &CreateInput) -> anyhow::Result<(String, String)> {
        Err(Missing::Fabric.into())
    }
    fn inspect(&self, _: &str) -> anyhow::Result<RunMachine> {
        Err(Missing::Fabric.into())
    }
    fn init(&self, _: &str) -> anyhow::Result<MachineKeys> {
        Err(Missing::Fabric.into())
    }
    fn destroy(&self, _: &str) -> anyhow::Result<()> {
        Err(Missing::Fabric.into())
    }
    fn delete_volume(&self, _: &str) -> anyhow::Result<()> {
        Err(Missing::Fabric.into())
    }
}

// ---- the copy flip (Stateful) --------------------------------------------------------------------------------

/// the state as it moves to the other copy
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Handed {
    machines: Option<BTreeMap<String, Option<Machine>>>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    fly_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "awsKey")]
    aws_key: Option<AwsCredentials>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fabric: Option<FabricCredentials>,
}

impl Stateful for Spawner {
    fn decide(&self, r: &Roster) -> anyhow::Result<()> {
        let _op = self.alone();
        self.cont.decide(r, "spawner")
    }

    /// frozen once no call is under way (no runner call after it), then the machines and the tokens
    fn handoff(&self, roster: &str) -> anyhow::Result<Vec<u8>> {
        let _op = self.alone();
        self.cont.freeze(roster)?;
        let g = self.lock();
        Ok(go_json(&Handed {
            machines: Some(
                g.machines
                    .iter()
                    .map(|(k, m)| (k.clone(), Some(m.clone())))
                    .collect(),
            ),
            fly_token: g.token.clone(),
            aws_key: g.aws_key.clone(),
            fabric: g.fabric_key.clone(),
        })?
        .into_bytes())
    }

    /// the predecessor's machines replace this volume's (saved before it serves), and its tokens
    fn takeover(&self, id: &str, state: &[u8]) -> anyhow::Result<()> {
        let _op = self.alone();
        if self.cont.can_take(id)? {
            return Ok(());
        }
        let h: Handed =
            strict_json(state).map_err(|e| fail(400, format!("the handed state: {e}")))?;
        let machines: BTreeMap<String, Machine> = h
            .machines
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(k, m)| m.map(|m| (k, m)))
            .collect();
        let n = machines.len();
        {
            let mut g = self.lock();
            g.machines = machines;
            self.save(&g)?;
            if !h.fly_token.is_empty() {
                self.fly.configure(&h.fly_token);
                g.token = h.fly_token.clone();
            }
            if let (Some(k), Some(aws)) = (&h.aws_key, &self.aws) {
                aws.configure(k.clone());
                g.aws_key = Some(k.clone());
            }
            if let (Some(k), Some((f, _))) = (&h.fabric, self.fabric.get()) {
                f.configure(k.clone());
                g.fabric_key = Some(k.clone());
            }
        }
        self.cont.took(id)?;
        log(&format!(
            "took over {n} machines (Fly token: {}, AWS key: {}); serving",
            !h.fly_token.is_empty(),
            h.aws_key.is_some()
        ));
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedIn {
    sealed: Sealed,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdIn {
    #[serde(default)]
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KillIn {
    #[serde(default)]
    id: String,
    #[serde(default)]
    snapshot: Option<Snapshot>,
}

pub fn register(s: &Arc<Server>, sp: Arc<Spawner>) {
    let st: Arc<dyn Stateful> = sp.clone();
    let _ = s.state.set(st);
    let p = sp.clone();
    handle(s, "POST /fly-token", move |i: SealedIn| {
        Answer::of(&p.set_fly_token(&i.sealed)?)
    });
    let p = sp.clone();
    handle(s, "POST /aws-credentials", move |i: SealedIn| {
        Answer::of(&p.set_aws_credentials(&i.sealed)?)
    });
    let p = sp.clone();
    handle(s, "POST /fabric-credentials", move |i: SealedIn| {
        Answer::of(&p.set_fabric_credentials(&i.sealed)?)
    });
    let p = sp.clone();
    handle(s, "POST /spawn", move |i: SpawnInput| {
        Answer::of(&p.spawn(&i)?)
    });
    let p = sp.clone();
    handle(s, "POST /init", move |i: IdIn| {
        Ok(Answer::Doc(p.init(&i.id)?))
    });
    let p = sp.clone();
    handle(s, "POST /kill", move |i: KillIn| {
        Answer::of(&p.kill(&i.id, i.snapshot.as_ref())?)
    });
    let p = sp;
    handle(s, "POST /destroy", move |i: IdIn| {
        Answer::of(&p.destroy(&i.id)?)
    });
}
