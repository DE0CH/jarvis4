//! The Fly Machines API (kernel/spawner/fly.go), used only by the spawner, the only holder of the Fly token (sealed to
//! it by the setup session: POST /fly-token). The token is narrowed to app jarvis4-sessions and to one command inside
//! a machine: jarvis2-init, with no arguments, whose output is the machine's public keys, so their link to the machine
//! is Fly's word, not the machine's or the router's. Volumes are made with Fly's automatic backups off: a session's
//! state is its signed snapshot only (Deyao, 2026-10-21: "let's not keep volume backups").

use super::{CreateInput, MachineKeys, Missing, RunMachine, Runner};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Fly: single calls, no waiting or retrying (the router retries)
pub trait Fly: Send + Sync {
    fn configure(&self, token: &str);
    /// an empty volume; guest is the machine's size, Fly's hint to put the volume on a host with room for that machine
    fn create_volume(&self, region: &str, size_gb: i64, guest: &Value) -> anyhow::Result<String>;
    /// a machine whose Fly metadata names the source it is from, so the router (with its read-only token) finds one
    /// whose answer was lost
    fn create(
        &self,
        image: &str,
        region: &str,
        guest: &Value,
        env: &BTreeMap<String, String>,
        volume: &str,
        source: &str,
    ) -> anyhow::Result<String>;
    fn inspect(&self, id: &str) -> anyhow::Result<RunMachine>;
    fn init(&self, id: &str) -> anyhow::Result<MachineKeys>;
    fn destroy(&self, id: &str) -> anyhow::Result<()>;
    fn delete_volume(&self, volume: &str) -> anyhow::Result<()>;
}

/// the Fly API as a Runner: a volume, then the machine on it (a create that fails deletes the volume)
pub struct FlyRunner(pub Arc<dyn Fly>);

impl Runner for FlyRunner {
    fn create(&self, i: &CreateInput) -> anyhow::Result<(String, String)> {
        let vid = self.0.create_volume(&i.region, i.disk_gb, &i.guest)?;
        match self
            .0
            .create(&i.image, &i.region, &i.guest, &i.env, &vid, &i.source)
        {
            Ok(id) => Ok((id, vid)),
            Err(e) => match self.0.delete_volume(&vid) {
                Ok(()) => Err(e),
                Err(de) => Err(e.context(format!("volume {vid} left: {de:#}"))),
            },
        }
    }
    fn inspect(&self, id: &str) -> anyhow::Result<RunMachine> {
        self.0.inspect(id)
    }
    fn init(&self, id: &str) -> anyhow::Result<MachineKeys> {
        self.0.init(id)
    }
    fn destroy(&self, id: &str) -> anyhow::Result<()> {
        self.0.destroy(id)
    }
    fn delete_volume(&self, volume: &str) -> anyhow::Result<()> {
        self.0.delete_volume(volume)
    }
}

/// Fly's refusal: its HTTP status and the "status" word of its JSON answer (e.g. volume_placement_capacity)
#[derive(Debug, Clone)]
pub struct FlyError {
    pub http: u16,
    pub status: String,
    pub msg: String,
}

impl std::fmt::Display for FlyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for FlyError {}

/// the refusal's HTTP status and Fly's status word (0, "" when e isn't Fly's refusal)
pub fn fly_status(e: &anyhow::Error) -> (u16, String) {
    e.downcast_ref::<FlyError>()
        .map(|f| (f.http, f.status.clone()))
        .unwrap_or((0, String::new()))
}

/// the session image's one command the spawner may run (session-image/Dockerfile); the Fly token allows only it
const INIT_PATH: &str = "/usr/local/bin/jarvis2-init";

/// the one Fly app the spawner makes machines in
pub const FLY_APP: &str = "jarvis4-sessions";

/// the Fly metadata key naming the source a machine is from (the router lists machines by it)
pub const SOURCE_META: &str = "jarvis4_source";

/// where the machine finds its volume
const VOLUME_PATH: &str = "/data";
const VOLUME_NAME: &str = "jarvis4_state";

// ---- machine sizes (the same rules are in rust/router/src/sizes.rs, rust/machine/src/deliver.rs and core/fly.go;
// the test the_sizes_match_the_routers) ----

/// the size's memory in GB; 0 = not a size: small (2 GB), medium (4 GB), large (8 GB), then every doubling past
/// large, named by its memory ("16gb", "32gb", …)
pub fn size_mem_gb(size: &str) -> i64 {
    for (n, gb) in [("small", 2), ("medium", 4), ("large", 8)] {
        if size == n {
            return gb;
        }
    }
    let Some(n) = size.strip_suffix("gb").and_then(|n| n.parse::<i64>().ok()) else {
        return 0;
    };
    if !(16..=1 << 20).contains(&n) || n & (n - 1) != 0 || format!("{n}gb") != size {
        return 0;
    }
    n
}

/// the size's Fly guest. Fly takes at most 2 GB per shared CPU and 8 GB per performance CPU. The named three have one
/// shared CPU per GB; 16 GB is the most a shared guest holds (8 CPUs × 2 GB); past it the guest is performance, with
/// large's 8 CPUs or, once the memory needs more (8 GB each), memory/8 CPUs.
pub fn size_guest(size: &str) -> (&'static str, i64, i64) {
    match size_mem_gb(size) {
        0 => ("", 0, 0),
        gb if gb <= 8 => ("shared", gb, gb * 1024),
        gb if gb <= 16 => ("shared", 8, gb * 1024),
        gb => ("performance", (gb / 8).max(8), gb * 1024),
    }
}

// ---- end of the machine sizes block ----

pub struct FlyApi {
    token: Mutex<String>,
    pub base: String,
    http: reqwest::blocking::Client,
}

impl FlyApi {
    pub fn new() -> FlyApi {
        FlyApi {
            token: Mutex::new(String::new()),
            base: "https://api.machines.dev/v1".into(),
            http: reqwest::blocking::Client::builder()
                .connect_timeout(Duration::from_secs(30))
                .timeout(Duration::from_secs(120))
                .build()
                .unwrap_or_default(),
        }
    }

    fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> anyhow::Result<Vec<u8>> {
        let token = self.token.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if token.is_empty() {
            return Err(Missing::FlyToken.into());
        }
        let m = method.as_str().to_string();
        let mut req = self
            .http
            .request(method, format!("{}/apps/{FLY_APP}{path}", self.base))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json");
        if let Some(b) = body {
            req = req.body(jarvis_sig::go_json(&b)?);
        }
        let resp = req.send()?;
        let status = resp.status().as_u16();
        let b = resp.bytes()?.to_vec();
        if status / 100 != 2 {
            let t = String::from_utf8_lossy(&b).trim().to_string();
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct St {
                status: String,
            }
            let st: St = jarvis_go::json::unmarshal(&b).unwrap_or_default();
            return Err(FlyError {
                http: status,
                status: st.status,
                msg: format!(
                    "{m} {path}: HTTP {status} {}",
                    jarvis_go::fmt::clip_bytes(&t, 300)
                ),
            }
            .into());
        }
        Ok(b)
    }
}

impl Default for FlyApi {
    fn default() -> Self {
        Self::new()
    }
}

impl Fly for FlyApi {
    fn configure(&self, token: &str) {
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = token.into();
    }

    fn create_volume(&self, region: &str, size_gb: i64, guest: &Value) -> anyhow::Result<String> {
        let body = json!({"name": VOLUME_NAME, "region": region, "size_gb": size_gb, "encrypted": true,
            "snapshot_retention": 1, "auto_backup_enabled": false, "require_unique_zone": false, "compute": guest});
        let b = self.call(reqwest::Method::POST, "/volumes", Some(body))?;
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct V {
            id: String,
        }
        let v: V = jarvis_go::json::unmarshal(&b)?;
        if v.id.is_empty() {
            return Err(anyhow::anyhow!("fly made no volume"));
        }
        Ok(v.id)
    }

    fn create(
        &self,
        image: &str,
        region: &str,
        guest: &Value,
        env: &BTreeMap<String, String>,
        volume: &str,
        source: &str,
    ) -> anyhow::Result<String> {
        let config = json!({"image": image, "guest": guest, "env": env, "restart": {"policy": "no"},
            "metadata": {SOURCE_META: source}, "mounts": [{"volume": volume, "path": VOLUME_PATH}]});
        let b = self.call(
            reqwest::Method::POST,
            "/machines",
            Some(json!({"region": region, "config": config})),
        )?;
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct M {
            id: String,
        }
        Ok(jarvis_go::json::unmarshal::<M>(&b)?.id)
    }

    fn inspect(&self, id: &str) -> anyhow::Result<RunMachine> {
        let b = match self.call(reqwest::Method::GET, &format!("/machines/{id}"), None) {
            Ok(b) => b,
            // Fly forgets a machine some time after it is destroyed
            Err(e) if fly_status(&e).0 == 404 => {
                return Ok(RunMachine {
                    state: "destroyed".into(),
                    ..Default::default()
                });
            }
            Err(e) => return Err(e),
        };
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Mount {
            volume: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Config {
            image: String,
            metadata: Option<BTreeMap<String, String>>,
            mounts: Option<Vec<Mount>>,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Ref {
            registry: String,
            repository: String,
            digest: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct M {
            state: String,
            config: Config,
            image_ref: Ref,
        }
        let m: M = jarvis_go::json::unmarshal(&b)?;
        let mut fm = RunMachine {
            state: m.state,
            image: m.config.image.clone(),
            source: m
                .config
                .metadata
                .as_ref()
                .and_then(|x| x.get(SOURCE_META).cloned())
                .unwrap_or_default(),
            volume: String::new(),
        };
        if !m.image_ref.digest.is_empty() {
            fm.image = format!(
                "{}/{}@{}",
                m.image_ref.registry, m.image_ref.repository, m.image_ref.digest
            );
        }
        if let Some(v) = m.config.mounts.as_ref().and_then(|v| v.first()) {
            fm.volume = v.volume.clone();
        }
        Ok(fm)
    }

    /// jarvis2-init waits for the machine's keys (made at boot), prints them and lets boot go on. One run.
    fn init(&self, id: &str) -> anyhow::Result<MachineKeys> {
        let b = self.call(
            reqwest::Method::POST,
            &format!("/machines/{id}/exec"),
            Some(json!({"command": [INIT_PATH], "timeout": 60})),
        )?;
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Out {
            stdout: String,
            stderr: String,
            exit_code: i64,
        }
        let out: Out = jarvis_go::json::unmarshal(&b)?;
        if out.exit_code != 0 {
            return Err(anyhow::anyhow!(
                "exit {}: {}",
                out.exit_code,
                out.stderr.trim()
            ));
        }
        match jarvis_go::json::unmarshal::<MachineKeys>(out.stdout.trim().as_bytes()) {
            Ok(k) if !k.encryption_key.is_empty() && !k.signing_key.is_empty() => Ok(k),
            _ => Err(anyhow::anyhow!("jarvis2-init gave no keys")),
        }
    }

    fn destroy(&self, id: &str) -> anyhow::Result<()> {
        self.call(
            reqwest::Method::DELETE,
            &format!("/machines/{id}?force=true"),
            None,
        )
        .map(|_| ())
    }

    fn delete_volume(&self, volume: &str) -> anyhow::Result<()> {
        self.call(reqwest::Method::DELETE, &format!("/volumes/{volume}"), None)
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(size_guest("small"), ("shared", 2, 2048));
        assert_eq!(size_guest("16gb"), ("shared", 8, 16384));
        assert_eq!(size_guest("128gb"), ("performance", 16, 131072));
        assert_eq!(size_guest("12gb"), ("", 0, 0));
    }

    /// the router's sizes are the spawner's (rust/router/src/sizes.rs)
    #[test]
    fn the_sizes_match_the_routers() {
        let rs = include_str!("../../../router/src/sizes.rs");
        for need in [
            r#"("small", 2), ("medium", 4), ("large", 8)"#,
            "n & (n - 1) != 0",
        ] {
            assert!(
                rs.contains(need),
                "rust/router/src/sizes.rs's sizes differ from the spawner's (no {need})"
            );
        }
    }
}
