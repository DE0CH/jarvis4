//! The AWS runner (docs/PLAN-aws.md; Deyao, 2026-11-03: AWS the default, Fly kept as an option). A session's runner
//! says where its machines run: "aws" (one EC2 instance per machine, kernel/spawner/aws.go) or "fly". Its region stays
//! a place (London, Singapore, Tokyo: regions.rs), which each runner maps to its own region.
//!
//! An AWS machine reaches the router over WireGuard: the router makes the machine's key pair and tunnel address per
//! spawn (kept on the session until the machine is up), the spawner writes them into the instance, and the m-gateways,
//! which list the machines here (GET /gw/aws-peers on the machines' port, closed to the machines themselves), start the
//! handshakes to each instance's public IPv4. Nothing about the tunnel is a trust element: every /m request is signed
//! by the machine's certified key.
//!
//!   DEFAULT_RUNNER            aws | fly: the runner a session gets when it names none (default fly)
//!   WG_AWS_GATEWAYS           the m-gateways' WireGuard public keys and tunnel addresses: "<key>@10.99.0.1,…"
//!   AWS_READ_ACCESS_KEY_ID, AWS_READ_SECRET_ACCESS_KEY   the router's read-only AWS key

use crate::http::Registrar;
use crate::nethttp::write_json;
use crate::router::Router;
use crate::state::{Persisted, Session};
use anyhow::{Result, anyhow};
use base64::Engine;
use jarvis_go::GoTime;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

pub struct RunnerOption {
    pub id: &'static str,
    pub label: &'static str,
}

/// what New session offers (the fabric only once the router has a fabric hermit: fabricrunner.rs). Hidden on
/// 2026-11-18 when a fabric session's final snapshot could not reach the snapshot bucket (its sandbox had no
/// resolvers); offered again with sandboxd aviary-15f22fb9c7fd, checked on the fabric replica (aviary
/// testing/fabric-replica: egress by name, pause, freeze and thaw).
pub fn session_runners() -> Vec<RunnerOption> {
    let mut out = vec![
        RunnerOption {
            id: "aws",
            label: "AWS",
        },
        RunnerOption {
            id: "fly",
            label: "Fly",
        },
    ];
    if crate::fabricrunner::fabric_enabled() {
        out.push(RunnerOption {
            id: "fabric",
            label: "Fabric (gVisor)",
        });
    }
    out
}

pub fn valid_runner(id: &str) -> bool {
    id == "aws" || id == "fly" || (id == "fabric" && crate::fabricrunner::fabric_enabled())
}

/// DEFAULT_RUNNER, else fly
pub fn default_runner() -> String {
    let v = std::env::var("DEFAULT_RUNNER").unwrap_or_default();
    if valid_runner(&v) { v } else { "fly".into() }
}

/// the regions the spawner starts instances in (the router's session regions for the aws runner)
pub const AWS_REGIONS: &[&str] = &["ap-northeast-1", "ap-southeast-1", "eu-west-2"];

/// each session region (regions.rs, Fly's codes) as the AWS region in the same place
pub fn aws_region_of(reg: &str) -> Option<&'static str> {
    match reg {
        "lhr" => Some("eu-west-2"),
        "sin" => Some("ap-southeast-1"),
        "nrt" => Some("ap-northeast-1"),
        _ => None,
    }
}

/// a runner as the log says it
pub fn runner_label(runner: &str) -> &'static str {
    match runner {
        "aws" => "AWS",
        "fabric" => "the fabric",
        "fly" => "Fly",
        _ => "its runner",
    }
}

/// an AWS machine's WireGuard: its key pair and tunnel address (the private key only until the machine is up)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AwsWg {
    #[serde(rename = "privateKey", skip_serializing_if = "String::is_empty")]
    pub private_key: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub address: String,
}

/// the spawner's WireGuard of a new machine (kernel/spawner WireGuard)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpawnWireGuard {
    #[serde(rename = "privateKey")]
    pub private_key: String,
    pub address: String,
    pub peers: Vec<WgPeer>,
}

/// one m-gateway: its public key and its tunnel address (the instance routes only that /32 to it)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WgPeer {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub address: String,
}

/// a fresh key pair and the first tunnel address in 10.99.1.0–10.99.255.254 that no machine of used has
pub fn new_aws_wg(used: &BTreeSet<String>) -> Result<AwsWg> {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    k[0] &= 248; // clamped, as wg genkey makes them
    k[31] = (k[31] & 127) | 64;
    let pubk = x25519_dalek::x25519(k, x25519_dalek::X25519_BASEPOINT_BYTES);
    let b64 = base64::engine::general_purpose::STANDARD;
    for x in 1u32..=255 {
        for y in 0u32..=255 {
            if y == 0 || (x == 255 && y == 255) {
                continue;
            }
            let a = format!("10.99.{x}.{y}");
            if used.contains(&a) {
                continue;
            }
            return Ok(AwsWg {
                private_key: b64.encode(k),
                public_key: b64.encode(pubk),
                address: a,
            });
        }
    }
    Err(anyhow!("no free WireGuard address for an AWS machine"))
}

/// the tunnel addresses of every machine and pending spawn the router knows (under the state lock)
pub fn used_wg_addresses(d: &Persisted) -> BTreeSet<String> {
    d.started
        .values()
        .filter_map(|s| s.wg.as_ref().map(|w| w.address.clone()))
        .chain(
            d.sessions
                .values()
                .filter_map(|s| s.wg.as_ref().map(|w| w.address.clone())),
        )
        .collect()
}

/// WG_AWS_GATEWAYS as the spawner's peers
pub fn aws_gateways() -> Result<Vec<WgPeer>> {
    let out: Vec<WgPeer> = std::env::var("WG_AWS_GATEWAYS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|p| {
            let (k, a) = p.trim().split_once('@')?;
            Some(WgPeer {
                public_key: k.into(),
                address: a.into(),
            })
        })
        .collect();
    if out.is_empty() {
        return Err(anyhow!(
            "WG_AWS_GATEWAYS is not set: no AWS machine can reach the router"
        ));
    }
    Ok(out)
}

/// a session instance as EC2 lists it, in the spawner's state words
#[derive(Debug, Clone, Default)]
pub struct Instance {
    pub id: String,
    pub region: String,
    pub state: String,
    pub source: String,
    pub type_: String,
    /// its public IPv4 address (the m-gateways' endpoint)
    pub public_ip: String,
    pub launched: GoTime,
}

/// EC2's instance state as the spawner's word
pub fn state_word(s: &str) -> String {
    match s {
        "pending" => "created",
        "running" => "started",
        "terminated" => "destroyed",
        "shutting-down" => "destroying",
        x => x, // stopping, stopped
    }
    .to_string()
}

/// the newest listing (lost_tick), for the gateways' peers
static AWS_SEEN: LazyLock<Mutex<BTreeMap<String, Instance>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// tests: what the newest listing saw of an instance (None: forget it)
#[cfg(test)]
pub fn aws_seen_set(id: &str, i: Option<Instance>) {
    let mut g = AWS_SEEN.lock().unwrap_or_else(|e| e.into_inner());
    match i {
        Some(i) => g.insert(id.to_string(), i),
        None => g.remove(id),
    };
}

/// the region the newest listing saw the instance in ("" when it didn't)
pub fn aws_region_of_instance(id: &str) -> String {
    AWS_SEEN
        .lock()
        .ok()
        .and_then(|g| g.get(id).map(|i| i.region.clone()))
        .unwrap_or_default()
}

/// the tag a session instance carries: the source it runs
pub const SOURCE_TAG: &str = "jarvis4_source";

/// every session instance EC2 lists (empty when the router has no AWS key: no AWS machines)
pub fn list_aws_machines() -> Result<Vec<Instance>> {
    if !crate::awsread::aws_read_on() {
        return Ok(vec![]);
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Named {
        name: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Tag {
        key: String,
        value: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Items<T> {
        item: Vec<T>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Inst {
        #[serde(rename = "instanceId")]
        id: String,
        #[serde(rename = "instanceState")]
        state: Named,
        #[serde(rename = "tagSet")]
        tags: Items<Tag>,
        #[serde(rename = "instanceType")]
        type_: String,
        #[serde(rename = "ipAddress")]
        public_ip: String,
        #[serde(rename = "launchTime")]
        launched: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Res {
        #[serde(rename = "instancesSet")]
        instances: Items<Inst>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Out {
        #[serde(rename = "reservationSet")]
        reservations: Items<Res>,
    }
    let mut all = vec![];
    for region in AWS_REGIONS {
        let out: Out = crate::awsread::ec2_read(
            region,
            &[
                ("Action", "DescribeInstances"),
                ("Filter.1.Name", "tag-key"),
                ("Filter.1.Value.1", SOURCE_TAG),
                ("MaxResults", "1000"),
            ],
        )
        .map_err(|e| anyhow!("{region}: {e:#}"))?;
        for r in out.reservations.item {
            for i in r.instances.item {
                let source = i
                    .tags
                    .item
                    .iter()
                    .find(|t| t.key == SOURCE_TAG)
                    .map(|t| t.value.clone())
                    .unwrap_or_default();
                all.push(Instance {
                    id: i.id,
                    region: region.to_string(),
                    state: state_word(&i.state.name),
                    source,
                    type_: i.type_,
                    public_ip: i.public_ip,
                    launched: GoTime::parse(&i.launched).unwrap_or_default(),
                });
            }
        }
    }
    if let Ok(mut g) = AWS_SEEN.lock() {
        g.clear();
        for i in &all {
            g.insert(i.id.clone(), i.clone());
        }
    }
    Ok(all)
}

/// one AWS machine as the m-gateways need it
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AwsPeer {
    pub id: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    /// its tunnel address
    pub address: String,
    /// <public IPv4>:51820
    pub endpoint: String,
}

/// where the session's machines run (its own runner, else the default)
pub fn session_runner(s: &Session) -> String {
    if valid_runner(&s.runner) {
        s.runner.clone()
    } else {
        default_runner()
    }
}

impl Router {
    /// the runner of the session sid (the router's record, never read from a machine id: Deyao, 2026-11-20, there
    /// are more than two kinds); "" for a session the router doesn't have
    pub fn runner_of_session(&self, sid: &str) -> String {
        self.st
            .read(|d| d.sessions.get(sid).map(session_runner))
            .unwrap_or_default()
    }

    /// the runner of the session the machine belongs to ("" for a machine of no session)
    pub fn runner_of_machine(&self, machine: &str) -> String {
        self.st
            .read(|d| {
                d.machines
                    .get(machine)
                    .and_then(|sid| d.sessions.get(sid))
                    .map(session_runner)
            })
            .unwrap_or_default()
    }

    /// where the session's machines run (its own runner, else the default)
    pub fn runner_of(&self, s: &Session) -> String {
        session_runner(s)
    }

    /// the region the spawner gets for the session's next machine, in its runner's terms
    pub fn spawn_region(&self, s: &Session) -> String {
        let reg = self.region_of(s);
        match self.runner_of(s).as_str() {
            "fabric" => crate::fabricrunner::FABRIC_REGION.into(),
            "aws" => aws_region_of(&reg).unwrap_or("eu-west-2").into(),
            _ => reg,
        }
    }

    /// the WireGuard of the session's next AWS machine: the one a spawn already made for this source (a lost answer:
    /// the same machine), else a new one, kept on the session before the spawn is asked for
    pub fn aws_spawn_wg(&self, sid: &str) -> Result<SpawnWireGuard> {
        let peers = aws_gateways()?;
        let wg = self.st.do_(|d| -> Result<AwsWg> {
            let used = used_wg_addresses(d);
            let s = d
                .sessions
                .get_mut(sid)
                .ok_or_else(|| anyhow!("no session {sid}"))?;
            if s.wg.as_ref().is_none_or(|w| w.private_key.is_empty()) {
                s.wg = Some(new_aws_wg(&used)?);
            }
            Ok(s.wg.clone().unwrap_or_default())
        })?;
        Ok(SpawnWireGuard {
            private_key: wg.private_key,
            address: wg.address,
            peers,
        })
    }

    /// the listing every 10 s, so a new instance's address reaches the gateways soon after it boots
    pub fn aws_list_loop(self: &Arc<Self>) {
        loop {
            if let Err(e) = list_aws_machines() {
                crate::logf!("[aws] list: {e:#}");
            }
            std::thread::sleep(Duration::from_secs(10));
        }
    }

    /// the machines with a WireGuard whose instance EC2 lists up with a public address
    pub fn aws_peers(&self) -> Vec<AwsPeer> {
        let seen = AWS_SEEN.lock().map(|g| g.clone()).unwrap_or_default();
        self.st.do_(|d| {
            d.started
                .iter()
                .filter_map(|(id, st)| {
                    let wg = st.wg.as_ref()?;
                    let i = seen.get(id)?;
                    if i.public_ip.is_empty() || i.state == "destroyed" || i.state == "destroying" {
                        return None;
                    }
                    Some(AwsPeer {
                        id: id.clone(),
                        public_key: wg.public_key.clone(),
                        address: wg.address.clone(),
                        endpoint: format!("{}:51820", i.public_ip),
                    })
                })
                .collect()
        })
    }
}

/// GET /gw/aws-peers on the machines' port, for the m-gateways (the gateway keeps the machines' own requests from it)
pub fn register_aws_peers(reg: &mut Registrar) {
    let r = reg.r.clone();
    reg.machine.handle_fn("GET /gw/aws-peers", move |w, _| {
        write_json(w, 200, &json!({"peers": r.aws_peers()}));
    });
}

/// the newest listing, by instance id
pub fn aws_seen() -> BTreeMap<String, Instance> {
    AWS_SEEN.lock().map(|g| g.clone()).unwrap_or_default()
}
