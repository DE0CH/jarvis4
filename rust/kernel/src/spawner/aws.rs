//! The EC2 API (kernel/spawner/aws.go), used only by the spawner, the only holder of its AWS key (sealed to it by the
//! setup session: POST /aws-credentials). One session machine = one EC2 instance (docs/PLAN-aws.md): Flatcar Container
//! Linux from the region's launch template `jarvis4-session` (infra/aws), whose Ignition user-data, written here, runs
//! the session image pinned by digest as the instance's one container (privileged, the host's network, /data bound
//! in). The machine's keys reach the spawner through the instance's serial console, read live over the EC2 Serial
//! Console (awsserial.rs) or else from GetConsoleOutput, so their link to the instance is AWS's word, not the
//! machine's or the router's. The instance has one EBS volume (Flatcar's root grows to fill it at first boot): the
//! image's room plus the session's diskGb, /data a directory on it, deleted with the instance.

use super::awsserial::{SerialEndpoints, SerialWatches};
use super::{CreateInput, MachineKeys, Missing, RunMachine, Runner};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

/// what POST /aws-credentials opens: the spawner's EC2 key
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwsCredentials {
    #[serde(default, rename = "AWS_ACCESS_KEY_ID")]
    pub access_key_id: String,
    #[serde(default, rename = "AWS_SECRET_ACCESS_KEY")]
    pub secret_access_key: String,
}

/// how an AWS machine reaches the router (docs/PLAN-aws.md "Reaching the router"): its own key and tunnel address,
/// made by the router per spawn, and the m-gateways as peers
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireGuard {
    /// base64, the machine's
    #[serde(default)]
    pub private_key: String,
    /// the machine's tunnel address, e.g. 10.99.1.7
    #[serde(default)]
    pub address: String,
    /// the m-gateways
    #[serde(default)]
    pub peers: Vec<WgPeer>,
}

/// one m-gateway: its public key and its tunnel address (the instance routes only that /32 to it)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WgPeer {
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub address: String,
}

/// the UDP port an instance's WireGuard listens on (the launch template's security group lets it in)
const WG_PORT: u16 = 51820;

/// ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ (a WireGuard key)
fn wg_key(k: &str) -> bool {
    let b = k.as_bytes();
    b.len() == 44
        && b[..42]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/')
        && b"AEIMQUYcgkosw048".contains(&b[42])
        && b[43] == b'='
}

/// ^10\.(9[0-9])\.[0-9]{1,3}\.[0-9]{1,3}$
fn wg_addr(a: &str) -> bool {
    let p: Vec<&str> = a.split('.').collect();
    let num = |s: &str| !s.is_empty() && s.len() <= 3 && s.bytes().all(|c| c.is_ascii_digit());
    p.len() == 4
        && p[0] == "10"
        && p[1].len() == 2
        && p[1].starts_with('9')
        && p[1].as_bytes()[1].is_ascii_digit()
        && num(p[2])
        && num(p[3])
}

impl WireGuard {
    /// keys that are WireGuard keys, addresses in 10.90.0.0–10.99.255.255, one to four gateways
    pub fn check(&self) -> Result<(), String> {
        if !wg_key(&self.private_key)
            || !wg_addr(&self.address)
            || self.peers.is_empty()
            || self.peers.len() > 4
        {
            return Err("wireguard: a key, an address in 10.90/15… and 1 to 4 peers".into());
        }
        if self
            .peers
            .iter()
            .any(|p| !wg_key(&p.public_key) || !wg_addr(&p.address))
        {
            return Err("wireguard: a peer's key or address".into());
        }
        Ok(())
    }
}

/// the regions the spawner starts instances in (each has the launch template jarvis4-session, infra/aws)
pub const AWS_REGIONS: &[&str] = &["eu-west-2", "ap-southeast-1", "ap-northeast-1"];

pub fn aws_region(r: &str) -> bool {
    AWS_REGIONS.contains(&r)
}

/// every region's template for session instances (infra/aws/main.tf)
const LAUNCH_TEMPLATE: &str = "jarvis4-session";

/// the instance tag naming the source a machine is from (the router lists instances by it)
pub const SOURCE_TAG: &str = "jarvis4_source";

/// the line the machine writes to the serial console with its public keys (rust/machine keeper)
pub const KEYS_MARK: &str = "JARVIS2-KEYS ";

/// the Ignition file naming the image the session unit runs (inspect reads it back from the user-data)
const IMAGE_ENV: &str = "/etc/jarvis4/image.env";

/// the EC2 type for a size: at least the size's memory for the session plus room for Flatcar and docker, and at least
/// as many CPUs as the Fly guest of the same size. A size past the table is refused ("").
pub fn instance_type(memory_mb: i64) -> &'static str {
    match memory_mb / 1024 {
        gb if gb <= 2 => "t3.medium",
        gb if gb <= 4 => "t3.large",
        gb if gb <= 8 => "m7i.xlarge",
        gb if gb <= 16 => "m7i.2xlarge",
        gb if gb <= 32 => "r7i.2xlarge",
        gb if gb <= 64 => "r7i.4xlarge",
        gb if gb <= 128 => "r7i.8xlarge",
        _ => "",
    }
}

/// the instance's volume besides the session's diskGb: Flatcar and the session image unpacked, with room to spare
const ROOT_GB: i64 = 30;

/// EC2's refusal: the HTTP status and its error code (e.g. InsufficientInstanceCapacity)
#[derive(Debug, Clone)]
pub struct AwsError {
    pub http: u16,
    pub code: String,
    pub msg: String,
}

impl std::fmt::Display for AwsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for AwsError {}

pub(crate) fn aws_err(http: u16, code: &str, msg: impl Into<String>) -> anyhow::Error {
    AwsError {
        http,
        code: code.into(),
        msg: msg.into(),
    }
    .into()
}

fn hmac_sha(key: &[u8], msg: &str) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap_or_else(|e| panic!("{e}"));
    m.update(msg.as_bytes());
    m.finalize().into_bytes().to_vec()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// AWS Signature Version 4: the headers a request needs (its URL, Content-Type, X-Amz-Target and body as sent)
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_v4(
    method: &str,
    u: &str,
    ctype: &str,
    target: &str,
    body: &[u8],
    c: &AwsCredentials,
    region: &str,
    service: &str,
    now: time::OffsetDateTime,
) -> Vec<(String, String)> {
    let t = now.to_offset(time::UtcOffset::UTC);
    let day = format!("{:04}{:02}{:02}", t.year(), u8::from(t.month()), t.day());
    let amz = format!("{day}T{:02}{:02}{:02}Z", t.hour(), t.minute(), t.second());
    let payload = hex(&Sha256::digest(body));
    let url = url::Url::parse(u).ok();
    let host = url
        .as_ref()
        .map(|x| match x.port() {
            Some(p) => format!("{}:{p}", x.host_str().unwrap_or("")),
            None => x.host_str().unwrap_or("").to_string(),
        })
        .unwrap_or_default();
    let mut headers = BTreeMap::from([
        ("content-type".to_string(), ctype.to_string()),
        ("host".to_string(), host),
        ("x-amz-content-sha256".to_string(), payload.clone()),
        ("x-amz-date".to_string(), amz.clone()),
    ]);
    if !target.is_empty() {
        headers.insert("x-amz-target".into(), target.into());
    }
    let canon_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{k}:{}\n", v.trim()))
        .collect();
    let signed = headers.keys().cloned().collect::<Vec<_>>().join(";");
    let path = url
        .as_ref()
        .map(|x| x.path().to_string())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "/".into());
    let query = url
        .as_ref()
        .and_then(|x| x.query().map(String::from))
        .unwrap_or_default();
    let canon = [method, &path, &query, &canon_headers, &signed, &payload].join("\n");
    let scope = format!("{day}/{region}/{service}/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz}\n{scope}\n{}",
        hex(&Sha256::digest(canon.as_bytes()))
    );
    let mut k = format!("AWS4{}", c.secret_access_key).into_bytes();
    for p in [day.as_str(), region, service, "aws4_request"] {
        k = hmac_sha(&k, p);
    }
    vec![
        ("X-Amz-Date".into(), amz),
        ("X-Amz-Content-Sha256".into(), payload),
        (
            "Authorization".into(),
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={}",
                c.access_key_id,
                hex(&hmac_sha(&k, &to_sign))
            ),
        ),
    ]
}

/// Go's url.PathEscape: everything but the unreserved and a path segment's allowed sub-delims escaped
fn path_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        let keep = b.is_ascii_alphanumeric() || b"-_.~$&+,:;=@".contains(&b);
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn path_unescape(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

// ---- the instance's Ignition config ----

/// the user-data that makes a Flatcar instance one session machine. Units:
///   - wg0 (systemd-networkd): the machine's WireGuard to the m-gateways, listening on WG_PORT
///   - jarvis4-session: the session image, pinned by digest, privileged on the host's network (the container is the
///     machine, as a Fly machine's image is), /data bound in, the env plus the instance id; its stdout goes to the
///     journal only (the serial console carries the machine's keys line). When it ends the instance powers off, and
///     the launch template terminates an instance that shuts itself down.
///
/// The metadata service is closed once the instance id is read (it serves the user-data, and so the WireGuard key).
pub fn ignition(
    image: &str,
    env: &BTreeMap<String, String>,
    wg: &WireGuard,
) -> anyhow::Result<Vec<u8>> {
    if image.contains(['\n', '"', '\'', ' ']) {
        return Err(anyhow::anyhow!(
            "the image has a character the unit can't carry"
        ));
    }
    wg.check().map_err(|e| anyhow::anyhow!(e))?;
    let mut netdev = format!(
        "[NetDev]\nName=wg0\nKind=wireguard\n[WireGuard]\nPrivateKey={}\nListenPort={WG_PORT}\n",
        wg.private_key
    );
    for p in &wg.peers {
        netdev.push_str(&format!(
            "[WireGuardPeer]\nPublicKey={}\nAllowedIPs={}/32\nPersistentKeepalive=25\n",
            p.public_key, p.address
        ));
    }
    let mut network = format!("[Match]\nName=wg0\n[Network]\nAddress={}/32\n", wg.address);
    for p in &wg.peers {
        network.push_str(&format!("[Route]\nDestination={}/32\n", p.address));
    }
    let mut env_file = String::from("JARVIS2_RUNNER=aws\n");
    for (k, v) in env {
        if v.contains('\n') || k.contains(['=', '\n']) {
            return Err(anyhow::anyhow!("env {k} doesn't fit one line"));
        }
        env_file.push_str(&format!("{k}={v}\n"));
    }
    let file = |path: &str, mode: i64, contents: &str| {
        json!({"path": path, "mode": mode, "overwrite": true,
            "contents": {"source": format!("data:,{}", path_escape(contents))}})
    };
    let session = format!(
        r#"[Unit]
Description=The session machine
After=docker.service network-online.target systemd-networkd.service
Requires=docker.service
Wants=network-online.target
[Service]
Type=simple
Restart=no
TimeoutStartSec=0
EnvironmentFile={IMAGE_ENV}
ExecStartPre=/bin/sh -c 'T=$(curl -sf -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" http://169.254.169.254/latest/api/token) && echo JARVIS2_MACHINE_ID=$(curl -sf -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/instance-id) > /etc/jarvis4/id.env'
ExecStartPre=/usr/sbin/iptables -I OUTPUT -d 169.254.169.254 -j DROP
ExecStartPre=/usr/bin/docker pull ${{IMAGE}}
ExecStart=/usr/bin/docker run --name session --network host --privileged --cgroupns host --env-file /etc/jarvis4/session.env --env-file /etc/jarvis4/id.env -v /data:/data -v /var/log/journal:/run/jarvis-host/journal:ro ${{IMAGE}}
ExecStopPost=/bin/sh -c 'echo "JARVIS4-SESSION-END result=$SERVICE_RESULT code=$EXIT_CODE status=$EXIT_STATUS" > /dev/ttyS0; [ "$SERVICE_RESULT" = success ] || sleep 50'
ExecStopPost=/usr/bin/systemctl poweroff
[Install]
WantedBy=multi-user.target
"#
    );
    let cfg = json!({
        "ignition": {"version": "3.4.0"},
        "storage": {
            "directories": [{"path": "/data", "mode": 0o755}],
            "files": [
                file(IMAGE_ENV, 0o644, &format!("IMAGE={image}\n")),
                file("/etc/jarvis4/session.env", 0o600, &env_file),
                file("/etc/flatcar/update.conf", 0o644, "REBOOT_STRATEGY=off\n"),
                file("/etc/systemd/network/50-wg0.netdev", 0o644, &netdev), // networkd (not root) reads it
                file("/etc/systemd/network/50-wg0.network", 0o644, &network),
            ],
        },
        "systemd": {"units": [
            {"name": "update-engine.service", "mask": true},
            {"name": "locksmithd.service", "mask": true},
            {"name": "jarvis4-session.service", "enabled": true, "contents": session},
        ]},
    });
    Ok(jarvis_sig::go_json(&cfg)?.into_bytes())
}

/// the image the instance's user-data runs (its image.env), "" if it names none
pub fn user_data_image(user_data: &str) -> String {
    use base64::Engine as _;
    let Ok(b) = base64::engine::general_purpose::STANDARD.decode(user_data) else {
        return String::new();
    };
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Contents {
        source: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct File {
        path: String,
        contents: Contents,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Storage {
        files: Vec<File>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Cfg {
        storage: Storage,
    }
    let Ok(cfg) = serde_json::from_slice::<Cfg>(&b) else {
        return String::new();
    };
    for f in cfg.storage.files {
        if f.path != IMAGE_ENV {
            continue;
        }
        let Some(s) = f
            .contents
            .source
            .strip_prefix("data:,")
            .and_then(path_unescape)
        else {
            return String::new();
        };
        for line in s.lines() {
            if let Some(img) = line.strip_prefix("IMAGE=")
                && !img.is_empty()
                && !img.contains(char::is_whitespace)
            {
                return img.to_string();
            }
        }
    }
    String::new()
}

/// EC2's instance state as the spawner's word
pub fn state_word(ec2: &str) -> String {
    match ec2 {
        "pending" => "created",
        "running" => "started",
        "terminated" => "destroyed",
        "shutting-down" => "destroying",
        other => other, // stopping, stopped
    }
    .into()
}

pub struct AwsApi {
    creds: Mutex<AwsCredentials>,
    http: reqwest::blocking::Client,
    /// the region's EC2 endpoint (tests point it at a fake)
    pub endpoint: Box<dyn Fn(&str) -> String + Send + Sync>,
    pub(crate) serial_ep: SerialEndpoints,
    pub(crate) serial: SerialWatches,
}

// EC2's XML, the parts read
#[derive(Deserialize, Default, Debug, Clone)]
#[serde(default)]
struct Items<T> {
    item: Vec<T>,
}

#[derive(Deserialize, Default, Debug, Clone)]
#[serde(default)]
struct Tag {
    key: String,
    value: String,
}

#[derive(Deserialize, Default, Debug, Clone)]
#[serde(default)]
struct InstanceState {
    name: String,
}

#[derive(Deserialize, Default, Debug, Clone)]
#[serde(default)]
pub(crate) struct Ec2Instance {
    #[serde(rename = "instanceId")]
    id: String,
    #[serde(rename = "instanceState")]
    state: InstanceState,
    #[serde(rename = "tagSet")]
    tags: Items<Tag>,
}

impl AwsApi {
    pub fn new() -> AwsApi {
        AwsApi {
            creds: Mutex::new(AwsCredentials::default()),
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap_or_default(),
            endpoint: Box::new(|r| format!("https://ec2.{r}.amazonaws.com/")),
            serial_ep: SerialEndpoints::default(),
            serial: SerialWatches::default(),
        }
    }

    pub fn configure(&self, c: AwsCredentials) {
        *self.creds.lock().unwrap_or_else(|e| e.into_inner()) = c;
    }

    pub(crate) fn configured(&self) -> anyhow::Result<AwsCredentials> {
        let c = self.creds.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if c.access_key_id.is_empty() || c.secret_access_key.is_empty() {
            return Err(Missing::AwsKey.into());
        }
        Ok(c)
    }

    pub(crate) fn http(&self) -> &reqwest::blocking::Client {
        &self.http
    }

    /// one EC2 Query API action in region, signed with SigV4 → its XML answer
    fn call(&self, region: &str, params: &[(&str, &str)]) -> anyhow::Result<Vec<u8>> {
        let c = self.configured()?;
        let mut p: Vec<(&str, &str)> = params.to_vec();
        p.push(("Version", "2016-11-15"));
        p.sort();
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&p)
            .finish();
        let endpoint = (self.endpoint)(region);
        let ctype = "application/x-www-form-urlencoded; charset=utf-8";
        let hs = sign_v4(
            "POST",
            &endpoint,
            ctype,
            "",
            body.as_bytes(),
            &c,
            region,
            "ec2",
            time::OffsetDateTime::now_utc(),
        );
        let mut req = self
            .http
            .post(&endpoint)
            .header("Content-Type", ctype)
            .body(body);
        for (k, v) in hs {
            req = req.header(k, v);
        }
        let resp = req.send()?;
        let status = resp.status().as_u16();
        let b = resp.bytes()?.to_vec();
        if status / 100 != 2 {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct E {
                #[serde(rename = "Code")]
                code: String,
                #[serde(rename = "Message")]
                message: String,
            }
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct Es {
                #[serde(rename = "Error")]
                error: Vec<E>,
            }
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct R {
                #[serde(rename = "Errors")]
                errors: Es,
            }
            let r: R = quick_xml::de::from_reader(&b[..]).unwrap_or_default();
            let (code, msg) = match r.errors.error.first() {
                Some(e) => (e.code.clone(), e.message.clone()),
                None => (
                    String::new(),
                    String::from_utf8_lossy(&b).trim().to_string(),
                ),
            };
            let action = params
                .iter()
                .find(|(k, _)| *k == "Action")
                .map_or("", |x| x.1);
            return Err(aws_err(
                status,
                &code,
                format!(
                    "{action}: HTTP {status} {code} {}",
                    jarvis_go::fmt::clip_bytes(&msg, 300)
                ),
            ));
        }
        Ok(b)
    }

    /// the instance in region (None when EC2 doesn't know it there)
    fn describe(&self, region: &str, id: &str) -> anyhow::Result<Option<Ec2Instance>> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Res {
            #[serde(rename = "instancesSet")]
            instances: Items<Ec2Instance>,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct R {
            #[serde(rename = "reservationSet")]
            reservations: Items<Res>,
        }
        let b = match self.call(
            region,
            &[("Action", "DescribeInstances"), ("InstanceId.1", id)],
        ) {
            Ok(b) => b,
            Err(e)
                if e.downcast_ref::<AwsError>().is_some_and(|a| {
                    a.code == "InvalidInstanceID.NotFound"
                        || a.code == "InvalidInstanceID.Malformed"
                }) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let r: R = quick_xml::de::from_reader(&b[..])?;
        Ok(r.reservations
            .item
            .into_iter()
            .flat_map(|x| x.instances.item)
            .find(|i| i.id == id))
    }

    /// the region an instance is in and the instance, looked up in every session region (an id is unique across them)
    pub(crate) fn find(&self, id: &str) -> anyhow::Result<Option<(String, Ec2Instance)>> {
        for region in AWS_REGIONS {
            if let Some(i) = self.describe(region, id)? {
                return Ok(Some((region.to_string(), i)));
            }
        }
        Ok(None)
    }
}

impl Default for AwsApi {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner for AwsApi {
    /// one RunInstances from the region's launch template: the size's instance type, its one volume (ROOT_GB +
    /// diskGb), the source tag, the Ignition user-data → the instance id (volume "": nothing of its own to delete)
    fn create(&self, i: &CreateInput) -> anyhow::Result<(String, String)> {
        self.configured()?;
        if !aws_region(&i.region) {
            return Err(aws_err(
                400,
                "UnknownRegion",
                format!("no session launch template in region {}", i.region),
            ));
        }
        let typ = instance_type(i.memory_mb);
        if typ.is_empty() {
            return Err(aws_err(
                400,
                "UnknownSize",
                format!("no instance type for {} MB", i.memory_mb),
            ));
        }
        let short = i.source.strip_prefix("source-").unwrap_or(&i.source);
        let hostname = format!("jarvis4-{}", &short[..short.len().min(12)]);
        let Some(wg) = &i.wireguard else {
            return Err(aws_err(
                400,
                "NoWireGuard",
                "an AWS machine needs its wireguard",
            ));
        };
        let ud = ignition(&i.image, &i.env, wg)?;
        if ud.len() > 16000 {
            // EC2's user-data limit is 16 KB before base64
            return Err(anyhow::anyhow!(
                "the user-data is {} bytes, over EC2's 16 KB",
                ud.len()
            ));
        }
        use base64::Engine as _;
        let ud64 = base64::engine::general_purpose::STANDARD.encode(&ud);
        let vol = (ROOT_GB + i.disk_gb).to_string();
        let p = [
            ("Action", "RunInstances"),
            ("MinCount", "1"),
            ("MaxCount", "1"),
            ("LaunchTemplate.LaunchTemplateName", LAUNCH_TEMPLATE),
            ("LaunchTemplate.Version", "$Default"),
            ("InstanceType", typ),
            ("UserData", ud64.as_str()),
            ("BlockDeviceMapping.1.DeviceName", "/dev/xvda"),
            ("BlockDeviceMapping.1.Ebs.VolumeSize", vol.as_str()),
            ("BlockDeviceMapping.1.Ebs.VolumeType", "gp3"),
            ("BlockDeviceMapping.1.Ebs.Encrypted", "true"),
            ("BlockDeviceMapping.1.Ebs.DeleteOnTermination", "true"),
            ("TagSpecification.1.ResourceType", "instance"),
            ("TagSpecification.1.Tag.1.Key", SOURCE_TAG),
            ("TagSpecification.1.Tag.1.Value", i.source.as_str()),
            ("TagSpecification.1.Tag.2.Key", "Name"),
            ("TagSpecification.1.Tag.2.Value", hostname.as_str()),
            ("TagSpecification.2.ResourceType", "volume"),
            ("TagSpecification.2.Tag.1.Key", SOURCE_TAG),
            ("TagSpecification.2.Tag.1.Value", i.source.as_str()),
        ];
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Inst {
            #[serde(rename = "instanceId")]
            id: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct R {
            #[serde(rename = "instancesSet")]
            instances: Items<Inst>,
        }
        let b = self.call(&i.region, &p)?;
        let r: R = quick_xml::de::from_reader(&b[..])?;
        if r.instances.item.len() != 1 || r.instances.item[0].id.is_empty() {
            return Err(anyhow::anyhow!("RunInstances made no instance"));
        }
        let id = r.instances.item[0].id.clone();
        self.watch_serial(&i.region, &id); // its keys line, live, as soon as it is written (awsserial.rs)
        Ok((id, String::new()))
    }

    /// the instance's state as the spawner's words, the image its user-data runs, and its source tag. An instance EC2
    /// no longer knows was terminated long ago: destroyed.
    fn inspect(&self, id: &str) -> anyhow::Result<RunMachine> {
        let Some((region, inst)) = self.find(id)? else {
            return Ok(RunMachine {
                state: "destroyed".into(),
                ..Default::default()
            });
        };
        let mut m = RunMachine {
            state: state_word(&inst.state.name),
            source: inst
                .tags
                .item
                .iter()
                .find(|t| t.key == SOURCE_TAG)
                .map(|t| t.value.clone())
                .unwrap_or_default(),
            ..Default::default()
        };
        if m.state == "started" {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct V {
                value: String,
            }
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct R {
                #[serde(rename = "userData")]
                user_data: V,
            }
            let b = self.call(
                &region,
                &[
                    ("Action", "DescribeInstanceAttribute"),
                    ("InstanceId", id),
                    ("Attribute", "userData"),
                ],
            )?;
            let r: R = quick_xml::de::from_reader(&b[..])?;
            m.image = user_data_image(&r.user_data.value);
        }
        Ok(m)
    }

    /// the machine's keys line from the instance's serial console: as the live reader read it (awsserial.rs), else the
    /// newest output EC2 keeps (GetConsoleOutput Latest, refreshed every 30-40 s). The machine writes it until its cert
    /// arrives; until then this is a not-started (the router asks again).
    fn init(&self, id: &str) -> anyhow::Result<MachineKeys> {
        if let (Some(k), _) = self.serial_keys(id) {
            return Ok(k);
        }
        let Some((region, _)) = self.find(id)? else {
            return Err(anyhow::anyhow!("instance {id} is gone"));
        };
        self.watch_serial(&region, id); // none yet: this spawner didn't create it (a restart, a copy flip)
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct R {
            output: String,
        }
        let b = self.call(
            &region,
            &[
                ("Action", "GetConsoleOutput"),
                ("InstanceId", id),
                ("Latest", "true"),
            ],
        )?;
        let r: R = quick_xml::de::from_reader(&b[..])?;
        use base64::Engine as _;
        let out = base64::engine::general_purpose::STANDARD
            .decode(r.output.trim())
            .unwrap_or_default();
        let text = String::from_utf8_lossy(&out);
        let Some(found) = text.lines().rfind(|l| l.contains(KEYS_MARK)) else {
            return Err(Missing::NotYet.into());
        };
        keys_from_line(found).map(|(k, _)| k)
    }

    /// TerminateInstances (its volume goes with it)
    fn destroy(&self, id: &str) -> anyhow::Result<()> {
        self.stop_serial(id);
        let Some((region, _)) = self.find(id)? else {
            return Ok(());
        };
        self.call(
            &region,
            &[("Action", "TerminateInstances"), ("InstanceId.1", id)],
        )
        .map(|_| ())
    }

    /// nothing: the instance's volume is deleted with it
    fn delete_volume(&self, _: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

/// the keys a console line carries (the machine's keeper writes "JARVIS2-KEYS {json}"); false: the line has none
pub fn keys_from_line(line: &str) -> anyhow::Result<(MachineKeys, bool)> {
    let Some(i) = line.find(KEYS_MARK) else {
        return Ok((MachineKeys::default(), false));
    };
    match serde_json::from_str::<MachineKeys>(line[i + KEYS_MARK.len()..].trim()) {
        Ok(k) if !k.encryption_key.is_empty() && !k.signing_key.is_empty() => Ok((k, true)),
        _ => Err(anyhow::anyhow!("the console's keys line has no keys")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_user_data_names_its_image() {
        let wg = WireGuard {
            private_key: format!("{}A=", "a".repeat(42)),
            address: "10.99.1.7".into(),
            peers: vec![WgPeer {
                public_key: format!("{}E=", "b".repeat(42)),
                address: "10.99.0.1".into(),
            }],
        };
        let img = format!("ghcr.io/de0ch/jarvis4-session@sha256:{}", "1".repeat(64));
        let env = BTreeMap::from([(
            "JARVIS2_URL".to_string(),
            "http://10.99.0.1:8081".to_string(),
        )]);
        let ud = ignition(&img, &env, &wg).unwrap_or_else(|e| panic!("{e:#}"));
        use base64::Engine as _;
        assert_eq!(
            user_data_image(&base64::engine::general_purpose::STANDARD.encode(&ud)),
            img
        );
        let s = String::from_utf8_lossy(&ud);
        assert!(
            s.contains(r#""source":"data:,JARVIS2_RUNNER=aws%0AJARVIS2_URL=http:%2F%2F10.99.1"#)
                || s.contains("JARVIS2_RUNNER=aws%0A"),
            "{s}"
        );
        assert!(ignition("a b", &env, &wg).is_err());
    }

    #[test]
    fn wireguard_checks() {
        let ok = WireGuard {
            private_key: format!("{}A=", "a".repeat(42)),
            address: "10.95.3.4".into(),
            peers: vec![WgPeer {
                public_key: format!("{}w=", "Z".repeat(42)),
                address: "10.90.0.1".into(),
            }],
        };
        assert!(ok.check().is_ok());
        let mut bad = ok.clone();
        bad.address = "10.80.0.1".into();
        assert!(bad.check().is_err());
        let mut bad = ok;
        bad.private_key = format!("{}B=", "a".repeat(42));
        assert!(bad.check().is_err());
    }
}
