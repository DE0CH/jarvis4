//! AWS spend in the budget (docs/PLAN-aws.md "Budget"; Deyao, 2026-11-04: "aws spend tracking just like fly's spend
//! tracking. they contribute to the same pool"). AWS has spend alerts but no hard stop, so the router estimates it the
//! way it estimates Fly (budget.rs): every tick it lists everything that accrues in jarvis4's AWS account in the
//! session regions (running instances by type and region, EBS volumes, snapshots, public IPv4 addresses) with the
//! router's read-only key, prices it at AWS's published on-demand rates and adds rate × elapsed to the month's total.
//!
//! Cross-check: every AWS_BILLED_EVERY the router asks Cost Explorer for the month's billed usage of its own account
//! (LINKED_ACCOUNT filter: no other account of the organisation; RECORD_TYPE Usage). Cost Explorer lags about a day and
//! catches what the estimate doesn't see, so the pool counts AWS as the larger of the two. Each Cost Explorer request
//! costs USD 0.01: 4 a day, USD 1.20 a month.

use crate::budget::{BudgetState, HOURS_PER_MONTH};
use crate::router::Router;
use anyhow::{Result, anyhow};
use hmac::{Hmac, Mac};
use jarvis_go::GoTime;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

/// the session regions (kernel/spawner/aws.go AWSRegions; infra/aws builds nothing elsewhere)
pub const AWS_BUDGET_REGIONS: &[&str] = &["eu-west-2", "ap-southeast-1", "ap-northeast-1"];

/// USD an hour, on-demand Linux, shared tenancy, for every instance type kernel/spawner/aws.go uses, per region (AWS's
/// Price List API, read 2026-11-04). A type not listed is priced at the dearest listed (the cap errs high).
const AWS_INSTANCE_RATES: &[(&str, &[(&str, f64)])] = &[
    ("eu-west-2", &[("t3.medium", 0.0472), ("t3.large", 0.0944), ("m7i.xlarge", 0.2331), ("m7i.2xlarge", 0.4662), ("r7i.2xlarge", 0.6216), ("r7i.4xlarge", 1.2432), ("r7i.8xlarge", 2.4864)]),
    ("ap-southeast-1", &[("t3.medium", 0.0528), ("t3.large", 0.1056), ("m7i.xlarge", 0.2520), ("m7i.2xlarge", 0.5040), ("r7i.2xlarge", 0.6384), ("r7i.4xlarge", 1.2768), ("r7i.8xlarge", 2.5536)]),
    ("ap-northeast-1", &[("t3.medium", 0.0544), ("t3.large", 0.1088), ("m7i.xlarge", 0.2604), ("m7i.2xlarge", 0.5208), ("r7i.2xlarge", 0.6384), ("r7i.4xlarge", 1.2768), ("r7i.8xlarge", 2.5536)]),
];

/// USD per GB-month: gp3 provisioned storage and snapshot data stored (read 2026-11-04)
const AWS_STORAGE_RATES: &[(&str, f64, f64)] = &[
    ("eu-west-2", 0.0928, 0.053),
    ("ap-southeast-1", 0.096, 0.05),
    ("ap-northeast-1", 0.096, 0.05),
];

/// a public IPv4 address, in use or idle, every region (read 2026-11-04)
pub const AWS_IPV4_PER_HOUR: f64 = 0.005;

/// Cost Explorer: USD 0.01 a request
pub const AWS_BILLED_EVERY: time::Duration = time::Duration::hours(6);
/// snapshots and Elastic IPs change rarely
pub const AWS_SNAPSHOT_EVERY: time::Duration = time::Duration::minutes(30);

pub fn aws_instance_rate(region: &str, typ: &str) -> (f64, bool) {
    for (r, m) in AWS_INSTANCE_RATES {
        if *r == region
            && let Some((_, p)) = m.iter().find(|(t, _)| *t == typ)
        {
            return (*p, true);
        }
    }
    let top = AWS_INSTANCE_RATES
        .iter()
        .flat_map(|(_, m)| m.iter().map(|(_, p)| *p))
        .fold(0.0, f64::max);
    (top, false)
}

pub fn aws_storage_rate(region: &str) -> (f64, f64) {
    if let Some((_, g, s)) = AWS_STORAGE_RATES.iter().find(|(r, _, _)| *r == region) {
        return (*g, *s);
    }
    AWS_STORAGE_RATES
        .iter()
        .fold((0.0, 0.0), |(g, s), (_, a, b)| (f64::max(g, *a), f64::max(s, *b)))
}

// ---- what AWS lists ------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct AwsInstance {
    pub id: String,
    pub region: String,
    pub type_: String,
    pub state: String,
    pub public_ip: String,
    pub name: String,
    pub source: String,
    /// the tag jarvis4_owner (awsowner.rs)
    pub owner: String,
}

#[derive(Debug, Clone, Default)]
pub struct AwsVolume {
    pub id: String,
    pub region: String,
    pub state: String,
    pub size_gb: i64,
}

#[derive(Debug, Clone, Default)]
pub struct AwsSnapshot {
    pub id: String,
    pub region: String,
    pub state: String,
    pub volume_gb: i64,
    /// fullSnapshotSizeInBytes (0 when EC2 doesn't say: volume_gb is counted)
    pub bytes: i64,
}

#[derive(Debug, Clone, Default)]
pub struct AwsAddress {
    pub region: String,
    pub public_ip: String,
}

#[derive(Debug, Clone, Default)]
pub struct AwsInventory {
    pub instances: Vec<AwsInstance>,
    pub volumes: Vec<AwsVolume>,
    pub snapshots: Vec<AwsSnapshot>,
    pub addresses: Vec<AwsAddress>,
}

/// AWS read only (the real one: AwsCostApi; tests: a fake)
pub trait AwsCoster: Send + Sync {
    /// everything in the session regions; a part that failed is its last good listing, with the first error
    fn inventory(&self, now: GoTime) -> (AwsInventory, Option<anyhow::Error>);
    /// Cost Explorer's usage cost so far in month ("YYYY-MM"), and the account it is for
    fn billed(&self, month: &str) -> (Result<f64>, String);
}

/// the hourly rate of an inventory
#[derive(Debug, Clone, Default)]
pub struct AwsBurn {
    pub rate_per_hour: f64,
    pub running: i64,
    pub volumes: i64,
    pub volume_gb: i64,
    pub snapshots: i64,
    pub snapshot_gb: f64,
    pub ipv4: i64,
    pub unknown_types: Vec<String>,
}

pub fn aws_burn_rate(inv: &AwsInventory) -> AwsBurn {
    let mut b = AwsBurn::default();
    let mut ips = BTreeSet::new();
    for i in &inv.instances {
        if i.state != "running" {
            continue; // pending is not billed yet; stopped instances bill only their volumes
        }
        let (p, known) = aws_instance_rate(&i.region, &i.type_);
        if !known {
            b.unknown_types.push(format!("{}/{}", i.region, i.type_));
        }
        b.rate_per_hour += p;
        b.running += 1;
        if !i.public_ip.is_empty() {
            ips.insert(i.public_ip.clone());
        }
    }
    for v in &inv.volumes {
        if matches!(v.state.as_str(), "deleting" | "deleted" | "error") {
            continue;
        }
        let (gp3, _) = aws_storage_rate(&v.region);
        b.rate_per_hour += v.size_gb as f64 * gp3 / HOURS_PER_MONTH;
        b.volumes += 1;
        b.volume_gb += v.size_gb;
    }
    for s in &inv.snapshots {
        if s.state == "error" {
            continue;
        }
        let gb = if s.bytes <= 0 { s.volume_gb as f64 } else { s.bytes as f64 / (1u64 << 30) as f64 };
        let (_, snap) = aws_storage_rate(&s.region);
        b.rate_per_hour += gb * snap / HOURS_PER_MONTH;
        b.snapshots += 1;
        b.snapshot_gb += gb;
    }
    for a in &inv.addresses {
        // Elastic IPs: billed attached or not; an attached one is its instance's address
        if !a.public_ip.is_empty() {
            ips.insert(a.public_ip.clone());
        }
    }
    b.ipv4 = ips.len() as i64;
    b.rate_per_hour += b.ipv4 as f64 * AWS_IPV4_PER_HOUR;
    b.unknown_types.sort();
    b
}

/// one Cost Explorer reading
#[derive(Debug, Clone, Default)]
pub struct AwsBilled {
    pub month: String,
    pub usd: f64,
    pub at: GoTime,
}

// ---- SigV4 ---------------------------------------------------------------------------------------------------

fn hmac_sha(key: &[u8], msg: &str) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap_or_else(|e| panic!("{e}"));
    m.update(msg.as_bytes());
    m.finalize().into_bytes().to_vec()
}

/// AWS Signature Version 4: the headers to add to a request (method, url, its Content-Type / X-Amz-Target, body)
#[allow(clippy::too_many_arguments)]
pub fn aws_sign_v4(
    method: &str,
    url_s: &str,
    extra: &[(&str, &str)],
    body: &[u8],
    id: &str,
    secret: &str,
    region: &str,
    service: &str,
    now: GoTime,
) -> Vec<(String, String)> {
    let t = now.utc().0.unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let day = format!("{:04}{:02}{:02}", t.year(), u8::from(t.month()), t.day());
    let amz_date = format!("{day}T{:02}{:02}{:02}Z", t.hour(), t.minute(), t.second());
    let payload = hex::encode(Sha256::digest(body));
    let u = url::Url::parse(url_s).ok();
    let host = u
        .as_ref()
        .map(|u| match u.port() {
            Some(p) => format!("{}:{p}", u.host_str().unwrap_or("")),
            None => u.host_str().unwrap_or("").to_string(),
        })
        .unwrap_or_default();
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in extra {
        let lk = k.to_lowercase();
        if lk == "content-type" || lk == "x-amz-target" {
            headers.insert(lk, v.to_string());
        }
    }
    headers.entry("content-type".into()).or_default();
    headers.insert("host".into(), host);
    headers.insert("x-amz-content-sha256".into(), payload.clone());
    headers.insert("x-amz-date".into(), amz_date.clone());
    let canon_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{k}:{}\n", v.trim()))
        .collect();
    let signed = headers.keys().cloned().collect::<Vec<_>>().join(";");
    let path = u.as_ref().map(|u| u.path().to_string()).filter(|p| !p.is_empty()).unwrap_or_else(|| "/".into());
    let query = u.as_ref().and_then(|u| u.query().map(str::to_string)).unwrap_or_default();
    let canon = [method, &path, &query, &canon_headers, &signed, &payload].join("\n");
    let scope = format!("{day}/{region}/{service}/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canon.as_bytes()))
    );
    let mut k = format!("AWS4{secret}").into_bytes();
    for p in [day.as_str(), region, service, "aws4_request"] {
        k = hmac_sha(&k, p);
    }
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={id}/{scope}, SignedHeaders={signed}, Signature={}",
        hex::encode(hmac_sha(&k, &to_sign))
    );
    let mut out: Vec<(String, String)> = extra.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    out.push(("X-Amz-Date".into(), amz_date));
    out.push(("X-Amz-Content-Sha256".into(), payload));
    out.push(("Authorization".into(), auth));
    out
}

// ---- the real reader: EC2's Query API, STS and Cost Explorer ------------------------------------------------

pub struct AwsCostApi {
    id: String,
    secret: String,
    http: reqwest::blocking::Client,
    pub ec2: fn(&str) -> String,
    pub sts: String,
    pub ce: String,
    st: Mutex<CostState>,
}

#[derive(Default)]
struct CostState {
    account: String,
    /// by region: the last good listing of each part
    last: BTreeMap<String, AwsInventory>,
    /// by region: when snapshots and addresses were last listed
    slow_at: BTreeMap<String, GoTime>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Items<T> {
    item: Vec<T>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Ec2Tag {
    key: String,
    value: String,
}

impl AwsCostApi {
    pub fn new(id: &str, secret: &str) -> AwsCostApi {
        AwsCostApi {
            id: id.into(),
            secret: secret.into(),
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|e| panic!("{e}")),
            ec2: |r| format!("https://ec2.{r}.amazonaws.com/"),
            sts: "https://sts.amazonaws.com/".into(),
            ce: "https://ce.us-east-1.amazonaws.com/".into(),
            st: Mutex::new(CostState::default()),
        }
    }

    fn post(&self, endpoint: &str, region: &str, service: &str, ctype: &str, target: &str, body: &[u8]) -> Result<Vec<u8>> {
        let mut extra = vec![("Content-Type", ctype)];
        if !target.is_empty() {
            extra.push(("X-Amz-Target", target));
        }
        let hs = aws_sign_v4("POST", endpoint, &extra, body, &self.id, &self.secret, region, service, GoTime::now());
        let mut req = self.http.post(endpoint).body(body.to_vec());
        for (k, v) in hs {
            req = req.header(k, v);
        }
        let resp = req.send()?;
        let status = resp.status().as_u16();
        let b = crate::util::read_limited(resp, 32 << 20)?;
        if status / 100 != 2 {
            let mut msg = String::from_utf8_lossy(&b).trim().to_string();
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
                error: E,
            }
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct R {
                #[serde(rename = "Errors")]
                errors: Es,
            }
            if let Ok(e) = quick_xml::de::from_reader::<_, R>(&b[..])
                && !e.errors.error.code.is_empty()
            {
                msg = format!("{} {}", e.errors.error.code, e.errors.error.message);
            }
            return Err(anyhow!("{service}: HTTP {status} {}", jarvis_go::fmt::clip_bytes(&msg, 300)));
        }
        Ok(b)
    }

    /// one EC2 Query action, every page (NextToken), each page's XML to page
    fn ec2_call(&self, region: &str, params: &[(&str, &str)], mut page: impl FnMut(&[u8]) -> Result<String>) -> Result<()> {
        let action = params.iter().find(|(k, _)| *k == "Action").map_or("", |x| x.1).to_string();
        let mut next = String::new();
        loop {
            let mut p: Vec<(&str, &str)> = params.to_vec();
            p.push(("Version", "2016-11-15"));
            if !next.is_empty() {
                p.push(("NextToken", &next));
            }
            p.sort();
            let body = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(p).finish();
            let b = self
                .post(&(self.ec2)(region), region, "ec2", "application/x-www-form-urlencoded; charset=utf-8", "", body.as_bytes())
                .map_err(|e| anyhow!("{region} {action}: {e:#}"))?;
            let n = page(&b).map_err(|e| anyhow!("{region} {action}: {e:#}"))?;
            if n.is_empty() {
                return Ok(());
            }
            next = n;
        }
    }

    fn instances(&self, region: &str) -> Result<Vec<AwsInstance>> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct State {
            name: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct I {
            #[serde(rename = "instanceId")]
            id: String,
            #[serde(rename = "instanceType")]
            type_: String,
            #[serde(rename = "instanceState")]
            state: State,
            #[serde(rename = "ipAddress")]
            ip: String,
            #[serde(rename = "tagSet")]
            tags: Items<Ec2Tag>,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Res {
            #[serde(rename = "instancesSet")]
            instances: Items<I>,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct R {
            #[serde(rename = "nextToken")]
            next: String,
            #[serde(rename = "reservationSet")]
            reservations: Items<Res>,
        }
        let mut out = vec![];
        self.ec2_call(region, &[("Action", "DescribeInstances"), ("MaxResults", "1000")], |b| {
            let r: R = quick_xml::de::from_reader(b)?;
            for res in r.reservations.item {
                for i in res.instances.item {
                    let mut x = AwsInstance {
                        id: i.id,
                        region: region.into(),
                        type_: i.type_,
                        state: i.state.name,
                        public_ip: i.ip,
                        ..Default::default()
                    };
                    for t in i.tags.item {
                        match t.key.as_str() {
                            "Name" => x.name = t.value,
                            "jarvis4_source" => x.source = t.value,
                            "jarvis4_owner" => x.owner = t.value,
                            _ => {}
                        }
                    }
                    out.push(x);
                }
            }
            Ok(r.next)
        })?;
        Ok(out)
    }

    fn volumes(&self, region: &str) -> Result<Vec<AwsVolume>> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct V {
            #[serde(rename = "volumeId")]
            id: String,
            size: i64,
            status: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct R {
            #[serde(rename = "nextToken")]
            next: String,
            #[serde(rename = "volumeSet")]
            volumes: Items<V>,
        }
        let mut out = vec![];
        self.ec2_call(region, &[("Action", "DescribeVolumes"), ("MaxResults", "500")], |b| {
            let r: R = quick_xml::de::from_reader(b)?;
            out.extend(r.volumes.item.into_iter().map(|v| AwsVolume {
                id: v.id,
                region: region.into(),
                state: v.status,
                size_gb: v.size,
            }));
            Ok(r.next)
        })?;
        Ok(out)
    }

    fn snapshots(&self, region: &str) -> Result<Vec<AwsSnapshot>> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct S {
            #[serde(rename = "snapshotId")]
            id: String,
            #[serde(rename = "volumeSize")]
            size: i64,
            #[serde(rename = "fullSnapshotSizeInBytes")]
            full: i64,
            status: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct R {
            #[serde(rename = "nextToken")]
            next: String,
            #[serde(rename = "snapshotSet")]
            snaps: Items<S>,
        }
        let mut out = vec![];
        self.ec2_call(region, &[("Action", "DescribeSnapshots"), ("Owner.1", "self"), ("MaxResults", "1000")], |b| {
            let r: R = quick_xml::de::from_reader(b)?;
            out.extend(r.snaps.item.into_iter().map(|s| AwsSnapshot {
                id: s.id,
                region: region.into(),
                state: s.status,
                volume_gb: s.size,
                bytes: s.full,
            }));
            Ok(r.next)
        })?;
        Ok(out)
    }

    fn addresses(&self, region: &str) -> Result<Vec<AwsAddress>> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct A {
            #[serde(rename = "publicIp")]
            ip: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct R {
            #[serde(rename = "addressesSet")]
            addrs: Items<A>,
        }
        let mut out = vec![];
        self.ec2_call(region, &[("Action", "DescribeAddresses")], |b| {
            let r: R = quick_xml::de::from_reader(b)?;
            out.extend(r.addrs.item.into_iter().map(|a| AwsAddress { region: region.into(), public_ip: a.ip }));
            Ok(String::new())
        })?;
        Ok(out)
    }

    /// the key's own account (STS GetCallerIdentity: needs no permission)
    pub fn account(&self) -> Result<String> {
        let a = self.st.lock().map(|g| g.account.clone()).unwrap_or_default();
        if !a.is_empty() {
            return Ok(a);
        }
        let b = self.post(&self.sts, "us-east-1", "sts", "application/x-www-form-urlencoded; charset=utf-8", "", b"Action=GetCallerIdentity&Version=2011-06-15")?;
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Res {
            #[serde(rename = "Account")]
            account: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct R {
            #[serde(rename = "GetCallerIdentityResult")]
            result: Res,
        }
        let r: R = quick_xml::de::from_reader(&b[..]).unwrap_or_default();
        if r.result.account.is_empty() {
            return Err(anyhow!("sts: no account in the answer"));
        }
        if let Ok(mut g) = self.st.lock() {
            g.account = r.result.account.clone();
        }
        Ok(r.result.account)
    }
}

impl AwsCoster for AwsCostApi {
    fn inventory(&self, now: GoTime) -> (AwsInventory, Option<anyhow::Error>) {
        let mut all = AwsInventory::default();
        let mut first: Option<anyhow::Error> = None;
        let mut keep = |e: anyhow::Error| {
            if first.is_none() {
                first = Some(e);
            }
        };
        for region in AWS_BUDGET_REGIONS {
            let (mut cur, mut slow_at) = self
                .st
                .lock()
                .map(|g| (g.last.get(*region).cloned().unwrap_or_default(), g.slow_at.get(*region).copied().unwrap_or_default()))
                .unwrap_or_default();
            match self.instances(region) {
                Ok(i) => cur.instances = i,
                Err(e) => keep(e),
            }
            match self.volumes(region) {
                Ok(v) => cur.volumes = v,
                Err(e) => keep(e),
            }
            if now.sub(&slow_at) >= AWS_SNAPSHOT_EVERY {
                let mut ok = true;
                match self.snapshots(region) {
                    Ok(s) => cur.snapshots = s,
                    Err(e) => {
                        keep(e);
                        ok = false;
                    }
                }
                match self.addresses(region) {
                    Ok(a) => cur.addresses = a,
                    Err(e) => {
                        keep(e);
                        ok = false;
                    }
                }
                if ok {
                    slow_at = now;
                }
            }
            if let Ok(mut g) = self.st.lock() {
                g.last.insert(region.to_string(), cur.clone());
                g.slow_at.insert(region.to_string(), slow_at);
            }
            all.instances.extend(cur.instances);
            all.volumes.extend(cur.volumes);
            all.snapshots.extend(cur.snapshots);
            all.addresses.extend(cur.addresses);
        }
        (all, first)
    }

    fn billed(&self, month: &str) -> (Result<f64>, String) {
        let acct = match self.account() {
            Ok(a) => a,
            Err(e) => return (Err(e), String::new()),
        };
        let r = (|| -> Result<f64> {
            let (y, m) = month
                .split_once('-')
                .and_then(|(y, m)| Some((y.parse::<i32>().ok()?, m.parse::<u8>().ok()?)))
                .ok_or_else(|| anyhow!("parsing time {month:?}"))?;
            let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
            let q = json!({
                "TimePeriod": {"Start": format!("{y:04}-{m:02}-01"), "End": format!("{ny:04}-{nm:02}-01")},
                "Granularity": "MONTHLY",
                "Metrics": ["UnblendedCost"],
                "Filter": {"And": [
                    {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [acct]}},
                    {"Dimensions": {"Key": "RECORD_TYPE", "Values": ["Usage"]}},
                ]},
            });
            let b = self.post(&self.ce, "us-east-1", "ce", "application/x-amz-json-1.1", "AWSInsightsIndexService.GetCostAndUsage", jarvis_go::marshal(&q).as_bytes())?;
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct Amount {
                #[serde(rename = "Amount")]
                amount: String,
            }
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct P {
                #[serde(rename = "Total")]
                total: BTreeMap<String, Amount>,
            }
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct R {
                #[serde(rename = "ResultsByTime")]
                results: Vec<P>,
            }
            let r: R = jarvis_go::unmarshal(&b)?;
            let mut total = 0.0;
            for p in r.results {
                let a = p.total.get("UnblendedCost").map(|x| x.amount.clone()).unwrap_or_default();
                total += a.parse::<f64>().map_err(|_| anyhow!("ce: amount {a:?}"))?;
            }
            Ok(total)
        })();
        (r, acct)
    }
}

/// the router's read-only key (AWS_READ_ACCESS_KEY_ID), else None: no AWS in the pool
pub fn aws_coster_from_env() -> Option<Box<dyn AwsCoster>> {
    let id = std::env::var("AWS_READ_ACCESS_KEY_ID").unwrap_or_default();
    let secret = std::env::var("AWS_READ_SECRET_ACCESS_KEY").unwrap_or_default();
    if id.is_empty() || secret.is_empty() {
        return None;
    }
    Some(Box::new(AwsCostApi::new(&id, &secret)))
}

// ---- the tick's AWS part -------------------------------------------------------------------------------------

/// what one tick read from AWS
#[derive(Default)]
pub struct AwsBudgetPart {
    pub inv: AwsInventory,
    /// by instance id: who owns the ones that carry jarvis4_owner (awsowner.rs)
    pub owners: BTreeMap<String, crate::awsowner::AwsOwner>,
    pub burn: AwsBurn,
    /// a fresh Cost Explorer reading, else None
    pub billed: Option<AwsBilled>,
    pub acct: String,
    pub err: String,
    pub bill_err: String,
}

static AWS_BILL_ACCOUNT: LazyLock<Mutex<(String, String)>> = LazyLock::new(|| Mutex::new((String::new(), String::new())));

/// the inventory every tick, Cost Explorer when the month's reading is older than AWS_BILLED_EVERY
pub fn read_aws(aws: Option<&dyn AwsCoster>, prev: Option<&BudgetState>, now: GoTime) -> Option<AwsBudgetPart> {
    let aws = aws?;
    let mut p = AwsBudgetPart::default();
    let (inv, err) = aws.inventory(now);
    p.burn = aws_burn_rate(&inv);
    p.owners = crate::awsowner::aws_owners(&inv.instances);
    p.inv = inv;
    if let Some(e) = err {
        p.err = format!("{e:#}");
        crate::logf!("[budget] AWS: {e:#} (counted from the last list)");
    }
    if !p.burn.unknown_types.is_empty() {
        crate::logf!("[budget] AWS: no price for {}: priced as the dearest type", p.burn.unknown_types.join(", "));
    }
    let month = now.utc().rfc3339()[..7].to_string();
    let due = prev.is_none_or(|pv| {
        pv.month != month || pv.aws_billed_at.as_ref().is_none_or(|at| now.sub(at) >= AWS_BILLED_EVERY)
    });
    if due {
        let (usd, acct) = aws.billed(&month);
        if let Ok(mut g) = AWS_BILL_ACCOUNT.lock() {
            if !acct.is_empty() {
                g.0 = acct;
            }
            g.1 = usd.as_ref().err().map(|e| format!("{e:#}")).unwrap_or_default();
        }
        match usd {
            Err(e) => crate::logf!("[budget] AWS Cost Explorer: {e:#}"),
            Ok(u) => p.billed = Some(AwsBilled { month, usd: u, at: now.utc() }),
        }
    }
    if let Ok(g) = AWS_BILL_ACCOUNT.lock() {
        p.acct = g.0.clone();
        p.bill_err = g.1.clone();
    }
    Some(p)
}

impl AwsBudgetPart {
    /// the AWS half of the budget view
    pub fn view(&self, r: &Router, s: &BudgetState) -> Map<String, Value> {
        // other: instances nobody owns (a warning); owned: no session's, but their owner is still at work
        let (mut other, mut owned) = r.st.do_(|d| {
            let (mut other, mut owned): (Vec<Value>, Vec<Value>) = (vec![], vec![]);
            for i in &self.inv.instances {
                if i.state == "terminated" || i.state == "shutting-down" {
                    continue;
                }
                let mine = d
                    .machines
                    .get(&i.id)
                    .and_then(|sid| d.sessions.get(sid))
                    .is_some_and(|ss| ss.machine_id == i.id);
                if mine {
                    continue;
                }
                let o = self.owners.get(&i.id).cloned().unwrap_or_default();
                let row = json!({"id": i.id, "region": i.region, "type": i.type_, "state": i.state, "name": i.name, "owner": o.text});
                if o.live {
                    owned.push(row);
                } else {
                    other.push(row);
                }
            }
            (other, owned)
        });
        let by_id = |a: &Value, b: &Value| a["id"].as_str().cmp(&b["id"].as_str());
        other.sort_by(by_id);
        owned.sort_by(by_id);
        let mut v = json!({"spentUsd": s.aws_part(), "estimateUsd": s.aws_usd, "billedUsd": s.aws_billed_usd,
            "billedAt": s.aws_billed_at, "ratePerHour": self.burn.rate_per_hour,
            "perMonth": self.burn.rate_per_hour * HOURS_PER_MONTH, "running": self.burn.running,
            "volumes": self.burn.volumes, "volumeGb": self.burn.volume_gb, "snapshots": self.burn.snapshots,
            "snapshotGb": (self.burn.snapshot_gb * 10.0).round() / 10.0, "publicIpv4": self.burn.ipv4,
            "account": self.acct, "regions": AWS_BUDGET_REGIONS, "other": other, "owned": owned,
            "error": null, "billedError": null});
        if !self.err.is_empty() {
            v["error"] = json!(self.err);
        }
        if !self.bill_err.is_empty() {
            v["billedError"] = json!(self.bill_err);
        }
        v.as_object().cloned().unwrap_or_default()
    }
}
