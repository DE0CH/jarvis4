//! The router's own EC2 reads with its read-only key (AWS_READ_*: IAM user jarvis4-router-read, infra/aws/iam.tf;
//! signed by awsbudget.rs's aws_sign_v4): one instance as EC2 describes it now, with its state's reasons (the
//! lifecycle log's AWS events, lifecycle.rs), and the newest serial console output of a session instance (awslogs.rs).

use anyhow::{Result, anyhow};
use base64::Engine;
use jarvis_go::GoTime;
use serde::Deserialize;
use std::sync::Mutex;
use std::time::Duration;

type EndpointFn = fn(&str) -> String;

/// tests point a region's EC2 endpoint at a fake
pub static AWS_READ_ENDPOINT: Mutex<Option<EndpointFn>> = Mutex::new(None);

pub fn aws_read_endpoint(region: &str) -> String {
    match AWS_READ_ENDPOINT.lock().ok().and_then(|g| *g) {
        Some(f) => f(region),
        None => format!("https://ec2.{region}.amazonaws.com/"),
    }
}

/// the router has its read-only AWS key
pub fn aws_read_on() -> bool {
    !std::env::var("AWS_READ_ACCESS_KEY_ID")
        .unwrap_or_default()
        .is_empty()
        && !std::env::var("AWS_READ_SECRET_ACCESS_KEY")
            .unwrap_or_default()
            .is_empty()
}

/// EC2's refusal (its error code, e.g. UnauthorizedOperation, InvalidInstanceID.NotFound)
#[derive(Debug, Clone)]
pub struct Ec2ReadError {
    pub status: u16,
    pub code: String,
    pub msg: String,
}

impl std::fmt::Display for Ec2ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EC2: HTTP {} {} {}", self.status, self.code, self.msg)
    }
}

impl std::error::Error for Ec2ReadError {}

/// one EC2 Query API action in region with the read-only key, SigV4-signed → its XML answer
pub fn ec2_read<T: serde::de::DeserializeOwned>(
    region: &str,
    params: &[(&str, &str)],
) -> Result<T> {
    let id = std::env::var("AWS_READ_ACCESS_KEY_ID").unwrap_or_default();
    let secret = std::env::var("AWS_READ_SECRET_ACCESS_KEY").unwrap_or_default();
    if id.is_empty() || secret.is_empty() {
        return Err(anyhow!(
            "the router has no AWS read key (AWS_READ_ACCESS_KEY_ID)"
        ));
    }
    let mut p: Vec<(&str, &str)> = params.to_vec();
    p.push(("Version", "2016-11-15"));
    p.sort();
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(p)
        .finish();
    let url = aws_read_endpoint(region);
    let headers = crate::awsbudget::aws_sign_v4(
        "POST",
        &url,
        &[(
            "Content-Type",
            "application/x-www-form-urlencoded; charset=utf-8",
        )],
        body.as_bytes(),
        &id,
        &secret,
        region,
        "ec2",
        GoTime::now(),
    );
    let mut req = reqwest::blocking::Client::new()
        .post(&url)
        .timeout(Duration::from_secs(30))
        .body(body);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let resp = req.send()?;
    let status = resp.status().as_u16();
    let b = crate::util::read_limited(resp, 8 << 20)?;
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
        struct Resp {
            #[serde(rename = "Errors")]
            errors: Es,
        }
        let e: Resp = quick_xml::de::from_reader(&b[..]).unwrap_or_default();
        let first = e.errors.error.into_iter().next().unwrap_or_default();
        return Err(Ec2ReadError {
            status,
            code: first.code,
            msg: first.message,
        }
        .into());
    }
    Ok(quick_xml::de::from_reader(&b[..])?)
}

/// one instance as DescribeInstances gives it, with the reasons for its state
#[derive(Debug, Clone, Default)]
pub struct AwsInstanceView {
    pub id: String,
    pub region: String,
    /// EC2's own state words: pending, running, stopping, stopped, shutting-down, terminated
    pub state: String,
    pub type_: String,
    pub zone: String,
    pub public_ip: String,
    pub launched: GoTime,
    /// stateTransitionReason, e.g. "User initiated (2026-11-04 13:18:40 GMT)"
    pub transition: String,
    /// stateReason: e.g. Client.InstanceInitiatedShutdown, Server.InsufficientInstanceCapacity
    pub reason_code: String,
    pub reason_msg: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Named {
    name: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Placement {
    #[serde(rename = "availabilityZone")]
    zone: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Reason {
    code: String,
    message: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Inst {
    #[serde(rename = "instanceId")]
    id: String,
    #[serde(rename = "instanceState")]
    state: Named,
    #[serde(rename = "instanceType")]
    type_: String,
    #[serde(rename = "ipAddress")]
    public_ip: String,
    #[serde(rename = "launchTime")]
    launched: String,
    placement: Placement,
    reason: String,
    #[serde(rename = "stateReason")]
    state_reason: Reason,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Items<T> {
    item: Vec<T>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Reservation {
    #[serde(rename = "instancesSet")]
    instances: Items<Inst>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DescribeOut {
    #[serde(rename = "reservationSet")]
    reservations: Items<Reservation>,
}

/// the instance as EC2 describes it now (None when no session region knows it: terminated long ago)
pub fn aws_describe(id: &str) -> Result<Option<AwsInstanceView>> {
    let mut regions: Vec<String> = vec![];
    let r0 = crate::awsrunner::aws_region_of_instance(id);
    if !r0.is_empty() {
        regions.push(r0.clone());
    }
    for r in crate::awsrunner::AWS_REGIONS {
        if regions.is_empty() || *r != regions[0] {
            regions.push(r.to_string());
        }
    }
    for region in regions {
        let out: DescribeOut = match ec2_read(
            &region,
            &[("Action", "DescribeInstances"), ("InstanceId.1", id)],
        ) {
            Ok(o) => o,
            Err(e)
                if e.downcast_ref::<Ec2ReadError>().is_some_and(|x| {
                    x.code == "InvalidInstanceID.NotFound"
                        || x.code == "InvalidInstanceID.Malformed"
                }) =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };
        for rs in out.reservations.item {
            for i in rs.instances.item {
                if i.id == id {
                    return Ok(Some(AwsInstanceView {
                        id: id.into(),
                        region: region.clone(),
                        state: i.state.name,
                        type_: i.type_,
                        zone: i.placement.zone,
                        public_ip: i.public_ip,
                        launched: GoTime::parse(&i.launched).unwrap_or_default(),
                        transition: i.reason,
                        reason_code: i.state_reason.code,
                        reason_msg: i.state_reason.message,
                    }));
                }
            }
        }
    }
    Ok(None)
}

/// the instance's newest serial console output (GetConsoleOutput Latest: up to its last 64 KB; EC2 keeps none once the
/// instance is terminated)
pub fn aws_console(region: &str, id: &str) -> Result<String> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Out {
        output: String,
    }
    let out: Out = ec2_read(
        region,
        &[
            ("Action", "GetConsoleOutput"),
            ("InstanceId", id),
            ("Latest", "true"),
        ],
    )?;
    let b = base64::engine::general_purpose::STANDARD
        .decode(out.output.trim())
        .map_err(|e| anyhow!("GetConsoleOutput: {e}"))?;
    Ok(String::from_utf8_lossy(&b).into_owned())
}
