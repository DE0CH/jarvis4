//! An AWS machine's keys line, read live from the instance's serial console (the EC2 Serial Console, over SSH;
//! kernel/spawner/awsserial.go) instead of waiting for GetConsoleOutput, whose newest output EC2 refreshes only every
//! 30-40 s (measured 2026-11-04: docs/PLAN-aws.md): the line reaches the spawner within a second of the machine
//! writing it. GetConsoleOutput stays the fallback (init), so a region without serial console access, a refused key
//! or a dropped connection only costs that wait again.
//!
//! The link to the instance is still AWS's word: the spawner pushes a one-off key for that instance id
//! (SendSerialConsoleSSHPublicKey, its own AWS key) and the SSH endpoint must show the host key AWS publishes for the
//! region (SERIAL_HOST_KEYS), so only AWS's serial console service can answer, and it answers only with that
//! instance's ttyS0. The spawner never writes to the console: the channel is read until the keys line, then closed.

use super::MachineKeys;
use super::aws::{AwsApi, AwsError, aws_err, keys_from_line, sign_v4};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// the EC2 Serial Console's SSH host key per session region, as AWS publishes them (EC2 User Guide, "EC2 Serial
/// Console endpoints and fingerprints")
pub const SERIAL_HOST_KEYS: &[(&str, &str)] = &[
    (
        "eu-west-2",
        "SHA256:a69rd5CE/AEG4Amm53I6lkD1ZPvS/BCV3tTPW2RnJg8",
    ),
    (
        "ap-southeast-1",
        "SHA256:PLFNn7WnCQDHx3qmwLu1Gy/O8TUX7LQgZuaC6L45CoY",
    ),
    (
        "ap-northeast-1",
        "SHA256:RQfsDCZTOfQawewTRDV1t9Em/HMrFQe+CRlIOT5um4k",
    ),
];

/// how long a watcher keeps trying (the router's own wait for init is 10 min)
const SERIAL_WATCH_MAX: Duration = Duration::from_secs(600);

/// at most this much of one console line is kept (a keys line is ~250 bytes)
const SERIAL_LINE_MAX: usize = 64 << 10;

/// where the push and the SSH go (tests point them at fakes)
pub struct SerialEndpoints {
    /// the EC2 Instance Connect API
    pub push: Box<dyn Fn(&str) -> String + Send + Sync>,
    /// the serial console's host:port
    pub ssh: Box<dyn Fn(&str) -> String + Send + Sync>,
    /// the SSH host key's SHA256 fingerprint ("" = no serial console there)
    pub host_key: Box<dyn Fn(&str) -> String + Send + Sync>,
    pub retry: Duration,
}

impl Default for SerialEndpoints {
    fn default() -> Self {
        SerialEndpoints {
            push: Box::new(|r| format!("https://ec2-instance-connect.{r}.amazonaws.com/")),
            ssh: Box::new(|r| format!("serial-console.ec2-instance-connect.{r}.aws:22")),
            host_key: Box::new(|r| {
                SERIAL_HOST_KEYS
                    .iter()
                    .find(|(x, _)| *x == r)
                    .map(|(_, k)| k.to_string())
                    .unwrap_or_default()
            }),
            retry: Duration::from_secs(2),
        }
    }
}

/// one instance's watcher: the keys once read
#[derive(Default)]
struct Watch {
    keys: Option<MachineKeys>,
    /// given up or done (init falls back to GetConsoleOutput unless keys is set)
    stopped: bool,
    cancel: Option<tokio_util::sync::CancellationToken>,
}

/// the live serial console readers, by instance id
#[derive(Default)]
pub struct SerialWatches(Mutex<BTreeMap<String, Arc<Mutex<Watch>>>>);

/// the endpoint showed a host key other than AWS's for the region; asking again won't change that
#[derive(Debug)]
struct HostKeyError(String);

impl std::fmt::Display for HostKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "not AWS's serial console host key: {}", self.0)
    }
}

impl std::error::Error for HostKeyError {}

/// a refusal that won't change by asking again (the account's or the key's, not the instance's state)
fn serial_fatal(code: &str) -> bool {
    matches!(
        code,
        "SerialConsoleAccessDisabledException"
            | "AccessDeniedException"
            | "UnrecognizedClientException"
            | "InvalidSignatureException"
            | "EC2InstanceTypeInvalidException"
            | "EC2InstanceNotFoundException"
    )
}

impl AwsApi {
    /// start reading id's serial console for its keys line, unless a watcher for it exists
    pub(crate) fn watch_serial(self: &AwsApi, region: &str, id: &str) {
        if (self.serial_ep.host_key)(region).is_empty() {
            return;
        }
        let w = {
            let mut g = self.serial.0.lock().unwrap_or_else(|e| e.into_inner());
            if g.contains_key(id) {
                return;
            }
            let w = Arc::new(Mutex::new(Watch {
                cancel: Some(tokio_util::sync::CancellationToken::new()),
                ..Default::default()
            }));
            g.insert(id.into(), w.clone());
            w
        };
        // the watcher needs the API (its key, its endpoints) for as long as it runs: a copy of what it uses
        let job = SerialJob {
            region: region.into(),
            id: id.into(),
            creds: self.configured().ok(),
            push: (self.serial_ep.push)(region),
            ssh: (self.serial_ep.ssh)(region),
            host_key: (self.serial_ep.host_key)(region),
            retry: self.serial_ep.retry,
            http: self.http().clone(),
        };
        std::thread::spawn(move || run_serial(job, w));
    }

    /// the keys the watcher read; whether one is still trying
    pub(crate) fn serial_keys(&self, id: &str) -> (Option<MachineKeys>, bool) {
        let g = self.serial.0.lock().unwrap_or_else(|e| e.into_inner());
        match g.get(id) {
            None => (None, false),
            Some(w) => {
                let w = w.lock().unwrap_or_else(|e| e.into_inner());
                (w.keys.clone(), !w.stopped)
            }
        }
    }

    /// the instance is going (destroy): its watcher stops and is forgotten
    pub(crate) fn stop_serial(&self, id: &str) {
        let mut g = self.serial.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(w) = g.remove(id) {
            let mut w = w.lock().unwrap_or_else(|e| e.into_inner());
            if !w.stopped {
                w.stopped = true;
                if let Some(c) = &w.cancel {
                    c.cancel();
                }
            }
        }
    }
}

struct SerialJob {
    region: String,
    id: String,
    creds: Option<super::aws::AwsCredentials>,
    push: String,
    ssh: String,
    host_key: String,
    retry: Duration,
    http: reqwest::blocking::Client,
}

fn run_serial(job: SerialJob, w: Arc<Mutex<Watch>>) {
    let deadline = Instant::now() + SERIAL_WATCH_MAX;
    let cancel = w
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .cancel
        .clone()
        .unwrap_or_default();
    let done = |k: Option<MachineKeys>, why: &str| {
        let mut g = w.lock().unwrap_or_else(|e| e.into_inner());
        if !g.stopped {
            g.keys = k;
            g.stopped = true;
            cancel.cancel();
        }
        drop(g);
        if !why.is_empty() {
            crate::serve::log(&format!(
                "[aws] {} serial console: {why} (the keys come from GetConsoleOutput)",
                job.id
            ));
        }
    };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return done(None, "no runtime");
    };
    while Instant::now() < deadline {
        if cancel.is_cancelled() {
            return;
        }
        match read_serial_once(&job, &rt, &cancel) {
            Ok(k) => return done(Some(k), ""),
            Err(e) => {
                let fatal = e
                    .downcast_ref::<AwsError>()
                    .is_some_and(|a| serial_fatal(&a.code))
                    || e.downcast_ref::<HostKeyError>().is_some();
                if fatal {
                    return done(None, &format!("{e:#}"));
                }
            }
        }
        let t = job.retry;
        if rt.block_on(async {
            tokio::select! {
                _ = cancel.cancelled() => true,
                _ = tokio::time::sleep(t) => false,
            }
        }) {
            return;
        }
    }
    done(None, &format!("no keys line in {}", "10m0s"))
}

/// one push and one connection: the first keys line read, or why not
fn read_serial_once(
    job: &SerialJob,
    rt: &tokio::runtime::Runtime,
    cancel: &tokio_util::sync::CancellationToken,
) -> anyhow::Result<MachineKeys> {
    let key =
        russh::keys::PrivateKey::random(&mut rand_core::OsRng, russh::keys::Algorithm::Ed25519)
            .map_err(|e| anyhow::anyhow!("a key: {e}"))?;
    let pub_line = key
        .public_key()
        .to_openssh()
        .map_err(|e| anyhow::anyhow!("the public key: {e}"))?;
    push_serial_key(job, &pub_line)?;
    rt.block_on(async {
        tokio::select! {
            _ = cancel.cancelled() => Err(anyhow::anyhow!("cancelled")),
            _ = tokio::time::sleep(SERIAL_WATCH_MAX) => Err(anyhow::anyhow!("the watch's time ran out")),
            r = read_serial_with(job, key) => r,
        }
    })
}

struct HostCheck {
    want: String,
    region: String,
}

impl russh::client::Handler for HostCheck {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, k: &russh::keys::PublicKey) -> Result<bool, Self::Error> {
        let got = k.fingerprint(russh::keys::HashAlg::Sha256).to_string();
        if got != self.want {
            return Err(
                HostKeyError(format!("{got}, not {} for {}", self.want, self.region)).into(),
            );
        }
        Ok(true)
    }
}

/// one connection with a key already pushed for the instance: the first keys line read, or why not
async fn read_serial_with(
    job: &SerialJob,
    key: russh::keys::PrivateKey,
) -> anyhow::Result<MachineKeys> {
    let cfg = Arc::new(russh::client::Config {
        inactivity_timeout: None,
        ..Default::default()
    });
    let handler = HostCheck {
        want: job.host_key.clone(),
        region: job.region.clone(),
    };
    let mut s = tokio::time::timeout(
        Duration::from_secs(20),
        russh::client::connect(cfg, job.ssh.as_str(), handler),
    )
    .await
    .map_err(|_| anyhow::anyhow!("the serial console didn't answer in 20 s"))??;
    let auth = s
        .authenticate_publickey(
            format!("{}.port0", job.id),
            russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None),
        )
        .await?;
    if !auth.success() {
        return Err(anyhow::anyhow!("the serial console refused the pushed key"));
    }
    let mut ch = s.channel_open_session().await?;
    ch.request_pty(false, "vt100", 200, 40, 0, 0, &[(russh::Pty::ECHO, 0)])
        .await?;
    // stdin stays open and empty: the serial console ends a session on its client's EOF (seen on AWS 2026-11-04)
    ch.request_shell(false).await?;
    let mut buf: Vec<u8> = vec![];
    while let Some(m) = ch.wait().await {
        let data = match m {
            russh::ChannelMsg::Data { data } => data.to_vec(),
            russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
            _ => continue,
        };
        buf.extend(data);
        // the console ends lines with \r\n, and a line may carry the getty's prompt before the mark
        while let Some(i) = buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buf.drain(..=i).collect();
            let (k, ok) = keys_from_line(&String::from_utf8_lossy(&line))?;
            if ok {
                let _ = ch.close().await;
                return Ok(k);
            }
        }
        if buf.len() > SERIAL_LINE_MAX {
            return Err(anyhow::anyhow!(
                "a console line over {SERIAL_LINE_MAX} bytes"
            ));
        }
    }
    Err(anyhow::anyhow!(
        "the serial console closed before a keys line"
    ))
}

/// EC2 Instance Connect's SendSerialConsoleSSHPublicKey: the key may open one serial console session on the
/// instance's port 0 within 60 s
fn push_serial_key(job: &SerialJob, pub_line: &str) -> anyhow::Result<()> {
    let Some(c) = &job.creds else {
        return Err(super::Missing::AwsKey.into());
    };
    let body = jarvis_sig::go_json(
        &json!({"InstanceId": job.id, "SerialPort": 0, "SSHPublicKey": pub_line}),
    )?;
    let ctype = "application/x-amz-json-1.1";
    let target = "AWSEC2InstanceConnectService.SendSerialConsoleSSHPublicKey";
    let hs = sign_v4(
        "POST",
        &job.push,
        ctype,
        target,
        body.as_bytes(),
        c,
        &job.region,
        "ec2-instance-connect",
        time::OffsetDateTime::now_utc(),
    );
    let mut req = job
        .http
        .post(&job.push)
        .header("Content-Type", ctype)
        .header("X-Amz-Target", target)
        .body(body);
    for (k, v) in hs {
        req = req.header(k, v);
    }
    let resp = req.send()?;
    let status = resp.status().as_u16();
    let b = resp.bytes()?.to_vec();
    let b = &b[..b.len().min(1 << 16)];
    if status / 100 == 2 {
        #[derive(serde::Deserialize, Default)]
        struct Ok {
            #[serde(default, rename = "Success")]
            success: bool,
        }
        if serde_json::from_slice::<Ok>(b).is_ok_and(|o| o.success) {
            return Result::Ok(());
        }
        return Err(aws_err(
            status,
            "NoSuccess",
            format!(
                "SendSerialConsoleSSHPublicKey: {}",
                jarvis_go::fmt::clip_bytes(&String::from_utf8_lossy(b), 300)
            ),
        ));
    }
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct E {
        #[serde(rename = "__type")]
        kind: String,
        message: String,
        #[serde(rename = "Message")]
        msg: String,
    }
    let e: E = serde_json::from_slice(b).unwrap_or_default();
    let code = e.kind.rsplit('#').next().unwrap_or_default().to_string();
    let mut msg = format!("{}{}", e.message, e.msg);
    if code.is_empty() {
        msg = String::from_utf8_lossy(b).trim().to_string();
    }
    Err(aws_err(
        status,
        &code,
        format!(
            "SendSerialConsoleSSHPublicKey: HTTP {status} {code} {}",
            jarvis_go::fmt::clip_bytes(&msg, 300)
        ),
    ))
}
