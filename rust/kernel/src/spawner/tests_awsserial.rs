//! kernel/spawner/awsserial_test.go: the live serial console reader against a fake EC2 Instance Connect push and a
//! fake serial console SSH endpoint

use super::super::Runner as _;
use super::super::aws::{AWS_REGIONS, AwsApi, AwsCredentials, keys_from_line};
use super::super::awsserial::{SERIAL_HOST_KEYS, SerialEndpoints};
use crate::kt::TestServer;
use jarvis_nethttp::{Req, W};
use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicI32, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ID: &str = "i-0123456789abcdef0";
const KEYS: &str = r#"{"encryptionKey":"ZW5j","signingKey":"c2ln"}"#;

/// a push: its headers and body
struct Push {
    target: String,
    authorization: String,
    body: String,
}

/// EC2 Instance Connect's push and the serial console's SSH endpoint, as AWS runs them: a pushed key opens one session
/// for its instance's port 0, and the session streams the console
struct Shared {
    /// authorized keys, by their OpenSSH form
    pushed: Mutex<BTreeSet<String>>,
    pushes: Mutex<Vec<Push>>,
    /// a push answered with this exception
    refuse: Mutex<String>,
    /// what the session streams (then it stays open)
    console: Mutex<String>,
    /// bytes the client wrote to the console
    written: AtomicI64,
    sessions: AtomicI32,
    /// connections that ended
    closed: AtomicI32,
}

struct FakeSerial {
    s: Arc<Shared>,
    api: TestServer,
    ssh: String,
    host_key: String,
    stop: tokio_util::sync::CancellationToken,
}

impl Drop for FakeSerial {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

fn split_every(s: &str, n: usize) -> Vec<String> {
    s.as_bytes()
        .chunks(n)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect()
}

struct Conn(Arc<Shared>);

impl Conn {
    fn allowed(&self, user: &str, k: &PublicKey) -> bool {
        let m = k.to_openssh().unwrap_or_default();
        user == format!("{ID}.port0")
            && self
                .0
                .pushed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(m.trim())
    }
}

impl russh::server::Handler for Conn {
    type Error = anyhow::Error;

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        k: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(if self.allowed(user, k) {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(&mut self, user: &str, k: &PublicKey) -> Result<Auth, Self::Error> {
        if !self.allowed(user, k) {
            return Ok(Auth::reject());
        }
        // one session per push
        let m = k.to_openssh().unwrap_or_default();
        self.0
            .pushed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(m.trim());
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _: Channel<Msg>,
        _: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.0.sessions.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }

    async fn shell_request(
        &mut self,
        ch: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let h = session.handle();
        let console = self
            .0
            .console
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            for part in split_every(&console, 7) {
                // the stream arrives in pieces
                let _ = h.data(ch, CryptoVec::from_slice(part.as_bytes())).await;
            }
        });
        Ok(())
    }

    async fn data(
        &mut self,
        _: ChannelId,
        data: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.0
            .written
            .fetch_add(data.len() as i64, Ordering::SeqCst);
        Ok(())
    }

    /// as AWS's: the client's EOF ends the session
    async fn channel_eof(
        &mut self,
        ch: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.close(ch)?;
        Ok(())
    }
}

fn fake_serial() -> FakeSerial {
    let s = Arc::new(Shared {
        pushed: Mutex::default(),
        pushes: Mutex::default(),
        refuse: Mutex::default(),
        console: Mutex::new(format!(
            "[   13.8] systemd[1]: booting\r\nip-10-40-0-9 login: JARVIS2-KEYS {KEYS}\r\n"
        )),
        written: AtomicI64::new(0),
        sessions: AtomicI32::new(0),
        closed: AtomicI32::new(0),
    });
    let s2 = s.clone();
    let api = TestServer::handler(move |w: &mut W, r: &mut Req| {
        let body = String::from_utf8_lossy(&r.read_body(1 << 20)).into_owned();
        s2.pushes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Push {
                target: r.header("X-Amz-Target"),
                authorization: r.header("Authorization"),
                body: body.clone(),
            });
        let refuse = s2.refuse.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if !refuse.is_empty() {
            w.write_header(400);
            w.write_str(&format!(
                r#"{{"__type":"com.amazon.aws.ec2instanceconnect#{refuse}","Message":"refused"}}"#
            ));
            return;
        }
        let v: Value = serde_json::from_str(&body).unwrap_or_default();
        if v["InstanceId"] != ID || v["SerialPort"] != 0 {
            w.write_header(400);
            return;
        }
        let k = v["SSHPublicKey"]
            .as_str()
            .unwrap_or_default()
            .trim()
            .to_string();
        s2.pushed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(k);
        w.write_str(r#"{"RequestId":"r","Success":true}"#);
    });
    let hk = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519)
        .unwrap_or_else(|e| panic!("{e}"));
    let host_key = hk.public_key().fingerprint(HashAlg::Sha256).to_string();
    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let ssh = ln
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"))
        .to_string();
    ln.set_nonblocking(true).unwrap_or_else(|e| panic!("{e}"));
    let stop = tokio_util::sync::CancellationToken::new();
    let (s3, stop2) = (s.clone(), stop.clone());
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap_or_else(|e| panic!("{e}"));
        rt.block_on(async move {
            let ln = tokio::net::TcpListener::from_std(ln).unwrap_or_else(|e| panic!("{e}"));
            let cfg = Arc::new(russh::server::Config {
                keys: vec![hk],
                auth_rejection_time: Duration::from_millis(1),
                auth_rejection_time_initial: Some(Duration::ZERO),
                ..Default::default()
            });
            loop {
                let c = tokio::select! {
                    _ = stop2.cancelled() => return,
                    c = ln.accept() => c,
                };
                let Ok((c, _)) = c else { return };
                let (cfg, s) = (cfg.clone(), s3.clone());
                tokio::spawn(async move {
                    if let Ok(run) = russh::server::run_stream(cfg, c, Conn(s.clone())).await {
                        let _ = run.await;
                    }
                    s.closed.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
    });
    FakeSerial {
        s,
        api,
        ssh,
        host_key,
        stop,
    }
}

/// an AwsApi whose push, SSH and EC2 calls go to the fakes; ec2 None: any EC2 call fails the test (answered 500, seen
/// in `ec2_calls`)
fn aws_for_serial(f: &FakeSerial, ec2: Option<TestServer>, host_key: &str) -> (AwsApi, TestServer) {
    let mut a = AwsApi::new();
    a.configure(AwsCredentials {
        access_key_id: "AKIDEXAMPLE".into(),
        secret_access_key: "secret".into(),
    });
    let es = ec2.unwrap_or_else(|| {
        TestServer::handler(|w: &mut W, r: &mut Req| {
            let b = r.read_body(1 << 20);
            eprintln!("an EC2 call: {}", String::from_utf8_lossy(&b));
            w.write_header(500);
            w.write_str(
                "<Response><Errors><Error><Code>Unexpected</Code></Error></Errors></Response>",
            );
        })
    });
    let eu = format!("{}/", es.url);
    a.endpoint = Box::new(move |_| eu.clone());
    let (push, ssh, hk) = (
        format!("{}/", f.api.url),
        f.ssh.clone(),
        host_key.to_string(),
    );
    a.serial_ep = SerialEndpoints {
        push: Box::new(move |_| push.clone()),
        ssh: Box::new(move |_| ssh.clone()),
        host_key: Box::new(move |_| hk.clone()),
        retry: Duration::from_millis(20),
    };
    (a, es)
}

fn wait_serial(a: &AwsApi) -> Option<super::super::MachineKeys> {
    let end = Instant::now() + Duration::from_secs(10);
    while Instant::now() < end {
        let (k, trying) = a.serial_keys(ID);
        if k.is_some() || !trying {
            return k;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the watcher neither read keys nor stopped");
}

fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !ok() {
        assert!(Instant::now() < end, "{what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// the keys line read live, through a pushed one-off key and AWS's host key, reaches Init with no EC2 call; the
/// console is only read, and the session closes once the keys are in
#[test]
fn serial_console_keys_reach_init() {
    let f = fake_serial();
    let (a, _es) = aws_for_serial(&f, None, &f.host_key);
    a.watch_serial("eu-west-2", ID);
    a.watch_serial("eu-west-2", ID); // a second start is the same watcher
    let k = wait_serial(&a).unwrap_or_else(|| panic!("no keys"));
    assert!(
        k.encryption_key == "ZW5j" && k.signing_key == "c2ln",
        "keys {k:?}"
    );
    let got = a.init(ID).unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(got, k);
    wait_for("the session stayed open after the keys line", || {
        f.s.closed.load(Ordering::SeqCst) > 0
    });
    assert_eq!(f.s.sessions.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.s.written.load(Ordering::SeqCst),
        0,
        "the spawner wrote to the console"
    );
    // the push: the JSON API's action, signed (X-Amz-Target among the signed headers), for port 0 of that instance
    let p = &f.s.pushes.lock().unwrap_or_else(|e| e.into_inner())[0];
    assert!(
        p.target == "AWSEC2InstanceConnectService.SendSerialConsoleSSHPublicKey"
            && p.authorization.contains(
                "/ec2-instance-connect/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-target,"
            )
            && p.body.contains(&format!(r#""InstanceId":"{ID}""#))
            && p.body.contains(r#""SerialPort":0"#)
            && p.body.contains(r#""SSHPublicKey":"ssh-ed25519 "#),
        "push {} {} {}",
        p.target,
        p.authorization,
        p.body
    );
}

/// an endpoint that doesn't show AWS's host key for the region is never read: no keys come from it
#[test]
fn serial_console_refuses_another_host_key() {
    let f = fake_serial();
    let (a, _es) = aws_for_serial(
        &f,
        None,
        "SHA256:a69rd5CE/AEG4Amm53I6lkD1ZPvS/BCV3tTPW2RnJg8",
    );
    a.watch_serial("eu-west-2", ID);
    assert!(wait_serial(&a).is_none(), "keys from a wrong host");
    assert_eq!(
        f.s.sessions.load(Ordering::SeqCst),
        0,
        "sessions opened on a wrong host"
    );
}

/// a region without serial console access (or a key EC2 refuses) stops the watcher at once, and Init reads the keys
/// from GetConsoleOutput as before
#[test]
fn serial_console_refused_falls_back_to_get_console_output() {
    let f = fake_serial();
    *f.s.refuse.lock().unwrap_or_else(|e| e.into_inner()) =
        "SerialConsoleAccessDisabledException".into();
    let calls = Arc::new(AtomicI32::new(0));
    let c2 = calls.clone();
    let ec2 = TestServer::handler(move |w: &mut W, r: &mut Req| {
        c2.fetch_add(1, Ordering::SeqCst);
        let b = r.read_body(1 << 20);
        let action = url::form_urlencoded::parse(&b)
            .find(|(k, _)| k == "Action")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        match action.as_str() {
            "DescribeInstances" => {
                w.write_str(&format!("<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>{ID}</instanceId><instanceState><name>running</name></instanceState></item></instancesSet></item></reservationSet></DescribeInstancesResponse>"));
            }
            "GetConsoleOutput" => {
                use base64::Engine as _;
                let out = base64::engine::general_purpose::STANDARD
                    .encode(format!("boot\r\nJARVIS2-KEYS {KEYS}\r\n"));
                w.write_str(&format!(
                    "<GetConsoleOutputResponse><output>{out}</output></GetConsoleOutputResponse>"
                ));
            }
            _ => w.write_header(400),
        }
    });
    let (a, _es) = aws_for_serial(&f, Some(ec2), &f.host_key);
    a.watch_serial("eu-west-2", ID);
    assert!(wait_serial(&a).is_none(), "keys from a refused console");
    assert_eq!(
        f.s.pushes.lock().unwrap_or_else(|e| e.into_inner()).len(),
        1,
        "pushes after a refusal that won't change"
    );
    let k = a.init(ID).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        k.encryption_key == "ZW5j" && calls.load(Ordering::SeqCst) > 0,
        "Init: {k:?}"
    );
}

/// an instance that isn't running yet refuses the push; the watcher asks again until it can read
#[test]
fn serial_console_waits_for_the_instance() {
    let f = fake_serial();
    *f.s.refuse.lock().unwrap_or_else(|e| e.into_inner()) =
        "EC2InstanceStateInvalidException".into();
    let (a, _es) = aws_for_serial(&f, None, &f.host_key);
    a.watch_serial("eu-west-2", ID);
    std::thread::sleep(Duration::from_millis(100));
    let (k, trying) = a.serial_keys(ID);
    assert!(k.is_none() && trying, "keys {k:?}, trying {trying}");
    f.s.refuse.lock().unwrap_or_else(|e| e.into_inner()).clear();
    assert!(wait_serial(&a).is_some(), "no keys once the instance ran");
}

/// a console that hasn't written the keys yet keeps the session open; Destroy closes it and forgets the watcher
#[test]
fn serial_console_stops_on_destroy() {
    let f = fake_serial();
    *f.s.console.lock().unwrap_or_else(|e| e.into_inner()) = "still booting\r\n".into();
    let ec2 = TestServer::handler(|w: &mut W, _: &mut Req| {
        w.write_str("<DescribeInstancesResponse><reservationSet></reservationSet></DescribeInstancesResponse>");
    });
    let (a, _es) = aws_for_serial(&f, Some(ec2), &f.host_key);
    a.watch_serial("eu-west-2", ID);
    wait_for("no session", || f.s.sessions.load(Ordering::SeqCst) > 0);
    a.destroy(ID).unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the session stayed open after Destroy", || {
        f.s.closed.load(Ordering::SeqCst) > 0
    });
    assert!(!a.serial_keys(ID).1, "the watcher is still known");
}

/// a region with no published host key has no live reader (GetConsoleOutput only)
#[test]
fn serial_console_only_where_aws_publishes_a_host_key() {
    for r in AWS_REGIONS {
        let k = SERIAL_HOST_KEYS
            .iter()
            .find(|(x, _)| x == r)
            .map(|(_, k)| *k)
            .unwrap_or_default();
        assert!(
            k.starts_with("SHA256:") && k.len() == 50,
            "{r}: host key {k}"
        );
    }
    let a = AwsApi::new();
    a.watch_serial("us-east-1", ID);
    assert!(!a.serial_keys(ID).1, "a watcher with no host key to check");
}

#[test]
fn keys_from_a_console_line() {
    for (line, want) in [
        (format!("JARVIS2-KEYS {KEYS}"), true),
        (format!("ip-10-40-0-9 login: JARVIS2-KEYS {KEYS}"), true), // the getty's prompt first
        (format!("JARVIS2-KEYS {KEYS}\r"), true),
        (
            "[ 13.8] systemd[1]: Started docker.service".to_string(),
            false,
        ),
    ] {
        let (k, ok) = keys_from_line(&line).unwrap_or_else(|e| panic!("{line}: {e:#}"));
        assert!(
            ok == want && (!ok || k.signing_key == "c2ln"),
            "{line}: {k:?} {ok}"
        );
    }
    assert!(
        keys_from_line(r#"JARVIS2-KEYS {"encryptionKey":""}"#).is_err(),
        "a keys line with no keys"
    );
}
