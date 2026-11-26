//! The phone's side of the e2e drivers (driver.rs, the kernel's line; aviary.rs, the aviary harness), as the iPhone
//! does it with software keys: the root key registered and the roster signed, the kernel's secrets claimed, the
//! spawner's runner credentials sealed to it, the root grant; and reading the router's records from its database.
//!
//!   E2E_ROUTER (the router), E2E_SPAWNER (the spawner, direct), E2E_DATABASE_URL (the router's database),
//!   E2E_MASTER_KEY_FILE, E2E_ROOT_KEY_FILE (the root key the components were started with), E2E_KERNEL (role=URL,… of
//!   every component of the serving copy), E2E_FLY_TOKEN, E2E_RUNNER ("" or "fabric"), E2E_FABRIC_MAGPIE and
//!   E2E_FABRIC_ADMIN (the fake hermit's tokens)

use anyhow::{Context, Result, bail};
use jarvis_sig::{Doc, Identity, Opener, Roster, Sealed, Signer, seal_to};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

/// the driver's settings (the E2E_* above), set by e2e-kernel before the driver runs in its process
static ENV: std::sync::OnceLock<std::collections::BTreeMap<String, String>> =
    std::sync::OnceLock::new();

pub fn set_env(m: std::collections::BTreeMap<String, String>) {
    let _ = ENV.set(m);
}

pub fn env(k: &str) -> String {
    ENV.get()
        .and_then(|m| m.get(k).cloned())
        .unwrap_or_else(|| std::env::var(k).unwrap_or_default())
}

pub fn router() -> String {
    env("E2E_ROUTER")
}

/// "15:04:05" UTC, as Go's log.Ltime prints it
fn now_hms() -> String {
    let t = time::OffsetDateTime::now_utc();
    format!("{:02}:{:02}:{:02}", t.hour(), t.minute(), t.second())
}

pub fn logf(msg: &str) {
    eprintln!("{} {msg}", now_hms());
}

pub fn step(msg: &str) {
    logf(&format!("==== {msg}"));
}

fn client() -> &'static reqwest::blocking::Client {
    static C: std::sync::OnceLock<reqwest::blocking::Client> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap_or_default()
    })
}

/// one call → (status, body); a connection error is an error
pub fn call(method: &str, url: &str, body: Option<&Value>) -> Result<(u16, Vec<u8>)> {
    let m = reqwest::Method::from_bytes(method.as_bytes())?;
    let mut r = client()
        .request(m, url)
        .header("Content-Type", "application/json");
    if let Some(b) = body {
        r = r.body(jarvis_sig::go_json(b)?);
    }
    let resp = r.send().with_context(|| format!("{method} {url}"))?;
    let st = resp.status().as_u16();
    Ok((st, resp.bytes()?.to_vec()))
}

/// one call → (status, body), a connection error as status 0 (a router not up yet)
pub fn call_quiet(method: &str, url: &str) -> (u16, Vec<u8>) {
    call(method, url, None).unwrap_or((0, vec![]))
}

/// a 2xx call's JSON answer (null for an empty one)
pub fn must(method: &str, url: &str, body: Option<&Value>) -> Result<Value> {
    let (st, b) = call(method, url, body)?;
    if st / 100 != 2 {
        bail!("{method} {url}: HTTP {st} {}", String::from_utf8_lossy(&b));
    }
    if b.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&b)
        .with_context(|| format!("{method} {url}: {}", String::from_utf8_lossy(&b)))
}

/// ok every 3 s until it says so, or an error after limit
pub fn wait_for(what: &str, limit: Duration, mut ok: impl FnMut() -> Result<bool>) -> Result<()> {
    let end = Instant::now() + limit;
    loop {
        if ok()? {
            return Ok(());
        }
        if Instant::now() > end {
            bail!(
                "timed out after {} waiting for {what}",
                jarvis_go::fmt::duration_string(limit)
            );
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// the router's sessions and records, from its database, in state.json's old shape: {"sessions": {id: …}, "records":
/// […]}
pub fn state_json() -> Result<Value> {
    let mut c = postgres::Client::connect(&env("E2E_DATABASE_URL"), postgres::NoTls)?;
    let mut sessions = serde_json::Map::new();
    for r in c.query("SELECT id, doc::text FROM sessions", &[])? {
        let id: String = r.get(0);
        let doc: String = r.get(1);
        sessions.insert(id, serde_json::from_str(&doc)?);
    }
    let mut records = vec![];
    for r in c.query("SELECT doc::text FROM records ORDER BY ord", &[])? {
        let doc: String = r.get(0);
        records.push(serde_json::from_str::<Value>(&doc)?);
    }
    Ok(json!({"sessions": sessions, "records": records}))
}

/// the router's own record of a session (its kernel line included), or None and whether its archived record's source
/// burned
pub fn read_session(id: &str) -> (Option<Value>, bool) {
    let Ok(st) = state_json() else {
        return (None, false);
    };
    if let Some(s) = st["sessions"].get(id) {
        return (Some(s.clone()), false);
    }
    for r in st["records"].as_array().into_iter().flatten() {
        if r["id"] == id {
            return (None, r["kernel"]["burned"] == true);
        }
    }
    (None, false)
}

/// the machine reported its harness running (a machine that booted without one, as the Rust machine's first image
/// did, "no fd 3 from the keeper", is no boot)
pub fn harness_runs(s: &Value) -> bool {
    s["live"]["registry"]["harness"]["running"] == true
}

pub fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

/// the phone's keys and the test's root and master keys
pub struct Phone {
    pub master: Signer,
    pub phone: Signer,
    pub agree: Opener,
    pub root: Signer,
}

impl Phone {
    pub fn new() -> Result<Phone> {
        let pem = |k: &str| -> Result<Signer> {
            let p = std::fs::read_to_string(env(k)).with_context(|| k.to_string())?;
            Ok(Signer::from_pkcs8_pem(&p)?)
        };
        Ok(Phone {
            master: pem("E2E_MASTER_KEY_FILE")?,
            phone: Signer::generate(),
            agree: Opener::generate(),
            root: pem("E2E_ROOT_KEY_FILE")?,
        })
    }

    /// the root key registered, every component's fresh keys vouched for in one root-signed document (E2E_KERNEL)
    pub fn roster(&self) -> Result<()> {
        let r = router();
        must(
            "POST",
            &format!("{r}/api/kernel/root-key"),
            Some(&json!({"rootKey": self.root.public_key()})),
        )?;
        let ro = Roster {
            copy: "blue".into(),
            members: identities(&env("E2E_KERNEL"))?,
            ..Default::default()
        };
        self.post_roster(&ro)?;
        Ok(())
    }

    /// a roster signed by the root key, to the router → its answer
    pub fn post_roster(&self, ro: &Roster) -> Result<Value> {
        let rp = ro.payload()?;
        let sig = self.root.sign(rp.as_bytes());
        must(
            "POST",
            &format!("{}/api/kernel/roster", router()),
            Some(&json!({"payload": rp, "rootSig": sig})),
        )
    }

    /// the kernel's secrets claimed as the app's Reset claims them (ios/Jarvis4/Security/KernelSetup.swift): the
    /// test master key, naming the phone and the root key, the seed the kit derives (HKDF of the master's scalar,
    /// "jarvis2/kernel-secrets-seed") in the bundle and the keys it derives as the claim's identity; then the roster
    /// again, naming those keys (secrets serves with them from now on, which a copy flip needs: only a secrets set up
    /// from the kit's seed hands over)
    pub fn claim(&self) -> Result<()> {
        use base64::Engine as _;
        use sha2::Digest as _;
        let r = router();
        let id = must("GET", &format!("{r}/api/kernel/secrets/identity"), None)?;
        let seed = jarvis_kernel::secrets::crypto::kdf(
            &self.master.scalar(),
            "jarvis2/kernel-secrets-seed",
        );
        let (ds, da) = jarvis_kernel::secrets::continuity::seed_identity(&seed)?;
        let bundle = jarvis_sig::go_json(
            &json!({"format": "keys", "secretsSeed": base64::engine::general_purpose::STANDARD.encode(seed)}),
        )?;
        let sum = sha2::Sha256::digest(bundle.as_bytes());
        let st = jarvis_sig::go_json(
            &json!({"kind": "kernel-claim", "master": self.master.public_key(),
            "secrets": {"signingKey": id["signingKey"], "agreementKey": id["agreementKey"]},
            "phone": {"signingKey": self.phone.public_key(), "agreementKey": self.agree.public_key()},
            "root": self.root.public_key(),
            "bundleSha256": sum.iter().map(|x| format!("{x:02x}")).collect::<String>(),
            "identity": {"signingKey": ds, "agreementKey": da}}),
        )?;
        let ms = self.master.sign(st.as_bytes());
        let sealed: Sealed = seal_to(
            s(&id["agreementKey"]),
            bundle.as_bytes(),
            "jarvis2/kernel-claim",
        )?;
        must(
            "POST",
            &format!("{r}/api/kernel/secrets/claim"),
            Some(&json!({"statement": st, "masterSig": ms, "bundle": sealed})),
        )?;
        let ro = Roster {
            copy: "blue".into(),
            members: identities(&env("E2E_KERNEL"))?,
            ..Default::default()
        };
        if ro.member("secrets").map(|m| m.signing_key.as_str()) != Some(ds.as_str()) {
            bail!("secrets doesn't serve with the keys the seed derives after the claim");
        }
        self.post_roster(&ro)?;
        Ok(())
    }

    /// the spawner's runner credentials sealed to it: the fabric's (the fake hermit's tokens) or the Fly token
    pub fn runner_credentials(&self) -> Result<()> {
        let sp = env("E2E_SPAWNER");
        let sd: Doc = serde_json::from_value(must("GET", &format!("{sp}/identity"), None)?)?;
        let sid: Identity = serde_json::from_str(&sd.payload)?;
        if env("E2E_RUNNER") == "fabric" {
            step("the spawner's fabric credentials, sealed to it");
            let cred = jarvis_sig::go_json(&json!({"magpieToken": env("E2E_FABRIC_MAGPIE"),
                "adminToken": env("E2E_FABRIC_ADMIN"), "admin": "e2e@fabric.invalid", "person": "jarvis4@deyaochen.com"}))?;
            let cs = seal_to(
                &sid.agreement_key,
                cred.as_bytes(),
                "jarvis4/fabric-credentials",
            )?;
            must(
                "POST",
                &format!("{sp}/fabric-credentials"),
                Some(&json!({"sealed": cs})),
            )?;
        } else {
            step("the spawner's Fly token, sealed to it");
            let tok = jarvis_sig::go_json(&json!({"FLY_API_TOKEN": env("E2E_FLY_TOKEN")}))?;
            let ts = seal_to(&sid.agreement_key, tok.as_bytes(), "jarvis2/fly-token")?;
            must(
                "POST",
                &format!("{sp}/fly-token"),
                Some(&json!({"sealed": ts})),
            )?;
        }
        Ok(())
    }

    /// the root grant: ⊤ on the sink, signed by the root key; then the kernel serves new sessions
    pub fn root_grant(&self) -> Result<()> {
        let r = router();
        let draft = must("GET", &format!("{r}/api/kernel/root-grant/draft"), None)?;
        let p = s(&draft["payload"]).to_string();
        let rs = self.root.sign(p.as_bytes());
        must(
            "POST",
            &format!("{r}/api/kernel/root-grant"),
            Some(&json!({"grant": {"payload": p, "sig": rs}})),
        )?;
        if must("GET", &format!("{r}/api/kernel"), None)?["serves"] != true {
            bail!("the kernel doesn't serve new sessions after its root grant");
        }
        Ok(())
    }
}

/// every component's identity in a "role=URL,…" list, each waited for (a component just started)
pub fn identities(list: &str) -> Result<Vec<Identity>> {
    let mut out = vec![];
    for kv in list.trim_end_matches(',').split(',') {
        let (role, base) = kv.split_once('=').unwrap_or((kv, ""));
        let mut m = Identity::default();
        wait_for(
            &format!("{role}'s identity"),
            Duration::from_secs(60),
            || {
                let Ok((200, b)) = call("GET", &format!("{base}/identity"), None) else {
                    return Ok(false);
                };
                m = identity_answer(role, &b).unwrap_or_default();
                Ok(!m.signing_key.is_empty())
            },
        )?;
        out.push(m);
    }
    Ok(out)
}

/// a component's GET /identity: secrets answers {role, signingKey, agreementKey, state}, the others their self-signed
/// identity
pub fn identity_answer(role: &str, b: &[u8]) -> Result<Identity> {
    if role == "secrets" {
        let v: Value = serde_json::from_slice(b)?;
        return Ok(Identity {
            role: s(&v["role"]).to_string(),
            signing_key: s(&v["signingKey"]).to_string(),
            agreement_key: s(&v["agreementKey"]).to_string(),
        });
    }
    let d: Doc = serde_json::from_slice(b)?;
    Ok(serde_json::from_str(&d.payload)?)
}
