//! A machine the kernel's spawner started (DESIGN "Target design", docs/PLAN-grants.md §4): its Fly config carries the
//! root key's public half (JARVIS2_KERNEL_ROOT), the root key's roster of the kernel's components
//! (JARVIS2_KERNEL_ROSTER) and its source (JARVIS2_SOURCE) instead of the old core's key. At boot it reads its documents
//! from the router (GET /m/kernel/boot) and believes them only as far as they check:
//!
//!   - every component identity is the roster's for its role, and the root key signed the roster;
//!   - the spawner's cert (source, fly-<this machine>, ⊤) names this machine's own keys and its source, and the
//!     notarizer notarized it;
//!   - the cert into the source is notarized too;
//!   - the grant, signed by the mover or the merger, is on this machine and its keys.
//!
//! From them it builds the Cert the rest of boot reads, and keeps the roster and secrets' keys for its pulls. The
//! roster it checks with is the one the router serves with the documents (the serving kernel copy's, root-signed:
//! checked against JARVIS2_KERNEL_ROOT), else the one in its Fly config. A delivered input whose challenge isn't the
//! notary's this machine knows makes it read the documents again (at most every 10 s), so the new copy's notary is
//! learnt at its first input.

use crate::cert::{Cert, Machine};
use crate::client::Client;
use crate::crypto::{SignedDoc, read_trim, sha256_hex};
use crate::{gojson, logf, machine_object, paths, util};
use anyhow::{Result, anyhow, bail};
use jarvis_doc::gv;
use jarvis_sig::{Doc, Identity, Trust, check_identity};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const KERNEL_ROOT_ENV: &str = "JARVIS2_KERNEL_ROOT";
pub const KERNEL_ROSTER_ENV: &str = "JARVIS2_KERNEL_ROSTER";
pub const KERNEL_SOURCE_ENV: &str = "JARVIS2_SOURCE";

/// what a kernel machine checks later answers with
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct KernelTrust {
    /// the root key's public half
    pub root: String,
    /// the root key's roster
    pub roster: SignedDoc,
    /// secrets' signing key (its pull answers)
    pub secrets: String,
    /// the log notary's signing key (every delivered input's challenge)
    pub notary: String,
    /// "fly-<id>": the object its grant and pulls name
    pub machine: String,
}

pub fn read_kernel_trust() -> Option<KernelTrust> {
    let b = std::fs::read(paths::kernel_trust_path()).ok()?;
    let t: KernelTrust = gojson::unmarshal(&b).ok()?;
    (!t.root.is_empty()).then_some(t)
}

/// an identity as the router sends it (read leniently, as Go's json.Unmarshal)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct LooseIdentity {
    pub role: String,
    #[serde(rename = "signingKey")]
    pub signing_key: String,
    #[serde(rename = "agreementKey")]
    pub agreement_key: String,
}

impl LooseIdentity {
    fn id(&self) -> Identity {
        Identity {
            role: self.role.clone(),
            signing_key: self.signing_key.clone(),
            agreement_key: self.agreement_key.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct LooseSigned {
    pub grant: SignedDoc,
    pub by: String,
    pub signer: Option<LooseIdentity>,
    pub keys: Option<SignedDoc>,
    pub secrets: Option<LooseIdentity>,
}

impl LooseSigned {
    fn signed(&self) -> gv::Signed {
        gv::Signed {
            grant: self.grant.as_sig_doc(),
            by: self.by.clone(),
            signer: self.signer.as_ref().map(LooseIdentity::id),
            keys: self.keys.as_ref().map(SignedDoc::as_sig_doc),
            secrets: self.secrets.as_ref().map(LooseIdentity::id),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct KernelBootDocs {
    pub grant: LooseSigned,
    #[serde(rename = "machineCert")]
    pub machine_cert: SignedDoc,
    #[serde(rename = "machineNotarized")]
    pub machine_notarized: SignedDoc,
    #[serde(rename = "sourceCert")]
    pub source_cert: SignedDoc,
    #[serde(rename = "sourceNotarized")]
    pub source_notarized: SignedDoc,
    pub notary: LooseIdentity,
    pub notarizer: LooseIdentity,
    pub mover: LooseIdentity,
    pub merger: LooseIdentity,
    pub spawner: LooseIdentity,
    pub secrets: LooseIdentity,
    /// secrets' {kind: keys, phone, root}
    pub keys: SignedDoc,
    /// secrets' signed store list (each store's sensitivity)
    pub stores: SignedDoc,
    /// the root key's roster of the serving kernel copy
    pub roster: Option<SignedDoc>,
}

/// a source's settings (router/kernelline.go kernelSettings), read strictly
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelSettings {
    #[serde(default)]
    v: i64,
    #[serde(default)]
    harness: String,
    #[serde(default, rename = "permissionMode")]
    permission_mode: String,
    #[serde(default)]
    config: Option<Box<RawValue>>,
}

/// the roster the documents come with (checked against the root key in the Fly config), else the one in the Fly config
pub fn kernel_trust_for(b: &KernelBootDocs) -> Result<Trust> {
    let t = Trust::new(crate::env::get(KERNEL_ROOT_ENV).trim());
    if let Some(r) = &b.roster {
        t.set(r.as_sig_doc(), None)
            .map_err(|e| anyhow!("the kernel's roster from the router: {e}"))?;
        return Ok(t);
    }
    let d: SignedDoc = gojson::unmarshal(
        crate::env::get(KERNEL_ROSTER_ENV)
            .as_bytes(),
    )
    .map_err(|e| anyhow!("the kernel's roster ({KERNEL_ROSTER_ENV}): {e}"))?;
    t.set(d.as_sig_doc(), None).map_err(|e| anyhow!("{e}"))?;
    Ok(t)
}

/// d opened by one of the keys the roster takes for role (its member's, then the retired ones)
fn open_by<T: serde::de::DeserializeOwned>(t: &Trust, role: &str, d: &Doc) -> Result<T> {
    let mut err = anyhow!("no {role} in the roster");
    for k in t.signing_keys(role) {
        match d.open(&k) {
            Ok(v) => return Ok(v),
            Err(e) => err = e.into(),
        }
    }
    Err(err)
}

/// the documents → the Cert boot reads, and what later pulls are checked with
pub fn check_kernel_boot(
    b: &KernelBootDocs,
    bx: &Trust,
    source: &str,
    me: &str,
    keys: &HashMap<String, String>,
) -> Result<(Cert, KernelTrust)> {
    for (role, id) in [
        ("notary", &b.notary),
        ("notarizer", &b.notarizer),
        ("mover", &b.mover),
        ("merger", &b.merger),
        ("spawner", &b.spawner),
        ("secrets", &b.secrets),
    ] {
        check_identity(&id.id(), role, bx).map_err(|e| anyhow!("{e}"))?;
    }
    let notarized = |c: &SignedDoc, nz: &SignedDoc| -> Result<()> {
        match open_by::<jarvis_doc::Notarized>(bx, "notarizer", &nz.as_sig_doc()) {
            Ok(n) if n.kind == "notarized" && n.cert == c.as_sig_doc().id() => Ok(()),
            Ok(_) => bail!("not notarized (<nil>)"),
            Err(e) => bail!("not notarized ({e})"),
        }
    };
    let self_obj = machine_object(me);
    let k = |n: &str| keys.get(n).cloned().unwrap_or_default();
    let mut mc = Err(anyhow!("no spawner in the roster"));
    for key in bx.signing_keys("spawner") {
        mc = jarvis_doc::open_cert(&b.machine_cert.as_sig_doc(), &key).map_err(|e| anyhow!("{e}"));
        if mc.is_ok() {
            break;
        }
    }
    let mc = mc.map_err(|e| anyhow!("the spawner's cert: {e}"))?;
    let Some(mm) = mc.machine.as_ref().filter(|m| {
        mc.succ.0 == self_obj
            && m.signing_key == k("signingKey")
            && m.encryption_key == k("encryptionKey")
    }) else {
        bail!("the spawner's cert names another machine or other keys");
    };
    if mc.pred.0 != source {
        bail!(
            "the spawner's cert comes from {}, this machine's Fly config says {source}",
            mc.pred.0
        );
    }
    notarized(&b.machine_cert, &b.machine_notarized)
        .map_err(|e| anyhow!("the spawner's cert: {e}"))?;
    let sc = match jarvis_doc::peek_cert(&b.source_cert.as_sig_doc()) {
        Ok(sc) if sc.succ == mc.pred && sc.source.is_some() => sc,
        _ => bail!("the source's cert isn't the cert into this machine's source"),
    };
    notarized(&b.source_cert, &b.source_notarized)
        .map_err(|e| anyhow!("the source's cert: {e}"))?;
    let src = sc.source.as_ref().ok_or_else(|| anyhow!("no source"))?;
    if reported_digest_of(&mm.image) != reported_digest_of(&src.image) {
        bail!("this machine runs another image than its source's");
    }
    let g = gv::open(&b.grant.signed(), bx).map_err(|e| anyhow!("the grant: {e}"))?;
    if g.machine.0 != self_obj
        || g.keys.signing_key != mm.signing_key
        || g.keys.encryption_key != mm.encryption_key
    {
        bail!("the grant is on another machine");
    }
    let st: KernelSettings = match serde_json::from_str(src.settings.get()) {
        Ok(st) => st,
        Err(e) => bail!("the source's settings: {e}"),
    };
    if st.v != 1 {
        bail!("the source's settings: <nil>");
    }
    let mut cert = Cert {
        kind: "succession-cert".into(),
        machine: Some(Machine {
            id: me.into(),
            image: String::new(),
            encryption_key: k("encryptionKey"),
            signing_key: k("signingKey"),
        }),
        ..Default::default()
    };
    cert.options.harness = st.harness;
    cert.options.permission_mode = st.permission_mode;
    if let Some(c) = &st.config {
        let raw = c.get();
        if !raw.is_empty() && raw != "{}" && raw != "null" {
            cert.options.config = raw.to_string();
        }
    }
    let mut stores: Vec<String> = vec![];
    if let Some(only) = g.pair.allowed.only.as_ref() {
        for a in only {
            if let Some(s) = a.strip_prefix("store:") {
                stores.push(s.to_string());
            }
        }
    }
    cert.stores = (!stores.is_empty()).then_some(stores);
    for c in g.pair.conditions.iter().flatten() {
        if let Some(s) = c.strip_prefix("session:") {
            cert.line = s.to_string();
        }
    }
    if sc.pred.kind() == Some(jarvis_doc::Kind::Machine) {
        cert.pred_id = sc.pred.machine_id().to_string();
    }
    cert.snapshot = src.snapshot.clone();
    // the phone's key and the stores' sensitivity, from secrets (what a core cert's phone and sensitive say)
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Ks {
        #[serde(default)]
        kind: String,
        #[serde(default)]
        phone: String,
        #[serde(default)]
        #[allow(dead_code)]
        root: String,
    }
    match b.keys.as_sig_doc().open::<Ks>(&b.secrets.signing_key) {
        Ok(ks) if ks.kind == "keys" && !ks.phone.is_empty() => cert.phone = ks.phone,
        Ok(_) => bail!("secrets' keys: <nil>"),
        Err(e) => bail!("secrets' keys: {e}"),
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct StoreRow {
        name: String,
        sensitive: bool,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Sl {
        kind: String,
        stores: Vec<StoreRow>,
    }
    let sl: Sl = match gojson::unmarshal::<Sl>(b.stores.payload.as_bytes()) {
        Ok(sl)
            if jarvis_sig::verify(
                &b.secrets.signing_key,
                b.stores.payload.as_bytes(),
                &b.stores.sig,
            ) && sl.kind == "stores" =>
        {
            sl
        }
        _ => bail!("secrets' store list isn't signed by secrets"),
    };
    let cs = cert.stores();
    let mut known = std::collections::HashSet::new();
    for s in &sl.stores {
        known.insert(s.name.clone());
        if s.sensitive && cs.contains(&s.name) {
            cert.sensitive = true;
        }
    }
    if cs.iter().any(|s| !known.contains(s)) {
        cert.sensitive = true; // a store secrets doesn't list: counted sensitive
    }
    let roster = bx.doc().map(SignedDoc::from).unwrap_or_default();
    Ok((
        cert,
        KernelTrust {
            root: bx.root().to_string(),
            roster,
            secrets: b.secrets.signing_key.clone(),
            notary: b.notary.signing_key.clone(),
            machine: self_obj,
        },
    ))
}

pub fn reported_digest_of(r: &str) -> String {
    match r.rfind("@sha256:") {
        Some(i) => r[i + 1..].to_string(),
        None => String::new(),
    }
}

fn write_trust_and_cert(trust: &KernelTrust, cert: Option<&Cert>) -> Result<()> {
    util::write_file(
        &paths::kernel_trust_path(),
        gojson::marshal(trust).as_bytes(),
        0o644,
    )?;
    if let Some(c) = cert {
        util::write_file(&paths::cert_path(), gojson::marshal(c).as_bytes(), 0o644)?;
    }
    Ok(())
}

fn source_env() -> String {
    crate::env::get(KERNEL_SOURCE_ENV)
        .trim()
        .to_string()
}

/// the documents, checked → the cert and the trust (nothing written)
pub fn fetch_and_check(
    c: &Client,
    me: &str,
    keys: &HashMap<String, String>,
) -> Result<(Cert, KernelTrust)> {
    let b: KernelBootDocs = c.json::<(), _>("GET", "/m/kernel/boot", None)?;
    let bx = kernel_trust_for(&b)?;
    check_kernel_boot(&b, &bx, &source_env(), me, keys)
}

/// boot's step 1 for a kernel machine (prepare)
pub fn kernel_boot_cert(c: &Client, me: &str, keys: &HashMap<String, String>) -> Result<Cert> {
    let mut i = 0;
    let b: KernelBootDocs = loop {
        match c.json::<(), _>("GET", "/m/kernel/boot", None) {
            Ok(b) => break b,
            Err(e) if i > 300 => bail!("no boot documents: {e:#}"),
            Err(_) => util::sleep(Duration::from_secs(2)),
        }
        i += 1;
    };
    let bx = kernel_trust_for(&b)?;
    let (cert, trust) = check_kernel_boot(&b, &bx, &source_env(), me, keys)?;
    util::write_file(
        &paths::kernel_trust_path(),
        gojson::marshal(&trust).as_bytes(),
        0o644,
    )?;
    // the settings as boot read them (the supervisor reads the stores from it)
    let _ = util::write_file(
        &paths::cert_path(),
        gojson::marshal(&cert).as_bytes(),
        0o644,
    );
    let (c2, me2, keys2) = (c.clone(), me.to_string(), keys.clone());
    set_refresh(Box::new(move || refresh_kernel_trust(&c2, &me2, &keys2)));
    Ok(cert)
}

type Refresh = Box<dyn Fn() -> Result<KernelTrust> + Send>;

struct RefreshState {
    refresh: Option<Refresh>,
    at: Option<Instant>,
}

static REFRESH: Mutex<RefreshState> = Mutex::new(RefreshState {
    refresh: None,
    at: None,
});

/// how often a delivered input that doesn't check makes the machine read its documents again (ms; tests shorten it)
pub static KERNEL_TRUST_EVERY_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(10_000);

fn set_refresh(f: Refresh) {
    if let Ok(mut s) = REFRESH.lock() {
        s.refresh = Some(f);
    }
}

/// Let this process read the kernel's documents again when a delivered input's challenge isn't the notary's it knows.
/// Boot arms it in prepare; each supervisor arms its own, as deliveries are checked there (2026-11-17: never armed in
/// supervisor-core, a copy flip left every running machine refusing every wakeup).
pub fn arm_kernel_trust_refresh(c: &Client) {
    if read_kernel_trust().is_none() {
        return; // an old core line: no notary to learn
    }
    let c = c.clone();
    set_refresh(Box::new(move || {
        let keys = crate::boot::own_keys()?;
        refresh_kernel_trust(&c, &c.me, &keys)
    }));
}

/// the documents again, checked as at boot; the trust they give replaces kernel.json
pub fn refresh_kernel_trust(
    c: &Client,
    me: &str,
    keys: &HashMap<String, String>,
) -> Result<KernelTrust> {
    let (_, trust) = fetch_and_check(c, me, keys)?;
    write_trust_and_cert(&trust, None)?;
    logf!(
        "the kernel's roster read again (notary {}…)",
        util::clip_bytes(&trust.notary, 16)
    );
    Ok(trust)
}

/// a kernel machine's reload of its documents (the grant names the stores now): kernel.json and cert.json rewritten
pub fn reload_documents(c: &Client) -> Result<()> {
    let keys = crate::boot::own_keys()?;
    let (cert, trust) = fetch_and_check(c, &c.me, &keys)?;
    write_trust_and_cert(&trust, Some(&cert))
}

/// the predecessor's snapshot, the one whose hash the source names
pub fn kernel_restore(c: &Client, want: &str) -> Result<()> {
    let tmp = paths::predecessor_tmp();
    let r = (|| {
        let (sum, _) = crate::snapdirect::fetch_snapshot(c, &tmp)?;
        if sum != want {
            bail!("the snapshot isn't the one the source names");
        }
        let n = crate::snapshot::unpack_file(&tmp)?;
        logf!("restored the predecessor's snapshot ({n} files)");
        Ok(())
    })();
    let _ = std::fs::remove_file(&tmp);
    r
}

/// what an input's attestation is checked with: the old core's key, or (a kernel machine, which has none) "",
/// check_attest then reading the notary's key from the kernel trust
pub fn attest_key() -> Result<String> {
    if let Some(k) = crate::apiproxy::test_core_key() {
        return Ok(k);
    }
    if read_kernel_trust().is_some() {
        return Ok(String::new());
    }
    read_trim(&paths::core_key_path())
}

/// what the log notary's challenge for an input delivered to a kernel machine is over (the router's kernelAttest makes
/// the same): the machine's object, the input's kind and the sha256 of its bytes
pub fn kernel_input_subject(machine: &str, kind: &str, sum: &str) -> String {
    sha256_hex(format!("jarvis2-input\n{machine}\n{kind}\n{sum}").as_bytes())
}

/// The notary logged this input for this machine (a challenge about "input" over its subject). One that isn't this
/// notary's: the documents are read again (a copy flip brings another notary), at most every 10 s, and the challenge
/// checked against the notary they name
pub fn check_kernel_attest(
    t: &KernelTrust,
    me: &str,
    kind: &str,
    attested: &[u8],
    d: Option<&SignedDoc>,
) -> Result<()> {
    let Some(d) = d else {
        bail!("no notary challenge (the input isn't in the kernel's log)")
    };
    let open = |notary: &str| -> Option<jarvis_doc::Challenge> {
        d.as_sig_doc()
            .open::<jarvis_doc::Challenge>(notary)
            .ok()
            .filter(|ch| ch.kind == "challenge" && ch.about == "input")
    };
    let ch = match open(&t.notary) {
        Some(ch) => ch,
        None => {
            let t2 = refreshed_trust();
            match t2 {
                Some(t2) if t2.notary != t.notary && t2.machine == t.machine => open(&t2.notary)
                    .ok_or_else(|| {
                        anyhow!("no notary challenge (the input isn't in the kernel's log)")
                    })?,
                _ => bail!("no notary challenge (the input isn't in the kernel's log)"),
            }
        }
    };
    if ch.subject != kernel_input_subject(&machine_object(me), kind, &sha256_hex(attested)) {
        bail!("the notary's challenge is for another input or machine");
    }
    Ok(())
}

/// the trust read again now, unless that was done less than 10 s ago
fn refreshed_trust() -> Option<KernelTrust> {
    let mut s = REFRESH.lock().ok()?;
    let every =
        Duration::from_millis(KERNEL_TRUST_EVERY_MS.load(std::sync::atomic::Ordering::Relaxed));
    if s.refresh.is_none() || s.at.is_some_and(|a| a.elapsed() < every) {
        return None;
    }
    s.at = Some(Instant::now());
    match (s.refresh.as_ref()?)() {
        Ok(t) => Some(t),
        Err(e) => {
            logf!("reading the kernel's documents again: {e:#}");
            None
        }
    }
}
