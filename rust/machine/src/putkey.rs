//! Writing one key into a store from a session (Deyao, 2026-10-13: any session with a valid machine key may write a
//! key, with no approval: it can't read the store, and the key's backup keeps every earlier value). The value never
//! leaves this machine in the clear: it is sealed to the store key P + K (only the phone and the core together open it)
//! and, for its backup, to the master key (only Deyao's kit opens it), and this machine signs both (core.WriterText).
//! The store key, the master key and the phone come from the core's signed documents, checked against the core key this
//! machine was started with, so the router can't hand it a key of its own.
//!
//!   jarvis put-key STORE KEY [--explain TEXT] < value     the value from stdin (never an argument)
//!   jarvis delete-key STORE KEY

use crate::client::Client;
use crate::crypto::{SignedDoc, load_private, read_trim, sha256_hex, verify_doc};
use crate::task::ENV_NAME_RE;
use crate::{logf, paths, util};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Result, anyhow, bail};
use hkdf::Hkdf;
use jarvis_sig::{b64, unb64};
use p256::PublicKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
use serde::Deserialize;
use sha2::Sha256;
use std::io::Read;

/// core.WriterText
pub fn writer_text(store: &str, key: &str, e: &str, data: &str, backup_sha: &str) -> String {
    let sum = if data.is_empty() {
        String::new()
    } else {
        sha256_hex(data.as_bytes())
    };
    format!("jarvis2-store-key\n{store}\n{key}\n{e}\n{sum}\n{backup_sha}")
}

pub fn gcm_seal(key: &[u8], plain: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let g = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("bad key"))?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = g
        .encrypt(&Nonce::from(nonce), Payload { msg: plain, aad })
        .map_err(|_| anyhow!("seal"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// ephemeral ECDH with the recipient point, HKDF-SHA256(info), AES-256-GCM (nonce ‖ ciphertext ‖ tag) → (e, data)
pub fn seal_parts(
    recipient: &str,
    plain: &[u8],
    info: &str,
    aad: &[u8],
) -> Result<(String, String)> {
    let r =
        PublicKey::from_sec1_bytes(&unb64(recipient)?).map_err(|_| anyhow!("bad public key"))?;
    let e = p256::ecdh::EphemeralSecret::random(&mut rand::rngs::OsRng);
    let x = e.diffie_hellman(&r);
    let mut k = [0u8; 32];
    Hkdf::<Sha256>::new(None, x.raw_secret_bytes())
        .expand(info.as_bytes(), &mut k)
        .map_err(|_| anyhow!("hkdf"))?;
    Ok((
        b64(e.public_key().to_encoded_point(false).as_bytes()),
        b64(&gcm_seal(&k, plain, aad)?),
    ))
}

/// What a write's targets are checked with: the old core's key, or on a kernel machine secrets' keys as the root key's
/// roster names them (its agreement key: the write's live copy is sealed to it) → (signing, agreement)
pub fn write_trust() -> Result<(String, String)> {
    if let Some(t) = crate::kernelboot::read_kernel_trust() {
        let r = jarvis_sig::open_roster(&t.roster.as_sig_doc(), &t.root)
            .map_err(|e| anyhow!("the kernel's roster: {e}"))?;
        let Some(m) = r.member("secrets").filter(|m| m.signing_key == t.secrets) else {
            bail!(
                "the kernel's roster names no secrets, or another one than this machine booted with"
            );
        };
        return Ok((m.signing_key.clone(), m.agreement_key.clone()));
    }
    Ok((read_trim(&paths::core_key_path())?, String::new()))
}

/// The store key and the master key, from the core's (or the kernel secrets') signed documents, checked with its key.
/// secrets_agreement: the kernel's secrets' agreement key K from the roster ("" = the core): secrets signs no store key,
/// so the machine computes P + K itself from the phone its signed state names
pub fn seal_targets(
    c: &Client,
    core_key: &str,
    secrets_agreement: &str,
) -> Result<(String, String)> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Ident {
        #[serde(rename = "signingKey")]
        signing_key: String,
        state: Option<SignedDoc>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Out {
        identity: Ident,
        #[serde(rename = "storeKey")]
        store_key: Option<SignedDoc>,
    }
    let out: Out = c.json::<(), Out>("GET", "/m/store-key", None)?;
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Phone {
        #[serde(rename = "agreementKey")]
        agreement_key: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct St {
        kind: String,
        master: String,
        phone: Option<Phone>,
    }
    let st: St = match verify_doc::<St>(core_key, out.identity.state.as_ref()) {
        Ok(st)
            if out.identity.signing_key == core_key
                && (st.kind == "core-state" || st.kind == "secrets-state")
                && !st.master.is_empty()
                && st.phone.is_some() =>
        {
            st
        }
        _ => {
            bail!("the core's state isn't signed by this machine's core, or the core isn't set up")
        }
    };
    let phone = st.phone.map(|p| p.agreement_key).unwrap_or_default();
    if !secrets_agreement.is_empty() {
        let sk = jarvis_sig::store_key(&phone, secrets_agreement).map_err(|e| anyhow!("{e}"))?;
        return Ok((sk, st.master));
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Sk {
        kind: String,
        phone: String,
        #[serde(rename = "storeKey")]
        store_key: String,
    }
    match verify_doc::<Sk>(core_key, out.store_key.as_ref()) {
        Ok(sk) if sk.kind == "store-key" && sk.phone == phone && !sk.store_key.is_empty() => {
            Ok((sk.store_key, st.master))
        }
        _ => bail!("the store key isn't the core's for its phone"),
    }
}

/// the HKDF info a write's live copy is sealed under (kernel/secrets infoLive + store + key)
pub fn live_info(store: &str, key: &str) -> String {
    format!("jarvis2/live-key\n{store}\n{key}")
}

/// what the router takes (router/storedocs.go keyWriteIn), sealed and signed here
#[allow(clippy::too_many_arguments)] // the router's fields, one each
pub fn key_write_request(
    store_key: &str,
    master: &str,
    signer: &jarvis_sig::Signer,
    store: &str,
    key: &str,
    value: &[u8],
    del: bool,
    explanation: &str,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    let mut req = serde_json::Map::new();
    req.insert("delete".into(), del.into());
    req.insert("explanation".into(), explanation.into());
    let (mut e, mut data, mut backup_sha) = (String::new(), String::new(), String::new());
    if !del {
        let mut dk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut dk);
        let (ee, wrapped) = seal_parts(store_key, &dk, "jarvis2/store-data-key", b"")
            .map_err(|e| anyhow!("the store key: {e:#}"))?;
        e = ee;
        let aad = format!("{store}\n{key}");
        data = b64(&gcm_seal(&dk, value, aad.as_bytes())?);
        let (be, bd) = seal_parts(master, value, "jarvis2/backup", aad.as_bytes())
            .map_err(|e| anyhow!("the master key: {e:#}"))?;
        backup_sha = sha256_hex(format!("{be}\n{bd}").as_bytes());
        req.insert(
            "wrapped".into(),
            serde_json::json!({"e": e, "wrapped": wrapped}),
        );
        req.insert("data".into(), data.clone().into());
        req.insert("backup".into(), serde_json::json!({"e": be, "data": bd}));
        req.insert("backupSha256".into(), backup_sha.clone().into());
    }
    req.insert(
        "sig".into(),
        signer
            .sign(writer_text(store, key, &e, &data, &backup_sha).as_bytes())
            .into(),
    );
    Ok(req)
}

/// jarvis put-key STORE KEY [--explain TEXT] (value on stdin) | jarvis delete-key STORE KEY
pub fn put_key_cmd(args: &[String], del: bool) -> Result<()> {
    let usage = "usage: jarvis put-key STORE KEY [--explain TEXT] < value   |   jarvis delete-key STORE KEY";
    let mut explain = String::new();
    let mut rest = vec![];
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--explain" && i + 1 < args.len() && !del {
            explain = args[i + 1].clone();
            i += 1;
        } else if args[i].starts_with('-') {
            bail!("{usage}");
        } else {
            rest.push(args[i].clone());
        }
        i += 1;
    }
    if rest.len() != 2 {
        bail!("{usage}");
    }
    let (store, key) = (&rest[0], &rest[1]);
    if !ENV_NAME_RE.is_match(key) {
        bail!(
            "key {}: letters, digits and _, not starting with a digit",
            util::go_quote(key)
        );
    }
    let mut value = vec![];
    if !del {
        std::io::stdin()
            .take((1 << 20) + 1)
            .read_to_end(&mut value)?;
        if value.len() > 1 << 20 {
            bail!("a value is at most 1 MiB");
        }
        if value.last() == Some(&b'\n') {
            value.pop(); // `echo x |` adds one
        }
        if value.is_empty() {
            bail!("no value on stdin (an empty key is a delete: jarvis delete-key)");
        }
    }
    let (core_key, secrets_agreement) = write_trust()?;
    let c = Client::new()?;
    let (store_key, master) = seal_targets(&c, &core_key, &secrets_agreement)?;
    let k = load_private()?;
    let mut req = key_write_request(
        &store_key, &master, &k.sig, store, key, &value, del, &explain,
    )?;
    if !secrets_agreement.is_empty() && !del {
        // the live copy: an open unlock of the store gets the new value at once
        let (e, data) = seal_parts(&secrets_agreement, &value, &live_info(store, key), b"")
            .map_err(|e| anyhow!("secrets' key: {e:#}"))?;
        req.insert("live".into(), serde_json::json!({"e": e, "data": data}));
    }
    let _: serde_json::Value =
        c.json("POST", &format!("/m/stores/{store}/keys/{key}"), Some(&req))?;
    let verb = if del { "deleted" } else { "written" };
    eprintln!(
        "{key} {verb} in {store} (backed up first). Sessions holding {store} get it at their next pull with a new cert (an add-store, a resume); no request goes to Deyao."
    );
    Ok(())
}

/// the router's refresh-secrets (an unlock for this machine's cert went through): the supervisor pulls again with the
/// newest cert into its RAM copy (secrets.rs), under the same lock as every other pull
pub fn refresh_from_router(c: &Client) {
    match crate::secrets::HELD.reload(c, false, false) {
        Err(e) => logf!("refresh-secrets: {e:#}"),
        Ok(n) => {
            logf!("refresh-secrets: the supervisor holds the stores as they are now ({n} keys)")
        }
    }
}
