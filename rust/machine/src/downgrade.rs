//! `jarvis-machine downgrade`: keep only the named stores, in place (main.go's downgrade, kernelboot.go's
//! downgradeKernel). The mode is always spelled out (Deyao, 2026-10-15): sessions twice passed the stores they meant
//! to keep to a command that dropped what it was given (and the other way round), so bare names are refused and every
//! name must be held.

use crate::boot::{cert_stores, go_list, with_secrets_lock};
use crate::cert::{Cert, Machine};
use crate::client::Client;
use crate::crypto::{Keys, SignedDoc, read_trim, verify_doc};
use crate::secrets::{SecretsReq, ask_secrets};
use crate::{gojson, logf, paths, util};
use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DowngradeSpec {
    /// keep | drop | none
    pub mode: String,
    pub names: Vec<String>,
}

const USAGE: &str = "downgrade --keep STORE… (keep only these) | --drop STORE… (drop these, keep the rest) | --none (drop all)";

pub fn downgrade_args(args: &[String]) -> Result<DowngradeSpec> {
    let Some(first) = args.first() else {
        bail!("say what to do: {USAGE}")
    };
    let mode = match first.as_str() {
        "--keep" => "keep",
        "--drop" => "drop",
        "--none" => {
            if args.len() != 1 {
                bail!("--none takes no store names: {USAGE}");
            }
            return Ok(DowngradeSpec {
                mode: "none".into(),
                names: vec![],
            });
        }
        a => bail!("{a}: name the mode first: {USAGE}"),
    };
    let mut sp = DowngradeSpec {
        mode: mode.into(),
        names: vec![],
    };
    for a in &args[1..] {
        if a.starts_with('-') {
            bail!("{a}: one mode only, then store names: {USAGE}");
        }
        if !sp.names.contains(a) {
            sp.names.push(a.clone());
        }
    }
    if sp.names.is_empty() {
        bail!("--{} needs store names: {USAGE}", sp.mode);
    }
    Ok(sp)
}

/// --drop named only stores this session doesn't hold: what was asked already holds
#[derive(Debug, thiserror::Error)]
#[error("nothing to drop")]
pub struct NothingToDrop;

impl DowngradeSpec {
    /// The stores to keep, from what this session holds now. --keep must name held stores (a typo would drop the real
    /// ones); --drop of a store not held is no refusal (noted on stderr), but a --drop that would leave nothing is
    /// refused: that is --none.
    pub fn keep_for(&self, held: &[String]) -> Result<Vec<String>> {
        if self.mode == "none" {
            return Ok(vec![]);
        }
        let mut gone = vec![];
        for n in &self.names {
            if !held.contains(n) {
                if self.mode == "keep" {
                    bail!(
                        "{n} isn't held by this session (held: {}); nothing changed. --keep names only held stores",
                        held.join(" ")
                    );
                }
                gone.push(n.clone());
            }
        }
        if !gone.is_empty() {
            eprintln!("not held by this session already: {}", gone.join(" "));
            if gone.len() == self.names.len() {
                return Err(NothingToDrop.into());
            }
        }
        if self.mode == "keep" {
            return Ok(self.names.clone());
        }
        let keep: Vec<String> = held
            .iter()
            .filter(|h| !self.names.contains(h))
            .cloned()
            .collect();
        if keep.is_empty() {
            bail!("--drop names every store this session holds; to drop them all, say --none");
        }
        Ok(keep)
    }
}

/// Keep only the named stores, in place. A new key pair; the core's challenge signed with the old key; the new cert
/// checked; only then the old keys and the secrets of the dropped stores are shredded. Under the secrets lock; an
/// add-store answered between the challenge and its answer makes the challenge stale (the core takes only the newest
/// cert), and the downgrade starts again from the new cert, with a new key pair.
pub fn downgrade(sp: &DowngradeSpec) -> Result<()> {
    if crate::kernelboot::read_kernel_trust().is_some() {
        return downgrade_kernel(sp);
    }
    with_secrets_lock(|| {
        let mut last = Ok(());
        for _ in 0..3 {
            last = downgrade_once(sp);
            match &last {
                Err(e) if format!("{e:#}").contains("newest") => {
                    logf!("downgrade: the cert changed meanwhile ({e:#}); again from the newest")
                }
                _ => return last,
            }
        }
        last
    })
}

fn downgrade_once(sp: &DowngradeSpec) -> Result<()> {
    let core_key = read_trim(&paths::core_key_path())?;
    let c = Client::new()?;
    let Some(held) = cert_stores(&c, &core_key, &c.me) else {
        bail!(
            "couldn't read this session's cert, so the stores it holds aren't known; nothing changed"
        );
    };
    let mut keep = match sp.keep_for(&held) {
        Err(e) if e.downcast_ref::<NothingToDrop>().is_some() => {
            eprintln!("nothing changed: this session holds {}", held.join(" "));
            return Ok(());
        }
        r => r?,
    };
    let k = Keys::generate();
    let (enc_pub, sig_pub) = (k.enc.public_key(), k.sig.public_key());
    keep.sort();
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Begin {
        challenge: Option<SignedDoc>,
    }
    let begin: Begin = c.json(
        "POST",
        "/m/downgrade",
        Some(&serde_json::json!({"stores": keep, "newEncryptionKey": enc_pub, "newSigningKey": sig_pub})),
    )?;
    let ch = begin.challenge.ok_or_else(|| anyhow!("the challenge isn't a core-signed downgrade of this machine to the new keys (bad signature)"))?;
    check_downgrade_challenge(&core_key, Some(&ch), &c.me, &enc_pub, &sig_pub, &keep)?;
    let old = crate::crypto::load_private()?;
    let signature = old.sig.sign(ch.payload.as_bytes());
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Fin {
        cert: Option<SignedDoc>,
    }
    let fin: Fin = c.json(
        "POST",
        "/m/downgrade/finish",
        Some(&serde_json::json!({"challenge": ch, "signature": signature})),
    )?;
    let cert = check_downgrade_cert(
        &core_key,
        fin.cert.as_ref(),
        &c.me,
        &enc_pub,
        &sig_pub,
        &keep,
    )?;
    // the new cert is in hand: switch to the new keys, shred the old ones, re-pull the remaining secrets
    shred_write(&paths::priv_path(), k.private_json().as_bytes(), 0o600)?;
    crate::deliver::add_line_key(&sig_pub); // what this machine asks for from now on is signed with the new key
    let _ = util::write_file(&paths::keys_path(), k.public_json().as_bytes(), 0o644);
    let _ = util::write_file(
        &paths::cert_path(),
        gojson::marshal(&fin.cert).as_bytes(),
        0o644,
    );
    // the supervisor's RAM copy, at once
    let n = ask_secrets(
        &SecretsReq {
            op: "reload".into(),
            drop: true,
            held: true,
            ..Default::default()
        },
        Duration::from_secs(20 * 60),
    )
    .map(|r| r.n)
    .unwrap_or(0); // locked or empty: nothing kept
    eprintln!(
        "downgraded to {}: old keys shredded, the supervisor holds {n} keys. Values already loaded in running processes stay there until they exit.",
        go_list(&cert.stores())
    );
    Ok(())
}

/// what the old key signs is a core-signed downgrade of this machine to its new keys, keeping exactly the stores asked
/// for (the router chooses the challenge's list: R1 audit)
pub fn check_downgrade_challenge(
    core_key: &str,
    d: Option<&SignedDoc>,
    me: &str,
    enc_pub: &str,
    sig_pub: &str,
    keep: &[String],
) -> Result<()> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Req {
        downgrade: bool,
        machine: Option<Machine>,
        stores: Vec<String>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Ch {
        kind: String,
        request: Req,
    }
    let ch: Ch = match verify_doc::<Ch>(core_key, d) {
        Ok(ch)
            if ch.kind == "challenge"
                && ch.request.downgrade
                && ch.request.machine.as_ref().is_some_and(|m| {
                    m.id == me && m.signing_key == sig_pub && m.encryption_key == enc_pub
                }) =>
        {
            ch
        }
        r => bail!(
            "the challenge isn't a core-signed downgrade of this machine to the new keys ({})",
            r.err()
                .map(|e| format!("{e:#}"))
                .unwrap_or_else(|| "<nil>".into())
        ),
    };
    if !same_stores(&ch.request.stores, keep) {
        bail!(
            "the challenge keeps {}, not the {} asked for: not signed",
            go_list(&ch.request.stores),
            go_list(keep)
        );
    }
    Ok(())
}

/// the new cert names this machine, its new keys and exactly the kept stores
pub fn check_downgrade_cert(
    core_key: &str,
    d: Option<&SignedDoc>,
    me: &str,
    enc_pub: &str,
    sig_pub: &str,
    keep: &[String],
) -> Result<Cert> {
    let cert: Cert = match verify_doc::<Cert>(core_key, d) {
        Ok(c)
            if c.kind == "succession-cert"
                && c.machine.as_ref().is_some_and(|m| {
                    m.id == me && m.signing_key == sig_pub && m.encryption_key == enc_pub
                }) =>
        {
            c
        }
        r => bail!(
            "the new cert isn't core-signed for the new keys ({})",
            r.err()
                .map(|e| format!("{e:#}"))
                .unwrap_or_else(|| "<nil>".into())
        ),
    };
    if !same_stores(&cert.stores(), keep) {
        bail!(
            "the new cert names {}, not the {} asked for",
            go_list(&cert.stores()),
            go_list(keep)
        );
    }
    Ok(cert)
}

/// overwrite the file's old bytes before replacing its contents
pub fn shred_write(path: &std::path::Path, data: &[u8], mode: u32) -> Result<()> {
    if let Ok(md) = std::fs::metadata(path) {
        use rand::RngCore;
        let mut z = vec![0u8; md.len() as usize];
        rand::thread_rng().fill_bytes(&mut z);
        let _ = util::write_file(path, &z, mode);
    }
    util::write_file(path, data, mode)?;
    Ok(())
}

/// the same set of store names
pub fn same_stores(a: &[String], b: &[String]) -> bool {
    let (mut x, mut y) = (a.to_vec(), b.to_vec());
    x.sort();
    y.sort();
    x == y
}

/// `jarvis downgrade` on a kernel machine: the router has the identity signer narrow this machine's grant to the stores
/// kept and the supervisor pulls with the narrower grant, holding only those stores' keys from then on
pub fn downgrade_kernel(sp: &DowngradeSpec) -> Result<()> {
    let b = std::fs::read(paths::cert_path())?;
    let Ok(cert) = gojson::unmarshal::<Cert>(&b) else {
        bail!(
            "couldn't read this session's grant, so the stores it holds aren't known; nothing changed"
        );
    };
    let keep = match sp.keep_for(&cert.stores()) {
        Err(e) if e.downcast_ref::<NothingToDrop>().is_some() => {
            eprintln!(
                "nothing changed: this session holds {}",
                cert.stores().join(" ")
            );
            return Ok(());
        }
        r => r?,
    };
    let c = Client::new()?;
    c.json_ok(
        "POST",
        "/m/kernel/downgrade",
        Some(&serde_json::json!({"keep": keep})),
    )?;
    let n = ask_secrets(
        &SecretsReq {
            op: "reload".into(),
            drop: true,
            ..Default::default()
        },
        Duration::from_secs(20 * 60),
    )
    .map(|r| r.n)
    .unwrap_or(0);
    eprintln!(
        "downgraded to {}: the supervisor holds {n} keys. Values already loaded in running processes stay there until they exit.",
        go_list(&keep)
    );
    Ok(())
}
