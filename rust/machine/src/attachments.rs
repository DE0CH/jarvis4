//! First-prompt attachments (rust/router/src/uploads.rs). The router stages the files the New Session form uploaded and binds
//! them to this session; the first machine fetches them over the machine-signed /m/attachments before the harness
//! starts, then the router drops them. Jarvis 1's session-attachments script does the rest (copies them into
//! ~/uploads, writes the paths into the first message), reading from a local file:// "box":
//! SESSION_ATTACH_DAV_BASE=file://$HOME, SESSION_ATTACH_DIR=.jarvis-uploads.
//!
//! Each file is taken only when (1) its bytes hash to the sha256 and size the cert names and (2) it carries the core's
//! attestation over (this machine, "attachment", that sha256). A file failing either is refused alone; the first
//! message names the refused ones and why (SESSION_ATTACHMENTS_REFUSED).

use crate::client::Client;
use crate::crypto::{SignedDoc, sha256_hex};
use crate::deliver::check_attest;
use crate::vouch::AttachmentRef;
use crate::{gojson, logf, paths, util};
use anyhow::{Result, anyhow};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

pub const ATTACH_STAGING: &str = ".jarvis-uploads";

/// env for the harness (empty when no file matches the cert)
pub fn fetch_attachments(c: &Client, core_key: &str, refs: &[AttachmentRef]) -> Vec<String> {
    let home = paths::home();
    let staging = home.join(ATTACH_STAGING);
    let (taken, refused) = match download_attachments(c, core_key, &staging, refs) {
        Ok(x) => x,
        Err((e, refused)) => {
            logf!("attachments: {e:#}");
            let _ = std::fs::remove_dir_all(&staging);
            return refused_env(&refused);
        }
    };
    logf!(
        "attachments: {} file(s) fetched, each the one the cert names; {} refused",
        taken.len(),
        refused.len()
    );
    if refused.is_empty() {
        // a refused one stays with the router, for a look by hand
        match c.raw("DELETE", "/m/attachments", b"", &[]) {
            Ok(r) if r.status == 200 => {}
            Ok(r) => logf!("attachments: the router kept its copy (HTTP {})", r.status),
            Err(e) => logf!("attachments: the router kept its copy ({e:#})"),
        }
    }
    if taken.is_empty() {
        let _ = std::fs::remove_dir_all(&staging);
        return refused_env(&refused);
    }
    let list: Vec<String> = taken
        .iter()
        .map(|r| {
            format!(
                r#"{{"name":{},"isImage":{}}}"#,
                gojson::marshal(&r.name),
                is_image_name(&r.name)
            )
        })
        .collect();
    let mut out = attachment_env(&home);
    out.push(format!("SESSION_ATTACHMENTS_JSON=[{}]", list.join(",")));
    out.extend(refused_env(&refused));
    out
}

/// the refused files (names from the cert, reasons from this machine), for the first message
pub fn refused_env(refused: &[String]) -> Vec<String> {
    if refused.is_empty() {
        return vec![];
    }
    vec![format!(
        "SESSION_ATTACHMENTS_REFUSED={}",
        gojson::marshal(refused)
    )]
}

pub fn is_image_name(n: &str) -> bool {
    let ext = Path::new(n)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    matches!(
        ext.as_str(),
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "heic" | "heif"
    )
}

pub fn attachment_env(home: &Path) -> Vec<String> {
    vec![
        format!("SESSION_ATTACH_DAV_BASE=file://{}", home.display()),
        format!("SESSION_ATTACH_DIR={ATTACH_STAGING}"),
        "SESSION_ATTACH_DAV_USER=".into(),
        "SESSION_ATTACH_DAV_PASS=".into(),
    ]
}

type Refused = Vec<String>;

/// the files that check (written into dir) and "name: why" for each that doesn't; an error only when nothing could be
/// fetched at all (the listing, the directory)
pub fn download_attachments(
    c: &Client,
    core_key: &str,
    dir: &Path,
    refs: &[AttachmentRef],
) -> Result<(Vec<AttachmentRef>, Refused), (anyhow::Error, Refused)> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Listing {
        attest: HashMap<String, Option<SignedDoc>>,
    }
    let refuse_all = |why: &str| {
        refs.iter()
            .map(|f| format!("{}: {why}", f.name))
            .collect::<Vec<_>>()
    };
    let list: Listing = c
        .json::<(), Listing>("GET", "/m/attachments", None)
        .map_err(|e| {
            (
                anyhow!("the listing: {e:#}"),
                refuse_all("the router's listing wasn't readable"),
            )
        })?;
    if let Err(e) = std::fs::create_dir_all(dir) {
        return Err((e.into(), refuse_all("no room on this machine")));
    }
    let mut taken = vec![];
    let mut refused = vec![];
    for f in refs {
        if !plain_name(&f.name) {
            refused.push(format!(
                "{}: not a plain file name",
                gojson::marshal(&f.name)
            ));
            continue;
        }
        // the signature covers the decoded path (as the router checks it); the URL carries it escaped
        let r = c.signed_do(
            "GET",
            &format!("/m/attachments/{}", f.name),
            &format!("/m/attachments/{}", util::path_escape(&f.name)),
            "",
            b"",
            "",
        );
        let r = match r {
            Ok(r) if r.status != 200 => Err(anyhow!("HTTP {}", r.status)),
            r => r,
        };
        match r {
            Err(e) => refused.push(format!("{}: not fetched ({e:#})", f.name)),
            Ok(r) if sha256_hex(&r.body) != f.sha256 || r.body.len() as i64 != f.size => refused
                .push(format!(
                    "{}: not the file Deyao approved (its bytes differ)",
                    f.name
                )),
            Ok(r)
                if check_attest(
                    core_key,
                    &c.me,
                    "attachment",
                    &r.body,
                    list.attest.get(&f.name).cloned().flatten().as_ref(),
                )
                .is_err() =>
            {
                refused.push(format!("{}: not in the core's input log", f.name))
            }
            Ok(r) => {
                if let Err(e) = util::write_file(&dir.join(&f.name), &r.body, 0o600) {
                    refused.push(format!("{}: not written ({e})", f.name));
                    continue;
                }
                taken.push(f.clone());
            }
        }
    }
    for r in &refused {
        logf!("attachments: refused {r}");
    }
    Ok((taken, refused))
}

/// one path segment (the router's safeName output)
pub fn plain_name(n: &str) -> bool {
    !n.is_empty() && n != "." && n != ".." && !n.contains(['/', '\\', '\0']) && n.len() <= 200
}
