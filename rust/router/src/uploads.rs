//! First-prompt attachments (Jarvis 1's /api/uploads + session-attachments). The New Session form uploads each picked
//! file here BEFORE creating the session (x-upload-id groups a form's files, x-upload-name names one); they are kept as
//! the router's objects (uploads/<uploadId>/<name>), not on the Storage Box, so no machine needs Storage Box creds.
//! POST /api/sessions {attachments: {uploadId, files: [{name, isImage}]}} binds the upload to that one session; only
//! that session's machines can fetch it (machine-signed GET /m/attachments, /m/attachments/{name}), and its machine
//! drops it once fetched (DELETE /m/attachments). Each file's sha256 and size go into the new line's signed config
//! (vouch.rs session_config), so the phone signs them; the listing carries the core's attestation of each (input
//! "attachment", origin "cert"), so each is in the input log, and the machine takes a file only with both
//! (rust/machine/src/attachments.rs). The app can read a staged file back (GET /api/sessions/{id}/attachments/{name})
//! to show it on the approval page, checked against the signed hash there. A session proposing a new session stages
//! its files the same way (PUT /m/api/sessions/{id}/uploads/{upload}/{name}): such an upload is owned by that session
//! (Upload.owner), only its own proposals can bind it, and from there it is the same line: signed by hash, attested,
//! fetched by the new session's first machine.

use crate::core::Doc;
use crate::http::Registrar;
use crate::nethttp::{W, write_json};
use crate::router::{Router, bad};
use crate::state::{Persisted, Session};
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

pub const ATTACH_MAX_FILES: usize = 20;
/// per file, as Jarvis 1 (the tunnel's request cap)
pub const ATTACH_MAX_BYTES: usize = 25 << 20;
pub const UPLOAD_TTL: time::Duration = time::Duration::hours(24);
/// unbound uploads a session may hold at once (each becomes one proposal's attachments)
pub const MAX_SESSION_UPLOADS: usize = 5;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Upload {
    pub id: String,
    pub created: GoTime,
    /// bound by POST /api/sessions
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session: String,
    /// the session that staged it (a proposal's attachments); "" = the app
    #[serde(skip_serializing_if = "String::is_empty")]
    pub owner: String,
    pub files: Vec<AttachFile>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AttachFile {
    pub name: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub size: i64,
    #[serde(rename = "isImage")]
    pub is_image: bool,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AttachmentsIn {
    #[serde(rename = "uploadId")]
    pub upload_id: String,
    pub files: Vec<AttachFile>,
}

/// a request answered with its own status (a file over the cap: 413)
#[derive(Debug)]
pub struct HttpStatusErr(pub u16, pub String);

impl std::fmt::Display for HttpStatusErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.1)
    }
}

impl std::error::Error for HttpStatusErr {}

fn re(s: &str) -> regex::Regex {
    regex::Regex::new(s).unwrap_or_else(|_| unreachable!())
}

static UPLOAD_ID_RE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9_-]{1,64}$"));
static CTRL_RE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"[\x00-\x1f]"));
/// Go's \s: ASCII whitespace only
static SPACE_RE: LazyLock<regex::Regex> = LazyLock::new(|| re(r"[\t\n\x0C\r ]+"));

/// Jarvis 1's lib/uploads.js safeName (a basename, no control characters, whitespace → "_", ≤ 200 bytes; a space would
/// split a pasted path in the TUI). "." and ".." become "file".
pub fn safe_name(raw: &str) -> String {
    let raw = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let s = SPACE_RE.replace_all(&CTRL_RE.replace_all(raw, ""), "_").trim().to_string();
    let s = jarvis_go::fmt::clip_bytes(&s, 200).to_string();
    if s.is_empty() || s == "." || s == ".." {
        return "file".into();
    }
    s
}

/// the extensions Claude Code's TUI attaches inline
pub fn is_image_name(n: &str) -> bool {
    let ext = n.rsplit_once('.').map(|(_, e)| e.to_lowercase()).unwrap_or_default();
    matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "gif" | "webp") && n.contains('.')
}

/// an upload's files are objects uploads/<id>/<name> (objstore.rs)
pub fn upload_key(id: &str, name: &str) -> String {
    format!("uploads/{id}/{name}")
}

fn has_file(u: &Upload, name: &str) -> bool {
    u.files.iter().any(|f| f.name == name)
}

/// under the state lock (admit_session). The files named must be in the upload; the upload must be the caller's own
/// (owner: the proposing session, "" = the app) and not belong to another live session. is_image is the router's own
/// reading of the name.
pub fn bind_upload(d: &mut Persisted, sid: &str, owner: &str, input: &AttachmentsIn) -> Result<Vec<AttachFile>> {
    let (files, uid) = check_upload(d, sid, owner, input)?;
    if let Some(u) = d.uploads.get_mut(&uid) {
        u.session = sid.into();
    }
    Ok(files)
}

/// bind_upload's checks without binding (sid "" = not yet made: check_proposal, before a batch is filed) → the files
/// and the upload's id
pub fn check_upload(d: &Persisted, sid: &str, owner: &str, input: &AttachmentsIn) -> Result<(Vec<AttachFile>, String)> {
    if !UPLOAD_ID_RE.is_match(&input.upload_id) {
        return Err(bad("attachments: missing uploadId"));
    }
    if input.files.len() > ATTACH_MAX_FILES {
        return Err(bad(format!("too many attachments (max {ATTACH_MAX_FILES})")));
    }
    let u = d
        .uploads
        .get(&input.upload_id)
        .filter(|u| u.owner == owner)
        .ok_or_else(|| bad(format!("attachments: no upload {}", input.upload_id)))?;
    if !u.session.is_empty() && u.session != sid && d.sessions.contains_key(&u.session) {
        return Err(bad("attachments: the upload belongs to another session"));
    }
    let mut out = vec![];
    let mut seen = BTreeSet::new();
    for f in &input.files {
        let n = safe_name(&f.name);
        if !seen.insert(n.clone()) {
            continue;
        }
        let found: Vec<&AttachFile> = u.files.iter().filter(|x| x.name == n).collect();
        if found.is_empty() {
            return Err(bad(format!("attachments: {n} wasn't uploaded")));
        }
        out.extend(found.into_iter().cloned());
    }
    if out.is_empty() {
        return Err(bad("attachments: no files named"));
    }
    Ok((out, u.id.clone()))
}

/// the first machine only (no cert yet). session-attachments (Jarvis 1) reads the names from SESSION_ATTACHMENTS_JSON;
/// the machine fills in where they are (rust/machine/src/attachments.rs).
pub fn attach_env(s: &Session, e: &mut BTreeMap<String, String>) {
    let Some(ops) = &s.ops else { return };
    if s.cert.is_some() || ops.attach.is_empty() {
        return;
    }
    let parts: Vec<String> = ops
        .attach
        .iter()
        .map(|f| format!(r#"{{"name":{},"isImage":{}}}"#, jarvis_go::fmt::go_quote(&f.name), f.is_image))
        .collect();
    e.insert("SESSION_ATTACHMENTS_JSON".into(), format!("[{}]", parts.join(",")));
}

impl Router {
    /// one file of a form's upload. owner: the session staging it ("" = the app); an upload takes files from its owner
    /// only.
    pub fn stage_upload(&self, upload_id: &str, owner: &str, raw_name: &str, body: &mut dyn Read) -> Result<AttachFile> {
        if !UPLOAD_ID_RE.is_match(upload_id) {
            return Err(bad("missing or bad x-upload-id"));
        }
        let name = safe_name(raw_name);
        let _g = self.ops.upload_mu.lock().unwrap_or_else(|e| e.into_inner());
        self.st.do_(|d| -> Result<()> {
            match d.uploads.get(upload_id) {
                None if !owner.is_empty() => {
                    let n = d.uploads.values().filter(|x| x.owner == owner && x.session.is_empty()).count();
                    if n >= MAX_SESSION_UPLOADS {
                        return Err(bad(format!(
                            "this session already holds {n} uploads no proposal uses yet: attach them to a proposal (or wait 24 h for them to go) before starting another"
                        )));
                    }
                }
                None => {}
                Some(u) if u.owner != owner => return Err(bad("this upload id is taken: pick another")),
                Some(u) if !u.session.is_empty() && d.sessions.contains_key(&u.session) => {
                    return Err(bad(
                        "this upload belongs to a session already: its files are fixed in that session's signed hashes, so start a new upload (a new upload id) for these files",
                    ));
                }
                Some(u) if u.files.len() >= ATTACH_MAX_FILES && !has_file(u, &name) => {
                    return Err(bad(format!("too many attachments (max {ATTACH_MAX_FILES})")));
                }
                Some(_) => {}
            }
            Ok(())
        })?;
        // read whole (at most ATTACH_MAX_BYTES) before it is stored: a file over the cap never becomes an object
        let mut b = vec![];
        body.take(ATTACH_MAX_BYTES as u64 + 1).read_to_end(&mut b)?;
        if b.len() > ATTACH_MAX_BYTES {
            return Err(HttpStatusErr(413, format!("{name} is larger than {} MB", ATTACH_MAX_BYTES >> 20)).into());
        }
        self.obj_put_bytes(&upload_key(upload_id, &name), &b)?;
        let af = AttachFile { name: name.clone(), size: b.len() as i64, is_image: is_image_name(&name) };
        self.st.do_(|d| {
            let u = d.uploads.entry(upload_id.to_string()).or_insert_with(|| Upload {
                id: upload_id.into(),
                created: GoTime::now(),
                owner: owner.into(),
                ..Default::default()
            });
            u.files.retain(|x| x.name != name);
            u.files.push(af.clone());
        });
        Ok(af)
    }

    /// the upload bound to the calling machine's session
    pub fn machine_upload(&self, machine: &str) -> Result<Upload> {
        let sid = self.machine_session(machine)?;
        self.st
            .do_(|d| {
                let s = d.sessions.get(&sid)?;
                let ops = s.ops.as_ref().filter(|o| !o.upload.is_empty())?;
                let x = d.uploads.get(&ops.upload).filter(|x| x.session == sid)?;
                let mut c = x.clone();
                c.files = ops.attach.clone();
                Some(c)
            })
            .ok_or_else(|| anyhow!("no attachments for this session"))
    }

    /// the core's input-log entry for each file as it is stored now (machine, "attachment", origin "cert", its sha256),
    /// kept in the router's copy of the log. The machine checks each against the bytes it gets.
    pub fn attest_attachments(&self, machine: &str, u: &Upload) -> Result<BTreeMap<String, Doc>> {
        let mut out = BTreeMap::new();
        for f in &u.files {
            let (sum, _) = self
                .obj_sha256(&upload_key(&u.id, &f.name))
                .map_err(|e| anyhow!("attachment {}: {e:#}", f.name))?;
            out.insert(f.name.clone(), self.attest_input(machine, "attachment", "cert", &sum)?);
        }
        Ok(out)
    }

    pub fn drop_upload(&self, id: &str) {
        if !UPLOAD_ID_RE.is_match(id) {
            return;
        }
        let _g = self.ops.upload_mu.lock().unwrap_or_else(|e| e.into_inner());
        self.st.do_(|d| {
            d.uploads.remove(id);
        });
        if let Err(e) = self.objects.delete_prefix(&format!("uploads/{id}/")) {
            crate::logf!("[uploads] {id}: {e:#}");
        }
    }

    /// unbound uploads older than a day, uploads whose session is gone, and unbound ones whose owner is gone
    pub fn sweep_uploads(&self, now: GoTime) {
        let drop: Vec<String> = self.st.do_(|d| {
            d.uploads
                .iter()
                .filter(|(_, u)| {
                    let gone = (!u.session.is_empty() && !d.sessions.contains_key(&u.session))
                        || (u.session.is_empty() && !u.owner.is_empty() && !d.sessions.contains_key(&u.owner));
                    gone || (u.session.is_empty() && now.sub(&u.created) > UPLOAD_TTL)
                })
                .map(|(id, _)| id.clone())
                .collect()
        });
        for id in drop {
            self.drop_upload(&id);
        }
    }

    pub fn uploads_loop(self: &Arc<Self>) {
        loop {
            std::thread::sleep(Duration::from_secs(3600));
            crate::leaderlease::await_lead();
            self.sweep_uploads(GoTime::now());
        }
    }

    /// a stored attachment's bytes, served with ranges
    fn serve_attachment(&self, w: &mut W, req: &crate::nethttp::Req, upload: &str, name: &str, no_store: bool) {
        let b = match self.obj_get_bytes(&upload_key(upload, name)) {
            Err(_) => return write_json(w, 404, &json!({"error": "no such attachment"})),
            Ok(b) => b,
        };
        w.set_header("Content-Type", "application/octet-stream");
        if no_store {
            w.set_header("Cache-Control", "no-store");
        }
        crate::util::serve_content(w, req, jarvis_go::GoTime::default(), &b[..], b.len() as i64);
    }
}

pub fn uploads_on_destroy(r: &Arc<Router>, s: &Session) {
    if let Some(up) = s.ops.as_ref().map(|o| o.upload.clone()).filter(|u| !u.is_empty()) {
        r.drop_upload(&up);
    }
}

fn write_upload(w: &mut W, res: Result<AttachFile>) {
    match res {
        Err(e) => match e.downcast_ref::<HttpStatusErr>() {
            Some(he) => write_json(w, he.0, &json!({"error": he.1})),
            None => crate::schedule::schedule_err(w, &e),
        },
        Ok(af) => write_json(w, 200, &af),
    }
}

pub fn register_uploads(reg: &mut Registrar) {
    reg.app("POST /api/uploads", |r, w, req| {
        let mut name = req.header("x-upload-name");
        if let Ok(n) = percent_encoding::percent_decode_str(&name).decode_utf8() {
            name = n.into_owned();
        }
        let id = req.header("x-upload-id");
        let res = r.stage_upload(&id, "", &name, &mut req.body);
        write_upload(w, res);
    });
    // a session stages a file for a new session it will propose (jarvis-request new-session --attach): the raw bytes,
    // the upload id and name in the path (the machine signs the path and the body's hash)
    reg.m("PUT /m/api/sessions/{id}/uploads/{upload}/{name}", |r, w, req, machine, body| {
        let sid = match r.machine_session(machine) {
            Err(e) => return write_json(w, 403, &json!({"error": format!("{e:#}")})),
            Ok(s) => s,
        };
        if req.path_value("id") != sid {
            return write_json(
                w,
                403,
                &json!({"error": format!("this machine is session {sid}, not {}", req.path_value("id"))}),
            );
        }
        let res = r.stage_upload(&req.path_value("upload"), &sid, &req.path_value("name"), &mut std::io::Cursor::new(body));
        write_upload(w, res);
    });
    reg.m("GET /m/attachments", |r, w, _, machine, _| {
        let u = match r.machine_upload(machine) {
            Err(e) => return write_json(w, 404, &json!({"error": format!("{e:#}")})),
            Ok(u) => u,
        };
        match r.attest_attachments(machine, &u) {
            Err(e) => write_json(w, 502, &json!({"error": format!("{e:#}")})),
            Ok(attest) => write_json(w, 200, &json!({"files": u.files, "attest": attest})),
        }
    });
    // the app: a staged file of a session not yet started (the approval page shows it, checked against the signed hash)
    reg.app("GET /api/sessions/{id}/attachments/{name}", |r, w, req| {
        let (sid, name) = (req.path_value("id"), req.path_value("name"));
        let up = r.st.do_(|d| {
            let s = d.sessions.get(&sid)?;
            let ops = s.ops.as_ref().filter(|o| !o.upload.is_empty())?;
            let u = d.uploads.get(&ops.upload).filter(|u| u.session == sid)?;
            ops.attach.iter().any(|f| f.name == name).then(|| u.id.clone())
        });
        let Some(up) = up.filter(|_| safe_name(&name) == name) else {
            return write_json(
                w,
                404,
                &json!({"error": "no such attachment (a started session's attachments are gone from the router)"}),
            );
        };
        r.serve_attachment(w, req, &up, &name, true);
    });
    reg.m("GET /m/attachments/{name}", |r, w, req, machine, _| {
        let name = req.path_value("name");
        let u = match r.machine_upload(machine) {
            Ok(u) if has_file(&u, &name) && safe_name(&name) == name => u,
            _ => return write_json(w, 404, &json!({"error": "no such attachment"})),
        };
        r.serve_attachment(w, req, &u.id, &name, false);
    });
    reg.m("DELETE /m/attachments", |r, w, _, machine, _| {
        let u = match r.machine_upload(machine) {
            Err(e) => return write_json(w, 404, &json!({"error": format!("{e:#}")})),
            Ok(u) => u,
        };
        r.drop_upload(&u.id);
        crate::logf!("session upload {} fetched and dropped", u.id);
        write_json(w, 200, &json!({"ok": true}));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(safe_name("../a b\u{1}.png"), "a_b.png");
        assert_eq!(safe_name(".."), "file");
        assert!(is_image_name("x.JPG"));
        assert!(!is_image_name("png"));
    }
}
