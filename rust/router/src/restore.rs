//! Restoring a destroyed session (Jarvis 1 POST /api/records/:id/restore). The destroy burnt the old line, so a restore
//! is a NEW line from null — the phone approves it like any new session — whose first machine restores the archived
//! snapshot.
//!
//! What the machine trusts (rust/machine/src/restore.rs): the core's succession challenge has no room for "restore
//! from" (core Options carry only the harness, and the core is off-limits), so the router passes the old line's signer
//! cert in the machine's env (JARVIS2_RESTORE_CERT) and serves the archived snapshot at /m/restore-snapshot. The
//! machine accepts it only on a line's FIRST machine (a cert with no predecessor), checks the old cert against the core
//! key (a core-signed succession cert, another machine), the snapshot against that cert's machine signing key, and
//! refuses a snapshot from a line that held a sensitive store into a line that holds none.
//!
//! The risk this leaves (docs/PARITY.md): the restore choice is not signed by the phone. A malicious router can make a
//! new line, which Deyao approved as "restore X", restore some other old snapshot of Deyao's (signed by one of his own
//! machines), or none. It can't forge a snapshot or bring one from outside Deyao's own lines; and the router holds
//! every snapshot in plaintext anyway, so the mix-up moves no data to anyone who didn't already have it
//! (confidentiality-neutral), apart from the sensitive-store rule above.

use crate::claimdevice::MasterCert;
use crate::core::Doc;
use crate::http::verify_p256;
use crate::router::Router;
use crate::snapstore::Snap;
use crate::state::Approval;
use crate::types::Session;
use anyhow::{Result, anyhow, bail};
use jarvis_go::GoTime;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// only the new line's first machine
pub fn restore_env(_: &Arc<Router>, s: &Session, env: &mut BTreeMap<String, String>) {
    if let Some(c) = &s.restore_cert
        && s.cert.is_none()
    {
        env.insert("JARVIS2_RESTORE_CERT".into(), jarvis_go::marshal(c));
    }
}

/// the snapshot row (snapstore.rs) holding a restoring session's archived snapshot, until its first boot
pub fn restore_snap(sid: &str) -> String {
    format!("restore-{sid}")
}

fn utc_date(t: GoTime) -> String {
    match t.utc().0 {
        Some(t) => format!("{:04}-{:02}-{:02}", t.year(), t.month() as u8, t.day()),
        None => "0001-01-01".into(),
    }
}

impl Router {
    /// the scratch directory the archive's files are fetched into and checked in (then gone)
    pub fn restores_dir(&self, sid: &str) -> PathBuf {
        Path::new(&self.cfg.data_dir)
            .join("tmp")
            .join(format!("restore-{sid}"))
    }

    /// the record's archived snapshot onto the volume, then a new session with the record's options, waiting for the
    /// phone (approval kind new-session, options.restore names what it restores)
    pub fn restore_record(self: &Arc<Self>, record_id: &str, request_id: &str) -> Result<String> {
        let mut rec = self
            .record(record_id)
            .ok_or_else(|| anyhow!("no such previous session"))?;
        let archive = rec.archive.clone().ok_or_else(|| {
            anyhow!("this session was destroyed without an archive: nothing to restore")
        })?;
        if archive.signer.is_empty() {
            bail!(
                "this archive has no signed snapshot, so it can't be restored: {}",
                archive.no_snapshot
            );
        }
        // an archive marked unverified (its snapshot wasn't named in its kill: an earlier core's machine) is checked
        // like any other below (check_restore_files: its cert by this core or an earlier core the master key claimed,
        // the snapshot by the cert's machine), and again by the restoring machine
        let b = self.box_().ok_or_else(crate::storagebox::no_storage_box)?;
        let h = match self.policy.harnesses.get(&rec.session.harness) {
            Some(h) => h.clone(),
            None => {
                // a harness the policy no longer has: restored on claude, as create_session falls back
                crate::logf!(
                    "restore {record_id}: no harness {} in the policy; restoring on claude",
                    rec.session.harness
                );
                rec.session.harness = "claude".into();
                self.policy
                    .harnesses
                    .get("claude")
                    .cloned()
                    .ok_or_else(|| anyhow!("no harness claude in the policy"))?
            }
        };
        // the record's stores, less the shared login's old store (its account comes as the account)
        let kept: Vec<String> = rec
            .session
            .stores
            .iter()
            .flatten()
            .filter(|n| n.as_str() != crate::claudeaccounts::LEGACY_CLAUDE_STORE)
            .cloned()
            .collect();
        let stores = self.with_harness_stores(&kept, &h.stores)?;
        let mut named = rec.session.claude_account.clone(); // the account it ran on, while it exists; else the default
        if self.accounts().hub(&named).is_none() {
            named.clear();
        }
        let account = self.accounts().resolve(&named, h.claude_account)?;
        let sid = format!("s{}", crate::util::rand_id());
        let dir = self.restores_dir(&sid);
        crate::util::mkdir_all_0700(&dir)?;
        let _rm = crate::flows::scopeguard({
            let dir = dir.clone();
            move || {
                let _ = std::fs::remove_dir_all(&dir); // the snapshot goes into the bucket (below); nothing stays on disk
            }
        });
        let fail = |e: anyhow::Error| -> Result<String> {
            self.snap_drop(&restore_snap(&sid));
            Err(e)
        };
        // streamed out of the archive (archivetar.rs); core-cert.json: the master key's claim of the core that signed
        // the cert, through which an archive from an earlier core restores (core continuity); absent when the router had
        // none
        let found = match crate::archivetar::extract_archive(
            &b,
            &archive.file,
            &dir,
            &[
                "jarvis2/snapshot.tar.gz",
                "jarvis2/snapshot.sig",
                "jarvis2/cert.json",
                "jarvis2/core-cert.json",
            ],
        ) {
            Ok(f) => f,
            Err(e) => return fail(e),
        };
        for f in ["snapshot.tar.gz", "snapshot.sig", "cert.json"] {
            if !found.contains(&format!("jarvis2/{f}")) {
                return fail(anyhow!("the archive has no jarvis2/{f}"));
            }
        }
        let cert = match self.check_restore_files(&dir) {
            Ok(c) => c,
            Err(e) => return fail(e),
        };
        if let Err(e) = self.put_restore_snapshot(&sid, &dir) {
            return fail(e);
        }
        let core_cert = std::fs::read(dir.join("core-cert.json"))
            .ok()
            .and_then(|b| jarvis_go::unmarshal::<MasterCert>(&b).ok())
            .filter(|mc| !mc.statement.is_empty());
        let label = if rec.session.label.is_empty() {
            archive.title.clone()
        } else {
            rec.session.label.clone()
        };
        let s = Session {
            id: sid.clone(),
            state: "approval".into(),
            created: GoTime::now().utc(),
            label: label.clone(),
            model: rec.session.model.clone(),
            permission_mode: "bypass".into(), // the only start mode, whatever the destroyed session ran in
            size: rec.session.size.clone(),
            harness: rec.session.harness.clone(),
            stores: Some(stores),
            claude_account: account,
            repos: rec.session.repos.clone(),
            request_id: request_id.into(),
            restore_from: record_id.into(),
            restore_cert: Some(cert),
            restore_core_cert: core_cert,
            ..Default::default()
        };
        self.st.do_(|d| {
            d.sessions.insert(sid.clone(), s.clone());
        });
        let unadd = |e: anyhow::Error| -> Result<String> {
            self.st.do_(|d| {
                d.sessions.remove(&sid);
            });
            fail(e)
        };
        // vouch.rs: names the snapshot this line restores (machine + sha256)
        let config = match self.session_config(&s) {
            Ok(c) => c,
            Err(e) => return unadd(e),
        };
        let what = if label.is_empty() {
            record_id.to_string()
        } else {
            label.clone()
        };
        let options = BTreeMap::from([
            ("model".to_string(), s.model.clone()),
            ("size".to_string(), s.size.clone()),
            ("permissionMode".to_string(), s.permission_mode.clone()),
            ("repos".to_string(), s.repos.clone()),
            (
                "restore".to_string(),
                format!("{what} (destroyed {})", utc_date(rec.destroyed_at)),
            ),
        ]);
        if self.kernel_serves() {
            // kernelline.rs: the restore on the kernel; the phone signs the snapshot's hash into the source
            let res = match self.snap(&restore_snap(&sid)) {
                None => Err(anyhow!("the restore's snapshot is gone")),
                Some(sn) => self.kernel_new_session_approval(
                    &s,
                    &config,
                    &options,
                    &Default::default(),
                    &sn.sha256,
                ),
            };
            if let Err(e) = res {
                return unadd(e);
            }
            return Ok(sid);
        }
        let ch = match self.succession(
            None,
            "",
            s.stores.as_deref().unwrap_or_default(),
            &s.harness,
            &s.permission_mode,
            &self.cfg.session_image,
            &config,
            "",
        ) {
            Ok(ch) => ch,
            Err(e) => return unadd(e),
        };
        self.add_approval(Approval {
            kind: "new-session".into(),
            session: sid.clone(),
            label: s.label.clone(),
            challenge: Some(ch),
            options,
            ..Default::default()
        });
        Ok(sid)
    }

    /// the router's own early check (the machine checks again, and only its check counts): the cert is the core's and
    /// the snapshot is signed by the cert's machine
    pub fn check_restore_files(&self, dir: &Path) -> Result<Doc> {
        let b = std::fs::read(dir.join("cert.json"))?;
        let cert = jarvis_go::unmarshal::<Doc>(&b)
            .ok()
            .filter(|c| !c.payload.is_empty())
            .ok_or_else(|| anyhow!("the archive's cert.json isn't a signed document"))?;
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct M {
            #[serde(rename = "signingKey")]
            signing_key: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct C {
            kind: String,
            machine: Option<M>,
        }
        let c: Option<C> = cert.decode().ok();
        let machine_key = match c {
            // a kernel line's: the spawner's cert
            Some(C {
                kind,
                machine: Some(m),
            }) if kind == "succession" => m.signing_key,
            Some(C {
                kind,
                machine: Some(m),
            }) if kind == "succession-cert" => {
                if let Ok(key) = self.core.key()
                    && let Some(k) = key.get("signingKey").filter(|k| !k.is_empty())
                    && !verify_p256(k, cert.payload.as_bytes(), &cert.sig)
                    && !self.earlier_core_signed(dir, &cert)
                {
                    bail!(
                        "the archive's cert isn't signed by this core, nor by an earlier core the master key claimed"
                    );
                }
                m.signing_key
            }
            _ => bail!("the archive's cert.json isn't a succession cert"),
        };
        let sig = std::fs::read_to_string(dir.join("snapshot.sig"))?;
        let sum = crate::archive::sha256hex(&dir.join("snapshot.tar.gz"))?;
        if !verify_p256(&machine_key, sum.as_bytes(), sig.trim()) {
            bail!("the archived snapshot isn't signed by the machine its cert names");
        }
        Ok(cert)
    }

    /// the sha256 of the archived snapshot a restoring session still holds ("" = none, or not restoring)
    pub fn restore_sum(&self, sid: &str) -> String {
        let restoring = self.st.do_(|d| {
            d.sessions
                .get(sid)
                .is_some_and(|s| s.restore_cert.is_some())
        });
        if !restoring {
            return String::new();
        }
        match self.snap(&restore_snap(sid)) {
            Some(s) if s.state == "committed" => s.sha256,
            _ => String::new(),
        }
    }

    /// the restore snapshot a machine may fetch — only the first machine of a restoring session (a kernel line: its
    /// running machine while no machine of the line has left a snapshot, kernelline.rs kernel_pred)
    pub fn restore_files_for(&self, machine: &str) -> Option<Snap> {
        let sid = self.st.do_(|d| {
            let s = d
                .machines
                .get(machine)
                .and_then(|sid| d.sessions.get(sid))?;
            if s.restore_cert.is_none()
                || s.machine_id != machine
                || !crate::grants::cert_field(d.certs.get(machine), "predecessorId").is_empty()
            {
                return None;
            }
            Some(s.id.clone())
        })?;
        self.snap(&restore_snap(&sid))
    }

    /// the checked archive's snapshot (dir) into the bucket, as the restoring session's row
    pub fn put_restore_snapshot(&self, sid: &str, dir: &Path) -> Result<()> {
        let sig = std::fs::read_to_string(dir.join("snapshot.sig"))?;
        let mut f = std::fs::File::open(dir.join("snapshot.tar.gz"))?;
        self.snap_put_whole(&restore_snap(sid), &mut f, sig.trim())
    }

    /// once a restoring session is past its first boot (or gone), its restore files go; a session that came up is
    /// noted on the record it was restored from. A kernel line keeps them until a machine of it has booted, whatever
    /// its state: one that never got past boot is killed with no snapshot, and the next start restores the archive
    /// again (kernelline.rs never_booted_state_kept).
    pub fn tidy_restores(&self) {
        for m in self.snaps_like("restore-") {
            let sid = m.trim_start_matches("restore-").to_string();
            let (state, from, kernel, booted) = self.st.do_(|d| {
                d.sessions
                    .get(&sid)
                    .map(|s| {
                        (
                            s.state.clone(),
                            s.restore_from.clone(),
                            s.kernel.is_some(),
                            !s.booted.is_empty(),
                        )
                    })
                    .unwrap_or_default()
            });
            if matches!(state.as_str(), "approval" | "starting" | "initialising")
                || (kernel && !booted)
            {
                continue;
            }
            if state == "started" || (kernel && booted) {
                self.mark_restored(&from, &sid);
            }
            self.snap_drop(&m);
        }
    }

    pub fn mark_restored(&self, record_id: &str, sid: &str) {
        if record_id.is_empty() {
            return;
        }
        let now = GoTime::now().utc();
        self.st.do_(|d| {
            for x in d.records.iter_mut().filter(|x| x.session.id == record_id) {
                x.restored.push(crate::archive::RestoreMark {
                    session: sid.into(),
                    at: now,
                });
            }
        });
        if let Some(b) = self.box_()
            && let Err(e) = crate::archive::update_index(&b, |mut list| {
                for e in list
                    .iter_mut()
                    .filter(|e| e.get("id") == Some(&json!(record_id)))
                {
                    let mut prev = e
                        .get("restored")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    prev.push(json!({"sessionId": sid, "at": now}));
                    e.insert("restored".into(), Value::Array(prev));
                }
                list
            })
        {
            crate::logf!("record {record_id}: restored by {sid}, not noted in the index: {e:#}");
        }
    }

    /// the archive's core-cert.json is the master key's claim (the running core's master) of a core whose key signed
    /// the cert — the router's early check of what rust/machine/src/restore.rs checks again (core continuity)
    pub fn earlier_core_signed(&self, dir: &Path, cert: &Doc) -> bool {
        let Some(mc) = std::fs::read(dir.join("core-cert.json"))
            .ok()
            .and_then(|b| jarvis_go::unmarshal::<MasterCert>(&b).ok())
        else {
            return false;
        };
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Cs {
            master: String,
        }
        let Some(cs) = self.core_state_doc().and_then(|st| st.decode::<Cs>().ok()) else {
            return false;
        };
        if cs.master.is_empty() || !verify_p256(&cs.master, mc.statement.as_bytes(), &mc.master_sig)
        {
            return false;
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Key {
            #[serde(alias = "SigningKey", alias = "signingkey")]
            #[serde(rename = "signingKey")]
            signing_key: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Claim {
            kind: String,
            master: String,
            core: Key,
            identity: Option<Key>,
        }
        let Ok(claim) = jarvis_go::unmarshal::<Claim>(mc.statement.as_bytes()) else {
            return false;
        };
        if claim.kind != "claim" || claim.master != cs.master {
            return false;
        }
        if verify_p256(&claim.core.signing_key, cert.payload.as_bytes(), &cert.sig) {
            return true;
        }
        claim
            .identity
            .is_some_and(|i| verify_p256(&i.signing_key, cert.payload.as_bytes(), &cert.sig))
    }

    /// the running core's signed state (its master key), as /identity answers it
    pub fn core_state_doc(&self) -> Option<Doc> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Id {
            state: Option<Doc>,
        }
        match self.core.raw("GET", "/identity", None) {
            Ok((200, b)) => jarvis_go::unmarshal::<Id>(&b).ok()?.state,
            _ => None,
        }
    }
}
