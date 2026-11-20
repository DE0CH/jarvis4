//! Stores, their keys and what each key is for (Deyao, 2026-10-11: "the names of the keys should be visible through
//! the api"; 2026-10-13: the explanation of each key is surfaced on the web and iPhone portal, and writing one key by
//! name is allowed without overwriting the store).
//!
//! On a box with no core (NO_CORE=1) all of this goes to the kernel's serving secrets (kernel.rs store_core), whose
//! store routes have the core's shapes; a kernel session's machine writes with the grant it holds instead of a cert.
//!
//! Key names and who wrote each key come from the core's signed store list (a store is a set of keys, core/keys.go).
//! What a store and each key are for is the router's own record (store-docs.json, a row of router_docs in its
//! database): not a secret and not part of any trust decision, written by whoever writes a key (a new key name needs
//! its explanation), by the setup session (`POST /setup/store-docs`) and by Deyao in the app. Every key's backup
//! carries its explanation too, so a Recover brings them back.
//!
//! Writing a key (no approval: Deyao, 2026-10-13, "any session with a valid machine key … writing a key is perfectly
//! safe (has backup, so can't overwrite, and also can't read)"): the writer seals the value to the store key P + K and,
//! for the backup, to the master key, and signs both (core.WriterText). The router writes the backup first
//! (keys/<store>/<key>.json in the versioned bucket), then the key into the core, records the explanation, and asks the
//! phone to refresh every running session that holds the store (its copy is behind until a new unlock: the core can't
//! open the new value without the phone).
//!
//!     GET /api/stores, GET /m/stores, GET /setup/stores/keys → {stores: [StoreRow], signed}
//!     GET /m/store-key, GET /setup/store-key → {identity, storeKey}: what a writer seals to (the core's signed
//!         identity, naming the master key, and its signed store key for the claimed phone; on a box with no core only
//!         secrets' identity: each writer computes P + K itself from secrets' signed state and its roster keys)
//!     POST /m/stores/{store}/keys/{key}      a session writes or deletes one key (machine-signed: core.WriterText)
//!     POST /setup/stores/{store}/keys/{key}  the same as the setup session (setup-key signed)
//!     POST /setup/store-docs, PUT /api/stores/{store}/docs {about?, keys: {KEY: text}} → {ok}

use crate::core::{CoreError, Doc};
use crate::http::{Registrar, write_err};
use crate::inbox::{
    ApiCall, BadRequest, Caller, Forbidden, Origin, REQUEST_KIND_UNLOCK, RequestParams,
    write_request_err,
};
use crate::nethttp::{W, write_error, write_json};
use crate::router::Router;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex};

/// who wrote a key, as the core signed it, with the session the router knows that line as
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct KeyWriter {
    pub by: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub machine: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub line: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session: String,
    #[serde(rename = "sessionLabel", skip_serializing_if = "String::is_empty")]
    pub session_label: String,
}

/// one key as listed (never a value)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct KeyRow {
    pub name: String,
    pub explanation: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writer: Option<KeyWriter>,
}

/// one store as listed
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct StoreRow {
    pub name: String,
    pub sensitive: bool,
    pub empty: bool,
    pub unlocked: bool,
    pub about: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// the key names, the shape every session image reads
    pub keys: Vec<String>,
    /// the same keys with what each is for and who wrote it
    #[serde(rename = "keyInfo")]
    pub key_info: Vec<KeyRow>,
    /// core: the names are the core's own signed list
    #[serde(rename = "keysFrom")]
    pub keys_from: String,
}

/// what a store and its keys are for
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct StoreDoc {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub about: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub keys: BTreeMap<String, String>,
}

static KEY_NAME_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$").unwrap_or_else(|_| unreachable!())
});

pub fn key_name_ok(k: &str) -> bool {
    KEY_NAME_RE.is_match(k)
}

/// characters of one explanation
pub const DOC_MAX: usize = 2000;

pub static STORE_DOCS_MU: Mutex<()> = Mutex::new(());

/// an explanation as plain text (clean_explanation's rules, longer)
pub fn clean_doc(s: &str) -> Result<String> {
    let out = crate::inbox::plain_lines(&s.replace('\n', " "))?;
    let n = out.chars().count();
    if n > DOC_MAX {
        return Err(anyhow!(
            "explanation longer than {DOC_MAX} characters ({n})"
        ));
    }
    Ok(out)
}

pub fn store_name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && n.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// one row of the core's signed list
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CoreStoreRow {
    pub name: String,
    pub sensitive: bool,
    pub empty: bool,
    pub unlocked: bool,
    pub version: String,
    pub keys: Vec<CoreStoreKey>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CoreStoreKey {
    pub name: String,
    pub at: String,
    pub writer: Option<KeyWriter>,
}

pub fn cert_line(c: Option<&Doc>) -> String {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct X {
        line: String,
    }
    c.and_then(|c| c.decode::<X>().ok())
        .map(|x| x.line)
        .unwrap_or_default()
}

pub fn cert_nonce(c: Option<&Doc>) -> String {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct X {
        nonce: String,
    }
    c.and_then(|c| c.decode::<X>().ok())
        .map(|x| x.nonce)
        .unwrap_or_default()
}

/// a writer's request (core.WriteKeyInput's sealed parts, the backup and the explanation)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct KeyWriteIn {
    pub delete: bool,
    pub wrapped: Option<Wrapped>,
    pub data: String,
    #[serde(rename = "backupSha256")]
    pub backup_sha256: String,
    pub backup: Option<Sealed>,
    pub sig: String,
    pub explanation: String,
    /// the value sealed to the kernel's secrets (kernel/secrets WriteKeyInput.Live), so an open unlock of the store
    /// stays current; passed on as is (the core has none)
    pub live: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Wrapped {
    pub e: String,
    pub wrapped: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Sealed {
    pub e: String,
    pub data: String,
}

/// what WriterText names for a key's backup — sha256 of its sealed parts
pub fn backup_sha(e: &str, data: &str) -> String {
    hex::encode(Sha256::digest(format!("{e}\n{data}").as_bytes()))
}

pub fn data_sha(data: &str) -> String {
    if data.is_empty() {
        return String::new();
    }
    hex::encode(Sha256::digest(data.as_bytes()))
}

/// a refusal the core gives in its own words (status, message)
pub fn write_write_err(w: &mut W, err: &anyhow::Error) {
    if let Some(ce) = err.downcast_ref::<CoreError>() {
        return write_error(w, ce.status, &ce.msg);
    }
    write_request_err(w, err);
}

impl Router {
    pub fn read_store_docs(&self) -> BTreeMap<String, StoreDoc> {
        self.st
            .read_doc("store-docs.json")
            .and_then(|b| {
                jarvis_go::unmarshal::<Option<BTreeMap<String, StoreDoc>>>(&b)
                    .ok()
                    .flatten()
            })
            .unwrap_or_default()
    }

    fn store_docs(&self) -> BTreeMap<String, StoreDoc> {
        let _g = STORE_DOCS_MU.lock().unwrap_or_else(|e| e.into_inner());
        self.read_store_docs()
    }

    /// a store's about text (None = unchanged) and explanations of its keys ("" removes one)
    pub fn set_store_docs(
        &self,
        store: &str,
        about: Option<&str>,
        keys: &BTreeMap<String, String>,
    ) -> Result<()> {
        if !store_name_ok(store) {
            return Err(anyhow!(
                "bad store name {}",
                jarvis_go::fmt::go_quote(store)
            ));
        }
        let mut clean = BTreeMap::new();
        for (k, v) in keys {
            if !key_name_ok(k) {
                return Err(anyhow!("bad key name {}", jarvis_go::fmt::go_quote(k)));
            }
            clean.insert(k.clone(), clean_doc(v).map_err(|e| anyhow!("{k}: {e:#}"))?);
        }
        let ab = about
            .map(clean_doc)
            .transpose()
            .map_err(|e| anyhow!("about: {e:#}"))?;
        let _g = STORE_DOCS_MU.lock().unwrap_or_else(|e| e.into_inner());
        let mut m = self.read_store_docs();
        let d = m.entry(store.to_string()).or_default();
        if let Some(ab) = ab {
            d.about = ab;
        }
        for (k, v) in clean {
            if v.is_empty() {
                d.keys.remove(&k);
            } else {
                d.keys.insert(k, v);
            }
        }
        self.st.write_doc(
            "store-docs.json",
            jarvis_go::fmt::marshal_indent1(&m).as_bytes(),
        )
    }

    /// the core's signed list with each store's keys, who wrote them and what they are for
    pub fn store_list(&self) -> Result<(Vec<StoreRow>, Doc)> {
        let d = self.store_core().call(
            "/stores",
            &json!({"nonce": format!("store-keys-{}", crate::util::rand_id())}),
        )?;
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct List {
            kind: String,
            stores: Vec<CoreStoreRow>,
        }
        let list = d
            .decode::<List>()
            .ok()
            .filter(|l| l.kind == "stores")
            .ok_or_else(|| anyhow!("the core's store list isn't readable"))?;
        let docs = self.store_docs();
        let lines: BTreeMap<String, (String, String)> = self.st.do_(|d| {
            let mut lines = BTreeMap::new(); // line → session id, label
            for s in d.sessions.values() {
                let l = cert_line(s.cert.as_ref());
                if !l.is_empty() {
                    lines.insert(l, (s.id.clone(), s.label.clone()));
                }
            }
            for rec in &d.records {
                let l = cert_line(rec.session.cert.as_ref());
                if !l.is_empty() {
                    lines
                        .entry(l)
                        .or_insert_with(|| (rec.session.id.clone(), rec.session.label.clone()));
                }
            }
            lines
        });
        let mut rows: Vec<StoreRow> = list
            .stores
            .into_iter()
            .map(|s| {
                let doc = docs.get(&s.name).cloned().unwrap_or_default();
                let mut row = StoreRow {
                    name: s.name.clone(),
                    sensitive: s.sensitive,
                    empty: s.empty,
                    unlocked: s.unlocked,
                    about: doc.about.clone(),
                    version: s.version,
                    keys_from: "core".into(),
                    ..Default::default()
                };
                for k in s.keys {
                    let mut writer = k.writer;
                    if let Some(w) = writer.as_mut()
                        && !w.line.is_empty()
                    {
                        let (sid, label) = lines.get(&w.line).cloned().unwrap_or_default();
                        w.session = sid;
                        w.session_label = label;
                    }
                    row.keys.push(k.name.clone());
                    row.key_info.push(KeyRow {
                        explanation: doc.keys.get(&k.name).cloned().unwrap_or_default(),
                        name: k.name,
                        at: k.at,
                        writer,
                    });
                }
                row
            })
            .collect();
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        Ok((rows, d))
    }

    pub fn serve_store_list(&self, w: &mut W) {
        match self.store_list() {
            Err(e) => write_err(w, &e),
            Ok((rows, d)) => write_json(w, 200, &json!({"stores": rows, "signed": d})),
        }
    }

    /// what a writer seals to — the core's identity (its keys, the box key's signature, its signed state naming the
    /// master key and the phone) and its signed store key for that phone; the kernel's secrets signs no store key (its
    /// writers compute P + K: sig.StoreKey)
    pub fn store_key_for(&self) -> Result<Value> {
        let sc = self.store_core();
        let b = match sc.raw("GET", "/identity", None) {
            Ok((200, b)) => b,
            Ok((st, _)) => {
                return Err(anyhow!(
                    "the {}'s identity isn't readable (HTTP {st}, <nil>)",
                    sc.who()
                ));
            }
            Err(e) => {
                return Err(anyhow!(
                    "the {}'s identity isn't readable (HTTP 0, {e:#})",
                    sc.who()
                ));
            }
        };
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Phone {
            #[serde(rename = "agreementKey")]
            agreement_key: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct St {
            phone: Phone,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Id {
            state: Option<Doc>,
        }
        let id: Id = jarvis_go::unmarshal(&b).unwrap_or_default();
        let phone = id
            .state
            .and_then(|s| s.decode::<St>().ok())
            .map(|s| s.phone.agreement_key)
            .filter(|k| !k.is_empty())
            .ok_or_else(|| anyhow!("the core isn't set up (no phone in its signed state)"))?;
        let ident: Value = serde_json::from_slice(&b)?;
        if self.secrets_stores.get().is_some() {
            return Ok(json!({"identity": ident}));
        }
        let sk = sc.call("/store-key", &json!({"phone": phone}))?;
        Ok(json!({"identity": ident, "storeKey": sk}))
    }

    /// one key written by a session's machine (writer "machine") or the setup session (writer "setup")
    pub fn write_key(
        &self,
        writer: &str,
        machine: &str,
        store: &str,
        key: &str,
        i: KeyWriteIn,
    ) -> Result<Value> {
        let bad = |m: String| -> anyhow::Error { BadRequest(m).into() };
        if !store_name_ok(store) || !key_name_ok(key) {
            return Err(bad(
                "store: lower-case letters, digits and -; key: letters, digits and _".into(),
            ));
        }
        // the core's own store never; the deploy-key token store only by the setup session (the core refuses a
        // machine's write there too: its keys otherwise come only from a phone-approved deploy-key call)
        if store == crate::policy::FLY_STORE
            || (store == crate::flows::DEPLOY_KEY_TOKEN_STORE && writer != "setup")
        {
            return Err(Forbidden(format!(
                "store {store} isn't written this way: the core's Fly token goes through `infra/setup.py backup-core`, the deploy-key token through `infra/setup.py write {store}` from the setup session"
            ))
            .into());
        }
        let expl = clean_doc(&i.explanation).map_err(|e| bad(format!("{e:#}")))?;
        let documented = self
            .store_docs()
            .get(store)
            .and_then(|d| d.keys.get(key))
            .is_some_and(|k| !k.is_empty());
        if !i.delete && expl.is_empty() && !documented {
            return Err(bad(format!(
                "{key} has no explanation yet: say what the key is for (explanation)"
            )));
        }
        if i.sig.is_empty() {
            return Err(bad(
                "sig: the writer's signature over core.WriterText".into()
            ));
        }
        let mut sealed = Value::Null;
        if !i.delete {
            match (&i.wrapped, &i.backup) {
                (Some(_), Some(bk))
                    if !i.data.is_empty() && !bk.e.is_empty() && !bk.data.is_empty() =>
                {
                    if i.backup_sha256 != backup_sha(&bk.e, &bk.data) {
                        return Err(bad("backupSha256 isn't the backup's".into()));
                    }
                    sealed = json!(bk);
                }
                _ => {
                    return Err(bad(
                        "a write carries wrapped, data and its backup (sealed to the master key)"
                            .into(),
                    ));
                }
            }
        } else if !i.backup_sha256.is_empty() {
            return Err(bad("a delete has no backup".into()));
        }
        let mut core = json!({"store": store, "key": key, "delete": i.delete, "data": i.data, "backupSha256": i.backup_sha256,
            "writer": writer, "sig": i.sig});
        if let Some(wr) = &i.wrapped {
            core["wrapped"] = json!(wr);
        }
        if let Some(l) = i.live.as_ref().filter(|l| !l.is_null()) {
            core["live"] = l.clone();
        }
        if writer == "machine" {
            let (cert, grant) = self.st.do_(|d| {
                let Some(s) = d.machines.get(machine).and_then(|sid| d.sessions.get(sid)) else {
                    return (None, None);
                };
                if s.machine_id != machine || s.state != "started" {
                    return (None, None);
                }
                if let Some(k) = &s.kernel {
                    // a kernel line (kernelline.rs): secrets checks the grant its machine holds
                    let g = k
                        .grant
                        .as_ref()
                        .filter(|_| k.machine_cert.is_some())
                        .map(|g| json!(g));
                    return (None, g);
                }
                (s.cert.clone(), None)
            });
            match (grant, cert) {
                (Some(g), _) => core["grant"] = g,
                (None, Some(c)) => core["cert"] = json!(c),
                _ => return Err(Forbidden("only a running session writes a key".into()).into()),
            }
        }
        let sc = self.store_core();
        let ident = match sc.raw("GET", "/identity", None) {
            Ok((200, b)) => b,
            Ok(_) => return Err(anyhow!("the {}'s identity isn't readable: <nil>", sc.who())),
            Err(e) => return Err(anyhow!("the {}'s identity isn't readable: {e:#}", sc.who())),
        };
        // the backup first: a key never reaches the core without one (Deyao: "has backup, so can't overwrite")
        let b = self.backup_bucket().ok_or_else(|| anyhow!("the router has no backup credential (BACKUP_READ_ACCESS_KEY): no key is written without its backup. The setup session installs it with infra/backup-read-key.py install (RUNBOOK, the router's secrets)"))?;
        let obj = json!({"kind": "key-backup", "store": store, "key": key, "deleted": i.delete, "sealed": sealed,
            "backupSha256": i.backup_sha256, "e": i.wrapped.as_ref().map(|w| w.e.clone()).unwrap_or_default(), "dataSha256": data_sha(&i.data),
            "writer": {"by": writer, "sig": i.sig, "cert": core.get("cert").cloned().unwrap_or(Value::Null)},
            "core": serde_json::from_slice::<Value>(&ident).unwrap_or(Value::Null), "explanation": expl, "at": GoTime::now().utc().rfc3339()});
        let raw = jarvis_go::marshal(&obj);
        b.put(&format!("keys/{store}/{key}.json"), raw.as_bytes())
            .map_err(|e| anyhow!("the backup wasn't written, so the key wasn't either: {e:#}"))?;
        let receipt = sc.call("/stores/write-key", &core)?;
        // storeversions.rs: the version this write makes (a box with no core)
        let entry = (!i.delete).then(|| crate::storeversions::VerEntry {
            wrapped: json!(i.wrapped),
            data: i.data.clone(),
            backup_sha256: i.backup_sha256.clone(),
            receipt: None,
            backup: serde_json::value::RawValue::from_string(raw.clone()).ok(),
        });
        self.record_key_write(store, key, entry, Some(&receipt));
        if !expl.is_empty()
            && let Err(e) = self.set_store_docs(
                store,
                None,
                &BTreeMap::from([(key.to_string(), expl.clone())]),
            )
        {
            crate::logf!("store {store}: the explanation of {key} wasn't kept: {e:#}");
        }
        // no Inbox request: a session holding the store gets the key at its next pull with a new cert (Deyao,
        // 2026-10-22)
        Ok(json!({"ok": true, "receipt": receipt}))
    }

    /// every running session whose cert names the store gets an unlock request (one batch when several), so the
    /// phone gives them the store as it is now; their machines pull again once it is unlocked (unlock_arrived)
    pub fn refresh_holders(&self, store: &str, why: &str) -> Vec<String> {
        let sids: Vec<String> = self.st.do_(|d| {
            d.sessions
                .values()
                .filter(|s| {
                    s.state == "started"
                        && !s.machine_id.is_empty()
                        && s.stores
                            .as_ref()
                            .is_some_and(|st| st.iter().any(|x| x == store))
                })
                .map(|s| s.id.clone())
                .collect()
        });
        self.file_refresh(&sids, why);
        sids
    }

    /// the unlock requests that bring sessions their stores as they are now (filed by the router)
    pub fn file_refresh(&self, sids: &[String], why: &str) {
        let o = Origin {
            caller: Caller {
                kind: "router".into(),
                ..Default::default()
            },
            call: ApiCall {
                method: "POST".into(),
                path: "/router/refresh".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        match sids.len() {
            0 => {}
            1 => {
                if let Err(e) = self.file_request(
                    REQUEST_KIND_UNLOCK,
                    RequestParams {
                        session: sids[0].clone(),
                        ..Default::default()
                    },
                    why,
                    o,
                ) {
                    crate::logf!("refresh {}: {e:#}", sids[0]);
                }
            }
            _ => {
                let Some(me) = self.me.get().and_then(std::sync::Weak::upgrade) else {
                    return;
                };
                for part in sids.chunks(crate::batches::BATCH_MAX_ITEMS) {
                    let items: Vec<Value> = part
                        .iter()
                        .map(|sid| json!({"intent": "unlock", "session": sid, "explanation": why}))
                        .collect();
                    let body = jarvis_go::marshal(&json!({"summary": why, "items": items}));
                    let (code, out) =
                        me.file_batch(&o.caller, "POST", "/router/refresh", body.as_bytes(), None);
                    if code != 200 {
                        crate::logf!(
                            "refresh {}: {code} {}",
                            jarvis_go::fmt::go_sprint(&json!(part)),
                            jarvis_go::fmt::go_sprint(&out)
                        );
                    }
                }
            }
        }
    }

    /// an unlock for one cert went through (the phone's unlock_finish): when that cert is a running, booted machine's
    /// newest, the machine's supervisor pulls again so it holds the store as it is now
    pub fn unlock_arrived(&self, answer: &[u8]) {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct X {
            kind: String,
            #[serde(rename = "for")]
            for_: String,
        }
        let Ok(a) = jarvis_go::unmarshal::<Doc>(answer) else {
            return;
        };
        let Ok(x) = jarvis_go::unmarshal::<X>(a.payload.as_bytes()) else {
            return;
        };
        if x.kind != "unlocked" || x.for_.is_empty() {
            return;
        }
        let machine = self.st.do_(|d| {
            d.sessions
                .values()
                .filter(|s| {
                    s.state == "started"
                        && !s.machine_id.is_empty()
                        && s.booted == s.machine_id
                        && cert_nonce(s.cert.as_ref()) == x.for_
                })
                .map(|s| s.machine_id.clone())
                .next_back()
                .unwrap_or_default()
        });
        if !machine.is_empty() {
            self.send(&machine, "refresh-secrets");
        }
    }
}

// ---- routes -------------------------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(default)]
struct DocsIn {
    store: String,
    about: Option<String>,
    keys: BTreeMap<String, String>,
}

fn write_key_route(
    r: &Arc<Router>,
    w: &mut W,
    writer: &str,
    machine: &str,
    store: &str,
    key: &str,
    body: &[u8],
) {
    let i: KeyWriteIn = match jarvis_go::unmarshal(body) {
        Ok(i) => i,
        Err(e) => return write_error(w, 400, &format!("bad JSON: {e}")),
    };
    match r.write_key(writer, machine, store, key, i) {
        Err(e) => write_write_err(w, &e),
        Ok(out) => write_json(w, 200, &out),
    }
}

fn store_key_route(r: &Arc<Router>, w: &mut W) {
    match r.store_key_for() {
        Err(e) => write_err(w, &e),
        Ok(out) => write_json(w, 200, &out),
    }
}

fn set_docs_route(r: &Arc<Router>, w: &mut W, store: &str, i: &DocsIn) {
    match r.set_store_docs(store, i.about.as_deref(), &i.keys) {
        Err(e) => write_error(w, 400, &format!("{e:#}")),
        Ok(()) => write_json(w, 200, &json!({"ok": true})),
    }
}

pub fn register_store_docs(reg: &mut Registrar) {
    reg.app("GET /api/stores", |r, w, _| r.serve_store_list(w));
    reg.app("PUT /api/stores/{store}/docs", |r, w, req| {
        let b = req.read_body(1 << 20);
        let i: DocsIn = match jarvis_go::unmarshal(&b) {
            Ok(i) => i,
            Err(e) => return write_error(w, 400, &format!("bad JSON: {e}")),
        };
        set_docs_route(r, w, &req.path_value("store"), &i);
    });
    // every session may see every store's names (not only its own): it needs them to know which store to ask for
    reg.m("GET /m/stores", |r, w, _, _, _| r.serve_store_list(w));
    reg.m("GET /m/store-key", |r, w, _, _, _| store_key_route(r, w));
    reg.m(
        "POST /m/stores/{store}/keys/{key}",
        |r, w, req, machine, body| {
            write_key_route(
                r,
                w,
                "machine",
                machine,
                &req.path_value("store"),
                &req.path_value("key"),
                body,
            )
        },
    );
    reg.setup_signed("GET /setup/stores/keys", 1 << 20, |r, w, _, _| {
        r.serve_store_list(w)
    });
    reg.setup_signed("GET /setup/store-key", 1 << 20, |r, w, _, _| {
        store_key_route(r, w)
    });
    reg.setup_signed(
        "POST /setup/stores/{store}/keys/{key}",
        1 << 20,
        |r, w, req, b| {
            write_key_route(
                r,
                w,
                "setup",
                "",
                &req.path_value("store"),
                &req.path_value("key"),
                b,
            )
        },
    );
    reg.setup_signed("POST /setup/store-docs", 1 << 20, |r, w, _, b| {
        let i: DocsIn = match jarvis_go::unmarshal(b) {
            Ok(i) => i,
            Err(e) => return write_error(w, 400, &format!("bad JSON: {e}")),
        };
        set_docs_route(r, w, &i.store.clone(), &i);
    });
}
