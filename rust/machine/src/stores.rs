//! jarvis stores [--keys | --json]: every store and the key NAMES it holds (never a value), with what each key is for,
//! from the router's GET /m/stores (router/storedocs.go), so a session knows which store to ask for. The store list,
//! sensitivity and key names are the core's signed list, checked here against the core's key; the explanations are the
//! router's record (words, not a trust decision).

use crate::client::Client;
use crate::crypto::{SignedDoc, read_trim, verify_doc};
use crate::{gojson, paths};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Writer {
    pub by: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session: String,
    #[serde(rename = "sessionLabel", skip_serializing_if = "String::is_empty")]
    pub session_label: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct KeyRow {
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub explanation: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writer: Option<Writer>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StoreRow {
    pub name: String,
    pub sensitive: bool,
    pub empty: bool,
    pub unlocked: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub about: String,
    /// names, as the core lists them
    pub keys: Option<Vec<String>>,
    /// the same keys with what each is for
    #[serde(rename = "keyInfo")]
    pub key_info: Option<Vec<KeyRow>>,
    #[serde(rename = "keysFrom")]
    pub keys_from: String,
}

impl StoreRow {
    fn key_names(&self) -> String {
        self.keys.clone().unwrap_or_default().join(" ")
    }
}

pub fn stores_cmd(args: &[String]) -> Result<()> {
    let as_json = args.len() == 1 && args[0] == "--json";
    let with_keys = args.len() == 1 && args[0] == "--keys";
    if !args.is_empty() && !as_json && !with_keys {
        bail!(
            "usage: jarvis stores [--keys | --json]   (--keys: each key on its own line with what it is for)"
        );
    }
    let c = Client::new()?;
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Out {
        stores: Vec<StoreRow>,
        signed: Option<SignedDoc>,
    }
    let out: Out = c.json::<(), Out>("GET", "/m/stores", None)?;
    // the store list and sensitivity: only as the core signed them
    if let (Ok(core_key), Some(signed)) = (read_trim(&paths::core_key_path()), &out.signed) {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct KeyName {
            name: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct CoreRow {
            name: String,
            sensitive: bool,
            empty: bool,
            keys: Vec<KeyName>,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct List {
            kind: String,
            stores: Vec<CoreRow>,
        }
        let list: List = match verify_doc::<List>(&core_key, Some(signed)) {
            Ok(l) if l.kind == "stores" => l,
            _ => bail!("the store list isn't signed by the core"),
        };
        let signed: HashMap<String, CoreRow> = list
            .stores
            .into_iter()
            .map(|s| (s.name.clone(), s))
            .collect();
        if signed.len() != out.stores.len() {
            bail!("the store list differs from the core's");
        }
        for s in &out.stores {
            let Some(c) = signed
                .get(&s.name)
                .filter(|c| c.sensitive == s.sensitive && c.empty == s.empty)
            else {
                bail!("store {} differs from the core's list", s.name);
            };
            let names: Vec<&str> = c.keys.iter().map(|k| k.name.as_str()).collect();
            if names.join(" ") != s.key_names() {
                bail!("store {}'s keys differ from the core's list", s.name);
            }
        }
    }
    // this session's own stores: from its core-signed cert
    let mut mine = HashSet::new();
    if let Ok(core_key) = read_trim(&paths::core_key_path()) {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Cs {
            cert: Option<SignedDoc>,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct C {
            stores: Vec<String>,
        }
        if let Ok(cs) = c.json::<(), Cs>("GET", "/m/cert", None)
            && let Some(cert) = cs.cert
            && let Ok(cert) = verify_doc::<C>(&core_key, Some(&cert))
        {
            mine.extend(cert.stores);
        }
    }
    if as_json {
        println!("{}", gojson::marshal(&out.stores));
        return Ok(());
    }
    for s in &out.stores {
        let mut flags = vec![];
        if mine.contains(&s.name) {
            flags.push("in this session");
        }
        if s.sensitive {
            flags.push("sensitive");
        }
        if s.empty {
            flags.push("empty");
        } else if !s.unlocked {
            flags.push("locked");
        }
        let mut line = s.name.clone();
        if !flags.is_empty() {
            line += &format!(" [{}]", flags.join(", "));
        }
        if !with_keys {
            println!("{line}: {}", s.key_names());
            continue;
        }
        println!("{line}");
        if !s.about.is_empty() {
            println!("  {}", s.about);
        }
        for k in s.key_info.iter().flatten() {
            let what = if k.explanation.is_empty() {
                "(no explanation yet)"
            } else {
                &k.explanation
            };
            let by = match &k.writer {
                Some(w) if w.by == "machine" => {
                    format!(" [written by session {} {}]", w.session_label, w.session)
                }
                _ => String::new(),
            };
            println!("  {}: {what}{by}", k.name);
        }
    }
    Ok(())
}
