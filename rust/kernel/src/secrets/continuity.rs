//! Continuity, carried over from core/continuity.go for secrets alone:
//!
//!  1. Secrets' long-lived keys come from the master key: the app derives a 32-byte seed (its own label, SecretsSeed)
//!     and sends it in the claim bundle; from it secrets derives its signing key, its store share K and the state key
//!     (derive_core_keys). Every Recover with the same kit brings back the same secrets, and the store key P + K stays.
//!  2. The state: the stores as secrets holds them (each key wrapped to P + K), the deploy-key stores' repos and
//!     GitHub key ids (they have no backup) and the stores that aren't sensitive, sealed under the state key and signed
//!     with a head {seq, sha256}; every answer carries X-Line-Seq and the router keeps the newest. A Recover takes back
//!     the deploy-key stores from it; the other kernel copy's secrets takes it whole in the copy flip (below: at most
//!     one secrets with these keys serves).
//!
//! The copy flip: both kernel copies' rosters name the same secrets (the keys the kit derives). A release lands on the
//! copy that doesn't serve, whose secrets starts empty with boot keys of its own; that copy's roster names them as
//! secretsBoot. Once the root key signed it, the router asks the serving secrets to hand over:
//!   - handoff (the serving secrets): the other copy's root-signed roster, naming this secrets as its secrets and an
//!     empty one as secretsBoot → the seed, the claim's keys (master, phone, root) and a FINAL line state (the open
//!     unlocks included), sealed to secretsBoot's agreement key and signed with the derived key; from then on it
//!     refuses every call but identity, roster, line-state and the same handoff again;
//!   - takeover (the empty secrets of the other copy): a handoff for exactly the roster it holds, sealed to its boot
//!     key and signed by the secrets that roster names → it derives the keys from the seed (they must be the ones the
//!     roster names), takes the final state whole and serves. The same handoff again answers the same; any other, or a
//!     secrets already set up, is refused.
//!
//! Go and Rust write the same documents: the copy flip that brings the Rust kernel in is a Go secrets handing over to
//! a Rust one (tests/secrets_go.rs opens Go's).

use super::crypto::{gcm_open, gcm_seal, kdf};
use super::keys::{KeyEntry, valid_entry};
use super::{Inner, Result, Secrets, Unlocked, fail, hex, sign, store_name};
use jarvis_go::GoTime;
use jarvis_sig::{Doc, Opener, Sealed, Signer, go_json, open_roster, seal_to, strict_json, verify};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// + signing | agreement | line-state (the app derives the seed: KernelContinuity.seed)
const CORE_KEY_INFO: &str = "jarvis2/kernel-secrets/";
const LINE_STATE_AAD: &str = "jarvis2/kernel-secrets-state";
pub const LINE_SEQ_HEADER: &str = "X-Line-Seq";

pub const MODE_SERVING: &str = "";
pub const MODE_HANDED_OFF: &str = "handed-off";
/// flip.rs HANDOFF_INFO + "secrets"
const INFO_HANDOFF: &str = "jarvis2/kernel-handoff/secrets";

/// what derive_core_keys makes
pub struct CoreKeys {
    pub signer: Signer,
    pub agreement: Opener,
    pub state: [u8; 32],
}

/// a valid P-256 scalar for the label — the first of label, label/1, label/2, … that is one
fn derive_scalar(seed: &[u8], label: &str) -> Result<Vec<u8>> {
    for i in 0..16 {
        let mut info = format!("{CORE_KEY_INFO}{label}");
        if i > 0 {
            info.push_str(&format!("/{i}"));
        }
        let d = kdf(seed, &info);
        if Opener::from_scalar(&d).is_ok() && d.iter().any(|b| *b != 0) {
            return Ok(d.to_vec());
        }
    }
    Err(anyhow::anyhow!("no valid scalar for {label}"))
}

/// secrets' keys from the seed (the app derives the same public keys: CoreCrypto.swift)
pub fn derive_core_keys(seed: &[u8]) -> Result<CoreKeys> {
    if seed.len() != 32 {
        return Err(anyhow::anyhow!("the seed is 32 bytes"));
    }
    let signer = Signer::from_scalar(&derive_scalar(seed, "signing")?)?;
    let agreement = Opener::from_scalar(&derive_scalar(seed, "agreement")?)?;
    let state = kdf(seed, &format!("{CORE_KEY_INFO}line-state"));
    Ok(CoreKeys {
        signer,
        agreement,
        state,
    })
}

/// the public keys a seed derives (what a claim with that seed names as its identity)
pub fn seed_identity(seed: &[u8]) -> Result<(String, String)> {
    let k = derive_core_keys(seed)?;
    Ok((k.signer.public_key(), k.agreement.public_key()))
}

// ---- the line state ---------------------------------------------------------------------------------------------

/// everything about the stores secrets must not forget across a Recover or a handoff
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LineState {
    #[serde(default)]
    pub seq: i64,
    /// a handoff's
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub r#final: bool,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub stores: BTreeMap<String, Option<BTreeMap<String, Option<KeyEntry>>>>,
    #[serde(default)]
    pub repo_owner: BTreeMap<String, String>,
    /// a deploy-key store's GitHub key id
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub repo_key_id: BTreeMap<String, i64>,
    #[serde(default)]
    pub not_sensitive: Vec<String>,
    /// a handoff's final state only: the open unlocks, so a blue/green flip keeps them (they never end by themselves)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlocked: Option<BTreeMap<String, Option<CarriedUnlock>>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CarriedUnlock {
    #[serde(default)]
    pub values: BTreeMap<String, String>,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub ids: BTreeMap<String, GoTime>,
}

/// the sealed state and secrets' signed head over it (what the router keeps and the app hands back)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineStateDoc {
    #[serde(default)]
    pub head: Doc,
    /// base64(nonce ‖ AES-GCM ciphertext)
    #[serde(default)]
    pub sealed: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct LineHead {
    /// "line-state-head"
    kind: String,
    seq: i64,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    r#final: bool,
    /// of the sealed bytes (base64-decoded)
    sha256: String,
    at: String,
}

/// the current state with seq 0
fn line_snapshot(g: &Inner) -> LineState {
    LineState {
        seq: 0,
        r#final: false,
        phone: g.phone_agreement.clone(),
        stores: g
            .stores
            .iter()
            .map(|(s, keys)| {
                (
                    s.clone(),
                    Some(
                        keys.iter()
                            .map(|(k, x)| (k.clone(), Some(x.clone())))
                            .collect(),
                    ),
                )
            })
            .collect(),
        repo_owner: g.repo_owner.clone(),
        repo_key_id: g.repo_key_id.clone(),
        not_sensitive: g.not_sensitive.iter().cloned().collect(),
        unlocked: None,
    }
}

impl Secrets {
    /// after every call — when the line state changed, the next seq, sealed and signed (a serving secrets with derived
    /// keys only)
    pub fn sync_line(&self) {
        let mut g = self.lock();
        if g.line_key.is_none() || g.mode != MODE_SERVING {
            return;
        }
        let Ok(plain) = go_json(&line_snapshot(&g)) else {
            return;
        };
        let h = hex(&Sha256::digest(plain.as_bytes()));
        if h == g.line_hash && g.line_doc.is_some() {
            return;
        }
        if let Ok(d) = seal_line(&mut g, false, (self.now)()) {
            g.line_hash = h;
            g.line_doc = Some(d);
        }
    }

    /// the newest sealed line state (404 on a secrets without derived keys)
    pub fn line_state(&self) -> Result<LineStateDoc> {
        self.sync_line();
        let g = self.lock();
        g.line_doc.clone().ok_or_else(|| {
            fail(
                404,
                "this core keeps no line state (it wasn't set up with a seed)",
            )
        })
    }

    /// the seq of the newest line state (0: none)
    pub fn line_seq(&self) -> i64 {
        self.lock().line_seq
    }

    /// serving ("") or handed-off
    pub fn mode(&self) -> String {
        self.lock().mode.clone()
    }

    /// to the other copy's secrets, as its root-signed roster names it; this secrets serves nothing after it (again
    /// for the same roster: the same handoff)
    pub fn handoff(&self, roster: &Doc) -> Result<Doc> {
        let me = self.component_identity();
        let own = self.trust.roster();
        let mut g = self.lock();
        let id = roster.id();
        if g.mode == MODE_HANDED_OFF && g.handed_to == id {
            return g
                .handoff
                .clone()
                .ok_or_else(|| fail(500, "the handoff made is gone"));
        }
        if g.mode == MODE_HANDED_OFF {
            return Err(fail(
                409,
                "this secrets already handed over to another roster: a final state goes to one roster only",
            ));
        }
        if g.line_key.is_none() || g.master_key.is_empty() || g.seed.is_none() {
            return Err(fail(
                409,
                "only a secrets set up from the kit's seed hands over",
            ));
        }
        let Some(own) = own else {
            return Err(fail(503, super::super::serve::no_roster()));
        };
        let r = open_roster(roster, self.trust.root()).map_err(|e| fail(403, e.to_string()))?;
        if r.copy == own.copy {
            return Err(fail(
                409,
                format!(
                    "a handoff goes to the other kernel copy (this is {}'s secrets)",
                    own.copy
                ),
            ));
        }
        let boot = match (r.member("secrets"), &r.secrets_boot) {
            (Some(m), Some(boot)) if *m == me => boot.clone(),
            _ => {
                return Err(fail(
                    403,
                    format!(
                        "the {} roster doesn't name this secrets as its secrets and an empty one to take over",
                        r.copy
                    ),
                ));
            }
        };
        let fin = seal_line(&mut g, true, (self.now)())?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct PublicKeys<'a> {
            signing_key: &'a str,
            agreement_key: &'a str,
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Handed<'a> {
            seed: String,
            master: &'a str,
            root: &'a str,
            phone: PublicKeys<'a>,
            line_state: &'a LineStateDoc,
        }
        let plain = go_json(&Handed {
            seed: jarvis_sig::b64(g.seed.as_deref().unwrap_or_default()),
            master: &g.master_key,
            root: &g.root,
            phone: PublicKeys {
                signing_key: &g.phone_signing,
                agreement_key: &g.phone_agreement,
            },
            line_state: &fin,
        })?;
        let sealed = seal_to(&boot.agreement_key, plain.as_bytes(), INFO_HANDOFF)?;
        let d = sign(
            &g,
            &HandoffDoc {
                kind: "handoff".into(),
                role: "secrets".into(),
                from: own.copy.clone(),
                roster: id.clone(),
                to: boot.agreement_key.clone(),
                sealed: Some(sealed),
            },
        )?;
        g.mode = MODE_HANDED_OFF.into();
        g.handed_to = id;
        g.handoff = Some(d.clone());
        g.line_doc = Some(fin);
        g.line_hash.clear();
        g.unlocked.clear();
        g.pending.clear();
        g.pending_keys.clear();
        crate::serve::log(&format!(
            "handed over to the {} copy: final line state {}; serving nothing from now on",
            r.copy, g.line_seq
        ));
        Ok(d)
    }

    /// an empty secrets takes its predecessor's handoff (for the roster it holds, sealed to its boot key, signed by the
    /// secrets that roster names) and serves with the keys the seed derives
    pub fn takeover(&self, d: &Doc) -> Result<Doc> {
        let held = self.trust.doc();
        let r = self.trust.roster();
        let mut g = self.lock();
        if !g.master_key.is_empty() {
            if g.took == d.id() {
                return sign(
                    &g,
                    &json!({"kind": "took-over", "role": "secrets", "handoff": d.id(), "lineSeq": g.line_seq, "again": true}),
                );
            }
            return Err(fail(409, "this secrets is set up: it takes no handoff"));
        }
        let (Some(held), Some(r)) = (held, r) else {
            return Err(fail(503, super::super::serve::no_roster()));
        };
        let h: HandoffDoc = match strict_json::<HandoffDoc>(d.payload.as_bytes()) {
            Ok(h) if h.kind == "handoff" && h.role == "secrets" && h.sealed.is_some() => h,
            _ => return Err(fail(400, "not a secrets handoff")),
        };
        let boot = (g.signer.public_key(), g.agreement.public_key());
        let m = r.member("secrets").cloned().unwrap_or_default();
        let named = r
            .secrets_boot
            .as_ref()
            .is_some_and(|b| b.signing_key == boot.0 && b.agreement_key == boot.1);
        if !named {
            return Err(fail(
                403,
                "the roster this secrets holds doesn't name it to take over",
            ));
        }
        if h.roster != held.id() {
            return Err(fail(
                403,
                "a handoff to another roster than the one this secrets holds",
            ));
        }
        if h.to != boot.1 {
            return Err(fail(
                403,
                "a handoff sealed to other keys than this secrets' boot keys",
            ));
        }
        if !verify(&m.signing_key, d.payload.as_bytes(), &d.sig) {
            return Err(fail(
                403,
                "the handoff isn't signed by the secrets the roster names",
            ));
        }
        let sealed = h.sealed.clone().unwrap_or_else(|| Sealed {
            e: String::new(),
            data: String::new(),
        });
        let plain = g
            .agreement
            .open(&sealed, INFO_HANDOFF)
            .map_err(|_| fail(403, "the handoff doesn't open with this secrets' boot key"))?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct PublicKeys {
            signing_key: String,
            agreement_key: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Handed {
            seed: String,
            master: String,
            root: String,
            phone: PublicKeys,
            line_state: Option<LineStateDoc>,
        }
        let hs: Handed = match strict_json::<Handed>(&plain) {
            Ok(hs) if hs.line_state.is_some() => hs,
            Ok(_) => return Err(fail(400, "the handed state: <nil>")),
            Err(e) => return Err(fail(400, format!("the handed state: {e}"))),
        };
        let seed = jarvis_sig::unb64(&hs.seed).unwrap_or_default();
        if seed.len() != 32 {
            return Err(fail(400, "the handed seed"));
        }
        let dk =
            derive_core_keys(&seed).map_err(|e| fail(400, format!("the handed seed: {e:#}")))?;
        if dk.signer.public_key() != m.signing_key || dk.agreement.public_key() != m.agreement_key {
            return Err(fail(
                403,
                "the handed seed derives other keys than the roster's secrets",
            ));
        }
        let st = open_line_state(
            hs.line_state.as_ref().unwrap_or(&LineStateDoc::default()),
            &dk,
        )?;
        if !st.r#final {
            return Err(fail(403, "not a final line state"));
        }
        g.master_key = hs.master;
        g.root = hs.root;
        g.phone_signing = hs.phone.signing_key;
        g.phone_agreement = hs.phone.agreement_key;
        g.signer = dk.signer;
        g.agreement = dk.agreement;
        g.line_key = Some(dk.state);
        g.seed = Some(seed);
        let stores = restore_line(&mut g, &st, true);
        g.mode = MODE_SERVING.into();
        g.line_hash.clear();
        g.line_doc = None;
        g.took = d.id();
        crate::serve::log(&format!(
            "took over from the {} copy at line state {} ({} stores); serving",
            h.from,
            st.seq,
            stores.len()
        ));
        sign(
            &g,
            &json!({"kind": "took-over", "role": "secrets", "handoff": d.id(), "lineSeq": st.seq, "stores": stores.len()}),
        )
    }
}

/// the signed handoff (flip.rs Handoff's shape, role "secrets")
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffDoc {
    kind: String,
    role: String,
    from: String,
    roster: String,
    to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed: Option<Sealed>,
}

/// the state as it is now, numbered on
fn seal_line(g: &mut Inner, fin: bool, now: GoTime) -> Result<LineStateDoc> {
    let key = g.line_key.ok_or_else(|| anyhow::anyhow!("no state key"))?;
    let mut st = line_snapshot(g);
    st.seq = g.line_seq + 1;
    st.r#final = fin;
    if fin {
        st.unlocked = Some(
            g.unlocked
                .iter()
                .map(|(n, u)| {
                    (
                        n.clone(),
                        Some(CarriedUnlock {
                            values: u.values.clone(),
                            version: u.version.clone(),
                            ids: u.ids.clone(),
                        }),
                    )
                })
                .collect(),
        );
    }
    let full = go_json(&st)?;
    let sealed = gcm_seal(&key, full.as_bytes(), LINE_STATE_AAD.as_bytes());
    let head = sign(
        g,
        &LineHead {
            kind: "line-state-head".into(),
            seq: st.seq,
            r#final: fin,
            sha256: hex(&Sha256::digest(&sealed)),
            at: now.utc().rfc3339(),
        },
    )?;
    g.line_seq = st.seq;
    Ok(LineStateDoc {
        head,
        sealed: jarvis_sig::b64(&sealed),
    })
}

/// a line state these keys made
pub fn open_line_state(d: &LineStateDoc, k: &CoreKeys) -> Result<LineState> {
    let h: Option<LineHead> = verify(
        &k.signer.public_key(),
        d.head.payload.as_bytes(),
        &d.head.sig,
    )
    .then(|| serde_json::from_str::<LineHead>(&d.head.payload).ok())
    .flatten()
    .filter(|h| h.kind == "line-state-head");
    let Some(h) = h else {
        return Err(fail(
            403,
            "the line state isn't this core's (its head isn't signed by the derived key)",
        ));
    };
    let sealed = jarvis_sig::unb64(&d.sealed).map_err(|_| fail(400, "line state: not base64"))?;
    if hex(&Sha256::digest(&sealed)) != h.sha256 {
        return Err(fail(403, "the line state isn't the one its head names"));
    }
    let plain = gcm_open(&k.state, &sealed, LINE_STATE_AAD.as_bytes())
        .map_err(|_| fail(403, "the line state doesn't open with the derived key"))?;
    match serde_json::from_slice::<LineState>(&plain) {
        Ok(st) if st.seq == h.seq => Ok(st),
        _ => Err(fail(400, "bad line state")),
    }
}

/// a line state taken back (the claim already took the stores from the bundle). all = a final state (a handoff): its
/// stores replace the bundle's, as they are newer; otherwise only a deploy-key store the bundle didn't bring comes
/// back. Stores come back only when they are wrapped for the phone of this claim.
pub(crate) fn restore_line(g: &mut Inner, st: &LineState, all: bool) -> Vec<String> {
    g.line_seq = st.seq;
    let mut back = vec![];
    if st.phone.is_empty() || st.phone != g.phone_agreement {
        return back;
    }
    let ns: BTreeSet<&String> = st.not_sensitive.iter().collect();
    // a store's keys as the state holds them, when every one is valid (None: refused)
    let valid = |s: &str,
                 keys: &Option<BTreeMap<String, Option<KeyEntry>>>|
     -> Option<BTreeMap<String, KeyEntry>> {
        if !store_name(s) {
            return None;
        }
        let mut out = BTreeMap::new();
        for (k, x) in keys.iter().flatten() {
            let x = x.as_ref()?;
            if x.key != *k || !valid_entry(x, s) {
                return None;
            }
            out.insert(k.clone(), x.clone());
        }
        Some(out)
    };
    if all {
        let mut stores = BTreeMap::new();
        let mut owners = BTreeMap::new();
        let mut ids = BTreeMap::new();
        let mut not_sensitive = BTreeSet::new();
        for (s, keys) in &st.stores {
            let Some(keys) = valid(s, keys) else {
                continue;
            };
            stores.insert(s.clone(), keys);
            if let Some(repo) = st.repo_owner.get(s).filter(|r| crate::minter::repo_ok(r)) {
                owners.insert(s.clone(), repo.clone());
                if let Some(id) = st.repo_key_id.get(s).filter(|id| **id > 0) {
                    ids.insert(s.clone(), *id);
                }
            }
            if ns.contains(s) {
                not_sensitive.insert(s.clone());
            }
            back.push(s.clone());
        }
        g.stores = stores;
        g.repo_owner = owners;
        g.repo_key_id = ids;
        g.not_sensitive = not_sensitive;
        g.unlocked = BTreeMap::new();
        for (n, u) in st.unlocked.iter().flatten() {
            if let Some(u) = u
                && g.stores.contains_key(n)
                && !u.ids.is_empty()
            {
                g.unlocked.insert(
                    n.clone(),
                    Unlocked {
                        values: u.values.clone(),
                        version: u.version.clone(),
                        ids: u.ids.clone(),
                    },
                );
            }
        }
        back.sort();
        return back;
    }
    for (s, repo) in &st.repo_owner {
        let keys = st.stores.get(s).cloned().flatten().unwrap_or_default();
        if g.stores.contains_key(s) || keys.is_empty() || !crate::minter::repo_ok(repo) {
            continue;
        }
        let Some(keys) = valid(s, &Some(keys)) else {
            continue;
        };
        g.stores.insert(s.clone(), keys);
        g.repo_owner.insert(s.clone(), repo.clone());
        if let Some(id) = st.repo_key_id.get(s).filter(|id| **id > 0) {
            g.repo_key_id.insert(s.clone(), *id);
        }
        if ns.contains(s) {
            g.not_sensitive.insert(s.clone());
        }
        back.push(s.clone());
    }
    back.sort();
    back
}

/// what a secrets that handed over still answers
pub fn allowed_in(pattern: &str) -> bool {
    matches!(
        pattern,
        "GET /identity"
            | "GET /line-state"
            | "POST /wipe"
            | "GET /roster"
            | "POST /roster"
            | "POST /handoff"
    )
}
