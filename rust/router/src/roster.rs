//! The kernel's roster (docs/PLAN-cluster.md "The roster"): the kernel's components make fresh keys at every start and
//! the root key (the Jarvis 4 app's) vouches for them in one signed document per kernel copy. The router only carries
//! it:
//!
//! ```text
//! POST /api/kernel/root-key      {rootKey}: the app registers its root key's public half (base64 X9.63); kept as
//!                                pending until the setup session commits it (keys/root.pub, the kernel's ConfigMap)
//! GET  /setup/kernel/root-key    {rootKey} (setup-signed): what infra/setup.py kernel-root-key commits
//! GET  /setup/kernel/roster      {current, serving, next, retiredInUse, flip, status, health} (setup-signed): the
//!                                serving copy's roster, which copy serves, the other copy's while it takes over, the
//!                                retired keys of the current roster that something a line holds is signed by (the
//!                                next roster names them again), the copy flip under way, and the kernel's health
//! POST /setup/kernel/roster      {copy, payload, setupSig} (setup-signed): the components' identities as the setup
//!                                session read them through kernel-id.deyaochen.com, signed by the setup key; pending
//! GET  /api/kernel/roster/pending {copy, payload, setupSig}: what the app shows and the root key signs
//! POST /api/kernel/roster        {payload, rootSig}: the root key's roster, posted to every component of its copy and
//!                                kept; the answer names what each component said. A roster of the serving copy (a
//!                                component restarted: it names the old keys as retired) replaces the current one; a
//!                                roster of the other copy (a release landed there) starts the copy flip
//!                                (kernelflip.rs)
//! GET  /api/kernel/roster        the current roster, what each component said, and what is stale
//! ```
//!
//! A component that restarts has new keys and no roster: the router posts the current roster again when it says so
//! (kernel.rs call_seq, and roster_loop every minute); the component refuses it (it names the old keys), and the
//! roster is stale until Deyao signs a new one: GET /api/kernel says "roster stale: component X restarted", and Deyao
//! gets one DM.

use crate::http::Registrar;
use crate::kernel::{KERNEL_COPIES, copy_of, is_no_roster, kernel_error};
use crate::router::Router;
use anyhow::{Result, anyhow};
use base64::Engine;
use jarvis_go::GoTime;
use jarvis_nethttp::{Req, W, write_json};
use jarvis_sig::{Doc as SDoc, Identity, Roster};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// every component of a copy (a roster names exactly these, sorted)
pub const KERNEL_ROLES: &[&str] = &[
    "gullible",
    "identity",
    "merger",
    "minter",
    "mover",
    "notarizer",
    "notary",
    "secrets",
    "spawner",
];

/// a copy's Deployments, which its roster goes to (KERNEL_URL's %s)
pub fn roster_targets(copy: &str) -> Vec<String> {
    KERNEL_ROLES.iter().map(|r| format!("{r}-{copy}")).collect()
}

/// the setup session's roster, waiting for the root key
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RosterFiling {
    pub copy: String,
    pub payload: String,
    #[serde(rename = "setupSig")]
    pub setup_sig: String,
    pub at: GoTime,
}

/// the root key's roster as it was posted
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RosterCurrent {
    pub copy: String,
    pub payload: String,
    pub sig: String,
    pub at: GoTime,
    /// Deployment → "taken", or what it answered
    pub results: BTreeMap<String, String>,
    /// Deployment → "roster stale: component X restarted (…)"
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub stale: BTreeMap<String, String>,
}

impl RosterCurrent {
    pub fn doc(&self) -> SDoc {
        SDoc {
            payload: self.payload.clone(),
            sig: self.sig.clone(),
        }
    }

    /// the payload read (the router checked the root key's signature when it took it)
    pub fn roster(&self) -> Roster {
        serde_json::from_str(&self.payload).unwrap_or_default()
    }
}

/// the stale roster was DMed (once per roster)
pub(crate) static ROSTER_DMED: AtomicBool = AtomicBool::new(false);

/// a P-256 public key, base64 X9.63 (65 bytes, uncompressed)
pub fn valid_root_key(k: &str) -> bool {
    match base64::engine::general_purpose::STANDARD.decode(k) {
        Ok(b) if b.len() == 65 && b[0] == 4 => p256::PublicKey::from_sec1_bytes(&b).is_ok(),
        _ => false,
    }
}

/// payload is a roster for copy, in the exact form Roster::payload makes (what both keys sign): one member per role,
/// retired keys of any role but secrets, secretsBoot a secrets identity
pub fn check_filed_roster(copy: &str, payload: &str) -> Result<()> {
    if copy != "blue" && copy != "green" {
        return Err(anyhow!("copy: blue or green"));
    }
    let ro: Roster = jarvis_sig::strict_json(payload.as_bytes())
        .map_err(|e| anyhow!("payload: not a roster: {e}"))?;
    if ro.kind != "kernel-roster" || ro.copy != copy || ro.members.is_empty() {
        return Err(anyhow!("payload: not a kernel roster for this copy"));
    }
    let mut roles = vec![];
    for m in &ro.members {
        if m.role.is_empty() || m.signing_key.is_empty() || m.agreement_key.is_empty() {
            return Err(anyhow!("payload: a member without keys"));
        }
        roles.push(m.role.as_str());
    }
    if roles != KERNEL_ROLES {
        return Err(anyhow!(
            "payload: the members must be exactly {}, sorted",
            KERNEL_ROLES.join(", ")
        ));
    }
    for m in &ro.retired {
        if !KERNEL_ROLES.contains(&m.role.as_str())
            || m.role == "secrets"
            || m.signing_key.is_empty()
            || m.agreement_key.is_empty()
        {
            return Err(anyhow!(
                "payload: a retired member that isn't a kernel component's keys (never secrets)"
            ));
        }
    }
    if let Some(b) = &ro.secrets_boot
        && (b.role != "secrets" || b.signing_key.is_empty() || b.agreement_key.is_empty())
    {
        return Err(anyhow!("payload: secretsBoot: a secrets identity"));
    }
    match ro.payload() {
        Ok(canon) if canon == payload => Ok(()),
        _ => Err(anyhow!("payload: not in sig.Roster.Payload's exact form")),
    }
}

/// ro, a roster of the copy that doesn't serve, can take over from cur: it names the same secrets, an empty one to
/// take over (secretsBoot), and retires every other member of cur
pub fn check_takeover(ro: &Roster, cur: &Roster) -> Result<()> {
    if ro.secrets_boot.is_none() {
        return Err(anyhow!(
            "a roster of the copy that doesn't serve names its empty secrets (secretsBoot): it takes over from the serving one"
        ));
    }
    if ro.member("secrets") != cur.member("secrets") {
        return Err(anyhow!(
            "a roster of the copy that doesn't serve names the serving copy's secrets (the keys the kit derives)"
        ));
    }
    for m in &cur.members {
        if m.role != "secrets" && !ro.retired.contains(m) {
            return Err(anyhow!(
                "a roster of the copy that doesn't serve retires every serving member: not the {}",
                m.role
            ));
        }
    }
    Ok(())
}

impl Router {
    /// the root key's roster the serving copy holds (None: none yet)
    pub fn current_roster(&self) -> Option<SDoc> {
        self.st
            .do_(|p| p.kernel_roster.as_ref().map(RosterCurrent::doc))
    }

    /// the roster a copy's components should hold: the serving copy's, or the other copy's while it takes over (None:
    /// none)
    pub fn roster_of_copy(&self, copy: &str) -> Option<RosterCurrent> {
        self.st.do_(|p| {
            if let Some(c) = p.kernel_roster.as_ref().filter(|c| c.copy == copy) {
                return Some(c.clone());
            }
            p.kernel_roster_next
                .as_ref()
                .filter(|c| c.copy == copy)
                .cloned()
        })
    }

    /// a component refused its copy's roster (kernel.rs post_roster)
    pub fn roster_stale(&self, dep: &str, msg: &str) {
        let first = self.st.do_(|p| {
            let copy = copy_of(dep);
            let next = p
                .kernel_roster_next
                .as_ref()
                .is_some_and(|n| n.copy == copy);
            let c = if next {
                p.kernel_roster_next.as_mut()
            } else {
                p.kernel_roster.as_mut()
            };
            let Some(c) = c.filter(|c| c.copy == copy) else {
                return false;
            };
            let first = !c.stale.contains_key(dep);
            c.stale.insert(dep.to_string(), msg.to_string());
            c.results.insert(dep.to_string(), msg.to_string());
            first
        });
        if first {
            crate::logf!("kernel: {msg}");
        }
        if ROSTER_DMED
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.dm(&format!(
                "🔴 Jarvis 4 needs you — {msg}. The kernel needs a new roster: the setup session runs infra/setup.py kernel-roster, then Settings → Kernel → Sign roster."
            ));
        }
    }

    /// d to every component of its copy; what each said
    pub fn distribute_roster(&self, d: &SDoc, copy: &str) -> BTreeMap<String, String> {
        let mut res = BTreeMap::new();
        let Some(k) = &self.kernel else { return res };
        for dep in roster_targets(copy) {
            let said = match k.do_(&dep, &dep, "POST", "/roster", Some(&json!({"roster": d}))) {
                Ok(_) => "taken".to_string(),
                Err(e) => match kernel_error(&e) {
                    Some(ke) => format!("refused: {}", ke.msg),
                    None => format!("unreachable: {e:#}"),
                },
            };
            res.insert(dep, said);
        }
        res
    }

    /// GET /api/kernel's roster part
    pub fn roster_status(&self) -> Value {
        let serving = self.serving_copy();
        self.st.do_(|p| {
            let mut out = Map::new();
            out.insert("state".into(), json!("none"));
            out.insert("serving".into(), json!(serving));
            out.insert("rootKey".into(), json!(!p.kernel_root_key.is_empty()));
            out.insert("pending".into(), json!(p.kernel_roster_pending.is_some()));
            if p.kernel_roster_pending.is_some() {
                out.insert("state".into(), json!("pending"));
            }
            if let Some(n) = &p.kernel_roster_next {
                out.insert(
                    "next".into(),
                    json!({"copy": n.copy, "id": n.doc().id(), "at": n.at, "results": n.results}),
                );
            }
            let Some(c) = &p.kernel_roster else {
                return Value::Object(out);
            };
            out.insert("copy".into(), json!(c.copy));
            out.insert("id".into(), json!(c.doc().id()));
            out.insert("at".into(), json!(c.at));
            out.insert("results".into(), json!(c.results));
            let mut stale: Vec<&String> = c.stale.values().collect();
            stale.sort();
            out.insert("stale".into(), json!(stale));
            if !stale.is_empty() {
                out.insert("state".into(), json!("stale"));
            } else if p.kernel_roster_pending.is_none() {
                out.insert("state".into(), json!("current"));
            }
            Value::Object(out)
        })
    }

    /// every component holds its copy's roster; one that lost it (a restart) gets it again, or the roster is stale
    /// (post_roster says so)
    pub fn roster_loop(self: &Arc<Self>, every: Duration) {
        loop {
            std::thread::sleep(every);
            crate::leaderlease::await_lead();
            self.roster_check();
        }
    }

    pub fn roster_check(&self) {
        let Some(k) = &self.kernel else { return };
        for copy in KERNEL_COPIES {
            let Some(c) = self.roster_of_copy(copy) else {
                continue; // the copy that doesn't serve, idle: it holds whatever it held
            };
            let d = c.doc();
            for dep in roster_targets(copy) {
                match k.do_(&dep, &dep, "GET", "/roster", None) {
                    Ok((b, _)) => {
                        if serde_json::from_slice::<SDoc>(&b)
                            .is_ok_and(|held| held.payload == d.payload)
                        {
                            continue;
                        }
                    }
                    Err(e) if !is_no_roster(&e) => continue, // unreachable (scaled down, restarting): the next round
                    Err(_) => {}
                }
                if k.post_roster(&dep, &d).is_ok() {
                    crate::logf!(
                        "kernel: {dep} had no roster (a restart?); it took its copy's again"
                    );
                    k.forget(&dep);
                }
            }
        }
    }

    /// the current roster's keys, its members' (but secrets') and its retired ones, that something a line holds is
    /// signed by (its grant, its certs and their notarizations): a re-signed roster of the serving copy names those it
    /// no longer has as members as retired, a roster of the other copy names the retired ones again; the others can go
    /// (a component that restarted with nothing signed by its old keys leaves none: a kernel that starts empty retires
    /// nothing)
    pub fn retired_in_use(&self) -> Vec<Identity> {
        let (ro, docs) = self.st.do_(|p| {
            let Some(cur) = &p.kernel_roster else {
                return (Roster::default(), vec![]);
            };
            let mut docs: Vec<(String, SDoc)> = vec![];
            for s in p.sessions.values() {
                let Some(l) = &s.kernel else { continue };
                if let Some(g) = l
                    .grant
                    .as_ref()
                    .filter(|g| g.by == "mover" || g.by == "merger")
                {
                    docs.push((g.by.clone(), g.grant.clone()));
                }
                for c in [&l.source_cert, &l.machine_cert].into_iter().flatten() {
                    if let Ok(cc) = jarvis_doc::peek_cert(c) {
                        docs.push((cc.signer, c.clone()));
                    }
                }
                for nz in [&l.source_nz, &l.machine_nz].into_iter().flatten() {
                    docs.push(("notarizer".into(), nz.clone()));
                }
            }
            (cur.roster(), docs)
        });
        let mut keys = ro.retired.clone();
        keys.extend(ro.members.iter().filter(|m| m.role != "secrets").cloned());
        keys.into_iter()
            .filter(|m| {
                docs.iter().any(|(role, d)| {
                    *role == m.role
                        && jarvis_sig::verify(&m.signing_key, d.payload.as_bytes(), &d.sig)
                })
            })
            .collect()
    }

    /// the root key's roster: the serving copy's (or the very first) replaces the current one; the other copy's starts
    /// the copy flip once every one of its components took it → (the answer, the status on an error)
    pub fn take_roster(
        self: &Arc<Self>,
        payload: &str,
        root_sig: &str,
    ) -> std::result::Result<Value, (u16, anyhow::Error)> {
        let (root, cur, flipping) = self.st.do_(|p| {
            (
                p.kernel_root_key.clone(),
                p.kernel_roster.clone(),
                p.kernel_flip
                    .as_ref()
                    .is_some_and(|f| !f.handoffs.is_empty()),
            )
        });
        if root.is_empty() {
            return Err((
                409,
                anyhow!("no root key registered (POST /api/kernel/root-key first)"),
            ));
        }
        let d = SDoc {
            payload: payload.into(),
            sig: root_sig.into(),
        };
        let ro = jarvis_sig::open_roster(&d, &root)
            .map_err(|e| anyhow!("{e}"))
            .and_then(|ro| check_filed_roster(&ro.copy, payload).map(|()| ro))
            .map_err(|e| (403, e))?;
        let serving = self.serving_copy();
        let next = cur.is_some() && ro.copy != serving;
        if let Some(cur) = cur.as_ref().filter(|_| next) {
            if flipping {
                // a component of the copy taking over restarted mid-flip: the frozen components hand their state to the
                // newer roster too (one that took a handoff already serves and takes no other)
                crate::logf!(
                    "kernel: a newer {} roster during the flip: the handoffs are made again for it",
                    ro.copy
                );
            }
            check_takeover(&ro, &cur.roster()).map_err(|e| (403, e))?;
        } else if ro.secrets_boot.is_some() {
            return Err((
                403,
                anyhow!("the serving copy's roster names its own secrets, no secretsBoot"),
            ));
        }
        let res = self.distribute_roster(&d, &ro.copy);
        let rc = RosterCurrent {
            copy: ro.copy.clone(),
            payload: payload.into(),
            sig: root_sig.into(),
            at: GoTime::now(),
            results: res.clone(),
            stale: BTreeMap::new(),
        };
        self.st.do_(|p| {
            if next {
                p.kernel_roster_next = Some(rc.clone());
            } else {
                if p.kernel_roster.is_none() {
                    p.kernel_copy = ro.copy.clone(); // the first roster names the copy that serves
                }
                p.kernel_roster = Some(rc.clone());
            }
            p.kernel_roster_pending = None;
        });
        ROSTER_DMED.store(false, Ordering::SeqCst);
        for (dep, msg) in &res {
            // one that restarted after the setup session read its identity
            if let Some(m) = msg.strip_prefix("refused: ") {
                self.roster_stale(
                    dep,
                    &format!("roster stale: component {dep} restarted ({m})"),
                );
            }
        }
        if let Some(k) = &self.kernel {
            k.forget_all(); // identities are read again (the roster may name new keys)
        }
        let id = d.id();
        crate::logf!(
            "kernel: the root key's roster {} for {} posted: {}",
            jarvis_go::fmt::clip_bytes(&id, 12),
            ro.copy,
            go_map_text(&res)
        );
        let mut out = json!({"ok": true, "id": id, "results": res});
        if next {
            // kernelflip.rs: it starts once every component of both copies is where the flip needs it
            self.start_flip(&ro.copy, &d.id());
            out["flip"] = json!(ro.copy);
        }
        self.kernel_health_check(); // kernelhealth.rs: the app's warning follows the new roster at once
        Ok(out)
    }
}

/// a map as Go's %v prints it: map[k:v k:v]
fn go_map_text(m: &BTreeMap<String, String>) -> String {
    let parts: Vec<String> = m.iter().map(|(k, v)| format!("{k}:{v}")).collect();
    format!("map[{}]", parts.join(" "))
}

fn setup_signed(
    f: impl Fn(&Arc<Router>, &mut W, &mut Req, &[u8]) + Send + Sync + 'static,
) -> impl Fn(&Arc<Router>, &mut W, &mut Req) + Send + Sync + 'static {
    move |r, w, req| {
        let b = req.read_body(1 << 20);
        if let Err(e) = r.check_setup_sig(
            &req.method,
            &req.path,
            &req.header("X-Setup-Time"),
            &req.header("X-Setup-Sig"),
            &b,
        ) {
            return write_json(w, 401, &json!({"error": format!("{e:#}")}));
        }
        f(r, w, req, &b)
    }
}

pub fn register_roster(reg: &mut Registrar) {
    reg.app("POST /api/kernel/root-key", |r, w, req| {
        #[derive(Deserialize)]
        struct In {
            #[serde(rename = "rootKey", default)]
            root_key: String,
        }
        let Ok(i) = crate::http::decode_body_strict::<In>(req, 1 << 16)
            .map_err(|_| ())
            .and_then(|i| {
                if valid_root_key(&i.root_key) {
                    Ok(i)
                } else {
                    Err(())
                }
            })
        else {
            return write_json(
                w,
                400,
                &json!({"error": "{rootKey}: a P-256 public key, base64 X9.63"}),
            );
        };
        r.st.do_(|p| p.kernel_root_key = i.root_key.clone());
        crate::logf!(
            "kernel: the app registered its root key {}…",
            jarvis_go::fmt::clip_bytes(&i.root_key, 16)
        );
        write_json(w, 200, &json!({"ok": true}));
    });
    reg.setup_route(
        "GET /setup/kernel/root-key",
        setup_signed(|r, w, _, _| {
            let k = r.st.do_(|p| p.kernel_root_key.clone());
            if k.is_empty() {
                return write_json(
                    w,
                    404,
                    &json!({"error": "the app hasn't registered its root key yet (Settings → Kernel)"}),
                );
            }
            write_json(w, 200, &json!({"rootKey": k}));
        }),
    );
    reg.setup_route(
        "GET /setup/kernel/roster",
        setup_signed(|r, w, _, _| {
            write_json(
                w,
                200,
                &json!({"current": r.current_roster(), "serving": r.serving_copy(), "retiredInUse": r.retired_in_use(),
                    "status": r.roster_status(), "health": r.kernel_health_view(), "flip": r.flip_status()}),
            );
        }),
    );
    reg.setup_route(
        "POST /setup/kernel/roster",
        setup_signed(|r, w, _, b| {
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct In {
                copy: String,
                payload: String,
                #[serde(rename = "setupSig")]
                setup_sig: String,
            }
            let Ok(i) = jarvis_go::unmarshal::<In>(b) else {
                return write_json(w, 400, &json!({"error": "{copy, payload, setupSig}"}));
            };
            if let Err(e) = check_filed_roster(&i.copy, &i.payload) {
                return write_json(w, 400, &json!({"error": format!("{e:#}")}));
            }
            if r.cfg.setup_key.is_empty()
                || !crate::http::verify_p256(&r.cfg.setup_key, i.payload.as_bytes(), &i.setup_sig)
            {
                return write_json(
                    w,
                    403,
                    &json!({"error": "setupSig: not the setup key's signature over the payload"}),
                );
            }
            r.st.do_(|p| {
                p.kernel_roster_pending = Some(RosterFiling {
                    copy: i.copy.clone(),
                    payload: i.payload.clone(),
                    setup_sig: i.setup_sig.clone(),
                    at: GoTime::now(),
                })
            });
            crate::logf!(
                "kernel: a roster for copy {} is filed, waiting for the root key",
                i.copy
            );
            let id = SDoc {
                payload: i.payload.clone(),
                sig: String::new(),
            }
            .id();
            write_json(w, 200, &json!({"ok": true, "id": id}));
        }),
    );
    reg.app("GET /api/kernel/roster/pending", |r, w, _| match r.st.do_(|p| p.kernel_roster_pending.clone()) {
        None => write_json(
            w,
            404,
            &json!({"error": "no roster filed (the setup session runs infra/setup.py kernel-roster)"}),
        ),
        Some(f) => write_json(w, 200, &f),
    });
    reg.app("GET /api/kernel/roster", |r, w, _| match r.st.do_(|p| p.kernel_roster.clone()) {
        None => write_json(w, 404, &json!({"error": "no roster signed yet"})),
        Some(c) => write_json(
            w,
            200,
            &json!({"copy": c.copy, "payload": c.payload, "sig": c.sig, "at": c.at, "results": c.results,
                "status": r.roster_status()}),
        ),
    });
    reg.app("POST /api/kernel/roster", |r, w, req| {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct In {
            payload: String,
            #[serde(rename = "rootSig")]
            root_sig: String,
        }
        let i = match crate::http::decode_body_strict::<In>(req, 1 << 20) {
            Ok(i) if !i.payload.is_empty() && !i.root_sig.is_empty() => i,
            _ => return write_json(w, 400, &json!({"error": "{payload, rootSig}"})),
        };
        if r.kernel.is_none() {
            return write_json(w, 503, &json!({"error": "this box runs no kernel yet"}));
        }
        match r.take_roster(&i.payload, &i.root_sig) {
            Err((code, e)) => write_json(w, code, &json!({"error": format!("{e:#}")})),
            Ok(out) => write_json(w, 200, &out),
        }
    });
}
