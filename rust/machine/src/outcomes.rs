//! Request outcomes (router/outcomes.go): what became of an Inbox request THIS session filed (approved, denied,
//! lapsed, dropped or failed). The text is built here from the session's own filing, exactly as one of this line's
//! machines signed it, and texts built into this image for each outcome; the router names only strict-format values per
//! item: the outcome (a word), an Inbox or session id, an HTTP status (a number), and a proof. An approval that leaves
//! a signed trace must carry it and it is checked here (a bad or missing proof refuses the whole delivery). An unlock
//! and an API call leave nothing signed, and a denial, a lapse, a drop or a failure is a non-event: those texts say
//! they are Jarvis's report. Deyao's own words never come through here.

use crate::cert::Cert;
use crate::crypto::{SignedDoc, read_trim, sha256_hex, verify_doc};
use crate::deliver::{DELIVERED_FILE, Delivery, SignedRequest, own_request_body};
use crate::grants::{Grant, current_cert};
use crate::kernelboot::read_kernel_trust;
use crate::util::go_quote;
use crate::{gojson, logf, paths, re, util};
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OutcomeItem {
    pub item: i64,
    pub outcome: String,
    #[serde(rename = "ref")]
    pub ref_: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub status: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<SignedDoc>,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// what the core attested (router/outcomes.go builds the same bytes)
#[derive(Serialize)]
struct OutcomeRecord {
    request: String,
    items: Vec<OutcomeRecordItem>,
}

#[derive(Serialize)]
struct OutcomeRecordItem {
    item: i64,
    outcome: String,
    #[serde(rename = "ref")]
    ref_: String,
    status: i64,
    proof: String,
}

re!(OUTCOME_REF_RE = r"^[a-z0-9-]{1,64}$");
re!(
    OUTCOME_PATH_RE = r"^/m/api/(?:actions/)?(requests/(?:repo/add|repo/remove|grant|unlock|add-store|call|peer|batch)|sessions|sessions/[a-z0-9-]{1,64}/(?:wakeup|wakeups|crons|watches))$"
);
re!(OUTCOME_SPACE = r"\s+");

/// tests give their own core key here
pub static TEST_CORE_KEY: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn outcome_core_key() -> Result<String> {
    if let Some(k) = TEST_CORE_KEY.lock().ok().and_then(|g| g.clone()) {
        return Ok(k);
    }
    read_trim(&paths::core_key_path())
}

const OUTCOME_FOOTER: &str = "This is Jarvis's checked record of the decision.";

/// one item of the filing, as the session signed it
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OutcomeAsked {
    pub intent: String,
    pub repo: String,
    pub holder: String,
    pub minutes: i64,
    pub days: i64,
    pub store: String,
    pub label: String,
    pub prompt: String,
    pub method: String,
    pub path: String,
    pub summary: String,
    pub sensitive: bool,
    /// repo/add: the store isn't to come into this session
    #[serde(rename = "noStore")]
    pub no_store: bool,
    /// peer: the session it was for
    pub to: String,
    /// wakeup, cron, watch: its name (a wakeup's may be a number)
    pub name: Option<serde_json::Value>,
}

/// the session's own words, on one line and capped
pub fn short(s: &str, n: usize) -> String {
    let s = OUTCOME_SPACE.replace_all(s, " ").trim().to_string();
    if s.chars().count() > n {
        return s.chars().take(n).collect::<String>() + "…";
    }
    s
}

impl OutcomeAsked {
    /// a wakeup's, cron's or watch's name as its message shows it ("default" when it has none)
    fn armed_name(&self) -> String {
        let n = match &self.name {
            None => return "default".into(),
            Some(v) => util::go_sprint(v).trim().to_string(),
        };
        if n.is_empty() {
            "default".into()
        } else {
            short(&n, 40)
        }
    }

    fn describe(&self) -> String {
        match self.intent.as_str() {
            "repo/add" => format!(
                "a deploy key (read + push) for the repo {}",
                go_quote(&short(&self.repo, 200))
            ),
            "repo/remove" => format!(
                "removing the deploy key of the repo {}",
                go_quote(&short(&self.repo, 200))
            ),
            "grant" => {
                if self.days > 0 {
                    return format!(
                        "a standing rule letting {} into this session for {} days",
                        go_quote(&short(&self.holder, 40)),
                        self.days
                    );
                }
                let m = if self.minutes == 0 { 10 } else { self.minutes };
                format!(
                    "a grant letting {} into this session for {m} min",
                    go_quote(&short(&self.holder, 40))
                )
            }
            "unlock" => "unlocking the locked stores this session waits on".into(),
            "add-store" => format!(
                "adding the store {} to this session",
                go_quote(&short(&self.store, 80))
            ),
            "new-session" => format!("a new session {}", go_quote(&short(&self.label, 120))),
            "call" => format!(
                "the app API call {} {}",
                short(&self.method, 10),
                short(&self.path, 300)
            ),
            "peer" => format!(
                "your message to session {}",
                go_quote(&short(&self.to, 120))
            ),
            "wakeup" => format!(
                "the message of this session's wakeup {} (Deyao approves each message into this session)",
                go_quote(&self.armed_name())
            ),
            "cron" => format!(
                "a run's message of this session's recurring wakeup {} (Deyao approves each message into this session)",
                go_quote(&self.armed_name())
            ),
            "watch" => format!(
                "the message of this session's watch {} (Deyao approves each message into this session)",
                go_quote(&self.armed_name())
            ),
            _ => "a request".into(),
        }
    }
}

/// the filing's items by index (a single request is item 0), a batch's summary, whether it is a batch
pub fn outcome_filing(
    r: &SignedRequest,
    keys: &[String],
) -> Result<(HashMap<i64, OutcomeAsked>, String, bool)> {
    let body = own_request_body(Some(r), keys)?;
    let m = OUTCOME_PATH_RE.captures(&r.path);
    let (true, Some(m)) = (r.method == "POST", m) else {
        bail!("the signed request isn't one of this session's Inbox filings");
    };
    let what = m[1].to_string();
    if what == "requests/batch" {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct B {
            summary: String,
            items: Vec<serde_json::Value>,
        }
        let b: B = match gojson::unmarshal::<B>(&body) {
            Ok(b) if !b.items.is_empty() => b,
            _ => bail!("the signed batch has no items"),
        };
        let mut out = HashMap::new();
        for (i, raw) in b.items.iter().enumerate() {
            let a: OutcomeAsked = gojson::unmarshal(raw.to_string().as_bytes()).unwrap_or_default();
            out.insert(i as i64, a);
        }
        return Ok((out, short(&b.summary, 300), true));
    }
    let mut a: OutcomeAsked =
        gojson::unmarshal(&body).map_err(|_| anyhow!("the signed request isn't JSON"))?;
    if what == "sessions" {
        a.intent = "new-session".into();
    } else if what.starts_with("sessions/") {
        // a message of the session's own wakeup, cron or watch (messages.rs)
        a.intent = match what.rsplit('/').next().unwrap_or("") {
            "wakeup" | "wakeups" => "wakeup",
            "crons" => "cron",
            "watches" => "watch",
            _ => "",
        }
        .into();
    } else {
        a.intent = what.strip_prefix("requests/").unwrap_or(&what).to_string();
    }
    Ok((HashMap::from([(0, a)]), String::new(), false))
}

/// owner/name, lower case, from the forms the router takes (owner/name, https or ssh URL, .git)
pub fn repo_name(s: &str) -> String {
    let mut s = s.trim().to_lowercase();
    for p in [
        "https://github.com/",
        "http://github.com/",
        "git@github.com:",
        "ssh://git@github.com/",
        "github.com/",
    ] {
        if let Some(r) = s.strip_prefix(p) {
            s = r.to_string();
        }
    }
    let s = s.strip_suffix('/').unwrap_or(&s);
    s.strip_suffix(".git").unwrap_or(s).to_string()
}

/// an approval's checked proof → what it established (a sentence), or an error refusing the delivery
pub fn outcome_result(a: &OutcomeAsked, it: &OutcomeItem, cert: &Cert) -> Result<String> {
    let need = || -> Result<&SignedDoc> {
        it.proof.as_ref().ok_or_else(|| {
            anyhow!(
                "an approval of {} needs its signed proof, and none came",
                a.intent
            )
        })
    };
    match a.intent.as_str() {
        "grant" => {
            let p = need()?;
            let g: Grant = match (cert.phone.is_empty(), verify_doc(&cert.phone, Some(p))) {
                (false, Ok(g)) => g,
                _ => bail!("the grant isn't the phone's, for this session"),
            };
            if g.session != cert.line || g.scope != "shell" {
                bail!("the grant isn't the phone's, for this session");
            }
            if g.kind == "rule" {
                return Ok(format!("Checked: the phone signed a standing rule for this session until {}.", g.until));
            }
            Ok(format!("Checked: the phone signed a grant for this session until {} (UTC).", g.expires))
        }
        "add-store" => {
            let p = need()?;
            let s = go_quote(&a.store);
            if read_kernel_trust().is_some() {
                // a kernel line: the grant this machine's own reload checked names the store; until the reload has
                // run, the delivery is refused and the router tries it again
                if !cert.stores().contains(&a.store) {
                    bail!("this machine's checked grant doesn't name the store {s} (yet)");
                }
                return Ok(format!("Checked: this machine's grant from the kernel names the store {s}, and the supervisor pulls it by itself; run a command with the keys it needs as `session-secret --keys K1,K2 --exec CMD` (this shell's env doesn't change; `pull-secrets` makes the supervisor pull again now)."));
            }
            let key = outcome_core_key()?;
            let c: Cert = match verify_doc(&key, Some(p)) {
                Ok(c) => c,
                Err(_) => bail!("the proof isn't a core-signed cert of this machine"),
            };
            match (&c.machine, &cert.machine) {
                (Some(m1), Some(m2)) if m1.id == m2.id => {}
                _ => bail!("the proof isn't a core-signed cert of this machine"),
            }
            if c.stores().contains(&a.store) {
                return Ok(format!("Checked: this machine's new core-signed cert names the store {s}. If `jarvis-request add-store` filed it, a background waiter has the supervisor pull it by itself (~/.jarvis-await-{}.log); then run a command with the keys it needs as `session-secret --keys K1,K2 --exec CMD` (this shell's env doesn't change; `pull-secrets` makes the supervisor pull again now).", a.store));
            }
            bail!("the cert doesn't name the store")
        }
        "new-session" => {
            let p = need()?;
            if read_kernel_trust().is_some() {
                return Ok(format!("This is Jarvis's report (on the kernel nothing here can check it): Deyao approved the proposed session. Its session id is {}; it is starting now.", it.ref_));
            }
            let key = outcome_core_key()?;
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct Opts {
                config: String,
            }
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct Req {
                predecessor: Option<SignedDoc>,
                options: Opts,
            }
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct Ap {
                kind: String,
                by: String,
                request: Req,
            }
            let ap: Ap = match verify_doc(&key, Some(p)) {
                Ok(ap) => ap,
                Err(_) => bail!("the proof isn't the core's approval, by the phone, of a new line"),
            };
            if ap.kind != "approval" || ap.by != "phone" || ap.request.predecessor.is_some() {
                bail!("the proof isn't the core's approval, by the phone, of a new line");
            }
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct Cfg {
                label: String,
                prompt: String,
            }
            match gojson::unmarshal::<Cfg>(ap.request.options.config.as_bytes()) {
                Ok(cfg) if cfg.label == a.label && cfg.prompt == a.prompt => {}
                _ => bail!("the approved session isn't the one this session proposed"),
            }
            Ok(format!("Checked: the core's approval (by the phone) of a new session with this proposal's title and prompt. Its session id is {}; it is starting now.", it.ref_))
        }
        "repo/add" | "repo/remove" => {
            if read_kernel_trust().is_some() {
                if a.intent == "repo/remove" {
                    return Ok("This is Jarvis's report (nothing signed reaches this machine on the kernel): the deploy key was removed.".into());
                }
                return Ok("This is Jarvis's report (nothing signed reaches this machine on the kernel): the deploy key was added, in a store of its own. Unless the request said --no-store, that store comes into this session in the same approval and the waiter `jarvis-request add-repo` started sets up the repo's SSH key (~/.jarvis-await-github-*.log).".into());
            }
            let p = need()?;
            let key = outcome_core_key()?;
            #[derive(Deserialize, Default)]
            #[serde(default)]
            struct K {
                kind: String,
                repo: String,
            }
            let want = if a.intent == "repo/add" { "deploy-key-added" } else { "deploy-key-removed" };
            match verify_doc::<K>(&key, Some(p)) {
                Ok(k) if k.kind == want && repo_name(&k.repo) == repo_name(&a.repo) => {}
                _ => bail!("the proof isn't the core's key answer for that repo"),
            }
            if a.intent == "repo/add" {
                if a.no_store {
                    return Ok("Checked: the core's signed answer says the deploy key was added. It is in a store of its own, which no session holds until it is added to one (`jarvis-request add-store <that store>`; the app's Repos list names it).".into());
                }
                return Ok("Checked: the core's signed answer says the deploy key was added, in a store of its own. That store comes into this session in the same approval (while it runs): the waiter `jarvis-request add-repo` started has the supervisor pull it and set up the repo's SSH key by itself (~/.jarvis-await-github-*.log). If it hasn't arrived (this session wasn't running, or the app asked for it separately and it lapsed), ask for it with `jarvis-request add-store <that store>`.".into());
            }
            Ok("Checked: the core's signed answer says the deploy key was removed.".into())
        }
        "unlock" => Ok("Nothing signed comes with an unlock: this is Jarvis's report. The stores open by themselves once the unlock is through (the machine's secrets pull retries).".into()),
        "peer" => Ok("Nothing signed comes with it: this is Jarvis's report. The message went to that session, wrapped with this session as its verified sender.".into()),
        "call" => Ok(format!("Nothing signed comes with an API call's approval: this is Jarvis's report. The call ran as Deyao and answered HTTP {}; read its result within 10 minutes: GET $JARVIS_URL/api/actions/requests/call/{}.", it.status, it.ref_)),
        _ => Ok("Nothing signed comes with it: this is Jarvis's report.".into()),
    }
}

/// one item's sentence (the outcome's fixed text over what was asked)
pub fn outcome_line(a: &OutcomeAsked, it: &OutcomeItem, cert: &Cert) -> Result<String> {
    let what = a.describe();
    let r = &it.ref_;
    Ok(match it.outcome.as_str() {
        "approved" => format!(
            "APPROVED: {what} (Inbox {r}). {}",
            outcome_result(a, it, cert)?
        ),
        "denied" => format!(
            "DENIED: {what} (Inbox {r}). Deyao denied it, as Jarvis reports (a denial leaves nothing signed). Don't file the same again unchanged; carry on without it, or tell Deyao in the chat why it is needed."
        ),
        "lapsed" => format!(
            "LAPSED: {what} (Inbox {r}). Nobody answered it within 10 minutes, so it left the Inbox, as Jarvis reports. That is not a refusal: Deyao may not have seen it. File it again if it is still needed."
        ),
        "dropped" => format!(
            "DROPPED: {what} (Inbox {r}). It left the Inbox without a decision, as Jarvis reports (this session paused or ran on another machine, or what it was about went away). File it again if it is still needed."
        ),
        "failed" => format!(
            "FAILED: {what} (Inbox {r}). It was approved but carrying it out failed, as Jarvis reports. Check the state yourself and file it again if it is still needed."
        ),
        o => bail!("not an outcome: {}", go_quote(o)),
    })
}

/// the request-outcome delivery's text and the bytes the core attested
pub fn outcome_text(d: &Delivery, keys: &[String]) -> Result<(String, Vec<u8>)> {
    let Some(req) = &d.request else {
        bail!("request-outcome: no request or items")
    };
    if d.outcomes.is_empty() || d.outcomes.len() > 20 {
        bail!("request-outcome: no request or items");
    }
    let (items, summary, batch) = outcome_filing(req, keys)?;
    let cert = current_cert().map_err(|e| anyhow!("no valid cert: {e:#}"))?;
    let mut list = d.outcomes.clone();
    list.sort_by_key(|i| i.item);
    let mut rec = OutcomeRecord {
        request: req.sig.clone(),
        items: vec![],
    };
    let mut lines = vec![];
    let mut seen = std::collections::HashSet::new();
    for it in &list {
        let a = items.get(&it.item);
        let Some(a) = a.filter(|_| {
            !seen.contains(&it.item)
                && OUTCOME_REF_RE.is_match(&it.ref_)
                && (0..=999).contains(&it.status)
        }) else {
            bail!("request-outcome: not an item of the filing, or not an id or status");
        };
        seen.insert(it.item);
        let mut l = outcome_line(a, it, &cert)?;
        if batch {
            l = format!("{}. {l}", it.item + 1);
        }
        lines.push(l);
        rec.items.push(OutcomeRecordItem {
            item: it.item,
            outcome: it.outcome.clone(),
            ref_: it.ref_.clone(),
            status: it.status,
            proof: it.proof.as_ref().map(proof_hash).unwrap_or_default(),
        });
    }
    let attested = gojson::marshal(&rec).into_bytes();
    let t = if batch {
        format!(
            "Deyao's Inbox has decided {} of the {} items of the batch (its summary: {}):\n{}\n{OUTCOME_FOOTER}",
            lines.len(),
            items.len(),
            go_quote(&summary),
            lines.join("\n")
        )
    } else {
        format!("{} {OUTCOME_FOOTER}", lines[0])
    };
    Ok((t, attested))
}

pub fn proof_hash(p: &SignedDoc) -> String {
    sha256_hex(format!("{}\n{}", p.payload, p.sig).as_bytes())
}

fn read_delivered() -> BTreeMap<String, serde_json::Value> {
    std::fs::read(paths::home().join(DELIVERED_FILE))
        .ok()
        .and_then(|b| gojson::unmarshal(&b).ok())
        .unwrap_or_default()
}

fn untold(d: &Delivery, seen: &BTreeMap<String, serde_json::Value>) -> Vec<OutcomeItem> {
    let sig = d.request.as_ref().map(|r| r.sig.as_str()).unwrap_or("");
    d.outcomes
        .iter()
        .filter(|it| !seen.contains_key(&format!("outcome {sig} {}", it.item)))
        .cloned()
        .collect()
}

fn items_text(l: &[OutcomeItem]) -> String {
    format!(
        "[{}]",
        l.iter()
            .map(|i| (i.item + 1).to_string())
            .collect::<Vec<_>>()
            .join(" ")
    )
}

/// Each item of a filing is told once (the delivered file, which travels in the snapshot); a delivery whose items were
/// all told already is refused (the router replaying it). With record, the untold items are marked told.
pub fn outcome_not_replayed(d: &Delivery, now: i64, record: bool) -> Result<()> {
    let _g = crate::deliver::delivered_lock();
    let mut seen = read_delivered();
    let fresh = untold(d, &seen);
    if fresh.is_empty() {
        bail!(
            "the outcomes of this filing's items {} were all delivered already",
            items_text(&d.outcomes)
        );
    }
    if !record {
        return Ok(());
    }
    let sig = d
        .request
        .as_ref()
        .map(|r| r.sig.clone())
        .unwrap_or_default();
    for it in fresh {
        seen.insert(
            format!("outcome {sig} {}", it.item),
            serde_json::json!({"run": 0, "at": now}),
        );
    }
    util::write_file(
        &paths::home().join(DELIVERED_FILE),
        gojson::marshal(&seen).as_bytes(),
        0o600,
    )?;
    Ok(())
}

/// d with only the items not told yet, for the text the harness gets (the attestation covers the whole delivery and is
/// checked before); d itself when every item is new
pub fn outcome_fresh(d: &Delivery) -> Delivery {
    let fresh = {
        let _g = crate::deliver::delivered_lock();
        untold(d, &read_delivered())
    };
    if fresh.is_empty() || fresh.len() == d.outcomes.len() {
        return d.clone();
    }
    logf!(
        "request-outcome: items {} were told already; delivering {}",
        items_text(&d.outcomes),
        items_text(&fresh)
    );
    let mut d = d.clone();
    d.outcomes = fresh;
    d
}

/// The delivery's checked text, under each of its items' ids (an Inbox id, or this session's id for an add-store), as
/// <ref>.<unix ns>.json {"ref","outcome","text"}, readable by the session's user; the jarvis-request command that filed
/// it waits for a file of its request's id newer than its filing
pub fn record_outcome(d: &Delivery, text: &str, _now: i64) -> Result<()> {
    let dir = paths::outcomes_dir();
    std::fs::create_dir_all(&dir)?;
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for it in &d.outcomes {
        if !OUTCOME_REF_RE.is_match(&it.ref_) {
            bail!("request-outcome: not an id");
        }
        let b = gojson::marshal(&BTreeMap::from([
            ("outcome", it.outcome.as_str()),
            ("ref", it.ref_.as_str()),
            ("text", text),
        ]));
        let p = dir.join(format!("{}.{ns}.json", it.ref_));
        let tmp = dir.join(format!("{}.{ns}.json.tmp", it.ref_));
        util::write_file(&tmp, b.as_bytes(), 0o644)?;
        std::fs::rename(&tmp, &p)?;
    }
    Ok(())
}

/// an outcome of a request jarvis-request filed (requests/…, a proposed session): its command waits for it. A wakeup's,
/// cron's or watch's message denied when it came due has no command waiting: that stays a message.
pub fn filed_by_command(d: &Delivery) -> bool {
    let Some(r) = &d.request else { return false };
    OUTCOME_PATH_RE
        .captures(&r.path)
        .is_some_and(|m| m[1].starts_with("requests/") || &m[1] == "sessions")
}
