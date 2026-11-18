//! Discord (Jarvis 1 parity, its lib/discord.js): Jarvis 4 shares Jarvis 1's bot, lobster.
//!
//! ```text
//! DM       → r.dm(text) posts to Deyao's DM with the bot
//! create   → every session gets a text channel under its own category (DISCORD_SESSIONS_CATEGORY, default
//!            "Jarvis 4"; Jarvis 1's "Sessions" category and its channels are never touched), made when the router
//!            builds the machine's env (the env hooks), so a start or resume carries it as LOBSTER_CHANNEL and the
//!            session's lobster-send posts there. A resume reuses the channel; one deleted by hand is made again.
//!            name = a slug of the session's title, topic = "Jarvis 4 session <id>"
//! title    → a tick renames the channel when the session's title changes (Discord allows 2 name/topic edits per
//!            channel per 10 minutes; a third waits for the window)
//! destroy  → the channel's messages and attachments go into the session's archive (archivetar.rs),
//!            discord/{messages.json,attachments/<message id>-<file>}, then the channel is deleted. A failed export
//!            (or no archive) keeps the channel (Deyao gets a DM) and the destroy goes on.
//! ```
//!
//! Settings (router env): LOBSTER_TOKEN (without it nothing here runs and r.dm only logs), DISCORD_GUILD_ID,
//! DISCORD_DM_CHANNEL, DISCORD_SESSIONS_CATEGORY, DISCORD_SESSION_CHANNELS=off (DMs only).

use crate::router::{Router, env};
use crate::state::Session;
use crate::titles::session_title;
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, RwLock};
use std::time::Duration;

pub const DISCORD_API: &str = "https://discord.com/api/v10";
const DISCORD_UA: &str = "jarvis4-router (https://github.com/DE0CH/jarvis4, 1.0)";
/// Discord: 2 name/topic edits per 10 min per channel
const DISCORD_EDIT_WINDOW: time::Duration = time::Duration::minutes(10);
const DISCORD_EDITS_PER_WIN: usize = 2;
pub const DISCORD_MSG_LIMIT: usize = 2000;
const DISCORD_TICK_EVERY: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Default)]
struct ChanInfo {
    name: String,
    topic: String,
    edits: Vec<GoTime>,
}

#[derive(Default)]
struct DiscState {
    category_id: String,
    category_at: GoTime,
    /// channel id → what it was last seen as
    names: BTreeMap<String, ChanInfo>,
}

pub type SleepFn = Arc<dyn Fn(Duration) + Send + Sync>;
pub type NowFn = Arc<dyn Fn() -> GoTime + Send + Sync>;

pub struct DiscordClient {
    pub api: String,
    pub token: String,
    pub guild: String,
    pub dm: String,
    pub category: String,
    /// per-session channels on (DISCORD_SESSION_CHANNELS != off)
    pub channels: bool,
    http: reqwest::blocking::Client,
    /// a 429 asking for longer than this fails (the caller retries later)
    pub max_wait: Duration,
    pub sleep: SleepFn,
    pub now: NowFn,
    mu: Mutex<DiscState>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct DiscordChannel {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: i64,
    pub name: String,
    pub topic: String,
    pub guild_id: String,
    pub parent_id: String,
}

/// a 429 whose wait is longer than the client holds a call for
#[derive(Debug)]
pub struct DiscordRateLimited {
    pub method: String,
    pub path: String,
    pub wait: Duration,
}

impl std::fmt::Display for DiscordRateLimited {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let secs = Duration::from_secs((self.wait.as_millis() as u64 + 500) / 1000);
        write!(
            f,
            "discord rate limit on {} {}: retry in {}",
            self.method,
            self.path,
            jarvis_go::fmt::duration_string(secs)
        )
    }
}

impl std::error::Error for DiscordRateLimited {}

impl DiscordClient {
    pub fn new(api: &str, token: &str, guild: &str, dm: &str, category: &str, channels: bool) -> DiscordClient {
        DiscordClient {
            api: api.to_string(),
            token: token.to_string(),
            guild: guild.to_string(),
            dm: dm.to_string(),
            category: category.to_string(),
            channels,
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            max_wait: Duration::from_secs(30),
            sleep: Arc::new(std::thread::sleep),
            now: Arc::new(GoTime::now),
            mu: Mutex::new(DiscState::default()),
        }
    }

    pub fn from_env() -> Option<DiscordClient> {
        let token = std::env::var("LOBSTER_TOKEN").unwrap_or_default();
        if token.is_empty() {
            return None;
        }
        Some(DiscordClient::new(
            DISCORD_API,
            &token,
            &env("DISCORD_GUILD_ID", "1482150592414486748"),
            &env("DISCORD_DM_CHANNEL", "1531422588247474266"),
            &env("DISCORD_SESSIONS_CATEGORY", "Jarvis 4"),
            std::env::var("DISCORD_SESSION_CHANNELS").unwrap_or_default() != "off",
        ))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DiscState> {
        self.mu.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// one REST call. 429 → wait retry_after and try again, up to 3 times (a wait over max_wait fails at once with
    /// DiscordRateLimited). 404 → None, no error. The body is the raw JSON ({} for 204).
    pub fn req(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Option<Vec<u8>>> {
        let payload = body.map(jarvis_go::marshal);
        let mut i = 0;
        loop {
            let mut rb = self
                .http
                .request(reqwest::Method::from_bytes(method.as_bytes())?, format!("{}{path}", self.api))
                .header("Authorization", format!("Bot {}", self.token))
                .header("User-Agent", DISCORD_UA);
            if let Some(p) = &payload {
                rb = rb.header("Content-Type", "application/json").body(p.clone());
            }
            let resp = rb.send()?;
            let status = resp.status().as_u16();
            let ra = resp
                .headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let b = crate::util::read_limited(resp, 32 << 20);
            match status {
                429 if i < 3 => {
                    let wait = retry_after(&b, &ra);
                    if wait > self.max_wait {
                        return Err(DiscordRateLimited { method: method.into(), path: path.into(), wait }.into());
                    }
                    (self.sleep)(wait);
                    i += 1;
                    continue;
                }
                404 => return Ok(None),
                204 => return Ok(Some(b"{}".to_vec())),
                s if !(200..=299).contains(&s) => {
                    let t = String::from_utf8_lossy(&b).trim().to_string();
                    return Err(anyhow!(
                        "discord {s} on {method} {path}: {}",
                        jarvis_go::fmt::clip_bytes(&t, 200)
                    ));
                }
                _ => {}
            }
            return Ok(Some(if b.is_empty() { b"{}".to_vec() } else { b }));
        }
    }

    pub fn send(&self, channel: &str, text: &str) -> Result<()> {
        for part in split_message(text) {
            if self
                .req("POST", &format!("/channels/{channel}/messages"), Some(&json!({"content": part})))?
                .is_none()
            {
                return Err(anyhow!("discord channel {channel} not found"));
            }
        }
        Ok(())
    }

    // ---- the category and one channel's life ------------------------------------------------------------

    pub fn ensure_category(&self) -> Result<String> {
        {
            let g = self.lock();
            if !g.category_id.is_empty() && (self.now)().sub(&g.category_at) < time::Duration::hours(1) {
                return Ok(g.category_id.clone());
            }
        }
        let b = self.req("GET", &format!("/guilds/{}/channels", self.guild), None)?.unwrap_or_default();
        let all: Vec<DiscordChannel> = jarvis_go::unmarshal(&b).unwrap_or_default();
        let mut id = all
            .iter()
            .find(|c| c.kind == 4 && c.name.eq_ignore_ascii_case(&self.category))
            .map(|c| c.id.clone())
            .unwrap_or_default();
        if id.is_empty() {
            let b = self
                .req(
                    "POST",
                    &format!("/guilds/{}/channels", self.guild),
                    Some(&json!({"name": self.category, "type": 4})),
                )?
                .unwrap_or_default();
            match jarvis_go::unmarshal::<DiscordChannel>(&b) {
                Ok(c) if !c.id.is_empty() => id = c.id,
                _ => return Err(anyhow!("discord: the category wasn't made")),
            }
        }
        let mut g = self.lock();
        g.category_id = id.clone();
        g.category_at = (self.now)();
        Ok(id)
    }

    /// the channel if it still exists in OUR guild (one deleted by hand, or another guild's id, is gone)
    pub fn get_channel(&self, id: &str) -> Result<Option<DiscordChannel>> {
        if id.is_empty() {
            return Ok(None);
        }
        let Some(b) = self.req("GET", &format!("/channels/{id}"), None)? else { return Ok(None) };
        match jarvis_go::unmarshal::<DiscordChannel>(&b) {
            Ok(c) if c.guild_id == self.guild => Ok(Some(c)),
            _ => Ok(None),
        }
    }

    fn remember(&self, c: &DiscordChannel) {
        self.lock()
            .names
            .entry(c.id.clone())
            .or_insert_with(|| ChanInfo { name: c.name.clone(), topic: c.topic.clone(), edits: vec![] });
    }

    /// the channel a session carries when it still exists, else a new one under the category → (it, made now)
    pub fn ensure_channel(&self, id: &str, sid: &str, title: &str) -> Result<(DiscordChannel, bool)> {
        if let Some(cur) = self.get_channel(id)? {
            self.remember(&cur);
            return Ok((cur, false));
        }
        let parent = self.ensure_category()?;
        let b = self
            .req(
                "POST",
                &format!("/guilds/{}/channels", self.guild),
                Some(&json!({"name": channel_name(title, sid), "type": 0, "parent_id": parent, "topic": channel_topic(sid)})),
            )?
            .unwrap_or_default();
        match jarvis_go::unmarshal::<DiscordChannel>(&b) {
            Ok(c) if !c.id.is_empty() => {
                self.remember(&c);
                Ok((c, true))
            }
            _ => Err(anyhow!("discord: the channel wasn't made")),
        }
    }

    /// rename to match the title (and fix the topic) — one PATCH, only when something differs and fewer than 2 edits
    /// were made in the last 10 minutes. Returns true when it edited.
    pub fn sync_name(&self, id: &str, title: &str, sid: &str) -> Result<bool> {
        if !self.lock().names.contains_key(id) {
            let Some(c) = self.get_channel(id)? else { return Ok(false) };
            self.remember(&c);
        }
        let patch = {
            let mut g = self.lock();
            let Some(cur) = g.names.get_mut(id) else { return Ok(false) };
            let mut patch = Map::new();
            let want = channel_name(title, sid);
            if cur.name != want {
                patch.insert("name".into(), json!(want));
            }
            let want = channel_topic(sid);
            if cur.topic != want {
                patch.insert("topic".into(), json!(want));
            }
            let now = (self.now)();
            cur.edits.retain(|t| now.sub(t) < DISCORD_EDIT_WINDOW);
            if patch.is_empty() || cur.edits.len() >= DISCORD_EDITS_PER_WIN {
                return Ok(false);
            }
            cur.edits.push(now); // counted even if it fails: no hammering a rate-limited edit
            patch
        };
        let Some(b) = self.req("PATCH", &format!("/channels/{id}"), Some(&Value::Object(patch)))? else {
            return Ok(false);
        };
        if let Ok(c) = jarvis_go::unmarshal::<DiscordChannel>(&b)
            && !c.id.is_empty()
            && let Some(cur) = self.lock().names.get_mut(id)
        {
            cur.name = c.name;
            cur.topic = c.topic;
        }
        Ok(true)
    }

    pub fn delete_channel(&self, id: &str) -> Result<bool> {
        let r = self.req("DELETE", &format!("/channels/{id}"), None);
        self.lock().names.remove(id);
        Ok(r?.is_some())
    }

    // ---- export: every message + every attachment, oldest first --------------------------------------

    /// messages paged newest→oldest (limit 100, before=…) and written oldest first to messages.json; attachment
    /// bytes downloaded now (CDN links expire) to attachments/<message id>-<file>. A failed attachment is noted on its
    /// entry (exportError) and doesn't fail the export. None when the channel is already gone.
    pub fn export_channel(
        &self,
        id: &str,
        sink: &dyn ExportSink,
        fetch: &dyn Fn(&str) -> Result<Vec<u8>>,
    ) -> Result<Option<ExportResult>> {
        let Some(ch) = self.get_channel(id)? else { return Ok(None) };
        let mut all: Vec<Map<String, Value>> = vec![];
        let mut before = String::new();
        loop {
            let mut p = format!("/channels/{id}/messages?limit=100");
            if !before.is_empty() {
                p += &format!("&before={before}");
            }
            let b = self.req("GET", &p, None)?.unwrap_or_default();
            let page: Vec<Map<String, Value>> =
                serde_json::from_slice(&b).map_err(|e| anyhow!("discord messages: {e}"))?;
            if page.is_empty() {
                break;
            }
            let n = page.len();
            before = page[n - 1].get("id").and_then(Value::as_str).unwrap_or_default().to_string();
            all.extend(page);
            if n < 100 || before.is_empty() {
                break;
            }
        }
        all.reverse();
        let mut res = ExportResult { messages: all.len(), name: ch.name.clone(), ..Default::default() };
        for m in all.iter_mut() {
            let mid = m.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
            let Some(Value::Array(atts)) = m.get_mut("attachments") else { continue };
            for x in atts.iter_mut() {
                let Value::Object(a) = x else { continue };
                let s = |k: &str| a.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
                let mut name = s("filename");
                if name.is_empty() {
                    name = s("id");
                }
                let rel = format!("attachments/{mid}-{}", safe_file_name(&name));
                let u = s("url");
                let mut ct = s("content_type");
                if ct.is_empty() {
                    ct = "application/octet-stream".into();
                }
                match fetch(&u).and_then(|b| sink.put_bytes(&rel, &b, &ct)) {
                    Err(e) => {
                        a.insert("exportError".into(), json!(format!("{e:#}")));
                        res.attachments_failed += 1;
                    }
                    Ok(()) => {
                        a.insert("exported".into(), json!(rel));
                        res.attachments += 1;
                    }
                }
            }
        }
        let out = jarvis_go::fmt::marshal_indent1(&json!({
            "channel": {"id": ch.id, "name": ch.name, "topic": ch.topic, "guild": self.guild},
            "exportedAt": (self.now)().utc().rfc3339(), "messages": all,
        }));
        sink.put_bytes("messages.json", out.as_bytes(), "application/json")?;
        Ok(Some(res))
    }
}

/// Discord's JSON retry_after (seconds, fractional), else the Retry-After header, else 1 s
pub fn retry_after(body: &[u8], header: &str) -> Duration {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct R {
        retry_after: f64,
    }
    if let Ok(r) = serde_json::from_slice::<R>(body)
        && r.retry_after > 0.0
    {
        return Duration::from_secs_f64(r.retry_after);
    }
    if let Ok(f) = header.parse::<f64>()
        && f > 0.0
        && f.is_finite()
    {
        return Duration::from_secs_f64(f);
    }
    Duration::from_secs(1)
}

// ---- messages -------------------------------------------------------------------------------------------------

/// Discord's 2000-character limit, split on line breaks where possible
pub fn split_message(text: &str) -> Vec<String> {
    let mut out = vec![];
    let mut r: Vec<char> = text.chars().collect();
    while r.len() > DISCORD_MSG_LIMIT {
        let mut cut = DISCORD_MSG_LIMIT;
        let mut i = DISCORD_MSG_LIMIT;
        while i > DISCORD_MSG_LIMIT / 2 {
            if r[i - 1] == '\n' {
                cut = i;
                break;
            }
            i -= 1;
        }
        out.push(r[..cut].iter().collect());
        r.drain(..cut);
    }
    if !r.is_empty() {
        out.push(r.iter().collect());
    }
    out
}

// ---- names ----------------------------------------------------------------------------------------------------

/// Discord channel names are 1–100 chars, lower case; the slug keeps ascii letters/digits and CJK ideographs,
/// everything else becomes one dash (as Jarvis 1's)
pub fn channel_name(title: &str, sid: &str) -> String {
    use unicode_general_category::{GeneralCategory, get_general_category};
    let mut b = String::new();
    let mut dash = false;
    for c in title.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || ('\u{4e00}'..='\u{9fff}').contains(&c) {
            b.push(c);
            dash = false;
        } else if get_general_category(c) == GeneralCategory::NonspacingMark {
            continue; // a combining mark: dropped, as Jarvis 1's NFKD strip does
        } else if !dash {
            b.push('-');
            dash = true;
        }
    }
    let mut s = b.trim_matches('-').to_string();
    if s.chars().count() > 90 {
        s = s.chars().take(90).collect::<String>().trim_end_matches('-').to_string();
    }
    if s.is_empty() {
        let mut sid = sid.to_string();
        if sid.len() > 8 {
            sid = sid[sid.len() - 8..].to_string();
        }
        if sid.is_empty() {
            sid = "new".into();
        }
        s = format!("session-{sid}");
    }
    s
}

pub fn channel_topic(sid: &str) -> String {
    format!("Jarvis 4 session {sid}")
}

pub trait ExportSink {
    fn put_bytes(&self, rel: &str, b: &[u8], content_type: &str) -> Result<()>;
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExportResult {
    pub messages: usize,
    pub attachments: usize,
    pub attachments_failed: usize,
    pub name: String,
}

pub fn safe_file_name(s: &str) -> String {
    s.chars()
        .map(|c| if r#"/\:*?"<>|"#.contains(c) || (c as u32) < 0x20 { '_' } else { c })
        .take(120)
        .collect()
}

pub fn http_fetch(u: &str) -> Result<Vec<u8>> {
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?
        .get(u)
        .send()?;
    let st = resp.status().as_u16();
    if st != 200 {
        return Err(anyhow!("HTTP {st}"));
    }
    Ok(resp.bytes()?.to_vec())
}

// ---- the router side ------------------------------------------------------------------------------------------

/// the bot (None without LOBSTER_TOKEN); tests set their own
pub static DISC: RwLock<Option<Arc<DiscordClient>>> = RwLock::new(None);
pub type FetchFn = Arc<dyn Fn(&str) -> Result<Vec<u8>> + Send + Sync>;
pub static DISC_FETCH: LazyLock<RwLock<FetchFn>> = LazyLock::new(|| RwLock::new(Arc::new(http_fetch)));
/// tests catch DMs here instead of the bot
pub type DmHook = Arc<dyn Fn(&str) + Send + Sync>;
pub static DM_HOOK: RwLock<Option<DmHook>> = RwLock::new(None);

pub fn disc() -> Option<Arc<DiscordClient>> {
    DISC.read().unwrap_or_else(|e| e.into_inner()).clone()
}

static DISCORD_STARTED: OnceLock<()> = OnceLock::new();

/// the export of each destroyed session's channel, so the destroy hook deletes it: Ok = in its archive
static DISCORD_EXPORTS: LazyLock<Mutex<BTreeMap<String, std::result::Result<ExportResult, String>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

impl Router {
    /// a message to Deyao's Discord DM; without a bot token it only logs
    pub fn dm(&self, text: &str) {
        if let Some(h) = DM_HOOK.read().unwrap_or_else(|e| e.into_inner()).clone() {
            h(text);
            return;
        }
        if let Some(d) = disc() {
            let text = text.to_string();
            std::thread::spawn(move || {
                if let Err(e) = d.send(&d.dm, &text) {
                    crate::logf!("[discord] DM not sent: {e:#}");
                }
            });
            return;
        }
        crate::logf!("[dm] {text}");
    }

    pub fn start_discord(self: &Arc<Self>) {
        if DISCORD_STARTED.set(()).is_err() {
            return;
        }
        let Some(d) = DiscordClient::from_env().map(Arc::new) else {
            crate::logf!("[discord] no LOBSTER_TOKEN: no DMs, no session channels");
            return;
        };
        let channels = d.channels;
        *DISC.write().unwrap_or_else(|e| e.into_inner()) = Some(d);
        if !channels {
            crate::logf!("[discord] DISCORD_SESSION_CHANNELS=off: DMs only");
            return;
        }
        let r = self.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(DISCORD_TICK_EVERY);
                crate::leaderlease::await_lead();
                r.discord_tick();
            }
        });
    }

    /// channels follow their sessions' titles; a running session without one (Discord was down when it started) gets
    /// one, so its destroy has something to export (its env can't change: it keeps DMing)
    pub fn discord_tick(&self) {
        let Some(disc) = disc().filter(|d| d.channels) else { return };
        let list: Vec<Session> = self.st.do_(|d| d.sessions.values().cloned().collect());
        for s in list {
            if matches!(s.state.as_str(), "destroying" | "destroyed" | "approval")
                || crate::tasks::is_task_harness(&s.harness)
            {
                continue;
            }
            if s.discord_channel.is_empty() {
                if s.machine_id.is_empty() || s.state != "started" {
                    continue;
                }
                match disc.ensure_channel("", &s.id, &session_title(&s)) {
                    Err(e) => crate::logf!("[discord] {}: no channel: {e:#}", s.id),
                    Ok((ch, _)) => {
                        self.st.do_(|d| {
                            if let Some(x) = d.sessions.get_mut(&s.id) {
                                x.discord_channel = ch.id.clone();
                            }
                        });
                        crate::logf!("[discord] {}: channel #{} made for a session that had none", s.id, ch.name);
                    }
                }
                continue;
            }
            match disc.sync_name(&s.discord_channel, &session_title(&s), &s.id) {
                Err(e) => {
                    if e.downcast_ref::<DiscordRateLimited>().is_none() {
                        crate::logf!("[discord] {}: rename failed: {e:#}", s.id);
                    }
                }
                Ok(true) => crate::logf!(
                    "[discord] {}: channel renamed to #{}",
                    s.id,
                    channel_name(&session_title(&s), &s.id)
                ),
                Ok(false) => {}
            }
        }
    }

    /// the session's channel exported into a local dir (tmp/discord) for its archive (archivetar.rs); None when it has
    /// no channel, the channel is gone, or the export failed (then the channel is kept and Deyao told, by
    /// discord_destroy). The returned done(archived) notes whether the archive holding it reached the Storage Box.
    pub fn discord_export(&self, s: &Session, tmp: &Path) -> (Option<PathBuf>, Box<dyn FnOnce(Option<String>) + Send>) {
        let none: Box<dyn FnOnce(Option<String>) + Send> = Box::new(|_| {});
        let Some(disc) = disc() else { return (None, none) };
        if s.discord_channel.is_empty() {
            return (None, none);
        }
        let dir = tmp.join("discord");
        let fetch = DISC_FETCH.read().unwrap_or_else(|e| e.into_inner()).clone();
        let sink = DirSink { dir: dir.clone() };
        match disc.export_channel(&s.discord_channel, &sink, &*fetch) {
            Err(e) => {
                crate::logf!("[discord] {}: channel {} NOT exported: {e:#}", s.id, s.discord_channel);
                exports().insert(s.id.clone(), Err(format!("{e:#}")));
                (None, none)
            }
            Ok(None) => (None, none),
            Ok(Some(res)) => {
                let sid = s.id.clone();
                (
                    Some(dir),
                    Box::new(move |archived: Option<String>| {
                        let v = match archived {
                            Some(e) => Err(format!("its archive failed: {e}")),
                            None => Ok(res),
                        };
                        exports().insert(sid, v);
                    }),
                )
            }
        }
    }
}

fn exports() -> std::sync::MutexGuard<'static, BTreeMap<String, std::result::Result<ExportResult, String>>> {
    DISCORD_EXPORTS.lock().unwrap_or_else(|e| e.into_inner())
}

/// the env hook: at every start/resume the session's channel (the one it carries, or a new one) goes into the
/// machine's env as LOBSTER_CHANNEL. Best effort: Discord being down mustn't stop a session (the session's
/// lobster-send then DMs).
pub fn discord_env(r: &Arc<Router>, s: &Session, e: &mut BTreeMap<String, String>) {
    let Some(disc) = disc().filter(|d| d.channels) else { return };
    if crate::tasks::is_task_harness(&s.harness) {
        return; // task lines report to their run records and the DM
    }
    let (ch, created) = match disc.ensure_channel(&s.discord_channel, &s.id, &session_title(s)) {
        Err(err) => {
            crate::logf!("[discord] {}: no channel: {err:#}", s.id);
            return;
        }
        Ok(x) => x,
    };
    if ch.id != s.discord_channel {
        r.st.do_(|d| {
            if let Some(x) = d.sessions.get_mut(&s.id) {
                x.discord_channel = ch.id.clone();
            }
        });
    }
    if created {
        crate::logf!("[discord] {}: channel #{} made", s.id, ch.name);
    }
    e.insert("LOBSTER_CHANNEL".into(), ch.id);
}

/// the destroy hook: the channel goes once its archive holds it; otherwise it is kept and Deyao told
pub fn discord_destroy(r: &Arc<Router>, s: &Session) {
    let Some(disc) = disc().filter(|d| d.channels) else { return };
    if s.discord_channel.is_empty() {
        return;
    }
    let v = exports().remove(&s.id);
    let res = match v {
        Some(Ok(res)) => res,
        other => {
            let why = match other {
                Some(Err(e)) => e,
                _ => "the session has no archive".to_string(),
            };
            crate::logf!("[discord] {}: channel {} NOT exported, kept: {why}", s.id, s.discord_channel);
            r.dm(&format!(
                "Jarvis 4: the Discord channel of destroyed session {} wasn't exported ({why}); it is kept: https://discord.com/channels/{}/{}",
                jarvis_go::fmt::go_quote(&session_title(s)),
                disc.guild,
                s.discord_channel
            ));
            return;
        }
    };
    if let Err(e) = disc.delete_channel(&s.discord_channel) {
        crate::logf!("[discord] {}: channel {} exported but NOT deleted: {e:#}", s.id, s.discord_channel);
        return;
    }
    crate::logf!(
        "[discord] {}: channel #{} exported ({} message(s), {} attachment(s), {} failed) and deleted",
        s.id,
        res.name,
        res.messages,
        res.attachments,
        res.attachments_failed
    );
}

/// the export's files under a local dir
pub struct DirSink {
    pub dir: PathBuf,
}

impl ExportSink for DirSink {
    fn put_bytes(&self, rel: &str, b: &[u8], _: &str) -> Result<()> {
        let p = self.dir.join(rel);
        if let Some(parent) = p.parent() {
            crate::util::mkdir_all_0700(parent)?;
        }
        crate::util::write_file_0600(&p, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_splits() {
        assert_eq!(channel_name("Fix the Café bill!", "s1"), "fix-the-caf-bill");
        assert_eq!(channel_name("深圳 trip", "s1"), "深圳-trip");
        assert_eq!(channel_name("!!!", "abcdef0123456789"), "session-23456789");
        assert_eq!(channel_name("", ""), "session-new");
        let long = "a\n".repeat(1500);
        let parts = split_message(&long);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].chars().count() <= DISCORD_MSG_LIMIT && parts[0].ends_with('\n'));
        assert_eq!(parts.concat(), long);
        assert_eq!(retry_after(br#"{"retry_after": 1.5}"#, ""), Duration::from_millis(1500));
        assert_eq!(retry_after(b"", "2"), Duration::from_secs(2));
        assert_eq!(retry_after(b"", ""), Duration::from_secs(1));
    }
}
