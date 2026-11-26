//! discord_test.go
use crate::discord::{
    DISC_FETCH, DiscordClient, DiscordRateLimited, ExportSink, channel_name, discord_destroy,
    discord_env, split_message,
};
use crate::state::Session;
use crate::testutil::*;
use crate::titles::session_title;
use jarvis_go::GoTime;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// just enough of Discord's REST API, in memory
#[derive(Default)]
pub struct FakeDiscordState {
    pub channels: BTreeMap<String, Value>,
    /// channel → newest first
    pub messages: BTreeMap<String, Vec<Value>>,
    pub posted: BTreeMap<String, Vec<String>>,
    pub calls: Vec<String>,
    /// "METHOD path" → 429s still to answer
    pub rate: BTreeMap<String, u32>,
    pub next: u64,
}

pub struct FakeDiscord {
    pub st: Arc<Mutex<FakeDiscordState>>,
    pub srv: TestServer,
}

impl FakeDiscord {
    pub fn lock(&self) -> std::sync::MutexGuard<'_, FakeDiscordState> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn channel(&self, id: &str) -> Option<Value> {
        self.lock().channels.get(id).cloned()
    }

    pub fn name_of(&self, id: &str) -> String {
        self.channel(id)
            .map(|c| c["name"].as_str().unwrap_or_default().to_string())
            .unwrap_or_default()
    }

    pub fn add_channel(&self, c: Value) {
        let id = c["id"].as_str().unwrap_or_default().to_string();
        self.lock().channels.insert(id, c);
    }
}

pub fn fake_discord() -> FakeDiscord {
    let st = Arc::new(Mutex::new(FakeDiscordState {
        next: 100,
        ..Default::default()
    }));
    let s2 = st.clone();
    let srv = TestServer::handler(move |w, req| {
        let body: Map<String, Value> =
            serde_json::from_slice(&req.read_body(1 << 20)).unwrap_or_default();
        let mut f = s2.lock().unwrap_or_else(|e| e.into_inner());
        let key = format!("{} {}", req.method, req.path);
        f.calls.push(key.clone());
        if req.header("Authorization") != "Bot tok" {
            w.write_header(401);
            return;
        }
        if let Some(n) = f.rate.get_mut(&key).filter(|n| **n > 0) {
            *n -= 1;
            w.write_header(429);
            w.write_str(r#"{"retry_after":0.25,"global":false}"#);
            return;
        }
        let p: Vec<String> = req
            .path
            .trim_matches('/')
            .split('/')
            .map(String::from)
            .collect();
        let s = |k: &str| {
            body.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let mut out = |v: &Value| {
            w.write_str(&jarvis_go::marshal(v));
        };
        let m = req.method.as_str();
        match (
            p.len(),
            p.first().map(String::as_str),
            p.get(2).map(String::as_str),
            m,
        ) {
            (3, Some("guilds"), _, "GET") => {
                let list: Vec<Value> = f
                    .channels
                    .values()
                    .filter(|c| c["guild_id"] == json!(p[1]))
                    .cloned()
                    .collect();
                out(&json!(list));
            }
            (3, Some("guilds"), _, "POST") => {
                f.next += 1;
                let c = json!({"id": f.next.to_string(), "guild_id": p[1], "name": s("name"), "topic": s("topic"),
                    "parent_id": s("parent_id"), "type": body.get("type").and_then(Value::as_i64).unwrap_or(0)});
                let id = f.next.to_string();
                f.channels.insert(id, c.clone());
                out(&c);
            }
            (2, Some("channels"), _, _) => {
                let Some(c) = f.channels.get_mut(&p[1]) else {
                    w.write_header(404);
                    return;
                };
                match m {
                    "PATCH" => {
                        for k in ["name", "topic"] {
                            if let Some(v) = body.get(k).and_then(Value::as_str) {
                                c[k] = json!(v);
                            }
                        }
                        out(&c.clone());
                    }
                    "DELETE" => {
                        let c = c.clone();
                        f.channels.remove(&p[1]);
                        out(&c);
                    }
                    _ => out(&c.clone()),
                }
            }
            (3, Some("channels"), Some("messages"), "POST") => {
                f.posted.entry(p[1].clone()).or_default().push(s("content"));
                out(&json!({"id": "m"}));
            }
            (3, Some("channels"), Some("messages"), "GET") => {
                let all = f.messages.get(&p[1]).cloned().unwrap_or_default();
                let limit: usize = req.query("limit").parse().unwrap_or(0);
                let mut start = 0;
                let b = req.query("before");
                if !b.is_empty() {
                    for (i, m) in all.iter().enumerate() {
                        if m["id"] == json!(b) {
                            start = i + 1;
                        }
                    }
                }
                let end = (start + limit).min(all.len());
                out(&json!(all[start.min(end)..end]));
            }
            _ => {
                w.write_header(404);
            }
        }
    });
    FakeDiscord { st, srv }
}

fn test_discord() -> (FakeDiscord, Arc<DiscordClient>, Arc<Mutex<Vec<Duration>>>) {
    test_discord_at(Arc::new(GoTime::now))
}

fn test_discord_at(
    now: crate::discord::NowFn,
) -> (FakeDiscord, Arc<DiscordClient>, Arc<Mutex<Vec<Duration>>>) {
    let f = fake_discord();
    let slept: Arc<Mutex<Vec<Duration>>> = Arc::default();
    let s2 = slept.clone();
    let mut d = DiscordClient::new(&f.srv.url, "tok", "g1", "dm1", "Jarvis 4", true);
    d.sleep = Arc::new(move |x| s2.lock().unwrap_or_else(|e| e.into_inner()).push(x));
    d.now = now;
    (f, Arc::new(d), slept)
}

fn slept_of(s: &Mutex<Vec<Duration>>) -> Vec<Duration> {
    s.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

#[test]
fn channel_names() {
    for (input, want) in [
        (
            "Fix the Jarvis 4 router!",
            "fix-the-jarvis-4-router".to_string(),
        ),
        (
            "  --Cafe\u{301} de\u{301}ja\u{300} vu-- ",
            "cafe-deja-vu".to_string(),
        ), // decomposed: the marks drop
        ("深圳 hotel", "深圳-hotel".to_string()),
        ("", "session-89abcdef".to_string()),
        ("!!!", "session-89abcdef".to_string()),
        (&"a".repeat(120), "a".repeat(90)),
    ] {
        assert_eq!(
            channel_name(input, "s0123456789abcdef"),
            want,
            "channel_name({input:?})"
        );
    }
}

#[test]
fn session_title_order() {
    let mut s = Session {
        id: "s1".into(),
        label: "label".into(),
        title: "ai".into(),
        ..Default::default()
    };
    assert_eq!(session_title(&s), "label", "label should beat the AI title");
    s.user_title = "mine".into();
    assert_eq!(
        session_title(&s),
        "mine",
        "Deyao's rename should beat the label"
    );
    s.app_title = "the app's".into();
    assert_eq!(
        session_title(&s),
        "the app's",
        "the Claude app's title should beat everything (Jarvis 1's serverTitle)"
    );
    let ai = Session {
        id: "s1".into(),
        title: "ai".into(),
        ..Default::default()
    };
    let bare = Session {
        id: "s1".into(),
        ..Default::default()
    };
    assert!(
        session_title(&ai) == "ai" && session_title(&bare) == "s1",
        "fallbacks"
    );
}

#[test]
fn split_messages() {
    let text = format!("{}\n{}", "x".repeat(1500), "y".repeat(1000));
    let parts = split_message(&text);
    assert!(
        parts.len() == 2
            && parts[0] == format!("{}\n", "x".repeat(1500))
            && parts[1] == "y".repeat(1000),
        "split on the line break: {} parts",
        parts.len()
    );
    let parts = split_message(&"z".repeat(4500));
    assert!(
        parts.len() == 3 && parts[0].len() == 2000 && parts[2].len() == 500,
        "hard split: {} parts",
        parts.len()
    );
}

#[test]
fn rate_limit_retries() {
    let (f, d, slept) = test_discord();
    f.lock()
        .rate
        .insert("POST /channels/dm1/messages".into(), 2);
    d.send("dm1", "hello").unwrap_or_else(|e| panic!("{e:#}"));
    let s = slept_of(&slept);
    let posted = f.lock().posted.get("dm1").cloned().unwrap_or_default();
    assert!(
        posted.len() == 1 && s.len() == 2 && s[0] == Duration::from_millis(250),
        "posted {posted:?} slept {s:?}"
    );
    // a wait longer than max_wait fails at once, without sleeping
    let mut d2 = DiscordClient::new(&f.srv.url, "tok", "g1", "dm1", "Jarvis 4", true);
    let s2 = slept.clone();
    d2.sleep = Arc::new(move |x| s2.lock().unwrap_or_else(|e| e.into_inner()).push(x));
    d2.max_wait = Duration::from_millis(100);
    f.lock()
        .rate
        .insert("POST /channels/dm1/messages".into(), 1);
    let err = d2.send("dm1", "again").err();
    assert!(
        err.as_ref()
            .is_some_and(|e| e.downcast_ref::<DiscordRateLimited>().is_some())
            && slept_of(&slept).len() == 2,
        "err {err:?} slept {:?}",
        slept_of(&slept)
    );
    // always 429: gives up after 3 retries
    d2.max_wait = Duration::from_secs(60);
    f.lock()
        .rate
        .insert("POST /channels/dm1/messages".into(), 10);
    let err = d2.send("dm1", "x").err();
    assert!(
        err.as_ref()
            .is_some_and(|e| format!("{e:#}").contains("429")),
        "want a 429 error, got {err:?}"
    );
}

#[test]
fn ensure_channel_and_category() {
    let (f, d, _) = test_discord();
    // Jarvis 1's category exists and is left alone
    f.add_channel(json!({"id": "1", "type": 4, "name": "Sessions", "guild_id": "g1"}));
    let (ch, created) = d
        .ensure_channel("", "s1", "My task")
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(created);
    let cat = f.channel(&ch.parent_id).unwrap_or_default();
    assert!(
        cat["name"] == "Jarvis 4"
            && cat["type"] == 4
            && ch.name == "my-task"
            && ch.topic == "Jarvis 4 session s1",
        "channel {ch:?} category {cat}"
    );
    // the category is reused
    let (ch2, _) = d
        .ensure_channel("", "s2", "other")
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(ch2.parent_id, ch.parent_id, "a second category");
    // the carried channel is kept
    let (again, created) = d
        .ensure_channel(&ch.id, "s1", "My task")
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(!created && again.id == ch.id, "carried channel not reused");
    // deleted by hand → a new one
    f.lock().channels.remove(&ch.id);
    let (again, created) = d
        .ensure_channel(&ch.id, "s1", "My task")
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        created && again.id != ch.id,
        "a gone channel should be replaced"
    );
    // another guild's channel id → a new one
    f.add_channel(json!({"id": "999", "guild_id": "other"}));
    let (c, created) = d
        .ensure_channel("999", "s3", "x")
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        created && c.id != "999",
        "another guild's channel was reused"
    );
}

#[test]
fn sync_name_rename_limit() {
    let now = Arc::new(Mutex::new(
        GoTime::parse("2026-10-09T12:00:00Z").unwrap_or_default(),
    ));
    let n2 = now.clone();
    let (f, d, _) = test_discord_at(Arc::new(move || {
        *n2.lock().unwrap_or_else(|e| e.into_inner())
    }));
    let (ch, _) = d
        .ensure_channel("", "s1", "first")
        .unwrap_or_else(|e| panic!("{e:#}"));
    let patches = || {
        let want = format!("PATCH /channels/{}", ch.id);
        f.lock().calls.iter().filter(|c| **c == want).count()
    };
    let ok = d.sync_name(&ch.id, "first", "s1").unwrap_or(true);
    assert!(!ok && patches() == 0, "no change should not PATCH");
    for (i, title) in ["second", "third", "fourth"].iter().enumerate() {
        let ok = d
            .sync_name(&ch.id, title, "s1")
            .unwrap_or_else(|e| panic!("rename {i}: {e:#}"));
        assert_eq!(ok, i < 2, "rename {i}");
    }
    assert!(
        patches() == 2 && f.name_of(&ch.id) == "third",
        "2 renames per window: {} patches, name {}",
        patches(),
        f.name_of(&ch.id)
    );
    {
        let mut g = now.lock().unwrap_or_else(|e| e.into_inner());
        *g = g.add(crate::discord::DISCORD_EDIT_WINDOW + time::Duration::seconds(1));
    }
    let ok = d.sync_name(&ch.id, "fourth", "s1").unwrap_or(false);
    assert!(
        ok && f.name_of(&ch.id) == "fourth",
        "the window should reopen"
    );
    // a channel first seen after a router restart: learned with one GET
    d.forget_names();
    assert!(
        !d.sync_name(&ch.id, "fourth", "s1").unwrap_or(true),
        "unchanged after learning"
    );
}

#[derive(Default)]
struct MemSink {
    files: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl ExportSink for MemSink {
    fn put_bytes(&self, rel: &str, b: &[u8], _: &str) -> anyhow::Result<()> {
        self.files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(rel.into(), b.to_vec());
        Ok(())
    }
}

impl MemSink {
    fn get(&self, rel: &str) -> Vec<u8> {
        self.files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(rel)
            .cloned()
            .unwrap_or_default()
    }
}

#[test]
fn export_channel() {
    let (f, d, _) = test_discord();
    let (ch, _) = d
        .ensure_channel("", "s1", "t")
        .unwrap_or_else(|e| panic!("{e:#}"));
    // 150 messages, newest first as Discord pages them; two carry attachments, one of which fails
    let mut msgs = vec![];
    for i in (1..=150).rev() {
        let mut m = json!({"id": format!("{i:04}"), "content": format!("msg {i}")});
        if i == 3 {
            m["attachments"] = json!([{"id": "a1", "filename": "shot/1.png", "url": "ok://1", "content_type": "image/png"}]);
        }
        if i == 120 {
            m["attachments"] = json!([{"id": "a2", "filename": "x.txt", "url": "bad://2"}]);
        }
        msgs.push(m);
    }
    f.lock().messages.insert(ch.id.clone(), msgs);
    let sink = MemSink::default();
    let fetch = |u: &str| -> anyhow::Result<Vec<u8>> {
        if u == "ok://1" {
            Ok(b"PNG".to_vec())
        } else {
            Err(anyhow::anyhow!("HTTP 403"))
        }
    };
    let res = d
        .export_channel(&ch.id, &sink, &fetch)
        .unwrap_or_else(|e| panic!("{e:#}"))
        .unwrap_or_else(|| panic!("none"));
    assert!(
        res.messages == 150 && res.attachments == 1 && res.attachments_failed == 1,
        "{res:?}"
    );
    assert_eq!(
        sink.get("attachments/0003-shot_1.png"),
        b"PNG",
        "attachment not saved"
    );
    let out: Value = serde_json::from_slice(&sink.get("messages.json")).unwrap_or_default();
    let ms = out["messages"].as_array().cloned().unwrap_or_default();
    assert!(
        ms.len() == 150
            && ms[0]["id"] == "0001"
            && ms[149]["id"] == "0150"
            && out["channel"]["id"] == json!(ch.id),
        "messages not oldest first: {}",
        ms.len()
    );
    let a = &ms[2]["attachments"][0];
    let b = &ms[119]["attachments"][0];
    assert!(
        a["exported"] == "attachments/0003-shot_1.png" && b["exportError"] == "HTTP 403",
        "attachment notes: {a} {b}"
    );
    // a gone channel exports nothing
    let gone = d.export_channel("nope", &sink, &fetch);
    assert!(gone.as_ref().is_ok_and(Option::is_none), "gone channel");
}

/// destroy: the channel goes into the session's archive (discord_export into the archive's scratch dir), and is
/// deleted only once the archive holds it; a failed export, or no archive, keeps it and tells Deyao
#[test]
fn destroy_exports_and_deletes() {
    let _g = serial(); // DISC_FETCH is global
    let (f, d, _) = test_discord();
    let saved_fetch = std::mem::replace(
        &mut *DISC_FETCH.write().unwrap_or_else(|e| e.into_inner()),
        Arc::new(|_: &str| Ok(b"bytes".to_vec())),
    );
    struct Restore(Option<crate::discord::FetchFn>);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Some(f) = self.0.take() {
                *DISC_FETCH.write().unwrap_or_else(|e| e.into_inner()) = f;
            }
        }
    }
    let _restore = Restore(Some(saved_fetch));
    let t = new_test_router();
    let r = t.r.clone();
    *r.disc_hook.write().unwrap_or_else(|e| e.into_inner()) = Some(d.clone());
    let dms = capture_dm(&r);
    let dm_count = || dms.lock().unwrap_or_else(|e| e.into_inner()).len();
    let s = Session {
        id: "s1dx".into(),
        label: "My task".into(),
        created: GoTime::parse("2026-10-09T00:00:00Z").unwrap_or_default(),
        ..Default::default()
    };
    r.st.do_(|p| {
        p.sessions.insert(s.id.clone(), s.clone());
    });
    // start: a channel, its id in the env and on the session
    let mut env = BTreeMap::new();
    let mut copy = s.clone();
    discord_env(&r, &copy, &mut env);
    let stored = r.st.read(|p| {
        p.sessions
            .get("s1dx")
            .map(|x| x.discord_channel.clone())
            .unwrap_or_default()
    });
    assert!(
        env.get("LOBSTER_CHANNEL")
            .is_some_and(|c| !c.is_empty() && *c == stored),
        "env {env:?} stored {stored:?}"
    );
    f.lock().messages.insert(
        stored.clone(),
        vec![
            json!({"id": "2", "content": "done", "attachments": [{"id": "a", "filename": "f.txt", "url": "x"}]}),
            json!({"id": "1", "content": "hi"}),
        ],
    );
    copy.discord_channel = stored.clone();
    // no archive: the channel is kept and Deyao told
    discord_destroy(&r, &copy);
    assert!(
        f.channel(&stored).is_some() && dm_count() == 1,
        "channel should be kept without an archive (dms {dm_count})",
        dm_count = dm_count()
    );
    // the archive's export: the files in its scratch dir; then the destroy deletes the channel
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let (dir, done) = r.discord_export(&copy, tmp.path());
    let dir = dir.unwrap_or_else(|| panic!("no export"));
    assert_eq!(
        std::fs::read(dir.join("attachments/2-f.txt")).unwrap_or_default(),
        b"bytes"
    );
    assert!(
        !std::fs::read(dir.join("messages.json"))
            .unwrap_or_default()
            .is_empty(),
        "no messages.json"
    );
    // the archive holding it failed (a forced destroy goes on): the channel is kept, Deyao told
    done(Some("PUT: HTTP 507".into()));
    discord_destroy(&r, &copy);
    assert!(
        f.channel(&stored).is_some() && dm_count() == 2,
        "channel should be kept when its archive failed (dms {})",
        dm_count()
    );
    // on the Storage Box: the destroy deletes the channel
    let (_, done) = r.discord_export(&copy, tmp.path());
    done(None);
    discord_destroy(&r, &copy);
    assert!(
        f.channel(&stored).is_none() && dm_count() == 2,
        "channel not deleted after the export (dms {})",
        dm_count()
    );
    // gone already: nothing is exported
    let tmp2 = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    assert!(
        r.discord_export(&copy, tmp2.path()).0.is_none(),
        "exported a deleted channel"
    );
}

#[test]
fn tick_renames_and_fills_missing() {
    let (f, d, _) = test_discord();
    let t = new_test_router();
    let r = t.r.clone();
    *r.disc_hook.write().unwrap_or_else(|e| e.into_inner()) = Some(d.clone());
    let (ch, _) = d
        .ensure_channel("", "s1", "old name")
        .unwrap_or_else(|e| panic!("{e:#}"));
    r.st.do_(|p| {
        for s in [
            Session {
                id: "s1".into(),
                state: "started".into(),
                machine_id: "m1".into(),
                title: "New AI title".into(),
                discord_channel: ch.id.clone(),
                ..Default::default()
            },
            Session {
                id: "s2".into(),
                state: "started".into(),
                machine_id: "m2".into(),
                label: "no channel yet".into(),
                ..Default::default()
            },
            Session {
                id: "s3".into(),
                state: "approval".into(),
                label: "waits".into(),
                ..Default::default()
            },
        ] {
            p.sessions.insert(s.id.clone(), s);
        }
    });
    r.discord_tick();
    assert_eq!(f.name_of(&ch.id), "new-ai-title", "not renamed");
    let (s2, s3) = r.st.read(|p| {
        let c = |id: &str| {
            p.sessions
                .get(id)
                .map(|s| s.discord_channel.clone())
                .unwrap_or_default()
        };
        (c("s2"), c("s3"))
    });
    assert!(
        !s2.is_empty() && f.name_of(&s2) == "no-channel-yet" && s3.is_empty(),
        "s2 {s2:?} s3 {s3:?}"
    );
}
