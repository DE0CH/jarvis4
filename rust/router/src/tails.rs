//! Reading a Claude Code transcript (JSONL) for people: the last messages and the title (Jarvis 1 lib/archive.js
//! parseTranscript; transcript.go). Only what was said: user prompts and assistant text; with tools (the live tail,
//! livetail.rs) also each tool call (role "tool": its name and input, keys sorted where Go keeps the file's order) and each
//! result (role "result"), clipped. Meta lines, sidechains (subagents) and injected <system-reminder>-style blocks are
//! left out. The title is what the Claude
//! app showed: the last custom-title (a rename), else the last ai-title. A message typed while Claude was mid-turn only
//! exists as a queue-operation enqueue, so those count as user messages too (deduplicated against the user record a
//! normally delivered one also gets).

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{Read, Write};
use std::sync::LazyLock;

/// how much of a transcript's end is read for its tail
pub const TAIL_BYTES: usize = 2 << 20;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TailMessage {
    pub role: String,
    pub text: String,
    pub at: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Tail {
    pub title: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub messages: Vec<TailMessage>,
    /// the session runs, so this is its last pause snapshot's tail, older than what it is doing now
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
}

/// one pattern per tag
static INJECTED: LazyLock<Vec<regex::Regex>> = LazyLock::new(|| {
    [
        "system-reminder",
        "task-notification",
        "local-command-stdout",
        "command-name",
        "command-message",
        "command-args",
    ]
    .iter()
    .map(|t| regex::Regex::new(&format!(r"(?s)<{t}>.*?</{t}>")).unwrap_or_else(|_| unreachable!()))
    .collect()
});

pub fn clip_text(t: &str, n: usize) -> String {
    if t.chars().count() <= n {
        return t.to_string();
    }
    t.chars().take(n).collect()
}

pub fn content_text(raw: Option<&Value>) -> String {
    match raw {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter_map(Value::as_object)
            .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
            .join("\n\n"),
        _ => String::new(),
    }
}

/// how much of a tool call's input or a result a tail with tools keeps
pub const TOOL_CLIP: usize = 600;

/// a message's tool calls (role "tool": name and input) and results (role "result"), clipped to TOOL_CLIP
pub fn tool_blocks(raw: Option<&Value>, at: &Value) -> Vec<TailMessage> {
    let Some(Value::Array(blocks)) = raw else {
        return vec![];
    };
    let clip = |t: &str| {
        let t = t.trim();
        if t.chars().count() > TOOL_CLIP {
            format!("{} …", clip_text(t, TOOL_CLIP))
        } else {
            t.to_string()
        }
    };
    let mut out = vec![];
    for b in blocks.iter().filter_map(Value::as_object) {
        let (role, text) = match b.get("type").and_then(Value::as_str) {
            Some("tool_use") => {
                let name = b.get("name").and_then(Value::as_str).unwrap_or_default();
                let input = b.get("input").map(Value::to_string).unwrap_or_default();
                ("tool", clip(&format!("{name} {input}")))
            }
            Some("tool_result") => {
                let mut t = content_text(b.get("content"));
                if b.get("is_error").and_then(Value::as_bool) == Some(true) {
                    t = format!("error: {t}");
                }
                ("result", clip(&t))
            }
            _ => continue,
        };
        out.push(TailMessage {
            role: role.into(),
            text,
            at: at.clone(),
        });
    }
    out
}

/// partial_first_line when text starts mid-file (a tail read); max messages, clip characters each
pub fn parse_transcript(text: &str, partial_first_line: bool, max: usize, clip: usize) -> Tail {
    parse_transcript_with(text, partial_first_line, max, clip, false)
}

/// parse_transcript, and with tools the tool calls and results as messages of their own
pub fn parse_transcript_with(
    text: &str,
    partial_first_line: bool,
    max: usize,
    clip: usize,
    tools: bool,
) -> Tail {
    let mut lines: Vec<&str> = text.split('\n').collect();
    if partial_first_line && !lines.is_empty() {
        lines.remove(0);
    }
    let (mut ai_title, mut custom_title, mut sid) = (String::new(), String::new(), String::new());
    // (message, queued)
    let mut msgs: Vec<(TailMessage, bool)> = vec![];
    let s = |j: &serde_json::Map<String, Value>, k: &str| {
        j.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    for l in lines {
        if l.trim().is_empty() {
            continue;
        }
        let Ok(Value::Object(j)) = serde_json::from_str::<Value>(l) else {
            continue;
        };
        let typ = s(&j, "type");
        if sid.is_empty() && !s(&j, "sessionId").is_empty() {
            sid = s(&j, "sessionId");
        }
        let at = j.get("timestamp").cloned().unwrap_or(Value::Null);
        if typ == "ai-title" && !s(&j, "aiTitle").is_empty() {
            ai_title = s(&j, "aiTitle");
            continue;
        }
        if typ == "custom-title" && !s(&j, "customTitle").is_empty() {
            custom_title = s(&j, "customTitle");
            continue;
        }
        if typ == "queue-operation" && s(&j, "operation") == "enqueue" {
            if let Some(Value::String(c)) = j.get("content")
                && !c
                    .trim_start_matches([' ', '\t', '\r', '\n'])
                    .starts_with('<')
            {
                msgs.push((
                    TailMessage {
                        role: "user".into(),
                        text: clip_text(c.trim(), clip),
                        at,
                    },
                    true,
                ));
            }
            continue;
        }
        let flag = |k: &str| j.get(k).and_then(Value::as_bool).unwrap_or(false);
        let msg = j.get("message").filter(|m| m.is_object());
        if (typ != "user" && typ != "assistant")
            || flag("isSidechain")
            || flag("isMeta")
            || msg.is_none()
        {
            continue;
        }
        // with tools: after the message's text, as Claude Code writes them
        let calls: Vec<(TailMessage, bool)> = if tools {
            tool_blocks(msg.and_then(|m| m.get("content")), &at)
                .into_iter()
                .map(|m| (m, false))
                .collect()
        } else {
            vec![]
        };
        let mut t = content_text(msg.and_then(|m| m.get("content")));
        for re in INJECTED.iter() {
            t = re.replace_all(&t, "").into_owned();
        }
        let mut t = t.trim().to_string();
        if t.is_empty() {
            msgs.extend(calls);
            continue;
        }
        if typ == "user"
            && let Some(i) = msgs
                .iter()
                .position(|(m, q)| *q && m.text == clip_text(&t, clip))
        {
            msgs.remove(i);
        }
        if t.chars().count() > clip {
            t = format!("{} …", clip_text(&t, clip));
        }
        msgs.push((
            TailMessage {
                role: typ,
                text: t,
                at,
            },
            false,
        ));
        msgs.extend(calls);
    }
    if msgs.len() > max {
        msgs.drain(..msgs.len() - max);
    }
    Tail {
        title: if custom_title.is_empty() {
            ai_title
        } else {
            custom_title
        },
        session_id: sid,
        messages: msgs.into_iter().map(|(m, _)| m).collect(),
        stale: false,
    }
}

/// the tail of a transcript's text (the whole file or its last bytes)
pub fn tail_of(text: &[u8]) -> Tail {
    parse_transcript(
        &String::from_utf8_lossy(text),
        text.len() >= TAIL_BYTES,
        40,
        4000,
    )
}

/// what a conversation ended on, for a card
pub fn snippet(t: &Tail) -> Option<TailMessage> {
    let mut m = t.messages.last()?.clone();
    m.text = clip_text(
        &m.text.split_whitespace().collect::<Vec<_>>().join(" "),
        280,
    );
    Some(m)
}

// ---- inside a snapshot (a tar relative to $HOME) --------------------------------------------------------------

/// .claude/projects/<project>/<id>.jsonl
pub fn is_transcript(name: &str) -> bool {
    let name = crate::util::path_clean(name);
    let parts: Vec<&str> = name.split('/').collect();
    parts.len() == 4
        && parts[0] == ".claude"
        && parts[1] == "projects"
        && parts[3].ends_with(".jsonl")
}

/// the last n bytes of what is written into it
pub struct TailBuf {
    b: Vec<u8>,
    n: usize,
}

impl TailBuf {
    pub fn new(n: usize) -> TailBuf {
        TailBuf { b: vec![], n }
    }

    pub fn bytes(&self) -> Vec<u8> {
        if self.b.len() > self.n {
            self.b[self.b.len() - self.n..].to_vec()
        } else {
            self.b.clone()
        }
    }
}

impl Write for TailBuf {
    fn write(&mut self, p: &[u8]) -> std::io::Result<usize> {
        self.b.extend_from_slice(p);
        if self.b.len() > 2 * self.n {
            let cut = self.b.len() - self.n;
            self.b.drain(..cut);
        }
        Ok(p.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// one pass over a snapshot: the tail of its newest transcript and the repos' changes file (the Go field names, as
/// the snapshots table keeps them)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SnapshotFacts {
    /// newest last
    #[serde(rename = "Transcripts")]
    pub transcripts: Option<Vec<String>>,
    #[serde(rename = "Tail")]
    pub tail: Option<Tail>,
    #[serde(rename = "Changes")]
    pub changes: Option<String>,
}

pub fn read_snapshot_facts(p: &std::path::Path) -> Result<SnapshotFacts> {
    read_snapshot_facts_from(&mut std::fs::File::open(p)?)
}

/// the facts of a snapshot's bytes (snapformat.rs), read through once
pub fn read_snapshot_facts_from(f: &mut dyn Read) -> Result<SnapshotFacts> {
    let gz = crate::snapformat::open_snap_reader(f)?;
    let mut tr = tar::Archive::new(gz);
    let mut out = SnapshotFacts::default();
    let mut newest: Option<u64> = None;
    let mut newest_tail: Option<Vec<u8>> = None;
    let mut all: Vec<(String, u64)> = vec![];
    for e in tr.entries()? {
        let mut e = e?;
        let h = e.header().clone();
        if h.entry_type() != tar::EntryType::Regular {
            continue;
        }
        let name = crate::util::path_clean(&String::from_utf8_lossy(&h.path_bytes()));
        let mtime = h.mtime().unwrap_or(0);
        if is_transcript(&name) {
            all.push((name.clone(), mtime));
            if newest_tail.is_none() || newest.is_none_or(|n| mtime >= n) {
                let mut tb = TailBuf::new(TAIL_BYTES);
                std::io::copy(&mut e, &mut tb)?;
                newest = Some(mtime);
                newest_tail = Some(tb.bytes());
            }
        } else if name == crate::archive::CHANGES_FILE {
            let mut b = vec![];
            (&mut e).take(1 << 20).read_to_end(&mut b)?;
            out.changes = Some(String::from_utf8_lossy(&b).into_owned());
        }
    }
    all.sort_by_key(|(_, at)| *at); // oldest first (stable)
    if !all.is_empty() {
        out.transcripts = Some(all.into_iter().map(|(n, _)| n).collect());
    }
    out.tail = newest_tail.map(|t| tail_of(&t));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transcript() {
        let t = r#"{"type":"user","sessionId":"s1","message":{"content":"hello <system-reminder>x</system-reminder>"},"timestamp":"t1"}
{"type":"queue-operation","operation":"enqueue","content":"later"}
{"type":"assistant","message":{"content":[{"type":"text","text":"hi"},{"type":"tool_use"}]}}
{"type":"user","message":{"content":"later"}}
{"type":"ai-title","aiTitle":"A"}
{"type":"custom-title","customTitle":"C"}"#;
        let tail = parse_transcript(t, false, 40, 4000);
        assert_eq!(tail.title, "C");
        assert_eq!(tail.session_id, "s1");
        let texts: Vec<&str> = tail.messages.iter().map(|m| m.text.as_str()).collect();
        assert_eq!(texts, vec!["hello", "hi", "later"]);
        assert!(is_transcript("./.claude/projects/p/x.jsonl"));
        assert!(!is_transcript(".claude/projects/p/q/x.jsonl"));
    }
}
