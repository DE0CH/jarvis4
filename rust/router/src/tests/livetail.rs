//! router/livetail_test.go
use crate::livesync::{LiveSync, forget_live_dir};
use crate::livetail::{LIVE_TAIL_WAIT_MS, last_entry_time};
use crate::tails::{TOOL_CLIP, parse_transcript, parse_transcript_with};
use crate::testutil::*;
use serde_json::json;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// a .live copy of sid on the box, recorded as the router's live sync records one
fn put_live(rg: &Rig, sid: &str, name: &str, body: &str) {
    let b = rg.box_().unwrap_or_else(|| panic!("no box"));
    let dir = format!("claude-records/.live/{sid}");
    b.mkcols(&dir).unwrap_or_else(|e| panic!("{e:#}"));
    b.put_bytes(&format!("{dir}/{name}"), body.as_bytes())
        .unwrap_or_else(|e| panic!("{e:#}"));
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut(sid) {
            s.live_sync
                .get_or_insert_with(LiveSync::default)
                .files
                .get_or_insert_with(Default::default)
                .insert(name.into(), body.len() as i64);
        }
    });
}

#[test]
fn transcript_with_tools() {
    let text = line(
        json!({"type": "user", "timestamp": "2026-11-20T10:00:00Z", "message": {"content": "find the bug"}}),
    ) + &line(
        json!({"type": "assistant", "timestamp": "2026-11-20T10:00:01Z", "message": {"content": [
            {"type": "text", "text": "Looking."},
            {"type": "tool_use", "name": "Bash", "input": {"command": "grep -rn bug ."}}]}}),
    ) + &line(
        json!({"type": "user", "timestamp": "2026-11-20T10:00:02Z", "message": {"content": [
            {"type": "tool_result", "content": format!("a.go:3: bug {}", "x".repeat(900))}]}}),
    ) + &line(
        json!({"type": "user", "timestamp": "2026-11-20T10:00:03Z", "message": {"content": [
            {"type": "tool_result", "is_error": true, "content": [{"type": "text", "text": "exit 1"}]}]}}),
    );
    let said = parse_transcript(&text, false, 40, 4000);
    assert_eq!(said.messages.len(), 2, "{:?}", said.messages);
    assert_eq!(said.messages[1].text, "Looking.");
    let all = parse_transcript_with(&text, false, 40, 4000, true);
    let roles: Vec<&str> = all.messages.iter().map(|m| m.role.as_str()).collect();
    assert_eq!(roles, ["user", "assistant", "tool", "result", "result"]);
    assert_eq!(all.messages[2].text, r#"Bash {"command":"grep -rn bug ."}"#);
    assert_eq!(all.messages[3].text.chars().count(), TOOL_CLIP + 2);
    assert!(all.messages[3].text.ends_with(" …"));
    assert_eq!(all.messages[4].text, "error: exit 1");
    assert_eq!(last_entry_time(text.as_bytes()), "2026-11-20T10:00:03Z");
    assert_eq!(last_entry_time(b"{\"type\":\"x\"}\n{\"timestam"), "");
}

#[test]
fn live_tail() {
    let _g = serial();
    let rg = Rig::new();
    let r: &crate::router::Router = &rg;
    let h = r.arc().machine_handler();
    add_session(r, "s2", "started", "m2", false);
    add_session(r, "s3", "started", "m3", false);
    let m = new_test_machine(r, "m2");
    let reader = new_test_machine(r, "m3");
    put_live(
        &rg,
        "s2",
        "aaaa.jsonl",
        &line(
            json!({"type": "user", "timestamp": "2026-11-20T09:00:00Z", "message": {"content": "an older conversation"}}),
        ),
    );
    put_live(
        &rg,
        "s2",
        "agent-zzzz.jsonl",
        &line(
            json!({"type": "user", "timestamp": "2026-11-20T23:00:00Z", "isSidechain": true, "message": {"content": "a subagent"}}),
        ),
    );

    // the machine answers the round: the newer conversation arrives, then live-synced
    LIVE_TAIL_WAIT_MS.store(5_000, Ordering::SeqCst);
    std::thread::scope(|sc| {
        sc.spawn(|| {
            assert_eq!(wait_cmd(r, "m2", Duration::from_secs(5)).as_deref(), Some("live-sync"));
            put_live(&rg, "s2", "bbbb.jsonl", &(line(json!({"type": "user", "timestamp": "2026-11-20T10:00:00Z", "message": {"content": "now"}}))
                + &line(json!({"type": "assistant", "timestamp": "2026-11-20T10:00:01Z", "message": {"content": [
                    {"type": "tool_use", "name": "Bash", "input": {"command": "ls"}}]}}))));
            let (code, out) = m.do_(&h, "POST", "/m/live-synced", "{}");
            assert_eq!(code, 200, "{out}");
        });
        let (code, out) = reader.do_(&h, "GET", "/m/api/tail/s2", "");
        assert_eq!(code, 200, "{out}");
        assert_eq!(out["file"], "bbbb.jsonl", "{out}");
        assert!(out.get("stale").is_none(), "{out}");
        assert_eq!(out["lastAt"], "2026-11-20T10:00:01Z");
        let msgs = out["messages"].as_array().cloned().unwrap_or_default();
        assert_eq!(msgs.len(), 2, "{out}");
        assert_eq!(msgs[1]["role"], "tool");
    });
    // by its title too, said only
    let (code, out) = reader.do_(&h, "GET", "/m/api/tail/label%20s2?said=1", "");
    assert_eq!(code, 200, "{out}");
    assert_eq!(out["messages"].as_array().map(Vec::len), Some(1), "{out}");

    // a machine that never answers (an older image): its last copy, stale
    LIVE_TAIL_WAIT_MS.store(300, Ordering::SeqCst);
    let t = r
        .live_tail_of("s2", true, 0)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        t.tail.stale && t.why.contains("did not answer") && t.file == "bbbb.jsonl",
        "{t:?}"
    );

    // a paused session isn't asked
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s2") {
            s.state = "paused".into();
            s.machine_id = String::new();
        }
    });
    while take_cmd(r, "m2").is_some() {}
    let t = r
        .live_tail_of("s2", true, 0)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(t.tail.stale && t.why.contains("it is paused"), "{t:?}");
    assert_eq!(
        take_cmd(r, "m2"),
        None,
        "a paused session's machine was asked"
    );

    // no copy yet; no such session
    assert_eq!(
        r.live_tail_of("s3", true, 0).map_err(|e| e.0).err(),
        Some(404)
    );
    let (code, out) = reader.do_(&h, "GET", "/m/api/tail/nope", "");
    assert_eq!(code, 404, "{out}");
    assert!(
        out["error"]
            .as_str()
            .unwrap_or("")
            .contains("transcript search"),
        "{out}"
    );
    LIVE_TAIL_WAIT_MS.store(45_000, Ordering::SeqCst);
    forget_live_dir("s2");
}
