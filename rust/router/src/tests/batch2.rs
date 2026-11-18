//! snapprogress, transcript, bbbudget and regions tests

use crate::bbbudget::{BbSession, BbUsage, bb_cycle_usage, bb_overage_of, bb_thresholds};
use crate::snapprogress::{SnapProgress, snap_progress_text};
use crate::tails::{Tail, TailMessage, is_transcript, parse_transcript, snippet};
use crate::testutil::{
    add_session, call, capture_dm, new_test_machine, new_test_router, new_test_router_with,
};
use jarvis_go::GoTime;
use serde_json::json;

fn sp(phase: &str, done: f64, total: f64, elapsed_ms: i64) -> SnapProgress {
    SnapProgress {
        phase: phase.into(),
        done: done as i64,
        total: total as i64,
        elapsed_ms,
        ..Default::default()
    }
}

#[test]
fn snap_progress_texts() {
    for (p, want) in [
        (
            sp("uploading", 1.2e9, 3.4e9, 30000),
            "uploading snapshot 1.2/3.4 GB (35%), 40 MB/s, 55 s left",
        ),
        (
            sp("uploading", 0.0, 500e6, 200),
            "uploading snapshot 0/500 MB (0%)",
        ),
        (
            sp("writing", 100e6, 400e6, 10000),
            "writing snapshot 100/400 MB (25%), 10 MB/s, 30 s left",
        ),
        (
            sp("uploading", 5e9, 4e9, 100000),
            "uploading snapshot 5.0/5.0 GB (100%), 50 MB/s",
        ), // files grew past the measure
        (
            sp("uploading", 1e9, 9e9, 10000),
            "uploading snapshot 1.0/9.0 GB (11%), 100 MB/s, 1 min 20 s left",
        ),
        (
            sp("measuring", 0.0, 2.5e9, 0),
            "measuring the snapshot (2.5 GB so far)",
        ),
        (sp("rm -rf", 0.0, 1.0, 0), ""),
        (sp("uploading", -1.0, 0.0, 0), ""),
    ] {
        assert_eq!(snap_progress_text(&p), want, "{p:?}");
    }
}

/// a report while the router awaits the machine's snapshot becomes the session's waiting line (and a lifecycle note);
/// without a waiter it is dropped; nonsense is refused
#[test]
fn snap_progress_route() {
    let t = new_test_router();
    add_session(&t, "sP", "pausing", "mP", false);
    let m = new_test_machine(&t, "mP");
    let h = t.machine_handler();
    let waiting = || t.st.do_(|d| d.sessions["sP"].waiting.clone());
    let body = jarvis_go::marshal(
        &json!({"phase": "uploading", "done": 1_200_000_000i64, "total": 3_400_000_000i64, "sent": 600_000_000i64, "elapsedMs": 30000}),
    );
    let (code, _) = m.do_(&h, "POST", "/m/snapshot-progress", &body);
    assert!(
        code == 200 && waiting().is_empty(),
        "no waiter: {code} {}",
        waiting()
    );
    let _ = t.await_snapshot("mP");
    let (code, _) = m.do_(&h, "POST", "/m/snapshot-progress", &body);
    assert!(
        code == 200 && waiting().starts_with("uploading snapshot 1.2/3.4 GB"),
        "awaited: {code} {}",
        waiting()
    );
    let (code, _) = m.do_(&h, "POST", "/m/snapshot-progress", r#"{"phase":"x"}"#);
    assert_eq!(code, 400, "nonsense");
    t.snapshot_arrived("mP");
    t.set_waiting("sP", "");
    let _ = m.do_(&h, "POST", "/m/snapshot-progress", &body);
    assert_eq!(waiting(), "", "after the snapshot arrived");
}

#[test]
fn parse_transcripts() {
    let text = [
        r#"{"type":"user","sessionId":"abc","message":{"content":"first <system-reminder>hidden</system-reminder>"}}"#.to_string(),
        "not json".into(),
        r#"{"type":"ai-title","aiTitle":"Auto"}"#.into(),
        r#"{"type":"queue-operation","operation":"enqueue","content":"typed mid-turn"}"#.into(),
        r#"{"type":"queue-operation","operation":"enqueue","content":"<task-notification>x</task-notification>"}"#.into(),
        r#"{"type":"assistant","message":{"content":[{"type":"tool_use"},{"type":"text","text":"reply"}]}}"#.into(),
        r#"{"type":"user","message":{"content":"typed mid-turn"}}"#.into(),
        r#"{"type":"assistant","isSidechain":true,"message":{"content":"subagent"}}"#.into(),
        r#"{"type":"user","isMeta":true,"message":{"content":"meta"}}"#.into(),
        r#"{"type":"custom-title","customTitle":"Renamed"}"#.into(),
        format!(r#"{{"type":"assistant","message":{{"content":"{}"}}}}"#, "x".repeat(30)),
    ]
    .join("\n");
    let tl = parse_transcript(&text, false, 40, 20);
    assert!(tl.title == "Renamed" && tl.session_id == "abc", "{tl:?}");
    let got: Vec<String> = tl
        .messages
        .iter()
        .map(|m| format!("{}:{}", m.role, m.text))
        .collect();
    let want = vec![
        "user:first".to_string(),
        "assistant:reply".into(),
        "user:typed mid-turn".into(),
        format!("assistant:{} …", "x".repeat(20)),
    ];
    assert_eq!(got, want);
    // a tail read drops its partial first line; max keeps the last messages
    let tl = parse_transcript(&format!("\"content\":\"cut\"}}}}\n{text}"), true, 1, 4000);
    assert!(
        tl.messages.len() == 1 && tl.messages[0].text.starts_with("xxx"),
        "{:?}",
        tl.messages
    );
    let s = snippet(&Tail {
        messages: vec![TailMessage {
            role: "user".into(),
            text: "a\n\n b".into(),
            ..Default::default()
        }],
        ..Default::default()
    });
    assert_eq!(s.map(|s| s.text).unwrap_or_default(), "a b");
}

#[test]
fn is_transcripts() {
    for (name, want) in [
        (".claude/projects/p/x.jsonl", true),
        (".claude/projects/p/sub/x.jsonl", false),
        (".claude/projects/p/x.json", false),
        ("workspace/.claude/projects/p/x.jsonl", false),
    ] {
        assert_eq!(is_transcript(name), want, "{name}");
    }
}

fn bbs(
    created: &str,
    started: &str,
    ended: &str,
    status: &str,
    updated: &str,
    proxy: f64,
) -> BbSession {
    BbSession {
        created_at: created.into(),
        started_at: started.into(),
        ended_at: ended.into(),
        status: status.into(),
        updated_at: updated.into(),
        proxy_bytes: proxy,
    }
}

#[test]
fn bb_usage_and_overage() {
    let now = GoTime::parse("2026-10-20T12:00:00Z").unwrap_or_default();
    let ss = vec![
        bbs(
            "2026-10-01T00:00:00Z",
            "2026-10-01T00:00:00Z",
            "2026-10-01T00:00:30Z",
            "",
            "",
            400.0,
        ), // 1 min, 1 MB
        bbs(
            "2026-10-02T00:00:00Z",
            "2026-10-02T00:00:00Z",
            "",
            "COMPLETED",
            "2026-10-02T01:00:01Z",
            0.0,
        ),
        bbs("2026-10-20T11:00:00Z", "", "", "RUNNING", "", 0.0), // up to now: 60 min
        bbs(
            "2026-09-30T23:59:00Z",
            "2026-09-30T23:59:00Z",
            "2026-10-01T05:00:00Z",
            "",
            "",
            0.0,
        ), // last month
    ];
    let u = bb_cycle_usage(&ss, "2026-10", now);
    assert!(
        u.count == 3
            && u.minutes == (1 + 61 + 60) as f64
            && u.proxy_mb == 1.0
            && u.proxy_bytes == 400.0,
        "{u:?}"
    );
    let o = bb_overage_of(&BbUsage {
        minutes: 7000.0,
        proxy_mb: 1500.0,
        proxy_bytes: 2e9,
        ..Default::default()
    });
    assert!(
        o.time == 2.0 && o.proxy_mb == 6.0 && o.proxy_bytes == 20.0 && o.total == 28.0,
        "{o:?}"
    );
    let (c, w) = bb_thresholds(|k| {
        if k == "BROWSERBASE_BUDGET_USD" {
            "10".into()
        } else {
            String::new()
        }
    });
    assert!(c == 10.0 && w == 8.0, "{c} {w}");
    let (c, _) = bb_thresholds(|_| String::new());
    assert_eq!(c, 0.0, "on without a cap");
}

#[test]
fn bb_budget_dms_once_per_month() {
    let t = new_test_router();
    let dms = capture_dm(&t);
    let now = GoTime::parse("2026-10-20T12:00:00Z").unwrap_or_default();
    // 6,000 included minutes + 4,500 over = USD 9 → warn (8), then 5,500 over = USD 11 → cap (10)
    let long = |min: i64| {
        let start = GoTime::parse("2026-10-01T00:00:00Z").unwrap_or_default();
        vec![bbs(
            &start.rfc3339(),
            &start.rfc3339(),
            &GoTime::from_unix(start.unix() + min * 60).rfc3339(),
            "",
            "",
            0.0,
        )]
    };
    for m in [1000, 10500, 10600, 11500, 11600] {
        t.bb_budget_tick(&long(m), now, 10.0, 8.0);
    }
    let got = dms.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        got.len() == 2
            && got[0]
                .contains("Browserbase spend: estimated overage USD 9.00 of the USD 10.00 cap")
            && got[1].contains("Browserbase spend cap reached: estimated overage USD 11.00"),
        "{got:?}"
    );
    // a new month starts afresh
    t.bb_budget_tick(
        &long(11600),
        GoTime::parse("2026-11-20T12:00:00Z").unwrap_or_default(),
        10.0,
        8.0,
    );
    assert_eq!(
        dms.lock().unwrap_or_else(|e| e.into_inner()).len(),
        2,
        "a DM for a month with no usage"
    );
}

#[test]
fn the_regions_list() {
    let t = new_test_router_with(|c| c.region = "lhr".into(), None, Default::default());
    let (code, out) = call(&t.handler(), "GET", "/api/regions", "");
    let regions = out["regions"].as_array().cloned().unwrap_or_default();
    assert!(
        code == 200
            && out["default"] == "lhr"
            && regions.len() == crate::regions::SESSION_REGIONS.len()
            && regions[1]["id"] == "sin",
        "{code} {out}"
    );
}
