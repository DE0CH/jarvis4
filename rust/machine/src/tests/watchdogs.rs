//! stall_test.go, pressure_test.go, rcwatch_test.go and autoaccept_test.go: the supervisor's watches on its own harness.

use super::testutil::*;
use crate::autoaccept::*;
use crate::disk::{DiskFs, DiskSample};
use crate::livesync::LiveSyncer;
use crate::memory::MemSample;
use crate::pressure::*;
use crate::rcwatch::*;
use crate::stall::*;
use crate::workers::{HookTask, WorkerEvent};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn at(t0: Instant, m: f64) -> Instant {
    t0 + Duration::from_secs_f64(m * 60.0)
}

/// idle with background jobs and no turn for 15 min → a nudge, again every 15 min; a new turn, no jobs, or a running
/// turn on the pane resets it; a busy host with no pane keeps the clock as it is
#[test]
fn stall_step_rules() {
    let t0 = Instant::now();
    let idle = HostStatus {
        ok: true,
        status: "idle".into(),
        status_at: 1,
        jobs: 2,
        ..Default::default()
    };
    let mut c = StallClock::default();
    assert!(
        !stall_step(&mut c, &idle, "", false, at(t0, 0.0)).0,
        "nudged at once"
    );
    assert!(
        !stall_step(&mut c, &idle, "", false, at(t0, 14.0)).0,
        "nudged before 15 min"
    );
    assert_eq!(
        stall_step(&mut c, &idle, "", false, at(t0, 15.0)),
        (true, 15),
        "no nudge at 15 min"
    );
    assert!(
        !stall_step(&mut c, &idle, "", false, at(t0, 20.0)).0,
        "nudged again within 15 min"
    );
    assert_eq!(
        stall_step(&mut c, &idle, "", false, at(t0, 30.0)),
        (true, 15),
        "not repeated after 15 more min"
    );
    // a new turn starts the clock again
    let mut turn = idle.clone();
    turn.status_at = 2;
    stall_step(&mut c, &turn, "", false, at(t0, 31.0));
    assert!(
        !stall_step(&mut c, &turn, "", false, at(t0, 45.0)).0,
        "the new turn's clock didn't restart"
    );
    // no jobs: nothing
    let mut c2 = StallClock::default();
    let nojobs = HostStatus {
        ok: true,
        status: "idle".into(),
        status_at: 1,
        ..Default::default()
    };
    for m in (0..=30).step_by(5) {
        assert!(
            !stall_step(&mut c2, &nojobs, "", false, at(t0, m as f64)).0,
            "nudged with no background jobs"
        );
    }
    // busy with jobs: a pane without a spinner counts as waiting on the jobs; with one, a turn runs
    let busy = HostStatus {
        ok: true,
        status: "busy".into(),
        status_at: 3,
        jobs: 1,
        ..Default::default()
    };
    let mut c3 = StallClock::default();
    stall_step(&mut c3, &busy, "❯ ", true, at(t0, 0.0));
    assert!(
        stall_step(&mut c3, &busy, "❯ ", true, at(t0, 15.0)).0,
        "a busy host waiting on its jobs wasn't nudged"
    );
    let spin = "\x1b[33m✻\x1b[0m Thinking… (12s · esc to interrupt)\n";
    assert!(
        !stall_step(&mut c3, &busy, spin, true, at(t0, 40.0)).0 && c3.since.is_none(),
        "a running turn didn't reset the clock"
    );
    // busy with no pane: the clock stays as it is (neither starts nor resets)
    let mut c4 = StallClock::default();
    assert!(
        !stall_step(&mut c4, &busy, "", false, at(t0, 0.0)).0 && c4.since.is_none(),
        "a busy host with no pane started the clock"
    );
    assert!(
        stall_text(1, 15).starts_with(
            "Jarvis watchdog: this session has been idle for 15 min while 1 background job has"
        ),
        "{}",
        stall_text(1, 15)
    );
}

/// read_host: the Remote Control host's entry, its jobs the larger of the shells and the hook-fed count
#[test]
fn read_host_entry() {
    let e = TestEnv::new();
    let d = e.root.join("sessions");
    std::fs::create_dir_all(&d).unwrap();
    *CLAUDE_SESSIONS.write().unwrap() = Some(d.clone());
    *TEST_SHELL_JOBS.lock().unwrap() = Some(1);
    std::fs::write(
        d.join("a.json"),
        r#"{"pid":10,"sessionId":"c1","status":"busy","statusUpdatedAt":5,"startedAt":1}"#,
    )
    .unwrap();
    std::fs::write(
        d.join("b.json"),
        r#"{"pid":11,"sessionId":"c2","status":"idle","statusUpdatedAt":7,"startedAt":2,"bridgeSessionId":"session_x"}"#,
    )
    .unwrap();
    let h = read_host();
    assert!(
        h.ok && h.status == "idle" && h.status_at == 7 && h.jobs == 1,
        "{h:?}"
    );
    let tasks = vec![
        HookTask {
            id: "j1".into(),
            type_: "shell".into(),
            status: String::new(),
        },
        HookTask {
            id: "j2".into(),
            type_: "monitor".into(),
            status: String::new(),
        },
    ];
    crate::workers::apply(
        &WorkerEvent {
            event: "Stop".into(),
            session_id: "c2".into(),
            tasks: Some(tasks),
            ..Default::default()
        },
        crate::util::unix_now() * 1000,
    );
    assert_eq!(read_host().jobs, 2, "the hook-fed count wasn't used");
}

/// supervisor-normal's live sync keeps what it sent in a file, so supervisor-core's teardown sends only what changed
#[test]
fn live_sent_across_processes() {
    let e = TestEnv::new();
    let f = e.root.join("a.jsonl");
    std::fs::write(&f, "{}\n").unwrap();
    let state = e.root.join("live-sent.json");
    let sent: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let mk = |s: Arc<Mutex<Vec<String>>>| -> crate::livesync::SendFnPub {
        Box::new(move |name: &str, _b: &[u8]| {
            s.lock().unwrap().push(name.into());
            Ok(())
        })
    };
    let normal = LiveSyncer::new(mk(sent.clone()), Some(state.clone()), Default::default());
    assert_eq!(normal.pass(std::slice::from_ref(&f)), 1, "normal");
    let saved = crate::gojson::unmarshal(&std::fs::read(&state).unwrap()).unwrap();
    let core = LiveSyncer::new(mk(sent.clone()), Some(state.clone()), saved);
    assert_eq!(
        core.pass(std::slice::from_ref(&f)),
        0,
        "the teardown sent unchanged transcripts again"
    );
    let later = std::time::SystemTime::now() + Duration::from_secs(60);
    std::fs::File::options()
        .write(true)
        .open(&f)
        .unwrap()
        .set_modified(later)
        .unwrap();
    assert_eq!(
        core.pass(std::slice::from_ref(&f)),
        1,
        "the teardown didn't send the changed transcript"
    );
    assert_eq!(
        normal.pass(std::slice::from_ref(&f)),
        0,
        "supervisor-normal sent again what supervisor-core's round sent"
    );
}

/// a new episode is told at once, again every 15 min while it lasts, never while healthy; a memory episode ends after
/// 15 healthy minutes, a disk one once the disk is clear again
#[test]
fn pressure_episode() {
    let t0 = Instant::now();
    let a = |m: f64| at(t0, m);
    let mut e = PressureEpisode::default();
    assert!(
        !e.step(false, true, a(0.0), PRESSURE_MEM_CLEAR),
        "told while healthy"
    );
    assert!(
        e.step(true, false, a(1.0), PRESSURE_MEM_CLEAR),
        "a new episode wasn't told"
    );
    assert!(
        !e.step(true, false, a(2.0), PRESSURE_MEM_CLEAR),
        "told again within 15 min"
    );
    assert!(
        e.step(true, false, a(16.0), PRESSURE_MEM_CLEAR),
        "not told again after 15 min under pressure"
    );
    e.step(false, true, a(17.0), PRESSURE_MEM_CLEAR);
    assert!(
        !e.step(true, false, a(20.0), PRESSURE_MEM_CLEAR),
        "a dip inside the episode was told as a new one"
    );
    e.step(false, true, a(21.0), PRESSURE_MEM_CLEAR);
    e.step(false, true, a(36.0), PRESSURE_MEM_CLEAR);
    assert!(
        e.step(true, false, a(37.0), PRESSURE_MEM_CLEAR),
        "a new episode after a clear one wasn't told"
    );
    e.untold();
    assert!(
        e.step(true, false, a(38.0), PRESSURE_MEM_CLEAR),
        "an untaken message wasn't sent again"
    );
    let mut d = PressureEpisode::default();
    d.step(true, false, a(0.0), Duration::ZERO);
    assert!(
        !d.step(false, false, a(1.0), Duration::ZERO) && d.on,
        "the disk episode ended before the disk was clear"
    );
    d.step(false, true, a(2.0), Duration::ZERO);
    assert!(!d.on, "a clear disk didn't end the episode");
}

/// the reasons are the router's (rust/router/src/memory.rs, rust/router/src/disk.rs)
#[test]
fn pressure_reasons() {
    let _e = TestEnv::new();
    *GUARD_LOG_PATH.write().unwrap() =
        Some(std::path::PathBuf::from("/nonexistent/supervisor.out"));
    let mut w = PressureWatch::default();
    let ok = MemSample {
        total_kb: 4 << 20,
        avail_kb: 2 << 20,
        oom_kills: Some(3),
        psi_full60: Some(0.0),
        top: None,
    };
    assert_eq!(w.mem_reason(&ok), "", "healthy memory");
    let mut killed = ok.clone();
    killed.oom_kills = Some(5);
    let r = w.mem_reason(&killed);
    assert!(r.contains("killed 2 processes"), "{r}");
    assert_eq!(w.mem_reason(&killed), "", "the same kills counted twice");
    let mut thrash = killed.clone();
    thrash.psi_full60 = Some(12.0);
    assert!(w.mem_reason(&thrash).contains("thrashing"));
    let mut low = killed.clone();
    low.avail_kb = 100 << 10;
    assert!(w.mem_reason(&low).contains("almost out of memory"));
    let root = DiskFs {
        total_kb: 8 << 20,
        avail_kb: 4 << 20,
    };
    let (l, c, _) = disk_pressure(&DiskSample {
        root: Some(root.clone()),
        data: None,
    });
    assert!(!l && c, "a half-empty disk is low or not clear");
    let (l, _, d) = disk_pressure(&DiskSample {
        root: Some(root),
        data: Some(DiskFs {
            total_kb: 10 << 20,
            avail_kb: 512 << 10,
        }),
    });
    assert!(l && d.contains("volume"), "a full volume: {d}");
    let (l, c, _) = disk_pressure(&DiskSample {
        root: Some(DiskFs {
            total_kb: 10 << 20,
            avail_kb: 1536 << 10,
        }),
        data: None,
    });
    assert!(
        !l && !c,
        "between the marks the disk is neither low nor clear"
    );
}

/// a harness's own memory guard kills before the kernel does (the aviary supervisor): its kills are pressure too
#[test]
fn pressure_guard_kills() {
    let e = TestEnv::new();
    let log = e.root.join("supervisor.out");
    *GUARD_LOG_PATH.write().unwrap() = Some(log.clone());
    let ok = MemSample {
        total_kb: 4 << 20,
        avail_kb: 2 << 20,
        oom_kills: Some(0),
        ..Default::default()
    };
    let add = |s: &str| {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&log)
            .unwrap();
        f.write_all(s.as_bytes()).unwrap();
    };
    let mut w = PressureWatch::default();
    assert_eq!(w.mem_reason(&ok), "", "no log yet");
    add(
        "{\"level\":\"warn\",\"msg\":\"memory guard killed\",\"pid\":7,\"comm\":\"old\",\"rss\":1073741824}\n",
    );
    let mut w = PressureWatch::default();
    assert_eq!(w.mem_reason(&ok), "", "a kill from before the watch");
    add(concat!(
        "{\"level\":\"info\",\"msg\":\"turn started\"}\n",
        "{\"level\":\"warn\",\"msg\":\"memory guard killed\",\"pid\":1682,\"comm\":\"npm ci\",\"rss\":3269664768,\"used\":3977883648}\n",
        "{\"level\":\"warn\",\"msg\":\"memory guard kil"
    ));
    let r = w.mem_reason(&ok);
    assert!(r.contains("memory guard killed npm ci at 3.0 GB"), "{r}");
    assert_eq!(w.mem_reason(&ok), "", "the same kill told twice");
    add("led\",\"pid\":1850,\"comm\":\"node\",\"rss\":2147483648}\n");
    assert!(w.mem_reason(&ok).contains("node at 2.0 GB"));
    std::fs::write(
        &log,
        "{\"msg\":\"memory guard killed\",\"comm\":\"cargo\",\"rss\":1073741824}\n",
    )
    .unwrap();
    assert!(w.mem_reason(&ok).contains("cargo at 1.0 GB"), "a new log");
}

#[test]
fn pressure_text_says_what_deyao_asked() {
    let m = pressure_text(
        "memory",
        "it is almost out of memory",
        "100 MB free of 4.0 GB",
        true,
    );
    for want in [
        "Jarvis watchdog: memory pressure",
        "100 MB free of 4.0 GB",
        "Do not upgrade",
        "Discord Deyao",
        "This is an automated message from Jarvis.",
        "stopped your running turn",
    ] {
        assert!(m.contains(want), "{m:?} is missing {want:?}");
    }
    // a harness with no interrupt (Paseo, OpenClaw…): the message joins the turn, and says nothing of a stop
    let d = pressure_text(
        "disk",
        "it is almost out of disk",
        "0.5 GB free of 10.0 GB on its volume",
        false,
    );
    assert!(
        d.contains("Jarvis watchdog: disk pressure") && d.contains("Do not upgrade"),
        "{d}"
    );
    assert!(!d.contains("stopped"), "{d}");
}

/// The pressure watchdog's message interrupts (Deyao, 2026-11-20): on aviary it is the gateway's delivery that says
/// `interrupt`, straight to the gateway (not the inbox spool, whose loop waits on a running turn); a refusal is an
/// error, so the watch tells it again at its next look
#[test]
fn interrupt_on_aviary_is_an_interrupting_delivery() {
    use crate::deliver::{TEST_AVIARY_GATEWAY, interrupt_harness};
    let _e = TestEnv::new();
    let got: Arc<Mutex<Vec<serde_json::Value>>> = Arc::default();
    let status = Arc::new(std::sync::atomic::AtomicU16::new(202));
    let (g, st) = (got.clone(), status.clone());
    let app = axum::Router::new().route(
        "/jarvis/deliver",
        axum::routing::post(move |axum::Json(b): axum::Json<serde_json::Value>| {
            let (g, st) = (g.clone(), st.clone());
            async move {
                g.lock().unwrap().push(b);
                let code = st.load(std::sync::atomic::Ordering::SeqCst);
                (axum::http::StatusCode::from_u16(code).unwrap(), "{}")
            }
        }),
    );
    let url = crate::rt::block_on(async move {
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", ln.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(ln, app).await;
        });
        url
    });
    *TEST_AVIARY_GATEWAY.write().unwrap() = Some(url);
    interrupt_harness(
        "aviary",
        "bypass",
        "jarvis",
        "Jarvis watchdog: memory pressure",
    )
    .unwrap();
    let b = got.lock().unwrap()[0].clone();
    assert_eq!(b["interrupt"], true);
    assert_eq!(b["text"], "Jarvis watchdog: memory pressure");
    assert!(b["id"].as_str().unwrap().starts_with("jarvis-"), "{b}");
    status.store(409, std::sync::atomic::Ordering::SeqCst);
    let e = interrupt_harness("aviary", "bypass", "jarvis", "again").unwrap_err();
    assert!(e.to_string().contains("409"), "{e:#}");
    assert_ne!(
        got.lock().unwrap()[1]["id"],
        b["id"],
        "each message its own id"
    );
}

/// On Claude Code a turn the pane shows running is stopped with Esc before the message goes in through the Jarvis
/// channel; an idle pane gets no key; a harness with no interrupt is sent the message as any other
#[test]
fn interrupt_on_claude_code_stops_the_turn_then_sends() {
    use crate::deliver::{interrupt_harness, interrupts};
    let e = TestEnv::new();
    let out = e.root.join("got");
    let script = e.root.join("send");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\n{{ echo \"$@\"; cat; }} > {}\necho '{{\"success\":true}}'\n",
            out.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let cfg = e.root.join("cfg.json");
    std::fs::write(&cfg, "{}").unwrap();
    *crate::deliver::TEST_CHANNEL.write().unwrap() =
        Some((script.display().to_string(), cfg.display().to_string()));
    let running = "✻ Compiling… (12s · esc to interrupt)\n❯ ";
    let pane = Arc::new(Mutex::new(running.to_string()));
    let keys: Arc<Mutex<Vec<String>>> = Arc::default();
    let p1 = pane.clone();
    *crate::claudelogin::TEST_PANE.lock().unwrap() =
        Some(Arc::new(move || p1.lock().unwrap().clone()));
    let (p2, k2) = (pane.clone(), keys.clone());
    *crate::claudelogin::TEST_KEYS.lock().unwrap() = Some(Arc::new(move |a: &[&str]| {
        k2.lock().unwrap().push(a.join(" "));
        if a == ["Escape"] {
            // the message must not be in the channel before the turn was stopped
            assert!(!std::fs::exists(&out).unwrap_or(false));
            *p2.lock().unwrap() = "⎿ Interrupted · What should Claude do instead?\n❯ ".into();
        }
        Ok(())
    }));
    let out = e.root.join("got");
    interrupt_harness(
        "claude",
        "bypass",
        "jarvis",
        "Jarvis watchdog: memory pressure",
    )
    .unwrap();
    assert_eq!(*keys.lock().unwrap(), ["Escape"]);
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        "--from jarvis\nJarvis watchdog: memory pressure"
    );
    // idle: no key, the message goes in at once
    interrupt_harness(
        "claude",
        "bypass",
        "jarvis",
        "Jarvis watchdog: disk pressure",
    )
    .unwrap();
    assert_eq!(keys.lock().unwrap().len(), 1);
    assert!(
        std::fs::read_to_string(&out)
            .unwrap()
            .ends_with("disk pressure")
    );
    assert!(interrupts("claude") && interrupts("") && interrupts("aviary"));
    assert!(!interrupts("paseo-claude") && !interrupts("openclaw") && !interrupts("dsh"));
}

/// only an outage that outlasts 3 min, seen between turns, is revived, and again only after 10 min
#[test]
fn rc_step_rules() {
    let t0 = Instant::now();
    let a = |m: f64| at(t0, m);
    let look = |up: bool, bridge: &str, server: &str, idle: bool| RcLook {
        host_up: up,
        bridge: bridge.into(),
        server: server.into(),
        idle,
    };
    let up = look(true, "session_a", "connected", true);
    let gone = look(true, "session_a", "disconnected", true);
    let off = look(true, "", "", true);
    let mut c = RcClock::default();
    for (m, l) in [&up, &gone, &gone, &gone].iter().enumerate() {
        assert!(!rc_step(&mut c, l, a(m as f64)), "revived at {m} min");
    }
    assert!(
        rc_step(&mut c, &gone, a(4.0)),
        "down 3 min between turns: not revived"
    );
    assert!(
        !rc_step(&mut c, &gone, a(5.0)) && !rc_step(&mut c, &gone, a(13.5)),
        "revived again before the retry wait"
    );
    assert!(
        rc_step(&mut c, &gone, a(14.5)),
        "still down after the retry wait: not revived again"
    );
    let mut c = RcClock::default();
    let mut busy = off.clone();
    busy.idle = false;
    for (m, l) in [&off, &busy, &busy, &busy, &busy].iter().enumerate() {
        assert!(
            !rc_step(&mut c, l, a(m as f64)),
            "revived in a turn at {m} min"
        );
    }
    assert!(
        rc_step(&mut c, &off, a(5.0)),
        "Remote Control off on the host, turn over: not revived"
    );
    for l in [RcLook::default(), look(true, "session_a", "", true)] {
        let mut c = RcClock::default();
        for m in 0..20 {
            assert!(!rc_step(&mut c, &l, a(m as f64)), "{l:?} revived");
        }
    }
    let mut c = RcClock::default();
    for (m, l) in [&gone, &gone, &up, &gone, &gone, &gone].iter().enumerate() {
        assert!(
            !rc_step(&mut c, l, a(m as f64)),
            "revived at {m} min after the blip"
        );
    }
}

/// the menu as Claude Code 2.1.310 draws it, under a conversation that quotes the same words
const RC_MENU_ON: &str = "❯ Disconnect this session, please
● Done.
▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔
   Remote Control
   This session is available in the Claude mobile app and at https://claude.ai/code/session_x.
     Disconnect this session
     Show QR code   Scan with your phone to open this session
   ❯ Continue
   Enter to select · Esc to continue";

/// the menu of a host with Remote Control off (2.1.310)
const RC_MENU_OFF: &str = "❯ /remote-control
  ⎿  Remote Control disconnected.
────────────────────────────────────────
 Remote Control
   Take this session with you and pick up right where you left off on any device.
   /remote-control.
   ❯ 1. Enable Remote Control  Opens a secure connection to claude.ai.
     2. Never mind             You can always enable it later with /remote-control.";

#[test]
fn rc_menu() {
    let m = open_menu(RC_MENU_ON);
    assert_eq!(menu_distance(&m, RC_DISCONNECT_TEXT), Some(-2));
    let off = open_menu(RC_MENU_OFF);
    assert_eq!(
        menu_distance(&off, crate::claudelogin::RC_ENABLE_TEXT),
        Some(0)
    );
    assert!(
        open_menu("❯ Disconnect this session\n").is_empty()
            && open_menu("Remote Control\n❯ Disconnect this session\n").is_empty()
    );
    assert_eq!(
        menu_distance(&m, crate::claudelogin::RC_ENABLE_TEXT),
        None,
        "a choice the menu lacks was found"
    );
}

/// the menu with its cursor one choice higher
fn cursor_up(menu: &str) -> String {
    let mut ls: Vec<String> = menu.split('\n').map(String::from).collect();
    for i in 1..ls.len() {
        if ls[i].starts_with("   ❯ ") && ls[i - 1].starts_with("     ") {
            let cur = format!("     {}", &ls[i]["   ❯ ".len()..]);
            let prev = format!("   ❯ {}", &ls[i - 1][5..]);
            ls[i] = cur;
            ls[i - 1] = prev;
            break;
        }
    }
    ls.join("\n")
}

/// reviving as Claude Code 2.1.310 does it: a held entry is disconnected (two lines up in its menu), and the next
/// /remote-control enables at once; a host with Remote Control off gets the Enable menu
#[test]
fn revive_remote_control_types_the_menu() {
    for (held, want) in [
        (
            "session_old",
            "-l /remote-control|Enter|Up|Up|Enter|-l /remote-control|Enter",
        ),
        ("", "-l /remote-control|Enter|Enter"),
    ] {
        let e = TestEnv::new();
        let sess = e.home.join(".claude/sessions");
        std::fs::create_dir_all(&sess).unwrap();
        crate::rcwatch::RC_STEP_WAIT_MS.store(2000, std::sync::atomic::Ordering::SeqCst);
        crate::claudelogin::RC_UP_WAIT_MS.store(2000, std::sync::atomic::Ordering::SeqCst);
        let reg = {
            let sess = sess.clone();
            move |bridge: &str| {
                let b = serde_json::json!({"status": "idle", "pid": std::process::id(), "bridgeSessionId": bridge});
                std::fs::write(sess.join("1.json"), b.to_string()).unwrap();
            }
        };
        reg(held);
        #[derive(Default)]
        struct St {
            pane: String,
            typed: bool,
            just_off: bool,
            keys: Vec<String>,
        }
        let st = Arc::new(Mutex::new(St {
            pane: "❯ ".into(),
            ..Default::default()
        }));
        let s1 = st.clone();
        *crate::claudelogin::TEST_PANE.lock().unwrap() =
            Some(Arc::new(move || s1.lock().unwrap().pane.clone()));
        let s2 = st.clone();
        let reg2 = reg.clone();
        *crate::claudelogin::TEST_KEYS.lock().unwrap() = Some(Arc::new(move |a: &[&str]| {
            let mut s = s2.lock().unwrap();
            let k = a.join(" ");
            s.keys.push(k.clone());
            let m = open_menu(&s.pane);
            if k == "-l /remote-control" {
                s.typed = true;
            } else if k == "Up" {
                s.pane = cursor_up(&s.pane);
            } else if k == "Enter" && s.typed && s.just_off {
                s.typed = false;
                s.pane = "❯ ".into();
                reg2("session_new");
            } else if k == "Enter" && s.typed {
                s.typed = false;
                s.pane = if crate::claudelogin::live_bridge().is_empty() {
                    RC_MENU_OFF.into()
                } else {
                    RC_MENU_ON.into()
                };
            } else if k == "Enter" {
                if menu_distance(&m, RC_DISCONNECT_TEXT) == Some(0) {
                    reg2("");
                    s.just_off = true;
                } else if menu_distance(&m, crate::claudelogin::RC_ENABLE_TEXT) == Some(0) {
                    reg2("session_new");
                }
                s.pane = "❯ ".into();
            }
            Ok(())
        }));
        let h = held.to_string();
        let t = std::thread::spawn(move || revive_remote_control(&h));
        let start = Instant::now();
        while !t.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(20), "revive hung");
            std::thread::sleep(Duration::from_millis(50));
        }
        let got = st.lock().unwrap().keys.join("|");
        assert_eq!(got, want, "held {held:?}");
        assert_eq!(crate::claudelogin::live_bridge(), "session_new");
        drop(e);
    }
}

fn dialog_pane() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tests/testdata/permission-dialog.txt"
    ))
    .unwrap()
}

#[test]
fn permission_dialog_found() {
    let (ok, what) = permission_dialog(&dialog_pane());
    assert!(
        ok && what.starts_with("Bash command")
            && what.contains("touch made-by-test.txt")
            && what.ends_with("Do you want to proceed?"),
        "{ok} {what:?}"
    );
}

#[test]
fn permission_dialog_others_left_alone() {
    let pane = dialog_pane();
    let moved = pane
        .replacen("❯ 1. Yes", "  1. Yes", 1)
        .replacen("  4. No", "❯ 4. No", 1);
    let quoted = format!("{pane}\n● done\n\n────\n❯ \n────\n  ⏵⏵ bypass permissions on\n");
    for (name, s) in [
        ("trust", " Quick safety check: Is this a project you created or one you trust?\n ❯ No, exit\n   Yes, I trust this folder\n\n Enter to confirm · Esc to cancel\n".to_string()),
        ("moved", moved),
        ("apikey", " Do you want to use this API key?\n ❯ 1. Yes\n   2. No (recommended)\n\n Enter to confirm · Esc to cancel\n".to_string()),
        ("plan", " Would you like to proceed?\n ❯ 1. Yes, and auto-accept edits\n   2. Yes, and manually approve edits\n Esc to cancel\n".to_string()),
        ("quoted", quoted),
        ("empty", String::new()),
    ] {
        assert!(!permission_dialog(&s).0, "{name}: taken for a tool permission dialog");
    }
}

#[test]
fn permission_dialog_other_tools() {
    for q in [
        "Do you want to make this edit to main.go?",
        "Do you want to create notes.md?",
        "Do you want to allow Claude to fetch this content?",
    ] {
        let s = format!(
            " Edit file\n {q}\n ❯ 1. Yes\n   2. Yes, allow all edits during this session\n   3. No\n\n Esc to cancel · Tab to amend\n"
        );
        assert!(permission_dialog(&s).0, "{q}: not found");
    }
}

#[test]
fn accept_step_only_in_bypass_and_at_most_twice() {
    let pane = dialog_pane();
    let mut s = AcceptState::default();
    assert!(
        !accept_step(&mut s, "auto", &pane).0,
        "pressed in auto mode"
    );
    for (i, want) in [true, true, false, false].iter().enumerate() {
        assert_eq!(
            accept_step(&mut s, "bypass", &pane).0,
            *want,
            "look {i} on the same dialog"
        );
    }
    assert!(
        !accept_step(&mut s, "bypass", "❯ \n").0,
        "pressed with no dialog"
    );
    assert!(
        accept_step(&mut s, "bypass", &pane).0,
        "the next dialog (same text, after it had gone) not pressed"
    );
}
