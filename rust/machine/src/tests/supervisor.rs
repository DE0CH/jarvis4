//! supervisor_test.go.

use super::testutil::*;
use crate::memory::TEST_SIGNALS;
use crate::paths;
use crate::supervisor::*;
use crate::supervisorlog::*;
use nix::sys::signal::Signal;
use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

fn signals() -> String {
    let v = TEST_SIGNALS
        .lock()
        .unwrap()
        .replace(vec![])
        .unwrap_or_default();
    v.iter()
        .map(|(p, s)| {
            format!(
                "{}:{p}",
                if *s == Signal::SIGSTOP {
                    "stop"
                } else if *s == Signal::SIGCONT {
                    "cont"
                } else {
                    "other"
                }
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// pause-harness stops the launcher, the tmux panes and their children (parents first), never the supervisor;
/// resume-harness lets the same ones go on, children first
#[test]
fn pause_and_resume_the_harness() {
    let e = TestEnv::new();
    *crate::keeper::TEST_KEEPER_DIR.write().unwrap() = Some(e.root.clone());
    std::fs::write(crate::keeper::harness_pid_path(), "100").unwrap();
    let (me, keeper) = (std::process::id() as i32, nix::unistd::getppid().as_raw());
    let kids = HashMap::from([
        (100, vec![keeper, 101]),
        (101, vec![102]),
        (200, vec![201]),
        (1, vec![100, 200]),
    ]);
    *TEST_TREE.lock().unwrap() = Some((kids, vec![200, me]));
    *TEST_SIGNALS.lock().unwrap() = Some(vec![]);
    pause_harness().unwrap();
    assert_eq!(signals(), "stop:100 stop:101 stop:102 stop:200 stop:201");
    resume_harness().unwrap();
    assert_eq!(signals(), "cont:201 cont:200 cont:102 cont:101 cont:100");
    assert!(
        resume_harness().is_err(),
        "resumed a harness that isn't paused"
    );
}

/// resume-harness is refused while the session is frozen for its final snapshot; an unknown command is ignored
#[test]
fn unguarded_commands() {
    let _e = TestEnv::new();
    std::fs::write(paths::harness_paused_path(), "100").unwrap();
    *TEST_SIGNALS.lock().unwrap() = Some(vec![]);
    let c = crate::client::Client::with_url("http://127.0.0.1:1", "m1");
    crate::snapshot::FROZEN.store(true, Ordering::SeqCst);
    run_command(&c, "resume-harness");
    assert_eq!(
        signals(),
        "",
        "let the harness go on during the final snapshot"
    );
    crate::snapshot::FROZEN.store(false, Ordering::SeqCst);
    run_command(&c, "resume-harness");
    assert_eq!(signals(), "cont:100", "resume-harness didn't run");
    run_command(&c, "rm -rf /"); // not a command: ignored, nothing runs
    assert_eq!(signals(), "");
}

/// not root (a CLI command, the tests): a command runs as it is; as root (the worker) it goes through `unprotected`,
/// which takes user claude's identity and the default OOM score
#[test]
fn session_command_as_root_and_not() {
    let _e = TestEnv::new();
    use crate::session::{TEST_PRIVILEGED, session_command};
    TEST_PRIVILEGED.store(1, Ordering::SeqCst);
    let c = session_command("bash", &["-c", "true"]);
    assert_eq!(c.get_program(), "bash", "not root: {c:?}");
    TEST_PRIVILEGED.store(2, Ordering::SeqCst);
    let c = session_command("bash", &["-c", "true"]);
    let args: Vec<_> = c
        .get_args()
        .take(3)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert!(
        c.get_program() == "/proc/self/exe" && args.join(" ") == "unprotected -- bash",
        "as root: {c:?}"
    );
}

/// the supervisor log: boot's and the supervisor's lines, pushed once each (also across a worker restart), with any
/// value the supervisor holds replaced, rotated once pushed
#[test]
fn supervisor_log_push() {
    let e = TestEnv::new();
    crate::secrets::HELD.set(HashMap::from(
        [
            ("A", "hunter2hunter2"),
            ("B", "it's a long one"),
            ("C", "short"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string())),
    ));
    SUPERVISOR_LOG_ROLL.store(400, Ordering::SeqCst);
    let lines: Arc<Mutex<Vec<LogLine>>> = Arc::default();
    let l2 = lines.clone();
    let key = e.machine_key();
    let srv = FakeRouter::new(&key.sig.public_key(), move |r| {
        if r.path != "/m/supervisor-log" {
            return ans(404, "");
        }
        #[derive(serde::Deserialize)]
        struct In {
            lines: Vec<LogLine>,
        }
        let i: In = serde_json::from_slice(&r.body).unwrap();
        l2.lock().unwrap().extend(i.lines);
        ans(200, r#"{"ok":true}"#)
    });
    let c = srv.client();
    let (mut boot, mut sup) = (FileLog::new("boot"), FileLog::new("supervisor"));
    boot.write_all(b"[jarvis] keys ready; waiting for init\n")
        .unwrap();
    sup.write_all(b"[jarvis] exec x refused: token hunter2hunter2 and it's a long one, short\n")
        .unwrap();
    push_log_once(&c).unwrap();
    push_log_once(&c).unwrap(); // nothing new: nothing pushed again
    {
        let l = lines.lock().unwrap();
        assert!(
            l.len() == 2 && l[0].text == "boot: keys ready; waiting for init",
            "pushed {l:?}"
        );
        let t = &l[1].text;
        assert!(
            !t.contains("hunter2")
                && !t.contains("long one")
                && t.contains("[secret]")
                && t.contains("short"),
            "not redacted: {t:?}"
        );
    }
    for i in 0..10 {
        // past the roll size: rotated after the push, nothing lost or repeated
        sup.write_all(format!("[jarvis] line {i}\n").as_bytes())
            .unwrap();
        let _ = push_log_once(&c);
    }
    let l = lines.lock().unwrap();
    assert!(
        l.len() == 12 && l[11].text == "supervisor: line 9",
        "after rotation {} lines, last {:?}",
        l.len(),
        l.last()
    );
    if let Ok(md) = std::fs::metadata(paths::supervisor_log_path()) {
        assert!(md.len() <= 400, "not rotated: {} bytes", md.len());
    }
    crate::secrets::HELD.set(HashMap::new());
}

/// gVisor has no setfsuid (ENOSYS): the supervisors' file identity is then the effective one, with the capabilities
/// Linux drops on a file identity change dropped (fabric boot check 2, 2026-11-18: both supervisors exited on
/// "setfsgid: function not implemented" and the machine refused to start)
#[test]
fn a_file_identity_drops_the_file_capabilities_and_keeps_the_rest() {
    use crate::session::file_identity_caps;
    // a root sandbox's permitted set under gVisor (measured): ffffdfff, and the high word's CAP_MAC_OVERRIDE
    assert_eq!(file_identity_caps([0xffff_dfff, 0x1]), [0xf7ff_dde0, 0x0]);
    // Linux, every capability: what setfsuid leaves (measured: f7fffde0)
    assert_eq!(file_identity_caps([0xffff_ffff, 0x0]), [0xf7ff_fde0, 0x0]);
    // CAP_KILL (5), CAP_SETUID (7), CAP_SYS_ADMIN (21) stay
    let kept = file_identity_caps([u32::MAX, u32::MAX])[0];
    assert!(kept & (1 << 5) != 0 && kept & (1 << 7) != 0 && kept & (1 << 21) != 0);
}
