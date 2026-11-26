//! runners_test.go (TestRunnersGoWithTheirSession and TestARestartKeepsRunners run on the core-line rig: the
//! runners' part of a pause and destroy is the same on a kernel line)
use crate::runners::{
    HETZNER, HetznerFn, MAX_SESSION_RUNNERS, RUNNERS_FORCE, key_body, runner_key_name,
};
use crate::schedule::normalize_wakeup;
use crate::state::{Record, Session};
use crate::testutil::*;
use jarvis_go::GoTime;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// the Cloud API as runners.rs uses it (servers and key objects of one project)
#[derive(Default)]
struct FakeHetzner {
    next: i64,
    servers: BTreeMap<i64, Value>,
    keys: BTreeMap<i64, Value>,
    actions: Vec<String>,
    /// servers whose delete Hetzner refuses
    fail: BTreeMap<i64, bool>,
}

static HZ: Mutex<Option<FakeHetzner>> = Mutex::new(None);

fn hz<R>(f: impl FnOnce(&mut FakeHetzner) -> R) -> R {
    let mut g = HZ.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(|| FakeHetzner {
        next: 100,
        ..Default::default()
    }))
}

impl FakeHetzner {
    fn add(&mut self, name: &str, labels: Value) -> i64 {
        self.next += 1;
        let n = self.next;
        self.servers.insert(
            n,
            json!({"id": n, "name": name, "status": "running", "created": format!("2026-11-17T03:00:{:02}Z", n % 60),
                "labels": if labels.is_null() { json!({}) } else { labels }, "location": {"name": "fsn1"},
                "server_type": {"name": "cx23", "cores": 2, "memory": 4.0, "prices": [
                    {"location": "fsn1", "price_monthly": {"gross": "6.5880000000000000"}}]},
                "public_net": {"ipv6": {"ip": format!("2a01:4f8:c0c:{n:x}::/64")}}}),
        );
        n
    }

    fn names(&self) -> String {
        let mut out: Vec<String> = self
            .servers
            .values()
            .map(|s| s["name"].as_str().unwrap_or_default().to_string())
            .collect();
        out.sort();
        out.join(" ")
    }
}

fn hz_err(status: u16, code: &str, msg: &str) -> anyhow::Error {
    crate::runners::HzError {
        status,
        code: code.into(),
        message: msg.into(),
    }
    .into()
}

fn fake_hetzner(method: &str, target: &str, input: Option<&Value>) -> anyhow::Result<Vec<u8>> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let q: BTreeMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let qget = |k: &str| q.get(k).cloned().unwrap_or_default();
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    let id: i64 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
    let input = input.cloned().unwrap_or_default();
    let out = |v: Value| Ok(jarvis_go::marshal(&v).into_bytes());
    hz(|f| match (method, parts[0], parts.len()) {
        ("GET", "servers", 1) => {
            let sel = qget("label_selector");
            let list: Vec<Value> = f
                .servers
                .values()
                .filter(|s| match sel.split_once('=') {
                    _ if sel.is_empty() => true,
                    Some((k, v)) => s["labels"][k] == v,
                    None => false,
                })
                .cloned()
                .collect();
            out(json!({"servers": list, "meta": {"pagination": {"next_page": null}}}))
        }
        ("POST", "servers", 1) => {
            if f.servers.values().any(|s| s["name"] == input["name"]) {
                return Err(hz_err(
                    409,
                    "uniqueness_error",
                    "server name is already used",
                ));
            }
            let nid = f.add(
                input["name"].as_str().unwrap_or_default(),
                input["labels"].clone(),
            );
            if let Some(s) = f.servers.get_mut(&nid) {
                s["request"] = input.clone();
            }
            out(json!({"server": f.servers.get(&nid).cloned().unwrap_or_default()}))
        }
        ("DELETE", "servers", _) => {
            if f.fail.get(&id).copied().unwrap_or(false) {
                return Err(hz_err(423, "locked", "server is locked"));
            }
            if f.servers.remove(&id).is_none() {
                return Err(hz_err(404, "not_found", "server not found"));
            }
            out(json!({"action": {"status": "running"}}))
        }
        ("POST", "servers", 4) => {
            let name = f
                .servers
                .get(&id)
                .map(|s| s["name"].as_str().unwrap_or_default().to_string())
                .unwrap_or_default();
            f.actions.push(format!("{name} {}", parts[3]));
            out(json!({"action": {"status": "running"}}))
        }
        ("GET", "ssh_keys", 1) => {
            let name = qget("name");
            let list: Vec<Value> = f
                .keys
                .values()
                .filter(|k| k["name"] == name.as_str())
                .cloned()
                .collect();
            out(json!({"ssh_keys": list}))
        }
        ("POST", "ssh_keys", 1) => {
            f.next += 1;
            let mut k = input.clone();
            k["id"] = json!(f.next);
            f.keys.insert(f.next, k.clone());
            out(json!({"ssh_key": k}))
        }
        ("DELETE", "ssh_keys", _) => {
            f.keys.remove(&id);
            Ok(vec![])
        }
        _ => Err(hz_err(404, "not_found", &format!("{method} {path}"))),
    })
}

/// the fake Hetzner in place of the live one while it lives (the seams are global: it holds serial())
struct HzGuard {
    saved: HetznerFn,
    _s: std::sync::MutexGuard<'static, ()>,
}

impl Drop for HzGuard {
    fn drop(&mut self) {
        *HETZNER.write().unwrap_or_else(|e| e.into_inner()) = self.saved;
        RUNNERS_FORCE.store(false, Ordering::SeqCst);
        *HZ.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

fn start_fake_hetzner() -> HzGuard {
    let s = serial();
    *HZ.lock().unwrap_or_else(|e| e.into_inner()) = None;
    let saved = std::mem::replace(
        &mut *HETZNER.write().unwrap_or_else(|e| e.into_inner()),
        fake_hetzner as HetznerFn,
    );
    RUNNERS_FORCE.store(true, Ordering::SeqCst);
    HzGuard { saved, _s: s }
}

const TEST_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3Qta2V5LW9mLWEtc2Vzc2lvbi1ydW5uZXIh hz-runner-sA";

fn err_of(out: &Value) -> String {
    out["error"].as_str().unwrap_or_default().to_string()
}

/// a session makes, lists, acts on and deletes its own runners through its machine: the server carries the session's
/// label whatever the caller sends, has no IPv4 and the session's key; another session can't touch it
#[test]
fn a_sessions_runners_are_its_own() {
    let _hz = start_fake_hetzner();
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sA", "started", "mA", false);
    add_session(&r, "sC", "started", "mC", false);
    let (ma, mc) = (new_test_machine(&r, "mA"), new_test_machine(&r, "mC"));
    let h = t.machine_handler();
    let body = jarvis_go::marshal(
        &json!({"name": "build-1", "type": "cpx42", "sshKey": TEST_PUB,
        "userData": "#!/bin/bash\ntrue\n", "labels": {"session": "sC", "purpose": "mine", "role": "gw"}}),
    );
    let (code, out) = ma.do_(&h, "POST", "/m/api/sessions/sA/runners", &body);
    assert!(
        code == 200
            && out["name"] == "build-1"
            && out["sessionId"] == "sA"
            && out["ipv6"].as_str().is_some_and(|i| i.ends_with("::1"))
            && out["monthly"] == "EUR 6.59/month",
        "{code} {out}"
    );
    let made = hz(|f| f.servers.values().next().cloned().unwrap_or_default());
    let (labels, req) = (&made["labels"], &made["request"]);
    assert!(
        labels["session"] == "sA" && labels["purpose"] == "runner" && labels["role"] == "gw",
        "labels {labels}"
    );
    let pn = &req["public_net"];
    assert!(
        pn["enable_ipv4"] == false
            && pn["enable_ipv6"] == true
            && req["server_type"] == "cpx42"
            && req["image"] == "ubuntu-24.04"
            && req["location"] == "fsn1"
            && req["ssh_keys"].as_array().is_some_and(|a| a.len() == 1)
            && req["user_data"] == "#!/bin/bash\ntrue\n",
        "request {req}"
    );
    let keys = hz(|f| f.keys.values().cloned().collect::<Vec<_>>());
    assert!(
        keys.len() == 1
            && keys[0]["name"] == "runner-sA"
            && keys[0]["public_key"] == key_body(TEST_PUB).as_str(),
        "keys {keys:?}"
    );
    // the same name again, a bad name, no key, another session's path
    let (code, out) = ma.do_(&h, "POST", "/m/api/sessions/sA/runners", &body);
    assert_eq!(code, 409, "{out}");
    let bad = format!(r#"{{"name":"Bad_Name","sshKey":"{TEST_PUB}"}}"#);
    assert_eq!(
        ma.do_(&h, "POST", "/m/api/sessions/sA/runners", &bad).0,
        400,
        "a bad name"
    );
    assert_eq!(
        ma.do_(
            &h,
            "POST",
            "/m/api/sessions/sA/runners",
            r#"{"name":"nokey"}"#
        )
        .0,
        400,
        "no key"
    );
    assert_eq!(
        mc.do_(&h, "POST", "/m/api/sessions/sA/runners", &body).0,
        403,
        "another session's path"
    );
    // sC sees none of sA's, and can neither act on nor delete it
    let (code, out) = mc.do_(&h, "GET", "/m/api/sessions/sC/runners", "");
    assert!(
        code == 200 && out["runners"].as_array().is_some_and(Vec::is_empty),
        "{code} {out}"
    );
    assert_eq!(
        mc.do_(&h, "DELETE", "/m/api/sessions/sC/runners/build-1", "")
            .0,
        400,
        "deleted another session's runner"
    );
    let code = mc
        .do_(
            &h,
            "POST",
            "/m/api/sessions/sC/runners/build-1/poweroff",
            "",
        )
        .0;
    assert!(
        code == 400 && hz(|f| f.actions.is_empty()),
        "acted on another session's runner"
    );
    let (code, out) = ma.do_(&h, "GET", "/m/api/sessions/sA/runners", "");
    assert!(
        code == 200 && out["runners"].as_array().is_some_and(|a| a.len() == 1),
        "{code} {out}"
    );
    let code = ma
        .do_(
            &h,
            "POST",
            "/m/api/sessions/sA/runners/build-1/poweroff",
            "",
        )
        .0;
    let actions = hz(|f| f.actions.clone());
    assert!(
        code == 200 && actions == ["build-1 poweroff"],
        "{code} {actions:?}"
    );
    assert_eq!(
        ma.do_(&h, "POST", "/m/api/sessions/sA/runners/build-1/rebuild", "")
            .0,
        400,
        "an action that isn't offered"
    );
    // a session on a new machine has a new key: the key object is replaced
    let other = TEST_PUB.replacen("AAAAIHRl", "AAAAIHRm", 1);
    let (code, out) = ma.do_(
        &h,
        "POST",
        "/m/api/sessions/sA/runners",
        &format!(r#"{{"name":"build-2","sshKey":"{other}"}}"#),
    );
    assert_eq!(code, 200, "{out}");
    let keys = hz(|f| f.keys.values().cloned().collect::<Vec<_>>());
    assert!(
        keys.len() == 1 && keys[0]["public_key"] == key_body(&other).as_str(),
        "keys {keys:?}"
    );
    // the last runner takes the key with it
    let code = ma
        .do_(&h, "DELETE", "/m/api/sessions/sA/runners/build-1", "")
        .0;
    assert!(code == 200 && hz(|f| f.keys.len()) == 1, "{code}");
    let code = ma
        .do_(&h, "DELETE", "/m/api/sessions/sA/runners/build-2", "")
        .0;
    assert!(
        code == 200 && hz(|f| f.keys.is_empty() && f.servers.is_empty()),
        "{code}"
    );
    // a session has at most MAX_SESSION_RUNNERS
    for i in 0..MAX_SESSION_RUNNERS {
        hz(|f| f.add(&format!("r{i}"), json!({"session": "sA"})));
    }
    let (code, out) = ma.do_(
        &h,
        "POST",
        "/m/api/sessions/sA/runners",
        &format!(r#"{{"name":"one-more","sshKey":"{TEST_PUB}"}}"#),
    );
    assert!(
        code == 400 && err_of(&out).contains("delete one first"),
        "{code} {out}"
    );
}

/// with no token the routes say so and a pause or destroy passes them by
#[test]
fn runners_not_set_up() {
    let _g = serial(); // HETZNER, RUNNERS_FORCE: the live ones
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sA", "started", "mA", false);
    let ma = new_test_machine(&r, "mA");
    let (code, out) = ma.do_(
        &t.machine_handler(),
        "GET",
        "/m/api/sessions/sA/runners",
        "",
    );
    assert!(
        code == 503 && err_of(&out).contains("HETZNER_RUNNERS_TOKEN"),
        "{code} {out}"
    );
    assert_eq!(inbox_do(&r, "GET", "/api/runners", "", true).0, 503);
}

fn wakeup_in(r: &crate::router::Router, sid: &str, secs: i64, prompt: &str) {
    let mut b = Map::new();
    b.insert("delaySeconds".into(), json!(secs));
    b.insert("prompt".into(), json!(prompt));
    let w = normalize_wakeup(&b, GoTime::now()).unwrap_or_else(|e| panic!("{e:#}"));
    r.arm_wakeup(sid, w).unwrap_or_else(|e| panic!("{e:#}"));
}

/// the Machines view lists every server of the project with its session, or why it stands out: no session label, a
/// session that is gone or destroyed, a paused session nothing will wake. Delete is only for those.
#[test]
fn runners_overview_shows_strays() {
    let _hz = start_fake_hetzner();
    let t = new_test_router();
    let r = t.r.clone();
    add_session(&r, "sRun", "started", "mRun", false);
    add_session(&r, "sIdle", "paused", "", false);
    add_session(&r, "sWake", "paused", "", false);
    wakeup_in(&r, "sWake", 3600, "check the build");
    r.st.do_(|d| {
        d.records.push(Record {
            session: Session {
                id: "sDead".into(),
                ..Default::default()
            },
            ..Default::default()
        })
    });
    let ids: BTreeMap<&str, i64> = hz(|f| {
        BTreeMap::from([
            (
                "of-running",
                f.add(
                    "of-running",
                    json!({"session": "sRun", "purpose": "runner"}),
                ),
            ),
            ("of-idle", f.add("of-idle", json!({"session": "sIdle"}))),
            ("of-waking", f.add("of-waking", json!({"session": "sWake"}))),
            (
                "of-destroyed",
                f.add("of-destroyed", json!({"session": "sDead"})),
            ),
            (
                "of-unknown",
                f.add("of-unknown", json!({"session": "sNever"})),
            ),
            ("by-hand", f.add("by-hand", Value::Null)),
        ])
    });
    let (code, out) = inbox_do(&r, "GET", "/api/runners", "", true);
    assert!(
        code == 200 && out["attention"] == 4 && out["project"] == "runners",
        "{code} {out}"
    );
    let mut got = BTreeMap::new();
    for v in out["runners"].as_array().cloned().unwrap_or_default() {
        let att = v["attention"].as_str().unwrap_or_default().to_string();
        let del = v["deletable"].as_bool().unwrap_or(false);
        assert_eq!(
            !att.is_empty(),
            del,
            "{}: stands out {att:?}, deletable {del}",
            v["name"]
        );
        got.insert(v["name"].as_str().unwrap_or_default().to_string(), att);
    }
    for (name, att) in [
        ("of-running", ""),
        ("of-waking", ""),
        (
            "of-idle",
            "Its session is paused and nothing is armed to wake it",
        ),
        ("of-destroyed", "Its session was destroyed"),
        ("of-unknown", "Its session is gone"),
        ("by-hand", "No session: made outside Jarvis 4"),
    ] {
        assert_eq!(got.get(name).map(String::as_str), Some(att), "{name}");
    }
    // Delete: refused for a runner of a session at work or one that will wake, done for a stray
    for name in ["of-running", "of-waking"] {
        let (code, out) = inbox_do(
            &r,
            "POST",
            &format!("/api/runners/{}/delete", ids[name]),
            "",
            true,
        );
        assert!(
            code == 400 && err_of(&out).contains("goes with its session"),
            "{name}: {code} {out}"
        );
    }
    for name in ["of-idle", "of-destroyed", "of-unknown", "by-hand"] {
        let (code, out) = inbox_do(
            &r,
            "POST",
            &format!("/api/runners/{}/delete", ids[name]),
            "",
            true,
        );
        assert_eq!(code, 200, "{name}: {out}");
    }
    assert_eq!(hz(|f| f.names()), "of-running of-waking");
    assert_eq!(
        inbox_do(&r, "POST", "/api/runners/999/delete", "", true).0,
        400,
        "a runner that isn't there"
    );
}

fn notes(rg: &Rig) -> String {
    rg.lc_lines("s1")
        .iter()
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect()
}

/// s1 running on m2 with its final snapshot in
fn running_with_snapshot(rg: &Rig) {
    rg.running_m2(false);
    rg.write_snapshot("m2", &rg.files);
}

fn pause_and_wait(rg: &Rig) {
    rg.pause("s1").unwrap_or_else(|e| panic!("{e:#}"));
    rg.wait_action_end("s1", "paused")
        .unwrap_or_else(|e| panic!("{e:#} {}", rg.session("s1").error));
}

/// a pause deletes the session's runners unless a wakeup is armed; a destroy deletes them; a runner Hetzner won't
/// delete doesn't fail the pause
#[test]
fn runners_go_with_their_session() {
    let _hz = start_fake_hetzner();
    let rg = Rig::with(|c| c.no_access = true);
    hz(|f| f.add("someone-elses", json!({"session": "sOther"})));
    // a wakeup is armed: the pause keeps the runners
    wakeup_in(&rg, "s1", 7200, "look at the runner");
    let stuck = hz(|f| {
        f.add("keep-1", json!({"session": "s1"}));
        let stuck = f.add("stuck-1", json!({"session": "s1"}));
        f.keys.insert(
            1,
            json!({"id": 1, "name": runner_key_name("s1"), "public_key": key_body(TEST_PUB)}),
        );
        stuck
    });
    running_with_snapshot(&rg);
    pause_and_wait(&rg);
    assert!(
        hz(|f| f.names() == "keep-1 someone-elses stuck-1" && f.keys.len() == 1),
        "{}",
        hz(|f| f.names())
    );
    assert!(
        notes(&rg).contains("kept the session's 2 runner(s): a wakeup or cron is armed"),
        "{}",
        notes(&rg)
    );
    // the wakeup is cancelled and the session, running again, pauses: its runners go; one Hetzner refuses stays, the
    // pause still ends, and the key stays with it
    rg.cancel_wakeups("s1", &[], true)
        .unwrap_or_else(|e| panic!("{e:#}"));
    hz(|f| f.fail.insert(stuck, true));
    running_with_snapshot(&rg);
    pause_and_wait(&rg);
    assert!(
        hz(|f| f.names() == "someone-elses stuck-1" && f.keys.len() == 1),
        "{}",
        hz(|f| f.names())
    );
    let n = notes(&rg);
    assert!(
        n.contains("deleted the session's runners (paused with no wakeup or cron armed): keep-1")
            && n.contains("a runner was not deleted"),
        "{n}"
    );
    // a destroy deletes what is left, and the key
    hz(|f| f.fail.insert(stuck, false));
    rg.destroy("s1").unwrap_or_else(|e| panic!("{e:#}"));
    wait_for("the record", || {
        rg.st.read(|d| !d.sessions.contains_key("s1"))
    });
    assert!(
        hz(|f| f.names() == "someone-elses" && f.keys.is_empty()),
        "{}",
        hz(|f| f.names())
    );
}

/// the pause of a restart (an Upgrade, a bigger machine) is no pause: the runners stay
#[test]
fn a_restart_keeps_runners() {
    let _hz = start_fake_hetzner();
    let rg = Rig::with(|c| c.no_access = true);
    hz(|f| f.add("mine", json!({"session": "s1"})));
    running_with_snapshot(&rg);
    rg.pause_with("s1", None)
        .unwrap_or_else(|e| panic!("{e:#}"));
    rg.wait_action_end("s1", "paused")
        .unwrap_or_else(|e| panic!("{e:#} {}", rg.session("s1").error));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(hz(|f| f.names()), "mine");
}
