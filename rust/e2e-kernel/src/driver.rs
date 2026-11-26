//! `e2e-kernel driver`: a kernel line's whole life (the port of e2e/kernel, Go): it plays the iPhone (phone.rs) to set
//! the kernel up, then a new session on the kernel (the phone signs its source), waits for its machine to boot from its
//! kernel documents and pull its secrets, pauses it (its snapshot goes into the next source), resumes it (a new machine
//! restores that snapshot), and destroys it (the source burns). On real Fly also the keeper's checks, a router rollout
//! with a pause in flight and the machine's teardown on a stop signal.

use crate::phone::{
    Phone, call, call_quiet, env, harness_runs, logf, must, read_session, router, s, step, wait_for,
};
use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::time::Duration;

const MIN15: Duration = Duration::from_secs(15 * 60);

/// a session's running machine once it booted from its kernel documents and its harness runs
fn running(id: &str, what: &str) -> Result<String> {
    let mut m = String::new();
    wait_for(what, MIN15, || {
        let (sess, _) = read_session(id);
        let Some(x) = sess else { return Ok(false) };
        if x["state"] == "failed" {
            bail!("{what}: the session failed: {}", s(&x["error"]));
        }
        let mid = s(&x["machineId"]);
        if x["state"] == "started" && !mid.is_empty() && x["booted"] == mid && harness_runs(&x) {
            m = mid.to_string();
            return Ok(true);
        }
        Ok(false)
    })?;
    Ok(m)
}

fn wait_paused(id: &str, what: &str) -> Result<()> {
    wait_for(what, MIN15, || {
        let (sess, _) = read_session(id);
        if let Some(x) = &sess
            && x["state"] == "failed"
        {
            bail!("{what}: the session failed: {}", s(&x["error"]));
        }
        Ok(sess.is_some_and(|x| x["state"] == "paused"))
    })
}

/// a kernel release onto copy `to` (its components start fresh: `release`, which answers their "role=URL,…"), then
/// the root key's roster of it, which retires the serving copy's members and names its empty secrets as secretsBoot;
/// the router flips (kernelflip.rs) and `to` serves
fn flip(
    p: &Phone,
    copies: &mut std::collections::BTreeMap<String, String>,
    serving: &mut String,
    to: &str,
    release: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<()> {
    let r = router();
    step(&format!(
        "a kernel release onto {to} ({}): its components start fresh, the root key signs its roster (the {serving} \
         members retired, its empty secrets as secretsBoot), the router hands {serving} over to it",
        env(&format!("E2E_IMPL_{to}"))
    ));
    copies.insert(to.into(), release(to)?);
    let next = crate::phone::identities(&copies[to])?;
    let cur = crate::phone::identities(&copies[serving.as_str()])?;
    let mut ro = jarvis_sig::Roster {
        copy: to.into(),
        ..Default::default()
    };
    for m in next {
        if m.role == "secrets" {
            ro.secrets_boot = Some(m);
        } else {
            ro.members.push(m);
        }
    }
    for m in cur {
        if m.role == "secrets" {
            ro.members.push(m); // the keys the kit derives, the same in both copies
        } else {
            ro.retired.push(m);
        }
    }
    let out = p.post_roster(&ro)?;
    if out["flip"] != to {
        bail!("the router took {to}'s roster without a flip: {out}");
    }
    wait_for(
        &format!("the flip to {to}"),
        Duration::from_secs(300),
        || {
            let k = must("GET", &format!("{r}/api/kernel"), None)?;
            Ok(
                k["roster"]["serving"] == to
                    && k["roster"]["next"].is_null()
                    && k["serves"] == true,
            )
        },
    )?;
    logf(&format!("the {to} copy serves"));
    *serving = to.into();
    Ok(())
}

/// a pause and a resume of the session on the kernel that serves now: its machine m killed into a source, a new
/// machine from it → that machine
fn pause_resume(id: &str, m: &str, what: &str) -> Result<String> {
    let r = router();
    must(
        "POST",
        &format!("{r}/api/sessions/{id}/pause"),
        Some(&json!({})),
    )?;
    wait_for(&format!("paused {what}"), MIN15, || {
        let (sess, _) = read_session(id);
        let Some(x) = sess else { return Ok(false) };
        if x["state"] == "failed" {
            bail!("pause {what}: the session failed: {}", s(&x["error"]));
        }
        let Ok(cert) = serde_json::from_str::<Value>(s(&x["kernel"]["sourceCert"]["payload"]))
        else {
            return Ok(false);
        };
        let pred = s(&cert["pred"]);
        Ok(x["state"] == "paused" && (pred == format!("fly-{m}") || pred == format!("fabric-{m}")))
    })?;
    must(
        "POST",
        &format!("{r}/api/sessions/{id}/resume"),
        Some(&json!({})),
    )?;
    let m2 = running(id, &format!("the machine {what}"))?;
    if m2 == m {
        bail!("the resume {what} ran on the same machine");
    }
    logf(&format!("machine {m2} booted {what}"));
    Ok(m2)
}

/// `release(copy)` starts that copy's components fresh (their volumes kept) and answers their "role=URL,…"
pub fn main(release: &mut dyn FnMut(&str) -> Result<String>) -> Result<()> {
    let r = router();
    let p = Phone::new()?;
    step(
        "the roster: the root key registered, every component's fresh keys vouched for in one root-signed document",
    );
    p.roster()?;
    step(
        "the kernel's secrets: a Reset with the test master key, naming the phone and the root key",
    );
    p.claim(r#"{"format":"keys"}"#)?;
    p.runner_credentials()?;
    step("the root grant: ⊤ on the sink, signed by the root key");
    p.root_grant()?;

    step("a new session on the kernel; the phone signs its source");
    let runner = env("E2E_RUNNER");
    let mut ns = json!({"label": "e2e on the kernel", "harness": "opencode", "size": "small"});
    if !runner.is_empty() {
        ns["runner"] = json!(runner);
    }
    let created = must("POST", &format!("{r}/api/sessions"), Some(&ns))?;
    let id = s(&created["id"]).to_string();
    let mut a = Value::Null;
    wait_for("the approval", Duration::from_secs(60), || {
        let st = must("GET", &format!("{r}/api/state"), None)?;
        for x in st["approvals"].as_array().into_iter().flatten() {
            if x["session"] == id.as_str() {
                a = x.clone();
            }
        }
        Ok(!a.is_null())
    })?;
    if a["kind"] != "kernel-source" {
        bail!("approval kind {}", a["kind"]);
    }
    let challenge = s(&a["challenge"]["payload"]).to_string();
    let c: Value = serde_json::from_str(&challenge)?;
    logf(&format!(
        "source {}, image {}",
        s(&c["succ"]),
        s(&c["source"]["image"])
    ));
    let ps = p.phone.sign(challenge.as_bytes());
    must(
        "POST",
        &format!("{r}/api/approvals/{}/respond", s(&a["id"])),
        Some(&json!({"signature": ps})),
    )?;

    let m1 = running(
        &id,
        "the first machine to boot from its kernel documents and pull its secrets",
    )?;
    logf(&format!("machine {m1} booted"));
    let on_fly = runner.is_empty();
    if on_fly {
        keeper_step(&id, &m1)?;
    }

    step("pause: the snapshot goes into the next source");
    if on_fly {
        drain_pause(&id)?;
    } else {
        must(
            "POST",
            &format!("{r}/api/sessions/{id}/pause"),
            Some(&json!({})),
        )?;
    }
    let mut snap = String::new();
    wait_for("paused", MIN15, || {
        let (sess, _) = read_session(&id);
        let Some(x) = sess else { return Ok(false) };
        if x["state"] == "failed" {
            bail!("pause: the session failed: {}", s(&x["error"]));
        }
        let sc = &x["kernel"]["sourceCert"];
        if x["state"] != "paused" || sc.is_null() {
            return Ok(false);
        }
        let Ok(cert) = serde_json::from_str::<Value>(s(&sc["payload"])) else {
            return Ok(false);
        };
        let pred = s(&cert["pred"]);
        if pred == format!("fly-{m1}") || pred == format!("fabric-{m1}") {
            snap = s(&cert["source"]["snapshot"]).to_string();
            return Ok(true);
        }
        Ok(false)
    })?;
    if snap.len() < 12 {
        bail!("the paused source names no snapshot");
    }
    logf(&format!(
        "paused into a source holding snapshot {}…",
        &snap[..12]
    ));

    step("resume: a new machine from that source restores the snapshot");
    must(
        "POST",
        &format!("{r}/api/sessions/{id}/resume"),
        Some(&json!({})),
    )?;
    let m2 = running(&id, "the second machine")?;
    if m2 == m1 {
        bail!("the resume ran on the same machine");
    }
    logf(&format!("machine {m2} booted from the snapshot"));
    // a kernel release is a copy flip (docs/PLAN-cluster.md "Releases: the copy flip"): onto green, the line goes on
    // (green's spawner kills the machine blue's made, green's notarizer defines the source, green's secrets serves the
    // next machine), and back onto blue started again (a rollback)
    let mut copies = std::collections::BTreeMap::from([("blue".to_string(), env("E2E_KERNEL"))]);
    let mut serving = "blue".to_string();
    let mut m2 = m2;
    for to in ["green", "blue"] {
        flip(&p, &mut copies, &mut serving, to, release)?;
        m2 = pause_resume(&id, &m2, &format!("after the flip to {to}"))?;
    }
    if on_fly {
        let (file, line) = teardown_step(&id, &m2)?;
        must(
            "POST",
            &format!("{r}/api/sessions/{id}/pause"),
            Some(&json!({})),
        )?;
        wait_paused(&id, "paused after the teardown")?;
        must(
            "POST",
            &format!("{r}/api/sessions/{id}/resume"),
            Some(&json!({})),
        )?;
        let m3 = running(&id, "the machine after the teardown")?;
        expect_on_machine(&m3, &format!("grep -c '{line}' {file}"), "1")?;
        logf(&format!(
            "machine {m3} has the transcript the teardown saved"
        ));
    }

    step("destroy: archived, its source burned");
    must(
        "POST",
        &format!("{r}/api/sessions/{id}/destroy?force=1"),
        Some(&json!({})),
    )?;
    wait_for("the destroy", MIN15, || {
        let (sess, burned) = read_session(&id);
        Ok(sess.is_none() && burned)
    })?;
    println!("e2e kernel: ok");
    Ok(())
}

// ---- on real Fly only (not the fabric: its machines are gVisor sandboxes, with no Fly exec and their own process
// model): the keeper (rust/machine/src/keeper.rs, DECISIONS 218), memory for the supervisor (rust/machine/src/
// oomguard.rs), a router rollout with a pause in flight (rust/router/src/main.rs SIGTERM) and the machine's teardown on
// a stop signal (rust/machine/src/teardown.rs)

/// a command on a Fly machine through the Machines API (the run's own org token) → (stdout, exit code)
fn fly_exec(m: &str, cmd: &[&str]) -> Result<(String, i64)> {
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(90))
        .build()?
        .post(format!(
            "https://api.machines.dev/v1/apps/jarvis4-sessions/machines/{m}/exec"
        ))
        .bearer_auth(env("E2E_FLY_TOKEN"))
        .json(&json!({"command": cmd, "timeout": 60}))
        .send()?;
    let st = resp.status().as_u16();
    let b = resp.bytes()?;
    if st != 200 {
        bail!("HTTP {st} {}", String::from_utf8_lossy(&b));
    }
    let v: Value = serde_json::from_slice(&b)?;
    Ok((
        s(&v["stdout"]).to_string(),
        v["exit_code"].as_i64().unwrap_or(-1),
    ))
}

/// the machine's own processes by their whole command line, so a pattern never matches the exec's own sh -c (which
/// carries the command's text): the keeper re-executes itself ("/proc/self/exe boot"), the supervisors are its children
/// ("/proc/self/exe supervisor --core|--normal …")
const PROCS: &str = "KEEPER='^(/usr/local/bin/jarvis-machine|/proc/self/exe) boot$'; CORE='^/proc/self/exe supervisor --core'; NORMAL='^/proc/self/exe supervisor --normal'; ";

/// exit 0 and stdout (trimmed) exactly want, within ten tries
fn expect_on_machine(m: &str, cmd: &str, want: &str) -> Result<()> {
    let full = format!("{PROCS}{cmd}");
    let mut last = String::new();
    for _ in 0..10 {
        match fly_exec(m, &["sh", "-c", &full]) {
            Ok((out, 0)) if out.trim() == want => {
                logf(&format!("   on {m}: {cmd:?} → {want:?} ok"));
                return Ok(());
            }
            Ok((out, code)) => last = format!("{out:?} (exit {code})"),
            Err(e) => last = format!("{e:#}"),
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    bail!("on {m}, {cmd:?} gave {last}, want {want:?}")
}

/// when the machine last reported its status (the router's record)
fn last_report(id: &str) -> String {
    read_session(id)
        .0
        .map(|x| s(&x["live"]["lastReport"]).to_string())
        .unwrap_or_default()
}

/// a status report newer than before
fn wait_report(id: &str, before: &str, after: &str) -> Result<()> {
    wait_for(
        &format!("a status report from the machine after {after}"),
        Duration::from_secs(90),
        || {
            let lr = last_report(id);
            Ok(!lr.is_empty() && lr != before)
        },
    )
}

/// on a running session's machine m
fn keeper_step(id: &str, m: &str) -> Result<()> {
    step(
        "the keeper: Fly's main child is jarvis-machine boot as root; supervisor-core and supervisor-normal are root; the harness is claude's, in its own session",
    );
    expect_on_machine(
        m,
        r#"k=$(pgrep -o -f "$KEEPER"); ps -o user=,ppid= -p $k | awk '{print $1, $2}'"#,
        "root 1",
    )?;
    expect_on_machine(m, r#"ps -o user= -p $(pgrep -o -f "$CORE")"#, "root")?;
    expect_on_machine(m, r#"ps -o user= -p $(pgrep -o -f "$NORMAL")"#, "root")?;
    expect_on_machine(
        m,
        "h=$(cat /run/jarvis-keeper/harness.pid); ps -o user=,sid= -p $h | awk -v h=$h '{print $1, ($2==h)}'",
        "claude 1",
    )?;
    expect_on_machine(
        m,
        r#"cat /proc/$(pgrep -o -f "$KEEPER")/oom_score_adj /proc/$(pgrep -o -f "$CORE")/oom_score_adj"#,
        "-1000\n-1000",
    )?;

    step(
        "memory for the supervisor: the session is under a memory limit below the machine's RAM, the rescue path under its own; the keeper's and supervisor-core's pages are locked, supervisor-normal is unprotected in the session's cgroup; a session hog over the limit is killed inside it and the supervisor reports on",
    );
    expect_on_machine(
        m,
        "G=/sys/fs/cgroup/memory/jarvis-session; t=$(awk '/MemTotal/{print $2*1024}' /proc/meminfo); l=$(cat $G/memory.limit_in_bytes); [ $l -lt $t ] && [ $((t-l)) -ge $((512<<20)) ] && echo limited",
        "limited",
    )?;
    expect_on_machine(
        m,
        "R=/sys/fs/cgroup/memory/jarvis-rescue; [ $(cat $R/memory.limit_in_bytes) -le $((384<<20)) ] && echo limited",
        "limited",
    )?;
    expect_on_machine(
        m,
        "/usr/local/bin/jarvis-machine unprotected --rescue -- cat /proc/self/cgroup | grep -o ':memory:.*'",
        ":memory:/jarvis-rescue",
    )?;
    expect_on_machine(
        m,
        "G=/sys/fs/cgroup/memory/jarvis-session; grep -qx $(cat /run/jarvis-keeper/harness.pid) $G/cgroup.procs && echo in",
        "in",
    )?;
    expect_on_machine(
        m,
        r#"for p in $(pgrep -o -f "$KEEPER") $(pgrep -o -f "$CORE"); do awk '/VmLck/{print ($2>0)}' /proc/$p/status; done"#,
        "1\n1",
    )?;
    expect_on_machine(
        m,
        r#"G=/sys/fs/cgroup/memory/jarvis-session; grep -qx $(pgrep -o -f "$CORE") $G/cgroup.procs && echo in || echo out"#,
        "out",
    )?;
    expect_on_machine(
        m,
        r#"N=$(pgrep -o -f "$NORMAL"); G=/sys/fs/cgroup/memory/jarvis-session; grep -qx $N $G/cgroup.procs && echo in; cat /proc/$N/oom_score_adj; awk '/VmLck/{print ($2>0)}' /proc/$N/status"#,
        "in\n0\n0",
    )?;
    let hog_before = last_report(id);
    expect_on_machine(
        m,
        "/usr/local/bin/jarvis-machine unprotected -- python3 -c 'a=[]\nwhile True: a.append(b\"x\"*(64<<20))' >/dev/null 2>&1; echo $?",
        "137",
    )?;
    wait_report(id, &hog_before, "the session's hog")?;

    step(
        "the session can't touch the supervisor: kill, pkill -f, a group kill, its OOM score and its environ all fail as claude",
    );
    for c in [
        "kill -TERM $K",
        "kill -KILL $K",
        "kill -TERM -$K",
        "kill -TERM $W",
        "kill -STOP $W",
        "echo 1000 > /proc/$K/oom_score_adj",
        "cat /proc/$W/environ",
    ] {
        expect_on_machine(
            m,
            &format!(
                r#"K=$(pgrep -o -f "$KEEPER"); W=$(pgrep -o -f "$CORE"); su claude -s /bin/sh -c "{c}" >/dev/null 2>&1 && echo worked || echo refused"#
            ),
            "refused",
        )?;
    }
    expect_on_machine(
        m,
        r#"K=$(pgrep -o -f "$KEEPER"); su claude -s /bin/sh -c 'pkill -f jarvis-machine'; sleep 1; kill -0 $K && pgrep -f "$CORE" >/dev/null && echo up"#,
        "up",
    )?;

    step(
        "the incident of 2026-10-21: a session process SIGTERMs the harness's launcher → the machine stays up, the harness starts again",
    );
    expect_on_machine(
        m,
        "su claude -s /bin/sh -c 'kill -TERM $(cat /run/jarvis-keeper/harness.pid)' && echo sent",
        "sent",
    )?;
    expect_on_machine(
        m,
        r#"for i in $(seq 1 40); do grep -q '"starts":2,"running":true' /run/jarvis-keeper/harness.json && break; sleep 1; done; grep -o '"starts":[0-9]*,"running":true' /run/jarvis-keeper/harness.json; grep -o '"lastExit":"[^"]*"' /run/jarvis-keeper/harness.json"#,
        "\"starts\":2,\"running\":true\n\"lastExit\":\"killed by SIGTERM\"",
    )?;
    expect_on_machine(
        m,
        "grep -c 'HARNESS ENDED (killed by SIGTERM)' /run/jarvis/supervisor.log",
        "1",
    )?;

    step(
        "kill -TERM -1 as claude: every session process ends, the keeper and the supervisors don't; the harness starts again",
    );
    expect_on_machine(
        m,
        r#"su claude -s /bin/sh -c 'kill -TERM -1'; sleep 2; pgrep -o -f "$KEEPER" >/dev/null && pgrep -f "$CORE" >/dev/null && echo up"#,
        "up",
    )?;
    expect_on_machine(
        m,
        r#"for i in $(seq 1 60); do grep -q '"starts":3,"running":true' /run/jarvis-keeper/harness.json && break; sleep 1; done; grep -o '"starts":[0-9]*,"running":true' /run/jarvis-keeper/harness.json"#,
        "\"starts\":3,\"running\":true",
    )?;

    step(
        "supervisor-normal dies (as a full session's OOM kill would end it): supervisor-core carries on, the keeper starts it again",
    );
    expect_on_machine(
        m,
        r#"C=$(pgrep -o -f "$CORE"); N=$(pgrep -o -f "$NORMAL"); kill -KILL $N; for i in $(seq 1 20); do M=$(pgrep -o -f "$NORMAL"); [ -n "$M" ] && [ "$M" != $N ] && break; sleep 1; done; [ "$(pgrep -o -f "$CORE")" = $C ] && [ -n "$M" ] && [ "$M" != $N ] && echo restarted"#,
        "restarted",
    )?;
    wait_report(id, &last_report(id), "the harness restarts") // supervisor-normal reports on through it all
}

/// the router's own process (E2E_ROUTER_BIN, not its m-gateway), as e2e-kernel started it
fn router_pid() -> i32 {
    let bin = env("E2E_ROUTER_BIN");
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return 0;
    };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let p = e.path();
        if std::fs::read_link(p.join("exe"))
            .ok()
            .is_none_or(|x| x.to_string_lossy() != bin)
        {
            continue;
        }
        if std::fs::read(p.join("cmdline"))
            .is_ok_and(|c| String::from_utf8_lossy(&c).contains("m-gateway"))
        {
            continue;
        }
        return pid;
    }
    0
}

fn alive(pid: i32) -> bool {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok()
}

/// a router rollout while a pause is in flight (rust/router/src/main.rs, SIGTERM). SIGTERM reaches the router right
/// after the pause began: it leaves the Service (/readyz 503) and hands the scheduler's lease on, goes on serving
/// (reads, and the machine's snapshot), lets the pause finish as its own job, then says "stopped" and exits;
/// e2e-kernel starts the next router on the same database, which finds the session paused
fn drain_pause(id: &str) -> Result<()> {
    step(
        "a rollout: SIGTERM with a pause in flight → out of the Service, reads served, the pause finishes, then the router exits and the next one takes over",
    );
    let r = router();
    let pid = router_pid();
    if pid == 0 {
        bail!("rollout: no router process (E2E_ROUTER_BIN)");
    }
    must(
        "POST",
        &format!("{r}/api/sessions/{id}/pause"),
        Some(&json!({})),
    )?;
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGTERM,
    )
    .map_err(|e| anyhow::anyhow!("SIGTERM to the router: {e}"))?;
    let log_text = || std::fs::read_to_string(env("E2E_ROUTER_LOG")).unwrap_or_default();
    // the signal is taken asynchronously: the stop has begun once the router says so
    let end = std::time::Instant::now() + Duration::from_secs(60);
    while !log_text().contains("stopping: out of the Service") {
        if std::time::Instant::now() > end {
            bail!("the router never said it was stopping");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let (code, _) = call_quiet("GET", &format!("{r}/readyz"));
    if code != 503 {
        bail!("GET /readyz while stopping: {code}, not 503 (still in the Service)");
    }
    let (code, b) = call_quiet("GET", &format!("{r}/api/state"));
    if code != 200 {
        bail!(
            "GET /api/state while stopping: {code} {}",
            String::from_utf8_lossy(&b)
        );
    }
    wait_for("the stopping router to exit", MIN15, || Ok(!alive(pid)))?;
    let l = log_text();
    match (l.rfind("snapshot committed"), l.rfind(" stopped\n")) {
        (Some(c), Some(st)) if c < st => {}
        _ => bail!("the stopping router did not finish the pause's snapshot before it stopped"),
    }
    wait_for("the next router", Duration::from_secs(120), || {
        let p = router_pid();
        if p == 0 || p == pid {
            return Ok(false);
        }
        Ok(call_quiet("GET", &format!("{r}/api/kernel")).0 == 200)
    })?;
    match read_session(id).0 {
        Some(x) if x["state"] == "paused" => Ok(()),
        x => bail!("the in-flight pause ended {x:?}"),
    }
}

/// a stop signal to Fly's main child on machine m, as Fly's stop sends it → the changed transcripts reach the router
/// first, then the final snapshot, committed, then the keeper exits; returns the transcript file and line written, for
/// the resume to find
fn teardown_step(id: &str, m: &str) -> Result<(String, String)> {
    step(
        "a stop signal to Fly's main child: the transcript tail first, then the final snapshot, then the keeper's exit",
    );
    let tag = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let file = format!(
        "/home/claude/.claude/projects/-e2e/0e2e0000-2222-4333-8444-{}.jsonl",
        &tag[tag.len().saturating_sub(12)..]
    );
    let line = format!("e2e tail {tag}");
    expect_on_machine(
        m,
        &format!(
            r#"mkdir -p /home/claude/.claude/projects/-e2e && echo '{{"type":"user","message":{{"content":"{line}"}}}}' > {file} && chown -R claude /home/claude/.claude && kill -TERM $(pgrep -o -f "$KEEPER") && echo sent"#
        ),
        "sent",
    )?;
    let r = router();
    wait_for("the teardown's log", Duration::from_secs(300), || {
        let Ok((200, b)) = call("GET", &format!("{r}/api/sessions/{id}/events"), None) else {
            return Ok(false);
        };
        let ev: Value = serde_json::from_slice(&b).unwrap_or_default();
        let texts: Vec<&str> = ev["events"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|e| s(&e["text"]))
            .collect();
        Ok(texts.iter().any(|t| t.contains("teardown 1/2:"))
            && texts
                .iter()
                .any(|t| t.contains("snapshot streamed and committed"))
            && texts.iter().any(|t| t.contains("teardown done")))
    })?;
    Ok((file, line))
}
