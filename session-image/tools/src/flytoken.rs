//! fly-token APP OUT [HOURS]: JARVIS2_FLY_TOKEN (the org token) narrowed with Fly macaroon caveats to app APP (read,
//! write, create, delete, control: Fly needs write to create a machine) and to ONE command inside a machine,
//! /usr/local/bin/jarvis2-init with no arguments (IfPresent: the command limit applies to exec only), optionally valid
//! for HOURS from now; written to OUT (mode 600), never printed. The kernel's spawner gets one for jarvis4-sessions, the
//! preloader one for jarvis4-sessions-preload (docs/PLAN-one-image.md), each sealed to it by
//! `infra/setup.py kernel-fly-token OUT [preloader]`. The caveats are infra/fly-token.sh's (tested 2026-10-09: create
//! and destroy allowed, `cat` refused, jarvis2-init allowed, with an argument refused); flyctl attenuates.

use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, ExitCode};

/// the caveats for app id APP_ID: the app, the one exec, and a validity window when `window` is (now, hours)
pub fn caveats(app_id: &str, window: Option<(i64, i64)>) -> Value {
    let mut c = vec![
        json!({"type": "Apps", "body": {"apps": {app_id: "rwcdC"}}}),
        json!({"type": "IfPresent", "body": {
            "ifs": [{"type": "Commands", "body": [{"args": ["/usr/local/bin/jarvis2-init"], "exact": true}]}],
            "else": "rwcdC"}}),
    ];
    if let Some((now, hours)) = window {
        c.push(json!({"type": "ValidityWindow", "body": {"not_before": now - 60, "not_after": now + hours * 3600}}));
    }
    Value::Array(c)
}

fn app_id(token: &str, app: &str) -> Result<String, String> {
    let q = json!({"query": format!("{{ app(name:\"{app}\"){{ internalNumericId }} }}")});
    let v: Value = ureq::post("https://api.fly.io/graphql")
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(q)
        .map_err(|e| format!("Fly's API: {e}"))?
        .into_json()
        .map_err(|e| format!("Fly's API: {e}"))?;
    match &v["data"]["app"]["internalNumericId"] {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        _ => Err(format!("no Fly app {app} in the token's org")),
    }
}

pub fn run(args: &[String]) -> Result<ExitCode, String> {
    let usage = "usage: fly-token APP OUT [HOURS]";
    let (app, out) = match args {
        [a, o] | [a, o, _] => (a, o),
        _ => return Err(usage.into()),
    };
    let hours = match args.get(2) {
        Some(h) => Some(h.parse::<i64>().map_err(|_| usage.to_string())?),
        None => None,
    };
    let token = std::env::var("JARVIS2_FLY_TOKEN")
        .map_err(|_| "JARVIS2_FLY_TOKEN isn't set".to_string())?;
    let id = app_id(&token, app)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;
    let cav = std::env::temp_dir().join(format!("fly-caveats-{}", std::process::id()));
    fs::write(&cav, caveats(&id, hours.map(|h| (now, h))).to_string())
        .map_err(|e| format!("{}: {e}", cav.display()))?;
    let o = Command::new("flyctl")
        .args(["tokens", "attenuate", "-f"])
        .arg(&cav)
        .env("FLY_API_TOKEN", &token)
        .output();
    let _ = fs::remove_file(&cav);
    let o = o.map_err(|e| format!("flyctl: {e}"))?;
    if !o.status.success() {
        return Err(format!(
            "flyctl tokens attenuate: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(out)
        .map_err(|e| format!("{out}: {e}"))?;
    f.write_all(&o.stdout).map_err(|e| format!("{out}: {e}"))?;
    println!("ok: a token narrowed to {app} and jarvis2-init in {out}");
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_caveats_are_the_app_the_one_exec_and_the_window() {
        let c = caveats("123", None);
        assert_eq!(
            c.to_string(),
            r#"[{"body":{"apps":{"123":"rwcdC"}},"type":"Apps"},{"body":{"else":"rwcdC","ifs":[{"body":[{"args":["/usr/local/bin/jarvis2-init"],"exact":true}],"type":"Commands"}]},"type":"IfPresent"}]"#
        );
        let w = caveats("123", Some((1000, 6)));
        assert_eq!(w[2]["body"]["not_before"], 940);
        assert_eq!(w[2]["body"]["not_after"], 1000 + 6 * 3600);
    }
}
