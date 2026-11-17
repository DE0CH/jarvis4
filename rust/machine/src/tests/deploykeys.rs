//! deploykeys_test.go: each repo its own deploy key, in the supervisor's agent; git's rewrites and ssh's aliases.

use super::testutil::*;
use crate::deploykeys::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

fn test_key(dir: &Path) -> String {
    let f = dir.join(format!("k{}", rand::random::<u32>()));
    let out = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "test", "-f"])
        .arg(&f)
        .output()
        .expect("ssh-keygen");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    B64.encode(std::fs::read(&f).unwrap())
}

fn get_url(u: &str) -> String {
    let mut c = Command::new("git");
    c.args(["ls-remote", "--get-url", u]);
    crate::env::apply(&mut c);
    String::from_utf8_lossy(&c.output().unwrap().stdout).trim().to_string()
}

#[test]
fn deploy_keys_give_each_repo_its_own_key() {
    let e = TestEnv::new();
    crate::env::set("GIT_CONFIG_NOSYSTEM", Some("1"));
    let home = e.home.clone();
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::write(home.join(".ssh/config"), "Host other\n  HostName example.com\n").unwrap();
    let (a, b) = (test_key(&e.root), test_key(&e.root));
    let mut secrets: HashMap<String, String> = [
        ("GITHUB_DEPLOY_REPO_DE0CH_CLAUDE_ENV", "DE0CH/claude-env"),
        ("GITHUB_DEPLOY_KEY_DE0CH_CLAUDE_ENV", a.as_str()),
        ("GITHUB_DEPLOY_REPO_DE0CH_JARVIS2", "DE0CH/jarvis2"),
        ("GITHUB_DEPLOY_KEY_DE0CH_JARVIS2", b.as_str()),
        ("GITHUB_DEPLOY_REPO_DE0CH_BROKEN", "DE0CH/broken"), // no key: skipped
        ("GITHUB_DEPLOY_REPO_EVIL", "../../x"),
        ("GITHUB_DEPLOY_KEY_EVIL", a.as_str()),
        ("OTHER", "x"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    setup_deploy_keys(&secrets).unwrap();
    // the keys, one per repo, in the supervisor's agent; on disk only their public halves
    for n in ["DE0CH__claude-env", "DE0CH__jarvis2"] {
        let b = std::fs::read_to_string(home.join(DEPLOY_KEY_DIR).join(format!("{n}.pub"))).unwrap();
        assert!(b.starts_with("ssh-ed25519 "), "{n}: {b:?}");
    }
    assert_eq!(std::fs::read_dir(home.join(DEPLOY_KEY_DIR)).unwrap().count(), 2);
    let out = Command::new("grep").args(["-rl", "PRIVATE KEY"]).arg(&home).output().unwrap();
    assert!(out.stdout.is_empty(), "a private key on disk: {}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(agent_keys().len(), 2, "keys in the agent");
    // git sends exactly these repos to their own alias; anything else stays as it was
    for (inp, want) in [
        ("https://github.com/DE0CH/claude-env.git", "git@github.com-jarvis2-de0ch-claude-env:DE0CH/claude-env.git"),
        ("git@github.com:DE0CH/claude-env.git", "git@github.com-jarvis2-de0ch-claude-env:DE0CH/claude-env.git"),
        ("https://github.com/de0ch/jarvis2.git", "git@github.com-jarvis2-de0ch-jarvis2:DE0CH/jarvis2.git"),
        ("https://github.com/DE0CH/jarvis2.git", "git@github.com-jarvis2-de0ch-jarvis2:DE0CH/jarvis2.git"),
        ("https://github.com/DE0CH/claude-env-x.git", "https://github.com/DE0CH/claude-env-x.git"),
        ("https://github.com/DE0CH/broken.git", "https://github.com/DE0CH/broken.git"),
        ("https://github.com/someone/else.git", "https://github.com/someone/else.git"),
    ] {
        assert_eq!(get_url(inp), want, "{inp}");
    }
    // ssh: the alias reaches github.com with that key only and GitHub's host keys pinned; our block comes first
    let cfg = std::fs::read_to_string(home.join(".ssh/config")).unwrap();
    assert!(cfg.starts_with(SSH_CONFIG_BEGIN) && cfg.contains("Host other\n"), "ssh config:\n{cfg}");
    for want in [
        format!("IdentityFile ~/{DEPLOY_KEY_DIR}/DE0CH__jarvis2.pub\n"),
        format!("UserKnownHostsFile ~/{GITHUB_KNOWN_HOSTS}\n"),
    ] {
        assert!(cfg.contains(&want), "ssh config lacks {want:?}:\n{cfg}");
    }
    assert!(!cfg.contains(home.to_str().unwrap()), "ssh config names the absolute home:\n{cfg}");
    let mut c = Command::new("ssh");
    c.arg("-F").arg(home.join(".ssh/config")).args(["-G", "github.com-jarvis2-de0ch-jarvis2"]);
    crate::env::apply(&mut c);
    if let Ok(o) = c.output() {
        let g = String::from_utf8_lossy(&o.stdout);
        for want in [
            "hostname github.com\n".to_string(),
            "user git\n".into(),
            "identitiesonly yes\n".into(),
            "stricthostkeychecking true\n".into(),
            format!("identityagent {}\n", crate::paths::ssh_agent_sock().display()),
            format!("/{GITHUB_KNOWN_HOSTS}\n"),
        ] {
            assert!(g.contains(&want), "ssh -G lacks {want:?}");
        }
    }
    let kh = std::fs::read_to_string(home.join(GITHUB_KNOWN_HOSTS)).unwrap();
    assert_eq!(kh.matches("github.com ").count(), 3, "GitHub's host keys aren't pinned");
    // a downgrade to one repo: the other's key and rewrite go; the rest of the ssh config stays
    secrets.remove("GITHUB_DEPLOY_REPO_DE0CH_JARVIS2");
    setup_deploy_keys(&secrets).unwrap();
    assert!(!home.join(DEPLOY_KEY_DIR).join("DE0CH__jarvis2.pub").exists(), "the dropped repo's key stayed");
    {
        let ks = agent_keys();
        assert!(ks.len() == 1 && ks[0].1 == "DE0CH/claude-env", "the agent after the downgrade");
    }
    assert_eq!(get_url("https://github.com/DE0CH/jarvis2.git"), "https://github.com/DE0CH/jarvis2.git", "the dropped repo's rewrite stayed");
    let cfg = std::fs::read_to_string(home.join(".ssh/config")).unwrap();
    assert!(
        cfg.matches(SSH_CONFIG_BEGIN).count() == 1 && !cfg.contains("jarvis2-de0ch-jarvis2") && cfg.contains("Host other\n"),
        "ssh config after:\n{cfg}"
    );
    agent_keys().clear();
}

#[test]
fn clone_url_forms() {
    for (inp, want) in [
        ("https://github.com/DE0CH/x", "https://github.com/DE0CH/x.git"),
        ("https://github.com/DE0CH/x.git", "https://github.com/DE0CH/x.git"),
        ("git@github.com:DE0CH/x.git", "https://github.com/DE0CH/x.git"),
        (" https://gitlab.com/a/b.git ", "https://gitlab.com/a/b.git"),
    ] {
        assert_eq!(clone_url(inp), want, "{inp:?}");
    }
}

fn frame(conn: &mut std::os::unix::net::UnixStream, msg: &[u8]) -> Vec<u8> {
    let mut out = (msg.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(msg);
    conn.write_all(&out).unwrap();
    let mut len = [0u8; 4];
    conn.read_exact(&mut len).unwrap();
    let mut b = vec![0u8; u32::from_be_bytes(len) as usize];
    conn.read_exact(&mut b).unwrap();
    b
}

fn string(b: &[u8]) -> Vec<u8> {
    let mut out = (b.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(b);
    out
}

/// the supervisor's agent signs with the deploy keys it holds and takes no key from outside
#[test]
fn the_supervisors_ssh_agent() {
    let e = TestEnv::new();
    crate::env::set("GIT_CONFIG_NOSYSTEM", Some("1"));
    let secrets: HashMap<String, String> = [("GITHUB_DEPLOY_REPO_X".to_string(), "DE0CH/x".to_string()), ("GITHUB_DEPLOY_KEY_X".to_string(), test_key(&e.root))].into();
    setup_deploy_keys(&secrets).unwrap();
    std::thread::spawn(serve_ssh_agent);
    let mut conn = None;
    for _ in 0..100 {
        if let Ok(c) = std::os::unix::net::UnixStream::connect(crate::paths::ssh_agent_sock()) {
            conn = Some(c);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut conn = conn.expect("the agent's socket");
    // list: one key
    let ans = frame(&mut conn, &[11]);
    assert_eq!(ans[0], 12);
    assert_eq!(u32::from_be_bytes([ans[1], ans[2], ans[3], ans[4]]), 1);
    let blen = u32::from_be_bytes([ans[5], ans[6], ans[7], ans[8]]) as usize;
    let blob = ans[9..9 + blen].to_vec();
    // sign: the signature verifies with that key
    let mut req = vec![13];
    req.extend(string(&blob));
    req.extend(string(b"data"));
    req.extend(0u32.to_be_bytes());
    let ans = frame(&mut conn, &req);
    assert_eq!(ans[0], 14, "the agent refused to sign");
    let pk = ssh_key::PublicKey::from_bytes(&blob).unwrap();
    let slen = u32::from_be_bytes([ans[1], ans[2], ans[3], ans[4]]) as usize;
    let sig = ssh_key::Signature::try_from(&ans[5..5 + slen]).unwrap();
    signature::Verifier::verify(&pk, b"data", &sig).unwrap();
    // remove all: refused, and the key stays
    assert_eq!(frame(&mut conn, &[19]), vec![5], "the agent took a change from a caller");
    assert_eq!(agent_keys().len(), 1, "a caller removed a key");
    agent_keys().clear();
    let _ = std::fs::remove_file(crate::paths::ssh_agent_sock());
}
