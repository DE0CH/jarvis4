//! secrets_test.go, secretslock_test.go, putkey_test.go and sealtargets_test.go.

use super::testutil::*;
use crate::client::Client;
use crate::crypto::{Keys, open_sealed, sha256_hex};
use crate::putkey::*;
use crate::secrets::*;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use jarvis_sig::{Opener, b64, unb64};
use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn ask(op: &str, keys: &[&str]) -> anyhow::Result<SecretsResp> {
    ask_secrets(
        &SecretsReq {
            op: op.into(),
            keys: keys.iter().map(|k| k.to_string()).collect(),
            ..Default::default()
        },
        Duration::from_secs(5),
    )
}

fn hm(kv: &[(&str, &str)]) -> HashMap<String, String> {
    kv.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// the supervisor serves what it holds over its socket, only the keys a request names (never all of them); each request
/// is logged with the key names and the caller, never a value; nothing is written to disk
#[test]
fn the_supervisor_serves_secrets_from_ram() {
    let e = TestEnv::new();
    crate::env::set("GIT_CONFIG_NOSYSTEM", Some("1"));
    HELD.set(hm(&[
        ("API_KEY", "value-of-api-key"),
        ("OTHER", "other-value-123"),
    ]));
    *crate::supervisorlog::TEST_LOG.lock().unwrap() = Some(vec![]);
    let c = Client::with_url("http://127.0.0.1:1", "m1");
    std::thread::spawn(move || serve_secrets(c));
    for _ in 0..100 {
        if crate::paths::secrets_sock().exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let r = ask("names", &[]).unwrap();
    assert_eq!(r.names.join(","), "API_KEY,OTHER");
    // a client that ends its request with a newline and reads the answer to the end (session-secret, pull-secrets)
    // gets the answer and then an end of file, never a reset (the newline left unread reset every such client)
    for req in [
        "{\"op\":\"names\"}\n",
        "{\"op\":\"get\",\"keys\":[\"API_KEY\"]}\n",
    ] {
        use std::io::{Read, Write};
        let mut s = std::os::unix::net::UnixStream::connect(crate::paths::secrets_sock()).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut b = vec![];
        s.read_to_end(&mut b)
            .unwrap_or_else(|e| panic!("reading the answer to {req:?} to the end: {e}"));
        assert!(
            String::from_utf8_lossy(&b).starts_with("{\"ok\":true"),
            "{req:?}: {}",
            String::from_utf8_lossy(&b)
        );
    }
    // named keys: exactly those
    let r = ask("get", &["API_KEY"]).unwrap();
    assert_eq!(r.secrets.len(), 1);
    assert_eq!(r.secrets["API_KEY"], "value-of-api-key");
    // a name not held is an error naming it, and nothing is handed over
    let r = ask("get", &["API_KEY", "NOPE"]);
    assert!(
        format!("{:#}", r.as_ref().unwrap_err()).contains("NOPE"),
        "an unknown key: {r:?}"
    );
    // no request for all keys
    for (op, keys) in [
        ("all", vec![]),
        ("get", vec![]),
        ("get", vec!["*"]),
        ("dump everything", vec![]),
    ] {
        assert!(ask(op, &keys).is_err(), "{op} {keys:?} answered");
    }
    // boot-env: only to the boot process (harness.pid), only before the machine has booted
    let kd = e.root.join("keeper");
    std::fs::create_dir_all(&kd).unwrap();
    *crate::keeper::TEST_KEEPER_DIR.write().unwrap() = Some(kd.clone());
    *crate::snapshot::TEST_BOOTED.lock().unwrap() = Some(false);
    std::fs::write(kd.join("harness.pid"), "1").unwrap(); // not this test process
    assert!(ask("boot-env", &[]).is_err(), "boot-env to another process");
    std::fs::write(kd.join("harness.pid"), std::process::id().to_string()).unwrap();
    assert_eq!(
        ask("boot-env", &[]).unwrap().secrets.len(),
        2,
        "boot-env to boot"
    );
    *crate::snapshot::TEST_BOOTED.lock().unwrap() = Some(true);
    assert!(ask("boot-env", &[]).is_err(), "boot-env after the boot");
    let l = crate::supervisorlog::TEST_LOG
        .lock()
        .unwrap()
        .clone()
        .unwrap()
        .join("\n");
    assert!(
        !l.contains("value-of-api-key") && !l.contains("other-value"),
        "a value in the log: {l}"
    );
    for want in [
        "secrets: get API_KEY for pid ",
        "secrets: refused get API_KEY NOPE for pid ",
        "(not held: NOPE)",
        "secrets: names (2) for pid ",
        "secrets: unknown op \"all\"",
        "secrets: refused get with no keys",
        "secrets: refused boot-env for pid",
        "secrets: boot-env (2 keys: API_KEY OTHER) for pid ",
    ] {
        assert!(l.contains(want), "log lacks {want:?}: {l}");
    }
    assert!(!e.home.join(".secrets").exists(), "~/.secrets written");
    // a downgrade or a refresh replaces the copy at once
    HELD.set(hm(&[("API_KEY", "v2-value-xx")]));
    let r = ask("get", &["API_KEY"]).unwrap();
    assert_eq!(r.secrets["API_KEY"], "v2-value-xx");
    let _ = std::fs::remove_file(crate::paths::secrets_sock());
}

/// the keeper's memfd keeps the copy across a worker restart, in RAM
#[test]
fn secrets_survive_a_worker_restart() {
    let _e = TestEnv::new();
    crate::env::set("GIT_CONFIG_NOSYSTEM", Some("1"));
    let mem = new_memfd().unwrap();
    let link = std::fs::read_link(format!("/proc/self/fd/{}", mem.as_raw_fd())).unwrap();
    assert!(
        link.to_string_lossy().starts_with("/memfd:"),
        "not a memfd: {link:?}"
    );
    let first = HeldSecrets::new_with_mem(Some(std::fs::File::from(mem.try_clone().unwrap())));
    first.set(hm(&[("K", "kept-value")]));
    let worker = || {
        crate::env::set(SECRETS_FD_ENV, Some(&mem.as_raw_fd().to_string()));
        let h = HeldSecrets::new_with_mem(None);
        h.load_held();
        h
    };
    assert_eq!(
        worker().snapshot().get("K").map(String::as_str),
        Some("kept-value"),
        "after a restart"
    );
    first.set(HashMap::new()); // a downgrade to nothing: the memfd holds nothing either
    assert!(worker().snapshot().is_empty(), "a dropped value survived");
}

/// Two add-store waiters approved together (2026-10-13): under the lock the second pulls only after the first has
/// written, from the router's newest cert at that moment, so the copy ends with the newest
#[test]
fn a_slower_waiter_never_writes_an_older_pull_over_a_newer_one() {
    let e = TestEnv::new();
    let version = Arc::new(Mutex::new(1));
    let current = {
        let v = version.clone();
        move || -> HashMap<String, String> {
            if *v.lock().unwrap() == 1 {
                hm(&[("YYC", "y")])
            } else {
                hm(&[("YYC", "y"), ("IDENTITY", "i")])
            }
        }
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let c1 = current.clone();
    let first = std::thread::spawn(move || {
        refresh_secrets(&|| Ok(()), &|| {
            let m = c1();
            tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(300));
            Ok(m)
        })
        .unwrap();
    });
    rx.recv().unwrap();
    *version.lock().unwrap() = 2; // identity approved meanwhile
    let c2 = current.clone();
    let second = std::thread::spawn(move || {
        refresh_secrets(&|| Ok(()), &|| Ok(c2())).unwrap();
    });
    first.join().unwrap();
    second.join().unwrap();
    let got = HELD.snapshot();
    assert!(
        got.len() == 2 && got["IDENTITY"] == "i",
        "the supervisor ends with {got:?}"
    );
    assert!(!e.home.join(".secrets").exists(), "~/.secrets written");
}

fn gcm_open_aad(key: &[u8], sealed: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < 28 {
        return None;
    }
    let g = Aes256Gcm::new_from_slice(key).ok()?;
    let mut n = [0u8; 12];
    n.copy_from_slice(&sealed[..12]);
    g.decrypt(
        &Nonce::from(n),
        Payload {
            msg: &sealed[12..],
            aad,
        },
    )
    .ok()
}

/// what put-key sends opens exactly as the core (with the combined store key's scalar) and Deyao's kit (with the
/// master key) open it, and the signature covers the core's WriterText
#[test]
fn put_key_seals_to_the_store_and_the_master_key() {
    let (combined, master) = (Opener::generate(), Opener::generate());
    let k = Keys::generate();
    let req = key_write_request(
        &combined.public_key(),
        &master.public_key(),
        &k.sig,
        "yyc",
        "YYC_KEY",
        b"v4lue",
        false,
        "the cluster's key",
    )
    .unwrap();
    let w = &req["wrapped"];
    let dk = open_sealed(
        &combined,
        w["e"].as_str().unwrap(),
        w["wrapped"].as_str().unwrap(),
        "jarvis2/store-data-key",
    )
    .unwrap();
    let data = unb64(req["data"].as_str().unwrap()).unwrap();
    assert_eq!(
        gcm_open_aad(&dk, &data, b"yyc\nYYC_KEY").as_deref(),
        Some(&b"v4lue"[..])
    );
    assert!(
        gcm_open_aad(&dk, &data, b"yyc\nOTHER").is_none(),
        "the value opened under another key's name"
    );
    let bk = &req["backup"];
    // the backup opens with the master key: the same ECDH + HKDF as sealing, with the store and key as AAD
    let be = bk["e"].as_str().unwrap();
    let bd = bk["data"].as_str().unwrap();
    let e_pub = p256::PublicKey::from_sec1_bytes(&unb64(be).unwrap()).unwrap();
    let x = p256::ecdh::diffie_hellman(
        p256::SecretKey::from_slice(&master.scalar())
            .unwrap()
            .to_nonzero_scalar(),
        e_pub.as_affine(),
    );
    let mut key = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, x.raw_secret_bytes())
        .expand(b"jarvis2/backup", &mut key)
        .unwrap();
    assert_eq!(
        gcm_open_aad(&key, &unb64(bd).unwrap(), b"yyc\nYYC_KEY").as_deref(),
        Some(&b"v4lue"[..]),
        "the backup doesn't open"
    );
    assert_eq!(
        req["backupSha256"].as_str().unwrap(),
        sha256_hex(format!("{be}\n{bd}").as_bytes())
    );
    let wt = writer_text(
        "yyc",
        "YYC_KEY",
        w["e"].as_str().unwrap(),
        req["data"].as_str().unwrap(),
        req["backupSha256"].as_str().unwrap(),
    );
    assert!(
        jarvis_sig::verify(
            &k.sig.public_key(),
            wt.as_bytes(),
            req["sig"].as_str().unwrap()
        ),
        "the signature doesn't cover WriterText"
    );
    // a delete: no value, no backup, still signed
    let del = key_write_request(
        &combined.public_key(),
        &master.public_key(),
        &k.sig,
        "yyc",
        "YYC_KEY",
        b"",
        true,
        "",
    )
    .unwrap();
    assert!(del.get("wrapped").is_none() && del.get("backup").is_none());
    assert!(jarvis_sig::verify(
        &k.sig.public_key(),
        writer_text("yyc", "YYC_KEY", "", "", "").as_bytes(),
        del["sig"].as_str().unwrap()
    ));
}

/// a kernel machine's live copy opens in secrets exactly as kernel/secrets liveUpdate opens it
#[test]
fn the_live_copy_opens_in_secrets() {
    let k = Opener::generate();
    let (e, data) =
        seal_parts(&k.public_key(), b"v4lue", &live_info("yyc", "YYC_KEY"), b"").unwrap();
    assert_eq!(
        open_sealed(&k, &e, &data, "jarvis2/live-key\nyyc\nYYC_KEY").unwrap(),
        b"v4lue"
    );
}

/// a kernel machine's write: secrets signs no store key, so the machine computes P + K from the phone secrets' signed
/// state names and secrets' agreement key from the roster; a state another key signed is refused
#[test]
fn a_kernel_writer_computes_the_store_key() {
    let e = TestEnv::new();
    let key = e.machine_key();
    let sec = new_key();
    let (phone, agree) = (Opener::generate(), Opener::generate());
    let (pa, ka) = (phone.public_key(), agree.public_key());
    let state = sec.doc(&serde_json::json!({"kind": "secrets-state", "master": "M", "phone": {"signingKey": "S", "agreementKey": pa}}));
    let sp = sec.public();
    let srv = FakeRouter::new(&key.sig.public_key(), move |_| {
        ok_json(serde_json::json!({"identity": {"signingKey": sp, "state": state}}))
    });
    let c = srv.client();
    let (store_key, master) = seal_targets(&c, &sec.public(), &ka).unwrap();
    assert_eq!(
        (store_key, master.as_str()),
        (jarvis_sig::store_key(&pa, &ka).unwrap(), "M")
    );
    assert!(
        seal_targets(&c, &new_key().public(), &ka).is_err(),
        "a state another key signed was taken"
    );
    let _ = b64(b"");
}
