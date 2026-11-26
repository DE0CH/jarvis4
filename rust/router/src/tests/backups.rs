//! GET /api/backups reads every object of the backup bucket: over one kept connection, not one per object
//! (2026-11-26: the Rust router's first hour, Deyao's "Download encrypted backup" spun until it timed out: each GET made
//! a client of its own, and every new connection from the cluster through WARP can take seconds, lesson 99)
use crate::backups::BackupBucket;
use crate::testutil::TestServer;
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// a TCP forwarder in front of addr that counts the connections it accepts
fn counting_forwarder(to: String) -> (String, Arc<AtomicUsize>) {
    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let addr = format!(
        "http://{}",
        ln.local_addr().unwrap_or_else(|e| panic!("{e}"))
    );
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    std::thread::spawn(move || {
        for c in ln.incoming().flatten() {
            n2.fetch_add(1, Ordering::SeqCst);
            let Ok(up) = std::net::TcpStream::connect(&to) else {
                continue;
            };
            let (mut a, mut b) = (
                c.try_clone().unwrap_or_else(|e| panic!("{e}")),
                up.try_clone().unwrap_or_else(|e| panic!("{e}")),
            );
            let (mut c2, mut up2) = (c, up);
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut a, &mut up2);
            });
            std::thread::spawn(move || {
                let mut buf = [0u8; 16 << 10];
                while let Ok(k) = b.read(&mut buf) {
                    if k == 0 || c2.write_all(&buf[..k]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, n)
}

#[test]
fn every_backup_comes_over_one_connection() {
    const N: usize = 30;
    let srv = TestServer::handler(|w, req| {
        if req.query("list-type") == "2" {
            let prefix = req.query("prefix");
            let mut x = String::from("<ListBucketResult><IsTruncated>false</IsTruncated>");
            if prefix == "stores/" {
                for i in 0..N {
                    x.push_str(&format!("<Contents><Key>stores/s{i}.json</Key></Contents>"));
                }
            }
            x.push_str("</ListBucketResult>");
            w.write_str(&x);
            return;
        }
        w.write_str(&format!("{{\"path\":\"{}\"}}", req.path));
    });
    let (url, conns) = counting_forwarder(srv.url.trim_start_matches("http://").to_string());
    let b = BackupBucket {
        endpoint: url,
        region: "fsn1".into(),
        bucket: "jarvis2-backup-de0ch".into(),
        write: String::new(),
        access_key: "ak".into(),
        secret_key: "sk".into(),
    };
    let objs = b.all().unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(objs.len(), N);
    let n = conns.load(Ordering::SeqCst);
    assert!(
        n <= 2,
        "{n} connections for {} requests: every request made its own",
        N + 3
    );
}
