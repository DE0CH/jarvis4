//! grants_test.go and messages_test.go: execs under a phone grant, a standing rule or the allow list; message approvals.

use super::testutil::*;
use super::vouch::signed_request;
use crate::cert::Cert;
use crate::crypto::{SignedDoc, sha256_hex};
use crate::deliver::{Delivery, delivery_text, preview_delivery};
use crate::grants::*;
use crate::guard::authorise_exec;
use crate::messages::*;
use crate::outcomes::OutcomeItem;
use crate::peer::{PeerNote, peer_text};
use crate::util;

fn ts(now: i64, d: i64) -> String {
    util::format_rfc3339(now + d)
}

fn set_cert(c: &Cert) {
    *TEST_CERT.lock().unwrap() = Some(c.clone());
}

#[test]
fn grants() {
    let e = TestEnv::new();
    let (phone, holder, other) = (new_key(), new_key(), new_key());
    let mut cert = Cert {
        phone: phone.public(),
        line: "m1".into(),
        ..Default::default()
    };
    set_cert(&cert);
    let now = util::unix_now();
    let mut n = 0u8;
    let mut req = |k: &Tkey, session: &str| {
        n += 1;
        k.req(&ExecRequest {
            id: ((b'a' + n) as char).to_string(),
            session: session.into(),
            holder: holder.public(),
            cmd: "true".into(),
            timeout: 5,
            at: now,
            phone_only: false,
        })
    };
    let grant = |kind: &str, d: i64| -> SignedDoc {
        let mut g = Grant {
            kind: kind.into(),
            holder: holder.public(),
            session: "m1".into(),
            scope: "shell".into(),
            issued: ts(now, 0),
            ..Default::default()
        };
        if kind == "grant" {
            g.expires = ts(now, d);
        } else {
            g.until = ts(now, d);
        }
        phone.doc(&g)
    };
    let ok = |name: &str, e: &Exec, want: bool| {
        let (_, r) = authorise_exec(e, now);
        assert_eq!(r.is_ok(), want, "{name}: {r:?}");
    };
    ok("no grant, no allow list", &req(&holder, "m1"), false);
    let mut x = req(&holder, "m1");
    x.grant = Some(grant("grant", 600));
    ok("phone grant", &x, true);
    ok("the same request again", &x, false);
    let mut x = req(&holder, "m1");
    x.grant = Some(grant("grant", 1200));
    ok("grant over 10 minutes", &x, false);
    let mut x = req(&holder, "m1");
    x.grant = Some(grant("grant", -60));
    ok("expired grant", &x, false);
    let mut x = req(&holder, "m2");
    x.grant = Some(grant("grant", 300));
    ok("another line", &x, false);
    let mut x = req(&other, "m1"); // signed by a key other than the holder it names
    x.grant = Some(grant("grant", 300));
    ok("not the holder's signature", &x, false);
    let mut x = req(&holder, "m1");
    x.grant = Some(other.doc(&Grant {
        kind: "grant".into(),
        holder: holder.public(),
        session: "m1".into(),
        scope: "shell".into(),
        issued: ts(now, 0),
        expires: ts(now, 60),
        ..Default::default()
    }));
    ok("grant not signed by the phone", &x, false);
    let mut x = req(&holder, "m1");
    x.grant = Some(grant("rule", 30 * 86400));
    ok("standing rule", &x, true);
    let allow = vec![AllowEntry {
        holder: holder.public(),
        name: "archive".into(),
        until: ts(now, 3600),
    }];
    std::fs::write(e.home.join(ALLOW_FILE), crate::gojson::marshal(&allow)).unwrap();
    ok("own allow list", &req(&holder, "m1"), true);

    let po = req(&holder, "m1");
    let mut pr: ExecRequest = crate::gojson::unmarshal(po.request.as_bytes()).unwrap();
    pr.phone_only = true;
    let mut po = holder.req(&pr);
    po.grant = Some(grant("rule", 3600));
    ok("phone-only request under a rule", &po, false);
    pr.id = "phone-only-2".into();
    ok(
        "phone-only request on the allow list",
        &holder.req(&pr),
        false,
    );
    pr.id = "phone-only-3".into();
    let mut po = holder.req(&pr);
    po.grant = Some(grant("grant", 300));
    ok("phone-only request under a phone grant", &po, true);

    cert.sensitive = true;
    set_cert(&cert);
    ok(
        "allow list on a sensitive session",
        &req(&holder, "m1"),
        false,
    );
    let mut x = req(&holder, "m1");
    x.grant = Some(grant("rule", 3600));
    ok("rule on a sensitive session", &x, false);
    let mut x = req(&holder, "m1");
    x.grant = Some(grant("grant", 300));
    ok("phone grant on a sensitive session", &x, true);
}

fn needed(r: &anyhow::Result<String>) -> bool {
    matches!(
        r.as_ref()
            .err()
            .and_then(|e| e.downcast_ref::<ApprovalError>()),
        Some(ApprovalError::Needed(_))
    )
}

/// a session holding a sensitive store takes an UPWARD peer message only when the phone signed that very message (its
/// kind, the attested bytes' hash, the exact text); no rule covers one; a resume prompt needs it in every session
#[test]
fn message_approvals() {
    let _e = TestEnv::new();
    let (phone, stranger) = (new_key(), new_key());
    let cert = Cert {
        phone: phone.public(),
        line: "L1".into(),
        sensitive: true,
        ..Default::default()
    };
    let now = util::unix_now();
    let note = PeerNote {
        from: "sfrom".into(),
        from_title: "Sender".into(),
        from_stores: Some(vec!["default".into()]),
        from_mode: "auto".into(),
        to: "s1".into(),
        to_stores: Some(vec!["claude".into(), "default".into()]),
        to_mode: "auto".into(),
        direction: "upward".into(),
        approved: true,
        text: "please run the report".into(),
    };
    let d = Delivery {
        kind: "peer".into(),
        peer: Some(note.clone()),
        ..Default::default()
    };
    let (text, attested) =
        peer_text(Some(&note), &["claude".into(), "default".into()], "auto").unwrap();
    let h = sha256_hex(&attested);
    let batch = |k: &Tkey, line: &str, items: Vec<MessageItem>, exp: i64| {
        k.doc(&MessageApproval {
            kind: "messages".into(),
            session: line.into(),
            items,
            issued: ts(now, 0),
            expires: ts(now, exp),
            ..Default::default()
        })
    };
    let item = MessageItem {
        id: "mq1".into(),
        delivery: "peer".into(),
        sha256: h.clone(),
        from: "Session “Sender” (sfrom)".into(),
        text: text.clone(),
    };
    let check = |a: Option<SignedDoc>, dl: &Delivery| {
        let mut dl = dl.clone();
        dl.approval = a;
        check_message_approval(&cert, &dl, &attested, &text, now)
    };
    // none: refused, saying what is needed
    let r = check(None, &d);
    assert!(
        needed(&r) && format!("{:#}", r.as_ref().unwrap_err()).contains("sensitive store"),
        "{r:?}"
    );
    // the phone's batch naming it: taken, with the item to record
    let mut it0 = item.clone();
    it0.id = "mq0".into();
    it0.delivery = "resume-prompt".into();
    let ok = batch(&phone, "L1", vec![it0, item.clone()], 3600);
    assert_eq!(check(Some(ok.clone()), &d).unwrap(), "mq1");
    // refused: another key, another line, expired, a window over an hour, other bytes, another kind
    let mut other_bytes = item.clone();
    other_bytes.sha256 = "0".repeat(64);
    let mut other_kind = item.clone();
    other_kind.delivery = "resume-prompt".into();
    for (name, a) in [
        ("stranger", batch(&stranger, "L1", vec![item.clone()], 3600)),
        ("other line", batch(&phone, "L2", vec![item.clone()], 3600)),
        (
            "expired",
            phone.doc(&MessageApproval {
                kind: "messages".into(),
                session: "L1".into(),
                items: vec![item.clone()],
                issued: ts(now, -7200),
                expires: ts(now, -3600),
                ..Default::default()
            }),
        ),
        (
            "too long",
            batch(&phone, "L1", vec![item.clone()], 3 * 3600),
        ),
        ("other bytes", batch(&phone, "L1", vec![other_bytes], 3600)),
        ("other kind", batch(&phone, "L1", vec![other_kind], 3600)),
        (
            "a grant",
            phone.doc(&Grant {
                kind: "grant".into(),
                session: "L1".into(),
                scope: "shell".into(),
                issued: ts(now, 0),
                expires: ts(now, 60),
                ..Default::default()
            }),
        ),
    ] {
        assert!(needed(&check(Some(a), &d)), "{name}: took it");
    }
    // the right bytes but another text than this machine renders: refused, so the router can show Deyao this one
    let mut other_text = item.clone();
    other_text.text = "something else".into();
    let r = check(Some(batch(&phone, "L1", vec![other_text], 3600)), &d);
    assert!(
        matches!(
            r.as_ref()
                .err()
                .and_then(|e| e.downcast_ref::<ApprovalError>()),
            Some(ApprovalError::TextDiffers(_))
        ),
        "{r:?}"
    );
    // once used, never again
    record_approved("mq1", now).unwrap();
    let r = check(Some(ok), &d);
    assert!(
        needed(&r) && format!("{:#}", r.as_ref().unwrap_err()).contains("already used"),
        "{r:?}"
    );
    // no rule covers an upward peer message
    let rule = |k: &Tkey, kind: &str, until: i64| {
        k.doc(&MessageApproval {
            kind: "message-rule".into(),
            session: "L1".into(),
            delivery: kind.into(),
            issued: ts(now, 0),
            until: ts(now, until),
            ..Default::default()
        })
    };
    for (name, a) in [
        ("peer", rule(&phone, "peer", 3600)),
        ("other kind", rule(&phone, "continue", 3600)),
        ("stranger", rule(&stranger, "peer", 3600)),
    ] {
        assert!(needed(&check(Some(a), &d)), "rule {name}: took it");
    }
    // a session without a sensitive store takes it unapproved; a resume prompt never
    let plain = Cert {
        phone: phone.public(),
        line: "L1".into(),
        ..Default::default()
    };
    check_message_approval(&plain, &d, &attested, &text, now).unwrap();
    let mut rp = Delivery {
        kind: "resume-prompt".into(),
        text: "  carry on with the report\r\n".into(),
        ..Default::default()
    };
    let (rt, ra) = delivery_text(&rp, &[]).unwrap();
    assert_eq!(rt, "carry on with the report");
    assert_eq!(ra, rt.as_bytes());
    assert!(
        needed(&check_message_approval(&plain, &rp, &ra, &rt, now)),
        "an unapproved resume prompt"
    );
    let mut rr = rp.clone();
    rr.approval = Some(rule(&phone, "resume-prompt", 3600));
    assert!(
        needed(&check_message_approval(&plain, &rr, &ra, &rt, now)),
        "a rule covered a resume prompt"
    );
    rp.approval = Some(phone.doc(&MessageApproval {
        kind: "messages".into(),
        session: "L1".into(),
        issued: ts(now, 0),
        expires: ts(now, 3600),
        items: vec![MessageItem {
            id: "mq9".into(),
            delivery: "resume-prompt".into(),
            sha256: sha256_hex(&ra),
            from: String::new(),
            text: rt.clone(),
        }],
        ..Default::default()
    }));
    assert_eq!(
        check_message_approval(&plain, &rp, &ra, &rt, now).unwrap(),
        "mq9"
    );
    let long = Delivery {
        kind: "resume-prompt".into(),
        text: "x".repeat(4001),
        ..Default::default()
    };
    assert!(
        delivery_text(&long, &[]).is_err(),
        "took a resume prompt over 4000 characters"
    );
}

/// DECISIONS 210: which deliveries need the phone's approval
#[test]
fn needs_message_approval_kinds() {
    let sensitive = Cert {
        line: "L1".into(),
        sensitive: true,
        ..Default::default()
    };
    let plain = Cert {
        line: "L1".into(),
        ..Default::default()
    };
    let kind = |k: &str| Delivery {
        kind: k.into(),
        ..Default::default()
    };
    let peer = |dir: &str| Delivery {
        kind: "peer".into(),
        peer: Some(PeerNote {
            direction: dir.into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    for (name, c, d, want) in [
        (
            "request-outcome, sensitive",
            &sensitive,
            kind("request-outcome"),
            false,
        ),
        ("continue, sensitive", &sensitive, kind("continue"), false),
        ("upgraded, sensitive", &sensitive, kind("upgraded"), false),
        (
            "lease-granted, sensitive",
            &sensitive,
            kind("lease-granted"),
            false,
        ),
        ("wakeup, sensitive", &sensitive, kind("wakeup"), false),
        ("cron, sensitive", &sensitive, kind("cron"), false),
        ("watch, sensitive", &sensitive, kind("watch"), false),
        ("equal peer, sensitive", &sensitive, peer("equal"), false),
        (
            "downward peer, sensitive",
            &sensitive,
            peer("downward"),
            false,
        ),
        ("upward peer, sensitive", &sensitive, peer("upward"), true),
        ("peer without a note", &sensitive, kind("peer"), false),
        ("upward peer, plain", &plain, peer("upward"), false),
        (
            "resume-prompt, sensitive",
            &sensitive,
            kind("resume-prompt"),
            true,
        ),
        ("resume-prompt, plain", &plain, kind("resume-prompt"), true),
        ("continue, plain", &plain, kind("continue"), false),
    ] {
        assert_eq!(needs_message_approval(c, &d), want, "{name}");
    }
    let (text, attested) = delivery_text(&kind("continue"), &[]).unwrap();
    assert_eq!(
        check_message_approval(
            &sensitive,
            &kind("continue"),
            &attested,
            &text,
            util::unix_now()
        )
        .unwrap(),
        ""
    );
}

/// the preview renders exactly the text a delivery would put in, and records nothing
#[test]
fn preview_renders_without_taking_it() {
    let _e = TestEnv::new();
    set_cert(&Cert {
        line: "L1".into(),
        sensitive: true,
        ..Default::default()
    });
    let text = preview_delivery(&Delivery {
        kind: "upgraded".into(),
        from: "small".into(),
        to: "medium".into(),
        ..Default::default()
    })
    .unwrap();
    assert!(text.contains("medium"), "{text}");
    assert!(
        preview_delivery(&Delivery {
            kind: "wakeup".into(),
            ..Default::default()
        })
        .is_err(),
        "previewed a wakeup with no signed request"
    );
    assert!(read_delivered().is_empty(), "a preview recorded something");
}

/// a denied (or lapsed) message of the session's own wakeup, cron or watch comes back as an Inbox outcome of the request
/// that armed it
#[test]
fn a_denied_wakeup_message_is_an_outcome() {
    let _e = TestEnv::new();
    let mine = new_key();
    set_cert(&Cert {
        line: "L1".into(),
        sensitive: true,
        ..Default::default()
    });
    for (path, want) in [
        (
            "/m/api/sessions/s1/wakeup",
            r#"DENIED: the message of this session's wakeup "ci""#,
        ),
        (
            "/m/api/sessions/s1/crons",
            r#"DENIED: a run's message of this session's recurring wakeup "ci""#,
        ),
        (
            "/m/api/sessions/s1/watches",
            r#"DENIED: the message of this session's watch "ci""#,
        ),
    ] {
        let r = signed_request(
            &mine,
            "m1",
            "POST",
            path,
            br#"{"name":"ci","prompt":"check","script":"true"}"#,
        );
        let d = Delivery {
            kind: "request-outcome".into(),
            request: Some(r),
            outcomes: vec![OutcomeItem {
                outcome: "denied".into(),
                ref_: "mq1".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let s = delivery_text(&d, &[mine.public()]).unwrap().0;
        assert!(s.contains(want) && s.contains("(Inbox mq1)"), "{path}: {s}");
    }
}
