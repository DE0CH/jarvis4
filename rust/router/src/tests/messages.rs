//! messages_test.go (the kernel-line cases wait for the kernel tests)
use crate::core::Doc;
use crate::messages::{
    MESSAGE_TTL, MessageApproval, MessageRule, PendingMessage, REQUEST_KIND_MSG, message_text,
    rule_text,
};
use crate::outcomes::{OUTCOME_APPROVED, OUTCOME_DENIED, OUTCOME_LAPSED, Outcome, OutcomeItem};
use crate::peermsg::{PeerNote, REQUEST_KIND_PEER};
use crate::router::Router;
use crate::testutil::*;
use crate::vouch::{Delivery, DeliveryResult, SignedRequest, attested};
use base64::Engine;
use jarvis_go::GoTime;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type AnswerFn = Arc<dyn Fn(&Delivery) -> DeliveryResult + Send + Sync>;

/// a router with a core that attests, one STARTED session s1 on machine `machine` whose cert names the phone key and
/// (sensitive) a sensitive store, and a fake machine that answers each delivery with answer(d)
struct MsgRig {
    rg: Rig,
    _vc: V2Core,
    r: Arc<Router>,
    phone: TestKey,
    got: Arc<Mutex<Vec<Delivery>>>,
    dms: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    th: Option<std::thread::JoinHandle<()>>,
}

impl Drop for MsgRig {
    fn drop(&mut self) {
        wait_for("messages delivered", || Router::messages_in_flight() == 0);
        self.stop.store(true, Ordering::SeqCst);
        if let Some(th) = self.th.take() {
            let _ = th.join();
        }
        let _ = &self.rg;
    }
}

fn new_msg_rig(machine: &str, sensitive: bool, answer: AnswerFn) -> MsgRig {
    let (rg, vc) = Rig::v2();
    let r = rg.t.r.clone();
    let dms = capture_dm(&r);
    let phone = TestKey::new();
    let cert = jarvis_go::marshal(
        &serde_json::json!({"kind": "succession-cert", "line": "L1", "sensitive": sensitive, "phone": phone.public()}),
    );
    r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.state = "started".into();
            s.machine_id = machine.into();
            s.cert = Some(Doc {
                payload: cert.clone(),
                sig: String::new(),
            });
        }
        d.machines.insert(machine.into(), "s1".into());
    });
    let got: Arc<Mutex<Vec<Delivery>>> = Arc::default();
    let stop = Arc::new(AtomicBool::new(false));
    let (r2, g2, s2, m2) = (r.clone(), got.clone(), stop.clone(), machine.to_string());
    let th = std::thread::spawn(move || {
        while !s2.load(Ordering::SeqCst) {
            let Some(b) = mq_wait_kind(&r2, &m2, "delivery", Duration::from_millis(50)) else {
                continue;
            };
            let d: Delivery = serde_json::from_str(&b).unwrap_or_default();
            g2.lock().unwrap_or_else(|e| e.into_inner()).push(d.clone());
            let mut res = answer(&d);
            res.id = d.id.clone();
            let _ = r2.mq_answer(&d.id, &serde_json::to_value(&res).unwrap_or_default());
        }
    });
    MsgRig {
        rg,
        _vc: vc,
        r,
        phone,
        got,
        dms,
        stop,
        th: Some(th),
    }
}

impl MsgRig {
    fn deliveries(&self) -> Vec<Delivery> {
        self.got.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn dms(&self) -> Vec<String> {
        self.dms.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn pending(&self) -> Vec<PendingMessage> {
        self.r.st.read(|d| d.messages.values().cloned().collect())
    }
    /// what the phone does with a draft
    fn sign(&self, text: &str) -> Doc {
        Doc {
            payload: text.into(),
            sig: self.phone.0.sign(text.as_bytes()),
        }
    }
    /// session from (added, started, holding stores) sends s1 a peer message; s1 holds claude+default, so a sender
    /// holding fewer stores sends UPWARD
    fn send_peer(&self, from: &str, stores: Option<Vec<&str>>, text: &str) -> Value {
        self.r.st.do_(|d| {
            if !d.sessions.contains_key(from) {
                d.sessions.insert(
                    from.into(),
                    crate::state::Session {
                        id: from.into(),
                        state: "started".into(),
                        machine_id: format!("m{from}"),
                        label: format!("label {from}"),
                        harness: "claude".into(),
                        stores: stores
                            .clone()
                            .map(|v| v.iter().map(|x| x.to_string()).collect()),
                        ..Default::default()
                    },
                );
                d.machines.insert(format!("m{from}"), from.into());
            }
        });
        self.r
            .send_peer(
                from,
                "s1",
                text,
                SignedRequest {
                    machine: format!("m{from}"),
                    method: "POST".into(),
                    path: "/m/api/requests/peer".into(),
                    sig: format!("p{}", crate::util::rand_id()),
                    ..Default::default()
                },
                "POST",
                "/m/api/requests/peer",
            )
            .unwrap_or_else(|e| panic!("{e:#}"))
    }
    /// until n messages are held (send_peer hands them over in the background)
    fn wait_pending(&self, n: usize) -> Vec<PendingMessage> {
        wait_for("held", || self.pending().len() >= n);
        self.pending()
    }
    fn wait_deliveries(&self, n: usize) -> Vec<Delivery> {
        wait_for("deliveries", || self.deliveries().len() >= n);
        self.deliveries()
    }
    fn settle(&self) {
        wait_for("messages delivered", || Router::messages_in_flight() == 0);
    }
    fn outcomes(&self, sid: &str) -> Vec<Outcome> {
        self.r
            .st
            .read(|d| d.outcomes.get(sid).cloned().unwrap_or_default())
    }
}

/// the machine renders the canned text the router would (its preview), and takes approved deliveries
fn preview_ok() -> AnswerFn {
    Arc::new(|d| {
        if d.preview {
            let (inp, _) = attested(d).unwrap_or_default();
            return DeliveryResult {
                ok: true,
                text: String::from_utf8_lossy(&inp).into_owned(),
                ..Default::default()
            };
        }
        DeliveryResult {
            ok: true,
            ..Default::default()
        }
    })
}

#[test]
fn a_message_into_a_sensitive_session_waits_for_deyao() {
    let m = new_msg_rig("mmsg1", true, preview_ok());
    // an upward peer message: held (the sender sees it handed over), with the machine's own text
    let out = m.send_peer("sfrom", None, "please run the report");
    assert_eq!(out["waiting"], "message", "{out}");
    let ps = m.wait_pending(1);
    let want = ps[0].text.clone();
    assert!(
        ps.len() == 1
            && ps[0].kind == "peer"
            && want.contains("please run the report")
            && ps[0].state == "pending"
            && ps[0].from.contains("sfrom"),
        "held {ps:?}"
    );
    let ds = m.deliveries();
    assert!(
        ds.len() == 1 && ds[0].preview && ds[0].attest.is_none(),
        "only a preview reached the machine: {ds:?}"
    );
    wait_for("the hand-over DM", || !m.dms().is_empty());
    assert!(
        m.dms().len() == 1 && m.dms()[0].contains("Peer message"),
        "dm {:?}",
        m.dms()
    );
    // it is in the Inbox, under its session, with the exact text and who asks
    let it = m.r.inbox().into_iter().find(|x| x.kind == REQUEST_KIND_MSG);
    assert!(
        it.as_ref().is_some_and(|it| it.session == "s1"
            && it.params.text == want
            && it.caller_text == ps[0].from
            && it.explanation.starts_with("Message from session “")),
        "inbox {it:?}"
    );
    // a second message waiting doesn't DM again (one DM per session while any waits)
    m.send_peer("sfrom", None, "and the other one");
    let ps2 = m.wait_pending(2);
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        ps2.len() == 2 && m.dms().len() == 1,
        "{ps2:?} (dms {})",
        m.dms().len()
    );
    let other = m
        .pending()
        .into_iter()
        .find(|pm| pm.id != ps[0].id)
        .map(|pm| pm.id)
        .unwrap_or_default();
    m.r.deny_messages(&[other]);

    // Deliver: the phone signs the draft; the machine gets exactly that message with the signature, attested
    let id = ps[0].id.clone();
    let (text, sid, line) =
        m.r.draft_messages(std::slice::from_ref(&id))
            .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(sid == "s1" && line == "L1");
    let a: MessageApproval = serde_json::from_str(&text).unwrap_or_default();
    use sha2::Digest;
    let sum = hex::encode(sha2::Sha256::digest(want.as_bytes()));
    assert!(
        a.kind == "messages"
            && a.session == "L1"
            && a.items.len() == 1
            && a.items[0].sha256 == sum
            && a.items[0].text == want,
        "draft {text}"
    );
    let stranger = TestKey::new();
    let bad = Doc {
        payload: text.clone(),
        sig: stranger.0.sign(text.as_bytes()),
    };
    assert!(
        m.r.approve_messages(&bad).is_err(),
        "took another key's signature"
    );
    let doc = m.sign(&text);
    let ids =
        m.r.approve_messages(&doc)
            .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(ids.len(), 1);
    m.settle();
    let ds = m.deliveries();
    let last = ds.last().cloned().unwrap_or_default();
    assert!(
        !last.preview
            && last.kind == "peer"
            && last.approval.as_ref().is_some_and(|a| a.payload == text)
            && last.attest.is_some(),
        "delivered {last:?}"
    );
    assert!(m.pending().is_empty(), "a delivered message stays");
    assert!(
        m.r.approve_messages(&doc).is_err(),
        "the same approval twice"
    );
}

/// a resume prompt is rendered by the router itself, so a paused session isn't started just to hold it
#[test]
fn a_paused_sensitive_session_isnt_started_to_hold_a_message() {
    let m = new_msg_rig("mmsg2", true, preview_ok());
    m.r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.state = "paused".into();
            s.machine_id = String::new();
        }
    });
    let rp = |t: &str| Delivery {
        kind: "resume-prompt".into(),
        text: t.into(),
        ..Default::default()
    };
    m.r.deliver_vouched("s1", rp("check   the CI"))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(m.r.session_state("s1").0, "paused", "started it");
    let ps = m.pending();
    assert!(
        ps.len() == 1
            && ps[0].kind == "resume-prompt"
            && ps[0].text.contains("check")
            && ps[0].from.contains("Deyao"),
        "{ps:?}"
    );
    // a second one replaces it, still without starting anything
    let _ = m.r.deliver_vouched("s1", rp("no, carry on"));
    let ps2 = m.pending();
    assert!(
        ps2.len() == 1 && ps2[0].id != ps[0].id && ps2[0].text == "no, carry on",
        "not replaced: {ps2:?}"
    );
    // Deny: nothing goes in
    let got = m.r.deny_messages(&[ps2[0].id.clone()]);
    assert_eq!(got.len(), 1, "not denied");
    assert!(
        m.pending().is_empty() && m.r.session_state("s1").0 == "paused",
        "pending {:?}",
        m.pending()
    );
    assert!(m.deliveries().is_empty(), "something reached the machine");
}

#[test]
fn a_delivery_into_a_plain_session_isnt_held_but_a_resume_prompt_is() {
    let m = new_msg_rig("mmsg3", false, preview_ok());
    m.r.deliver_canned(
        "s1",
        Delivery {
            kind: "continue".into(),
            ..Default::default()
        },
        "",
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    let ds = m.deliveries();
    assert!(
        ds.len() == 1 && !ds[0].preview && ds[0].approval.is_none() && m.pending().is_empty(),
        "{ds:?}"
    );
    m.r.deliver_vouched(
        "s1",
        Delivery {
            kind: "resume-prompt".into(),
            text: "carry on".into(),
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    let ps = m.pending();
    assert!(
        ps.len() == 1
            && ps[0].kind == "resume-prompt"
            && ps[0].text == "carry on"
            && rule_text("resume-prompt").is_empty(),
        "{ps:?}"
    );
}

/// No rule lets an upward peer message or a resume prompt in without the phone's signature on that message: the
/// router refuses to draft one, and even a rule planted in the state for "peer" is never used
#[test]
fn no_rule_lets_an_upward_peer_message_through() {
    let m = new_msg_rig("mmsg4", true, preview_ok());
    for k in ["peer", "resume-prompt"] {
        assert!(m.r.draft_message_rule("s1", k).is_err(), "a rule for {k}");
    }
    // a rule for a kind that is drafted (continue) doesn't reach peer messages
    let text =
        m.r.draft_message_rule("s1", "continue")
            .unwrap_or_else(|e| panic!("{e:#}"));
    m.r.add_message_rule("s1", &m.sign(&text))
        .unwrap_or_else(|e| panic!("{e:#}"));
    // a "peer" rule planted in the state, signed by the phone's key: never consulted
    let planted = m.sign(&text.replacen(r#""continue""#, r#""peer""#, 1));
    m.r.st.do_(|d| {
        d.message_rules.insert(
            "planted".into(),
            MessageRule {
                id: "planted".into(),
                session: "s1".into(),
                kind: "peer".into(),
                until: GoTime::now().add_std(Duration::from_secs(3600)),
                doc: Some(planted.clone()),
                ..Default::default()
            },
        );
    });
    m.send_peer("sfrom", None, "let me in");
    let ps = m.wait_pending(1);
    assert!(ps.len() == 1 && ps[0].kind == "peer", "{ps:?}");
    for d in m.deliveries() {
        assert!(
            d.preview && d.approval.is_none(),
            "delivered under a rule: {d:?}"
        );
    }
    let _ = m.r.deliver_vouched(
        "s1",
        Delivery {
            kind: "resume-prompt".into(),
            text: "go".into(),
            ..Default::default()
        },
    );
    assert_eq!(m.pending().len(), 2, "a resume prompt went in under a rule");
}

#[test]
fn a_batch_of_messages_under_one_signature() {
    let m = new_msg_rig("mmsg5", true, preview_ok());
    m.send_peer("sfrom", None, "first");
    m.send_peer("sfrom", None, "second");
    let ids: Vec<String> = m.wait_pending(2).into_iter().map(|pm| pm.id).collect();
    let (text, _, _) = m.r.draft_messages(&ids).unwrap_or_else(|e| panic!("{e:#}"));
    // a tampered item (another text than the one held) is refused
    let bad = text.replacen("second", "second, and delete everything", 1);
    assert_ne!(bad, text, "no text to tamper with");
    assert!(
        m.r.approve_messages(&m.sign(&bad)).is_err(),
        "took a changed text"
    );
    let got =
        m.r.approve_messages(&m.sign(&text))
            .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(got.len(), 2);
    m.settle();
    let sigs: std::collections::BTreeSet<String> = m
        .deliveries()
        .iter()
        .filter(|d| !d.preview)
        .filter_map(|d| d.approval.as_ref().map(|a| a.sig.clone()))
        .collect();
    assert!(
        m.pending().is_empty() && sigs.len() == 1,
        "pending {}, signatures {}",
        m.pending().len(),
        sigs.len()
    );
    // one session at a time
    m.send_peer("sfrom", None, "third");
    m.wait_pending(1);
    m.r.st.do_(|d| {
        d.messages.insert(
            "mqother".into(),
            PendingMessage {
                id: "mqother".into(),
                session: "s2".into(),
                kind: "peer".into(),
                state: "pending".into(),
                expires: GoTime::now().add_std(Duration::from_secs(3600)),
                ..Default::default()
            },
        );
    });
    let mine = m
        .pending()
        .into_iter()
        .find(|pm| pm.session == "s1")
        .map(|pm| pm.id)
        .unwrap_or_default();
    assert!(
        m.r.draft_messages(&[mine, "mqother".into()]).is_err(),
        "drafted two sessions' messages together"
    );
}

#[test]
fn messages_lapse_and_approvals_run_out() {
    let m = new_msg_rig(
        "mmsg6",
        true,
        Arc::new(|d| {
            if d.preview {
                let (inp, _) = attested(d).unwrap_or_default();
                return DeliveryResult {
                    ok: true,
                    text: String::from_utf8_lossy(&inp).into_owned(),
                    ..Default::default()
                };
            }
            DeliveryResult {
                error: "target gone".into(), // the approved delivery fails
                ..Default::default()
            }
        }),
    );
    m.send_peer("sfrom", None, "x");
    let ps = m.wait_pending(1);
    assert!(
        ps.len() == 1
            && ps[0].kind == "peer"
            && ps[0]
                .origin
                .as_ref()
                .is_some_and(|o| o.caller.session == "sfrom"),
        "{ps:?}"
    );
    // a day on, nobody answered: it lapses and the sender hears so
    let later = GoTime::now().add(MESSAGE_TTL + time::Duration::minutes(1));
    m.r.message_tick_once(later);
    let oc = m.outcomes("sfrom");
    assert!(
        m.pending().is_empty() && oc.len() == 1 && oc[0].outcome == OUTCOME_LAPSED,
        "{oc:?}"
    );
    // approved but the machine fails it: failed, and it says why
    m.send_peer("sfrom", None, "y");
    let id = m.wait_pending(1)[0].id.clone();
    let (text, _, _) =
        m.r.draft_messages(&[id])
            .unwrap_or_else(|e| panic!("{e:#}"));
    let _ = m.r.approve_messages(&m.sign(&text));
    m.settle();
    let ps = m.pending();
    assert!(
        ps.len() == 1 && ps[0].state == "failed" && ps[0].error.contains("target gone"),
        "{ps:?}"
    );
}

/// DECISIONS 210: Jarvis's own messages (an Inbox outcome, the watchdog, "continue", an upgrade note) and the
/// session's own wakeups go straight into a running session holding a sensitive store: never held, no preview, no
/// signature
#[test]
fn jarvis_own_messages_go_straight_into_a_sensitive_session() {
    let m = new_msg_rig("mmsg10", true, preview_ok());
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    let wake = SignedRequest {
        machine: "mmsg10".into(),
        method: "POST".into(),
        path: "/m/api/sessions/s1/wakeup".into(),
        at: "1".into(),
        body: b64(r#"{"name":"ci","prompt":"check the CI","delaySeconds":60}"#),
        sig: "sw".into(),
    };
    let filed = SignedRequest {
        machine: "mmsg10".into(),
        method: "POST".into(),
        path: "/m/api/requests/add-store".into(),
        at: "1".into(),
        body: b64("{}"),
        sig: "sr".into(),
    };
    let all = [
        Delivery {
            kind: "request-outcome".into(),
            request: Some(filed),
            outcomes: vec![OutcomeItem {
                outcome: OUTCOME_APPROVED.into(),
                r#ref: "q1".into(),
                ..Default::default()
            }],
            ..Default::default()
        },
        Delivery {
            kind: "wakeup".into(),
            request: Some(wake),
            ..Default::default()
        },
        Delivery {
            kind: "continue".into(),
            ..Default::default()
        },
        Delivery {
            kind: "upgraded".into(),
            from: "medium".into(),
            to: "large".into(),
            ..Default::default()
        },
    ];
    for (i, d) in all.into_iter().enumerate() {
        assert!(!m.r.needs_approval("s1", &d), "{} needs approval", d.kind);
        let kind = d.kind.clone();
        m.r.deliver_vouched("s1", d)
            .unwrap_or_else(|e| panic!("{kind}: {e:#}"));
        let ds = m.deliveries();
        assert!(
            ds.len() == i + 1
                && ds[i].kind == kind
                && !ds[i].preview
                && ds[i].approval.is_none()
                && ds[i].attest.is_some(),
            "{kind} not delivered straight in: {ds:?}"
        );
    }
    assert!(
        m.pending().is_empty() && m.dms().is_empty(),
        "held {:?}, dms {:?}",
        m.pending(),
        m.dms()
    );
}

/// DECISIONS 210, 272: into a session holding a sensitive store, an equal or downward peer message waits as a one-tap
/// Inbox request (no signature), as into any session; only an upward one (from a session holding less) is held for
/// Deyao to deliver signed
#[test]
fn only_an_upward_peer_message_into_a_sensitive_session_is_held() {
    let m = new_msg_rig("mmsg11", true, preview_ok());
    let eq = m.send_peer("sequal", Some(vec!["claude", "default"]), "same stores");
    assert!(
        eq["direction"] == "equal" && eq["waiting"] == "inbox",
        "{eq}"
    );
    let down = m.send_peer(
        "sdown",
        Some(vec!["claude", "default", "infra"]),
        "more stores",
    );
    assert!(
        down["direction"] == "downward" && down["waiting"] == "inbox",
        "{down}"
    );
    assert!(
        m.deliveries().is_empty(),
        "delivered before Deyao approved: {:?}",
        m.deliveries()
    );
    for out in [&eq, &down] {
        m.r.approve_peer(out["id"].as_str().unwrap_or_default())
            .unwrap_or_else(|e| panic!("{e:#}"));
    }
    for d in m.wait_deliveries(2) {
        assert!(
            d.kind == "peer"
                && !d.preview
                && d.approval.is_none()
                && d.attest.is_some()
                && d.peer.as_ref().is_some_and(|p| p.approved),
            "not straight in once approved: {d:?}"
        );
    }
    assert!(m.pending().is_empty(), "held {:?}", m.pending());
    let out = m.send_peer("sup", Some(vec!["claude"]), "fewer stores");
    assert!(
        out["direction"] == "upward" && out["waiting"] == "message",
        "{out}"
    );
    let ps = m.wait_pending(1);
    assert!(
        ps.len() == 1
            && ps[0].kind == "peer"
            && ps[0]
                .delivery
                .peer
                .as_ref()
                .is_some_and(|p| p.from == "sup"),
        "{ps:?}"
    );
    // the same rule on the router's side, peer by peer
    let peer = |dir: &str| Delivery {
        kind: "peer".into(),
        peer: Some(PeerNote {
            direction: dir.into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    for (dir, want) in [("equal", false), ("downward", false), ("upward", true)] {
        assert_eq!(m.r.needs_approval("s1", &peer(dir)), want, "{dir}");
    }
    // into a plain session not even an upward one waits for a signature (it is a one-tap request instead)
    m.r.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.cert = Some(Doc {
                payload: r#"{"kind":"succession-cert","line":"L1","sensitive":false}"#.into(),
                sig: String::new(),
            });
        }
    });
    assert!(
        !m.r.needs_approval("s1", &peer("upward")),
        "an upward peer into a plain session needs the phone's signature"
    );
}

/// the machine renders another text than the phone signed: it refuses with its own, and that one is held for Deyao
#[test]
fn a_text_the_machine_renders_differently_is_held_again() {
    let m = new_msg_rig(
        "mmsg7",
        true,
        Arc::new(|d| {
            if d.preview {
                return DeliveryResult {
                    ok: true,
                    text: "continue".into(),
                    ..Default::default()
                };
            }
            DeliveryResult {
                error: "message approval: the signed text isn't the text this machine renders"
                    .into(),
                needs_approval: true,
                text: "the machine's text".into(),
                ..Default::default()
            }
        }),
    );
    let _ = m.r.deliver_canned(
        "s1",
        Delivery {
            kind: "continue".into(),
            ..Default::default()
        },
        "",
    );
    // the machine refuses it for want of an approval: held for Deyao
    let ps = m.pending();
    assert_eq!(ps.len(), 1, "not held: {ps:?}");
    let id = ps[0].id.clone();
    let (text, _, _) =
        m.r.draft_messages(std::slice::from_ref(&id))
            .unwrap_or_else(|e| panic!("{e:#}"));
    m.r.approve_messages(&m.sign(&text))
        .unwrap_or_else(|e| panic!("{e:#}"));
    m.settle();
    let ps = m.pending();
    assert!(
        ps.len() == 1
            && ps[0].id != id
            && ps[0].state == "pending"
            && ps[0].text == "the machine's text",
        "{ps:?}"
    );
}

/// a peer message into a session holding a sensitive store isn't a one-tap upward request: Deyao signs the message
#[test]
fn a_peer_message_into_a_sensitive_session_is_held() {
    let m = new_msg_rig(
        "mmsg8",
        true,
        Arc::new(|d| {
            if d.preview {
                return DeliveryResult {
                    ok: true,
                    text: format!(
                        "[Message from another Jarvis 4 session] {}",
                        d.peer.as_ref().map(|p| p.text.clone()).unwrap_or_default()
                    ),
                    ..Default::default()
                };
            }
            DeliveryResult {
                ok: true,
                ..Default::default()
            }
        }),
    );
    add_session(&m.r, "sfrom", "started", "mfrom", false);
    let out =
        m.r.send_peer(
            "sfrom",
            "s1",
            "please run the report",
            SignedRequest {
                machine: "mfrom".into(),
                method: "POST".into(),
                path: "/m/api/requests/peer".into(),
                sig: "p".into(),
                ..Default::default()
            },
            "POST",
            "/m/api/requests/peer",
        )
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(out["waiting"], "message", "{out}");
    let ps = m.wait_pending(1);
    assert!(
        ps.len() == 1
            && ps[0].kind == "peer"
            && ps[0].delivery.peer.as_ref().is_some_and(|p| p.approved)
            && ps[0]
                .origin
                .as_ref()
                .is_some_and(|o| o.caller.session == "sfrom"),
        "{ps:?}"
    );
    assert!(
        !m.r.inbox().iter().any(|q| q.kind == REQUEST_KIND_PEER),
        "also filed as an upward peer request"
    );
    m.r.deny_messages(&[ps[0].id.clone()]);
    let oc = m.outcomes("sfrom");
    assert!(
        oc.len() == 1 && oc[0].outcome == OUTCOME_DENIED && oc[0].kind == REQUEST_KIND_PEER,
        "the sender wasn't told: {oc:?}"
    );
}

/// the router's twins render what rust/machine/src/deliver.rs delivery_text renders (its tests pin the same strings)
#[test]
fn message_text_twins() {
    let req = |path: &str, body: &str| SignedRequest {
        method: "POST".into(),
        path: path.into(),
        body: base64::engine::general_purpose::STANDARD.encode(body),
        ..Default::default()
    };
    for (d, want) in [
        (
            Delivery {
                kind: "cron".into(),
                run: 3,
                request: Some(req(
                    "/m/api/sessions/s1/crons",
                    r#"{"name":"daily","prompt":"report","everySeconds":86400}"#,
                )),
                ..Default::default()
            },
            r#"[recurring wakeup "daily" — run 3] report"#.to_string(),
        ),
        (
            Delivery {
                kind: "wakeup".into(),
                request: Some(req("/m/api/sessions/s1/wakeup", r#"{"prompt":"go  on"}"#)),
                ..Default::default()
            },
            "go on".into(),
        ),
        (
            Delivery {
                kind: "watch-fail".into(),
                request: Some(req(
                    "/m/api/sessions/s1/watches",
                    r#"{"name":"ci","prompt":"x","failPrompt":"look"}"#,
                )),
                ..Default::default()
            },
            r#"[watch "ci" gave up] look"#.into(),
        ),
        (
            Delivery {
                kind: "upgraded".into(),
                from: "medium".into(),
                to: "large".into(),
                ..Default::default()
            },
            crate::memory::upgraded_text("medium", "large"),
        ),
    ] {
        let got = message_text(&d).map(|(t, _, _)| t);
        assert_eq!(got.as_deref(), Some(want.as_str()), "{}", d.kind);
    }
}

/// a machine on an image from before message approvals: it knows no preview, so it takes the router's preview as a
/// delivery and refuses it for want of the core's attestation; an attested delivery it takes
fn old_image_machine() -> AnswerFn {
    Arc::new(|d| {
        if d.attest.is_none() {
            return DeliveryResult {
                error: "no core attestation (the input isn't in the core's log)".into(),
                ..Default::default()
            };
        }
        DeliveryResult {
            ok: true,
            ..Default::default()
        }
    })
}

/// An upward peer message into a sensitive session whose machine can't preview is held with Jarvis's own rendering,
/// and delivered once Deyao delivers it (2026-10-20: it was reported FAILED to its sender before Deyao saw it)
#[test]
fn a_message_into_an_old_image_machine_is_held_with_jarvis_text() {
    let m = new_msg_rig("mmsg9", true, old_image_machine());
    add_session(&m.r, "sfrom", "started", "mfrom", false);
    let out =
        m.r.send_peer(
            "sfrom",
            "s1",
            "test step 2 could not run",
            SignedRequest {
                machine: "mfrom".into(),
                method: "POST".into(),
                path: "/m/api/requests/peer".into(),
                sig: "p".into(),
                ..Default::default()
            },
            "POST",
            "/m/api/requests/peer",
        )
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(out["waiting"], "message", "{out}");
    let ps = m.wait_pending(1);
    let oc = m.outcomes("sfrom");
    assert!(
        oc.is_empty(),
        "the sender was told before Deyao saw the message: {oc:?}"
    );
    assert!(
        ps.len() == 1
            && ps[0].kind == "peer"
            && ps[0].state == "pending"
            && ps[0].text.contains("test step 2 could not run")
            && ps[0].text.contains("relayed by Jarvis")
            && ps[0].note.contains("before message approvals"),
        "not held with Jarvis's text: {ps:?}"
    );
    let (text, _, _) =
        m.r.draft_messages(&[ps[0].id.clone()])
            .unwrap_or_else(|e| panic!("{e:#}"));
    m.r.approve_messages(&m.sign(&text))
        .unwrap_or_else(|e| panic!("{e:#}"));
    m.settle();
    let last = m.deliveries().last().cloned().unwrap_or_default();
    assert!(
        !last.preview
            && last.kind == "peer"
            && last.attest.is_some()
            && last.peer.as_ref().is_some_and(|p| p.approved),
        "delivered {last:?}"
    );
    let oc = m.outcomes("sfrom");
    assert!(
        oc.len() == 1 && oc[0].outcome == OUTCOME_APPROVED && m.pending().is_empty(),
        "outcomes {oc:?}, pending {:?}",
        m.pending()
    );
    // Jarvis's own kinds aren't held at all (DECISIONS 210): a login "continue" goes straight in, attested
    let n = m.deliveries().len();
    m.r.deliver_canned(
        "s1",
        Delivery {
            kind: "continue".into(),
            ..Default::default()
        },
        "",
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    let ds = m.deliveries();
    assert!(
        ds.len() == n + 1
            && ds[n].kind == "continue"
            && !ds[n].preview
            && ds[n].attest.is_some()
            && m.pending().is_empty(),
        "continue {:?}, pending {:?}",
        &ds[n..],
        m.pending()
    );
}
