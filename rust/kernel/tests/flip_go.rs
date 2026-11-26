//! A Go copy's flip taken by Rust components (kernel/kerneltest/rustflipvec_test.go writes the vector): the kernel's
//! cut is a flip from Go's notarizer, spawner and secrets to Rust's, and a rollback the flip back. Each Rust
//! component takes Go's handoff and hands over again: the state it hands over is the state Go handed it (so a Go
//! component takes it back as Go made it); and the Rust spawner kills the machine Go's made.

use jarvis_kernel::flip::HANDOFF_INFO;
use jarvis_kernel::kerneltest::FakeFly;
use jarvis_kernel::notarizer::{self, Notarizer};
use jarvis_kernel::secrets::Secrets;
use jarvis_kernel::serve::Server;
use jarvis_kernel::spawner::{self, Spawner};
use jarvis_nethttp::{HandlerFn, Req, W};
use jarvis_sig::{Component, Doc, Identity, Opener, Sealed, Signer, Trust, unb64};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Deserialize, Clone)]
struct VecKeys {
    role: String,
    signing: String,
    agreement: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VecMachine {
    #[serde(rename = "ID")]
    id: String,
    image: String,
    state: String,
    volume: String,
    source: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct V {
    root: String,
    green: Doc,
    next: Doc,
    keys: BTreeMap<String, VecKeys>,
    next_keys: BTreeMap<String, VecKeys>,
    handoffs: BTreeMap<String, Doc>,
    machines: Vec<VecMachine>,
    running: String,
}

fn vectors() -> V {
    serde_json::from_str(include_str!("vectors/flip-handoff.json"))
        .unwrap_or_else(|e| panic!("{e}"))
}

fn signer(k: &VecKeys) -> Signer {
    Signer::from_scalar(&unb64(&k.signing).unwrap_or_default()).unwrap_or_else(|e| panic!("{e}"))
}

fn opener(k: &VecKeys) -> Opener {
    Opener::from_scalar(&unb64(&k.agreement).unwrap_or_default()).unwrap_or_else(|e| panic!("{e}"))
}

fn component(k: &VecKeys) -> Component {
    let (s, a) = (signer(k), opener(k));
    Component {
        role: k.role.clone(),
        identity: Identity {
            role: k.role.clone(),
            signing_key: s.public_key(),
            agreement_key: a.public_key(),
        },
        signer: s,
        agreement: a,
    }
}

/// one call to a handler → (status, the signed answer)
fn call(h: &HandlerFn, path: &str, body: &Value) -> (u16, Doc) {
    let mut w = W::recorder();
    let mut r = Req::new("POST", path, body.to_string().as_bytes())
        .with_header("Content-Type", "application/json");
    h(&mut w, &mut r);
    let d: Doc = serde_json::from_str(&w.body_text()).unwrap_or(Doc {
        payload: w.body_text(),
        sig: String::new(),
    });
    (w.status(), d)
}

fn ok(h: &HandlerFn, path: &str, body: &Value) -> Doc {
    let (st, d) = call(h, path, body);
    assert_eq!(st, 200, "{path}: {}", d.payload);
    d
}

/// the state a handoff carries, opened with its recipient's agreement key
fn state(h: &Doc, to: &Opener, role: &str) -> Value {
    let p: Value = serde_json::from_str(&h.payload).unwrap_or_default();
    let sealed: Sealed =
        serde_json::from_value(p["sealed"].clone()).unwrap_or_else(|e| panic!("{role}: {e}"));
    let plain = to
        .open(&sealed, &format!("{HANDOFF_INFO}{role}"))
        .unwrap_or_else(|e| panic!("{role}: {e}"));
    serde_json::from_slice(&plain).unwrap_or_else(|e| panic!("{role}: {e}"))
}

fn fly(v: &V) -> Arc<FakeFly> {
    let f = Arc::new(FakeFly::default());
    for m in &v.machines {
        f.st().machines.insert(
            m.id.clone(),
            jarvis_kernel::kerneltest::FakeMachine {
                id: m.id.clone(),
                image: m.image.clone(),
                state: m.state.clone(),
                source: m.source.clone(),
                volume: m.volume.clone(),
                env: BTreeMap::new(),
                sig: Arc::new(Signer::generate()),
                enc: Arc::new(Opener::generate()),
            },
        );
    }
    f
}

fn spawner_on(v: &V, dir: &std::path::Path) -> HandlerFn {
    let c = component(&v.keys["spawner"]);
    let s = Server::new(component(&v.keys["spawner"]), Arc::new(Trust::new(&v.root)));
    let sp = Spawner::open(
        &dir.join("spawner"),
        c.signer,
        c.agreement,
        s.trust.clone(),
        fly(v),
        None,
        Some(BTreeMap::from([(
            "JARVIS2_URL".to_string(),
            "http://router".to_string(),
        )])),
        None,
    )
    .unwrap_or_else(|e| panic!("{e:#}"));
    spawner::register(&s, Arc::new(sp));
    s.handler()
}

/// take Go's handoff, hand over to the next roster: the same state
fn round_trip(v: &V, role: &str, h: &HandlerFn) {
    ok(h, "/roster", &json!({"roster": v.green}));
    let took = ok(h, "/takeover", &json!({"handoff": v.handoffs[role]}));
    assert!(
        took.payload.contains("took-over") || !took.payload.is_empty(),
        "{role}: {}",
        took.payload
    );
    let again = ok(h, "/handoff", &json!({"roster": v.next}));
    let go = state(&v.handoffs[role], &opener(&v.keys[role]), role);
    let rust = state(&again, &opener(&v.next_keys[role]), role);
    if role == "secrets" {
        // the line goes on in the Rust secrets: its head moves; everything it holds is Go's
        let (mut g, mut r) = (go.clone(), rust.clone());
        for x in [&mut g, &mut r] {
            if let Some(o) = x.as_object_mut() {
                o.remove("lineState");
            }
        }
        assert_eq!(r, g, "{role}: the state handed over again isn't Go's");
    } else {
        assert_eq!(rust, go, "{role}: the state handed over again isn't Go's");
    }
}

#[test]
fn a_rust_notarizer_takes_a_go_handoff_and_hands_it_on() {
    let v = vectors();
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let s = Server::new(
        component(&v.keys["notarizer"]),
        Arc::new(Trust::new(&v.root)),
    );
    let n = Notarizer::open(&dir.path().join("notarizer"), &s.trust)
        .unwrap_or_else(|e| panic!("{e:#}"));
    notarizer::register(&s, Arc::new(n));
    round_trip(&v, "notarizer", &s.handler());
}

#[test]
fn a_rust_spawner_takes_a_go_handoff_and_hands_it_on() {
    let v = vectors();
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    round_trip(&v, "spawner", &spawner_on(&v, dir.path()));
}

/// the Rust spawner holds Go's machines: it kills the line's machine into a source
#[test]
fn a_rust_spawner_kills_the_machine_a_go_one_made() {
    let v = vectors();
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let h = spawner_on(&v, dir.path());
    ok(&h, "/roster", &json!({"roster": v.green}));
    ok(&h, "/takeover", &json!({"handoff": v.handoffs["spawner"]}));
    let kd = ok(&h, "/kill", &json!({"id": v.running}));
    let p: Value = serde_json::from_str(&kd.payload).unwrap_or_default();
    let cert: Doc =
        serde_json::from_value(p["cert"].clone()).unwrap_or_else(|e| panic!("{e}: {}", kd.payload));
    let c = jarvis_doc::open_cert(&cert, &component(&v.keys["spawner"]).identity.signing_key)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(c.pred.0, format!("fly-{}", v.running));
    assert!(c.succ.0.starts_with("source-"), "{c:?}");
}

#[test]
fn a_rust_secrets_takes_a_go_handoff_and_hands_it_on() {
    let v = vectors();
    let k = &v.keys["secrets"];
    let s = Arc::new(Secrets::with_keys(&v.root, signer(k), opener(k), None));
    round_trip(&v, "secrets", &jarvis_kernel::secrets::http::handler(s));
}
