//! The kernel's side of the app's tests, over the kernel's own crates (rust/sig, rust/doc): the ports of
//! ios/interop/rostervec, ios/interop/vectors and ios/ci/fakekernel (Go, over kernel/).
//!
//!   ios-ci rostervec [-open ROOTPUB]   (also as a binary named `rostervec`: the Swift test runs it with the args alone)
//!       reads {"copy", "members": [{role, signingKey, agreementKey}…], "retired": […], "secretsBoot": {…}} on stdin and
//!       prints the roster's payload (Roster::payload); with -open ROOTPUB, reads {"payload","sig"} and prints the
//!       roster open_roster reads, or fails
//!   ios-ci vectors                     kernel documents as the kernel makes them, for the app's interop test
//!       (ios/interop Kernel): a new source's cert for session s1, an add-store's two certs, the payloads that must be
//!       refused, and store keys P + K (the app computes its own)
//!   ios-ci fakekernel ADDR [ROUTER]    a stand-in for the kernel's nine components, for ios.yml's kernel-health UI test
//!       (KernelUITests): one server answers every role at http://ADDR/<role> (the router's KERNEL_URL =
//!       http://ADDR/%s), each with fresh keys and the kernel's own roster check (Trust) against a root key made here.
//!       With ROUTER it then plays the root key and the app: registers the root key with the router and posts the
//!       roster it signs (POST /api/kernel/root-key, POST /api/kernel/roster; the router runs NO_ACCESS=1), so the
//!       router's kernel is healthy. POST /_down/<role> makes a role stop answering (the test's unhealthy kernel),
//!       POST /_up/<role> brings it back.

use anyhow::{Context, Result, anyhow, bail};
use jarvis_doc::perm::{Pair, Set};
use jarvis_doc::{Cert, Machine, Object, SINK, Source, by};
use jarvis_nethttp::{Req, W};
use jarvis_sig::{Component, Doc, Opener, Roster, Signer, Trust, open_roster, store_key};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

pub fn rostervec(args: &[&str]) -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    match args {
        ["-open", root] | ["--open", root] => {
            let d: Doc = serde_json::from_str(&input)?;
            let r = open_roster(&d, root).map_err(|e| anyhow!("{e}"))?;
            println!("{}", jarvis_sig::go_json(&r)?);
            Ok(())
        }
        [] => {
            let mut v: Value = serde_json::from_str(&input)?;
            if let Some(o) = v.as_object_mut() {
                o.entry("kind").or_insert(json!(""));
            }
            let r: Roster = serde_json::from_value(v)?;
            print!("{}", r.payload()?);
            std::io::stdout().flush()?;
            Ok(())
        }
        _ => bail!("usage: rostervec [-open ROOTPUB]"),
    }
}

/// the public key of a small scalar (base64 X9.63)
fn point(n: u8) -> Result<String> {
    let mut d = [0u8; 32];
    d[31] = n;
    Ok(Opener::from_scalar(&d)?.public_key())
}

pub fn vectors() -> Result<()> {
    const IMG: &str = "ghcr.io/de0ch/jarvis4-session:sha-aaaaaaaaaaaa@sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let settings = r#"{"config":{"label":"x","model":"claude-opus-5-5","prompt":"hi"},"harness":"claude","permissionMode":"auto","v":1}"#;
    let src = "source-0123456789abcdef0123456789abcdef";
    let add = "source-fedcba9876543210fedcba9876543210";
    let at = "2026-10-21T15:00:00Z";
    let stores = || {
        Pair::new(
            Set::only(["store:default", "store:tunnel"]),
            vec!["session:s1".into()],
        )
    };
    let source = |image: &str, snapshot: &str| -> Result<Option<Source>> {
        Ok(Some(Source {
            image: image.into(),
            settings: serde_json::value::RawValue::from_string(settings.into())?,
            snapshot: snapshot.into(),
        }))
    };
    let machine = || {
        Some(Machine {
            signing_key: "BAAA".into(),
            encryption_key: "BAAB".into(),
            image: IMG.into(),
        })
    };
    let cert = |pred: &str,
                succ: &str,
                pair: Pair,
                s: Option<Source>,
                m: Option<Machine>|
     -> Result<String> {
        let c = Cert {
            kind: "succession".into(),
            pred: Object(pred.into()),
            succ: Object(succ.into()),
            pair,
            source: s,
            machine: m,
            signer: by::IPHONE.into(),
            issued_at: at.into(),
        };
        c.check().map_err(|e| anyhow!("{succ}: {e}"))?;
        Ok(jarvis_sig::go_json(&c)?)
    };
    let one = |store: &str| Pair::new(Set::only([store]), vec!["session:s1".into()]);
    let out = BTreeMap::from([
        ("source", cert(SINK, src, stores(), source(IMG, "")?, None)?),
        (
            "restore",
            cert(
                SINK,
                src,
                stores(),
                source(
                    IMG,
                    "e3025c921e4262bf368c224c3fbd893d113cdf58cd333b11806adc45e4f75c6f",
                )?,
                None,
            )?,
        ),
        (
            "addFirst",
            cert(SINK, add, one("store:extra"), source(IMG, "")?, None)?,
        ),
        (
            "addSecond",
            cert(add, "fly-0123456789abcd", Pair::top(), None, machine())?,
        ),
        // the same onto a machine of each other runner (rust/doc MACHINE_RE)
        (
            "addSecondAWS",
            cert(add, "aws-i-0123456789abcdef0", Pair::top(), None, machine())?,
        ),
        (
            "addSecondFabric",
            cert(
                add,
                "fabric-x01a1f84c119b7406bf3daf4fb7f0cba9",
                Pair::top(),
                None,
                machine(),
            )?,
        ),
        // refused: allows a shell, another session's, another repo's image
        (
            "shell",
            cert(
                SINK,
                src,
                Pair::new(
                    Set::only(["shell", "store:default"]),
                    vec!["session:s1".into()],
                ),
                source(IMG, "")?,
                None,
            )?,
        ),
        (
            "otherSession",
            cert(
                SINK,
                src,
                Pair::new(Set::only(["store:default"]), vec!["session:s2".into()]),
                source(IMG, "")?,
                None,
            )?,
        ),
        (
            "otherImage",
            cert(
                SINK,
                src,
                stores(),
                source(
                    "ghcr.io/evil/x@sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "",
                )?,
                None,
            )?,
        ),
        // the store key: 7G + 11G, and 5G + 5G (a doubling)
        ("storeKeyPhone", point(7)?),
        ("storeKeySecrets", point(11)?),
        ("storeKey", store_key(&point(7)?, &point(11)?)?),
        ("storeKeyTwice", point(5)?),
        ("storeKeyDouble", store_key(&point(5)?, &point(5)?)?),
    ]);
    println!("{}", jarvis_sig::go_json(&out)?);
    Ok(())
}

const ROLES: [&str; 9] = [
    "gullible",
    "identity",
    "merger",
    "minter",
    "mover",
    "notarizer",
    "notary",
    "secrets",
    "spawner",
];

struct Stand {
    c: Component,
    trust: Trust,
}

pub fn fakekernel(addr: &str, router: Option<&str>) -> Result<()> {
    let root = Signer::generate();
    let comps: Arc<BTreeMap<&str, Stand>> = Arc::new(
        ROLES
            .iter()
            .map(|r| {
                (
                    *r,
                    Stand {
                        c: Component::new(r),
                        trust: Trust::new(&root.public_key()),
                    },
                )
            })
            .collect(),
    );
    let ids: Vec<_> = ROLES.iter().map(|r| comps[r].c.identity.clone()).collect();
    let down: Arc<Mutex<BTreeMap<String, bool>>> = Arc::default();
    let h: jarvis_nethttp::Handler = {
        let (comps, down) = (comps.clone(), down.clone());
        Arc::new(move |w: &mut W, req: &mut Req| {
            let (code, v) = answer(&comps, &down, req);
            jarvis_nethttp::write_json(w, code, &v);
        })
    };
    let rt = tokio::runtime::Runtime::new()?;
    let stop = tokio_util::sync::CancellationToken::new();
    let a = addr.to_string();
    let serve = std::thread::spawn(move || rt.block_on(jarvis_nethttp::serve(&a, h, stop)));
    // the server is up once it answers
    for _ in 0..50 {
        if std::net::TcpStream::connect(addr).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if let Some(router) = router {
        let payload = Roster {
            copy: "blue".into(),
            members: ids,
            ..Default::default()
        }
        .payload()?;
        let rs = root.sign(payload.as_bytes());
        post(
            &format!("{router}/api/kernel/root-key"),
            &json!({"rootKey": root.public_key()}),
        )?;
        let out = post(
            &format!("{router}/api/kernel/roster"),
            &json!({"payload": payload, "rootSig": rs}),
        )?;
        eprintln!("the roster is posted: {out}");
    }
    serve.join().map_err(|_| anyhow!("the server ended"))?
}

fn answer(
    comps: &BTreeMap<&str, Stand>,
    down: &Mutex<BTreeMap<String, bool>>,
    req: &mut Req,
) -> (u16, Value) {
    let url = req.path.clone();
    let Some((dep, rest)) = url.trim_start_matches('/').split_once('/') else {
        return (404, json!({"error": "not found"}));
    };
    let path = format!("/{rest}");
    if dep == "_down" || dep == "_up" {
        down.lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(rest.to_string(), dep == "_down");
        eprintln!("{dep} {rest}");
        return (200, json!({"ok": true}));
    }
    // secrets-blue and -green: one secrets
    let role = dep.trim_end_matches("-blue").trim_end_matches("-green");
    let is_down = {
        let d = down.lock().unwrap_or_else(|e| e.into_inner());
        d.get(dep).copied().unwrap_or(false) || d.get(role).copied().unwrap_or(false)
    };
    let Some(c) = comps.get(role).filter(|_| !is_down) else {
        return (503, json!({"error": format!("{dep} is down")}));
    };
    match (req.method.as_str(), path.as_str()) {
        ("GET", "/identity") => (200, json!(c.c.identity)),
        ("GET", "/roster") => match c.trust.doc() {
            Some(d) => (200, json!(d)),
            None => (
                404,
                json!({"kind": "error", "error": jarvis_sig::IdentityError::NoRoster.to_string()}),
            ),
        },
        ("POST", "/roster") => {
            let b = req.read_body(1 << 20);
            let d = serde_json::from_slice::<Value>(&b)
                .ok()
                .and_then(|v| serde_json::from_value::<Doc>(v["roster"].clone()).ok());
            let Some(d) = d else {
                return (
                    400,
                    json!({"error": "the body: {\"roster\": {payload, sig}}"}),
                );
            };
            let id = d.id();
            match c.trust.set(d, Some(&c.c.identity)) {
                Ok(()) => (200, json!({"kind": "roster-taken", "roster": id})),
                Err(e) => (403, json!({"error": e.to_string()})),
            }
        }
        _ => (
            404,
            json!({"error": "the stand-in answers only /identity and /roster"}),
        ),
    }
}

fn post(url: &str, body: &Value) -> Result<String> {
    let resp = reqwest::blocking::Client::new()
        .post(url)
        .json(body)
        .send()
        .with_context(|| url.to_string())?;
    let st = resp.status().as_u16();
    let out = resp.text()?;
    if st != 200 {
        bail!("{url}: HTTP {st} {out}");
    }
    Ok(out.trim().to_string())
}
