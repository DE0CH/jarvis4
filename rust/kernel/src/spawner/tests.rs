//! kernel/spawner/spawner_test.go: spawn, init, kill and destroy on a fake Fly

#[path = "tests_fabric.rs"]
mod fabric;

use super::fly::{Fly, FlyError};
use super::{
    MachineKeys, REASON_BAD_SNAPSHOT, REASON_CAME_UP, REASON_FLY, REASON_HOST_FULL,
    REASON_NOT_DESTROYED, REASON_NOT_STARTED, REASON_UNKNOWN, REASON_WRONG_IMAGE, RunMachine,
    Snapshot, SpawnInput, Spawner,
};
use crate::kt::{World, source, source_content};
use crate::notarizer::{Input, Notarizer};
use crate::serve::Fail;
use jarvis_doc::perm::{Pair, Set};
use jarvis_doc::{Cert, by, open_cert, peek_cert};
use jarvis_sig::{Doc, Opener, Signer};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const IMG: &str = "ghcr.io/de0ch/jarvis4-session@sha256:2222222222222222222222222222222222222222222222222222222222222222";

struct FakeM {
    image: String,
    state: String,
    volume: String,
    source: String,
    keys: Signer,
    enc: Signer,
}

#[derive(Default)]
struct FlyState {
    n: i64,
    ms: BTreeMap<String, FakeM>,
    vols: BTreeMap<String, bool>,
    /// report this image instead
    swap: String,
    slow_stop: bool,
    /// create makes the machine but answers an error (a lost answer)
    lose: bool,
    /// create answers that the volume's host is full (412 volume_placement_capacity)
    full: bool,
    /// delete_volume fails
    stuck_vols: bool,
    /// the compute hint of each create_volume
    guests: Vec<Value>,
}

#[derive(Default)]
struct FakeFly(Mutex<FlyState>);

impl FakeFly {
    fn st(&self) -> std::sync::MutexGuard<'_, FlyState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn start(&self, id: &str) {
        if let Some(m) = self.st().ms.get_mut(id) {
            m.state = "started".into();
        }
    }
    fn state(&self, id: &str) -> String {
        self.st()
            .ms
            .get(id)
            .map(|m| m.state.clone())
            .unwrap_or_default()
    }
}

impl Fly for FakeFly {
    fn configure(&self, _: &str) {}
    fn create_volume(&self, _: &str, _: i64, guest: &Value) -> anyhow::Result<String> {
        let mut g = self.st();
        g.guests.push(guest.clone());
        g.n += 1;
        let v = format!("vol_{}", g.n);
        g.vols.insert(v.clone(), true);
        Ok(v)
    }
    fn create(
        &self,
        image: &str,
        _: &str,
        _: &Value,
        _: &BTreeMap<String, String>,
        volume: &str,
        source: &str,
    ) -> anyhow::Result<String> {
        let mut g = self.st();
        if g.full {
            return Err(FlyError {
                http: 412,
                status: "volume_placement_capacity".into(),
                msg: format!("POST /machines: HTTP 412 insufficient resources to create new machine with existing volume '{volume}'"),
            }
            .into());
        }
        g.n += 1;
        let id = format!("{:014x}", g.n);
        g.ms.insert(
            id.clone(),
            FakeM {
                image: image.into(),
                state: "created".into(),
                volume: volume.into(),
                source: source.into(),
                keys: Signer::generate(),
                enc: Signer::generate(),
            },
        );
        if g.lose {
            return Err(anyhow::anyhow!("connection reset"));
        }
        Ok(id)
    }
    fn inspect(&self, id: &str) -> anyhow::Result<RunMachine> {
        let g = self.st();
        let Some(m) = g.ms.get(id) else {
            return Ok(RunMachine {
                state: "destroyed".into(),
                ..Default::default()
            });
        };
        Ok(RunMachine {
            state: m.state.clone(),
            image: if g.swap.is_empty() {
                m.image.clone()
            } else {
                g.swap.clone()
            },
            volume: m.volume.clone(),
            source: m.source.clone(),
        })
    }
    fn init(&self, id: &str) -> anyhow::Result<MachineKeys> {
        let g = self.st();
        let m = g.ms.get(id).ok_or_else(|| anyhow::anyhow!("no machine"))?;
        Ok(MachineKeys {
            encryption_key: m.enc.public_key(),
            signing_key: m.keys.public_key(),
        })
    }
    fn destroy(&self, id: &str) -> anyhow::Result<()> {
        let mut g = self.st();
        let slow = g.slow_stop;
        if let Some(m) = g.ms.get_mut(id) {
            m.state = if slow {
                "stopping".into()
            } else {
                "destroyed".into()
            };
        }
        Ok(())
    }
    fn delete_volume(&self, v: &str) -> anyhow::Result<()> {
        let mut g = self.st();
        if g.stuck_vols {
            return Err(FlyError {
                http: 412,
                status: String::new(),
                msg: "volume is attached".into(),
            }
            .into());
        }
        g.vols.remove(v);
        Ok(())
    }
}

struct Rig {
    w: World,
    fly: Arc<FakeFly>,
    sp: Arc<Spawner>,
    nz: Notarizer,
    path: PathBuf,
    _dir: tempfile::TempDir,
}

fn open_spawner(w: &World, path: &std::path::Path, fly: Arc<FakeFly>) -> Spawner {
    let c = &w.c["spawner"];
    Spawner::open(
        path,
        Signer::from_scalar(&c.signer.scalar()).unwrap_or_else(|e| panic!("{e}")),
        Opener::from_scalar(&c.agreement.scalar()).unwrap_or_else(|e| panic!("{e}")),
        w.trust.clone(),
        fly,
        None,
        Some(BTreeMap::from([(
            "JARVIS2_URL".to_string(),
            "http://router".to_string(),
        )])),
        None,
    )
    .unwrap_or_else(|e| panic!("{e:#}"))
}

fn rig() -> Rig {
    let w = World::new();
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let fly = Arc::new(FakeFly::default());
    let path = dir.path().join("sp.json");
    let sp = Arc::new(open_spawner(&w, &path, fly.clone()));
    let nz = Notarizer::open(&dir.path().join("nz"), &w.trust).unwrap_or_else(|e| panic!("{e:#}"));
    Rig {
        w,
        fly,
        sp,
        nz,
        path,
        _dir: dir,
    }
}

/// the stable reason of a spawner refusal
fn reason<T>(r: &anyhow::Result<T>) -> String {
    r.as_ref()
        .err()
        .and_then(|e| e.downcast_ref::<Fail>())
        .map(|f| f.reason.clone())
        .unwrap_or_default()
}

fn id_of(out: &Value) -> String {
    out["id"].as_str().unwrap_or_default().to_string()
}

impl Rig {
    fn notarize(&self, cert: &Doc) -> Doc {
        let c = peek_cert(cert).unwrap_or_else(|e| panic!("{e}"));
        let mut i = Input {
            cert: cert.clone(),
            challenge: self
                .w
                .challenge(&cert.id(), "cert", time::OffsetDateTime::now_utc()),
            notary: self.w.id("notary"),
            signer: None,
            keys: None,
            secrets: None,
        };
        if c.signer == by::IPHONE || c.signer == by::ROOT {
            i.keys = Some(self.w.keys_doc.clone());
            i.secrets = Some(self.w.id("secrets"));
        } else {
            i.signer = Some(self.w.id(&c.signer));
        }
        self.nz
            .notarize(&self.w.c["notarizer"].signer, &self.w.trust, &i)
            .unwrap_or_else(|e| panic!("{e:#}"))
    }

    /// a notarized new source (phone) with the test image
    fn source(&self) -> (Doc, Doc) {
        let mut src = source_content("t");
        src.image = IMG.into();
        let cert = self.w.cert(
            by::IPHONE,
            "sink",
            &source(),
            &Pair::new(Set::only(["store:a"]), vec![]),
            Some(src),
            None,
        );
        let nz = self.notarize(&cert);
        (cert, nz)
    }

    fn input(&self, cert: &Doc, nz: &Doc) -> SpawnInput {
        SpawnInput {
            cert: cert.clone(),
            notarized: nz.clone(),
            notarizer: self.w.id("notarizer"),
            region: "lhr".into(),
            size: "medium".into(),
            disk_gb: 10,
            runner: String::new(),
            fabric: None,
            wireguard: None,
        }
    }

    fn spawn(&self) -> (String, Doc) {
        let (cert, nz) = self.source();
        let out = self
            .sp
            .spawn(&self.input(&cert, &nz))
            .unwrap_or_else(|e| panic!("{e:#}"));
        let id = id_of(&out);
        let r = self.sp.init(&id);
        assert_eq!(
            reason(&r),
            REASON_NOT_STARTED,
            "init before start: {:?}",
            r.err()
        );
        self.fly.start(&id);
        let d = self.sp.init(&id).unwrap_or_else(|e| panic!("{e:#}"));
        (id, d)
    }

    fn spawner_key(&self) -> String {
        self.w.c["spawner"].identity.signing_key.clone()
    }
}

fn kill_cert(out: anyhow::Result<Value>) -> (Doc, String) {
    let o = out.unwrap_or_else(|e| panic!("{e:#}"));
    (
        serde_json::from_value(o["cert"].clone()).unwrap_or_default(),
        o["volumeLeft"].as_str().unwrap_or_default().to_string(),
    )
}

/// spawn → a cert the notarizer takes; kill with the machine's signed snapshot → a source the notarizer takes,
/// holding the snapshot; the volume is gone; a second kill answers the same cert, also after a restart
#[test]
fn spawn_and_kill() {
    let r = rig();
    let (id, d) = r.spawn();
    let c = open_cert(&d, &r.spawner_key()).unwrap_or_else(|e| panic!("{e}"));
    let mkey = r.fly.st().ms[&id].keys.public_key();
    assert!(
        c.succ.0 == format!("fly-{id}")
            && c.machine.as_ref().is_some_and(|m| m.signing_key == mkey),
        "{c:?}"
    );
    assert_eq!(
        r.fly.st().ms[&id].source,
        c.pred.0,
        "the machine's Fly metadata doesn't name its source"
    );
    r.notarize(&d);
    let sum = "ef".repeat(32);
    let ssig = r.fly.st().ms[&id].keys.sign(sum.as_bytes());
    let (kd, left) = kill_cert(r.sp.kill(
        &id,
        Some(&Snapshot {
            sha256: sum.clone(),
            sig: ssig,
        }),
    ));
    let kc = open_cert(&kd, &r.spawner_key()).unwrap_or_else(|e| panic!("{e}"));
    let ks = kc.source.clone().unwrap_or_else(|| panic!("no source"));
    assert!(
        ks.snapshot == sum && ks.image == IMG && kc.pred.0 == format!("fly-{id}"),
        "{kc:?}"
    );
    r.notarize(&kd);
    assert!(
        r.fly.st().vols.is_empty() && left.is_empty(),
        "volumes left: {left:?}"
    );
    let sp2 = open_spawner(&r.w, &r.path, r.fly.clone());
    let (again, _) = kill_cert(sp2.kill(&id, None));
    assert_eq!(again, kd, "a second kill signed another cert");
    // the first cert wins: init again answers the cert it signed
    assert_eq!(sp2.init(&id).ok(), Some(d), "init signed a second cert");
}

/// ✱ a snapshot that isn't signed by the machine's key (another key, not a hash) is refused and the machine untouched;
/// ✱ none: the source's own snapshot is passed on
#[test]
fn a_bad_snapshot_is_refused() {
    let r = rig();
    let (id, _) = r.spawn();
    let sum = "ef".repeat(32);
    let bad = Signer::generate().sign(sum.as_bytes());
    for s in [
        Snapshot {
            sha256: sum.clone(),
            sig: bad.clone(),
        },
        Snapshot::default(),
        Snapshot {
            sha256: "x".into(),
            sig: bad,
        },
    ] {
        assert_eq!(reason(&r.sp.kill(&id, Some(&s))), REASON_BAD_SNAPSHOT);
    }
    assert_eq!(r.fly.state(&id), "started", "the machine was touched");
    // a machine of a source with a snapshot that signs none passes that snapshot on
    let r2 = rig();
    let mut src = source_content("t");
    src.image = IMG.into();
    src.snapshot = "cd".repeat(32);
    let cert = r2.w.cert(
        by::IPHONE,
        "sink",
        &source(),
        &Pair::top(),
        Some(src.clone()),
        None,
    );
    let nz = r2.notarize(&cert);
    let id2 = id_of(
        &r2.sp
            .spawn(&r2.input(&cert, &nz))
            .unwrap_or_else(|e| panic!("{e:#}")),
    );
    r2.fly.start(&id2);
    r2.sp.init(&id2).unwrap_or_else(|e| panic!("{e:#}"));
    let (kd2, _) = kill_cert(r2.sp.kill(&id2, None));
    let kc2: Cert = open_cert(&kd2, &r2.spawner_key()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        kc2.source.map(|s| s.snapshot),
        Some(src.snapshot),
        "the source's snapshot wasn't passed on"
    );
}

/// ✱ a spawn from a cert that isn't notarized, or not into a source, or with another image, or with no disk; ✱ Fly
/// running another digest
#[test]
fn spawn_refuses() {
    let r = rig();
    let (cert, nz) = r.source();
    let (other, _) = r.source();
    assert!(
        r.sp.spawn(&r.input(&other, &nz)).is_err(),
        "spawned from a cert not notarized"
    );
    let mut src = source_content("t");
    src.image = format!("docker.io/evil/image@sha256:{}", "3".repeat(64));
    let evil =
        r.w.cert(by::IPHONE, "sink", &source(), &Pair::top(), Some(src), None);
    let enz = r.notarize(&evil);
    assert!(
        r.sp.spawn(&r.input(&evil, &enz)).is_err(),
        "spawned another repo's image"
    );
    let mut i = r.input(&cert, &nz);
    i.size = "huge".into();
    assert!(r.sp.spawn(&i).is_err(), "a size that isn't one");
    let mut i = r.input(&cert, &nz);
    i.disk_gb = 0;
    assert!(r.sp.spawn(&i).is_err(), "no disk size");
    let id = id_of(
        &r.sp
            .spawn(&r.input(&cert, &nz))
            .unwrap_or_else(|e| panic!("{e:#}")),
    );
    r.fly.start(&id);
    r.fly.st().swap = format!("ghcr.io/de0ch/jarvis4-session@sha256:{}", "4".repeat(64));
    assert_eq!(reason(&r.sp.init(&id)), REASON_WRONG_IMAGE);
    assert_eq!(reason(&r.sp.init("nosuch")), REASON_UNKNOWN);
}

/// a kill waits until Fly says destroyed (409 meanwhile); a machine never up gets a kill record, not a source
#[test]
fn kill_waits_for_fly() {
    let r = rig();
    let (cert, nz) = r.source();
    let id = id_of(
        &r.sp
            .spawn(&r.input(&cert, &nz))
            .unwrap_or_else(|e| panic!("{e:#}")),
    );
    r.fly.st().slow_stop = true;
    assert_eq!(reason(&r.sp.kill(&id, None)), REASON_NOT_DESTROYED);
    r.fly.st().slow_stop = false;
    let (d, _) = kill_cert(r.sp.kill(&id, None));
    assert!(d.payload.contains(r#""up":false"#), "{}", d.payload);
}

/// a volume Fly won't delete yet: the kill still answers its cert and names the volume left; the next kill deletes it
/// and answers the same cert
#[test]
fn a_kill_tries_the_volume_once() {
    let r = rig();
    let (id, _) = r.spawn();
    let vol = r.fly.st().ms[&id].volume.clone();
    r.fly.st().stuck_vols = true;
    let (kd, left) = kill_cert(r.sp.kill(&id, None));
    assert!(
        left == vol && r.fly.st().vols.contains_key(&vol),
        "volume left {left:?}"
    );
    r.fly.st().stuck_vols = false;
    let (again, left) = kill_cert(r.sp.kill(&id, None));
    assert!(
        again == kd && left.is_empty() && r.fly.st().vols.is_empty(),
        "second kill: left {left:?}"
    );
}

/// a spawn is single calls: ✱ Fly's 412 volume_placement_capacity answers host-full and deletes the volume it made;
/// ✱ every volume is made with the machine's size as its hint; ✱ a lost create answer leaves the machine, which the
/// router's destroy takes off Fly with its volume, also after a restart forgot it; ✱ a machine with a cert isn't
/// destroyed, and nor is one the spawner didn't make
#[test]
fn spawn_is_single_calls() {
    let r = rig();
    let (cert, nz) = r.source();
    r.fly.st().full = true;
    let res = r.sp.spawn(&r.input(&cert, &nz));
    assert!(
        reason(&res) == REASON_HOST_FULL && r.fly.st().vols.is_empty(),
        "host full: {:?}",
        res.err()
    );
    r.fly.st().full = false;
    r.sp.spawn(&r.input(&cert, &nz))
        .unwrap_or_else(|e| panic!("{e:#}"));
    for g in &r.fly.st().guests {
        assert!(
            !g["cpus"].is_null() && !g["memory_mb"].is_null() && !g["cpu_kind"].is_null(),
            "a volume without the machine's size as its hint: {g}"
        );
    }

    let r2 = rig();
    let (cert2, nz2) = r2.source();
    r2.fly.st().lose = true;
    assert_eq!(reason(&r2.sp.spawn(&r2.input(&cert2, &nz2))), REASON_FLY);
    r2.fly.st().lose = false;
    let stray = r2.fly.st().ms.keys().next().cloned().unwrap_or_default();
    let want = peek_cert(&cert2).unwrap_or_else(|e| panic!("{e}")).succ.0;
    assert_eq!(r2.fly.st().ms[&stray].source, want, "the stray's metadata");
    let sp2 = open_spawner(&r2.w, &r2.path, r2.fly.clone());
    let out = sp2.destroy(&stray).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        out["volumeLeft"] == ""
            && r2.fly.state(&stray) == "destroyed"
            && r2.fly.st().vols.is_empty(),
        "destroy: {out}"
    );
    assert!(sp2.init(&stray).is_err(), "a destroyed machine initialised");
    sp2.destroy(&stray)
        .unwrap_or_else(|e| panic!("a repeated destroy: {e:#}"));

    let (id, _) = r.spawn();
    let res = r.sp.destroy(&id);
    assert!(
        reason(&res) == REASON_CAME_UP && r.fly.state(&id) == "started",
        "{:?}",
        res.err()
    );
    r.fly.st().ms.insert(
        "elsewhere".into(),
        FakeM {
            image: String::new(),
            state: "started".into(),
            volume: String::new(),
            source: String::new(),
            keys: Signer::generate(),
            enc: Signer::generate(),
        },
    );
    let res = r.sp.destroy("elsewhere");
    assert!(
        reason(&res) == REASON_UNKNOWN && r.fly.state("elsewhere") == "started",
        "{:?}",
        res.err()
    );
}
