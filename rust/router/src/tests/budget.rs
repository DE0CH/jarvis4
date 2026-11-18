//! budget_test.go, awsbudget_test.go, awsowner_test.go
use crate::awsbudget::{
    AWS_BILLED_EVERY, AWS_BUDGET_REGIONS, AwsAddress, AwsBilled, AwsCostApi, AwsCoster,
    AwsInstance, AwsInventory, AwsSnapshot, AwsVolume, aws_burn_rate, aws_instance_rate,
    aws_storage_rate,
};
use crate::awsowner::{GITHUB_RUN, GhRun};
use crate::budget::{
    BUDGET_DM, BUDGET_PAUSE, BudgetActions, BudgetState, FlyGuest, FlyMachine, FlyMachineConfig,
    FlyReader, FlySnapshot, FlyVolume, HOURS_PER_MONTH, MAX_DELTA_H, SpendSample, apply_sample,
    budget_thresholds, burn_rate, hourly_machine_cost, hourly_snapshot_cost, hourly_volume_cost,
    live_volumes,
};
use crate::router::{Busy, Router};
use crate::sizes::size_guest;
use crate::state::Session;
use crate::testutil::{TestServer, add_session, new_test_router, new_test_router_on, serial};
use anyhow::{Result, anyhow};
use jarvis_go::GoTime;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn near(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

fn at(y: i32, mo: u8, d: u8, h: u8, mi: u8) -> GoTime {
    let date = time::Date::from_calendar_date(
        y,
        time::Month::try_from(mo).unwrap_or(time::Month::January),
        d,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    GoTime(Some(
        date.with_hms(h, mi, 0)
            .unwrap_or_else(|e| panic!("{e}"))
            .assume_utc(),
    ))
}

fn hours(n: i64) -> time::Duration {
    time::Duration::hours(n)
}

fn mins(n: i64) -> time::Duration {
    time::Duration::minutes(n)
}

fn guest(kind: &str, cpus: i64, mb: i64) -> FlyGuest {
    FlyGuest {
        cpu_kind: kind.into(),
        cpus,
        memory_mb: mb,
    }
}

fn machine(id: &str, state: &str) -> FlyMachine {
    FlyMachine {
        id: id.into(),
        state: state.into(),
        config: FlyMachineConfig {
            guest: Some(guest("shared", 4, 4096)),
        },
        ..Default::default()
    }
}

fn vol(id: &str, state: &str, gb: i64) -> FlyVolume {
    FlyVolume {
        id: id.into(),
        state: state.into(),
        size_gb: gb,
        ..Default::default()
    }
}

#[derive(Default)]
struct FakeFly {
    ms: Vec<FlyMachine>,
    vs: Vec<FlyVolume>,
    err: Option<String>,
    snaps: Option<BTreeMap<String, Vec<FlySnapshot>>>,
    asked: Mutex<Vec<String>>,
}

impl FlyReader for FakeFly {
    fn machines(&self) -> Result<Vec<FlyMachine>> {
        match &self.err {
            Some(e) => Err(anyhow!("{e}")),
            None => Ok(self.ms.clone()),
        }
    }
    fn volumes(&self) -> Result<Vec<FlyVolume>> {
        Ok(self.vs.clone())
    }
    fn snapshots(&self, v: &str) -> Option<Result<Vec<FlySnapshot>>> {
        let snaps = self.snaps.as_ref()?;
        self.asked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(v.into());
        Some(Ok(snaps.get(v).cloned().unwrap_or_default()))
    }
}

struct FakeAws {
    inv: AwsInventory,
    billed: f64,
    calls: AtomicUsize,
}

impl AwsCoster for FakeAws {
    fn inventory(&self, _now: GoTime) -> (AwsInventory, Option<anyhow::Error>) {
        (self.inv.clone(), None)
    }
    fn billed(&self, _month: &str) -> (Result<f64>, String) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        (Ok(self.billed), "795109470764".into())
    }
}

fn smp(fly: f64, aws: f64, billed: Option<AwsBilled>) -> SpendSample {
    SpendSample {
        fly_rate: fly,
        aws_rate: aws,
        billed,
    }
}

/// the effects the budget tick takes (BUDGET_PAUSE / BUDGET_DM are fn pointers: their record is here)
static PAUSED: Mutex<Vec<String>> = Mutex::new(vec![]);
static DMS: Mutex<Vec<String>> = Mutex::new(vec![]);
static S2_BUSY: AtomicBool = AtomicBool::new(false);

fn fake_pause(_: &Arc<Router>, sid: &str) -> Result<()> {
    if sid == "s2" && S2_BUSY.load(Ordering::SeqCst) {
        return Err(anyhow::Error::new(Busy(String::new())));
    }
    PAUSED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(sid.into());
    Ok(())
}

fn fake_dm(_: &Arc<Router>, text: &str) {
    DMS.lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(text.into());
}

/// the fakes in place until dropped
struct Effects;

impl Effects {
    fn install(s2_busy: bool) -> Effects {
        PAUSED.lock().unwrap_or_else(|e| e.into_inner()).clear();
        DMS.lock().unwrap_or_else(|e| e.into_inner()).clear();
        S2_BUSY.store(s2_busy, Ordering::SeqCst);
        *BUDGET_PAUSE.lock().unwrap_or_else(|e| e.into_inner()) = Some(fake_pause);
        *BUDGET_DM.lock().unwrap_or_else(|e| e.into_inner()) = Some(fake_dm);
        Effects
    }
    fn paused(&self) -> String {
        PAUSED.lock().unwrap_or_else(|e| e.into_inner()).join(",")
    }
    fn dms(&self) -> Vec<String> {
        DMS.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Drop for Effects {
    fn drop(&mut self) {
        *BUDGET_PAUSE.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *BUDGET_DM.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

fn put_session(r: &Router, id: &str, machine: &str, label: &str, state: &str) {
    r.st.do_(|d| {
        d.sessions.insert(
            id.into(),
            Session {
                id: id.into(),
                machine_id: machine.into(),
                label: label.into(),
                state: state.into(),
                ..Default::default()
            },
        );
    });
}

fn link(r: &Router, machine: &str, sid: &str) {
    r.st.do_(|d| {
        d.machines.insert(machine.into(), sid.into());
    });
}

#[test]
fn costs() {
    let small = guest("shared", 2, 2048);
    assert!((hourly_machine_cost(Some(&small), "lhr") - 0.0211).abs() <= 0.00005);
    let perf = guest("performance", 2, 4096);
    assert!((hourly_machine_cost(Some(&perf), "lhr") - 0.1040).abs() <= 0.00005);
    for (size, per_hour) in [
        ("large", 0.0844),
        ("16gb", 0.1601),
        ("32gb", 0.5674),
        ("64gb", 0.8701),
        ("128gb", 1.7402),
    ] {
        let (kind, cpus, mb) = size_guest(size);
        let got = hourly_machine_cost(Some(&guest(kind, cpus, mb)), "lhr");
        assert!(
            (got - per_hour).abs() <= 0.00005,
            "{size}: {got:.4} an hour, Fly says {per_hour:.4}"
        );
    }
    assert!(hourly_machine_cost(None, "lhr") == 0.0 && near(hourly_volume_cost(10), 1.5 / 730.0));
    let ms = vec![
        FlyMachine {
            state: "started".into(),
            config: FlyMachineConfig {
                guest: Some(small.clone()),
            },
            ..Default::default()
        },
        FlyMachine {
            state: "stopped".into(),
            config: FlyMachineConfig { guest: Some(perf) },
            ..Default::default()
        },
    ];
    let vs = vec![
        vol("", "created", 10),
        vol("", "destroyed", 99),
        vol("", "pending_destroy", 10),
        vol("", "destroying", 10),
    ];
    let b = burn_rate(&ms, &vs);
    assert!(
        b.running == 1
            && b.volumes == 1
            && near(
                b.rate_per_hour,
                hourly_machine_cost(Some(&small), "") + hourly_volume_cost(10)
            ),
        "{b:?}"
    );
}

#[test]
fn apply_sample_steps() {
    let t0 = at(2026, 10, 9, 0, 0);
    let (s, a, _) = apply_sample(None, t0, &smp(1.0, 0.0, None), 30.0, 25.0);
    assert!(
        s.spent_usd == 0.0 && a == BudgetActions::default() && s.month == "2026-10",
        "{s:?}"
    );
    // a gap longer than MAX_DELTA_H bills only MAX_DELTA_H
    let (mut s, _, dh) = apply_sample(
        Some(&s),
        t0.add(hours(10)),
        &smp(1.0, 0.0, None),
        30.0,
        25.0,
    );
    assert!(dh == MAX_DELTA_H && s.spent_usd == 6.0, "gap {dh} {s:?}");
    // clock going backwards bills nothing
    let (s2, _, dh) = apply_sample(Some(&s), t0.add(hours(9)), &smp(1.0, 0.0, None), 30.0, 25.0);
    assert!(dh == 0.0 && s2.spent_usd == 6.0, "backwards {dh} {s2:?}");
    let next = |s: &BudgetState| s.last_sample_at.unwrap_or_default().add(hours(1));
    // warn once
    s.spent_usd = 24.5;
    let (s, a, _) = apply_sample(Some(&s), next(&s), &smp(1.0, 0.0, None), 30.0, 25.0);
    assert!(a.warn_dm && !a.enforce && s.warned, "warn {s:?} {a:?}");
    let (mut s, a, _) = apply_sample(Some(&s), next(&s), &smp(1.0, 0.0, None), 30.0, 25.0);
    assert!(!a.warn_dm, "warned twice");
    // cap: DM once, enforce every tick
    s.spent_usd = 29.5;
    let (s, a, _) = apply_sample(Some(&s), next(&s), &smp(1.0, 0.0, None), 30.0, 25.0);
    assert!(
        a.enforce && a.cap_dm && s.capped && s.capped_at.is_some(),
        "cap {s:?} {a:?}"
    );
    let (s, a, _) = apply_sample(Some(&s), next(&s), &smp(0.0, 0.0, None), 30.0, 25.0);
    assert!(a.enforce && !a.cap_dm, "still capped {a:?}");
    // a new month starts from zero
    let (s, a, _) = apply_sample(
        Some(&s),
        at(2026, 11, 1, 0, 1),
        &smp(1.0, 0.0, None),
        30.0,
        25.0,
    );
    assert!(
        s.month == "2026-11" && s.spent_usd == 0.0 && !s.capped && !s.warned && !a.enforce,
        "new month {s:?} {a:?}"
    );
    // straight past both lines: the cap, without a warn DM
    let last = s.last_sample_at.unwrap_or_default();
    let jump = BudgetState {
        month: "2026-11".into(),
        spent_usd: 20.0,
        last_sample_at: Some(last),
        ..Default::default()
    };
    let (_, a, _) = apply_sample(
        Some(&jump),
        last.add(hours(5)),
        &smp(3.0, 0.0, None),
        30.0,
        25.0,
    );
    assert!(a.cap_dm && !a.warn_dm, "jump {a:?}");
}

/// raising the lines mid-month re-arms them: warned at 25, the warn line moved to 35 → one DM at 35, one at 40
#[test]
fn raised_lines_rearm() {
    let t0 = at(2026, 10, 20, 12, 0);
    let st = BudgetState {
        month: "2026-10".into(),
        spent_usd: 28.0,
        warned: true,
        last_sample_at: Some(t0),
        ..Default::default()
    };
    let (s, a, _) = apply_sample(
        Some(&st),
        t0.add(hours(1)),
        &smp(1.0, 0.0, None),
        40.0,
        35.0,
    );
    assert!(
        !s.warned && a == BudgetActions::default(),
        "not re-armed {s:?} {a:?}"
    );
    let (s, a, _) = apply_sample(Some(&s), t0.add(hours(8)), &smp(1.0, 0.0, None), 40.0, 35.0);
    assert!(a.warn_dm && s.warned, "no DM at 35 {s:?} {a:?}");
    let (_, a, _) = apply_sample(Some(&s), t0.add(hours(9)), &smp(1.0, 0.0, None), 40.0, 35.0);
    assert!(!a.warn_dm && !a.cap_dm, "DM twice {a:?}");
    // capped at 30, the cap raised to 40: no longer capped until 40
    let st = BudgetState {
        month: "2026-10".into(),
        spent_usd: 31.0,
        warned: true,
        capped: true,
        capped_at: Some(t0),
        last_sample_at: Some(t0),
        ..Default::default()
    };
    let (s, a, _) = apply_sample(
        Some(&st),
        t0.add(hours(1)),
        &smp(1.0, 0.0, None),
        40.0,
        35.0,
    );
    assert!(
        !s.capped && !a.enforce && !s.warned,
        "still capped {s:?} {a:?}"
    );
}

#[test]
fn thresholds() {
    let env = |m: &'static [(&'static str, &'static str)]| {
        move |k: &str| {
            m.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
                .unwrap_or_default()
        }
    };
    assert_eq!(budget_thresholds(env(&[])), (50.0, 45.0));
    assert_eq!(
        budget_thresholds(env(&[("FLY_BUDGET_USD", "50")])),
        (50.0, 40.0)
    );
    assert_eq!(
        budget_thresholds(env(&[
            ("FLY_BUDGET_USD", "0"),
            ("FLY_BUDGET_WARN_USD", "0")
        ])),
        (0.0, 0.0)
    );
}

fn budget_view(r: &Router) -> (Value, Value) {
    r.load_budget_view()
}

#[test]
fn budget_tick() {
    let _g = serial();
    let t = new_test_router();
    let r = t.arc();
    put_session(&r, "s1", "m1", "one", "started");
    put_session(&r, "s2", "m2", "two", "started");
    put_session(&r, "s3", "", "", "paused");
    link(&r, "m1", "s1");
    link(&r, "m2", "s2");
    link(&r, "m3old", "s3");
    let fx = Effects::install(true);
    let fly = FakeFly {
        ms: vec![
            machine("m1", "started"),
            machine("m2", "started"),
            machine("m3old", "started"),
            machine("x9", "started"),
            machine("m4", "stopped"),
        ],
        vs: vec![vol("v1", "created", 1)],
        ..Default::default()
    };
    let t0 = at(2026, 10, 9, 0, 0);
    // under the warn line: nothing happens; Also on Fly lists the strangers
    let (a, _) = r.budget_tick(&fly, None, t0, 30.0, 25.0).expect("tick");
    assert!(
        a == BudgetActions::default() && fx.dms().is_empty(),
        "{a:?} {:?}",
        fx.dms()
    );
    let ids: Vec<String> = budget_view(&r).1["other"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|o| {
            format!(
                "{}:{}",
                o["kind"].as_str().unwrap_or(""),
                o["id"].as_str().unwrap_or("")
            )
        })
        .collect();
    assert_eq!(
        ids.join(","),
        "machine:m3old,machine:m4,machine:x9,volume:v1"
    );
    // over the cap: pause what can be paused, DM once with the strangers named
    r.st.do_(|d| {
        if let Some(b) = d.budget.as_mut() {
            b.spent_usd = 31.0;
        }
    });
    let (a, p) = r
        .budget_tick(&fly, None, t0.add(mins(1)), 30.0, 25.0)
        .expect("tick");
    assert!(
        a.enforce && a.cap_dm && p.join(",") == "one" && fx.paused() == "s1",
        "{a:?} {p:?} {}",
        fx.paused()
    );
    let dms = fx.dms();
    assert!(
        dms.len() == 1
            && dms[0].contains("Paused 1 running session(s): one")
            && dms[0].contains("m3old, x9"),
        "dm {dms:?}"
    );
    assert_eq!(budget_view(&r).0["capped"], true);
    // next tick: s2 is free now and gets paused, with a DM naming it; nothing to pause → no DM
    S2_BUSY.store(false, Ordering::SeqCst);
    PAUSED.lock().unwrap_or_else(|e| e.into_inner()).clear();
    r.budget_tick(&fly, None, t0.add(mins(2)), 30.0, 25.0)
        .expect("tick");
    assert_eq!(fx.paused(), "s1,s2");
    assert_eq!(fx.dms().len(), 2, "{:?}", fx.dms());
    let _ = r.budget_tick(&FakeFly::default(), None, t0.add(mins(3)), 30.0, 25.0);
    assert_eq!(fx.dms().len(), 2, "DM with nothing paused: {:?}", fx.dms());
    // Fly unreachable: the error shows, nothing else changes
    let down = FakeFly {
        err: Some("down".into()),
        ..Default::default()
    };
    assert!(
        r.budget_tick(&down, None, t0.add(mins(4)), 30.0, 25.0)
            .is_err()
    );
    assert_eq!(budget_view(&r).1["error"], "down");
}

/// the cap counts what Fly bills for volume snapshots too: those of Fly's volumes, each snapshot once, past the free
/// 10 GB, at USD 0.08 per GB-month
#[test]
fn the_budget_counts_volume_snapshots() {
    let _g = serial();
    assert_eq!(
        hourly_snapshot_cost(8_000_000_000),
        0.0,
        "under the free 10 GB"
    );
    let c = hourly_snapshot_cost(20_000_000_000) * HOURS_PER_MONTH;
    assert!(
        (c - 0.80).abs() <= 1e-9,
        "20 GB stored: USD {c} a month, want 0.80"
    );
    let t = new_test_router();
    let r = t.arc();
    // a time of its own: the snapshot cache is the process's
    let now = at(2031, 10, 15, 12, 0);
    let sn = |id: &str, size: i64, status: &str| FlySnapshot {
        id: id.into(),
        size,
        status: status.into(),
    };
    let fly = FakeFly {
        vs: vec![
            vol("vol_live", "created", 10),
            vol("vol_rec", "created", 10),
        ],
        snaps: Some(BTreeMap::from([
            (
                "vol_live".to_string(),
                vec![
                    sn("vs_d1", 6_000_000_000, "created"),
                    sn("vs_x", 9_000_000_000, "failed"),
                ],
            ),
            (
                "vol_rec".to_string(),
                vec![
                    sn("vs_r", 4_000_000_000, "created"),
                    sn("vs_d1", 6_000_000_000, "created"),
                ],
            ),
        ])),
        ..Default::default()
    };
    r.budget_tick(&fly, None, now, 30.0, 25.0).expect("tick");
    assert_eq!(
        fly.asked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .join(","),
        "vol_live,vol_rec"
    );
    let v = budget_view(&r).0;
    let want = hourly_volume_cost(20) + hourly_snapshot_cost(10_000_000_000);
    assert!(
        v["snapshots"] == 2
            && (v["snapshotGb"].as_f64().unwrap_or(0.0) - 10.0).abs() <= 1e-9
            && (v["ratePerHour"].as_f64().unwrap_or(0.0) - want).abs() <= 1e-12,
        "view {v}, want rate {want}"
    );
    // listed at most every 30 min
    r.budget_tick(&fly, None, now.add(mins(2)), 30.0, 25.0)
        .expect("tick");
    assert_eq!(
        fly.asked.lock().unwrap_or_else(|e| e.into_inner()).len(),
        2,
        "listed again within 30 min"
    );
}

/// Singapore and Tokyo machines cost more than London's; a region not in Fly's list is priced as the dearest
#[test]
fn region_prices() {
    let g = guest("shared", 2, 2048);
    let (lhr, sin, nrt) = (
        hourly_machine_cost(Some(&g), "lhr"),
        hourly_machine_cost(Some(&g), "sin"),
        hourly_machine_cost(Some(&g), "nrt"),
    );
    assert!(
        (sin / lhr - 1.269230769 / 1.134615385).abs() < 1e-9
            && (nrt / lhr - 1.307692308 / 1.134615385).abs() < 1e-9,
        "lhr {lhr:.4} sin {sin:.4} nrt {nrt:.4}"
    );
    assert_eq!(
        hourly_machine_cost(Some(&g), "xyz"),
        hourly_machine_cost(Some(&g), "gru")
    );
    let mut m = machine("m1", "started");
    m.region = "nrt".into();
    let b = burn_rate(std::slice::from_ref(&m), &[]);
    assert!(
        near(
            b.rate_per_hour,
            hourly_machine_cost(m.config.guest.as_ref(), "nrt")
        ),
        "{b:?}"
    );
}

/// only the leading replica ticks; the other replica's /api/state shows the same figures
#[test]
fn budget_view_on_every_replica() {
    let _g = serial();
    let t = new_test_router();
    let leader = t.arc();
    let (other, _dir) = new_test_router_on(&t);
    let fly = FakeFly {
        ms: vec![machine("m1", "started")],
        ..Default::default()
    };
    let t0 = at(2026, 10, 9, 0, 0);
    leader
        .budget_tick(&fly, None, t0, 30.0, 25.0)
        .expect("tick");
    leader
        .budget_tick(&fly, None, t0.add(hours(1)), 30.0, 25.0)
        .expect("tick");
    leader.bb_budget_tick(&[], t0, 10.0, 8.0);
    let mut out = Map::new();
    for h in crate::features::state_hooks() {
        h(&other, &mut out);
    }
    let (b, f, bb) = (&out["budget"], &out["fly"], &out["browserbaseBudget"]);
    assert!(
        b["capUsd"] == 30.0
            && b["spentUsd"].as_f64().unwrap_or(0.0) > 0.0
            && f["machines"] == 1
            && bb["capUsd"] == 10.0,
        "budget {b} fly {f} bb {bb}"
    );
}

/// 2026-11-17: the app showed 185 volumes "outside the sessions"; only what is neither a session's nor deleted counts
#[test]
fn only_leftover_volumes_are_outside_the_sessions() {
    let t = new_test_router();
    add_session(&t, "s1", "running", "", false);
    t.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut("s1") {
            s.machine_id = "m1".into();
        }
        d.machines.insert("m1".into(), "s1".into());
    });
    let ms = vec![FlyMachine {
        id: "m1".into(),
        state: "started".into(),
        ..Default::default()
    }];
    let sv = crate::volsweep::SESSION_VOLUME;
    let v = |id: &str, state: &str, att: &str| FlyVolume {
        id: id.into(),
        name: sv.into(),
        state: state.into(),
        attached_machine_id: att.into(),
        ..Default::default()
    };
    let vs = vec![
        v("vol_live", "created", "m1"),
        v("vol_gone1", "pending_destroy", ""),
        v("vol_gone2", "destroying", ""),
        v("vol_left", "created", ""),
    ];
    let ids: Vec<String> = t.also_on_fly(&ms, &vs).into_iter().map(|o| o.id).collect();
    assert_eq!(ids, vec!["vol_left".to_string()]);
    assert_eq!(live_volumes(&vs), 2);
}

fn inst(id: &str, region: &str, typ: &str, state: &str) -> AwsInstance {
    AwsInstance {
        id: id.into(),
        region: region.into(),
        type_: typ.into(),
        state: state.into(),
        ..Default::default()
    }
}

#[test]
fn aws_burn_rate_of_an_inventory() {
    let ip = |mut i: AwsInstance, ip: &str| {
        i.public_ip = ip.into();
        i
    };
    let inv = AwsInventory {
        instances: vec![
            ip(inst("i-1", "eu-west-2", "t3.medium", "running"), "1.2.3.4"),
            ip(
                inst("i-2", "ap-northeast-1", "r7i.2xlarge", "running"),
                "5.6.7.8",
            ),
            inst("i-3", "eu-west-2", "t3.large", "stopped"),
            inst("i-4", "eu-west-2", "t3.medium", "terminated"),
            inst("i-5", "eu-west-2", "x9.huge", "running"),
        ],
        volumes: vec![
            AwsVolume {
                region: "eu-west-2".into(),
                state: "in-use".into(),
                size_gb: 40,
                ..Default::default()
            },
            AwsVolume {
                region: "ap-southeast-1".into(),
                state: "available".into(),
                size_gb: 10,
                ..Default::default()
            },
            AwsVolume {
                region: "eu-west-2".into(),
                state: "deleting".into(),
                size_gb: 999,
                ..Default::default()
            },
        ],
        snapshots: vec![
            AwsSnapshot {
                region: "eu-west-2".into(),
                state: "completed".into(),
                volume_gb: 20,
                bytes: 10 << 30,
                ..Default::default()
            },
            AwsSnapshot {
                region: "ap-southeast-1".into(),
                state: "completed".into(),
                volume_gb: 20,
                ..Default::default()
            },
        ],
        addresses: vec![
            AwsAddress {
                region: "eu-west-2".into(),
                public_ip: "1.2.3.4".into(),
            },
            AwsAddress {
                region: "eu-west-2".into(),
                public_ip: "9.9.9.9".into(),
            },
        ],
    };
    let b = aws_burn_rate(&inv);
    let want = 0.0472
        + 0.6384
        + 2.5536
        + (40.0 * 0.0928 + 10.0 * 0.096) / 730.0
        + (10.0 * 0.053 + 20.0 * 0.05) / 730.0
        + 3.0 * 0.005;
    assert!(
        (b.rate_per_hour - want).abs() <= 1e-9
            && b.running == 3
            && b.volumes == 2
            && b.volume_gb == 50
            && b.snapshots == 2
            && b.ipv4 == 3,
        "{b:?}, want {want:.6}"
    );
    assert_eq!(b.unknown_types.join(","), "eu-west-2/x9.huge");
    for region in AWS_BUDGET_REGIONS {
        for typ in [
            "t3.medium",
            "t3.large",
            "m7i.xlarge",
            "m7i.2xlarge",
            "r7i.2xlarge",
            "r7i.4xlarge",
            "r7i.8xlarge",
        ] {
            assert!(
                aws_instance_rate(region, typ).1,
                "no price for {typ} in {region}"
            );
        }
        let (g, s) = aws_storage_rate(region);
        assert!(g != 0.0 && s != 0.0, "no storage price in {region}");
    }
}

/// Fly and AWS fill one pool; Cost Explorer's figure is a floor under the AWS part
#[test]
fn one_pool() {
    let t0 = at(2026, 11, 4, 0, 0);
    let st = BudgetState {
        month: "2026-11".into(),
        spent_usd: 20.0,
        last_sample_at: Some(t0),
        ..Default::default()
    };
    let (s, _, _) = apply_sample(
        Some(&st),
        t0.add(hours(1)),
        &smp(1.0, 2.0, None),
        50.0,
        45.0,
    );
    assert!(
        near(s.spent_usd, 23.0)
            && near(s.aws_usd, 2.0)
            && near(s.fly_part(), 21.0)
            && near(s.pool(), 23.0),
        "{s:?}"
    );
    let bill = |usd: f64| AwsBilled {
        month: "2026-11".into(),
        usd,
        at: t0,
    };
    let (s, a, _) = apply_sample(
        Some(&s),
        t0.add(hours(2)),
        &smp(1.0, 2.0, Some(bill(26.0))),
        50.0,
        45.0,
    );
    assert!(
        near(s.aws_part(), 26.0) && near(s.pool(), 22.0 + 26.0) && a.warn_dm,
        "{s:?} {a:?}"
    );
    let (s, a, _) = apply_sample(
        Some(&s),
        t0.add(hours(3)),
        &smp(0.0, 30.0, None),
        50.0,
        45.0,
    );
    assert!(
        near(s.aws_usd, 34.0)
            && near(s.aws_part(), 34.0)
            && near(s.pool(), 22.0 + 34.0)
            && a.enforce
            && a.cap_dm,
        "{s:?} {a:?}"
    );
    let (s, _, _) = apply_sample(
        Some(&s),
        at(2026, 12, 1, 0, 1),
        &smp(0.0, 0.0, Some(bill(99.0))),
        50.0,
        45.0,
    );
    assert!(s.pool() == 0.0 && s.aws_billed_usd == 0.0, "{s:?}");
}

#[test]
fn budget_tick_pauses_aws_sessions() {
    let _g = serial();
    let t = new_test_router();
    let r = t.arc();
    put_session(&r, "s1", "m1", "on fly", "started");
    put_session(&r, "s2", "i-aaa", "on aws", "started");
    link(&r, "m1", "s1");
    link(&r, "i-aaa", "s2");
    let fx = Effects::install(false);
    let fly = FakeFly {
        ms: vec![machine("m1", "started")],
        ..Default::default()
    };
    let mut aaa = inst("i-aaa", "eu-west-2", "t3.medium", "running");
    aaa.public_ip = "1.1.1.1".into();
    let mut bake = inst("i-bake", "eu-west-2", "t3.medium", "running");
    bake.name = "jarvis4-bake".into();
    let aws = FakeAws {
        inv: AwsInventory {
            instances: vec![aaa, bake],
            ..Default::default()
        },
        billed: 1.5,
        calls: AtomicUsize::new(0),
    };
    let t0 = at(2026, 11, 4, 0, 0);
    r.budget_tick(&fly, Some(&aws), t0, 50.0, 45.0)
        .expect("tick");
    let v = budget_view(&r).0;
    let ap = &v["aws"];
    assert!(
        aws.calls.load(Ordering::SeqCst) == 1
            && ap["billedUsd"] == 1.5
            && v["spentUsd"] == 1.5
            && ap["running"] == 2
            && v["running"] == 3
            && ap["account"] == "795109470764",
        "{v}"
    );
    let o = ap["other"].as_array().cloned().unwrap_or_default();
    assert!(
        o.len() == 1 && o[0]["id"] == "i-bake" && ap["owned"].as_array().map(Vec::len) == Some(0),
        "other {o:?}"
    );
    // Cost Explorer is read again only after AWS_BILLED_EVERY
    r.budget_tick(&fly, Some(&aws), t0.add(hours(1)), 50.0, 45.0)
        .expect("tick");
    assert_eq!(
        aws.calls.load(Ordering::SeqCst),
        1,
        "Cost Explorer asked every tick"
    );
    r.budget_tick(
        &fly,
        Some(&aws),
        t0.add(AWS_BILLED_EVERY + mins(1)),
        50.0,
        45.0,
    )
    .expect("tick");
    assert_eq!(
        aws.calls.load(Ordering::SeqCst),
        2,
        "Cost Explorer not asked again"
    );
    // over the cap: both runners' sessions pause, the stranger is named, the DM gives the split
    r.st.do_(|d| {
        if let Some(b) = d.budget.as_mut() {
            b.spent_usd = 49.9;
        }
    });
    let (a, _) = r
        .budget_tick(
            &fly,
            Some(&aws),
            t0.add(AWS_BILLED_EVERY + mins(2)),
            50.0,
            45.0,
        )
        .expect("tick");
    assert!(a.enforce && fx.paused() == "s1,s2", "{a:?} {}", fx.paused());
    let dms = fx.dms();
    assert!(
        dms.len() == 1
            && dms[0].contains("i-bake")
            && dms[0].contains("(Fly USD")
            && dms[0].contains("AWS USD"),
        "{dms:?}"
    );
}

static AWS_URL: Mutex<String> = Mutex::new(String::new());

fn fake_ec2(_: &str) -> String {
    format!("{}/", AWS_URL.lock().unwrap_or_else(|e| e.into_inner()))
}

/// the real reader against a fake AWS: every call signed, EC2's XML and Cost Explorer's JSON read, the account filter set
#[test]
fn aws_cost_api() {
    let _g = serial();
    let ce_body: Arc<Mutex<Value>> = Arc::default();
    let unsigned: Arc<Mutex<Vec<String>>> = Arc::default();
    let (cb, un) = (ce_body.clone(), unsigned.clone());
    let srv = TestServer::handler(move |w, req| {
        if !req
            .header("Authorization")
            .starts_with("AWS4-HMAC-SHA256 Credential=AKID/")
        {
            un.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(req.path.clone());
        }
        let b = req.read_body(1 << 20);
        if req.header("X-Amz-Target") == "AWSInsightsIndexService.GetCostAndUsage" {
            *cb.lock().unwrap_or_else(|e| e.into_inner()) =
                serde_json::from_slice(&b).unwrap_or_default();
            w.write_str(r#"{"ResultsByTime":[{"Total":{"UnblendedCost":{"Amount":"1.4201","Unit":"USD"}}}]}"#);
            return;
        }
        let q: BTreeMap<String, String> = url::form_urlencoded::parse(&b).into_owned().collect();
        let get = |k: &str| q.get(k).cloned().unwrap_or_default();
        match get("Action").as_str() {
            "GetCallerIdentity" => w.write_str("<GetCallerIdentityResponse><GetCallerIdentityResult><Account>795109470764</Account></GetCallerIdentityResult></GetCallerIdentityResponse>"),
            "DescribeInstances" => w.write_str("<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-1</instanceId><instanceType>t3.medium</instanceType><instanceState><name>running</name></instanceState><ipAddress>1.2.3.4</ipAddress><tagSet><item><key>jarvis4_source</key><value>source-x</value></item></tagSet></item></instancesSet></item></reservationSet></DescribeInstancesResponse>"),
            "DescribeVolumes" => {
                if get("NextToken").is_empty() {
                    w.write_str("<DescribeVolumesResponse><volumeSet><item><volumeId>vol-1</volumeId><size>30</size><status>in-use</status></item></volumeSet><nextToken>p2</nextToken></DescribeVolumesResponse>")
                } else {
                    w.write_str("<DescribeVolumesResponse><volumeSet><item><volumeId>vol-2</volumeId><size>10</size><status>available</status></item></volumeSet></DescribeVolumesResponse>")
                }
            }
            "DescribeSnapshots" => w.write_str("<DescribeSnapshotsResponse><snapshotSet><item><snapshotId>snap-1</snapshotId><volumeSize>20</volumeSize><status>completed</status><fullSnapshotSizeInBytes>19121831936</fullSnapshotSizeInBytes></item></snapshotSet></DescribeSnapshotsResponse>"),
            "DescribeAddresses" => w.write_str("<DescribeAddressesResponse><addressesSet/></DescribeAddressesResponse>"),
            _ => {
                w.write_header(400);
                0
            }
        };
    });
    *AWS_URL.lock().unwrap_or_else(|e| e.into_inner()) = srv.url.clone();
    let mut a = AwsCostApi::new("AKID", "secret");
    a.ec2 = fake_ec2;
    a.sts = format!("{}/", srv.url);
    a.ce = format!("{}/", srv.url);
    let (inv, err) = a.inventory(GoTime::now());
    assert!(err.is_none(), "{err:?}");
    let n = AWS_BUDGET_REGIONS.len();
    assert!(
        inv.instances.len() == n
            && inv.instances[0].source == "source-x"
            && inv.instances[0].public_ip == "1.2.3.4"
            && inv.volumes.len() == 2 * n
            && inv.snapshots.len() == n
            && inv.snapshots[0].bytes == 19121831936,
        "{inv:?}"
    );
    let (usd, acct) = a.billed("2026-11");
    assert!(
        usd.as_ref().ok() == Some(&1.4201) && acct == "795109470764",
        "{usd:?} {acct}"
    );
    let b = serde_json::to_string(&*ce_body.lock().unwrap_or_else(|e| e.into_inner()))
        .unwrap_or_default();
    assert!(
        b.contains(r#""LINKED_ACCOUNT","Values":["795109470764"]"#)
            || b.contains(r#""Values":["795109470764"]"#),
        "{b}"
    );
    assert!(
        b.contains(r#""Start":"2026-11-01""#) && b.contains(r#""End":"2026-12-01""#),
        "{b}"
    );
    assert!(
        unsigned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "unsigned calls"
    );
}

/// GitHub's runs, as the fake answers them
static RUNS: Mutex<BTreeMap<String, (String, String, String)>> = Mutex::new(BTreeMap::new());
static RUN_CALLS: Mutex<BTreeMap<String, usize>> = Mutex::new(BTreeMap::new());

fn fake_run(id: &str) -> Result<GhRun> {
    *RUN_CALLS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(id.into())
        .or_default() += 1;
    match RUNS.lock().unwrap_or_else(|e| e.into_inner()).get(id) {
        Some((name, status, conclusion)) => Ok(GhRun {
            name: name.clone(),
            status: status.clone(),
            conclusion: conclusion.clone(),
        }),
        None => Err(anyhow!("GitHub answered 404")),
    }
}

fn set_run(id: &str, status: &str, conclusion: &str) {
    RUNS.lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id.into(), ("aws".into(), status.into(), conclusion.into()));
}

/// an instance a workflow run owns is listed as that run's while the run is at work, and is a warning again (naming the
/// run) once the run is over; no tag, an unknown kind and a run GitHub can't show are warnings
#[test]
fn aws_instance_owners() {
    let _g = serial();
    let t = new_test_router();
    let r = t.arc();
    // run ids of this test's own: a finished run is remembered for the process
    set_run("907", "in_progress", "");
    set_run("908", "completed", "success");
    *GITHUB_RUN.lock().unwrap_or_else(|e| e.into_inner()) = Some(fake_run);
    struct Undo;
    impl Drop for Undo {
        fn drop(&mut self) {
            *GITHUB_RUN.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
    }
    let _undo = Undo;
    let tagged = |id: &str, state: &str, name: &str, owner: &str| {
        let mut i = inst(id, "eu-west-2", "t3.large", state);
        i.name = name.into();
        i.owner = owner.into();
        i
    };
    let aws = FakeAws {
        inv: AwsInventory {
            instances: vec![
                tagged("i-1", "running", "jarvis4-bake", "github-run:907"),
                tagged("i-2", "running", "jarvis4-bake-test", "github-run:907"),
                tagged("i-3", "stopped", "jarvis4-bake", "github-run:908"),
                tagged("i-4", "running", "by hand", ""),
                tagged("i-5", "running", "", "github-run:909"),
                tagged("i-6", "running", "", "someone"),
                tagged("i-7", "terminated", "", "github-run:910"),
            ],
            ..Default::default()
        },
        billed: 0.0,
        calls: AtomicUsize::new(0),
    };
    let rows = |now: GoTime| -> (BTreeMap<String, String>, BTreeMap<String, String>) {
        r.budget_tick(&FakeFly::default(), Some(&aws), now, 50.0, 45.0)
            .expect("tick");
        let ap = budget_view(&r).0["aws"].clone();
        let of = |k: &str| -> BTreeMap<String, String> {
            ap[k]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|o| {
                    (
                        o["id"].as_str().unwrap_or("").to_string(),
                        o["owner"].as_str().unwrap_or("").to_string(),
                    )
                })
                .collect()
        };
        (of("owned"), of("other"))
    };
    let calls = |id: &str| {
        RUN_CALLS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .copied()
            .unwrap_or(0)
    };
    let t0 = at(2026, 11, 12, 9, 0);
    let (owned, other) = rows(t0);
    assert!(
        owned.len() == 2
            && owned["i-1"] == "workflow aws, run 907 (in progress)"
            && owned["i-2"] == owned["i-1"],
        "owned {owned:?}"
    );
    assert!(
        other.len() == 4
            && other["i-3"] == "left by workflow aws, run 908 (success)"
            && other["i-4"].is_empty()
            && other["i-5"] == "workflow run 909 (not checked: GitHub answered 404)"
            && other["i-6"] == "owner tag someone (a kind the router doesn't know)",
        "other {other:?}"
    );
    assert!(calls("907") == 1 && calls("910") == 0, "calls");
    // the run ends and leaves its builder: a warning now; the finished run 908 is not asked for again
    set_run("907", "completed", "failure");
    let (owned, other) = rows(t0.add(mins(2)));
    assert!(
        owned.is_empty() && other["i-1"] == "left by workflow aws, run 907 (failure)",
        "owned {owned:?} other {other:?}"
    );
    assert!(
        calls("907") == 2 && calls("908") == 1,
        "calls 907 {} 908 {}",
        calls("907"),
        calls("908")
    );
}
