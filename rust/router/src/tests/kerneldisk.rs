//! kerneldisk_test.go: More disk on a kernel line (the whole kernel in-process)
use super::kernelline::{KRig, kdo, kernel_rig, kernel_session};
use crate::disk::DEFAULT_DISK;
use crate::testutil::*;
use jarvis_kernel::kerneltest::FakeMachine;

fn next(kr: &KRig, sid: &str, last: &mut String, what: &str) -> FakeMachine {
    let l = last.clone();
    wait_for(what, || {
        let s = kernel_session(kr, sid);
        !s.machine_id.is_empty()
            && s.machine_id != l
            && s.kernel.as_ref().is_some_and(|k| k.machine_cert.is_some())
    });
    *last = kernel_session(kr, sid).machine_id;
    kr.k.fly
        .machine(last)
        .unwrap_or_else(|| panic!("no machine {last}"))
}

/// More disk on a kernel line never asks the old core (it knows none of the kernel's machines: "machine … has no volume
/// of this core", and the session kept its disk): the size is the next spawn's. ✱ A running session moves to a new
/// machine on the bigger volume (pause and resume); ✱ a failed one whose machine was kept (it refused to start: its
/// restore ran out of disk) gets it at the Resume, which is what lets that restore fit.
#[test]
fn more_disk_on_a_kernel_line_is_the_next_spawns() {
    use sha2::Digest;
    let kr = kernel_rig();
    let sid = {
        let sid = kr
            .create_session(crate::flows::NewSession {
                label: "more disk".into(),
                harness: "claude".into(),
                ..Default::default()
            })
            .unwrap_or_else(|e| panic!("{e:#}"));
        let a = super::kernelline::approval_of(&kr, &sid);
        let sig = kr.k.phone.sign(super::kernelline::challenge(&a).as_bytes());
        kr.respond(&a.id, &sig).unwrap_or_else(|e| panic!("{e:#}"));
        sid
    };
    let h = kr.machine_handler();
    let tarball = make_tar(&kr.files);
    let want = hex::encode(sha2::Sha256::digest(&tarball));
    // booted, with its final snapshot here already (the fake machine takes none)
    let up = |m: &FakeMachine| {
        let (code, body) = kdo(&h, m, "POST", "/m/pull-secrets", "{}");
        assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
        let (code, body) = kdo(&h, m, "POST", "/m/status", r#"{"raw":""}"#);
        assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
        put_snap(&kr.t.r, &m.id, &tarball, &m.sig.sign(want.as_bytes()));
    };
    let volume = |m: &str| {
        kr.st.do_(|d| {
            d.started
                .get(m)
                .and_then(|st| st.volume.as_ref())
                .map(|v| v.size_gb)
                .unwrap_or_default()
        })
    };
    let core_asked = || {
        kr.core
            .calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|c| c == "/extend")
    };
    let mut last = String::new();
    let m1 = next(&kr, &sid, &mut last, "the machine");
    up(&m1);
    assert_eq!(volume(&m1.id), DEFAULT_DISK, "the first machine's volume");
    // running: a new machine on twice the disk
    let out = kr.more_disk(&sid).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        out["started"] == true && out["fromGb"] == DEFAULT_DISK && out["toGb"] == 2 * DEFAULT_DISK,
        "more disk on the running session: {out}"
    );
    let m2 = next(&kr, &sid, &mut last, "the machine on the bigger disk");
    assert!(
        volume(&m2.id) == 2 * DEFAULT_DISK && kernel_session(&kr, &sid).disk_gb == 2 * DEFAULT_DISK,
        "the second machine's volume: {} GB (the session's disk: {})",
        volume(&m2.id),
        kernel_session(&kr, &sid).disk_gb
    );
    assert_eq!(
        kr.k.fly
            .machine(&m1.id)
            .map(|m| m.state)
            .unwrap_or_default(),
        "destroyed",
        "the machine on the smaller disk is still there"
    );
    let (code, body) = kdo(&h, &m2, "GET", "/m/snapshot", "");
    assert!(
        code == 200 && body == tarball,
        "the second machine's snapshot: {code}"
    );
    wait_for("the More disk job's end", || !kr.busy(&sid));
    assert!(
        !core_asked(),
        "the old core was asked to extend a kernel machine's volume"
    );
    // failed with its machine kept (it refused to start): the bigger disk is the next start's
    let (code, body) = kdo(
        &h,
        &m2,
        "POST",
        "/m/boot-failed",
        r#"{"error":"snapshot: no space left on device"}"#,
    );
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let s = kernel_session(&kr, &sid);
    assert!(
        s.state == "failed" && s.machine_id == m2.id,
        "the session: {} on {:?}",
        s.state,
        s.machine_id
    );
    let out = kr.more_disk(&sid).unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        out["nextStart"] == true
            && out["toGb"] == 4 * DEFAULT_DISK
            && kernel_session(&kr, &sid).disk_gb == 4 * DEFAULT_DISK,
        "more disk on the failed session: {out} (the session's disk: {})",
        kernel_session(&kr, &sid).disk_gb
    );
    assert!(
        !core_asked()
            && kr
                .k
                .fly
                .machine(&m2.id)
                .is_some_and(|m| m.state != "destroyed"),
        "the old core was asked, or the kept machine went"
    );
    kr.resume(&sid, false).unwrap_or_else(|e| panic!("{e:#}"));
    let m3 = next(&kr, &sid, &mut last, "the third machine");
    assert_eq!(
        volume(&m3.id),
        4 * DEFAULT_DISK,
        "the third machine's volume"
    );
}
