//! snaphelp_test.go, procstat_test.go (importSnapshotFiles is dead code in Go, never called: not ported)
use crate::testutil::{make_tar, new_test_router, put_snap, snap_bytes, tfile};

/// a committed snapshot and its carry; a carried-over snapshot shares its predecessor's object until both are dropped
#[test]
fn snapshots_in_the_bucket() {
    let t = new_test_router();
    let tarball = make_tar(&[tfile("workspace/a.txt", "a", 0)]);
    put_snap(&t, "m1", &tarball, "sig1");
    t.save_carry("m1", "blob");
    let s = t.snap("m1").expect("m1's snapshot");
    assert!(
        s.state == "committed"
            && s.sig == "sig1"
            && snap_bytes(&t, "m1").as_deref() == Some(&tarball[..])
            && t.snap("m0").is_none(),
        "{s:?}"
    );
    assert!(
        s.facts.is_some() && t.read_carry("m1") == "blob",
        "facts {:?} carry {:?}",
        s.facts,
        t.read_carry("m1")
    );
    t.snap_carry("m2", "m1", &s.sha256, "sig2").expect("carry");
    t.snap_drop("m1");
    assert_eq!(
        snap_bytes(&t, "m2").as_deref(),
        Some(&tarball[..]),
        "dropping the predecessor took the carried object with it"
    );
    t.snap_drop("m2");
    let left = t.objects.list("snapshots/").unwrap_or_default();
    assert!(left.is_empty(), "left: {left:?}");
}

#[test]
fn process_status() {
    let v = crate::procstat::process_status();
    assert!(
        v.contains_key("rssMB")
            && v.contains_key("peakRssMB")
            && v["threads"].as_i64().unwrap_or(0) >= 1,
        "process status: {v:?}"
    );
}
