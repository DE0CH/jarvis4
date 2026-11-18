//! The router process's own memory, for /setup/status (`process`): sizing the control box (Deyao, 2026-10-15: measure
//! the router's real memory before sizing the box) and seeing a leak, on a box with no other way in. VmRSS and VmHWM
//! (peak), RssAnon (the heap and the threads' stacks) and the thread count, from /proc/self/status.

use serde_json::{Map, Value, json};
use std::sync::LazyLock;
use std::time::Instant;

static PROC_START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// PROC_START from the process's start (main calls it first)
pub fn mark_start() {
    LazyLock::force(&PROC_START);
}

pub fn process_status() -> Map<String, Value> {
    let mut v = Map::new();
    v.insert("uptimeS".into(), json!(PROC_START.elapsed().as_secs() as i64));
    let text = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for l in text.lines() {
        let (k, val, ok) = jarvis_go::fmt::cut(l, ":");
        let name = match k {
            "VmRSS" => "rssMB",
            "VmHWM" => "peakRssMB",
            "RssAnon" => "heapMB",
            "Threads" => "threads",
            _ => continue,
        };
        if !ok {
            continue;
        }
        let n: i64 = val.trim().trim_end_matches(" kB").parse().unwrap_or(0);
        v.insert(name.into(), json!(if name == "threads" { n } else { n >> 10 }));
    }
    v
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_status_reads_proc() {
        let v = super::process_status();
        assert!(v.contains_key("rssMB") && v.contains_key("peakRssMB"));
        assert!(v["threads"].as_i64().unwrap_or(0) >= 1);
    }
}
