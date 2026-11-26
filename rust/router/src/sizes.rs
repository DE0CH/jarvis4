//! Machine sizes (the same rules are in core/fly.go, rust/machine/src/deliver.rs and rust/kernel/src/spawner/fly.rs; the test
//! below checks the machine's).

use std::sync::Mutex;
use std::time::{Duration, Instant};

// ---- machine sizes ----

/// The sizes: small (2 GB), medium (4 GB), large (8 GB), then every doubling past large, named by its memory ("16gb",
/// "32gb", …). Upgrade moves a session one step up, and there is no last step: a guest Fly can't make is Fly's to
/// refuse, with its own error.
pub const NAMED_SIZES: &[(&str, i64)] = &[("small", 2), ("medium", 4), ("large", 8)];

pub fn named_size(s: &str) -> i64 {
    NAMED_SIZES
        .iter()
        .find(|(n, _)| *n == s)
        .map(|(_, g)| *g)
        .unwrap_or(0)
}

/// the size's memory in GB; 0 = not a size (the 1<<20 bound only keeps memory_mb an ordinary int)
pub fn size_mem_gb(size: &str) -> i64 {
    let gb = named_size(size);
    if gb != 0 {
        return gb;
    }
    let Ok(n) = size.strip_suffix("gb").unwrap_or(size).parse::<i64>() else {
        return 0;
    };
    if !(16..=1 << 20).contains(&n) || n & (n - 1) != 0 || format!("{n}gb") != size {
        return 0;
    }
    n
}

/// the size's Fly guest → (cpu kind, cpus, memory MB). Fly takes at most 2 GB per shared CPU and 8 GB per performance
/// CPU (fly.io/docs/machines/guides-examples/machine-sizing). The named three have one shared CPU per GB; 16 GB is
/// the most a shared guest holds (8 CPUs × 2 GB); past it the guest is performance, with large's 8 CPUs or, once the
/// memory needs more (8 GB each), memory/8 CPUs.
pub fn size_guest(size: &str) -> (&'static str, i64, i64) {
    let gb = size_mem_gb(size);
    match gb {
        0 => ("", 0, 0),
        1..=8 => ("shared", gb, gb * 1024),
        9..=16 => ("shared", 8, gb * 1024),
        _ => ("performance", 8.max(gb / 8), gb * 1024),
    }
}

/// the size Upgrade moves to, twice the memory (a session with no size runs medium)
pub fn next_size(size: &str) -> String {
    let mut gb = size_mem_gb(size);
    if gb == 0 {
        gb = named_size("medium");
    }
    for (name, n) in NAMED_SIZES {
        if *n == 2 * gb {
            return name.to_string();
        }
    }
    format!("{}gb", 2 * gb)
}

/// "large (8 GB)", "16 GB"
pub fn size_text(size: &str) -> String {
    let gb = named_size(size);
    if gb != 0 {
        return format!("{size} ({gb} GB)");
    }
    format!("{} GB", size_mem_gb(size))
}

// ---- end of the machine sizes block ----

/// the size's guest as the apps show it, "8×shared · 16 GB" ("" = not a size)
pub fn size_label(size: &str) -> String {
    let (kind, cpus, mb) = size_guest(size);
    if kind.is_empty() {
        return String::new();
    }
    format!("{cpus}×{kind} · {} GB", mb / 1024)
}

// ---- what the running core starts ---------------------------------------------------------------------------
//
// Sizes past large need a core that reports sizeLadder in /identity (core/core.go Identity); a core before it starts
// only small, medium and large. So an Upgrade past large is offered (the memory DM, memAlert.nextSize) only while the
// running core says it takes it. What the core said is kept here (one core per router process), noted by every
// /identity read (core.rs key, e.g. each GET /api/state).

static CORE_SIZES: Mutex<(bool, Option<Instant>)> = Mutex::new((false, None));

/// how long an /identity answer about sizes is used before refresh_core_sizes asks again
const CORE_SIZE_TTL: Duration = Duration::from_secs(60);

pub fn note_core_sizes(ladder: bool) {
    *CORE_SIZES.lock().unwrap_or_else(|e| e.into_inner()) = (ladder, Some(Instant::now()));
}

/// the running core starts this size, by its last /identity (no call: safe under the state lock). The named three
/// always; past large only when the core said so (not known yet = no).
pub fn core_takes_size(size: &str) -> bool {
    if size_mem_gb(size) == 0 {
        return false;
    }
    if named_size(size) != 0 {
        return true;
    }
    CORE_SIZES.lock().unwrap_or_else(|e| e.into_inner()).0
}

impl crate::router::Router {
    /// asks the core's /identity when the last answer is older than CORE_SIZE_TTL (outside the state lock)
    pub fn refresh_core_sizes(&self) {
        let fresh = CORE_SIZES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .1
            .is_some_and(|t| t.elapsed() < CORE_SIZE_TTL);
        if !fresh {
            let _ = self.core.key(); // notes sizeLadder
        }
    }
}

/// the size Upgrade moves to, "" when the running core can't start it (nothing to offer)
pub fn upgrade_target(size: &str) -> String {
    let next = next_size(size);
    if core_takes_size(&next) {
        next
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(size_guest("small"), ("shared", 2, 2048));
        assert_eq!(size_guest("16gb"), ("shared", 8, 16384));
        assert_eq!(size_guest("128gb"), ("performance", 16, 131072));
        assert_eq!(size_guest("12gb"), ("", 0, 0));
        assert_eq!(next_size(""), "large");
        assert_eq!(next_size("large"), "16gb");
        assert_eq!(size_text("16gb"), "16 GB");
        assert_eq!(size_label("16gb"), "8×shared · 16 GB");
    }

    /// the machine (rust/machine/src/deliver.rs) has the same named sizes, the doubling past large and the text
    #[test]
    fn the_machines_sizes_match() {
        let rs = include_str!("../../machine/src/deliver.rs");
        for need in [
            r#"("small", 2), ("medium", 4), ("large", 8)"#,
            "(16..=1 << 20).contains(&n) || n & (n - 1) != 0",
            r#"format!("{size} ({gb} GB)")"#,
            r#"format!("{} GB", size_mem_gb(size))"#,
        ] {
            assert!(
                rs.contains(need),
                "rust/machine/src/deliver.rs's sizes differ from the router's (no {need})"
            );
        }
    }
}
