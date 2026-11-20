//! The fly-preload runner's golden volumes (router/preload.go; docs/PLAN-one-image.md, kernel/spawner/preload.go).
//! The router asks the kernel's preloader to step the golden volume of the image fly-preload sessions run, in each
//! region they start in, until it is ready: a deploy that moves PRELOAD_SESSION_IMAGE begins the next ones, so making
//! them is part of the deploy with no credentials of its own. The preloader keeps a region's newest three.
//!
//!   PRELOAD_SESSION_IMAGE  the image fly-preload sessions run (ghcr.io/de0ch/jarvis4-session@sha256:…); unset: nothing runs
//!   PRELOAD_REGIONS        the regions they start in, comma-separated (default: the router's region)
//!   PRELOAD_DISK_GB        every session volume forked from a golden (default 20)

use crate::router::Router;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_DISK: i64 = 20;
const EVERY: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreloadConfig {
    pub image: String,
    pub regions: Vec<String>,
    pub disk_gb: i64,
}

/// the configuration read with `get` (the environment); None when PRELOAD_SESSION_IMAGE is unset
pub fn preload_config(get: impl Fn(&str) -> String, region: &str) -> Option<PreloadConfig> {
    let image = get("PRELOAD_SESSION_IMAGE").trim().to_string();
    if image.is_empty() {
        return None;
    }
    let mut regions: Vec<String> = get("PRELOAD_REGIONS")
        .split(',')
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();
    if regions.is_empty() && !region.is_empty() {
        regions.push(region.to_string());
    }
    let disk_gb = get("PRELOAD_DISK_GB")
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_DISK);
    Some(PreloadConfig {
        image,
        regions,
        disk_gb,
    })
}

/// the preloader's POST /golden bodies, one per region
pub fn preload_steps(c: &PreloadConfig) -> Vec<Value> {
    c.regions
        .iter()
        .map(|r| json!({"region": r, "image": c.image, "diskGb": c.disk_gb}))
        .collect()
}

/// the preloader's answer (a document it signed over the golden volume) in a few words
pub fn golden_state(b: &[u8]) -> String {
    let payload = serde_json::from_slice::<Value>(b)
        .ok()
        .and_then(|d| d["payload"].as_str().map(str::to_string))
        .and_then(|p| serde_json::from_str::<Value>(&p).ok());
    let Some(g) = payload else {
        return "an answer that isn't the preloader's".into();
    };
    let w = |k: &str| g[k].as_str().unwrap_or_default().to_string();
    format!("{} {} {}", w("state"), w("volume"), w("error"))
        .trim()
        .to_string()
}

impl Router {
    /// the golden volumes stepped every minute (the leader only); what each answers is logged when it changes
    pub fn preload_loop(self: &Arc<Self>) {
        let mut last: BTreeMap<String, String> = BTreeMap::new();
        loop {
            crate::leaderlease::await_lead();
            let c = preload_config(|k| std::env::var(k).unwrap_or_default(), &self.cfg.region);
            if let (Some(c), Some(k)) = (c, &self.kernel) {
                for input in preload_steps(&c) {
                    let region = input["region"].as_str().unwrap_or_default().to_string();
                    let state = match k.call("preloader", "POST", "/golden", Some(&input)) {
                        Err(e) => format!("error: {e:#}"),
                        Ok(b) => golden_state(&b),
                    };
                    if last.get(&region) != Some(&state) {
                        crate::logf!(
                            "preload: the golden volume of {} in {region}: {state}",
                            c.image
                        );
                        last.insert(region, state);
                    }
                }
            }
            std::thread::sleep(EVERY);
        }
    }
}
