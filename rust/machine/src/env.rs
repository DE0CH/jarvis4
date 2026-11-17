//! The process environment, read through one place: tests set values over it (Rust forbids changing the real
//! environment once threads run, and this crate forbids `unsafe`).

use std::collections::BTreeMap;
use std::sync::RwLock;

static OVERLAY: RwLock<BTreeMap<String, Option<String>>> = RwLock::new(BTreeMap::new());

/// the variable's value ("" when unset), as Go's os.Getenv
pub fn get(k: &str) -> String {
    if let Ok(o) = OVERLAY.read()
        && let Some(v) = o.get(k)
    {
        return v.clone().unwrap_or_default();
    }
    std::env::var(k).unwrap_or_default()
}

/// every variable with the overlay over it, as Go's os.Environ
pub fn vars() -> Vec<(String, String)> {
    let mut m: BTreeMap<String, String> = std::env::vars_os()
        .map(|(k, v)| (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned()))
        .collect();
    if let Ok(o) = OVERLAY.read() {
        for (k, v) in o.iter() {
            match v {
                Some(v) => {
                    m.insert(k.clone(), v.clone());
                }
                None => {
                    m.remove(k);
                }
            }
        }
    }
    m.into_iter().collect()
}

/// tests: set (Some) or unset (None) a variable for this process's readers
#[cfg(test)]
pub fn set(k: &str, v: Option<&str>) {
    if let Ok(mut o) = OVERLAY.write() {
        o.insert(k.to_string(), v.map(String::from));
    }
}

/// tests: the overlay emptied
#[cfg(test)]
pub fn reset() {
    if let Ok(mut o) = OVERLAY.write() {
        o.clear();
    }
}

/// the overlay onto a command's environment (a child sees what this process's readers see)
pub fn apply(cmd: &mut std::process::Command) {
    if let Ok(o) = OVERLAY.read() {
        for (k, v) in o.iter() {
            match v {
                Some(v) => {
                    cmd.env(k, v);
                }
                None => {
                    cmd.env_remove(k);
                }
            }
        }
    }
}
