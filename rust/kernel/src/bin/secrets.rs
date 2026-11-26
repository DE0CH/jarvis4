//! Secrets' process (secrets/): empty until the app claims it (Reset or Recover); a wipe ends the process. KERNEL_ROOT:
//! the root key's public half (keys/root.pub), which its roster is checked against. KERNEL_MINTER_URL: the minter,
//! where an approved deploy-key call goes; secrets itself reaches nothing outside the cluster.
use jarvis_kernel::serve::{fatal, log};
use std::sync::Arc;

fn main() {
    let root = std::env::var("KERNEL_ROOT").unwrap_or_default();
    if root.is_empty() {
        fatal("KERNEL_ROOT (the root key's public half, keys/root.pub) isn't set");
    }
    let minter =
        jarvis_kernel::minter::Client::new(&std::env::var("KERNEL_MINTER_URL").unwrap_or_default());
    let c = Arc::new(jarvis_kernel::secrets::Secrets::new(
        &root,
        Some(Box::new(minter)),
    ));
    c.set_exit(Box::new(|| {
        std::thread::sleep(std::time::Duration::from_millis(500));
        log("wiped: exiting");
        std::process::exit(0);
    }));
    let addr = std::env::var("KERNEL_ADDR")
        .ok()
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| ":8080".into());
    log("secrets up, empty");
    let rt = tokio::runtime::Runtime::new().unwrap_or_else(|e| fatal(&e.to_string()));
    let stop = tokio_util::sync::CancellationToken::new();
    if let Err(e) = rt.block_on(jarvis_nethttp::serve(
        &addr,
        jarvis_kernel::secrets::http::handler(c),
        stop,
    )) {
        fatal(&format!("{e:#}"));
    }
}
