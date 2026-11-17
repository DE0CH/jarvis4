//! jarvis-machine: the session machine's side of Jarvis 4 (docs/DESIGN.md, "Machine side"), the Rust port of
//! machine/. It is the image's entry point and its fixed init entry point:
//!
//!   jarvis-machine boot       ENTRYPOINT, as root: the keeper (keeper.rs), Fly's main child for the machine's whole
//!                             life. It starts the boot steps (prepare), supervisor-core and supervisor-normal and
//!                             then the harness, each as its own child, restarts them when they die, and turns Fly's
//!                             stop signal into the priority teardown.
//!   jarvis-machine prepare    the boot steps, as user claude (started by the keeper).
//!   jarvis-machine init       what the core runs through Fly exec (no arguments): asks boot to go on.
//!   jarvis-machine supervisor --core|--normal
//!   jarvis-machine stores [--json]
//!   jarvis-machine add-store <name>
//!
//! It trusts only what it can check: the core's public key arrives through Fly exec (written by the core at start),
//! the cert and the secrets are core-signed, and the predecessor's snapshot is signed by the predecessor's own key,
//! taken from the predecessor's core-signed cert. The router only relays.

#![allow(dead_code)] // while the port is under way: removed once every Go file is ported

mod client;
mod crypto;
mod gojson;
mod paths;
mod routerdial;
mod rt;
mod snapformat;
mod util;

use anyhow::{Result, bail};

const USAGE: &str = "usage: jarvis-machine boot | init | stores [--json] | put-key <store> <key> [--explain <text>] < value | delete-key <store> <key> | add-store <name> | await-store <name> | downgrade --keep <store>… | --drop <store>… | --none | allow [<holder> <duration> | --remove <holder>] | sign-request <METHOD> <path> < body | supervisor";

/// Go's log package with the "[jarvis] " prefix: one line to stderr
#[macro_export]
macro_rules! logf {
    ($($a:tt)*) => {{ eprintln!("[jarvis] {}", format!($($a)*)); }};
}

/// this machine's id as its runner knows it: the EC2 instance id the instance's unit read (AWS), else Fly's; "" when
/// this isn't a session machine (a test, a dev box)
pub fn machine_id() -> String {
    if on_aws() || on_fabric() {
        return std::env::var("JARVIS2_MACHINE_ID").unwrap_or_default();
    }
    std::env::var("FLY_MACHINE_ID").unwrap_or_default()
}

/// this machine's kernel object, "<runner>-<id>" (kernel/doc)
pub fn machine_object(id: &str) -> String {
    if on_aws() {
        return format!("aws-{id}");
    }
    if on_fabric() {
        return format!("fabric-{id}");
    }
    format!("fly-{id}")
}

/// started by the spawner's AWS runner (the instance's unit sets JARVIS2_RUNNER=aws)
pub fn on_aws() -> bool {
    std::env::var("JARVIS2_RUNNER").as_deref() == Ok("aws")
}

/// a gVisor sandbox on aviary's fabric (docs/PLAN-fabric.md)
pub fn on_fabric() -> bool {
    std::env::var("JARVIS2_RUNNER").as_deref() == Ok("fabric")
}

fn run(args: &[String]) -> Result<()> {
    let Some(cmd) = args.get(1) else {
        bail!("{USAGE}");
    };
    #[allow(clippy::match_single_binding)] // the commands arrive as their files are ported
    match cmd.as_str() {
        c => bail!("unknown command {c}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Err(e) = run(&args) {
        logf!("{e:#}");
        std::process::exit(1);
    }
}
