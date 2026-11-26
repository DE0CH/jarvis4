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

mod apiproxy;
mod apptitle;
mod attachments;
mod autoaccept;
mod boot;
mod cert;
mod chanpipe;
mod claudelogin;
mod client;
mod crypto;
mod deliver;
mod deploykeys;
mod disk;
mod downgrade;
mod env;
mod gojson;
mod grants;
mod guard;
mod harnesses;
mod harnesslog;
mod https;
mod jarvis1import;
mod keeper;
mod kernelboot;
mod livesync;
mod memory;
mod messages;
mod oomguard;
mod outcomes;
mod output;
mod paths;
mod peer;
mod pressure;
mod putkey;
mod rcwatch;
mod restore;
mod rollback;
mod routerdial;
mod rt;
mod screen;
mod secrets;
mod session;
mod signrequest;
mod snapdirect;
mod snapformat;
mod snapshot;
mod snapstream;
mod stall;
mod status;
mod stores;
mod supervisor;
mod supervisorlog;
mod task;
mod teardown;
#[cfg(test)]
mod tests;
mod util;
mod volume;
mod vouch;
mod workers;

use anyhow::{Result, bail};

const USAGE: &str = "usage: jarvis-machine boot | init | stores [--json] | put-key <store> <key> [--explain <text>] < value | delete-key <store> <key> | add-store <name> | await-store <name> | downgrade --keep <store>… | --drop <store>… | --none | allow [<holder> <duration> | --remove <holder>] | sign-request <METHOD> <path> < body | supervisor";

/// Go's log package with the "[jarvis] " prefix: one line to stderr
#[macro_export]
macro_rules! logf {
    ($($a:tt)*) => {{ $crate::supervisorlog::log_line(&format!($($a)*)); }};
}

/// this machine's id as its runner knows it: the EC2 instance id the instance's unit read (AWS), else Fly's; "" when
/// this isn't a session machine (a test, a dev box)
pub fn machine_id() -> String {
    if on_aws() || on_fabric() {
        return crate::env::get("JARVIS2_MACHINE_ID");
    }
    crate::env::get("FLY_MACHINE_ID")
}

/// this machine's kernel object, "<runner>-<id>" (rust/doc)
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
    crate::env::get("JARVIS2_RUNNER") == "aws"
}

/// a gVisor sandbox on aviary's fabric (docs/PLAN-fabric.md)
pub fn on_fabric() -> bool {
    crate::env::get("JARVIS2_RUNNER") == "fabric"
}

fn run(args: &[String]) -> Result<()> {
    let Some(cmd) = args.get(1) else {
        bail!("{USAGE}");
    };
    let rest = &args[2.min(args.len())..];
    let one = |what: &str| -> Result<String> {
        match rest {
            [n] => Ok(n.clone()),
            _ => bail!("usage: jarvis-machine {what} <name>"),
        }
    };
    match cmd.as_str() {
        "boot" => keeper::keeper(),
        "prepare" => boot::prepare_cmd(), // keeper.rs starts it, as user claude
        "init" => boot::init_cmd(),
        "add-store" => boot::add_store(&one("add-store")?),
        // after `jarvis-request add-store`: no second ask, only the wait and the pull
        "await-store" => boot::await_store(&one("await-store")?),
        "stores" => stores::stores_cmd(rest),
        "put-key" => putkey::put_key_cmd(rest, false),
        "delete-key" => putkey::put_key_cmd(rest, true),
        "downgrade" => downgrade::downgrade(&downgrade::downgrade_args(rest)?),
        // supervisor.rs: supervisor-core and supervisor-normal, started (and restarted) by the keeper, each in a
        // session of its own
        "supervisor" => {
            let _ = nix::unistd::setsid();
            match rest.first().map(String::as_str) {
                Some("--core") if rest.len() == 1 => supervisor::supervise_core(),
                Some("--normal") if rest.len() == 1 => supervisor::supervise_normal(),
                _ => bail!(
                    "usage: jarvis-machine supervisor --core|--normal (the keeper starts them)"
                ),
            }
        }
        // session.rs: a command for the session: back under the OOM killer, as user claude, then exec
        "unprotected" => session::unprotected(rest),
        // session.rs: a signal to every process of user claude (kill -1 as claude)
        "signal-session" => session::signal_session_cmd(rest),
        "workers-hook" => {
            workers::workers_hook(); // a Claude Code hook; never fails
            Ok(())
        }
        "allow" => grants::allow_cmd(rest),
        // a request for a service outside Jarvis 4, signed with the machine key
        "sign-request" => signrequest::sign_request_cmd(rest),
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
