//! Where the machine keeps its files. Everything of Jarvis 4's own lives under `/run/jarvis` (a tmpfs, owned by user
//! claude); tests move that root with [`set_dir`].

use std::path::PathBuf;
use std::sync::RwLock;

static DIR: RwLock<Option<PathBuf>> = RwLock::new(None);

/// The machine's own directory (`/run/jarvis`)
pub fn dir() -> PathBuf {
    DIR.read()
        .ok()
        .and_then(|d| d.clone())
        .unwrap_or_else(|| PathBuf::from("/run/jarvis"))
}

/// Tests: move the machine's directory
#[cfg(test)]
pub fn set_dir(p: &std::path::Path) {
    if let Ok(mut d) = DIR.write() {
        *d = Some(p.to_path_buf());
    }
}

macro_rules! under {
    ($($(#[$m:meta])* $name:ident = $rel:expr;)*) => {
        $( $(#[$m])* pub fn $name() -> PathBuf { dir().join($rel) } )*
    };
}

under! {
    /// public halves, printed by init for the core (through Fly exec)
    keys_path = "keys.json";
    /// the core's key, from the machine's Fly config (the core set it)
    core_key_path = "core-key";
    /// init ran (Fly), or the keeper announced the keys (AWS)
    go_path = "init-requested";
    cert_path = "cert.json";
    /// written once the boot is done (cert, snapshot, secrets, repos): the harness starts next
    booted_path = "booted";
    /// the router URL + this machine's id, for later commands
    client_path = "client.json";
    /// the private halves, never leave the machine
    priv_path = "private.json";
    restore_tmp = "restore.tar.gz";
    final_snapshot = "final-snapshot.tar.gz";
    final_snapshot_sig = "final-snapshot.sig";
    claude_login_on = "claude-login";
    live_sent_path = "live-sent.json";
    kernel_trust_path = "kernel.json";
    ssh_agent_sock = "ssh-agent.sock";
    outcomes_dir = "outcomes";
    output_log_path = "output.log";
    journal_log_path = "journal.log";
    secrets_sock = "secrets.sock";
    carried_run = "carried";
    harness_paused_path = "harness-paused";
    supervisor_log_path = "supervisor.log";
    /// how far the push got (bytes), across worker restarts
    supervisor_log_sent = "supervisor.log.sent";
    workers_sock = "workers.sock";
    workers_state = "workers.json";
    vouched_path = "vouched.json";
}

/// root's (0755): what only the keeper writes
pub const KEEPER_DIR: &str = "/run/jarvis-keeper";
/// an AWS instance's serial console (GetConsoleOutput)
pub const CONSOLE_PATH: &str = "/dev/ttyS0";
/// a fabric sandbox's console: its first process's stdout, which sandboxd keeps
pub const FABRIC_CONSOLE_PATH: &str = "/proc/1/fd/1";
/// the console line's mark (kernel/spawner/aws.go)
pub const KEYS_MARK: &str = "JARVIS2-KEYS ";
pub const CLAUDE_HOME: &str = "/home/claude";

/// $HOME (Go's os.UserHomeDir)
pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// where the predecessor's snapshot lands while it is checked (a machine with a volume: on the volume)
pub static PREDECESSOR_TMP: RwLock<Option<PathBuf>> = RwLock::new(None);

pub fn predecessor_tmp() -> PathBuf {
    PREDECESSOR_TMP
        .read()
        .ok()
        .and_then(|p| p.clone())
        .unwrap_or_else(|| dir().join("predecessor.tar.gz"))
}
