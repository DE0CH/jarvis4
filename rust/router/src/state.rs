//! The router's records: in memory under one lock and in Postgres (statedb.rs). Nothing here is trusted by anyone
//! else: the certs are core-signed and the snapshots machine-signed.

use crate::db::DB;
use crate::statestats::DoLoad;
use crate::types::*;
use jarvis_go::GoTime;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero_i64(n: &i64) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Session {
    /// stable: the first machine's id
    pub id: String,
    /// "" while paused
    #[serde(rename = "machineId")]
    pub machine_id: String,
    pub state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// archive.rs: why its snapshot isn't one this core vouches for
    #[serde(rename = "snapshotNote", skip_serializing_if = "String::is_empty")]
    pub snapshot_note: String,
    pub created: GoTime,
    #[serde(rename = "pausedAt", skip_serializing_if = "Option::is_none")]
    pub paused_at: Option<GoTime>,
    pub label: String,
    #[serde(skip)]
    pub prompt: String,
    pub model: String,
    #[serde(rename = "permissionMode")]
    pub permission_mode: String,
    pub size: String,
    /// regions.rs: where its machines start ("" = the router's default)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub region: String,
    /// awsrunner.rs: aws | fabric | fly ("" = DEFAULT_RUNNER)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub runner: String,
    /// awsrunner.rs: the next AWS machine's WireGuard, until it is up
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wg: Option<AwsWg>,
    /// fabricrunner.rs: its conversation at the fabric hermit, its machine's env
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fabric: Option<FabricLine>,
    pub harness: String,
    pub stores: Option<Vec<String>>,
    /// claudeaccounts.rs: the Claude account it uses, fixed when made
    #[serde(rename = "claudeAccount", skip_serializing_if = "String::is_empty")]
    pub claude_account: String,
    pub repos: String,
    /// content.rs: the content stores the line gets (signed in its config)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Vec<String>>,
    /// what the current line runs (ref@digest), pinned on resume
    pub image: String,
    /// the line's latest succession cert (its session_certs row)
    #[serde(skip)]
    pub cert: Option<Doc>,
    #[serde(rename = "createRequestId", skip_serializing_if = "String::is_empty")]
    pub request_id: String,
    #[serde(rename = "aiTitle", skip_serializing_if = "String::is_empty")]
    pub title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub status: String,
    /// Deyao's own rename (the transcript's custom title): beats Label
    #[serde(rename = "userTitle", skip_serializing_if = "String::is_empty")]
    pub user_title: String,
    /// the Claude app's own title (machine report): beats all
    #[serde(rename = "serverTitle", skip_serializing_if = "String::is_empty")]
    pub app_title: String,
    /// livesync.rs: the transcripts the machine last copied out
    #[serde(rename = "liveSync", skip_serializing_if = "Option::is_none")]
    pub live_sync: Option<LiveSync>,
    /// the session's channel (discord.rs), LOBSTER_CHANNEL on the machine
    #[serde(rename = "discordChannel", skip_serializing_if = "String::is_empty")]
    pub discord_channel: String,
    /// reported status, auto-pause/one-shot settings (autopilot.rs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live: Option<Liveness>,
    /// archivetar.rs: fixed by the destroy that archives it
    #[serde(rename = "archiveFile", skip_serializing_if = "String::is_empty")]
    pub archive_file: String,
    /// restore.rs: the record this session restores
    #[serde(rename = "restoreFrom", skip_serializing_if = "String::is_empty")]
    pub restore_from: String,
    /// restore.rs: that record's signer cert
    #[serde(rename = "restoreCert", skip_serializing_if = "Option::is_none")]
    pub restore_cert: Option<Doc>,
    /// restore.rs: the master key's claim of the core that signed RestoreCert (an archive from an earlier core)
    #[serde(rename = "restoreCoreCert", skip_serializing_if = "Option::is_none")]
    pub restore_core_cert: Option<MasterCert>,
    /// jarvis1import.rs: the paused Jarvis 1 session this line imports
    #[serde(rename = "importFrom", skip_serializing_if = "String::is_empty")]
    pub import_from: String,
    /// jarvis1import.rs: that import manifest's sha256 (in the cert's restore)
    #[serde(rename = "importSha256", skip_serializing_if = "String::is_empty")]
    pub import_sha: String,
    /// sessionops.rs: API proxy, env patch, rollback, attachments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ops: Option<SessionOps>,
    /// the machine that has reported status: it got past boot (lastSnapshot)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub booted: String,
    /// the image the harness check found its Claude never came up on (autopilot.rs)
    #[serde(rename = "stuckImage", skip_serializing_if = "String::is_empty")]
    pub stuck_image: String,
    /// what a pause or destroy is waiting on, in plain words (the app shows it)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub waiting: String,
    /// the store the machine waits on at boot (its secrets pull got 423 "store X is locked")
    #[serde(rename = "lockedStore", skip_serializing_if = "String::is_empty")]
    pub locked_store: String,
    /// corechange.rs: its line is an earlier core's; destroyed once paused
    #[serde(rename = "oldCore", skip_serializing_if = "is_false")]
    pub old_core: bool,
    /// legacy.rs: its line was taken over from an earlier core, whose carried secrets don't open here
    #[serde(rename = "carryLost", skip_serializing_if = "is_false")]
    pub carry_lost: bool,
    /// snapsafe.rs: the final snapshot failed and the machine (no volume) is kept
    #[serde(rename = "snapshotFailed", skip_serializing_if = "String::is_empty")]
    pub snapshot_failed: String,
    /// snapsafe.rs: the line's last machine left no snapshot: Resume refuses
    #[serde(rename = "noSnapshot", skip_serializing_if = "String::is_empty")]
    pub no_snapshot: String,
    /// disk.rs: the volume size the next machine gets (0 = the core's default)
    #[serde(rename = "diskGb", skip_serializing_if = "is_zero_i64")]
    pub disk_gb: i64,
    /// kernelline.rs: the line is the kernel's (not the old core's)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<KernelLine>,
    /// lostmachine.rs: its machine stopped or went away without Jarvis doing it (Resume brings it back)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lost: Option<LostMachine>,
    /// failures.rs: when it last became failed (Error says why); None while it isn't failed
    #[serde(rename = "failedAt", skip_serializing_if = "Option::is_none")]
    pub failed_at: Option<GoTime>,
    /// a refused resume DMed once (not kept)
    #[serde(skip)]
    pub no_snapshot_dmed: bool,
    /// vouch.rs: a task line's instance + parameters while its first challenge is made (not kept)
    #[serde(skip)]
    pub task_config: Option<TaskConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Approval {
    pub id: String,
    /// new-session | resume-upgrade | add-store
    pub kind: String,
    pub created: GoTime,
    pub session: String,
    pub machine: String,
    pub label: String,
    pub challenge: Option<Doc>,
    /// an add-store's challenges made before its current one (flows.rs rebase_add_stores, newest first)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub earlier: Vec<Doc>,
    #[serde(rename = "burnCert", skip_serializing_if = "Option::is_none")]
    pub burn_cert: Option<Doc>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
    /// inbox.rs: who asked for it and the call it made
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub explanation: String,
    /// CI's signature over "jarvis2-session-image <image>" for the image the challenge names
    #[serde(rename = "imageSig", skip_serializing_if = "String::is_empty")]
    pub image_sig: String,
    /// batches.rs: the batch it was filed in
    #[serde(skip_serializing_if = "String::is_empty")]
    pub batch: String,
    /// flows.rs start_again: a failed new line's start asked again
    #[serde(skip_serializing_if = "is_false")]
    pub again: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Record {
    #[serde(flatten)]
    pub session: Session,
    #[serde(rename = "destroyedAt")]
    pub destroyed_at: GoTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive: Option<ArchiveInfo>,
    #[serde(rename = "archiveError", skip_serializing_if = "String::is_empty")]
    pub archive_error: String,
    #[serde(rename = "liveKept", skip_serializing_if = "String::is_empty")]
    pub live_kept: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub restored: Vec<RestoreMark>,
}

/// what the core reported at start (the machine's keys authenticate its requests here)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Started {
    pub id: String,
    pub image: String,
    #[serde(rename = "encryptionKey")]
    pub encryption_key: String,
    #[serde(rename = "signingKey")]
    pub signing_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume: Option<Volume>,
    #[serde(rename = "kernelPred", skip_serializing_if = "String::is_empty")]
    pub kernel_pred: String,
    #[serde(rename = "kernelCert", skip_serializing_if = "Option::is_none")]
    pub kernel_cert: Option<Doc>,
    #[serde(rename = "kernelVolumeLeft", skip_serializing_if = "String::is_empty")]
    pub kernel_volume_left: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wg: Option<AwsWg>,
}

/// The records. Each field is a table (a map: one row per key; records: one row per position) or a settings row
/// named after its JSON key (statedb.rs, `persisted_fields!`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Persisted {
    pub sessions: BTreeMap<String, Session>,
    pub approvals: BTreeMap<String, Approval>,
    pub records: Vec<Record>,
    pub started: BTreeMap<String, Started>,
    /// machine id → its latest succession cert
    pub certs: BTreeMap<String, Doc>,
    /// machine id → session id
    pub machines: BTreeMap<String, String>,
    #[serde(rename = "sessionCerts")]
    pub sess_certs: BTreeMap<String, Doc>,
    /// id → a phone-signed grant or standing rule (grants.rs)
    pub grants: BTreeMap<String, StoredGrant>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub schedules: BTreeMap<String, Schedule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<BudgetState>,
    #[serde(rename = "bbBudget", skip_serializing_if = "Option::is_none")]
    pub bb_budget: Option<BBBudgetState>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub devices: BTreeMap<String, Device>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub uploads: BTreeMap<String, Upload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tasks: Option<TaskState>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub inbox: BTreeMap<String, InboxRequest>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub batches: BTreeMap<String, Batch>,
    #[serde(rename = "callResults", skip_serializing_if = "BTreeMap::is_empty")]
    pub call_results: BTreeMap<String, CallResult>,
    #[serde(rename = "coreKey", skip_serializing_if = "String::is_empty")]
    pub core_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leases: Option<LeaseState>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub outcomes: BTreeMap<String, Vec<Outcome>>,
    #[serde(rename = "activeCore", skip_serializing_if = "String::is_empty")]
    pub active_core: String,
    #[serde(rename = "kernelRoot", skip_serializing_if = "Option::is_none")]
    pub kernel_root: Option<GvSigned>,
    #[serde(rename = "kernelCopy", skip_serializing_if = "String::is_empty")]
    pub kernel_copy: String,
    #[serde(rename = "kernelRootKey", skip_serializing_if = "String::is_empty")]
    pub kernel_root_key: String,
    #[serde(rename = "kernelRosterPending", skip_serializing_if = "Option::is_none")]
    pub kernel_roster_pending: Option<RosterFiling>,
    #[serde(rename = "kernelRoster", skip_serializing_if = "Option::is_none")]
    pub kernel_roster: Option<RosterCurrent>,
    #[serde(rename = "kernelRosterNext", skip_serializing_if = "Option::is_none")]
    pub kernel_roster_next: Option<RosterCurrent>,
    #[serde(rename = "kernelFlip", skip_serializing_if = "Option::is_none")]
    pub kernel_flip: Option<KernelFlip>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub messages: BTreeMap<String, PendingMessage>,
    #[serde(rename = "messageRules", skip_serializing_if = "BTreeMap::is_empty")]
    pub message_rules: BTreeMap<String, MessageRule>,
}

/// State: the router's records, in memory under one lock and in Postgres (statedb.rs)
pub struct State {
    pub(crate) inner: Mutex<StateInner>,
    /// the volume: what is still a file there (docs/STATE.md)
    pub dir: std::path::PathBuf,
    pub(crate) sdb: Option<crate::statedb::StateDB>,
    /// sealed.rs: the router's secrets in the database
    pub seal: Option<crate::sealed::Sealer>,
    /// failures.rs: told (outside the lock) of each session that has just become failed, with its reason
    pub on_failed: Mutex<Option<Arc<dyn Fn(&str, &str) + Send + Sync>>>,
}

pub(crate) struct StateInner {
    pub data: Persisted,
    /// what the database holds, as last written or read
    pub written: crate::statedb::Rows,
    /// the state_version that copy is of (-1: none yet, reload)
    pub ver: i64,
    /// statestats.rs: what the Do's of the last minute cost
    pub load: DoLoad,
}

/// a Do just gave up (jobs.rs: a job ending now isn't marked done: another replica carries it on)
pub static STATE_WRITE_FAILING: AtomicBool = AtomicBool::new(false);

/// what a Do panics with when it can't write a change (the HTTP handlers answer it as a 503)
#[derive(Debug, Clone)]
pub struct StateWriteError(pub String);

impl std::fmt::Display for StateWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the records couldn't be written: {}", self.0)
    }
}

/// the waits before each attempt of a Do
const DO_BACKOFF_MS: [u64; 4] = [0, 200, 1000, 3000];

impl State {
    /// a State with no database (tests' frozen stand-ins)
    pub fn memory(d: Persisted) -> State {
        let mut d = d;
        crate::statedb::init_maps(&mut d);
        State {
            inner: Mutex::new(StateInner {
                data: d,
                written: Default::default(),
                ver: 0,
                load: DoLoad::default(),
            }),
            dir: std::env::temp_dir(),
            sdb: None,
            seal: None,
            on_failed: Mutex::new(None),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, StateInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn db(&self) -> Option<&DB> {
        self.sdb.as_ref().map(|s| &s.db)
    }

    /// Do runs fn on the records under the lock of every replica (the state_version row, taken FOR UPDATE: Do's are
    /// serialised across the replicas) and writes what it changed in the same transaction; a replica whose copy is
    /// older than the database's reloads it first. A transaction the database refuses leaves it as it was: Do
    /// reloads and runs fn again (DO_BACKOFF_MS.len() times, backing off). A change it still can't write never
    /// vanishes quietly: Do panics with a StateWriteError, which the HTTP handlers answer as a 503 (state_write_guard)
    /// and which ends this replica otherwise.
    #[track_caller]
    pub fn do_<R>(&self, mut f: impl FnMut(&mut Persisted) -> R) -> R {
        let who = caller();
        let mut failed = vec![];
        let r = self.do_locked(&who, |d| {
            let r = f(d);
            failed = crate::failures::stamp_failures(d, GoTime::now());
            r
        });
        let hook = self
            .on_failed
            .lock()
            .ok()
            .and_then(|g| g.clone());
        if let Some(h) = hook {
            for (id, why) in failed {
                let h = h.clone();
                std::thread::spawn(move || h(&id, &why));
            }
        }
        r
    }

    /// Read runs fn on the records as the database has them, for a fn that only looks: nothing is marshalled or
    /// written and the other replicas' Do's aren't waited for. The copy is brought up to the database's version
    /// first (catch_up, in a snapshot); when that can't be done here it is a Do.
    #[track_caller]
    pub fn read<R>(&self, mut f: impl FnMut(&Persisted) -> R) -> R {
        let who = caller();
        let mut out = None;
        if self.read_inner(&who, |d| out = Some(f(d))) {
            if let Some(r) = out {
                return r;
            }
        }
        self.do_locked(&who, |d| f(d))
    }

    fn read_inner(&self, who: &str, f: impl FnOnce(&Persisted)) -> bool {
        let asked = std::time::Instant::now();
        let mut g = self.lock();
        let Some(sdb) = &self.sdb else {
            f(&g.data);
            return true;
        };
        if g.ver < 0 {
            return false;
        }
        let got = std::time::Instant::now();
        let r = sdb.read_tx(&mut g);
        match r {
            Ok(true) => {
                f(&g.data);
                g.load.reads += 1;
                g.load.done(who, asked, got);
                true
            }
            Ok(false) => false,
            Err(_) => {
                g.ver = -1; // a catch-up cut short: the copy is read whole again by the Do this becomes
                false
            }
        }
    }

    fn do_locked<R>(&self, who: &str, mut f: impl FnMut(&mut Persisted) -> R) -> R {
        let asked = std::time::Instant::now();
        let mut g = self.lock();
        let got = std::time::Instant::now();
        let Some(sdb) = &self.sdb else {
            let r = f(&mut g.data);
            g.load.done(who, asked, got);
            return r;
        };
        let mut last = String::new();
        for (i, wait) in DO_BACKOFF_MS.iter().enumerate() {
            if sdb.db.closed() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(*wait));
            let mut out = None;
            match sdb.do_once(&mut g, &mut |d| out = Some(f(d))) {
                Ok(()) => {
                    STATE_WRITE_FAILING.store(false, Ordering::SeqCst);
                    g.load.done(who, asked, got);
                    if let Some(r) = out {
                        return r;
                    }
                }
                Err(e) => {
                    last = format!("{e:#}");
                    crate::logf!(
                        "state: a change wasn't written (attempt {} of {}; the records are read again): {last}",
                        i + 1,
                        DO_BACKOFF_MS.len()
                    );
                }
            }
        }
        if sdb.db.closed() {
            // the database was closed: the process (or a test) is ending; the change runs on the copy only
            let r = f(&mut g.data);
            return r;
        }
        STATE_WRITE_FAILING.store(true, Ordering::SeqCst);
        drop(g);
        std::panic::panic_any(StateWriteError(last))
    }

    /// the last failed write and since when (None when the database has every record)
    pub fn store_error(&self) -> Option<(String, GoTime)> {
        self.sdb.as_ref().and_then(|s| s.last_error())
    }
}

/// the line that called State::do_/read ("flows.rs:707")
#[track_caller]
fn caller() -> String {
    let l = std::panic::Location::caller();
    let f = std::path::Path::new(l.file())
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!("{f}:{}", l.line())
}
