//! The teardown (Deyao, 2026-10-21: "sigterm sigint etc should trigger a clean but also priority driven teardown. As in
//! upload the most important items first quickly. Transcript tail is the most important, artifacts is less."): a stop
//! signal reaches the keeper, which kills supervisor-normal and sends supervisor-core SIGUSR1. It uploads, most
//! important first, each step on its own:
//!
//!  1. the transcripts that changed since their last copy (the live sync's), the newest first, then the subagents';
//!  2. the final snapshot, streamed in the snapshot's order (the transcripts and ~/.claude.json first, the workspace and
//!     the artifacts last) and committed with the machine's one signature.
//!
//! A machine whose final snapshot the router already has (a pause: the snapshot first, then the core's stop) skips both.

use crate::client::Client;
use crate::snapshot::{FROZEN, booted};
use crate::{logf, supervisorlog};
use std::sync::atomic::Ordering;
use std::time::Instant;

pub fn teardown(c: &Client) {
    let start = Instant::now();
    if crate::snapstream::snapshot_committed() {
        logf!("teardown: the final snapshot is already with the router; nothing more to upload");
        let _ = supervisorlog::push_log_once(c);
        return;
    }
    if booted() && !FROZEN.load(Ordering::SeqCst) {
        let l = crate::livesync::live_syncer_for(c);
        let n = l.pass(&crate::livesync::main_transcripts());
        logf!(
            "teardown 1/2: {n} changed transcripts sent in {}",
            crate::keeper::dur_text(start.elapsed())
        );
        let m = l.pass(&crate::livesync::subagent_transcripts());
        if m > 0 {
            logf!("teardown 1/2: {m} changed subagent transcripts sent");
        }
        let _ = supervisorlog::push_log_once(c);
    }
    logf!(
        "teardown 2/2: the final snapshot (the transcripts and ~/.claude.json first, the workspace and the artifacts last)"
    );
    crate::supervisor::run_command(c, "snapshot");
    logf!(
        "teardown done in {}",
        crate::keeper::dur_text(start.elapsed())
    );
    let _ = supervisorlog::push_log_once(c);
    crate::output::push_outputs_once(c);
}
