//! Features outside the lifecycle (Jarvis 1 parity, docs/PARITY.md). Each lives in its own file, registers its routes
//! in register_features and its background loop in start_features, and reads its own settings from the environment
//! (secrets come from the router's Secret via envFrom). They act on sessions only through the router's own flows and
//! through grants (grants.rs); none talks to the core directly, except machines.rs's Destroy of a machine with no
//! session (the core's kill, as a pause makes it).
//!
//! The Go router's init() hooks are the lists below, in the order Go ran them (its files' order, then Discord's at
//! start).

use crate::http::Registrar;
use crate::router::Router;
use crate::state::Session;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

/// each adds to the env a machine starts with (start and resume; flows.rs machine_env). Not secret: the env is
/// unsigned.
pub type EnvHook = fn(&Arc<Router>, &Session, &mut BTreeMap<String, String>);
/// each adds fields to GET /api/state
pub type StateHook = fn(&Arc<Router>, &mut Map<String, Value>);
/// each runs once a session's machine is killed and its line burned, before it becomes a record (flows.rs destroy),
/// in order; they must not fail the destroy
pub type DestroyHook = fn(&Arc<Router>, &Session);

pub fn env_hooks() -> Vec<EnvHook> {
    vec![
        crate::autopilot::live_env,
        crate::livesync::livesync_env,
        crate::restore::restore_env,
        crate::sessionapi::sessionapi_env,
        crate::sessionops::ops_env,
        crate::tasks::task_env,
        crate::discord::discord_env,
    ]
}

pub fn state_hooks() -> Vec<StateHook> {
    vec![
        crate::bbbudget::bb_state_hook,
        crate::budget::budget_state_hook,
        crate::inbox::inbox_state_hook,
        crate::kernelhealth::kernel_health_state_hook,
        crate::leases::leases_state_hook,
        crate::messages::messages_state_hook,
        crate::nextcore::nextcore_state_hook,
        crate::repos::repos_state_hook,
        crate::sessionops::ops_state_hook,
    ]
}

pub fn on_destroy() -> Vec<DestroyHook> {
    vec![
        crate::inbox::inbox_on_destroy,
        crate::messages::messages_on_destroy,
        crate::outcomes::outcomes_on_destroy,
        crate::screens::screens_on_destroy,
        crate::uploads::uploads_on_destroy,
        crate::discord::discord_destroy,
    ]
}

/// called once while the handlers are built
pub fn register_features(reg: &mut Registrar) {
    crate::autopilot::register_autopilot(reg);
    crate::memory::register_memory(reg); // the memory reports and their DMs
    crate::disk::register_disk(reg); // disk reports, the low-disk DM, More disk
    crate::bootfailed::register_boot_failed(reg); // a machine that refuses to start fails its session
    crate::harness::register_harnesses(reg); // /api/models
    crate::remote::register_remote(reg); // remote pages, /api/remotes, tunnel proofs
    crate::leases::register_leases(reg); // shared-device leases (before sessionapi.rs's /m/api/ catch-all)
    crate::watches::register_watches(reg); // conditional wakeups
    crate::sessionapi::register_session_api(reg); // wakeups, crons, /m/api
    crate::jarvis1import::register_jarvis1_import(reg); // paused Jarvis 1 sessions as new lines
    crate::archive::register_archive(reg); // archive.rs, restore.rs (budget.rs needs no routes: /api/state)
    crate::sessionops::register_session_ops(reg); // sessionops.rs, uploads.rs, repos.rs
    crate::tasks::register_tasks(reg); // task instances (one-shot session lines), runs, schedules
    crate::inbox::register_inbox(reg); // requests waiting for the phone (the app's Inbox)
    crate::peermsg::register_peer_messages(reg); // one session telling another, through Jarvis
    crate::outcomes::register_outcomes(reg); // a session reads what became of its requests
    crate::messages::register_messages(reg); // messages held for Deyao to deliver or deny, his per-kind rules
    crate::vouch::register_vouch(reg); // /m/config, /m/restore-cert, deliveries, the input log
    crate::runners::register_runners(reg); // Hetzner runners, each its session's (before the /m/api/ catch-all)
    crate::machines::register_machines(reg); // every Fly machine of the app; Destroy for one with no session
    crate::content::register_content(reg); // content stores (Storage Box folders) for the app and the sessions
    crate::claudelogin::register_claude_login(reg); // the Claude login, its refresh, Re-login, the usage quota
    crate::devices::register_devices(reg); // pairing Deyao's OpenClaw/Paseo apps, /api/remotes, Start
    crate::supervisorlog::register_supervisor_log(reg); // the machines' supervisor logs
    crate::awslogs::register_machine_output(reg); // the AWS machines' output, to Grafana
    crate::sessionevents::register_session_events(reg); // a session's one event stream (supervisor + lifecycle)
    crate::lifecycle::register_lifecycle(reg); // each boot/pause/resume/destroy's log, the harness pause
}

fn go(r: &Arc<Router>, f: fn(&Arc<Router>)) {
    let r = r.clone();
    std::thread::spawn(move || f(&r));
}

impl Router {
    /// called once from main after the router is built
    pub fn start_features(self: &Arc<Self>) {
        self.end_cut_off(); // drain.rs: what a crash cut off becomes a failed or paused session, before any loop looks
        self.lc_cut_off(); // lifecycle.rs: an operation log a restart left open is closed as cut off
        self.start_discord();
        self.start_autopilot();
        self.start_live_push(); // livepush.rs: the live dashboard's Jarvis 4 panel
        go(self, |r| r.schedule_loop()); // schedule.rs: wakeups, crons, resume prompts
        go(self, |r| r.lease_loop()); // leases.rs: expire silent holders, wake promoted ones
        go(self, |r| r.watch_loop()); // watches.rs: run due checks on the watch runner, deliver met / given-up ones
        go(self, |r| r.archive_loop()); // archive.rs: restore files tidied
        go(self, |r| r.budget_loop()); // budget.rs: the Fly budget cap
        go(self, |r| r.bb_budget_loop()); // bbbudget.rs: the Browserbase spend DM
        go(self, |r| r.uploads_loop()); // uploads.rs: stale attachments
        go(self, |r| r.inbox_loop()); // inbox.rs: requests and approvals go after 10 min
        go(self, |r| r.outcome_loop()); // outcomes.rs: tell a session what became of its Inbox requests
        go(self, |r| r.message_loop()); // messages.rs: approved messages delivered, pending ones lapse
        go(self, |r| r.tasks_loop()); // tasks.rs: daily schedules, runs, pausing finished task lines
        go(self, |r| r.input_log_loop()); // vouch.rs: the core's input log onto the volume
        go(self, |r| r.core_change_loop()); // corechange.rs: a new core → the earlier core's paused sessions go
        go(self, |r| r.login_loop()); // claudelogin.rs: refresh the Claude logins
        go(self, |r| r.vol_sweep_loop()); // volsweep.rs: delete leftover session volumes (DECISIONS 195)
        go(self, |r| r.aws_list_loop()); // awsrunner.rs: the AWS machines, for the gateways' peers
        go(self, |r| r.aws_log_loop()); // awslogs.rs: the AWS machines' log lines to the shipper
        go(self, |r| r.console_loop()); // awslogs.rs: the AWS instances' serial consoles (the leader)
        go(self, |r| r.lost_loop()); // lostmachine.rs: machines that stopped without Jarvis doing it
        go(self, |r| r.never_booted_loop()); // neverbooted.rs: a machine that never boots fails its session
        go(self, |r| r.kernel_volumes_loop()); // kernelline.rs: a killed kernel machine's volume left, killed again
    }

    /// a text built into the session image ("continue"), as a delivery the core attests: the router picks when, never
    /// what
    pub fn deliver_canned(&self, session: &str, d: crate::types::Delivery, _text: &str) -> anyhow::Result<()> {
        self.arc().deliver_vouched(session, d)
    }

    /// the core answers and was set up (Reset or Recover): its state names a master key
    pub fn core_set_up(&self) -> bool {
        let Ok((200, b)) = self.core.raw("GET", "/identity", None) else { return false };
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct StateDoc {
            payload: String,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Id {
            state: StateDoc,
        }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct St {
            master: String,
        }
        let Ok(id) = jarvis_go::unmarshal::<Id>(&b) else { return false };
        jarvis_go::unmarshal::<St>(id.state.payload.as_bytes()).is_ok_and(|st| !st.master.is_empty())
    }
}
