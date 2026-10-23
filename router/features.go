package main

// Features outside the lifecycle (Jarvis 1 parity, docs/PARITY.md). Each lives in its own file, registers its
// routes in registerFeatures and its background loop in startFeatures, and reads its own settings from the
// environment (secrets come from k8s/control/secrets/router.enc.yaml via envFrom). They act on sessions only through
// the router's own flows and through grants (grants.go); none talks to the core directly, except machines.go's Destroy
// of a machine with no session (the core's kill, as a pause makes it).

import (
	"encoding/json"
	"log"
	"net/http"
)

type (
	appRoute     func(pattern string, fn http.HandlerFunc)
	machineRoute func(pattern string, fn func(w http.ResponseWriter, req *http.Request, machine string, body []byte))
	// publicRoute: a route on the public listener with the feature's own Access check (not requireDeyao)
	publicRoute func(pattern string, h http.Handler)
)

// registerFeatures: called once from buildHandlers
func (r *Router) registerFeatures(app appRoute, m machineRoute, public publicRoute) {
	r.registerAutopilot(app, m)
	r.registerMemory(app, m)                // memory.go
	r.registerDisk(app, m)                  // disk.go: disk reports, the low-disk DM, More disk
	r.registerHarnesses(app)                // harness.go: /api/models
	r.registerRemote(app, m, public)        // remote.go: remote pages, /api/remotes, tunnel proofs
	r.registerLeases(app, m, public)        // leases.go: shared-device leases (before sessionapi.go's /m/api/ catch-all)
	r.registerWatches(app, m)               // watches.go: conditional wakeups
	r.registerSessionAPI(app, m)            // sessionapi.go: wakeups, crons, /m/api
	r.registerJarvis1Import(app, m, public) // jarvis1import.go: paused Jarvis 1 sessions as new lines
	r.registerArchive(app, m)               // archive.go, restore.go (budget.go needs no routes: /api/state via stateHooks)
	r.registerSessionOps(app, m)            // sessionops.go, uploads.go, repos.go
	r.registerTasks(app, m)                 // tasks.go: task instances (one-shot session lines), runs, schedules
	r.registerInbox(app, m, public)         // inbox.go: requests waiting for the phone (the app's Inbox)
	r.registerPeerMessages(m)               // peermsg.go: one session telling another, through Jarvis
	r.registerOutcomes(m)                   // outcomes.go: a session reads what became of its requests
	r.registerMessages(app)                 // messages.go: messages held for Deyao to deliver or deny, his per-kind rules
	r.registerVouch(app, m)                 // vouch.go: /m/config, /m/restore-cert, deliveries, the input log
	r.registerMachines(app)                 // machines.go: every Fly machine of the app; Destroy for one with no session
	r.registerContent(app, m)               // content.go: content stores (Storage Box folders) for the app and the sessions
	r.registerClaudeLogin(app, m, public)   // claudelogin.go: the Claude login, its refresh, Re-login, the usage quota
	r.registerDevices(app, public)          // devices.go: pairing Deyao's OpenClaw/Paseo apps, /api/remotes, Start
	r.registerSupervisorLog(m)              // supervisorlog.go: the machines' supervisor logs
	r.registerSessionEvents(app)            // sessionevents.go: a session's one event stream (supervisor + lifecycle)
	r.registerLifecycle(app)                // lifecycle.go: each boot/pause/resume/destroy's log, the harness pause
}

// startFeatures: called once from main after the router is built
func (r *Router) startFeatures() {
	r.endCutOff() // drain.go: what a crash cut off becomes a failed or paused session, before any loop looks
	r.lcCutOff()  // lifecycle.go: an operation log a restart left open is closed as cut off
	r.startDiscord()
	r.startAutopilot()
	go r.scheduleLoop()   // schedule.go: wakeups, crons, resume prompts
	go r.leaseLoop()      // leases.go: expire silent holders, wake promoted ones
	go r.watchLoop()      // watches.go: run due checks on the watch runner, deliver met / given-up watches
	go r.archiveLoop()    // archive.go: restore files tidied
	go r.budgetLoop()     // budget.go: the Fly budget cap
	go r.bbBudgetLoop()   // bbbudget.go: the Browserbase spend DM
	go r.uploadsLoop()    // uploads.go: stale attachments
	go r.inboxLoop()      // inbox.go: requests and approvals go after 10 min
	go r.outcomeLoop()    // outcomes.go: tell a session what became of its Inbox requests
	go r.messageLoop()    // messages.go: approved messages delivered, pending ones lapse
	go r.tasksLoop()      // tasks.go: daily schedules, runs, pausing finished task lines
	go r.inputLogLoop()   // vouch.go: the core's input log onto the volume
	go r.coreChangeLoop() // corechange.go: a new core → the earlier core's paused sessions are destroyed
	go r.loginLoop()      // claudelogin.go: refresh the Claude login (own) or mirror Jarvis 1's (follow)
	go r.volSweepLoop()   // volsweep.go: delete leftover session volumes (DECISIONS 195)
	go r.lostLoop()       // lostmachine.go: machines that stopped without Jarvis doing it
}

// stateHooks: add fields to GET /api/state
var stateHooks []func(r *Router, out map[string]any)

// DM: a message to Deyao's Discord DM (filled in by discord.go); without a bot token it only logs
var dmHook func(text string)

func (r *Router) DM(text string) {
	if dmHook != nil {
		dmHook(text)
		return
	}
	log.Printf("[dm] %s", text)
}

// DeliverCanned: a text built into the session image ("continue", the watchdog's nudge), as a delivery the core
// attests: the router picks when, never what
func (r *Router) DeliverCanned(session string, d Delivery, text string) error {
	return r.deliverVouched(session, d)
}

// envHooks: each adds to the env a machine starts with (start and resume; flows.go machineEnv). Not secret:
// the env is unsigned.
var envHooks []func(r *Router, s *Session, env map[string]string)

// onDestroy: each runs once a session's machine is killed and its line burned, before it becomes a record
// (flows.go Destroy), in order; they must not fail the destroy
var onDestroy []func(r *Router, s Session)

// coreSetUp: the core answers and was set up (Reset or Recover): its state names a master key
func (r *Router) coreSetUp() bool {
	status, b, err := r.core.Raw("GET", "/identity", nil)
	if err != nil || status != 200 {
		return false
	}
	var id struct {
		State struct {
			Payload string `json:"payload"`
		} `json:"state"`
	}
	var st struct {
		Master string `json:"master"`
	}
	if json.Unmarshal(b, &id) != nil || json.Unmarshal([]byte(id.State.Payload), &st) != nil {
		return false
	}
	return st.Master != ""
}
