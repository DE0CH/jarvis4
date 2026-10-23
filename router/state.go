package main

// The router's own records, in one JSON file on the box's volume (written atomically). Nothing here is
// trusted by anyone else: the certs are core-signed and the snapshots machine-signed.

import (
	"context"
	"log"
	"sync/atomic"

	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/jackc/pgx/v5"

	"sync"
	"time"
)

type Session struct {
	ID        string `json:"id"`        // stable: the first machine's id
	MachineID string `json:"machineId"` // "" while paused
	State     string `json:"state"`
	Error     string `json:"error,omitempty"`
	// archive.go: why its snapshot isn't one this core vouches for (a destroy killed the machine without naming it,
	// the core refusing the claim: a machine from an earlier core). Archived as is; a restore of it is refused.
	SnapshotNote   string     `json:"snapshotNote,omitempty"`
	Created        time.Time  `json:"created"`
	PausedAt       *time.Time `json:"pausedAt,omitempty"`
	Label          string     `json:"label"`
	Prompt         string     `json:"-"`
	Model          string     `json:"model"`
	PermissionMode string     `json:"permissionMode"`
	Size           string     `json:"size"`
	Harness        string     `json:"harness"`
	Stores         []string   `json:"stores"`
	ClaudeAccount  string     `json:"claudeAccount,omitempty"` // claudeaccounts.go: the Claude account it uses, fixed when made
	Repos          string     `json:"repos"`
	Content        []string   `json:"content,omitempty"` // content.go: the content stores the line gets (signed in its config)
	Image          string     `json:"image"`             // what the current line runs (ref@digest), pinned on resume
	Cert           *Doc       `json:"-"`                 // the line's latest succession cert
	RequestID      string     `json:"createRequestId,omitempty"`
	Title          string     `json:"aiTitle,omitempty"`
	Status         string     `json:"status,omitempty"`
	UserTitle      string     `json:"userTitle,omitempty"`      // Deyao's own rename (the transcript's custom title): beats Label
	AppTitle       string     `json:"serverTitle,omitempty"`    // the Claude app's own title (machine report; Jarvis 1's serverTitle): beats all
	LiveSync       *LiveSync  `json:"liveSync,omitempty"`       // livesync.go: the transcripts the machine last copied out
	DiscordChannel string     `json:"discordChannel,omitempty"` // the session's channel (discord.go), LOBSTER_CHANNEL on the machine
	Live           *Liveness  `json:"live,omitempty"`           // reported status, auto-pause/one-shot settings (autopilot.go)
	ArchiveFile    string     `json:"archiveFile,omitempty"`    // archivetar.go: fixed by the destroy that archives it
	RestoreFrom    string     `json:"restoreFrom,omitempty"`    // restore.go: the record this session restores
	RestoreCert    *Doc       `json:"restoreCert,omitempty"`    // restore.go: that record's signer cert
	// restore.go: the master key's claim of the core that signed RestoreCert (an archive from an earlier core)
	RestoreCoreCert *MasterCert `json:"restoreCoreCert,omitempty"`
	ImportFrom      string      `json:"importFrom,omitempty"`   // jarvis1import.go: the paused Jarvis 1 session this line imports
	ImportSha       string      `json:"importSha256,omitempty"` // jarvis1import.go: that import manifest's sha256 (in the cert's restore)
	Ops             *SessionOps `json:"ops,omitempty"`          // sessionops.go: API proxy, env patch, rollback, attachments
	Booted          string      `json:"booted,omitempty"`       // the machine that has reported status: it got past boot (lastSnapshot)
	StuckImage      string      `json:"stuckImage,omitempty"`   // the image the harness check found its Claude never came up on (autopilot.go): a resume goes on the newest
	Waiting         string      `json:"waiting,omitempty"`      // what a pause or destroy is waiting on, in plain words (the app shows it)
	LockedStore     string      `json:"lockedStore,omitempty"`  // the store the machine waits on at boot (its secrets pull got 423 "store X is locked")
	OldCore         bool        `json:"oldCore,omitempty"`      // corechange.go: its line is an earlier core's; destroyed once paused
	// legacy.go: its line was taken over from an earlier core, whose carried secrets don't open here: the first pull
	// that waits on a store files the unlock request itself
	CarryLost bool `json:"carryLost,omitempty"`
	// snapsafe.go: what the machine's final snapshot left behind
	SnapshotFailed string      `json:"snapshotFailed,omitempty"` // the final snapshot failed and the machine (no volume) is kept
	NoSnapshot     string      `json:"noSnapshot,omitempty"`     // the line's last machine left no snapshot: Resume refuses
	DiskGB         int         `json:"diskGb,omitempty"`         // disk.go: the volume size the next machine gets (0 = the core's default)
	Kernel         *KernelLine `json:"kernel,omitempty"`         // kernelline.go: the line is the kernel's (not the old core's)
	// lostmachine.go: its machine stopped or went away without Jarvis doing it (Resume brings it back)
	Lost *LostMachine `json:"lost,omitempty"`
	// failures.go: when it last became failed (Error says why); nil while it isn't failed
	FailedAt       *time.Time  `json:"failedAt,omitempty"`
	noSnapshotDMed bool        // a refused resume DMed once
	taskConfig     *TaskConfig // vouch.go: a task line's instance + parameters while its first challenge is made (not kept)
}

type Approval struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"` // new-session | resume-upgrade | add-store
	Created   time.Time `json:"created"`
	Session   string    `json:"session"`
	Machine   string    `json:"machine"`
	Label     string    `json:"label"`
	Challenge *Doc      `json:"challenge"`
	// an add-store's challenges made before its current one (flows.go rebaseAddStores, newest first): a phone that
	// signed one of them while its page was open is still answered
	Earlier  []*Doc            `json:"earlier,omitempty"`
	BurnCert *Doc              `json:"burnCert,omitempty"`
	Options  map[string]string `json:"options,omitempty"`
	// inbox.go: who asked for it (from the caller's credential) and the call it made, and the caller's own words
	Origin      *Origin `json:"origin,omitempty"`
	Explanation string  `json:"explanation,omitempty"`
	// ImageSig: CI's signature over "jarvis2-session-image <image>" for the image the challenge names, when that is the
	// current CI build (SESSION_IMAGE_SIG, made by images.yml with the key of keys/ci.pub): the phone checks it
	ImageSig string `json:"imageSig,omitempty"`
	// batches.go: the batch it was filed in (reviewed with the batch's others under one Face ID)
	Batch string `json:"batch,omitempty"`
	// flows.go startAgain: a failed new line's start asked again; Deny leaves the session failed instead of removing it
	Again bool `json:"again,omitempty"`
}

type Record struct {
	Session
	DestroyedAt  time.Time     `json:"destroyedAt"`
	Archive      *ArchiveInfo  `json:"archive,omitempty"`      // archive.go
	ArchiveError string        `json:"archiveError,omitempty"` // a forced destroy whose archive failed
	LiveKept     string        `json:"liveKept,omitempty"`     // livearchive.go: live copies kept because the archive doesn't hold them
	Restored     []RestoreMark `json:"restored,omitempty"`
}

// Started: what the core reported at start (the machine's keys authenticate its requests here)
type Started struct {
	ID            string  `json:"id"`
	Image         string  `json:"image"`
	EncryptionKey string  `json:"encryptionKey"`
	SigningKey    string  `json:"signingKey"`
	Volume        *Volume `json:"volume,omitempty"`     // snapsafe.go: the machine's Fly volume (a core with volumes)
	KernelPred    string  `json:"kernelPred,omitempty"` // kernelline.go: the machine whose snapshot this one restores
	KernelCert    *Doc    `json:"kernelCert,omitempty"` // kernelline.go: the spawner's cert naming it (what its archive keeps)
}

type persisted struct {
	Sessions  map[string]*Session     `json:"sessions"`
	Approvals map[string]*Approval    `json:"approvals"`
	Records   []*Record               `json:"records"`
	Started   map[string]*Started     `json:"started"`
	Certs     map[string]*Doc         `json:"certs"`    // machine id → its latest succession cert
	Machines  map[string]string       `json:"machines"` // machine id → session id
	SessCerts map[string]*Doc         `json:"sessionCerts"`
	Grants    map[string]*StoredGrant `json:"grants"` // id → a phone-signed grant or standing rule (grants.go)

	Schedules   map[string]*Schedule     `json:"schedules,omitempty"`   // session id → wakeups, crons, resume prompt (schedule.go)
	Budget      *BudgetState             `json:"budget,omitempty"`      // budget.go: this month's Fly spend estimate
	BBBudget    *BBBudgetState           `json:"bbBudget,omitempty"`    // bbbudget.go: this month's Browserbase DM flags
	Devices     map[string]*Device       `json:"devices,omitempty"`     // devices.go: Deyao's paired OpenClaw/Paseo apps
	Uploads     map[string]*Upload       `json:"uploads,omitempty"`     // uploads.go: first-prompt attachments staged on the volume
	Tasks       *TaskState               `json:"tasks,omitempty"`       // tasks.go: task instances (session lines), runs, daily schedules
	Inbox       map[string]*InboxRequest `json:"inbox,omitempty"`       // inbox.go: requests waiting for the phone
	Batches     map[string]*Batch        `json:"batches,omitempty"`     // batches.go: requests and approvals filed together, one review
	CallResults map[string]*CallResult   `json:"callResults,omitempty"` // apicalls.go: approved/denied API calls, for their caller
	CoreKey     string                   `json:"coreKey,omitempty"`     // corechange.go: the signing key of the core the sessions' lines belong to
	Leases      *LeaseState              `json:"leases,omitempty"`      // leases.go: shared-device leases (holder + queue per device)
	Outcomes    map[string][]*Outcome    `json:"outcomes,omitempty"`    // outcomes.go: session id → decisions on its Inbox filings, until delivered
	ActiveCore  string                   `json:"activeCore,omitempty"`  // nextcore.go: the core URL that serves after a flip
	KernelRoot  *gv.Signed               `json:"kernelRoot,omitempty"`  // kernelline.go: the root key's ⊤ on the sink
	// kernel.go: the colour of the kernel's secrets that serves ("" = blue)
	KernelSecrets string `json:"kernelSecrets,omitempty"`
	// roster.go: the app's root key (registered, for keys/root.pub), the setup session's roster waiting for it, and
	// the root key's roster the components hold
	KernelRootKey       string         `json:"kernelRootKey,omitempty"`
	KernelRosterPending *RosterFiling  `json:"kernelRosterPending,omitempty"`
	KernelRoster        *RosterCurrent `json:"kernelRoster,omitempty"`
	// messages.go: messages held for Deyao to deliver or deny, and his per-kind rules
	Messages     map[string]*PendingMessage `json:"messages,omitempty"`
	MessageRules map[string]*MessageRule    `json:"messageRules,omitempty"`
}

// State: the router's records, in memory under one lock and in Postgres (statedb.go)
type State struct {
	mu   sync.Mutex
	dir  string // the volume: what is still a file there (docs/STATE.md)
	data persisted
	sdb  *stateDB
	seal *Sealer // sealed.go: the router's secrets in the database
	// failures.go: told (outside the lock) of each session that has just become failed, with its reason
	onFailed func(session, reason string)
}

// Do runs fn on the records under the lock of every replica (the state_version row, taken FOR UPDATE: Do's are
// serialised across the replicas) and writes what it changed in the same transaction; a replica whose copy is older
// than the database's reloads it first. A transaction the database refuses leaves it as it was: Do reloads and runs fn
// again (doAttempts times, backing off). A change it still can't write never vanishes quietly: Do panics with a
// stateWriteError, which the HTTP handlers answer as a 503 to their caller (stateWriteGuard) and which ends this
// replica otherwise (a job in flight is then carried on by another replica: its holder marks it neither done nor
// failed, jobs.go jobUnlock).
func (s *State) Do(fn func(d *persisted)) {
	var failed [][2]string
	s.doLocked(func(d *persisted) {
		fn(d)
		failed = stampFailures(d, time.Now().UTC()) // failures.go: a failed session says why and since when
	})
	if hook := s.onFailed; hook != nil {
		for _, f := range failed {
			go hook(f[0], f[1])
		}
	}
}

func (s *State) doLocked(fn func(d *persisted)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sdb == nil {
		fn(&s.data) // a State that was never opened (a test's frozen stand-in)
		return
	}
	select {
	case <-s.sdb.db.done:
		return // the database was closed: the process (or a test) is ending
	default:
	}
	var err error
	for i, wait := range doBackoff {
		time.Sleep(wait)
		if err = s.doOnce(fn); err == nil {
			stateWriteFailing.Store(false)
			return
		}
		log.Printf("state: a change wasn't written (attempt %d of %d; the records are read again): %v", i+1, len(doBackoff), err)
	}
	select {
	case <-s.sdb.db.done:
		return
	default:
	}
	stateWriteFailing.Store(true)
	panic(stateWriteError{err})
}

// doBackoff: the waits before each attempt of a Do
var doBackoff = []time.Duration{0, 200 * time.Millisecond, time.Second, 3 * time.Second}

// stateWriteFailing: a Do just gave up (jobs.go: a job ending now isn't marked done: another replica carries it on)
var stateWriteFailing atomic.Bool

// stateWriteError: what a Do panics with when it can't write a change
type stateWriteError struct{ err error }

func (e stateWriteError) Error() string { return "the records couldn't be written: " + e.err.Error() }

func (s *State) doOnce(fn func(d *persisted)) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var written rows
	var ver int64
	err := pgx.BeginFunc(ctx, s.sdb.db.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT v FROM state_version WHERE id = 1 FOR UPDATE").Scan(&ver); err != nil {
			return err
		}
		if ver != s.sdb.ver {
			if err := s.reload(ctx, tx); err != nil {
				return err
			}
			s.sdb.ver = ver
		}
		fn(&s.data)
		d := &s.data
		d.SessCerts = map[string]*Doc{}
		for id, ss := range d.Sessions {
			if ss.Cert != nil {
				d.SessCerts[id] = ss.Cert
			}
		}
		now, changed, err := s.sdb.writeTx(ctx, tx, d)
		if err != nil {
			return err
		}
		if changed {
			if err := tx.QueryRow(ctx, "UPDATE state_version SET v = v + 1 WHERE id = 1 RETURNING v").Scan(&ver); err != nil {
				return err
			}
		}
		written = now
		return nil
	})
	s.sdb.mu.Lock()
	defer s.sdb.mu.Unlock()
	if err != nil {
		s.sdb.ver = -1 // the copy here may hold what the database refused: read again next time
		if s.sdb.lastErr == nil {
			s.sdb.errAt = time.Now()
		}
		s.sdb.lastErr = err
		return err
	}
	s.sdb.written, s.sdb.ver = written, ver
	if s.sdb.lastErr != nil {
		log.Printf("state: writes go through again (they failed since %s)", s.sdb.errAt.Format(time.RFC3339))
		s.sdb.lastErr = nil
	}
	return nil
}
