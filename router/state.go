package main

// The router's own records, in one JSON file on the box's volume (written atomically). Nothing here is
// trusted by anyone else: the certs are core-signed and the snapshots machine-signed.

import (
	"github.com/DE0CH/jarvis4/kernel/gv"

	"encoding/json"
	"os"
	"path/filepath"
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
	ArchiveDir     string     `json:"archiveDir,omitempty"`     // archive.go: fixed by the destroy that archives it
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
	// messages.go: messages held for Deyao to deliver or deny, and his per-kind rules
	Messages     map[string]*PendingMessage `json:"messages,omitempty"`
	MessageRules map[string]*MessageRule    `json:"messageRules,omitempty"`
}

type State struct {
	mu   sync.Mutex
	dir  string
	data persisted
}

func LoadState(dir string) (*State, error) {
	if err := os.MkdirAll(filepath.Join(dir, "snapshots"), 0o700); err != nil {
		return nil, err
	}
	s := &State{dir: dir}
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err == nil {
		if err := json.Unmarshal(b, &s.data); err != nil {
			return nil, err
		}
	}
	d := &s.data
	if d.Sessions == nil {
		d.Sessions = map[string]*Session{}
	}
	if d.Inbox == nil {
		d.Inbox = map[string]*InboxRequest{}
	}
	if d.Approvals == nil {
		d.Approvals = map[string]*Approval{}
	}
	if d.Batches == nil {
		d.Batches = map[string]*Batch{}
	}
	if d.Messages == nil {
		d.Messages = map[string]*PendingMessage{}
	}
	if d.MessageRules == nil {
		d.MessageRules = map[string]*MessageRule{}
	}
	if d.Started == nil {
		d.Started = map[string]*Started{}
	}
	if d.Certs == nil {
		d.Certs = map[string]*Doc{}
	}
	if d.Machines == nil {
		d.Machines = map[string]string{}
	}
	if d.SessCerts == nil {
		d.SessCerts = map[string]*Doc{}
	}
	if d.Grants == nil {
		d.Grants = map[string]*StoredGrant{}
	}
	for id, c := range d.SessCerts {
		if s := d.Sessions[id]; s != nil {
			s.Cert = c
		}
	}
	return s, nil
}

// Do runs fn under the lock and saves afterwards
func (s *State) Do(fn func(d *persisted)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.data)
	s.save()
}

func (s *State) save() {
	d := &s.data
	d.SessCerts = map[string]*Doc{}
	for id, ss := range d.Sessions {
		if ss.Cert != nil {
			d.SessCerts[id] = ss.Cert
		}
	}
	b, _ := json.MarshalIndent(d, "", " ")
	tmp := filepath.Join(s.dir, "state.json.tmp")
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, filepath.Join(s.dir, "state.json"))
	}
}

func (s *State) snapshotPath(machine string) string {
	return filepath.Join(s.dir, "snapshots", machine+".tar.gz")
}
