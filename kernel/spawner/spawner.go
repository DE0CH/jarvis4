// Package spawner: the spawner (DESIGN "Target design"), the kernel's only holder of the Fly token. It attests Fly
// facts only, so every cert it signs has the pair ⊤:
//
//	spawn:   a notarized cert into source-x → a new empty volume and a Fly machine on it with the source's image (by
//	         digest) and the machine env naming the source, the kernel's roster and root key
//	init:    M started on Fly with that digest → its keys (jarvis2-init, through Fly) → (source-x, fly-M, ⊤) naming
//	         them and the image Fly runs; the first cert signed is the one kept
//	kill:    M destroyed, confirmed through Fly → (fly-M, source-y, ⊤), source-y holding M's image and settings and the
//	         hash of the snapshot M signed (the source's own when M sent none); one kill cert per machine
//	destroy: a machine the spawner made that never came up (a spawn whose answer was lost) → destroyed, no cert
//
// Each call is single Fly calls with no waiting or retrying: the router retries (a 409 while Fly isn't there yet), moves
// a spawn off a full host by spawning again, finds the machine of a spawn whose answer was lost with its read-only
// token, and calls kill again while a volume is left. A second machine from one source can't take the line: the
// notarizer refuses a second successor of a source.
//
// The machines it made, and each kill's cert, are kept on its own volume (state.json), so a restart neither forgets a
// machine nor signs a second kill of one. The Fly token is kept in memory only: after a restart the setup session (or
// the app's Recover) sends it again. In the copy flip (internal/serve flip.go) the machines and the token move to the
// other copy's spawner, sealed to it, and this one freezes: it makes no Fly call after its handoff.
package spawner

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// SessionRepo: the only image the spawner starts, pinned by digest
const SessionRepo = "ghcr.io/de0ch/jarvis4-session"

var imageRE = regexp.MustCompile(`^` + regexp.QuoteMeta(SessionRepo) + `(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@(sha256:[0-9a-f]{64})$`)

func imageDigest(ref string) string {
	if m := imageRE.FindStringSubmatch(ref); m != nil {
		return m[2]
	}
	return ""
}

func reportedDigest(ref string) string {
	i := strings.LastIndex(ref, "@sha256:")
	if i < 0 || len(ref)-i-1 != len("sha256:")+64 {
		return ""
	}
	return ref[i+1:]
}

const (
	maxDiskGB    = 500
	infoFlyToken = "jarvis2/fly-token"
	infoAWSKey   = "jarvis4/aws-credentials"
)

// The reasons of the spawner's refusals the router acts on (the error answer's "reason", serve.FailBecause)
const (
	ReasonNoFlyToken   = "no-fly-token"    // 503: the setup session (or the app's Recover) sends the token again
	ReasonFly          = "fly"             // 502: Fly refused or didn't answer; the call may be made again
	ReasonNoAWSKey     = "no-aws-key"      // 503: the setup session (or the app's Recover) sends the AWS key again
	ReasonAWS          = "aws"             // 502: EC2 refused or didn't answer; the call may be made again
	ReasonHostFull     = "host-full"       // 502: Fly's 412 volume_placement_capacity; the volume is deleted, spawn again
	ReasonUnknown      = "unknown-machine" // 404: not a machine the spawner made
	ReasonNotStarted   = "not-started"     // 409: init before the runner says started (AWS: before the keys line)
	ReasonWrongImage   = "wrong-image"     // 409: Fly runs another digest than the source's
	ReasonNotDestroyed = "not-destroyed"   // 409: Fly doesn't say destroyed yet; kill (or destroy) again
	ReasonBadSnapshot  = "bad-snapshot"    // 400: the snapshot isn't signed by the machine's key
	ReasonCameUp       = "came-up"         // 409: a destroy of a machine that has a cert: it is killed instead
	ReasonKilled       = "killed"          // 409: init of a machine killed meanwhile
)

// Machine: one the spawner made
type Machine struct {
	ID       string     `json:"id"`
	Runner   string     `json:"runner,omitempty"` // "aws", or "" for Fly (state from before the AWS runner)
	Source   doc.Object `json:"source"`
	Content  doc.Source `json:"content"`          // the source's image and settings (its snapshot is the predecessor's)
	Volume   string     `json:"volume,omitempty"` // its volume, until Fly deleted it
	Keys     *doc.Keys  `json:"keys,omitempty"`   // once init read them
	Image    string     `json:"image,omitempty"`
	Cert     *sig.Doc   `json:"cert,omitempty"`     // (source, fly-M, ⊤)
	KillCert *sig.Doc   `json:"killCert,omitempty"` // (fly-M, source-y, ⊤), or a kill record for one never up
	Killed   bool       `json:"killed,omitempty"`   // destroyed on Fly by a kill or a destroy
}

type Spawner struct {
	mu sync.Mutex
	// op: every call holds it shared; the handoff and the takeover hold it alone, so no call is halfway through
	// when the state moves
	op        sync.RWMutex
	cont      *serve.Continuity // its mode in the copy flip (path + ".mode")
	token     string            // the Fly token (memory only), handed over with the machines
	awsKey    *AWSCredentials   // the AWS key (memory only), handed over with the machines
	s         *sig.Signer
	agreement *ecdh.PrivateKey
	trust     *sig.Trust
	fly       Fly
	aws       *AWSAPI
	env       map[string]string // what every Fly machine's config env gets (the router's address); the roster and the root key are added per spawn
	awsEnv    map[string]string // the same for an AWS machine (the router's address on the tailnet)
	path      string
	machines  map[string]*Machine
}

type state struct {
	Machines map[string]*Machine `json:"machines"`
}

// Open: the state at path (made if missing), its mode beside it. env, awsEnv: the env every Fly / AWS machine gets
// (the router's address as that runner's machines reach it). aws nil: no AWS runner.
func Open(path string, c *sig.Component, t *sig.Trust, fly Fly, aws *AWSAPI, env, awsEnv map[string]string) (*Spawner, error) {
	cont, err := serve.OpenContinuity(path + ".mode")
	if err != nil {
		return nil, err
	}
	if r := t.Roster(); r != nil { // a roster already held decides a new volume's mode now (else POST /roster does)
		if err := cont.Decide(*r, "spawner"); err != nil {
			return nil, err
		}
	}
	sp := &Spawner{cont: cont, s: c.Signer, agreement: c.Agreement, trust: t, fly: fly, aws: aws, env: env, awsEnv: awsEnv, path: path, machines: map[string]*Machine{}}
	b, err := os.ReadFile(path)
	if err == nil {
		var st state
		if err := json.Unmarshal(b, &st); err != nil {
			return nil, fmt.Errorf("%s: %v", path, err)
		}
		if st.Machines != nil {
			sp.machines = st.Machines
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return sp, nil
}

// save: the state, atomically (callers hold mu)
func (sp *Spawner) save() error {
	b, _ := json.Marshal(state{Machines: sp.machines})
	tmp := sp.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Clean(sp.path))
}

// flyFail: a runner call that failed, answered with its reason
func flyFail(what string, err error) error {
	switch {
	case errors.Is(err, errNoToken):
		return serve.FailBecause(503, ReasonNoFlyToken, "%v", err)
	case errors.Is(err, errNoAWSCredentials):
		return serve.FailBecause(503, ReasonNoAWSKey, "%v", err)
	case errors.Is(err, errNotYet):
		return serve.FailBecause(409, ReasonNotStarted, "%v", err)
	}
	var ae *AWSError
	if errors.As(err, &ae) {
		return serve.FailBecause(502, ReasonAWS, "aws %s: %v", what, err)
	}
	return serve.FailBecause(502, ReasonFly, "fly %s: %v", what, err)
}

func orFly(runner string) string {
	if runner == "" {
		return "fly"
	}
	return runner
}

// runnerOf: the runner of a machine id: an EC2 instance id (i-…) is AWS's, anything else Fly's
func runnerOf(id string) string {
	if strings.HasPrefix(id, "i-") {
		return "aws"
	}
	return "fly"
}

// runner: the API of a machine id's runner
func (sp *Spawner) runner(id string) Runner {
	if runnerOf(id) == "aws" && sp.aws != nil {
		return sp.aws
	}
	return flyRunner{sp.fly}
}

// object: the machine's object, "<runner>-<id>"
func object(id string) doc.Object { return doc.Object(runnerOf(id) + "-" + id) }

// serving: a call may go on (callers hold op shared)
func (sp *Spawner) serving() error { return sp.cont.Serving() }

// SetAWSCredentials: AWSCredentials sealed to the spawner's agreement key
func (sp *Spawner) SetAWSCredentials(sealed sig.Sealed) (any, error) {
	sp.op.RLock()
	defer sp.op.RUnlock()
	if err := sp.serving(); err != nil {
		return nil, err
	}
	if sp.aws == nil {
		return nil, serve.Fail(503, "this spawner has no AWS runner")
	}
	plain, err := sig.OpenSealed(sp.agreement, sealed, infoAWSKey)
	if err != nil {
		return nil, serve.Fail(400, "can't open the AWS key")
	}
	var v AWSCredentials
	if json.Unmarshal(plain, &v) != nil || v.AccessKeyID == "" || v.SecretAccessKey == "" {
		return nil, serve.Fail(400, "need AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
	}
	sp.aws.Configure(v)
	sp.mu.Lock()
	sp.awsKey = &v
	sp.mu.Unlock()
	log.Printf("AWS key set")
	return map[string]string{"kind": "aws-key-set"}, nil
}

// SetFlyToken: {"FLY_API_TOKEN": …} sealed to the spawner's agreement key
func (sp *Spawner) SetFlyToken(sealed sig.Sealed) (any, error) {
	sp.op.RLock()
	defer sp.op.RUnlock()
	if err := sp.serving(); err != nil {
		return nil, err
	}
	plain, err := sig.OpenSealed(sp.agreement, sealed, infoFlyToken)
	if err != nil {
		return nil, serve.Fail(400, "can't open the Fly token")
	}
	var v struct {
		Token string `json:"FLY_API_TOKEN"`
	}
	if json.Unmarshal(plain, &v) != nil || v.Token == "" {
		return nil, serve.Fail(400, "no FLY_API_TOKEN")
	}
	sp.fly.Configure(v.Token)
	sp.mu.Lock()
	sp.token = v.Token
	sp.mu.Unlock()
	log.Printf("Fly token set")
	return map[string]string{"kind": "fly-token-set"}, nil
}

// SpawnInput: the notarized cert into the source, and the machine's size, region and disk
type SpawnInput struct {
	Cert      sig.Doc      `json:"cert"`
	Notarized sig.Doc      `json:"notarized"`
	Notarizer sig.Identity `json:"notarizer"`
	Region    string       `json:"region"`
	Size      string       `json:"size"`
	DiskGB    int          `json:"diskGb"`
	Runner    string       `json:"runner,omitempty"` // "aws" or "fly" ("" = fly: the router from before the AWS runner)
	// WireGuard: an AWS machine's way to the router, which the router makes per spawn (aws.go WireGuard)
	WireGuard *WireGuard `json:"wireguard,omitempty"`
}

// Spawn: a machine on a new, empty disk on the source's runner (Fly: a volume and one create on it; AWS: one
// instance), from a notarized source → {kind: "created", id, source, volume}. A Fly create that fails deletes the
// volume (one try; a volume left is the router's sweep's).
func (sp *Spawner) Spawn(in SpawnInput) (any, error) {
	sp.op.RLock()
	defer sp.op.RUnlock()
	if err := sp.serving(); err != nil {
		return nil, err
	}
	if err := sig.CheckIdentity(in.Notarizer, "notarizer", sp.trust); err != nil {
		return nil, serve.Fail(403, "%v", err)
	}
	var nz doc.Notarized
	if err := in.Notarized.Open(in.Notarizer.SigningKey, &nz); err != nil || nz.Kind != "notarized" || nz.Cert != in.Cert.ID() {
		return nil, serve.Fail(403, "the cert isn't notarized")
	}
	c, err := doc.PeekCert(in.Cert)
	if err != nil || c.Succ.Kind() != "source" {
		return nil, serve.Fail(400, "a spawn is from a cert into a source")
	}
	if imageDigest(c.Source.Image) == "" {
		return nil, serve.Fail(400, "the source's image isn't %s pinned by digest", SessionRepo)
	}
	kind, cpus, mem := sizeGuest(in.Size)
	if kind == "" {
		return nil, serve.Fail(400, "size: small, medium, large or a doubling past it (16gb, 32gb, …)")
	}
	if in.DiskGB < 1 || in.DiskGB > maxDiskGB || in.Region == "" {
		return nil, serve.Fail(400, "diskGb 1 to %d and a region", maxDiskGB)
	}
	var run Runner = flyRunner{sp.fly}
	switch in.Runner {
	case "", "fly":
	case "aws":
		if sp.aws == nil {
			return nil, serve.Fail(503, "this spawner has no AWS runner")
		}
		if !AWSRegions[in.Region] {
			return nil, serve.Fail(400, "no AWS region %q", in.Region)
		}
		if instanceType(mem) == "" {
			return nil, serve.Fail(400, "no instance type for size %s", in.Size)
		}
		if in.WireGuard == nil {
			return nil, serve.Fail(400, "an AWS machine needs its wireguard")
		}
		if err := in.WireGuard.Check(); err != nil {
			return nil, serve.Fail(400, "%v", err)
		}
		run = sp.aws
	default:
		return nil, serve.Fail(400, "runner: aws or fly")
	}
	base := sp.env
	if in.Runner == "aws" {
		base = sp.awsEnv
	}
	if base == nil {
		return nil, serve.Fail(503, "the spawner has no router address for its %s machines (KERNEL_MACHINE_URL, KERNEL_AWS_MACHINE_URL)", orFly(in.Runner))
	}
	rd := sp.trust.Doc()
	if rd == nil {
		return nil, serve.Fail(503, "%v", sig.ErrNoRoster)
	}
	guest := map[string]any{"cpu_kind": kind, "cpus": cpus, "memory_mb": mem}
	rj, _ := json.Marshal(rd)
	// the machine checks the kernel's identities against the root key's roster (machine/kernelboot.go)
	env := map[string]string{"JARVIS2_SOURCE": string(c.Succ), "JARVIS2_KERNEL_ROSTER": string(rj), "JARVIS2_KERNEL_ROOT": sp.trust.Root()}
	for k, v := range base {
		env[k] = v
	}
	id, vid, err := run.Create(CreateInput{Image: c.Source.Image, Region: in.Region, Guest: guest, MemoryMB: mem, Env: env,
		DiskGB: in.DiskGB, Source: string(c.Succ), WireGuard: in.WireGuard})
	if err != nil {
		if code, st := flyStatus(err); code == 412 && st == "volume_placement_capacity" {
			// the volume's host has no room for this machine; a volume is pinned to its host, so a new spawn (a new
			// volume) is the way to another host
			return nil, serve.FailBecause(502, ReasonHostFull, "fly create: %v", err)
		}
		var ae *AWSError
		if errors.As(err, &ae) && ae.Code == "InsufficientInstanceCapacity" {
			return nil, serve.FailBecause(502, ReasonHostFull, "aws create: %v", err)
		}
		return nil, flyFail("create", err)
	}
	runner := ""
	if runnerOf(id) == "aws" {
		runner = "aws"
	}
	m := &Machine{ID: id, Runner: runner, Source: c.Succ, Content: *c.Source, Volume: vid}
	sp.mu.Lock()
	sp.machines[id] = m
	err = sp.save()
	sp.mu.Unlock()
	if err != nil {
		return nil, err
	}
	log.Printf("machine %s created from %s (%s)", id, c.Succ, c.Source.Image)
	return map[string]any{"kind": "created", "id": id, "source": c.Succ, "volume": vid}, nil
}

// Init: one try at reading a created machine's keys (409 while it isn't up yet: the router retries) → its cert
func (sp *Spawner) Init(id string) (sig.Doc, error) {
	sp.op.RLock()
	defer sp.op.RUnlock()
	if err := sp.serving(); err != nil {
		return sig.Doc{}, err
	}
	sp.mu.Lock()
	m := sp.machines[id]
	sp.mu.Unlock()
	switch {
	case m == nil:
		return sig.Doc{}, serve.FailBecause(404, ReasonUnknown, "machine %s isn't one the spawner made", id)
	case m.Cert != nil:
		return *m.Cert, nil
	}
	fm, err := sp.runner(id).Inspect(id)
	if err != nil {
		return sig.Doc{}, flyFail("inspect", err)
	}
	if fm.State != "started" {
		return sig.Doc{}, serve.FailBecause(409, ReasonNotStarted, "machine %s is %s, not started", id, fm.State)
	}
	if reportedDigest(fm.Image) != imageDigest(m.Content.Image) {
		return sig.Doc{}, serve.FailBecause(409, ReasonWrongImage, "machine %s runs %s, not its source's %s", id, fm.Image, m.Content.Image)
	}
	k, err := sp.runner(id).Init(id)
	if err != nil {
		return sig.Doc{}, flyFail("init", err)
	}
	keys := doc.Keys{SigningKey: k.SigningKey, EncryptionKey: k.EncryptionKey}
	c := doc.Cert{Kind: "succession", Pred: m.Source, Succ: object(id), Pair: perm.Top(),
		Machine: &doc.Machine{Keys: keys, Image: fm.Image}, Signer: doc.BySpawner, IssuedAt: doc.Now()}
	if err := c.Check(); err != nil {
		return sig.Doc{}, serve.Fail(502, "machine %s: %v", id, err)
	}
	d, err := sp.s.SignJSON(c)
	if err != nil {
		return sig.Doc{}, err
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()
	switch {
	case m.Cert != nil: // an init meanwhile: the first cert wins
		return *m.Cert, nil
	case m.Killed:
		return sig.Doc{}, serve.FailBecause(409, ReasonKilled, "machine %s was killed meanwhile", id)
	}
	m.Keys, m.Image, m.Cert = &keys, fm.Image, &d
	if err := sp.save(); err != nil {
		return sig.Doc{}, err
	}
	log.Printf("machine %s up (%s)", id, fm.Image)
	return d, nil
}

// Snapshot: what a machine signed over its snapshot (the hex sha256 of the tarball)
type Snapshot struct {
	Sha256 string `json:"sha256"`
	Sig    string `json:"sig"`
}

var hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// destroyOnFly: the machine destroyed, as its runner says (single calls: a destroy, then a look) → its volume as
// Fly listed it ("" on AWS)
func (sp *Spawner) destroyOnFly(id string) (string, error) {
	run := sp.runner(id)
	fm, err := run.Inspect(id)
	if err != nil {
		return "", flyFail("inspect", err)
	}
	vol := fm.Volume
	if fm.State != "destroyed" {
		derr := run.Destroy(id)
		if fm, err = run.Inspect(id); err != nil {
			return "", flyFail("inspect", err)
		}
		if fm.State != "destroyed" {
			return "", serve.FailBecause(409, ReasonNotDestroyed, "machine %s is %s, not destroyed yet (destroy: %v)", id, fm.State, derr)
		}
	}
	return vol, nil
}

// dropVolume: one try at deleting the destroyed machine's volume → the volume still there ("" = gone)
func (sp *Spawner) dropVolume(m *Machine) string {
	sp.mu.Lock()
	v := m.Volume
	sp.mu.Unlock()
	if v == "" {
		return ""
	}
	if err := sp.runner(m.ID).DeleteVolume(v); err != nil {
		if code, _ := flyStatus(err); code != 404 {
			log.Printf("machine %s: volume %s: delete: %v (the router kills it again)", m.ID, v, err)
			return v
		}
	}
	sp.mu.Lock()
	m.Volume = ""
	sp.save()
	sp.mu.Unlock()
	return ""
}

// Kill: the machine destroyed (409 until Fly reports it) → {kind: "killed", id, cert: (fly-M, source-y, ⊤), volumeLeft}.
// The cert is signed once per machine and answered again to every later kill; each kill makes one try at deleting the
// machine's volume, and volumeLeft names it while it is still there (the router kills again).
func (sp *Spawner) Kill(id string, snap *Snapshot) (any, error) {
	sp.op.RLock()
	defer sp.op.RUnlock()
	if err := sp.serving(); err != nil {
		return nil, err
	}
	sp.mu.Lock()
	m := sp.machines[id]
	sp.mu.Unlock()
	if m == nil {
		return nil, serve.FailBecause(404, ReasonUnknown, "machine %s isn't one the spawner made", id)
	}
	if m.KillCert == nil {
		sum := ""
		if snap != nil {
			switch {
			case m.Keys == nil:
				return nil, serve.FailBecause(400, ReasonBadSnapshot, "machine %s never came up, so it signed no snapshot", id)
			case !hex64RE.MatchString(snap.Sha256) || !sig.Verify(m.Keys.SigningKey, []byte(snap.Sha256), snap.Sig):
				return nil, serve.FailBecause(400, ReasonBadSnapshot, "machine %s's snapshot isn't signed by its key", id)
			}
			sum = snap.Sha256
		}
		if _, err := sp.destroyOnFly(id); err != nil {
			return nil, err
		}
		var d sig.Doc
		var err error
		if m.Keys == nil { // never up: no state, nothing goes on from it
			d, err = sp.s.SignJSON(map[string]any{"kind": "killed", "id": id, "up": false})
		} else {
			b := make([]byte, 16)
			rand.Read(b)
			// a machine that signed no snapshot passes on the one its source named: it has no newer state the spawner
			// vouched for
			src := m.Content
			if sum != "" {
				src.Snapshot = sum
			}
			c := doc.Cert{Kind: "succession", Pred: object(id), Succ: doc.NewSource(b), Pair: perm.Top(),
				Source: &src, Signer: doc.BySpawner, IssuedAt: doc.Now()}
			if err := c.Check(); err != nil {
				return nil, err
			}
			d, err = sp.s.SignJSON(c)
		}
		if err != nil {
			return nil, err
		}
		sp.mu.Lock()
		if m.KillCert == nil { // a kill meanwhile: its cert is the one
			m.Killed, m.KillCert = true, &d
			err = sp.save()
		}
		sp.mu.Unlock()
		if err != nil {
			return nil, err
		}
		log.Printf("machine %s killed (snapshot %q)", id, sum)
	}
	left := sp.dropVolume(m)
	sp.mu.Lock()
	d := *m.KillCert
	sp.mu.Unlock()
	return map[string]any{"kind": "killed", "id": id, "cert": d, "volumeLeft": left}, nil
}

// Destroy: a machine the spawner made that never came up (a spawn whose answer was lost, also one made just before a
// restart that the state never recorded: Fly's metadata names its source) destroyed → {kind: "destroyed", id,
// volumeLeft}, no cert. A machine with a cert is killed instead (409 came-up).
func (sp *Spawner) Destroy(id string) (any, error) {
	sp.op.RLock()
	defer sp.op.RUnlock()
	if err := sp.serving(); err != nil {
		return nil, err
	}
	sp.mu.Lock()
	m := sp.machines[id]
	sp.mu.Unlock()
	if m != nil && m.Cert != nil && m.KillCert == nil {
		return nil, serve.FailBecause(409, ReasonCameUp, "machine %s came up: it is killed, not destroyed", id)
	}
	if m == nil || !m.Killed {
		if m == nil {
			fm, err := sp.runner(id).Inspect(id)
			if err != nil {
				return nil, flyFail("inspect", err)
			}
			if fm.Source == "" {
				return nil, serve.FailBecause(404, ReasonUnknown, "machine %s isn't one the spawner made", id)
			}
			m = &Machine{ID: id, Source: doc.Object(fm.Source)}
			if runnerOf(id) == "aws" {
				m.Runner = "aws"
			}
		}
		vol, err := sp.destroyOnFly(id)
		if err != nil {
			return nil, err
		}
		sp.mu.Lock()
		if cur := sp.machines[id]; cur != nil {
			m = cur
		} else {
			sp.machines[id] = m
		}
		if m.Volume == "" {
			m.Volume = vol
		}
		m.Killed = true
		err = sp.save()
		sp.mu.Unlock()
		if err != nil {
			return nil, err
		}
		log.Printf("machine %s destroyed (never came up)", id)
	}
	return map[string]any{"kind": "destroyed", "id": id, "volumeLeft": sp.dropVolume(m)}, nil
}

// ---- the copy flip (serve.Stateful) --------------------------------------------------------------------------

// handed: the state as it moves to the other copy
type handed struct {
	Machines map[string]*Machine `json:"machines"`
	FlyToken string              `json:"flyToken,omitempty"`
	AWSKey   *AWSCredentials     `json:"awsKey,omitempty"`
}

func (sp *Spawner) Decide(r sig.Roster) error {
	sp.op.Lock()
	defer sp.op.Unlock()
	return sp.cont.Decide(r, "spawner")
}

// Mode: serving, standby or handed-off ("" before the first roster)
func (sp *Spawner) Mode() string { return sp.cont.Mode() }

// Handoff: frozen once no call is under way (no Fly call after it), then the machines and the Fly token
func (sp *Spawner) Handoff(roster string) ([]byte, error) {
	sp.op.Lock()
	defer sp.op.Unlock()
	if err := sp.cont.Freeze(roster); err != nil {
		return nil, err
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return json.Marshal(handed{Machines: sp.machines, FlyToken: sp.token, AWSKey: sp.awsKey})
}

// Takeover: the predecessor's machines replace this volume's (saved before it serves), and its Fly token
func (sp *Spawner) Takeover(id string, state []byte) error {
	sp.op.Lock()
	defer sp.op.Unlock()
	again, err := sp.cont.CanTake(id)
	if err != nil || again {
		return err
	}
	var h handed
	if err := sig.StrictJSON(state, &h); err != nil {
		return serve.Fail(400, "the handed state: %v", err)
	}
	if h.Machines == nil {
		h.Machines = map[string]*Machine{}
	}
	sp.mu.Lock()
	sp.machines = h.Machines
	err = sp.save()
	if err == nil && h.FlyToken != "" {
		sp.fly.Configure(h.FlyToken)
		sp.token = h.FlyToken
	}
	if err == nil && h.AWSKey != nil && sp.aws != nil {
		sp.aws.Configure(*h.AWSKey)
		sp.awsKey = h.AWSKey
	}
	sp.mu.Unlock()
	if err != nil {
		return err
	}
	if err := sp.cont.Took(id); err != nil {
		return err
	}
	log.Printf("took over %d machines (Fly token: %v, AWS key: %v); serving", len(h.Machines), h.FlyToken != "", h.AWSKey != nil)
	return nil
}

func Register(s *serve.Server, sp *Spawner) {
	s.State = sp
	serve.Handle(s, "POST /fly-token", func(in struct {
		Sealed sig.Sealed `json:"sealed"`
	}) (any, error) {
		return sp.SetFlyToken(in.Sealed)
	})
	serve.Handle(s, "POST /aws-credentials", func(in struct {
		Sealed sig.Sealed `json:"sealed"`
	}) (any, error) {
		return sp.SetAWSCredentials(in.Sealed)
	})
	serve.Handle(s, "POST /spawn", func(in SpawnInput) (any, error) { return sp.Spawn(in) })
	serve.Handle(s, "POST /init", func(in struct {
		ID string `json:"id"`
	}) (any, error) {
		return sp.Init(in.ID)
	})
	serve.Handle(s, "POST /kill", func(in struct {
		ID       string    `json:"id"`
		Snapshot *Snapshot `json:"snapshot,omitempty"`
	}) (any, error) {
		return sp.Kill(in.ID, in.Snapshot)
	})
	serve.Handle(s, "POST /destroy", func(in struct {
		ID string `json:"id"`
	}) (any, error) {
		return sp.Destroy(in.ID)
	})
}
