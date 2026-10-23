// Package spawner: the spawner (DESIGN "Target design"), the kernel's only holder of the Fly token. It attests Fly
// facts only, so every cert it signs has the pair ⊤:
//
//	spawn:  a notarized cert into source-x → a Fly machine with the source's image and a new empty volume; once it is
//	        up, its keys (jarvis2-init, through Fly) → (source-x, fly-M, ⊤) naming them and the image Fly runs.
//	kill:   M alive → destroyed, confirmed through Fly, its volume deleted → (fly-M, source-y, ⊤), source-y holding M's
//	        image and settings and the hash of the snapshot M signed (none when M sent none; a caller that would rather
//	        keep M than lose its state says required, and the kill is then refused).
//
// The machines it made, and each kill's cert, are kept on its own volume (state.json), so a restart neither forgets a
// machine nor signs a second kill of one. The Fly token is not kept: the setup session sends it again.
package spawner

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
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
	defaultDiskGB = 10
	maxDiskGB     = 500
	infoFlyToken  = "jarvis2/fly-token"
)

// Machine: one the spawner made
type Machine struct {
	ID       string     `json:"id"`
	Source   doc.Object `json:"source"`
	Content  doc.Source `json:"content"` // the source's image and settings (its snapshot is the predecessor's)
	Volume   string     `json:"volume,omitempty"`
	DiskGB   int        `json:"diskGb,omitempty"`
	Keys     *doc.Keys  `json:"keys,omitempty"` // once init read them
	Image    string     `json:"image,omitempty"`
	Cert     *sig.Doc   `json:"cert,omitempty"`     // (source, fly-M, ⊤)
	KillCert *sig.Doc   `json:"killCert,omitempty"` // (fly-M, source-y, ⊤), or a kill record for one never up
	Killed   bool       `json:"killed,omitempty"`
}

type Spawner struct {
	mu        sync.Mutex
	s         *sig.Signer
	agreement *ecdh.PrivateKey
	trust     *sig.Trust
	fly       Fly
	env       map[string]string // what every machine's Fly config env gets (the router's address); the roster and the root key are added per spawn
	path      string
	machines  map[string]*Machine
	orphans   map[string]bool // volumes whose delete failed: tried again at every kill
	spawns    map[string]*Spawn
	inflight  map[string]bool // spawn keys a Spawn call is working on now
}

// Spawn: one spawn, keyed by the id of the notarized cert into the source, written before Fly is asked for anything.
// A repeated spawn of the same cert answers the machine it made (while that one isn't killed); one whose machine
// never got recorded (a crash or a lost answer between Fly's create and the state write) finds it in Fly by the
// metadata naming the key (Fly.Find), so a retry never makes a second machine.
type Spawn struct {
	Volume  string `json:"volume,omitempty"`
	DiskGB  int    `json:"diskGb,omitempty"`
	Machine string `json:"machine,omitempty"`
}

type state struct {
	Machines map[string]*Machine `json:"machines"`
	Orphans  []string            `json:"orphans"`
	Spawns   map[string]*Spawn   `json:"spawns,omitempty"`
}

// crashAfterCreate: tests stop Spawn here, between Fly's create and the state write, as a crash would
var crashAfterCreate func()

// Open: the state at path (made if missing). env: the machines' Fly config env.
func Open(path string, c *sig.Component, t *sig.Trust, fly Fly, env map[string]string) (*Spawner, error) {
	sp := &Spawner{s: c.Signer, agreement: c.Agreement, trust: t, fly: fly, env: env, path: path,
		machines: map[string]*Machine{}, orphans: map[string]bool{}, spawns: map[string]*Spawn{}, inflight: map[string]bool{}}
	b, err := os.ReadFile(path)
	if err == nil {
		var st state
		if err := json.Unmarshal(b, &st); err != nil {
			return nil, fmt.Errorf("%s: %v", path, err)
		}
		if st.Machines != nil {
			sp.machines = st.Machines
		}
		if st.Spawns != nil {
			sp.spawns = st.Spawns
		}
		for _, o := range st.Orphans {
			sp.orphans[o] = true
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return sp, nil
}

// save: the state, atomically (callers hold mu)
func (sp *Spawner) save() error {
	st := state{Machines: sp.machines, Orphans: []string{}, Spawns: sp.spawns}
	for o := range sp.orphans {
		st.Orphans = append(st.Orphans, o)
	}
	b, _ := json.Marshal(st)
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

// SetFlyToken: {"FLY_API_TOKEN": …} sealed to the spawner's agreement key
func (sp *Spawner) SetFlyToken(sealed sig.Sealed) (any, error) {
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
}

// Spawn: one Fly create (with a new empty volume) from a notarized source → {kind: "created", id, source, volume}
func (sp *Spawner) Spawn(in SpawnInput) (any, error) {
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
	gb := in.DiskGB
	if gb == 0 {
		gb = defaultDiskGB
	}
	if gb < 1 || gb > maxDiskGB || in.Region == "" {
		return nil, serve.Fail(400, "diskGb 1 to %d and a region", maxDiskGB)
	}
	if sp.env == nil {
		return nil, serve.Fail(503, "the spawner has no router address for its machines (KERNEL_MACHINE_URL)")
	}
	rd := sp.trust.Doc()
	if rd == nil {
		return nil, serve.Fail(503, "%v", sig.ErrNoRoster)
	}
	key := in.Cert.ID()
	created := func(m *Machine) map[string]any {
		return map[string]any{"kind": "created", "id": m.ID, "source": m.Source, "volume": m.Volume, "diskGb": m.DiskGB}
	}
	// adopt: the machine Fly made for this spawn, recorded (callers hold mu)
	adopt := func(sw *Spawn, id string) (any, error) {
		m := &Machine{ID: id, Source: c.Succ, Content: *c.Source, Volume: sw.Volume, DiskGB: sw.DiskGB}
		sp.machines[id], sw.Machine = m, id
		if err := sp.save(); err != nil {
			return nil, err
		}
		log.Printf("machine %s created from %s (%s)", id, c.Succ, c.Source.Image)
		return created(m), nil
	}

	sp.mu.Lock()
	if sp.inflight[key] {
		sp.mu.Unlock()
		return nil, serve.Fail(409, "this source's spawn is under way: try again")
	}
	sw := sp.spawns[key]
	if sw != nil && sw.Machine != "" {
		if m := sp.machines[sw.Machine]; m != nil && !m.Killed {
			sp.mu.Unlock()
			return created(m), nil // a repeat: the machine already made
		}
		sw = nil // that machine was killed: a new spawn
	}
	if sw != nil { // recorded but no machine: Fly may have made it before the answer was lost
		ids, err := sp.fly.Find(key)
		if err != nil {
			sp.mu.Unlock()
			return nil, serve.Fail(502, "fly: %v", err)
		}
		if len(ids) > 0 {
			defer sp.mu.Unlock()
			return adopt(sw, ids[0])
		}
	} else {
		sw = &Spawn{DiskGB: gb}
		sp.spawns[key] = sw
		if err := sp.save(); err != nil {
			delete(sp.spawns, key)
			sp.mu.Unlock()
			return nil, err
		}
	}
	sp.inflight[key] = true
	sp.mu.Unlock()
	defer func() {
		sp.mu.Lock()
		delete(sp.inflight, key)
		sp.mu.Unlock()
	}()

	if sw.Volume == "" {
		vid, err := sp.fly.CreateVolume(in.Region, gb)
		if err != nil {
			return nil, serve.Fail(502, "fly volume: %v", err)
		}
		sp.mu.Lock()
		sw.Volume, sw.DiskGB = vid, gb
		err = sp.save()
		sp.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	rj, _ := json.Marshal(rd)
	// the machine checks the kernel's identities against the root key's roster (machine/kernelboot.go)
	env := map[string]string{"JARVIS2_SOURCE": string(c.Succ), "JARVIS2_KERNEL_ROSTER": string(rj), "JARVIS2_KERNEL_ROOT": sp.trust.Root()}
	for k, v := range sp.env {
		env[k] = v
	}
	id, err := sp.fly.Create(c.Source.Image, in.Region, map[string]any{"cpu_kind": kind, "cpus": cpus, "memory_mb": mem}, env, sw.Volume, key)
	if err == nil && crashAfterCreate != nil {
		crashAfterCreate()
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if err != nil {
		// a lost answer may still have made it
		if ids, ferr := sp.fly.Find(key); ferr == nil && len(ids) > 0 {
			return adopt(sw, ids[0])
		} else if ferr != nil {
			return nil, serve.Fail(502, "fly create: %v (and the lookup for it: %v; the next try looks again)", err, ferr)
		}
		if sp.fly.DeleteVolume(sw.Volume) != nil {
			sp.orphans[sw.Volume] = true
		}
		delete(sp.spawns, key)
		sp.save()
		return nil, serve.Fail(502, "fly create: %v", err)
	}
	return adopt(sw, id)
}

// Init: one try at reading a created machine's keys (409 while it isn't up yet: the router retries) → its cert
func (sp *Spawner) Init(id string) (sig.Doc, error) {
	sp.mu.Lock()
	m := sp.machines[id]
	sp.mu.Unlock()
	switch {
	case m == nil:
		return sig.Doc{}, serve.Fail(404, "machine %s isn't one the spawner made", id)
	case m.Killed:
		return sig.Doc{}, serve.Fail(409, "machine %s was killed", id)
	case m.Cert != nil:
		return *m.Cert, nil
	}
	fm, err := sp.fly.Inspect(id)
	if err != nil {
		return sig.Doc{}, serve.Fail(502, "fly: %v", err)
	}
	if fm.State != "started" {
		return sig.Doc{}, serve.Fail(409, "machine %s is %s, not started", id, fm.State)
	}
	if reportedDigest(fm.Image) != imageDigest(m.Content.Image) {
		return sig.Doc{}, serve.Fail(409, "machine %s runs %s, not its source's %s", id, fm.Image, m.Content.Image)
	}
	k, err := sp.fly.Init(id)
	if err != nil {
		return sig.Doc{}, serve.Fail(502, "fly exec init: %v", err)
	}
	keys := doc.Keys{SigningKey: k.SigningKey, EncryptionKey: k.EncryptionKey}
	c := doc.Cert{Kind: "succession", Pred: m.Source, Succ: doc.Object("fly-" + id), Pair: perm.Top(),
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
	if m.Killed || m.Cert != nil {
		return sig.Doc{}, serve.Fail(409, "machine %s was killed or initialised meanwhile", id)
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
	Sha256   string `json:"sha256"`
	Sig      string `json:"sig"`
	Required bool   `json:"required"` // keep the machine rather than kill it without this snapshot vouched for
}

var hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Kill: the machine destroyed (409 until Fly reports it), its volume deleted → (fly-M, source-y, ⊤); the same
// answer again for a machine already killed
func (sp *Spawner) Kill(id string, snap *Snapshot) (sig.Doc, error) {
	sp.mu.Lock()
	m := sp.machines[id]
	sp.mu.Unlock()
	if m == nil {
		return sig.Doc{}, serve.Fail(404, "machine %s isn't one the spawner made", id)
	}
	if m.KillCert != nil {
		return *m.KillCert, nil
	}
	sum := ""
	if snap != nil && snap.Sha256 != "" {
		switch {
		case m.Keys == nil:
			if snap.Required {
				return sig.Doc{}, serve.Fail(409, "machine %s never came up, so it signed no snapshot", id)
			}
		case !hex64RE.MatchString(snap.Sha256) || !sig.Verify(m.Keys.SigningKey, []byte(snap.Sha256), snap.Sig):
			if snap.Required {
				return sig.Doc{}, serve.Fail(409, "machine %s is kept, not killed: its snapshot isn't signed by its key", id)
			}
		default:
			sum = snap.Sha256
		}
	} else if snap != nil && snap.Required {
		return sig.Doc{}, serve.Fail(409, "machine %s is kept, not killed: no snapshot", id)
	}
	fm, err := sp.fly.Inspect(id)
	if err != nil {
		return sig.Doc{}, serve.Fail(502, "fly: %v", err)
	}
	if fm.State != "destroyed" {
		derr := sp.fly.Destroy(id)
		if fm, err = sp.fly.Inspect(id); err != nil {
			return sig.Doc{}, serve.Fail(502, "fly: %v", err)
		}
		if fm.State != "destroyed" {
			return sig.Doc{}, serve.Fail(409, "machine %s is %s, not destroyed yet (destroy: %v)", id, fm.State, derr)
		}
	}
	var d sig.Doc
	if m.Keys == nil { // never up: no state, nothing goes on from it
		d, err = sp.s.SignJSON(map[string]any{"kind": "killed", "id": id, "up": false})
	} else {
		b := make([]byte, 16)
		rand.Read(b)
		// a machine that signed no snapshot passes on the one its source named: it has no newer state the spawner
		// vouched for (the router kills a booted machine without one only when told to)
		src := m.Content
		if sum != "" {
			src.Snapshot = sum
		}
		c := doc.Cert{Kind: "succession", Pred: doc.Object("fly-" + id), Succ: doc.NewSource(b), Pair: perm.Top(),
			Source: &src, Signer: doc.BySpawner, IssuedAt: doc.Now()}
		if err := c.Check(); err != nil {
			return sig.Doc{}, err
		}
		d, err = sp.s.SignJSON(c)
	}
	if err != nil {
		return sig.Doc{}, err
	}
	sp.mu.Lock()
	m.Killed, m.KillCert = true, &d
	if m.Volume != "" {
		sp.orphans[m.Volume] = true
	}
	err = sp.save()
	sp.mu.Unlock()
	if err != nil {
		return sig.Doc{}, err
	}
	sp.dropVolumes()
	log.Printf("machine %s killed (snapshot %q)", id, sum)
	return d, nil
}

// dropVolumes: every volume of a killed machine (and earlier failed deletes); a failure is tried at the next kill
func (sp *Spawner) dropVolumes() {
	sp.mu.Lock()
	todo := []string{}
	for v := range sp.orphans {
		todo = append(todo, v)
	}
	sp.mu.Unlock()
	for _, v := range todo {
		if err := sp.fly.DeleteVolume(v); err != nil && !strings.Contains(err.Error(), "HTTP 404") {
			log.Printf("volume %s: delete: %v (tried again at the next kill)", v, err)
			continue
		}
		sp.mu.Lock()
		delete(sp.orphans, v)
		sp.save()
		sp.mu.Unlock()
	}
}

// Extend: the live machine's volume grows to sizeGB (More disk) → {kind: "extended", id, sizeGb, needsRestart}
func (sp *Spawner) Extend(id string, sizeGB int) (any, error) {
	sp.mu.Lock()
	m := sp.machines[id]
	sp.mu.Unlock()
	if m == nil || m.Killed || m.Volume == "" {
		return nil, serve.Fail(409, "machine %s has no live volume of the spawner's", id)
	}
	if sizeGB <= m.DiskGB || sizeGB > maxDiskGB {
		return nil, serve.Fail(400, "sizeGb: more than the volume's %d GB, at most %d", m.DiskGB, maxDiskGB)
	}
	restart, err := sp.fly.ExtendVolume(m.Volume, sizeGB)
	if err != nil {
		return nil, serve.Fail(502, "fly volume extend: %v", err)
	}
	sp.mu.Lock()
	m.DiskGB = sizeGB
	sp.save()
	sp.mu.Unlock()
	return map[string]any{"kind": "extended", "id": id, "volume": m.Volume, "sizeGb": sizeGB, "needsRestart": restart}, nil
}

func Register(s *serve.Server, sp *Spawner) {
	serve.Handle(s, "POST /fly-token", func(in struct {
		Sealed sig.Sealed `json:"sealed"`
	}) (any, error) {
		return sp.SetFlyToken(in.Sealed)
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
	serve.Handle(s, "POST /extend", func(in struct {
		ID     string `json:"id"`
		SizeGB int    `json:"sizeGb"`
	}) (any, error) {
		return sp.Extend(in.ID, in.SizeGB)
	})
}
