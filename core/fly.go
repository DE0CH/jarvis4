package main

// The Fly Machines API, used only by start, init and kill. The token is held by the core alone (from a Recover
// bundle, or sealed to the core by the setup session) and is narrowed to this app and to one command inside a
// machine: jarvis2-init, with no arguments. Its output is the machine's public keys, so their link to the
// machine is Fly's guarantee, not anything the machine or the router says. The app is fixed here, in git: a
// token for any other app can't reach it (Fly app names are global, and only Deyao's org holds this one), so
// whoever hands the core a token can at worst hand it one that fails.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

type MachineKeys struct {
	EncryptionKey string `json:"encryptionKey"`
	SigningKey    string `json:"signingKey"`
}

// Fly: single calls, no waiting or retrying (the router retries; DESIGN "The core").
type Fly interface {
	Configure(token string) // from the core store (Recover) or SetFlyToken
	Create(r StartRequest, guest map[string]any, env map[string]string) (id string, err error)
	Inspect(id string) (FlyMachine, error) // its state and the image Fly runs (registry/repository@digest)
	Init(id string) (MachineKeys, error)   // one run of jarvis2-init; its output is the machine's public keys
	Destroy(id string) error
}

type FlyMachine struct {
	State string // created, starting, started, …, destroyed
	Image string // what Fly reports it runs: registry/repository@sha256:…
}

// the session image's one command the core may run (session-image/Dockerfile); the Fly token allows only it
const initPath = "/usr/local/bin/jarvis2-init"

// ---- machine sizes (the same block is in router/sizes.go, core/fly.go and machine/deliver.go, and its guest part in kernel/spawner/fly.go; TestSizeBlocksMatch) ----

// The sizes: small (2 GB), medium (4 GB), large (8 GB), then every doubling past large, named by its memory ("16gb",
// "32gb", …). Upgrade moves a session one step up, and there is no last step: a guest Fly can't make is Fly's to
// refuse, with its own error.
var namedSizes = map[string]int{"small": 2, "medium": 4, "large": 8}

// sizeMemGB: the size's memory in GB; 0 = not a size (the 1<<20 bound only keeps memory_mb an ordinary int)
func sizeMemGB(size string) int {
	if gb := namedSizes[size]; gb != 0 {
		return gb
	}
	n, err := strconv.Atoi(strings.TrimSuffix(size, "gb"))
	if err != nil || n < 16 || n > 1<<20 || n&(n-1) != 0 || strconv.Itoa(n)+"gb" != size {
		return 0
	}
	return n
}

// sizeGuest: the size's Fly guest. Fly takes at most 2 GB per shared CPU and 8 GB per performance CPU
// (fly.io/docs/machines/guides-examples/machine-sizing). The named three have one shared CPU per GB; 16 GB is the
// most a shared guest holds (8 CPUs × 2 GB); past it the guest is performance, with large's 8 CPUs or, once the
// memory needs more (8 GB each), memory/8 CPUs.
func sizeGuest(size string) (cpuKind string, cpus, memoryMB int) {
	gb := sizeMemGB(size)
	switch {
	case gb == 0:
		return "", 0, 0
	case gb <= 8:
		return "shared", gb, gb * 1024
	case gb <= 16:
		return "shared", 8, gb * 1024
	}
	return "performance", max(8, gb/8), gb * 1024
}

// nextSize: the size Upgrade moves to, twice the memory (a session with no size runs medium)
func nextSize(size string) string {
	gb := sizeMemGB(size)
	if gb == 0 {
		gb = namedSizes["medium"]
	}
	for name, n := range namedSizes {
		if n == 2*gb {
			return name
		}
	}
	return strconv.Itoa(2*gb) + "gb"
}

// sizeText: "large (8 GB)", "16 GB"
func sizeText(size string) string {
	if gb := namedSizes[size]; gb != 0 {
		return fmt.Sprintf("%s (%d GB)", size, gb)
	}
	return fmt.Sprintf("%d GB", sizeMemGB(size))
}

// ---- end of the machine sizes block ----

// FlyApp: the one Fly app the core makes machines in
const FlyApp = "jarvis4-sessions"

// the core's own signing key goes into every machine it creates (Fly config env): the machine trusts the
// core that made it, through Fly, which only the core's token can create machines with
const coreKeyEnv = "JARVIS2_CORE_KEY"

type FlyAPI struct {
	mu    sync.Mutex
	token string
	base  string
	http  *http.Client
}

func (f *FlyAPI) Configure(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.token = token
}

func (f *FlyAPI) ready() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.token == "" {
		return fmt.Errorf("the core has no Fly token yet (infra/setup.py backup-core sends it)")
	}
	return nil
}

func (f *FlyAPI) call(method, path string, body any, out any) error {
	if err := f.ready(); err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.base+"/apps/"+FlyApp+path, rd)
	f.mu.Lock()
	req.Header.Set("Authorization", "Bearer "+f.token)
	f.mu.Unlock()
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: HTTP %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(b))[:min(300, len(strings.TrimSpace(string(b))))])
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (f *FlyAPI) Create(r StartRequest, guest map[string]any, env map[string]string) (string, error) {
	return f.CreateWithVolume(r, guest, env, "", "")
}

// CreateWithVolume: Create with the volume mounted at path (volume "" = none)
func (f *FlyAPI) CreateWithVolume(r StartRequest, guest map[string]any, env map[string]string, volume, path string) (string, error) {
	var m struct {
		ID string `json:"id"`
	}
	config := map[string]any{"image": r.Image, "guest": guest, "env": env, "restart": map[string]any{"policy": "no"}}
	if volume != "" {
		config["mounts"] = []map[string]any{{"volume": volume, "path": path}}
	}
	if err := f.call("POST", "/machines", map[string]any{"region": r.Region, "config": config}, &m); err != nil {
		return "", err
	}
	return m.ID, nil
}

// ---- volumes (volumes.go; Fly Machines API /volumes) ----

// CreateVolume: Fly's daily automatic snapshots off (no volume snapshot of any kind: volumes.go)
func (f *FlyAPI) CreateVolume(region string, sizeGB int, guest map[string]any) (string, error) {
	var v struct {
		ID string `json:"id"`
	}
	body := map[string]any{"name": volumeName, "region": region, "size_gb": sizeGB, "encrypted": true,
		"auto_backup_enabled": false, "require_unique_zone": false}
	if guest != nil {
		// Fly places the volume on a host with room for a machine of this size: a volume is pinned to its host, and
		// without the hint Fly may pick one too full for the machine (412 volume_placement_capacity)
		body["compute"] = guest
	}
	if err := f.call("POST", "/volumes", body, &v); err != nil {
		return "", err
	}
	if v.ID == "" {
		return "", fmt.Errorf("fly made no volume")
	}
	return v.ID, nil
}

func (f *FlyAPI) ExtendVolume(volume string, sizeGB int) (bool, error) {
	var out struct {
		NeedsRestart bool `json:"needs_restart"`
	}
	err := f.call("PUT", "/volumes/"+volume+"/extend", map[string]any{"size_gb": sizeGB}, &out)
	return out.NeedsRestart, err
}

func (f *FlyAPI) DeleteVolume(volume string) error {
	return f.call("DELETE", "/volumes/"+volume, nil, nil)
}

func (f *FlyAPI) Inspect(id string) (FlyMachine, error) {
	var m struct {
		State  string `json:"state"`
		Config struct {
			Image string `json:"image"`
		} `json:"config"`
		ImageRef struct {
			Registry, Repository, Tag, Digest string
		} `json:"image_ref"`
	}
	if err := f.call("GET", "/machines/"+id, nil, &m); err != nil {
		if strings.Contains(err.Error(), "HTTP 404") {
			// Fly forgets a machine some time after it is destroyed: one it doesn't know is gone (a kill, or a line
			// taken over from an earlier core long after its pause: legacy.go)
			return FlyMachine{State: "destroyed"}, nil
		}
		return FlyMachine{}, err
	}
	image := m.Config.Image
	if m.ImageRef.Digest != "" {
		image = m.ImageRef.Registry + "/" + m.ImageRef.Repository + "@" + m.ImageRef.Digest
	}
	return FlyMachine{State: m.State, Image: image}, nil
}

func (f *FlyAPI) exec(id string, cmd []string, timeout int) (string, error) {
	var out struct {
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		ExitCode int    `json:"exit_code"`
	}
	if err := f.call("POST", "/machines/"+id+"/exec", map[string]any{"command": cmd, "timeout": timeout}, &out); err != nil {
		return "", err
	}
	if out.ExitCode != 0 {
		return out.Stdout, fmt.Errorf("exit %d: %s", out.ExitCode, strings.TrimSpace(out.Stderr))
	}
	return out.Stdout, nil
}

// Init: jarvis2-init waits for the machine's keys (made at boot), prints them and lets boot go on. One run.
func (f *FlyAPI) Init(id string) (MachineKeys, error) {
	var k MachineKeys
	out, err := f.exec(id, []string{initPath}, 60)
	if err != nil {
		return k, err
	}
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &k) != nil || k.EncryptionKey == "" || k.SigningKey == "" {
		return k, fmt.Errorf("jarvis2-init gave no keys")
	}
	return k, nil
}

func (f *FlyAPI) Destroy(id string) error {
	return f.call("DELETE", "/machines/"+id+"?force=true", nil, nil)
}
