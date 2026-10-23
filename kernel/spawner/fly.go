package spawner

// The Fly Machines API, used only by the spawner, the only holder of the Fly token (sealed to it by the setup
// session: POST /fly-token). The token is narrowed to app jarvis4-sessions and to one command inside a machine:
// jarvis2-init, with no arguments, whose output is the machine's public keys, so their link to the machine is Fly's
// word, not the machine's or the router's. Volumes are made with Fly's automatic backups off: a session's state is
// its signed snapshot only (Deyao, 2026-10-21: "let's not keep volume backups").

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// MachineKeys: what jarvis2-init prints
type MachineKeys struct {
	EncryptionKey string `json:"encryptionKey"`
	SigningKey    string `json:"signingKey"`
}

// FlyMachine: a machine's state and the image Fly runs (registry/repository@sha256:…)
type FlyMachine struct {
	State string
	Image string
}

// Fly: single calls, no waiting or retrying (the router retries)
type Fly interface {
	Configure(token string)
	CreateVolume(region string, sizeGB int) (string, error)
	// Create: a machine whose Fly metadata names the spawn it is for (spawnKey: the cert's id), so a spawn whose
	// answer was lost (a crash, a timeout) finds it again with Find instead of making a second one
	Create(image, region string, guest map[string]any, env map[string]string, volume, spawnKey string) (string, error)
	// Find: the machines (not destroyed) whose metadata names spawnKey
	Find(spawnKey string) ([]string, error)
	Inspect(id string) (FlyMachine, error)
	Init(id string) (MachineKeys, error)
	Destroy(id string) error
	// Start: a stopped machine started again (its config, image and volume unchanged)
	Start(id string) error
	DeleteVolume(volume string) error
	ExtendVolume(volume string, sizeGB int) (needsRestart bool, err error)
}

// the session image's one command the spawner may run (session-image/Dockerfile); the Fly token allows only it
const initPath = "/usr/local/bin/jarvis2-init"

// FlyApp: the one Fly app the spawner makes machines in
const FlyApp = "jarvis4-sessions"

// spawnMeta: the Fly metadata key naming the spawn a machine is for
const spawnMeta = "jarvis4_spawn"

const (
	volumePath = "/data" // where the machine finds its volume (machine/volume.go)
	volumeName = "jarvis4_state"
)

// ---- machine sizes (the same block is in router/sizes.go, core/fly.go, kernel/spawner/fly.go and machine/deliver.go; TestSizeBlocksMatch) ----

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

type FlyAPI struct {
	mu    sync.Mutex
	token string
	base  string
	http  *http.Client
}

func NewFlyAPI() *FlyAPI {
	return &FlyAPI{base: "https://api.machines.dev/v1", http: &http.Client{}}
}

func (f *FlyAPI) Configure(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.token = token
}

func (f *FlyAPI) call(method, path string, body any, out any) error {
	f.mu.Lock()
	token := f.token
	f.mu.Unlock()
	if token == "" {
		return fmt.Errorf("the spawner has no Fly token yet (infra/setup.py sends it)")
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.base+"/apps/"+FlyApp+path, rd)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t := strings.TrimSpace(string(b))
		return fmt.Errorf("%s %s: HTTP %d %s", method, path, resp.StatusCode, t[:min(300, len(t))])
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (f *FlyAPI) CreateVolume(region string, sizeGB int) (string, error) {
	var v struct {
		ID string `json:"id"`
	}
	body := map[string]any{"name": volumeName, "region": region, "size_gb": sizeGB, "encrypted": true,
		"snapshot_retention": 1, "auto_backup_enabled": false, "require_unique_zone": false}
	if err := f.call("POST", "/volumes", body, &v); err != nil {
		return "", err
	}
	if v.ID == "" {
		return "", fmt.Errorf("fly made no volume")
	}
	return v.ID, nil
}

func (f *FlyAPI) Create(image, region string, guest map[string]any, env map[string]string, volume, spawnKey string) (string, error) {
	var m struct {
		ID string `json:"id"`
	}
	config := map[string]any{"image": image, "guest": guest, "env": env, "restart": map[string]any{"policy": "no"},
		"metadata": map[string]string{spawnMeta: spawnKey}}
	if volume != "" {
		config["mounts"] = []map[string]any{{"volume": volume, "path": volumePath}}
	}
	if err := f.call("POST", "/machines", map[string]any{"region": region, "config": config}, &m); err != nil {
		return "", err
	}
	return m.ID, nil
}

func (f *FlyAPI) Find(spawnKey string) ([]string, error) {
	var ms []struct {
		ID     string `json:"id"`
		State  string `json:"state"`
		Config struct {
			Metadata map[string]string `json:"metadata"`
		} `json:"config"`
	}
	if err := f.call("GET", "/machines?metadata."+spawnMeta+"="+url.QueryEscape(spawnKey), nil, &ms); err != nil {
		return nil, err
	}
	ids := []string{}
	for _, m := range ms { // the filter is Fly's; checked again here
		if m.Config.Metadata[spawnMeta] == spawnKey && m.State != "destroyed" && m.State != "destroying" {
			ids = append(ids, m.ID)
		}
	}
	return ids, nil
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
			return FlyMachine{State: "destroyed"}, nil // Fly forgets a machine some time after it is destroyed
		}
		return FlyMachine{}, err
	}
	image := m.Config.Image
	if m.ImageRef.Digest != "" {
		image = m.ImageRef.Registry + "/" + m.ImageRef.Repository + "@" + m.ImageRef.Digest
	}
	return FlyMachine{State: m.State, Image: image}, nil
}

// Init: jarvis2-init waits for the machine's keys (made at boot), prints them and lets boot go on. One run.
func (f *FlyAPI) Init(id string) (MachineKeys, error) {
	var out struct {
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		ExitCode int    `json:"exit_code"`
	}
	var k MachineKeys
	if err := f.call("POST", "/machines/"+id+"/exec", map[string]any{"command": []string{initPath}, "timeout": 60}, &out); err != nil {
		return k, err
	}
	if out.ExitCode != 0 {
		return k, fmt.Errorf("exit %d: %s", out.ExitCode, strings.TrimSpace(out.Stderr))
	}
	if json.Unmarshal([]byte(strings.TrimSpace(out.Stdout)), &k) != nil || k.EncryptionKey == "" || k.SigningKey == "" {
		return k, fmt.Errorf("jarvis2-init gave no keys")
	}
	return k, nil
}

func (f *FlyAPI) Destroy(id string) error {
	return f.call("DELETE", "/machines/"+id+"?force=true", nil, nil)
}

func (f *FlyAPI) Start(id string) error {
	return f.call("POST", "/machines/"+id+"/start", nil, nil)
}

func (f *FlyAPI) DeleteVolume(volume string) error {
	return f.call("DELETE", "/volumes/"+volume, nil, nil)
}

func (f *FlyAPI) ExtendVolume(volume string, sizeGB int) (bool, error) {
	var out struct {
		NeedsRestart bool `json:"needs_restart"`
	}
	err := f.call("PUT", "/volumes/"+volume+"/extend", map[string]any{"size_gb": sizeGB}, &out)
	return out.NeedsRestart, err
}
