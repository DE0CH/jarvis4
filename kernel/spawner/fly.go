package spawner

// The Fly Machines API, used only by the spawner, the only holder of the Fly token (sealed to it by the setup
// session: POST /fly-token). The token is narrowed to app jarvis4-sessions and to one command inside a machine:
// jarvis2-init, with no arguments, whose output is the machine's public keys, so their link to the machine is Fly's
// word, not the machine's or the router's. Volumes are made with Fly's automatic backups off: a session's state is
// its signed snapshot only (Deyao, 2026-10-21: "let's not keep volume backups").

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// MachineKeys: what jarvis2-init prints
type MachineKeys struct {
	EncryptionKey string `json:"encryptionKey"`
	SigningKey    string `json:"signingKey"`
}

// FlyMachine: a machine's state, the image Fly runs (registry/repository@sha256:…), the volume it mounts and the
// source its Fly metadata names (SourceMeta; "" on a machine the spawner didn't make)
type FlyMachine struct {
	State  string
	Image  string
	Volume string
	Source string
}

// Fly: single calls, no waiting or retrying (the router retries)
type Fly interface {
	Configure(token string)
	// CreateVolume: an empty volume; guest is the machine's size, Fly's hint to put the volume on a host with room for
	// that machine (a volume is pinned to its host)
	CreateVolume(region string, sizeGB int, guest map[string]any) (string, error)
	// Create: a machine whose Fly metadata names the source it is from, so the router (with its read-only token)
	// finds one whose answer was lost
	Create(image, region string, guest map[string]any, env map[string]string, volume, source string) (string, error)
	Inspect(id string) (FlyMachine, error)
	Init(id string) (MachineKeys, error)
	Destroy(id string) error
	DeleteVolume(volume string) error
}

// FlyError: Fly's refusal: its HTTP status and the "status" word of its JSON answer (e.g. volume_placement_capacity)
type FlyError struct {
	HTTP   int
	Status string
	Msg    string
}

func (e *FlyError) Error() string { return e.Msg }

// flyStatus: the refusal's HTTP status and Fly's status word (0, "" when err isn't Fly's refusal)
func flyStatus(err error) (int, string) {
	var fe *FlyError
	if errors.As(err, &fe) {
		return fe.HTTP, fe.Status
	}
	return 0, ""
}

// the session image's one command the spawner may run (session-image/Dockerfile); the Fly token allows only it
const initPath = "/usr/local/bin/jarvis2-init"

// FlyApp: the one Fly app the spawner makes machines in
const FlyApp = "jarvis4-sessions"

// SourceMeta: the Fly metadata key naming the source a machine is from (the router lists machines by it)
const SourceMeta = "jarvis4_source"

const (
	volumePath = "/data" // where the machine finds its volume (machine/volume.go)
	volumeName = "jarvis4_state"
)

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
		return errNoToken
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
		var st struct {
			Status string `json:"status"`
		}
		json.Unmarshal(b, &st)
		return &FlyError{HTTP: resp.StatusCode, Status: st.Status, Msg: fmt.Sprintf("%s %s: HTTP %d %s", method, path, resp.StatusCode, t[:min(300, len(t))])}
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// errNoToken: the spawner restarted and the setup session (or the app's Recover) hasn't sent the token again
var errNoToken = errors.New("the spawner has no Fly token yet (infra/setup.py sends it)")

func (f *FlyAPI) CreateVolume(region string, sizeGB int, guest map[string]any) (string, error) {
	var v struct {
		ID string `json:"id"`
	}
	body := map[string]any{"name": volumeName, "region": region, "size_gb": sizeGB, "encrypted": true,
		"snapshot_retention": 1, "auto_backup_enabled": false, "require_unique_zone": false, "compute": guest}
	if err := f.call("POST", "/volumes", body, &v); err != nil {
		return "", err
	}
	if v.ID == "" {
		return "", fmt.Errorf("fly made no volume")
	}
	return v.ID, nil
}

func (f *FlyAPI) Create(image, region string, guest map[string]any, env map[string]string, volume, source string) (string, error) {
	var m struct {
		ID string `json:"id"`
	}
	config := map[string]any{"image": image, "guest": guest, "env": env, "restart": map[string]any{"policy": "no"},
		"metadata": map[string]string{SourceMeta: source}, "mounts": []map[string]any{{"volume": volume, "path": volumePath}}}
	if err := f.call("POST", "/machines", map[string]any{"region": region, "config": config}, &m); err != nil {
		return "", err
	}
	return m.ID, nil
}

func (f *FlyAPI) Inspect(id string) (FlyMachine, error) {
	var m struct {
		State  string `json:"state"`
		Config struct {
			Image    string            `json:"image"`
			Metadata map[string]string `json:"metadata"`
			Mounts   []struct {
				Volume string `json:"volume"`
			} `json:"mounts"`
		} `json:"config"`
		ImageRef struct {
			Registry, Repository, Tag, Digest string
		} `json:"image_ref"`
	}
	if err := f.call("GET", "/machines/"+id, nil, &m); err != nil {
		if code, _ := flyStatus(err); code == 404 {
			return FlyMachine{State: "destroyed"}, nil // Fly forgets a machine some time after it is destroyed
		}
		return FlyMachine{}, err
	}
	fm := FlyMachine{State: m.State, Image: m.Config.Image, Source: m.Config.Metadata[SourceMeta]}
	if m.ImageRef.Digest != "" {
		fm.Image = m.ImageRef.Registry + "/" + m.ImageRef.Repository + "@" + m.ImageRef.Digest
	}
	if len(m.Config.Mounts) > 0 {
		fm.Volume = m.Config.Mounts[0].Volume
	}
	return fm, nil
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

func (f *FlyAPI) DeleteVolume(volume string) error {
	return f.call("DELETE", "/volumes/"+volume, nil, nil)
}
