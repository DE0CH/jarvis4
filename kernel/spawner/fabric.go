package spawner

// The fabric runner (docs/PLAN-fabric.md): a machine is a gVisor sandbox on aviary's fabric, started by the fabric
// hermit (DE0CH/aviary's hermit, an internal service of Jarvis 4's cluster) on one of its AWS hosts. The spawner is
// a client of hermit's contract (aviary docs/CONTRACTS.md "The hermit contract"), the only holder of its two pair
// tokens (sealed to it by the setup session: POST /fabric-credentials, memory only, handed over in the copy flip):
//
//	Create   PUT /v1/conversations/{cid}/sandbox {"person"} as caller magpie → the sandbox; its id is the machine's.
//	         cid is the session's conversation at hermit (its /workspace and home on the network filesystem), named
//	         by the router per spawn. hermit keeps one live sandbox per conversation, so a second machine on one
//	         session's files cannot be made.
//	Inspect  GET /v1/conversations/{cid}/sandbox: the sandbox's state in the spawner's words, the image hermit
//	         started it on.
//	Init     the keeper writes its keys line (keysMark) to its stdout, the sandbox's console, as an AWS machine
//	         writes it to the serial console; hermit's admin route GET /v1/admin/sandboxes/{id}/log answers a live
//	         sandbox's console as its host has it. Their link to the machine is hermit's and its host's word, as it is
//	         Fly's or EC2's on the other runners.
//	Destroy  POST /v1/admin/sandboxes/{id}/release (forced, this sandbox and no later one of the conversation).
//
// There is no volume: the session's files stay at hermit across machines and go only when the session is destroyed
// (the router's call, not a machine's end).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// FabricRepo: the only image a fabric machine runs, pinned by digest (the session image with aviary's sandbox image
// as a directory; hermit's configuration names the same digest)
const FabricRepo = "ghcr.io/de0ch/jarvis4-session-fabric"

var fabricImageRE = regexp.MustCompile(`^` + regexp.QuoteMeta(FabricRepo) + `(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@(sha256:[0-9a-f]{64})$`)

// fabricImageDigest: the digest of a fabric image reference, "" for any other reference
func fabricImageDigest(ref string) string {
	if m := fabricImageRE.FindStringSubmatch(ref); m != nil {
		return m[2]
	}
	return ""
}

// FabricCredentials: what POST /fabric-credentials opens: hermit's pair tokens for the callers magpie (a
// conversation's sandbox) and admin (a sandbox's console, its forced release), the operator the admin calls are
// audited as, and the person every sandbox is started for (one of hermit's catalogue)
type FabricCredentials struct {
	MagpieToken string `json:"magpieToken"`
	AdminToken  string `json:"adminToken"`
	Admin       string `json:"admin"`
	Person      string `json:"person"`
}

func (c FabricCredentials) ok() bool {
	return c.MagpieToken != "" && c.AdminToken != "" && c.Admin != "" && c.Person != ""
}

// FabricInput: what a spawn on the fabric names beside the cert: the session's conversation at hermit (a UUID). Not
// a trust element of the kernel's line: the session's files are hermit's to keep, as a Fly volume's are Fly's.
type FabricInput struct {
	Conversation string `json:"conversation"`
}

var (
	uuidRE      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	fabricIDRE  = regexp.MustCompile(`^x[0-9a-f]{32}$`)
	errNoFabric = errors.New("the spawner has no fabric credentials (POST /fabric-credentials)")
)

// Check: a lowercase UUID
func (f *FabricInput) Check() error {
	if !uuidRE.MatchString(f.Conversation) {
		return errors.New("fabric: conversation is a lowercase UUID")
	}
	return nil
}

// fabricMachineID: a sandbox's id as the machine's: "x" and the UUID's 32 hex digits (a machine object is
// fabric-x<32 hex>; the x tells it from a Fly machine id, which is hex only)
func fabricMachineID(sandbox string) string { return "x" + strings.ReplaceAll(sandbox, "-", "") }

// fabricSandboxID: the sandbox's UUID of a machine id
func fabricSandboxID(id string) string {
	if !fabricIDRE.MatchString(id) {
		return ""
	}
	id = id[1:]
	return id[0:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:]
}

// FabricError: hermit's refusal: the HTTP status and the envelope's code (HTTP 0: hermit did not answer)
type FabricError struct {
	HTTP int
	Code string
	Msg  string
}

func (e *FabricError) Error() string { return e.Msg }

// FabricAPI: hermit's contract as a Runner. conv: the conversation of a machine the spawner made (its state), which
// every call after the create needs: hermit's sandbox routes are by conversation.
type FabricAPI struct {
	URL  string // hermit's address inside the cluster
	HTTP *http.Client
	conv func(id string) string

	mu   sync.Mutex
	cred *FabricCredentials
}

func NewFabricAPI(url string) *FabricAPI {
	return &FabricAPI{URL: strings.TrimRight(url, "/"), HTTP: &http.Client{Timeout: 20 * time.Second}}
}

func (f *FabricAPI) Configure(c FabricCredentials) {
	f.mu.Lock()
	f.cred = &c
	f.mu.Unlock()
}

func (f *FabricAPI) configured() (FabricCredentials, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cred == nil {
		return FabricCredentials{}, errNoFabric
	}
	return *f.cred, nil
}

// fabricSandbox: hermit's sandbox object, the fields the spawner reads
type fabricSandbox struct {
	ID    string `json:"id"`
	State string `json:"state"`
	Phase string `json:"phase"`
	Image string `json:"image"`
}

// call: one call of hermit's core surface as caller magpie or admin → the status and the body (into out when 2xx)
func (f *FabricAPI) call(admin bool, method, path string, in, out any) (int, error) {
	c, err := f.configured()
	if err != nil {
		return 0, err
	}
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, f.URL+path, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Aviary-Protocol", "hermit-core=1")
	if in != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	if admin {
		req.Header.Set("Authorization", "Bearer "+c.AdminToken)
		req.Header.Set("Aviary-Admin", c.Admin)
	} else {
		req.Header.Set("Authorization", "Bearer "+c.MagpieToken)
	}
	res, err := f.HTTP.Do(req)
	if err != nil {
		return 0, &FabricError{Msg: fmt.Sprintf("hermit %s %s: %v", method, path, err)}
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode/100 != 2 {
		var env struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		json.Unmarshal(b, &env)
		return res.StatusCode, &FabricError{HTTP: res.StatusCode, Code: env.Code,
			Msg: fmt.Sprintf("hermit %s %s: %d %s %s", method, path, res.StatusCode, env.Code, env.Message)}
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return res.StatusCode, fmt.Errorf("hermit %s %s: %v", method, path, err)
		}
	}
	return res.StatusCode, nil
}

// Create: the conversation's sandbox, started if it has none → the machine id. A sandbox of the conversation that is
// already there is answered as it is (hermit's get-or-start): Spawn refuses an id it already holds. in.Image, the
// region, the size and the disk are hermit's configuration, not the call's; in.Env is not passed either (hermit's
// contract has no per-sandbox environment): the machine asks the router for it (docs/PLAN-fabric.md).
func (f *FabricAPI) Create(in CreateInput) (string, string, error) {
	c, err := f.configured()
	if err != nil {
		return "", "", err
	}
	if in.Fabric == nil {
		return "", "", errors.New("a fabric machine needs its conversation")
	}
	var s fabricSandbox
	if _, err := f.call(false, "PUT", "/v1/conversations/"+in.Fabric.Conversation+"/sandbox", map[string]string{"person": c.Person}, &s); err != nil {
		return "", "", err
	}
	id := fabricMachineID(s.ID)
	if !fabricIDRE.MatchString(id) {
		return "", "", fmt.Errorf("hermit answered a sandbox with the id %q", s.ID)
	}
	return id, "", nil
}

// fabricState: a sandbox's state in the spawner's words. A sandbox is up for the spawner (its first process runs, the
// keeper can write its keys) from hermit's phase supervisor on: hermit calls it ready only when the session's
// supervisor answers, which is after the machine has its cert.
func fabricState(s fabricSandbox) string {
	switch s.State {
	case "starting":
		if s.Phase == "supervisor" {
			return "started"
		}
		return "created"
	case "ready", "paused":
		return "started"
	case "releasing":
		return "destroying"
	case "gone":
		return "destroyed"
	}
	return s.State
}

// Inspect: the machine's sandbox as hermit has it. The conversation's sandbox being another one (a later start), or
// none at all, means this one is gone.
func (f *FabricAPI) Inspect(id string) (FlyMachine, error) {
	cid := ""
	if f.conv != nil {
		cid = f.conv(id)
	}
	if cid == "" {
		return FlyMachine{}, fmt.Errorf("no conversation known for fabric machine %s", id)
	}
	var s fabricSandbox
	if code, err := f.call(false, "GET", "/v1/conversations/"+cid+"/sandbox", nil, &s); err != nil {
		if code == 404 {
			return FlyMachine{State: "destroyed"}, nil
		}
		return FlyMachine{}, err
	}
	if fabricMachineID(s.ID) != id {
		return FlyMachine{State: "destroyed"}, nil
	}
	m := FlyMachine{State: fabricState(s)}
	if strings.HasPrefix(s.Image, "sha256:") {
		m.Image = FabricRepo + "@" + s.Image
	}
	return m, nil
}

// Init: the machine's keys line on the sandbox's console, the newest one hermit's host holds. Not there yet (the
// sandbox is still being placed, the keeper hasn't written it): errNotYet, and the router asks again.
func (f *FabricAPI) Init(id string) (MachineKeys, error) {
	var k MachineKeys
	sid := fabricSandboxID(id)
	if sid == "" {
		return k, fmt.Errorf("%q is no fabric machine id", id)
	}
	var tail struct {
		Text string `json:"text"`
	}
	if code, err := f.call(true, "GET", "/v1/admin/sandboxes/"+sid+"/log", nil, &tail); err != nil {
		if code == 404 {
			return k, errNotYet
		}
		return k, err
	}
	found := ""
	for _, line := range strings.Split(tail.Text, "\n") {
		if strings.Contains(line, keysMark) {
			found = line
		}
	}
	if found == "" {
		return k, errNotYet
	}
	k, _, err := keysFromLine(found)
	return k, err
}

// Destroy: the sandbox's forced release. One that hermit no longer has, or that is already going, is not an error:
// the caller looks (Inspect) for what became of it.
func (f *FabricAPI) Destroy(id string) error {
	sid := fabricSandboxID(id)
	if sid == "" {
		return fmt.Errorf("%q is no fabric machine id", id)
	}
	code, err := f.call(true, "POST", "/v1/admin/sandboxes/"+sid+"/release", map[string]string{"note": "jarvis: the machine's end"}, nil)
	if err != nil && (code == 404 || code == 409) {
		return nil
	}
	return err
}

// DeleteVolume: a fabric machine has no volume of its own
func (f *FabricAPI) DeleteVolume(string) error { return nil }
