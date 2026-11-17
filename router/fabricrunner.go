package main

// The fabric runner (docs/PLAN-fabric.md): a session's machines are gVisor sandboxes on aviary's fabric, started by
// the fabric hermit through the kernel's spawner (kernel/spawner/fabric.go). Each session has one conversation at
// hermit for its life (its /workspace and home on the fabric's network filesystem), made here at its first fabric
// spawn and named in every spawn after.
//
// hermit's contract passes no environment to a sandbox, so the spawner's answer carries the machine's env and the
// router serves it: the fabric image's entrypoint asks GET /fabric/env on the fabric listener (the fabric's egress
// address leads there) with its sandbox token, hermit's hst1 token from its boot environment's proxy URL, which the
// router checks against hermit's published keys. Nothing in the env is secret: the machine's keys line and the
// spawner's cert are the trust path, as on the other runners. The same listener serves the machines' /m routes.
//
//	FABRIC_HERMIT_URL          the fabric hermit inside the cluster (unset: no fabric runner, nothing here runs)
//	FABRIC_HERMIT_TOOLS_TOKEN  hermit's pair token of the caller tools (GET /v1/sandbox-token-keys)
//	FABRIC_HERMIT_MAGPIE_TOKEN hermit's pair token of the caller magpie for the router (a session's files deleted at Destroy)
//	FABRIC_MACHINE_ADDR        the fabric listener (the fabric's egress target), e.g. :3128
//	FABRIC_SESSION_IMAGE       the fabric image a fabric session's sources name (ghcr.io/de0ch/jarvis4-session-fabric@sha256:…,
//	                           the digest hermit's configuration starts), and FABRIC_SESSION_IMAGE_SIG CI's signature over it

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FabricLine: a fabric session's conversation at hermit, and its current machine's env (from the spawner's answer)
type FabricLine struct {
	Conversation string            `json:"conversation"`
	Machine      string            `json:"machine,omitempty"`
	Env          map[string]string `json:"env,omitempty"`
}

// fabricEnabled: the router has a fabric hermit to send sessions to
func fabricEnabled() bool { return os.Getenv("FABRIC_HERMIT_URL") != "" }

// fabricRegion: the region a fabric spawn names (the spawner wants one; hermit's hosts are where its config says)
const fabricRegion = "fra"

// newConversation: a random lowercase UUID v4 (the session's conversation at hermit)
func newConversation() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// sourceImage: the image a new source of the session names: the fabric image for a fabric session, else the session
// image (the phone checks CI's signature over either: ios KernelChecks.pinned)
func (r *Router) sourceImage(s *Session) string {
	if r.runnerOf(s) == "fabric" {
		if f := os.Getenv("FABRIC_SESSION_IMAGE"); f != "" {
			return f
		}
	}
	return r.cfg.SessionImage
}

// isFabricSession: the session's machines run on the fabric
func (r *Router) isFabricSession(id string) (yes bool) {
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[id]; s != nil {
			yes = s.Fabric != nil
		}
	})
	return
}

// deleteFabricFiles: DELETE /v1/workspaces/{conversation} as caller magpie: the session's /workspace and its other
// folders (the home) at the fabric hermit, after its archive (a destroy's last machine sent its whole state). hermit
// releases a live sandbox of the conversation first and answers 204 also when nothing is there.
var deleteFabricFiles = func(conversation string) error {
	req, _ := http.NewRequest("DELETE", strings.TrimRight(os.Getenv("FABRIC_HERMIT_URL"), "/")+"/v1/workspaces/"+conversation, nil)
	req.Header.Set("Authorization", "Bearer "+os.Getenv("FABRIC_HERMIT_MAGPIE_TOKEN"))
	req.Header.Set("Aviary-Protocol", "hermit-core=1")
	res, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return fmt.Errorf("hermit: HTTP %d %s", res.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (r *Router) deleteFabricFiles(conversation string) error { return deleteFabricFiles(conversation) }

// fabricLine: the session's fabric line, its conversation made on first use
func (r *Router) fabricLine(sid string) (*FabricLine, error) {
	var out *FabricLine
	r.st.Do(func(d *persisted) {
		s := d.Sessions[sid]
		if s == nil {
			return
		}
		if s.Fabric == nil {
			s.Fabric = &FabricLine{Conversation: newConversation()}
		}
		cp := *s.Fabric
		out = &cp
	})
	if out == nil {
		return nil, fmt.Errorf("no session %s", sid)
	}
	return out, nil
}

// setFabricMachine: the machine the spawner made for the session, and the env it is to get
func (r *Router) setFabricMachine(sid, machine string, env map[string]string) {
	r.st.Do(func(d *persisted) {
		if s := d.Sessions[sid]; s != nil && s.Fabric != nil {
			s.Fabric.Machine, s.Fabric.Env = machine, env
		}
	})
}

// ---- hermit's sandbox token (aviary crates/hermit-api/src/token.rs) ------------------------------------------------

// hstClaims: what a sandbox token says
type hstClaims struct {
	Sandbox, Conversation string // lowercase hyphenated UUIDs
	Expires               time.Time
}

const hstContext = "hermit-sandbox-token\x00"

func uuidText(b []byte) string {
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// verifyHST: `hst1.<kid>.<payload>.<sig>` checked against keys (kid → Ed25519 public key) at now
func verifyHST(tok string, keys map[uint32]ed25519.PublicKey, now time.Time) (hstClaims, error) {
	var c hstClaims
	if len(tok) > 600 {
		return c, errors.New("token too long")
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 4 || parts[0] != "hst1" {
		return c, errors.New("not a sandbox token")
	}
	kid, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return c, errors.New("bad kid")
	}
	key := keys[uint32(kid)]
	if key == nil {
		return c, fmt.Errorf("unknown kid %d", kid)
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(parts[2])
	sig, err2 := base64.RawURLEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return c, errors.New("bad encoding")
	}
	if !ed25519.Verify(key, append([]byte(hstContext), payload...), sig) {
		return c, errors.New("bad signature")
	}
	const fixed = 1 + 16 + 16 + 4 + 8
	if len(payload) < fixed+1 || payload[0] != 1 {
		return c, errors.New("bad payload")
	}
	c.Sandbox, c.Conversation = uuidText(payload[1:17]), uuidText(payload[17:33])
	c.Expires = time.Unix(int64(binary.BigEndian.Uint64(payload[37:45])), 0)
	if !now.Before(c.Expires) {
		return c, errors.New("token expired")
	}
	return c, nil
}

// hermitKeys: hermit's token keys, fetched at most every 5 minutes (a kid it doesn't know fetches again)
type hermitKeys struct {
	mu   sync.Mutex
	at   time.Time
	keys map[uint32]ed25519.PublicKey
	get  func() (map[uint32]ed25519.PublicKey, error)
}

func (h *hermitKeys) current(force bool) (map[uint32]ed25519.PublicKey, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.keys != nil && !force && time.Since(h.at) < 5*time.Minute {
		return h.keys, nil
	}
	k, err := h.get()
	if err != nil {
		if h.keys != nil {
			return h.keys, nil
		}
		return nil, err
	}
	h.keys, h.at = k, time.Now()
	return k, nil
}

// fetchHermitKeys: GET /v1/sandbox-token-keys as caller tools
func fetchHermitKeys() (map[uint32]ed25519.PublicKey, error) {
	req, _ := http.NewRequest("GET", strings.TrimRight(os.Getenv("FABRIC_HERMIT_URL"), "/")+"/v1/sandbox-token-keys", nil)
	req.Header.Set("Authorization", "Bearer "+os.Getenv("FABRIC_HERMIT_TOOLS_TOKEN"))
	req.Header.Set("Aviary-Protocol", "hermit-core=1")
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("hermit token keys: HTTP %d", res.StatusCode)
	}
	return parseHermitKeys(io.LimitReader(res.Body, 64<<10))
}

func parseHermitKeys(r io.Reader) (map[uint32]ed25519.PublicKey, error) {
	var v struct {
		Keys []struct {
			Kid       uint32 `json:"kid"`
			Alg       string `json:"alg"`
			PublicKey string `json:"publicKey"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(r).Decode(&v); err != nil {
		return nil, err
	}
	out := map[uint32]ed25519.PublicKey{}
	for _, k := range v.Keys {
		b, err := base64.RawURLEncoding.DecodeString(k.PublicKey)
		if k.Alg == "Ed25519" && err == nil && len(b) == ed25519.PublicKeySize {
			out[k.Kid] = b
		}
	}
	return out, nil
}

// ---- the env a fabric machine asks for ------------------------------------------------------------------------------

// fabricEnvFor: the env of the session whose current fabric machine is the token's sandbox, with the runner's two
// names added. The token's conversation must be that session's.
func (r *Router) fabricEnvFor(c hstClaims) (map[string]string, bool) {
	machine := "x" + strings.ReplaceAll(c.Sandbox, "-", "")
	var env map[string]string
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			if f := s.Fabric; f != nil && f.Machine == machine && f.Conversation == c.Conversation && f.Env != nil {
				env = map[string]string{}
				for k, v := range f.Env {
					env[k] = v
				}
			}
		}
	})
	if env == nil {
		return nil, false
	}
	env["JARVIS2_RUNNER"], env["JARVIS2_MACHINE_ID"] = "fabric", machine
	return env, true
}

// fabricEnvHandler: GET /fabric/env with `Authorization: Bearer <hst1 token>`
func (r *Router) fabricEnvHandler(keys *hermitKeys) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		tok, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
		if !ok {
			writeJSON(w, 401, map[string]string{"error": "a sandbox token is needed"})
			return
		}
		ks, err := keys.current(false)
		if err != nil {
			writeJSON(w, 503, map[string]string{"error": "hermit's token keys: " + err.Error()})
			return
		}
		c, err := verifyHST(tok, ks, time.Now())
		if err != nil && strings.HasPrefix(err.Error(), "unknown kid") {
			if ks, err2 := keys.current(true); err2 == nil {
				c, err = verifyHST(tok, ks, time.Now())
			}
		}
		if err != nil {
			writeJSON(w, 401, map[string]string{"error": err.Error()})
			return
		}
		env, ok := r.fabricEnvFor(c)
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "no session's machine is this sandbox"})
			return
		}
		writeJSON(w, 200, map[string]any{"env": env})
	}
}

// FabricMachineHandler: the fabric listener: the machines' /m routes and GET /fabric/env
func (r *Router) FabricMachineHandler(keys *hermitKeys) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /fabric/env", r.fabricEnvHandler(keys))
	mux.Handle("/", r.MachineHandler())
	return mux
}
