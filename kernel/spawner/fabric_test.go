package spawner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/internal/kt"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

const fabricImg = FabricRepo + "@sha256:" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

// fakeHermit: the routes of hermit's contract the fabric runner calls (aviary docs/CONTRACTS.md), one sandbox per
// conversation, with the callers' tokens and headers checked as hermit's guard checks them
type fakeHermit struct {
	mu    sync.Mutex
	t     *testing.T
	n     int
	byCid map[string]*fakeSbx
	calls []string
	image string // what hermit says it started the sandbox on
}

type fakeSbx struct {
	id, state, phase, console string
}

func newFakeHermit(t *testing.T) (*fakeHermit, *httptest.Server) {
	h := &fakeHermit{t: t, byCid: map[string]*fakeSbx{}, image: strings.TrimPrefix(fabricImg, FabricRepo+"@")}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return h, srv
}

func (h *fakeHermit) sandbox(cid string) *fakeSbx {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.byCid[cid]
}

func (h *fakeHermit) set(cid string, f func(*fakeSbx)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f(h.byCid[cid])
}

func (h *fakeHermit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, r.Method+" "+r.URL.Path)
	fail := func(code int, c string) {
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]string{"code": c, "message": c})
	}
	if r.Header.Get("Aviary-Protocol") != "hermit-core=1" {
		fail(400, "unsupported_protocol")
		return
	}
	admin := strings.HasPrefix(r.URL.Path, "/v1/admin/")
	switch tok := r.Header.Get("Authorization"); {
	case admin && (tok != "Bearer admin-token" || r.Header.Get("Aviary-Admin") != "ops@example.org"):
		fail(403, "wrong_caller")
		return
	case !admin && tok != "Bearer magpie-token":
		fail(403, "wrong_caller")
		return
	}
	obj := func(s *fakeSbx) map[string]any {
		var phase any
		if s.phase != "" {
			phase = s.phase
		}
		return map[string]any{"id": s.id, "state": s.state, "phase": phase, "image": h.image, "busy": false}
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case len(parts) == 4 && parts[1] == "conversations" && parts[3] == "sandbox":
		s := h.byCid[parts[2]]
		switch r.Method {
		case "PUT":
			var in struct{ Person string }
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.Person != "deyao@example.org" {
				fail(403, "not_allowed")
				return
			}
			if s == nil || s.state == "gone" {
				h.n++
				s = &fakeSbx{id: "0190f6c2-5b1e-7a3c-9d4e-" + strings.Repeat("0", 11) + string(rune('0'+h.n)), state: "starting", phase: "capacity"}
				h.byCid[parts[2]] = s
			}
			w.WriteHeader(202)
			json.NewEncoder(w).Encode(obj(s))
		case "GET":
			if s == nil {
				fail(404, "no_sandbox")
				return
			}
			json.NewEncoder(w).Encode(obj(s))
		}
	case len(parts) == 5 && parts[1] == "admin" && parts[2] == "sandboxes":
		var s *fakeSbx
		for _, x := range h.byCid {
			if x.id == parts[3] {
				s = x
			}
		}
		switch {
		case s == nil:
			fail(404, "not_found")
		case parts[4] == "log" && r.Method == "GET":
			if s.console == "" {
				fail(404, "not_found")
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"sandboxId": s.id, "reason": "live", "text": s.console})
		case parts[4] == "release" && r.Method == "POST":
			if s.state == "gone" {
				fail(409, "sandbox_gone")
				return
			}
			s.state, s.phase = "releasing", ""
			json.NewEncoder(w).Encode(map[string]any{"released": 1})
		}
	default:
		fail(404, "not_found")
	}
}

type fabricRig struct {
	*rig
	h   *fakeHermit
	api *FabricAPI
}

func newFabricRig(t *testing.T) *fabricRig {
	r := newRig(t)
	h, srv := newFakeHermit(t)
	api := NewFabricAPI(srv.URL)
	r.sp.SetFabric(api, map[string]string{"JARVIS2_URL": "http://10.202.1.1:3128"})
	return &fabricRig{r, h, api}
}

func (r *fabricRig) credentials() {
	r.t.Helper()
	b, _ := json.Marshal(FabricCredentials{MagpieToken: "magpie-token", AdminToken: "admin-token", Admin: "ops@example.org", Person: "deyao@example.org"})
	sealed, err := sig.SealTo(r.w.C["spawner"].Identity.AgreementKey, b, infoFabric)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.sp.SetFabricCredentials(sealed); err != nil {
		r.t.Fatal(err)
	}
}

// fabricSource: a notarized new source with the fabric's image
func (r *fabricRig) fabricSource() (sig.Doc, sig.Doc) {
	src := kt.SourceContent("t")
	src.Image = fabricImg
	cert := r.w.Cert(doc.ByIPhone, doc.Sink, kt.Source(), perm.Pair{Allowed: perm.Only("store:a"), Conditions: []string{}}, src, nil)
	return cert, r.notarize(cert)
}

func (r *fabricRig) fabricInput(cid string) SpawnInput {
	cert, nz := r.fabricSource()
	in := r.input(cert, nz)
	in.Runner, in.Fabric = "fabric", &FabricInput{Conversation: cid}
	return in
}

const (
	cidA = "0190f6c2-4a0d-7b2c-8e1f-0a1b2c3d4e5f"
	cidB = "0190f6c2-4a0d-7b2c-8e1f-0a1b2c3d4e60"
)

// A machine on the fabric from its spawn to its kill: hermit's sandbox is the machine, its console carries the keys,
// its forced release is the kill, and the session's conversation never gets a second machine while one lives.
func TestFabricSpawnInitKill(t *testing.T) {
	r := newFabricRig(t)
	if _, err := r.sp.Spawn(r.fabricInput(cidA)); reason(err) != ReasonNoFabricKey {
		t.Fatalf("a spawn before the credentials: %v", err)
	}
	r.credentials()
	out, err := r.sp.Spawn(r.fabricInput(cidA))
	if err != nil {
		t.Fatal(err)
	}
	o := out.(map[string]any)
	id := o["id"].(string)
	if id != "x0190f6c25b1e7a3c9d4e000000000001" || runnerOf(id) != "fabric" || object(id) != doc.Object("fabric-"+id) || object(id).Kind() != "machine" {
		t.Fatalf("machine id %q, object %q", id, object(id))
	}
	if o["volume"] != "" {
		t.Fatalf("a fabric machine has no volume: %v", o["volume"])
	}
	// the env the machine must get, for the router to serve: its source, the roster, the root key, the router's address
	env := o["env"].(map[string]string)
	if env["JARVIS2_SOURCE"] != string(o["source"].(doc.Object)) || env["JARVIS2_KERNEL_ROOT"] == "" || env["JARVIS2_KERNEL_ROSTER"] == "" || env["JARVIS2_URL"] != "http://10.202.1.1:3128" {
		t.Fatalf("env %v", env)
	}
	// the same spawn again (its answer was lost): the same machine, nothing new at hermit
	again, err := r.sp.Spawn(r.fabricInput(cidA))
	if err == nil {
		t.Fatal("a new source on a live conversation's sandbox was taken")
	}
	r.rig.t.Helper()
	nin := r.fabricInput(cidB)
	first, err := r.sp.Spawn(nin)
	if err != nil {
		t.Fatal(err)
	}
	if again, err = r.sp.Spawn(nin); err != nil || again.(map[string]any)["id"] != first.(map[string]any)["id"] {
		t.Fatalf("a repeated spawn: %v %v", again, err)
	}
	// nothing went to Fly
	if len(r.fly.ms) != 0 || len(r.fly.vols) != 0 {
		t.Fatal("a fabric spawn reached Fly")
	}
	// being placed: not started; created on a host with its first process running (hermit's phase supervisor): up
	if _, err := r.sp.Init(id); reason(err) != ReasonNotStarted {
		t.Fatalf("init while hermit places it: %v", err)
	}
	r.h.set(cidA, func(s *fakeSbx) { s.phase = "supervisor" })
	if _, err := r.sp.Init(id); reason(err) != ReasonNotStarted {
		t.Fatalf("init before the keys line: %v", err)
	}
	mk, _ := sig.NewSigner()
	me, _ := sig.NewSigner()
	keys := `{"encryptionKey":"` + me.PublicKey() + `","signingKey":"` + mk.PublicKey() + `"}`
	r.h.set(cidA, func(s *fakeSbx) {
		s.console = "boot\n" + keysMark + `{"encryptionKey":"old","signingKey":"old"}` + "\nmore\n\n" + keysMark + keys + "\n"
	})
	d, err := r.sp.Init(id)
	if err != nil {
		t.Fatal(err)
	}
	c := mustPeek(d)
	if c.Succ != doc.Object("fabric-"+id) || c.Machine == nil || c.Machine.Image != fabricImg || c.Machine.SigningKey != mk.PublicKey() || c.Machine.EncryptionKey != me.PublicKey() {
		t.Fatalf("cert %+v", c)
	}
	// the conversation's sandbox is this machine: a second spawn on it is refused, another conversation's is not
	if _, err := r.sp.Spawn(r.fabricInput(cidA)); reason(err) != ReasonFabricBusy {
		t.Fatalf("a second machine on the session's files: %v", err)
	}
	// the kill: hermit's forced release of this sandbox; not destroyed until hermit says gone
	if _, err := r.sp.Kill(id, nil); reason(err) != ReasonNotDestroyed {
		t.Fatalf("kill while hermit releases it: %v", err)
	}
	if s := r.h.sandbox(cidA); s.state != "releasing" {
		t.Fatalf("the sandbox is %s", s.state)
	}
	r.h.set(cidA, func(s *fakeSbx) { s.state = "gone" })
	out, err = r.sp.Kill(id, nil)
	kd, left := killCert(t, out, err)
	kc, err := doc.OpenCert(kd, r.w.C["spawner"].Identity.SigningKey)
	if err != nil || kc.Pred != doc.Object("fabric-"+id) || kc.Source.Image != fabricImg || left != "" {
		t.Fatal(err, kc, left)
	}
	r.notarize(kd)
	// the session's next machine: the same conversation, a new sandbox, a new machine
	out, err = r.sp.Spawn(r.fabricInput(cidA))
	if err != nil {
		t.Fatal(err)
	}
	if id2 := out.(map[string]any)["id"].(string); id2 == id || runnerOf(id2) != "fabric" {
		t.Fatalf("the next machine is %q", id2)
	}
	// a restart keeps the machines and their conversations (a kill again answers the same cert; the tokens are sent
	// again, as the Fly token is)
	sp2, err := Open(r.path, r.w.C["spawner"], r.w.Trust, r.fly, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sp2.SetFabric(r.api, map[string]string{"JARVIS2_URL": "http://10.202.1.1:3128"})
	out, err = sp2.Kill(id, nil)
	if again, _ := killCert(t, out, err); again != kd {
		t.Fatal("a second kill signed another cert")
	}
	if got := sp2.conversationOf(id); got != cidA {
		t.Fatalf("the machine's conversation after a restart: %q", got)
	}
}

// What the fabric runner refuses: another runner's image, a spawn without its conversation, an image hermit did not
// start; and a spawner without the runner never sends a fabric machine's call to Fly.
func TestFabricRefuses(t *testing.T) {
	r := newFabricRig(t)
	r.credentials()
	// the session image on the fabric, the fabric image on Fly
	cert, nz := r.source()
	in := r.input(cert, nz)
	in.Runner, in.Fabric = "fabric", &FabricInput{Conversation: cidA}
	if _, err := r.sp.Spawn(in); err == nil || !strings.Contains(err.Error(), FabricRepo) {
		t.Fatalf("the session image on the fabric: %v", err)
	}
	fin := r.fabricInput(cidA)
	fin.Runner, fin.Fabric = "", nil
	if _, err := r.sp.Spawn(fin); err == nil || !strings.Contains(err.Error(), SessionRepo) {
		t.Fatalf("the fabric image on Fly: %v", err)
	}
	for _, bad := range []*FabricInput{nil, {Conversation: ""}, {Conversation: "../admin"}, {Conversation: strings.ToUpper(cidA)}} {
		in := r.fabricInput(cidA)
		in.Fabric = bad
		if _, err := r.sp.Spawn(in); err == nil {
			t.Fatalf("conversation %+v taken", bad)
		}
	}
	if len(r.h.calls) != 0 {
		t.Fatalf("a refused spawn reached hermit: %v", r.h.calls)
	}
	// hermit started the sandbox on another image than the source's: no cert
	out, err := r.sp.Spawn(r.fabricInput(cidA))
	if err != nil {
		t.Fatal(err)
	}
	id := out.(map[string]any)["id"].(string)
	r.h.mu.Lock()
	r.h.image = "sha256:" + strings.Repeat("d", 64)
	r.h.mu.Unlock()
	r.h.set(cidA, func(s *fakeSbx) { s.phase, s.console = "supervisor", keysMark+`{"encryptionKey":"e","signingKey":"s"}` })
	if _, err := r.sp.Init(id); reason(err) != ReasonWrongImage {
		t.Fatalf("init on another image: %v", err)
	}
	// hermit down: a fabric refusal the router may retry, not a Fly one
	r.api.URL = "http://127.0.0.1:1"
	if _, err := r.sp.Init(id); reason(err) != ReasonFabric {
		t.Fatalf("init with hermit down: %v", err)
	}
	// a spawner without the fabric runner (an older Deployment's env) holds the machine but calls nothing for it
	sp2, err := Open(r.path, r.w.C["spawner"], r.w.Trust, r.fly, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sp2.Init(id); reason(err) != ReasonNoFabricKey {
		t.Fatalf("init on a spawner without the runner: %v", err)
	}
	if len(r.fly.ms) != 0 {
		t.Fatal("a fabric machine's call reached Fly")
	}
}

func TestFabricIDs(t *testing.T) {
	sid := "0190f6c2-5b1e-7a3c-9d4e-1f2a3b4c5d6e"
	id := fabricMachineID(sid)
	if id != "x0190f6c25b1e7a3c9d4e1f2a3b4c5d6e" || fabricSandboxID(id) != sid || fabricSandboxID("0190f6c25b1e7a3c9d4e1f2a3b4c5d6e") != "" {
		t.Fatalf("%q %q", id, fabricSandboxID(id))
	}
	for id, want := range map[string]string{id: "fabric", "i-0abc1234def567890": "aws", "0190f6c25b1e7a": "fly", "0190f6c25b1e7a3c9d4e1f2a3b4c5d6e": "fly"} {
		if runnerOf(id) != want {
			t.Fatalf("%s: %s", id, runnerOf(id))
		}
	}
	if doc.Object("fabric-"+id).Kind() != "machine" || doc.Object("fabric-"+id).Runner() != "fabric" || doc.Object("fabric-"+id).MachineID() != id {
		t.Fatal("the fabric machine object")
	}
	if doc.Object("fabric-0190f6c25b1e7a3c9d4e1f2a3b4c5d6e").Kind() != "" {
		t.Fatal("a fabric object without the x")
	}
	for s, want := range map[fabricSandbox]string{{State: "starting", Phase: "capacity"}: "created", {State: "starting", Phase: "creating"}: "created",
		{State: "starting", Phase: "supervisor"}: "started", {State: "ready"}: "started", {State: "releasing"}: "destroying", {State: "gone"}: "destroyed"} {
		if got := fabricState(s); got != want {
			t.Fatalf("%+v: %s", s, got)
		}
	}
}
