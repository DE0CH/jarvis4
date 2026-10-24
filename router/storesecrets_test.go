package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// kernelStoreRouter: a box with no core (NO_CORE=1, the core's URL unreachable) whose kernel serves secrets-blue
// and secrets-green with the core's store routes (kernel/secrets/http.go); returns both colours' fakes
func kernelStoreRouter(t *testing.T) (*Router, *storeCore, *storeCore) {
	t.Helper()
	r, _, _ := storeRouter(t)
	blue, green := &storeCore{key: newTestKey()}, &storeCore{key: newTestKey()}
	bs, gs := httptest.NewServer(blue), httptest.NewServer(green)
	t.Cleanup(bs.Close)
	t.Cleanup(gs.Close)
	r.core = &CoreClient{base: "http://core.invalid:8090", http: http.DefaultClient}
	r.cfg.NoCore = true
	k := newKernelClient("http://%s.kernel.test")
	k.url = func(role string) string {
		switch role {
		case "secrets-blue":
			return bs.URL
		case "secrets-green":
			return gs.URL
		}
		return "http://" + role + ".kernel.invalid"
	}
	r.wireKernel(k)
	return r, blue, green
}

// on a box with no core every store path reaches the kernel's serving secrets: the setup session's listing and
// writes, the app's store pages and its relayed store calls, the identity a writer computes the store key from
func TestStoresGoToSecretsWithNoCore(t *testing.T) {
	r, blue, green := kernelStoreRouter(t)
	code, out := appDo(t, r, "GET", "/setup/stores/keys", "")
	if code != 200 || len(out["stores"].([]any)) != 3 {
		t.Fatalf("setup store list: %d %v", code, out)
	}
	if code, out := appDo(t, r, "GET", "/api/stores", ""); code != 200 || len(out["stores"].([]any)) != 3 {
		t.Fatalf("app store list: %d %v", code, out)
	}
	for _, p := range []string{"/setup/stores", "/api/core/stores", "/api/core/stores/versions"} {
		if code, out := appDo(t, r, "POST", p, `{"nonce":"n"}`); code == 503 || out["coreDown"] != nil {
			t.Fatalf("%s didn't reach secrets: %d %v", p, code, out)
		}
	}
	if code, out := appDo(t, r, "GET", "/setup/identity", ""); code != 200 || out["signingKey"] != blue.key.pub() {
		t.Fatalf("setup identity: %d %v", code, out)
	}
	if code, out := appDo(t, r, "GET", "/setup/store-key", ""); code != 200 || out["identity"] == nil || out["storeKey"] != nil { // secrets signs no store key: each writer computes P + K
		t.Fatalf("store key: %d %v", code, out)
	}
	body := strings.Replace(writeBody("a key"), `"sig"`, `"live":{"e":"LE","data":"LD"},"sig"`, 1)
	if code, out := appDo(t, r, "POST", "/setup/stores/infra/keys/K", body); code != 200 {
		t.Fatalf("setup write: %d %v", code, out)
	}
	if len(blue.writes) != 1 || blue.writes[0]["writer"] != "setup" || blue.writes[0]["live"] == nil {
		t.Fatalf("secrets got %v", blue.writes)
	}
	// a flip: every later store call goes to the other colour
	r.st.Do(func(d *persisted) { d.KernelSecrets = "green" })
	if code, _ := appDo(t, r, "POST", "/setup/stores/infra/keys/K2", writeBody("another")); code != 200 || len(green.writes) != 1 || len(blue.writes) != 1 {
		t.Fatalf("after the flip: %d blue %d green %d", code, len(blue.writes), len(green.writes))
	}
}

// a kernel session's machine writes with the grant it holds (secrets checks it), not a core cert
func TestAKernelSessionWritesWithItsGrant(t *testing.T) {
	r, blue, _ := kernelStoreRouter(t)
	addSession(r, "sK", "started", "mK", false)
	g := &gv.Signed{Grant: sig.Doc{Payload: `{"kind":"grant"}`, Sig: "G"}, By: "mover"}
	r.st.Do(func(d *persisted) {
		d.Sessions["sK"].Cert = nil
		d.Sessions["sK"].Kernel = &KernelLine{Grant: g, MachineCert: &sig.Doc{Payload: "{}"}}
	})
	m := newTestMachine(r, "mK")
	if code, out := m.do(t, r.MachineHandler(), "POST", "/m/stores/default/keys/NEW_KEY", writeBody("a key")); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if len(blue.writes) != 1 || blue.writes[0]["grant"] == nil || blue.writes[0]["cert"] != nil || blue.writes[0]["writer"] != "machine" {
		t.Fatalf("secrets got %v", blue.writes)
	}
	// a kernel line with no machine grant yet writes nothing
	r.st.Do(func(d *persisted) { d.Sessions["sK"].Kernel.MachineCert = nil })
	if code, _ := m.do(t, r.MachineHandler(), "POST", "/m/stores/default/keys/NEW_KEY", writeBody("")); code != 403 {
		t.Fatalf("a write without the machine's grant: %d", code)
	}
}
