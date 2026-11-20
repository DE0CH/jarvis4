package kerneltest

import (
	"encoding/json"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// a fly-preload line through the whole kernel (docs/PLAN-one-image.md): the preloader's golden volume for the image is
// made (POST /golden until ready); a line on the fly-preload runner gets a machine on a fork of it, whose cert the
// preloader signs as flypreload-<id>; the notarizer takes it, the grant moves onto the machine and pulls; and the line survives a copy flip (the preloader's golden volumes go with it)
func TestAFlyPreloadLine(t *testing.T) {
	k := Start(t, map[string]string{"JARVIS2_URL": "http://router"})
	var g struct {
		State, Volume string
	}
	for range 2 {
		d, err := k.post("preloader", "/golden", map[string]any{"region": "lhr", "image": testImage, "diskGb": 20})
		if err != nil {
			t.Fatal(err)
		}
		json.Unmarshal([]byte(d.Payload), &g)
	}
	if g.State != "ready" || g.Volume == "" {
		t.Fatalf("golden: %+v", g)
	}
	boot, m := k.LineOn(t, "fly-preload", "s1", testImage, json.RawMessage(`{"v":1}`))
	if k.Fly.ForkOf(m.Volume) != g.Volume || m.Env["JARVIS2_RUNNER"] != "fly-preload" {
		t.Fatalf("machine %s on %s (a fork of %q), env %v", m.ID, m.Volume, k.Fly.ForkOf(m.Volume), m.Env)
	}
	c, err := doc.OpenCert(boot["machineCert"].(sig.Doc), k.Identity("preloader").SigningKey)
	if err != nil || c.Signer != doc.ByPreloader || c.Succ != doc.Object("flypreload-"+m.ID) {
		t.Fatal(err, c)
	}
	if err := k.pull(boot["grant"].(gv.Signed)); err != nil {
		t.Fatal(err)
	}
	k.Release(t)
	if err := k.SignRoster("green"); err != nil {
		t.Fatal(err)
	}
	k.Flip(t)
	d, err := k.post("preloader", "/goldens", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	var list struct{ Goldens []struct{ Volume string } }
	json.Unmarshal([]byte(d.Payload), &list)
	if len(list.Goldens) != 1 || list.Goldens[0].Volume != g.Volume {
		t.Fatalf("after the flip: %+v", list)
	}
}
