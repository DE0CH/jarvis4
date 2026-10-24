package kerneltest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

const testImage = "ghcr.io/de0ch/jarvis4-session:sha-aaaaaaaaaaaa@sha256:1111111111111111111111111111111111111111111111111111111111111111"

// pull: the secrets' answer to a pull with g (an error: refused)
func (k *Kernel) pull(g gv.Signed) error {
	_, err := k.post("secrets", "/pull", g)
	return err
}

// the copy flip, end to end on the kernel alone: a live line on blue; a release onto green; green's roster retires
// blue; every blue component hands over and freezes, green's notarizer, spawner and secrets take over; the line's grant
// (blue's mover signed it) still pulls, its machine is killed by green's spawner (which has blue's record of it) into a
// source green's notarizer defines, the grant moves on and a new machine starts from it; and a second release flips
// back to blue the same way, the grant then signed by green's mover
func TestACopyFlipKeepsALiveLine(t *testing.T) {
	k := Start(t, map[string]string{"JARVIS2_URL": "http://router"})
	settings := json.RawMessage(`{"v":1}`)
	boot, m1 := k.Line(t, "s1", testImage, settings)
	g := boot["grant"].(gv.Signed)
	if err := k.pull(g); err != nil {
		t.Fatal(err)
	}
	for _, back := range []string{"green", "blue"} {
		from := k.Active
		k.Release(t)
		if err := k.SignRoster(back); err != nil {
			t.Fatal(err)
		}
		// the standby serves nothing before it takes over
		if _, err := k.Post("notarizer-"+back, "/notarize", map[string]any{}); err == nil {
			t.Fatal("the standby notarizer answered")
		}
		k.Flip(t)
		if k.Active != back {
			t.Fatal(k.Active)
		}
		// ✱ the frozen source: every component of the old copy refuses work
		for _, role := range []string{"notarizer", "mover", "spawner", "notary"} {
			_, err := k.Post(role+"-"+from, map[string]string{"notarizer": "/notarize", "mover": "/move", "spawner": "/init", "notary": "/challenge"}[role], map[string]any{})
			if err == nil || !strings.Contains(err.Error(), "handed over") {
				t.Fatalf("%s-%s after its handoff: %v", role, from, err)
			}
		}
		if _, err := k.Post("secrets-"+from, "/keys", map[string]any{}); err == nil {
			t.Fatal("the old secrets answered")
		}
		// the live line: its grant pulls through the new copy's secrets
		if err := k.pull(g); err != nil {
			t.Fatalf("the grant after the flip to %s: %v", back, err)
		}
		// a pause: the new spawner kills the machine its predecessor made, the kill cert is notarized, the grant moves
		kd, err := k.post("spawner", "/kill", map[string]string{"id": m1.ID})
		if err != nil {
			t.Fatal(err)
		}
		var kc struct{ Cert sig.Doc }
		json.Unmarshal([]byte(kd.Payload), &kc)
		knz := k.Notarize(t, kc.Cert)
		g = k.Move(t, g, kc.Cert, knz)
		// a resume from that source
		cr, err := k.post("spawner", "/spawn", map[string]any{"cert": kc.Cert, "notarized": knz, "notarizer": k.Identity("notarizer"), "region": "lhr", "size": "medium", "diskGb": 10})
		if err != nil {
			t.Fatal(err)
		}
		var c struct{ ID string }
		json.Unmarshal([]byte(cr.Payload), &c)
		mc, err := k.post("spawner", "/init", map[string]string{"id": c.ID})
		if err != nil {
			t.Fatal(err)
		}
		g = k.Move(t, g, mc, k.Notarize(t, mc))
		if err := k.pull(g); err != nil {
			t.Fatal(err)
		}
		m1 = k.Fly.Machine(c.ID)
		// the new notarizer holds the old one's sources: the paused source's second successor is refused
		x, err := k.post("spawner", "/spawn", map[string]any{"cert": kc.Cert, "notarized": knz, "notarizer": k.Identity("notarizer"), "region": "lhr", "size": "medium", "diskGb": 10})
		if err != nil {
			t.Fatal(err)
		}
		json.Unmarshal([]byte(x.Payload), &c)
		second, err := k.post("spawner", "/init", map[string]string{"id": c.ID})
		if err != nil {
			t.Fatal(err)
		}
		ch, _ := k.post("notary", "/challenge", map[string]string{"subject": second.ID(), "about": "cert"})
		if _, err := k.post("notarizer", "/notarize", map[string]any{"cert": second, "challenge": ch, "notary": k.Identity("notary"),
			"signer": k.Identity("spawner")}); err == nil || !strings.Contains(err.Error(), "already has a successor") {
			t.Fatal("a second machine from the paused source:", err)
		}
		// a new line starts on the new copy
		k.Line(t, "s-"+back, testImage, settings)
	}
}

// ✱ the handoff's refusals: to a roster of the same copy, to one that doesn't retire the component (a newer roster of
// the other copy gets the same frozen state); the takeover's: a handoff of another role, for another roster than the
// one held (a replay), signed by a key the roster doesn't retire, any handoff once it serves; the same handoff again is
// answered the same
func TestTheHandoffRefusals(t *testing.T) {
	k := Start(t, map[string]string{"JARVIS2_URL": "http://router"})
	blue, _ := k.Roster()
	if _, err := k.post("notarizer", "/handoff", map[string]any{"roster": blue}); err == nil || !strings.Contains(err.Error(), "other kernel copy") {
		t.Fatal("a handoff to the same copy:", err)
	}
	k.Release(t)
	green := k.Copies["green"]
	keep := green.retired
	green.retired = nil
	unretired, _ := k.RosterFor("green")
	if _, err := k.post("notarizer", "/handoff", map[string]any{"roster": unretired}); err == nil || !strings.Contains(err.Error(), "doesn't retire") {
		t.Fatal("a handoff to a roster that doesn't retire it:", err)
	}
	green.retired = keep
	if err := k.SignRoster("green"); err != nil {
		t.Fatal(err)
	}
	gd, _ := k.RosterFor("green")
	h, err := k.post("notarizer", "/handoff", map[string]any{"roster": gd})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.post("notarizer", "/notarize", map[string]any{}); err == nil || !strings.Contains(err.Error(), "handed over") {
		t.Fatal("the frozen notarizer answered:", err)
	}
	// a second roster for green (as if one of its components restarted before taking over; here: the minter's keys not
	// retired): the frozen notarizer hands the same state to it
	green.retired = keep[:len(keep)-1]
	gd2, _ := k.RosterFor("green")
	green.retired = keep
	h2, err := k.post("notarizer", "/handoff", map[string]any{"roster": gd2})
	if err != nil || h2.Payload == h.Payload {
		t.Fatal("a frozen notarizer's handoff to a newer roster:", err)
	}
	sh, err := k.post("spawner", "/handoff", map[string]any{"roster": gd})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Post("notarizer-green", "/takeover", map[string]any{"handoff": sh}); err == nil || !strings.Contains(err.Error(), "a handoff of a spawner") {
		t.Fatal("the notarizer took the spawner's handoff:", err)
	}
	forged := h
	x, _ := sig.NewSigner()
	forged.Sig, _ = x.Sign([]byte(h.Payload))
	if _, err := k.Post("notarizer-green", "/takeover", map[string]any{"handoff": forged}); err == nil || !strings.Contains(err.Error(), "isn't signed by the notarizer this roster retires") {
		t.Fatal("a handoff signed by another key:", err)
	}
	// the replay: green's notarizer holding another roster than the one the handoff names
	if err := postRoster(green.URL["notarizer"], gd2); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Post("notarizer-green", "/takeover", map[string]any{"handoff": h}); err == nil || !strings.Contains(err.Error(), "another roster") {
		t.Fatal("a handoff for another roster:", err)
	}
	if err := postRoster(green.URL["notarizer"], gd); err != nil {
		t.Fatal(err)
	}
	a, err := k.Post("notarizer-green", "/takeover", map[string]any{"handoff": h})
	if err != nil {
		t.Fatal(err)
	}
	b, err := k.Post("notarizer-green", "/takeover", map[string]any{"handoff": h})
	if err != nil || a.Payload != b.Payload {
		t.Fatal("the same handoff again:", err)
	}
	// ✱ once it took one it serves: the frozen state handed again (to the newer roster) never replaces what it went on with
	if err := postRoster(green.URL["notarizer"], gd2); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Post("notarizer-green", "/takeover", map[string]any{"handoff": h2}); err == nil || !strings.Contains(err.Error(), "serves") {
		t.Fatal("a serving notarizer took a second handoff:", err)
	}
	// a stateless component takes no handoff
	if _, err := k.Post("mover-green", "/takeover", map[string]any{"handoff": h}); err == nil {
		t.Fatal("the mover took a handoff")
	}
}

// a crash restart (not a release): the mover comes back with new keys; its copy's re-signed roster names the old keys
// as retired, so a live line's grant (the old mover signed it) still opens and moves; the retired mover's keys sign
// nothing new (its process is gone)
func TestACrashRestartKeepsTheGrants(t *testing.T) {
	k := Start(t, map[string]string{"JARVIS2_URL": "http://router"})
	boot, m := k.Line(t, "s1", testImage, json.RawMessage(`{"v":1}`))
	g := boot["grant"].(gv.Signed)
	k.Restart(t, "mover")
	if err := k.PostRoster(""); err != nil {
		t.Fatal(err)
	}
	if _, err := gv.Open(g, k.Trust()); err != nil {
		t.Fatal("the old mover's grant no longer opens:", err)
	}
	if err := k.pull(g); err != nil {
		t.Fatal(err)
	}
	kd, err := k.post("spawner", "/kill", map[string]string{"id": m.ID})
	if err != nil {
		t.Fatal(err)
	}
	var kc struct{ Cert sig.Doc }
	json.Unmarshal([]byte(kd.Payload), &kc)
	g2 := k.Move(t, g, kc.Cert, k.Notarize(t, kc.Cert))
	if g2.Signer.SigningKey == g.Signer.SigningKey {
		t.Fatal("the move wasn't the new mover's")
	}
	gg, err := gv.Open(g2, k.Trust())
	if err != nil || gg.Machine.Kind() != "source" {
		t.Fatal(err, gg)
	}
	// a grant on the sink signed by a key the roster never named is refused as before
	x, _ := sig.NewSigner()
	d, _ := x.SignJSON(doc.Grant{Kind: "grant", Machine: gg.Machine, Keys: gg.Keys, Pair: gg.Pair, From: []string{}, At: doc.Now()})
	id := sig.Identity{Role: "mover", SigningKey: x.PublicKey(), AgreementKey: x.PublicKey()}
	if _, err := gv.Open(gv.Signed{Grant: d, By: "mover", Signer: &id}, k.Trust()); err == nil {
		t.Fatal("a grant by a mover the roster never named")
	}
}
