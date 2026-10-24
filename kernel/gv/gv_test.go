package gv

import (
	"testing"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/internal/kt"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// a grant signed by a retired mover or merger (the other copy's, or one from before a restart) opens as one signed by
// the current one; a retired key passes only for its own role; a key the roster names nowhere is refused
func TestRetiredSignersGrantsOpen(t *testing.T) {
	w := kt.New(t)
	oldMover, _ := sig.NewComponent("mover")
	oldMerger, _ := sig.NewComponent("merger")
	oldNotarizer, _ := sig.NewComponent("notarizer")
	ids := []sig.Identity{}
	for _, r := range kt.Roles {
		ids = append(ids, w.C[r].Identity)
	}
	d := kt.SignRoster(t, w.Root, sig.Roster{Copy: "green", Members: ids,
		Retired: []sig.Identity{oldMover.Identity, oldMerger.Identity, oldNotarizer.Identity}})
	tr := sig.NewTrust(w.Root.PublicKey())
	if err := tr.Set(d, nil); err != nil {
		t.Fatal(err)
	}
	_, m := kt.MachineKeys()
	grant := func(c *sig.Component, by string) Signed {
		g, err := c.Signer.SignJSON(doc.Grant{Kind: "grant", Machine: "fly-aaaaaaaa01", Keys: m.Keys,
			Pair: perm.Pair{Allowed: perm.Only("store:x"), Conditions: []string{"session:s"}}, From: []string{}, At: doc.Now()})
		if err != nil {
			t.Fatal(err)
		}
		id := c.Identity
		return Signed{Grant: g, By: by, Signer: &id}
	}
	for _, s := range []Signed{grant(w.C["mover"], "mover"), grant(oldMover, "mover"), grant(w.C["merger"], "merger"), grant(oldMerger, "merger")} {
		if g, err := Open(s, tr); err != nil || g.Machine != "fly-aaaaaaaa01" {
			t.Fatal(s.By, err)
		}
	}
	retiredAs := oldNotarizer.Identity
	retiredAs.Role = "mover"
	stray, _ := sig.NewComponent("mover")
	for what, s := range map[string]Signed{
		"a retired mover's grant as the merger's":    grant(oldMover, "merger"),
		"a retired notarizer's key named as a mover": {Grant: grant(oldNotarizer, "mover").Grant, By: "mover", Signer: &retiredAs},
		"a mover the roster names nowhere":           grant(stray, "mover"),
	} {
		if _, err := Open(s, tr); err == nil {
			t.Fatal(what, "opened")
		}
	}
}
