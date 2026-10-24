package secrets

import (
	"encoding/json"
	"strings"
	"testing"
)

// a restore is the router writing an earlier entry back with secrets' own receipt for it (writer "replay"): the entry
// comes back with the writer and time the receipt names; ✱ a receipt of another entry, ✱ one another key signed, ✱ a
// delete's receipt, ✱ a repo's deploy-key store, ✱ a store that doesn't exist; a replayed delete needs no receipt
func TestAReplayPutsAnEarlierEntryBack(t *testing.T) {
	c, p, _ := setup(t)
	v1 := sealKey(t, c, p, "default", "A", "first")
	r1 := pl2(t)(c.WriteKey(WriteKeyInput{Store: "default", Key: "A", Wrapped: v1.Wrapped, Data: v1.Data, Writer: "setup", Sig: "c2lnMQ==",
		BackupSha256: strings.Repeat("a", 64)}))
	var first receipt
	json.Unmarshal([]byte(r1.Payload), &first)
	pl(t)(setupWrite(c, sealKey(t, c, p, "default", "A", "second")))
	if storeOf(t, c, p, "default")["A"] != "second" {
		t.Fatal("the second write")
	}
	replay := func(x KeyEntry, backup string, r *SignedDoc) (SignedDoc, error) {
		return c.WriteKey(WriteKeyInput{Store: x.Store, Key: x.Key, Wrapped: x.Wrapped, Data: x.Data, BackupSha256: backup, Writer: "replay", Receipt: r})
	}
	other := sealKey(t, c, p, "default", "A", "other")
	forged, _ := NewSigner()
	fs, _ := forged.Sign([]byte(r1.Payload))
	del := pl2(t)(c.WriteKey(WriteKeyInput{Store: "default", Key: "B", Delete: true, Writer: "setup", Sig: "c2ln"}))
	for name, try := range map[string]func() (SignedDoc, error){
		"no receipt":              func() (SignedDoc, error) { return replay(v1, first.BackupSha256, nil) },
		"another entry's receipt": func() (SignedDoc, error) { return replay(other, first.BackupSha256, &r1) },
		"another backup":          func() (SignedDoc, error) { return replay(v1, "", &r1) },
		"a receipt another key signed": func() (SignedDoc, error) {
			return replay(v1, first.BackupSha256, &SignedDoc{Payload: r1.Payload, Sig: fs})
		},
		"a delete's receipt":    func() (SignedDoc, error) { return replay(v1, first.BackupSha256, &del) },
		"another key's receipt": func() (SignedDoc, error) { v := v1; v.Key = "C"; return replay(v, first.BackupSha256, &r1) },
	} {
		if _, err := try(); err == nil {
			t.Fatalf("%s: replayed", name)
		}
	}
	again := pl2(t)(replay(v1, first.BackupSha256, &r1))
	var out map[string]any
	json.Unmarshal([]byte(again.Payload), &out)
	w := out["writer"].(map[string]any)
	if out["kind"] != "key-written" || w["by"] != "setup" || w["sig"] != "c2lnMQ==" || out["at"] != first.At || out["replayedAt"] == nil {
		t.Fatalf("the replay's receipt: %v", out)
	}
	if x := c.stores["default"]["A"]; x.Writer.By != "setup" || x.Writer.Sig != "c2lnMQ==" || x.At != first.At || x.BackupSha256 != first.BackupSha256 {
		t.Fatalf("the entry put back: %+v", x)
	}
	if storeOf(t, c, p, "default")["A"] != "first" {
		t.Fatal("the earlier value isn't back")
	}
	// the replay's own receipt replays too (a restore of a restore)
	pl(t)(setupWrite(c, sealKey(t, c, p, "default", "A", "third")))
	pl(t)(replay(v1, first.BackupSha256, &again))
	if storeOf(t, c, p, "default")["A"] != "first" {
		t.Fatal("a replay's receipt didn't replay")
	}
	// a replayed delete
	pl(t)(c.WriteKey(WriteKeyInput{Store: "default", Key: "A", Delete: true, Writer: "replay"}))
	if _, ok := c.stores["default"]["A"]; ok {
		t.Fatal("the replayed delete left the key")
	}
	// never into a store that isn't there, nor a repo's deploy-key store
	g := sealKey(t, c, p, "nowhere", "A", "x")
	if _, err := replay(g, "", &r1); err == nil {
		t.Fatal("a replay made a store")
	}
	c.repoOwner["default"] = "DE0CH/x"
	if _, err := replay(v1, first.BackupSha256, &r1); err == nil || !strings.Contains(err.Error(), "deploy-key") {
		t.Fatal("a replay into a repo's store:", err)
	}
}
